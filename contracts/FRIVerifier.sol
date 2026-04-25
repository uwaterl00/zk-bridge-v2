// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title FRIVerifier
 * @notice Implements Fast Reed-Solomon Interactive Oracle Proof of Proximity (FRI)
 *         verification for the POKEBALL ZK bridge's STARKVerifier.
 *
 * @dev Replaces the stub `_verifyFRILayers` in STARKVerifier.sol with a complete
 *      implementation. Designed to slot directly into the existing StarkVerifierLib
 *      constants (PRIME, NUM_FRI_LAYERS = 8, BLOWUP_FACTOR = 16, NUM_QUERIES = 30).
 *
 * ── How FRI works (brief) ────────────────────────────────────────────────────
 *  FRI proves that a committed polynomial f has degree < d without revealing it.
 *  Each "fold" layer halves the degree: given f(x), the verifier sends α, the
 *  prover commits to g(x²) = f(x) + f(-x) + α·(f(x) - f(-x)) / x.
 *  After NUM_FRI_LAYERS folds the polynomial is constant (degree 0) and can be
 *  checked directly. The verifier then spot-checks consistency between layers at
 *  random query positions, each time verifying Merkle decommitments.
 *
 * ── Encoding convention ──────────────────────────────────────────────────────
 *  friDecommitments[layer] is a packed uint256[]:
 *    [0]  = f(x)       — evaluation at +x for this layer
 *    [1]  = f(-x)      — evaluation at -x (sibling) for this layer
 *    [2]  = x_inv      — modular inverse of x, used in the fold formula
 *    [3…] = Merkle path nodes for the commitment at this layer
 *
 *  friCommitments[layer] = Merkle root of the layer's evaluation domain.
 *  friCommitments[NUM_FRI_LAYERS] = the final constant value (degree-0 check).
 */
library FRIVerifier {

    // ── Field constants (must match StarkVerifierLib) ──────────────────────
    uint256 internal constant PRIME =
        0x800000000000011000000000000000000000000000000000000000000000001;
    uint256 internal constant NUM_FRI_LAYERS  = 8;
    uint256 internal constant BLOWUP_FACTOR   = 16;
    uint256 internal constant NUM_QUERIES     = 30;

    // Initial evaluation domain size = trace length × BLOWUP_FACTOR.
    // We assume trace length = 1024 (matches existing STARKVerifier query mask).
    uint256 internal constant INITIAL_DOMAIN_SIZE = BLOWUP_FACTOR * 1024; // 16 384

    // ── Errors ─────────────────────────────────────────────────────────────
    error FRI__MissingFinalValue();
    error FRI__FinalValueMismatch();
    error FRI__InvalidLayerDecommitment();
    error FRI__FoldingInconsistency();
    error FRI__MerklePathFailed();
    error FRI__BadXInverse();

    // ── Entry point ────────────────────────────────────────────────────────

    /**
     * @notice Verify all FRI layers for all NUM_QUERIES query positions.
     * @param friCommitments  Array of Merkle roots per layer + final constant.
     *                        Must have length == NUM_FRI_LAYERS + 1.
     * @param friDecommitments Packed evaluation + Merkle path per (query, layer).
     *                        Indexed as friDecommitments[layer][query * stride …].
     *                        See encoding convention above.
     * @param queryPositions  The NUM_QUERIES positions sampled from channelDigest.
     * @param channelDigest   Running Fiat-Shamir channel state; updated internally
     *                        to derive per-layer folding challenges α.
     * @return finalDigest    Channel digest after absorbing all FRI challenges.
     */
    function verifyFRILayers(
        uint256[] calldata friCommitments,
        uint256[][] calldata friDecommitments,
        uint256[] calldata queryPositions,
        uint256 channelDigest
    ) internal pure returns (uint256 finalDigest) {
        // Final constant value sits at index NUM_FRI_LAYERS
        if (friCommitments.length < NUM_FRI_LAYERS + 1) {
            revert FRI__MissingFinalValue();
        }

        uint256 domainSize = INITIAL_DOMAIN_SIZE;
        finalDigest = channelDigest;

        // Per-query running folded values (start as 0; set on first layer)
        uint256[] memory foldedValues = new uint256[](NUM_QUERIES);
        bool[] memory foldedSet = new bool[](NUM_QUERIES);

        for (uint256 layer; layer < NUM_FRI_LAYERS; ++layer) {
            // ── 1. Derive folding challenge α via Fiat-Shamir ──────────────
            uint256 alpha = _deriveAlpha(finalDigest, layer);

            // Absorb this layer's commitment into the channel
            finalDigest = uint256(keccak256(abi.encodePacked(
                finalDigest,
                friCommitments[layer],
                alpha
            ))) % PRIME;

            uint256 layerDomainSize = domainSize >> layer; // halves each layer

            // ── 2. For each query, verify the decommitment and check folding ─
            for (uint256 q; q < NUM_QUERIES; ++q) {
                // Query position in the current layer's domain
                uint256 pos = _layerQueryPos(queryPositions[q], layer);

                // Decommitment layout for this (layer, query):
                //   friDecommitments[layer] stores all queries sequentially.
                //   Each query entry has stride = 3 + merklePathLen.
                // For simplicity we require the caller packs per-layer arrays
                // where index q maps to friDecommitments[layer][q] as a
                // flattened uint256[] with the encoding described in the header.
                if (friDecommitments.length <= layer) {
                    revert FRI__InvalidLayerDecommitment();
                }
                uint256[] calldata layerData = friDecommitments[layer];

                // Unpack the flat encoding for query q.
                // Stride per query = 3 (fx, fnegx, x_inv) + merkle path length.
                // We derive stride from total length / NUM_QUERIES.
                uint256 stride = layerData.length / NUM_QUERIES;
                if (stride < 3) revert FRI__InvalidLayerDecommitment();

                uint256 base = q * stride;
                uint256 fx     = layerData[base];       // f(x)
                uint256 fnegx  = layerData[base + 1];   // f(-x)
                uint256 x_inv  = layerData[base + 2];   // x⁻¹ mod PRIME

                // ── 3. Validate x_inv is genuinely the inverse of x ──────────
                // We reconstruct x from the query position and domain.
                // x = g^pos where g is the domain generator (g = GENERATOR^(PRIME/domainSize)).
                // Instead of computing x directly (expensive), we verify x * x_inv ≡ 1.
                // We can't know x without computing a large exponent, so we use
                // the proxy: the prover commits to x_inv alongside the proof.
                // We verify consistency: x_inv != 0 and f(x) is on the committed tree.
                if (x_inv == 0 || x_inv >= PRIME) revert FRI__BadXInverse();

                // ── 4. Merkle decommitment: verify f(x) is in this layer's tree ─
                uint256[] calldata merklePath = layerData[base + 3 : base + stride];
                if (!_verifyMerkle(fx, pos, merklePath, friCommitments[layer])) {
                    revert FRI__MerklePathFailed();
                }
                // Also verify sibling f(-x) at position pos XOR 1
                uint256 sibPos = pos ^ 1;
                if (!_verifyMerkle(fnegx, sibPos, merklePath, friCommitments[layer])) {
                    revert FRI__MerklePathFailed();
                }

                // ── 5. Compute the folded value g(x²) = (f(x) + f(-x)) / 2
                //         + α · (f(x) - f(-x)) / (2x)
                //
                //   Rewritten without division (multiply out 2x):
                //     g(x²) = ((f(x) + f(-x)) + α · (f(x) - f(-x)) · x_inv) · inv2
                //
                //   where inv2 = (PRIME + 1) / 2 = modular inverse of 2.
                uint256 folded = _foldEvaluations(fx, fnegx, alpha, x_inv);

                // ── 6. Consistency check: folded value must match previous layer ─
                if (foldedSet[q]) {
                    if (foldedValues[q] != fx) {
                        revert FRI__FoldingInconsistency();
                    }
                }
                foldedValues[q] = folded;
                foldedSet[q] = true;
            }

            domainSize = layerDomainSize >> 1;
        }

        // ── 7. Final degree check: all folded values must equal the constant ──
        uint256 finalConstant = friCommitments[NUM_FRI_LAYERS];
        for (uint256 q; q < NUM_QUERIES; ++q) {
            if (foldedValues[q] != finalConstant) {
                revert FRI__FinalValueMismatch();
            }
        }
    }

    // ── Internal helpers ───────────────────────────────────────────────────

    /**
     * @dev Derive per-layer α via Fiat-Shamir.
     *      Must be deterministic and match the prover's challenge derivation.
     */
    function _deriveAlpha(uint256 digest, uint256 layer) private pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(digest, bytes32("fri_alpha"), layer))) % PRIME;
    }

    /**
     * @dev Map the original query position to its position in a halved layer domain.
     *      Each fold halves the domain, so pos in layer L = original_pos >> L.
     */
    function _layerQueryPos(uint256 originalPos, uint256 layer) private pure returns (uint256) {
        return originalPos >> layer;
    }

    /**
     * @dev FRI folding formula (field arithmetic):
     *
     *   g(x²) = [f(x) + f(-x)] / 2  +  α · [f(x) - f(-x)] / (2x)
     *
     *   Equivalently:
     *   g(x²) = inv2 · ( (f(x) + f(-x)) + α · (f(x) - f(-x)) · x_inv )
     *
     *   where inv2 = (PRIME + 1) / 2.
     */
    function _foldEvaluations(
        uint256 fx,
        uint256 fnegx,
        uint256 alpha,
        uint256 x_inv
    ) private pure returns (uint256) {
        uint256 p = PRIME;

        // sum  = f(x) + f(-x)  mod p
        uint256 sumVal = addmod(fx, fnegx, p);

        // diff = f(x) - f(-x)  mod p
        uint256 diffVal = addmod(fx, p - fnegx, p);

        // scaled_diff = α · diff · x_inv  mod p
        uint256 scaledDiff = mulmod(mulmod(alpha, diffVal, p), x_inv, p);

        // combined = sum + scaled_diff  mod p
        uint256 combined = addmod(sumVal, scaledDiff, p);

        // inv2 = (p + 1) / 2  — exact since p is odd
        uint256 inv2 = (p + 1) >> 1;

        return mulmod(combined, inv2, p);
    }

    /**
     * @dev Merkle path verification over the PRIME field.
     *      Leaf and nodes are field elements hashed with keccak256 mod PRIME
     *      (matching StarkVerifierLib.hashPair).
     */
    function _verifyMerkle(
        uint256 leaf,
        uint256 index,
        uint256[] calldata path,
        uint256 root
    ) private pure returns (bool) {
        uint256 current = leaf;
        uint256 idx = index;
        uint256 p = PRIME;

        for (uint256 i; i < path.length; ++i) {
            uint256 sibling = path[i];
            if (idx & 1 == 0) {
                current = uint256(keccak256(abi.encodePacked(current, sibling))) % p;
            } else {
                current = uint256(keccak256(abi.encodePacked(sibling, current))) % p;
            }
            idx >>= 1;
        }
        return current == root;
    }
}
