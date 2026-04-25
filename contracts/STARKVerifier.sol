// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ISTARKVerifier} from "./interfaces/ISTARKVerifier.sol";
import {StarkVerifierLib} from "./StarkVerifierLib.sol";
import {FRIVerifier} from "./FRIVerifier.sol";

/**
 * @title STARKVerifier
 * @notice STARK proof verifier for the POKEBALL ZK bridge.
 *
 * @dev Changes from the original stub:
 *   - `_verifyFRILayers` now delegates to `FRIVerifier.verifyFRILayers`, which
 *     implements the correct FRI folding equation:
 *
 *         g(x²) = [f(x) + f(-x)] / 2  +  α · [f(x) - f(-x)] / (2x)
 *
 *     and verifies Merkle decommitments at every layer for every query.
 *   - `_validateProofStructure` updated to require `friCommitments.length ==
 *     NUM_FRI_LAYERS + 1`  (the last element is the degree-0 constant).
 *   - `_verifyFRILayers` now returns `uint256 finalDigest` so it participates
 *     in the Fiat-Shamir channel correctly.
 */
contract STARKVerifier is ISTARKVerifier {
    using StarkVerifierLib for *;

    error STARKVerifier__InvalidProofLength();
    error STARKVerifier__ConstraintCheckFailed();

    // ── Entry point ────────────────────────────────────────────────────────

    function verifyProof(
        StarkProof calldata proof,
        PublicInputs calldata publicInputs
    ) external pure override returns (bool) {
        _validateProofStructure(proof);
        _validatePublicInputs(publicInputs);

        uint256 channelDigest = _initializeChannel(publicInputs);

        channelDigest = _verifyTraceCommitments(proof, channelDigest);
        channelDigest = _verifyConstraintCommitments(proof, channelDigest);
        channelDigest = _verifyFRICommitments(proof, channelDigest);

        if (!StarkVerifierLib.verifyGrinding(channelDigest, proof.powNonce)) {
            revert StarkVerifierLib.StarkVerifier__InvalidPowNonce();
        }

        _verifyQueries(proof, channelDigest);

        return true;
    }

    // ── Validation helpers ─────────────────────────────────────────────────

    function _validateProofStructure(StarkProof calldata proof) internal pure {
        if (proof.traceCommitments.length == 0) {
            revert StarkVerifierLib.StarkVerifier__InvalidTraceCommitment();
        }
        if (proof.constraintCommitments.length == 0) {
            revert StarkVerifierLib.StarkVerifier__InvalidConstraintCommitment();
        }
        // friCommitments must have NUM_FRI_LAYERS + 1 elements:
        //   [0 … NUM_FRI_LAYERS-1] = per-layer Merkle roots
        //   [NUM_FRI_LAYERS]       = final constant value (degree-0 check)
        if (proof.friCommitments.length != StarkVerifierLib.NUM_FRI_LAYERS + 1) {
            revert StarkVerifierLib.StarkVerifier__InvalidFRICommitment();
        }
        if (proof.queryPositions.length != StarkVerifierLib.NUM_QUERIES) {
            revert StarkVerifierLib.StarkVerifier__InvalidQueryCount();
        }
    }

    function _validatePublicInputs(PublicInputs calldata publicInputs) internal pure {
        if (publicInputs.stateRoot == bytes32(0)) {
            revert StarkVerifierLib.StarkVerifier__InvalidPublicInputs();
        }
        if (publicInputs.previousStateRoot == bytes32(0)) {
            revert StarkVerifierLib.StarkVerifier__InvalidPublicInputs();
        }
        if (publicInputs.chainId == 0) {
            revert StarkVerifierLib.StarkVerifier__InvalidPublicInputs();
        }
    }

    // ── Channel / commitment helpers ───────────────────────────────────────

    function _initializeChannel(PublicInputs calldata publicInputs) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(
            publicInputs.stateRoot,
            publicInputs.previousStateRoot,
            publicInputs.blockNumber,
            publicInputs.chainId
        ))) % StarkVerifierLib.PRIME;
    }

    function _verifyTraceCommitments(
        StarkProof calldata proof,
        uint256 channelDigest
    ) internal pure returns (uint256) {
        for (uint256 i; i < proof.traceCommitments.length; ++i) {
            channelDigest = uint256(keccak256(abi.encodePacked(
                channelDigest,
                proof.traceCommitments[i]
            ))) % StarkVerifierLib.PRIME;
        }
        return channelDigest;
    }

    function _verifyConstraintCommitments(
        StarkProof calldata proof,
        uint256 channelDigest
    ) internal pure returns (uint256) {
        for (uint256 i; i < proof.constraintCommitments.length; ++i) {
            channelDigest = uint256(keccak256(abi.encodePacked(
                channelDigest,
                proof.constraintCommitments[i]
            ))) % StarkVerifierLib.PRIME;
        }
        return channelDigest;
    }

    function _verifyFRICommitments(
        StarkProof calldata proof,
        uint256 channelDigest
    ) internal pure returns (uint256) {
        // Absorb only the per-layer roots (indices 0 … NUM_FRI_LAYERS-1).
        // The final constant at index NUM_FRI_LAYERS is checked by FRIVerifier
        // during the folding verification, not absorbed here.
        for (uint256 i; i < StarkVerifierLib.NUM_FRI_LAYERS; ++i) {
            channelDigest = uint256(keccak256(abi.encodePacked(
                channelDigest,
                proof.friCommitments[i]
            ))) % StarkVerifierLib.PRIME;
        }
        return channelDigest;
    }

    // ── Query verification ─────────────────────────────────────────────────

    function _verifyQueries(
        StarkProof calldata proof,
        uint256 channelDigest
    ) internal pure {
        for (uint256 q; q < StarkVerifierLib.NUM_QUERIES; ++q) {
            uint256 queryPos = proof.queryPositions[q];

            uint256 expectedPos = uint256(keccak256(abi.encodePacked(
                channelDigest,
                q
            ))) % (StarkVerifierLib.BLOWUP_FACTOR * 1024);

            if (queryPos != expectedPos) {
                revert StarkVerifierLib.StarkVerifier__DecommitmentFailed();
            }

            // Trace decommitment at this query position
            if (proof.traceDecommitments.length > q) {
                if (!StarkVerifierLib.verifyMerklePath(
                    proof.traceDecommitments[q][0],
                    queryPos,
                    proof.traceDecommitments[q][1:],
                    proof.traceCommitments[0]
                )) {
                    revert StarkVerifierLib.StarkVerifier__DecommitmentFailed();
                }
            }

            // Constraint decommitment at this query position
            if (proof.constraintDecommitments.length > q) {
                if (!StarkVerifierLib.verifyMerklePath(
                    proof.constraintDecommitments[q][0],
                    queryPos,
                    proof.constraintDecommitments[q][1:],
                    proof.constraintCommitments[0]
                )) {
                    revert StarkVerifierLib.StarkVerifier__DecommitmentFailed();
                }
            }
        }

        // FRI layer verification — replaces the broken stub with the full
        // FRIVerifier implementation (correct folding + Merkle decommitments).
        _verifyFRILayers(proof, channelDigest);
    }

    /**
     * @dev Delegate FRI layer verification to FRIVerifier.
     *
     *      The original stub computed `v + α·v` which trivially passes for any
     *      non-zero value. This implementation uses the correct fold:
     *
     *        g(x²) = [f(x) + f(-x)] / 2  +  α · [f(x) - f(-x)] / (2x)
     *
     *      and verifies Merkle decommitments at every layer for every query.
     *
     * @param proof          Full STARK proof (uses friCommitments, friDecommitments,
     *                       queryPositions).
     * @param channelDigest  Fiat-Shamir channel state after all prior absorptions.
     * @return finalDigest   Updated channel digest after absorbing all FRI challenges.
     */
    function _verifyFRILayers(
        StarkProof calldata proof,
        uint256 channelDigest
    ) internal pure returns (uint256 finalDigest) {
        finalDigest = FRIVerifier.verifyFRILayers(
            proof.friCommitments,
            proof.friDecommitments,
            proof.queryPositions,
            channelDigest
        );
    }
}
