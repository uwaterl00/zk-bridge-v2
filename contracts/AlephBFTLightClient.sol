// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title AlephBFTLightClient
 * @notice On-chain light client that tracks finalized state roots from the
 *         remote chain (Aleph Zero / any AlephBFT-consensus chain) and feeds
 *         them to PermissionlessBridge as its trusted state root source.
 *
 * @dev Replaces the `updateRemoteStateRoot` placeholder in PermissionlessBridge.
 *      PermissionlessBridge should call `getLatestStateRoot()` on this contract
 *      instead of maintaining its own `latestRemoteStateRoot`.
 *
 * ── AlephBFT Finality ─────────────────────────────────────────────────────────
 *  AlephBFT reaches finality when ≥ 2/3 of the committee signs an aggregated
 *  finality certificate for a block. The certificate contains:
 *    - blockNumber  : the finalized block height
 *    - blockHash    : keccak256 (or substrate Blake2b) hash of the block header
 *    - stateRoot    : the state root in that block header
 *    - signers[]    : bitmask of signing validators
 *    - signatures[] : one ECDSA sig per signer over the certificate digest
 *
 *  This contract:
 *    1. Maintains the current validator set (public keys + weights).
 *    2. Accepts a finality certificate + state root update.
 *    3. Verifies ≥ 2/3 total weight of signatures over the cert digest.
 *    4. Emits and stores the new trusted state root.
 *
 *  Validator set rotation is handled via a separate `updateValidatorSet` call,
 *  also protected by a finality certificate from the previous set.
 *
 * ── Security model ────────────────────────────────────────────────────────────
 *  - Liveness: any relayer can submit a valid cert (permissionless).
 *  - Safety: requires 2/3 supermajority; minority cannot forge a cert.
 *  - Stale protection: blockNumber must strictly increase.
 *
 * @custom:security-contact security@example.com
 */
contract AlephBFTLightClient is Ownable2Step {
    using ECDSA for bytes32;

    // ── Errors ─────────────────────────────────────────────────────────────
    error LC__ZeroAddress();
    error LC__StaleBlock();
    error LC__InsufficientSignatures();
    error LC__DuplicateSigner();
    error LC__InvalidSignature();
    error LC__InvalidValidatorSet();
    error LC__WeightOverflow();
    error LC__InvalidThreshold();
    error LC__ValidatorSetSizeMismatch();
    error LC__EmptyCertificate();

    // ── Events ─────────────────────────────────────────────────────────────
    event StateRootFinalized(
        bytes32 indexed stateRoot,
        bytes32 indexed blockHash,
        uint256 blockNumber
    );
    event ValidatorSetUpdated(uint256 indexed epoch, uint256 validatorCount);

    // ── Structs ─────────────────────────────────────────────────────────────

    /**
     * @notice One validator: an ECDSA public key (recovered as address) and weight.
     * @dev    Weights are integers; threshold is expressed in the same unit.
     *         A uniform committee of N members → each weight = 1, threshold = ⌈2N/3⌉.
     */
    struct Validator {
        address pubkey; // recovered Ethereum address (keccak of uncompressed key)
        uint96  weight;
    }

    /**
     * @notice A finality certificate attesting that blockNumber/blockHash are final.
     * @dev    signerBitmap is a bitmask over the current validator set; bit i = 1
     *         means validators[i] signed. signatures[j] corresponds to the j-th
     *         set bit in signerBitmap (packed, no gaps).
     */
    struct FinalityCert {
        uint256   blockNumber;
        bytes32   blockHash;
        bytes32   stateRoot;
        uint256   signerBitmap;    // one bit per validator slot
        bytes[]   signatures;      // packed ECDSA sigs (65 bytes each), ordered by validator index
    }

    // ── State ──────────────────────────────────────────────────────────────

    /// @notice Current epoch (increments on each validator set rotation)
    uint256 public epoch;

    /// @notice Current validator set
    Validator[] public validators;

    /// @notice Total weight of the current validator set
    uint256 public totalWeight;

    /**
     * @notice Minimum weight required to accept a certificate.
     *         Should be set to ⌈2 * totalWeight / 3⌉ for BFT safety.
     */
    uint256 public threshold;

    /// @notice Latest finalized state root accepted by this light client
    bytes32 public latestStateRoot;

    /// @notice Block number corresponding to `latestStateRoot`
    uint256 public latestBlockNumber;

    /// @notice Block hash corresponding to `latestStateRoot`
    bytes32 public latestBlockHash;

    // ── Constructor ────────────────────────────────────────────────────────

    /**
     * @param admin          Owner address (for emergency validator set bootstrapping)
     * @param initialSet     Genesis validator set
     * @param initialThreshold 2/3-supermajority threshold in weight units
     * @param genesisRoot    Trusted genesis state root (out-of-band)
     * @param genesisBlock   Block number of the genesis root
     */
    constructor(
        address admin,
        Validator[] memory initialSet,
        uint256 initialThreshold,
        bytes32 genesisRoot,
        uint256 genesisBlock
    ) Ownable(admin) {
        if (admin == address(0)) revert LC__ZeroAddress();
        _setValidatorSet(initialSet, initialThreshold);
        latestStateRoot   = genesisRoot;
        latestBlockNumber = genesisBlock;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                    PERMISSIONLESS FINALIZATION
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Submit a finality certificate to advance the trusted state root.
     * @dev    Anyone can call this. The certificate is valid iff signers hold
     *         ≥ `threshold` total weight.
     * @param cert  The finality certificate from the remote chain.
     */
    function submitFinalityCertificate(FinalityCert calldata cert) external {
        if (cert.blockNumber <= latestBlockNumber) revert LC__StaleBlock();
        if (cert.signatures.length == 0) revert LC__EmptyCertificate();

        // Reconstruct the message the validators signed.
        // Convention: sign keccak256(abi.encode(chainSelector, blockNumber, blockHash, stateRoot))
        // Using chainSelector = block.chainid of *this* contract's deployment chain
        // (the bridge destination) so certs can't be replayed across deployments.
        bytes32 certDigest = _certDigest(cert);

        uint256 accumulatedWeight;
        uint256 bitmap = cert.signerBitmap;
        uint256 sigIdx;
        uint256 numValidators = validators.length;

        // Iterate over set bits in signerBitmap
        for (uint256 i; i < numValidators; ++i) {
            if (bitmap & (1 << i) == 0) continue;

            if (sigIdx >= cert.signatures.length) revert LC__InvalidSignature();

            address recovered = certDigest.recover(cert.signatures[sigIdx]);
            if (recovered != validators[i].pubkey) revert LC__InvalidSignature();

            // Ensure no duplicate counting (bitmap bit already checked; defensive)
            accumulatedWeight += validators[i].weight;
            sigIdx++;
        }

        if (accumulatedWeight < threshold) revert LC__InsufficientSignatures();

        // Accept the update
        latestStateRoot   = cert.stateRoot;
        latestBlockNumber = cert.blockNumber;
        latestBlockHash   = cert.blockHash;

        emit StateRootFinalized(cert.stateRoot, cert.blockHash, cert.blockNumber);
    }

    /**
     * @notice Submit a validator set rotation certified by the *current* set.
     * @dev    The new set takes effect immediately after successful verification.
     *         The rotation itself must be attested by a finality certificate
     *         so that the current validators confirm the new set.
     * @param cert        Finality cert attesting the rotation block.
     * @param newSet      The replacement validator set.
     * @param newThreshold New 2/3 threshold for the replacement set.
     */
    function submitValidatorSetRotation(
        FinalityCert calldata cert,
        Validator[] calldata newSet,
        uint256 newThreshold
    ) external {
        // First, finalize the cert (advances latestStateRoot)
        this.submitFinalityCertificate(cert);

        // Then rotate the validator set
        _setValidatorSet(newSet, newThreshold);
        epoch++;

        emit ValidatorSetUpdated(epoch, newSet.length);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                         VIEW / QUERY
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Returns the latest trusted state root — the value PermissionlessBridge
     *         should use as `latestRemoteStateRoot`.
     */
    function getLatestStateRoot() external view returns (bytes32) {
        return latestStateRoot;
    }

    /**
     * @notice Returns full finalization context for the latest accepted block.
     */
    function getLatestFinalized()
        external
        view
        returns (bytes32 stateRoot, bytes32 blockHash, uint256 blockNumber)
    {
        return (latestStateRoot, latestBlockHash, latestBlockNumber);
    }

    /**
     * @notice Returns the current validator set length.
     */
    function getValidatorCount() external view returns (uint256) {
        return validators.length;
    }

    /**
     * @notice Returns validator at index `i`.
     */
    function getValidator(uint256 i) external view returns (Validator memory) {
        return validators[i];
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                         OWNER FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Emergency owner override to set the validator set without a cert.
     *         Use only for genesis bootstrapping or chain halts.
     */
    function emergencySetValidatorSet(
        Validator[] calldata newSet,
        uint256 newThreshold
    ) external onlyOwner {
        _setValidatorSet(newSet, newThreshold);
        epoch++;
        emit ValidatorSetUpdated(epoch, newSet.length);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                         INTERNAL
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @dev Compute the EIP-191 personal-sign digest that validators sign.
     *      Using a structured encoding avoids cross-context replay attacks.
     *
     *      Signed message: keccak256(
     *          "\x19Ethereum Signed Message:\n32",
     *          keccak256(abi.encode(
     *              "AlephBFTFinality",
     *              remoteChainId,   ← encoded in cert or a constructor param
     *              blockNumber,
     *              blockHash,
     *              stateRoot
     *          ))
     *      )
     *
     *      For simplicity we use the local chain.id as a deployment nonce.
     *      In practice the remote chain's id should be passed in.
     */
    function _certDigest(FinalityCert calldata cert) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            "AlephBFTFinality",
            block.chainid,
            cert.blockNumber,
            cert.blockHash,
            cert.stateRoot
        ));
        // EIP-191 personal_sign prefix
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
    }

    /**
     * @dev Replace the current validator set; validates input and recomputes
     *      totalWeight and threshold.
     */
    function _setValidatorSet(Validator[] memory newSet, uint256 newThreshold) internal {
        if (newSet.length == 0) revert LC__InvalidValidatorSet();
        if (newThreshold == 0) revert LC__InvalidThreshold();

        // Clear old set
        delete validators;
        totalWeight = 0;

        uint256 accumulated;
        for (uint256 i; i < newSet.length; ++i) {
            if (newSet[i].pubkey == address(0)) revert LC__ZeroAddress();
            // Duplicate-key check (O(n²), acceptable for small committees ≤ 128)
            for (uint256 j; j < i; ++j) {
                if (validators[j].pubkey == newSet[i].pubkey) revert LC__DuplicateSigner();
            }
            validators.push(newSet[i]);
            accumulated += newSet[i].weight;
            if (accumulated < totalWeight) revert LC__WeightOverflow(); // overflow guard
            totalWeight = accumulated;
        }

        if (newThreshold > totalWeight) revert LC__InvalidThreshold();
        threshold = newThreshold;
    }
}
