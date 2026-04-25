// SPDX-License-Identifier: MIT
// @custom:security-contact bridge-security@alephzero.org

// ============================================================================
// FILE: IChainVerifier.sol
// PURPOSE: Defines the universal interface that every chain-specific verifier
//          module must implement. This is the core abstraction that makes the
//          bridge modular — adding a new chain means deploying a new verifier
//          that conforms to this interface, then registering it in the
//          VerifierRegistry.
// ============================================================================

// Solidity version pinned to 0.8.34 for production safety.
// Versions 0.8.28–0.8.33 have a high-severity transient storage bug.
pragma solidity ^0.8.26;

/// @title IChainVerifier
/// @notice Universal interface for chain-specific finality and state proof verification.
/// @dev Each supported chain (Ethereum, Aleph Zero, Cosmos, etc.) gets its own
///      implementation of this interface. The bridge core only interacts through
///      this abstraction, enabling permissionless chain extension.
interface IChainVerifier {

    // ========================================================================
    // STRUCTS
    // ========================================================================

    /// @notice Represents a finalized block header from the source chain.
    /// @dev Different chains populate these fields differently:
    ///      - Ethereum: stateRoot = beacon state root, blockHash = execution block hash
    ///      - Aleph Zero: stateRoot = substrate trie root, blockHash = block hash
    /// @param blockNumber The height of the finalized block on the source chain.
    /// @param blockHash The hash of the finalized block (chain-specific encoding).
    /// @param stateRoot The state trie root committed in this block.
    /// @param timestamp The UNIX timestamp when this block was produced.
    struct BlockHeader {
        uint256 blockNumber;    // The block height on the source chain
        bytes32 blockHash;      // The canonical block hash
        bytes32 stateRoot;      // The state root committed in this block
        uint256 timestamp;      // UNIX timestamp of block production
    }

    /// @notice Encapsulates a finality proof from the source chain's consensus.
    /// @dev The `proofData` field is opaque — its encoding depends on the chain:
    ///      - For Ethereum: sync committee BLS aggregate signature + participation bits
    ///      - For Aleph Zero: ZK-SNARK proof (Groth16) of AlephBFT finality
    ///      - For Cosmos/Tendermint: ≥2/3 validator signatures on the block
    /// @param header The block header being proven as finalized.
    /// @param proofData The chain-specific proof bytes (opaque to the bridge core).
    struct FinalityProof {
        BlockHeader header;     // The block header this proof attests to
        bytes proofData;        // Opaque proof data (chain-specific encoding)
    }

    /// @notice Encapsulates a storage proof for a specific account and slot.
    /// @dev For Ethereum this is an EIP-1186 Merkle Patricia Trie proof.
    ///      For Substrate-based chains this is a trie proof against the state root.
    /// @param account The address of the contract whose storage is being proven.
    /// @param storageSlot The specific storage slot being proven.
    /// @param storageValue The value at that storage slot (proven by the proof).
    /// @param stateRoot The state root against which this proof is verified.
    /// @param proof The encoded proof data (MPT nodes for Ethereum, trie nodes for Substrate).
    struct StorageProof {
        address account;        // The contract address on the source chain
        bytes32 storageSlot;    // The storage slot index being proven
        bytes32 storageValue;   // The proven value at that slot
        bytes32 stateRoot;      // The state root this proof is verified against
        bytes proof;            // The encoded Merkle proof nodes
    }

    // ========================================================================
    // EVENTS
    // ========================================================================

    /// @notice Emitted when a new block header is successfully verified and stored.
    /// @param blockNumber The height of the verified block.
    /// @param blockHash The hash of the verified block.
    /// @param stateRoot The state root from the verified block.
    event HeaderVerified(
        uint256 indexed blockNumber,    // Indexed for efficient log filtering by height
        bytes32 indexed blockHash,      // Indexed for efficient log filtering by hash
        bytes32 stateRoot               // The state root committed in this block
    );

    // ========================================================================
    // ERRORS
    // ========================================================================

    /// @notice Thrown when a finality proof fails cryptographic verification.
    error InvalidFinalityProof();

    /// @notice Thrown when a storage proof does not match the expected state root.
    error InvalidStorageProof();

    /// @notice Thrown when a submitted header references a block number that is
    ///         not newer than the latest verified header (prevents replay).
    error StaleHeader();

    /// @notice Thrown when the proof references a validator set that is not
    ///         currently recognized (e.g., after rotation but before update).
    error UnknownValidatorSet();

    // ========================================================================
    // EXTERNAL FUNCTIONS — STATE-CHANGING
    // ========================================================================

    /// @notice Verifies a finality proof and stores the proven header.
    /// @dev This is the primary entry point for relayers. The function:
    ///      1. Decodes the chain-specific proof from `proof.proofData`
    ///      2. Verifies the proof against the current validator set / committee
    ///      3. Stores the header if valid (for later state proof verification)
    ///      4. Emits HeaderVerified event
    /// @param proof The finality proof containing the header and proof data.
    /// @return valid True if the proof was successfully verified and stored.
    function verifyFinality(
        FinalityProof calldata proof    // The complete finality proof to verify
    ) external returns (bool valid);

    // ========================================================================
    // EXTERNAL FUNCTIONS — VIEW (READ-ONLY)
    // ========================================================================

    /// @notice Verifies a storage proof against a previously verified state root.
    /// @dev The state root must have been previously stored via verifyFinality().
    ///      This function does NOT modify state — it only checks the proof.
    /// @param proof The storage proof to verify.
    /// @return value The proven storage value (only valid if the proof passes).
    function verifyStorageProof(
        StorageProof calldata proof      // The storage proof to verify
    ) external view returns (bytes32 value);

    /// @notice Returns the block number of the latest verified header.
    /// @dev Used by the bridge to determine the freshness of the light client.
    /// @return height The block number of the most recently verified header.
    function getLatestHeight() external view returns (uint256 height);

    /// @notice Returns the full header data for a previously verified block.
    /// @dev Returns a zeroed struct if the block number has not been verified.
    /// @param blockNumber The block height to look up.
    /// @return header The stored header data for that block number.
    function getHeader(
        uint256 blockNumber             // The block height to query
    ) external view returns (BlockHeader memory header);

    /// @notice Returns a unique identifier for this chain verifier.
    /// @dev Used by the VerifierRegistry to prevent duplicate registrations.
    ///      Convention: keccak256 of the chain name, e.g., keccak256("ALEPH_ZERO").
    /// @return chainId The unique chain identifier for this verifier.
    function chainId() external pure returns (bytes32 chainId);
}
