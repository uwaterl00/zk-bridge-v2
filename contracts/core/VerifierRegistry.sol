// SPDX-License-Identifier: MIT
// @custom:security-contact bridge-security@alephzero.org

// ============================================================================
// FILE: VerifierRegistry.sol
// PURPOSE: Central registry that maps chain identifiers to their respective
//          IChainVerifier implementations. This is the "pluggable" layer that
//          allows the bridge to support new chains by simply registering a new
//          verifier contract — no upgrades to the bridge core needed.
//
// ARCHITECTURE:
//   The registry is owned by a TimelockController (which itself is governed
//   by a Gnosis Safe multisig). This ensures that adding/removing verifiers
//   goes through a time-delayed governance process, giving users time to
//   react to changes.
//
// SECURITY:
//   - Ownable2Step prevents accidental ownership transfer
//   - Only the timelock can register/deregister verifiers
//   - Events emitted for all state changes (off-chain monitoring)
// ============================================================================

// Solidity version pinned to 0.8.34 for production safety.
pragma solidity ^0.8.26;

// OpenZeppelin v5.6.1 imports — using absolute paths per coding standards.
// Ownable2Step requires explicit acceptance of ownership transfer (2-step pattern).
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";

// The universal verifier interface that all chain-specific verifiers implement.
import {IChainVerifier} from "../interfaces/IChainVerifier.sol";

/// @title VerifierRegistry
/// @notice Manages the mapping of chain IDs to their IChainVerifier implementations.
/// @dev The owner should be a TimelockController governed by a multisig.
///      This contract does NOT hold any funds — it is purely a registry.
contract VerifierRegistry is Ownable2Step {

    // ========================================================================
    // STATE VARIABLES
    // ========================================================================

    /// @notice Maps a chain identifier (bytes32) to its verifier contract.
    /// @dev The key is the value returned by IChainVerifier.chainId().
    ///      A zero address means no verifier is registered for that chain.
    mapping(bytes32 => IChainVerifier) private s_verifiers;

    /// @notice Array of all registered chain IDs, for enumeration.
    /// @dev Used by getRegisteredChains() to return all supported chains.
    ///      Order is not guaranteed after removals (swap-and-pop pattern).
    bytes32[] private s_registeredChains;

    /// @notice Maps chain ID to its index in s_registeredChains (1-indexed).
    /// @dev 0 means not registered. We use 1-indexed to distinguish from default.
    ///      This enables O(1) removal from the s_registeredChains array.
    mapping(bytes32 => uint256) private s_chainIndex;

    // ========================================================================
    // EVENTS
    // ========================================================================

    /// @notice Emitted when a new chain verifier is registered.
    /// @param chainId The unique identifier for the chain.
    /// @param verifier The address of the IChainVerifier implementation.
    event VerifierRegistered(
        bytes32 indexed chainId,        // The chain this verifier handles
        address indexed verifier        // The verifier contract address
    );

    /// @notice Emitted when an existing chain verifier is removed.
    /// @param chainId The unique identifier for the chain being removed.
    /// @param verifier The address of the removed verifier contract.
    event VerifierRemoved(
        bytes32 indexed chainId,        // The chain being deregistered
        address indexed verifier        // The removed verifier contract address
    );

    /// @notice Emitted when a chain verifier is replaced with a new one.
    /// @param chainId The unique identifier for the chain.
    /// @param oldVerifier The address of the previous verifier.
    /// @param newVerifier The address of the new verifier.
    event VerifierUpdated(
        bytes32 indexed chainId,        // The chain being updated
        address indexed oldVerifier,    // The old verifier being replaced
        address indexed newVerifier     // The new verifier taking over
    );

    // ========================================================================
    // ERRORS
    // ========================================================================

    /// @notice Thrown when trying to register a verifier for a chain that
    ///         already has one. Use updateVerifier() instead.
    error VerifierRegistry__AlreadyRegistered(bytes32 chainId);

    /// @notice Thrown when trying to remove or query a verifier for a chain
    ///         that has no registered verifier.
    error VerifierRegistry__NotRegistered(bytes32 chainId);

    /// @notice Thrown when the provided verifier address is the zero address.
    error VerifierRegistry__ZeroAddress();

    /// @notice Thrown when the verifier's self-reported chainId doesn't match
    ///         the chainId being registered. Prevents misconfigurations.
    error VerifierRegistry__ChainIdMismatch(bytes32 expected, bytes32 actual);

    // ========================================================================
    // CONSTRUCTOR
    // ========================================================================

    /// @notice Deploys the registry with the given owner (should be a TimelockController).
    /// @param initialOwner The address that will own this registry.
    ///        MUST be a multisig or timelock — never a bare EOA in production.
    constructor(
        address initialOwner            // The governance address (timelock/multisig)
    ) Ownable(initialOwner) {
        // Ownable constructor sets the initial owner.
        // No additional initialization needed.
    }

    // ========================================================================
    // EXTERNAL FUNCTIONS — STATE-CHANGING (OWNER ONLY)
    // ========================================================================

    /// @notice Registers a new chain verifier.
    /// @dev Reverts if a verifier is already registered for this chain.
    ///      The verifier's self-reported chainId() must match the provided chainId.
    /// @param _chainId The unique identifier for the chain.
    /// @param _verifier The IChainVerifier implementation for this chain.
    function registerVerifier(
        bytes32 _chainId,               // The chain identifier to register
        IChainVerifier _verifier        // The verifier contract to associate
    ) external onlyOwner {
        // CHECKS: Validate inputs before any state changes (CEI pattern).

        // Ensure the verifier address is not zero (would break lookups).
        if (address(_verifier) == address(0)) {
            revert VerifierRegistry__ZeroAddress();
        }

        // Ensure no verifier is already registered for this chain.
        // Use updateVerifier() to replace an existing one.
        if (address(s_verifiers[_chainId]) != address(0)) {
            revert VerifierRegistry__AlreadyRegistered(_chainId);
        }

        // Verify that the verifier's self-reported chain ID matches what we're registering.
        // This prevents accidentally registering an Ethereum verifier under the Aleph Zero key.
        bytes32 reportedChainId = _verifier.chainId();
        if (reportedChainId != _chainId) {
            revert VerifierRegistry__ChainIdMismatch(_chainId, reportedChainId);
        }

        // EFFECTS: Update state.

        // Store the verifier in the mapping.
        s_verifiers[_chainId] = _verifier;

        // Add the chain ID to the enumerable array.
        s_registeredChains.push(_chainId);

        // Store the 1-indexed position for O(1) removal later.
        s_chainIndex[_chainId] = s_registeredChains.length;

        // INTERACTIONS: Emit event for off-chain indexing and monitoring.
        emit VerifierRegistered(_chainId, address(_verifier));
    }

    /// @notice Removes a registered chain verifier.
    /// @dev Uses swap-and-pop to maintain a compact array without gaps.
    /// @param _chainId The chain identifier to deregister.
    function removeVerifier(
        bytes32 _chainId                // The chain identifier to remove
    ) external onlyOwner {
        // CHECKS: Ensure the chain is actually registered.
        IChainVerifier verifier = s_verifiers[_chainId];
        if (address(verifier) == address(0)) {
            revert VerifierRegistry__NotRegistered(_chainId);
        }

        // EFFECTS: Remove from mapping.
        delete s_verifiers[_chainId];

        // Remove from the enumerable array using swap-and-pop.
        // This is O(1) but does not preserve order.
        uint256 index = s_chainIndex[_chainId] - 1;    // Convert from 1-indexed to 0-indexed
        uint256 lastIndex = s_registeredChains.length - 1; // Index of the last element

        // If the element to remove is not the last one, swap it with the last.
        if (index != lastIndex) {
            bytes32 lastChainId = s_registeredChains[lastIndex]; // Get the last chain ID
            s_registeredChains[index] = lastChainId;             // Move last to the gap
            s_chainIndex[lastChainId] = index + 1;               // Update the moved element's index (1-indexed)
        }

        // Pop the last element (which is now either the removed one or a duplicate of the swapped one).
        s_registeredChains.pop();

        // Clear the index mapping for the removed chain.
        delete s_chainIndex[_chainId];

        // INTERACTIONS: Emit event.
        emit VerifierRemoved(_chainId, address(verifier));
    }

    /// @notice Replaces an existing chain verifier with a new one.
    /// @dev The new verifier's chainId() must match the existing registration.
    /// @param _chainId The chain identifier to update.
    /// @param _newVerifier The new IChainVerifier implementation.
    function updateVerifier(
        bytes32 _chainId,               // The chain identifier to update
        IChainVerifier _newVerifier     // The new verifier contract
    ) external onlyOwner {
        // CHECKS: Validate inputs.

        // Ensure the new verifier address is not zero.
        if (address(_newVerifier) == address(0)) {
            revert VerifierRegistry__ZeroAddress();
        }

        // Ensure there is an existing verifier to replace.
        IChainVerifier oldVerifier = s_verifiers[_chainId];
        if (address(oldVerifier) == address(0)) {
            revert VerifierRegistry__NotRegistered(_chainId);
        }

        // Verify the new verifier's self-reported chain ID matches.
        bytes32 reportedChainId = _newVerifier.chainId();
        if (reportedChainId != _chainId) {
            revert VerifierRegistry__ChainIdMismatch(_chainId, reportedChainId);
        }

        // EFFECTS: Replace the verifier in the mapping.
        // The s_registeredChains array and s_chainIndex don't need updating
        // because the chain ID itself hasn't changed — only the implementation.
        s_verifiers[_chainId] = _newVerifier;

        // INTERACTIONS: Emit event with both old and new addresses for auditability.
        emit VerifierUpdated(_chainId, address(oldVerifier), address(_newVerifier));
    }

    // ========================================================================
    // EXTERNAL FUNCTIONS — VIEW (READ-ONLY)
    // ========================================================================

    /// @notice Returns the verifier for a given chain ID.
    /// @dev Reverts if no verifier is registered (prevents silent failures).
    /// @param _chainId The chain identifier to look up.
    /// @return verifier The IChainVerifier implementation for that chain.
    function getVerifier(
        bytes32 _chainId                // The chain identifier to query
    ) external view returns (IChainVerifier verifier) {
        // Look up the verifier from the mapping.
        verifier = s_verifiers[_chainId];

        // Revert if no verifier is registered — callers should not silently get address(0).
        if (address(verifier) == address(0)) {
            revert VerifierRegistry__NotRegistered(_chainId);
        }

        // Return the verifier (named return variable already set).
    }

    /// @notice Checks whether a verifier is registered for a given chain.
    /// @param _chainId The chain identifier to check.
    /// @return registered True if a verifier exists for this chain.
    function isRegistered(
        bytes32 _chainId                // The chain identifier to check
    ) external view returns (bool registered) {
        // A non-zero address in the mapping means a verifier is registered.
        registered = address(s_verifiers[_chainId]) != address(0);
    }

    /// @notice Returns all registered chain IDs.
    /// @dev Useful for front-ends and monitoring tools to discover supported chains.
    /// @return chains Array of all registered chain identifiers.
    function getRegisteredChains() external view returns (bytes32[] memory chains) {
        // Return the full array. This is a view function so gas cost is only
        // relevant for on-chain callers (off-chain calls are free).
        chains = s_registeredChains;
    }

    /// @notice Returns the total number of registered chains.
    /// @return count The number of chains with registered verifiers.
    function getRegisteredChainCount() external view returns (uint256 count) {
        count = s_registeredChains.length;
    }
}
