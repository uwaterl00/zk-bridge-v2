// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @dev StateProofVerifier delegates to MerklePatriciaVerifier (from POLYNOMIAL/).
 *
 *      The original stub always returned `true` for any non-empty proof array.
 *      This replacement wires in the full MPT traversal with inline RLP decoding.
 *
 *      Usage:
 *        proof.verifyAccountState(account, trustedStateRoot)
 *        proof.verifyStorageSlot(slot, expectedValue)
 *
 *      Both call signatures are identical to the stub.
 */
import {MerklePatriciaVerifier as StateProofVerifier} from "../MerklePatriciaVerifier.sol";
