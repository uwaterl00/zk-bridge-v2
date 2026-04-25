// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ISTARKVerifier} from "./interfaces/ISTARKVerifier.sol";

library StarkVerifierLib {
    uint256 internal constant PRIME = 0x800000000000011000000000000000000000000000000000000000000000001;
    uint256 internal constant GENERATOR = 3;
    uint256 internal constant EXTENSION_DEGREE = 2;
    uint256 internal constant NUM_FRI_LAYERS = 8;
    uint256 internal constant BLOWUP_FACTOR = 16;
    uint256 internal constant NUM_QUERIES = 30;
    uint256 internal constant GRINDING_BITS = 20;

    error StarkVerifier__InvalidTraceCommitment();
    error StarkVerifier__InvalidConstraintCommitment();
    error StarkVerifier__InvalidFRICommitment();
    error StarkVerifier__InvalidQueryCount();
    error StarkVerifier__InvalidPowNonce();
    error StarkVerifier__FRIVerificationFailed();
    error StarkVerifier__DecommitmentFailed();
    error StarkVerifier__InvalidPublicInputs();

    function hashPair(uint256 a, uint256 b) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(a, b))) % PRIME;
    }

    function verifyMerklePath(
        uint256 leaf,
        uint256 index,
        uint256[] calldata path,
        uint256 root
    ) internal pure returns (bool) {
        uint256 current = leaf;
        uint256 idx = index;
        for (uint256 i; i < path.length; ++i) {
            if (idx & 1 == 0) {
                current = hashPair(current, path[i]);
            } else {
                current = hashPair(path[i], current);
            }
            idx >>= 1;
        }
        return current == root;
    }

    function powMod(uint256 base, uint256 exp, uint256 mod) internal pure returns (uint256 result) {
        result = 1;
        base = base % mod;
        while (exp > 0) {
            if (exp & 1 == 1) {
                result = mulmod(result, base, mod);
            }
            exp >>= 1;
            base = mulmod(base, base, mod);
        }
    }

    function verifyGrinding(
        uint256 channelDigest,
        uint256 powNonce
    ) internal pure returns (bool) {
        uint256 hash = uint256(keccak256(abi.encodePacked(channelDigest, powNonce)));
        return hash >> (256 - GRINDING_BITS) == 0;
    }
}