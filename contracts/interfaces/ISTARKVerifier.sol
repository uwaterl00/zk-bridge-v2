// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface ISTARKVerifier {
    struct StarkProof {
        uint256[] traceCommitments;
        uint256[] constraintCommitments;
        uint256[] friCommitments;
        uint256[] queryPositions;
        uint256[][] traceDecommitments;
        uint256[][] constraintDecommitments;
        uint256[][] friDecommitments;
        uint256 powNonce;
    }

    struct PublicInputs {
        bytes32 stateRoot;
        bytes32 previousStateRoot;
        uint256 blockNumber;
        uint256 chainId;
    }

    function verifyProof(
        StarkProof calldata proof,
        PublicInputs calldata publicInputs
    ) external view returns (bool);
}