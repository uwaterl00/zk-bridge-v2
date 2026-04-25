// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ISTARKVerifier} from "./interfaces/ISTARKVerifier.sol";
import {AlephBFTLightClient} from "./AlephBFTLightClient.sol";

/**
 * @title ZKStarkBridge
 * @notice STARK-based cross-chain bridge with AlephBFT finality.
 *
 * @dev Changes from the original stub:
 *
 *   1. BUG FIX — `submitStateRoot`:
 *      The original code tested `publicInputs.previousStateRootVerifiedStateRoot`
 *      which is not a field on `PublicInputs` and always evaluates to `false`
 *      (a non-existent member access resolves to zero/false in Solidity,
 *       silently bypassing the check).
 *      Fixed to: `publicInputs.previousStateRoot != latestVerifiedStateRoot`
 *      so that the chain of state roots is properly linked.
 *
 *   2. AlephBFT light-client integration:
 *      The bridge can optionally be wired to an `AlephBFTLightClient` instance.
 *      When `lightClient` is set (non-zero), `submitStateRoot` also validates
 *      that `publicInputs.stateRoot` matches the latest finalized root from the
 *      light client, providing an additional layer of security: a STARK proof
 *      alone is not sufficient — the state root must also be finalized by the
 *      AlephBFT validator supermajority.
 *
 *      Deployment pattern:
 *        1. Deploy AlephBFTLightClient with genesis validator set + genesis root.
 *        2. Deploy ZKStarkBridge with the light client address.
 *        3. Relayers call AlephBFTLightClient.submitFinalityCertificate() to
 *           advance the finalized root; provers call ZKStarkBridge.submitStateRoot()
 *           to supply the STARK proof.
 */
contract ZKStarkBridge is Ownable2Step, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    // ── Errors ─────────────────────────────────────────────────────────────
    error ZKStarkBridge__ZeroAddress();
    error ZKStarkBridge__ZeroAmount();
    error ZKStarkBridge__InvalidChainId();
    error ZKStarkBridge__ProofVerificationFailed();
    error ZKStarkBridge__DepositAlreadyProcessed();
    error ZKStarkBridge__WithdrawalAlreadyClaimed();
    error ZKStarkBridge__InsufficientBridgeLiquidity();
    error ZKStarkBridge__StateRootMismatch();
    error ZKStarkBridge__InvalidBlockNumber();
    error ZKStarkBridge__TokenNotSupported();
    error ZKStarkBridge__ExceedsMaxDeposit();
    error ZKStarkBridge__LightClientRootMismatch();

    // ── Structs ─────────────────────────────────────────────────────────────

    struct Deposit {
        address depositor;
        address token;
        uint256 amount;
        uint256 destinationChainId;
        uint256 nonce;
        bytes32 commitment;
    }

    struct WithdrawalClaim {
        address recipient;
        address token;
        uint256 amount;
        uint256 sourceChainId;
        uint256 nonce;
        bytes32 depositHash;
    }

    // ── Immutable state ────────────────────────────────────────────────────

    ISTARKVerifier public immutable starkVerifier;
    uint256 public immutable sourceChainId;

    /**
     * @notice Optional AlephBFT light client.  When set, every state root
     *         submitted via `submitStateRoot` must also be the latest finalized
     *         root from the light client.  Address(0) disables the check.
     */
    AlephBFTLightClient public immutable lightClient;

    // ── Mutable state ──────────────────────────────────────────────────────

    uint256 public depositNonce;
    bytes32 public latestVerifiedStateRoot;
    uint256 public latestVerifiedBlockNumber;
    uint256 public maxDepositAmount;

    mapping(bytes32 => bool)    public processedDeposits;
    mapping(bytes32 => bool)    public claimedWithdrawals;
    mapping(bytes32 => Deposit) public deposits;
    mapping(address => bool)    public supportedTokens;
    mapping(uint256 => bytes32) public stateRoots;

    // ── Events ─────────────────────────────────────────────────────────────

    event DepositInitiated(
        bytes32 indexed depositHash,
        address indexed depositor,
        address indexed token,
        uint256 amount,
        uint256 destinationChainId,
        uint256 nonce
    );

    event WithdrawalClaimed(
        bytes32 indexed depositHash,
        address indexed recipient,
        address indexed token,
        uint256 amount,
        uint256 sourceChainId
    );

    event StateRootUpdated(
        bytes32 indexed newStateRoot,
        bytes32 indexed previousStateRoot,
        uint256 blockNumber
    );

    event TokenSupportUpdated(address indexed token, bool supported);
    event MaxDepositUpdated(uint256 newMaxDeposit);

    // ── Constructor ────────────────────────────────────────────────────────

    /**
     * @param _starkVerifier     Address of the deployed STARKVerifier contract.
     * @param _owner             Initial owner (Ownable2Step admin).
     * @param _maxDepositAmount  Maximum deposit per tx (0 = unlimited).
     * @param _lightClient       Address of AlephBFTLightClient (address(0) to disable).
     */
    constructor(
        address _starkVerifier,
        address _owner,
        uint256 _maxDepositAmount,
        address _lightClient
    ) Ownable(_owner) {
        if (_starkVerifier == address(0)) revert ZKStarkBridge__ZeroAddress();
        if (_owner == address(0)) revert ZKStarkBridge__ZeroAddress();

        starkVerifier    = ISTARKVerifier(_starkVerifier);
        sourceChainId    = block.chainid;
        maxDepositAmount = _maxDepositAmount;
        // _lightClient == address(0) is explicitly allowed (disables check)
        lightClient = AlephBFTLightClient(_lightClient);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                          DEPOSIT
    // ═══════════════════════════════════════════════════════════════════════

    function deposit(
        address token,
        uint256 amount,
        uint256 destinationChainId
    ) external nonReentrant whenNotPaused {
        if (token == address(0))              revert ZKStarkBridge__ZeroAddress();
        if (amount == 0)                      revert ZKStarkBridge__ZeroAmount();
        if (destinationChainId == sourceChainId) revert ZKStarkBridge__InvalidChainId();
        if (!supportedTokens[token])          revert ZKStarkBridge__TokenNotSupported();
        if (maxDepositAmount > 0 && amount > maxDepositAmount)
                                              revert ZKStarkBridge__ExceedsMaxDeposit();

        uint256 currentNonce = depositNonce++;

        bytes32 commitment = keccak256(abi.encodePacked(
            msg.sender,
            token,
            amount,
            destinationChainId,
            currentNonce,
            block.chainid
        ));

        bytes32 depositHash = keccak256(abi.encodePacked(
            commitment,
            block.number,
            block.timestamp
        ));

        deposits[depositHash] = Deposit({
            depositor:          msg.sender,
            token:              token,
            amount:             amount,
            destinationChainId: destinationChainId,
            nonce:              currentNonce,
            commitment:         commitment
        });

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        emit DepositInitiated(depositHash, msg.sender, token, amount, destinationChainId, currentNonce);
    }

    function depositETH(
        uint256 destinationChainId
    ) external payable nonReentrant whenNotPaused {
        if (msg.value == 0)                      revert ZKStarkBridge__ZeroAmount();
        if (destinationChainId == sourceChainId) revert ZKStarkBridge__InvalidChainId();
        if (maxDepositAmount > 0 && msg.value > maxDepositAmount)
                                                 revert ZKStarkBridge__ExceedsMaxDeposit();

        uint256 currentNonce = depositNonce++;

        bytes32 commitment = keccak256(abi.encodePacked(
            msg.sender,
            address(0),
            msg.value,
            destinationChainId,
            currentNonce,
            block.chainid
        ));

        bytes32 depositHash = keccak256(abi.encodePacked(
            commitment,
            block.number,
            block.timestamp
        ));

        deposits[depositHash] = Deposit({
            depositor:          msg.sender,
            token:              address(0),
            amount:             msg.value,
            destinationChainId: destinationChainId,
            nonce:              currentNonce,
            commitment:         commitment
        });

        emit DepositInitiated(depositHash, msg.sender, address(0), msg.value, destinationChainId, currentNonce);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                      STATE ROOT SUBMISSION
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Submit a STARK proof to advance the bridge's trusted state root.
     *
     * @dev  FIX: The original code checked `publicInputs.previousStateRootVerifiedStateRoot`
     *       which accessed a non-existent field (always false), silently bypassing
     *       the state-root linkage check.  The correct check is:
     *
     *         publicInputs.previousStateRoot != latestVerifiedStateRoot
     *
     *       which ensures each submitted proof chains from the current latest root.
     *
     *       Additionally, if a light client is wired in, the submitted stateRoot
     *       must match the latest finalized root from AlephBFT, providing dual
     *       verification (STARK proof + BFT supermajority finality).
     *
     * @param proof        The STARK proof.
     * @param publicInputs Public inputs including stateRoot, previousStateRoot,
     *                     blockNumber, and chainId.
     */
    function submitStateRoot(
        ISTARKVerifier.StarkProof calldata proof,
        ISTARKVerifier.PublicInputs calldata publicInputs
    ) external nonReentrant whenNotPaused {
        // ── FIX: correct state-root linkage check ─────────────────────────
        // Original (broken): if (publicInputs.previousStateRootVerifiedStateRoot)
        //   — accesses a non-existent member; always false; check never fires.
        // Fixed: compare previousStateRoot against the stored latest root.
        if (publicInputs.previousStateRoot != latestVerifiedStateRoot) {
            revert ZKStarkBridge__StateRootMismatch();
        }

        if (publicInputs.blockNumber <= latestVerifiedBlockNumber) {
            revert ZKStarkBridge__InvalidBlockNumber();
        }

        // ── Optional AlephBFT light-client cross-check ────────────────────
        // When a light client is configured, the new state root must also be
        // the latest root finalized by the AlephBFT supermajority.  This
        // prevents a STARK-proof-only attack where a prover submits a valid
        // proof for a non-canonical state root.
        if (address(lightClient) != address(0)) {
            bytes32 lcRoot = lightClient.getLatestStateRoot();
            if (lcRoot != publicInputs.stateRoot) {
                revert ZKStarkBridge__LightClientRootMismatch();
            }
        }

        // ── STARK proof verification ──────────────────────────────────────
        bool valid = starkVerifier.verifyProof(proof, publicInputs);
        if (!valid) {
            revert ZKStarkBridge__ProofVerificationFailed();
        }

        bytes32 previousRoot = latestVerifiedStateRoot;
        latestVerifiedStateRoot    = publicInputs.stateRoot;
        latestVerifiedBlockNumber  = publicInputs.blockNumber;
        stateRoots[publicInputs.blockNumber] = publicInputs.stateRoot;

        emit StateRootUpdated(publicInputs.stateRoot, previousRoot, publicInputs.blockNumber);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                         WITHDRAWAL CLAIM
    // ═══════════════════════════════════════════════════════════════════════

    function claimWithdrawal(
        WithdrawalClaim calldata claim,
        bytes32[] calldata merkleProof
    ) external nonReentrant whenNotPaused {
        if (claim.recipient == address(0)) revert ZKStarkBridge__ZeroAddress();
        if (claim.amount == 0)             revert ZKStarkBridge__ZeroAmount();

        bytes32 claimHash = keccak256(abi.encode(claim));
        if (claimedWithdrawals[claimHash]) {
            revert ZKStarkBridge__WithdrawalAlreadyClaimed();
        }

        bytes32 leaf = keccak256(abi.encodePacked(
            claim.recipient,
            claim.token,
            claim.amount,
            claim.sourceChainId,
            claim.nonce,
            claim.depositHash
        ));

        if (!_verifyMerkleInclusion(leaf, merkleProof, latestVerifiedStateRoot)) {
            revert ZKStarkBridge__ProofVerificationFailed();
        }

        claimedWithdrawals[claimHash] = true;

        if (claim.token == address(0)) {
            if (address(this).balance < claim.amount) {
                revert ZKStarkBridge__InsufficientBridgeLiquidity();
            }
            (bool success,) = claim.recipient.call{value: claim.amount}("");
            if (!success) revert ZKStarkBridge__InsufficientBridgeLiquidity();
        } else {
            if (IERC20(claim.token).balanceOf(address(this)) < claim.amount) {
                revert ZKStarkBridge__InsufficientBridgeLiquidity();
            }
            IERC20(claim.token).safeTransfer(claim.recipient, claim.amount);
        }

        emit WithdrawalClaimed(claim.depositHash, claim.recipient, claim.token, claim.amount, claim.sourceChainId);
    }

    // ── Internal helpers ───────────────────────────────────────────────────

    function _verifyMerkleInclusion(
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes32 root
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;
        for (uint256 i; i < proof.length; ++i) {
            if (computedHash <= proof[i]) {
                computedHash = keccak256(abi.encodePacked(computedHash, proof[i]));
            } else {
                computedHash = keccak256(abi.encodePacked(proof[i], computedHash));
            }
        }
        return computedHash == root;
    }

    // ── Owner functions ────────────────────────────────────────────────────

    function setSupportedToken(address token, bool supported) external onlyOwner {
        if (token == address(0)) revert ZKStarkBridge__ZeroAddress();
        supportedTokens[token] = supported;
        emit TokenSupportUpdated(token, supported);
    }

    function setMaxDepositAmount(uint256 newMax) external onlyOwner {
        maxDepositAmount = newMax;
        emit MaxDepositUpdated(newMax);
    }

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    // ── View helpers ───────────────────────────────────────────────────────

    function getDeposit(bytes32 depositHash) external view returns (Deposit memory) {
        return deposits[depositHash];
    }

    function isWithdrawalClaimed(bytes32 claimHash) external view returns (bool) {
        return claimedWithdrawals[claimHash];
    }

    function getStateRoot(uint256 blockNumber) external view returns (bytes32) {
        return stateRoots[blockNumber];
    }

    receive() external payable {}
}
