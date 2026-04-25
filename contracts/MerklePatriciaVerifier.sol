// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title MerklePatriciaVerifier
 * @notice Full Ethereum Merkle Patricia Trie (MPT) proof verifier.
 *         Replaces the stub functions in StateProofVerifier.sol.
 *
 * @dev Drop-in replacement for StateProofVerifier. Call verifyAccountState()
 *      and verifyStorageSlot() exactly as before — the interface is identical.
 *
 * ── How Ethereum MPT proofs work ─────────────────────────────────────────────
 *  Ethereum's world state is a Merkle Patricia Trie whose root is the
 *  stateRoot in every block header. To prove account X has storageRoot R:
 *    1. Provide an account proof: a list of RLP-encoded trie nodes forming
 *       the path from stateRoot → keccak256(address).
 *    2. The leaf node contains the RLP-encoded account: [nonce, balance,
 *       storageRoot, codeHash].
 *    3. Decode the leaf to extract storageRoot.
 *    4. For a storage slot, provide a storage proof: nodes from
 *       storageRoot → keccak256(slot), whose leaf encodes the slot value.
 *
 * ── Node types (EIP-19 / Yellow Paper) ───────────────────────────────────────
 *  - Extension node : [encodedPath, nextNodeOrHash]
 *  - Leaf node      : [encodedPath, value]
 *  - Branch node    : [child0, …, child15, value]  (17 elements)
 *  - Empty          : RLP of ""
 *
 * ── RLP encoding (minimal inline implementation) ─────────────────────────────
 *  We implement only the subset of RLP decode required for trie node traversal.
 *
 * @custom:security-contact security@example.com
 */
library MerklePatriciaVerifier {

    // ── Errors ─────────────────────────────────────────────────────────────
    error MPT__InvalidProofLength();
    error MPT__NodeHashMismatch();
    error MPT__InvalidRLPNode();
    error MPT__PathMismatch();
    error MPT__InvalidAccountRLP();
    error MPT__InvalidStorageValue();
    error MPT__UnexpectedNodeType();

    // ── Account layout (decoded from leaf RLP) ─────────────────────────────
    struct Account {
        uint256 nonce;
        uint256 balance;
        bytes32 storageRoot;
        bytes32 codeHash;
    }

    // ── StateProof (identical to existing StateProofVerifier.StateProof) ───
    struct StateProof {
        bytes32 stateRoot;
        bytes32 storageRoot;
        bytes[] accountProof;
        bytes[] storageProof;
        uint256 blockNumber;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                       PUBLIC ENTRY POINTS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Verify that `account` exists in the trie rooted at `trustedStateRoot`
     *         and that its storageRoot matches `proof.storageRoot`.
     * @param proof            The state proof with accountProof nodes.
     * @param account          The Ethereum address being proved.
     * @param trustedStateRoot The state root from the verified block header.
     * @return true on success; reverts on any proof failure.
     */
    function verifyAccountState(
        StateProof calldata proof,
        address account,
        bytes32 trustedStateRoot
    ) internal pure returns (bool) {
        if (proof.stateRoot != trustedStateRoot) {
            revert MPT__NodeHashMismatch();
        }
        if (proof.accountProof.length == 0) {
            revert MPT__InvalidProofLength();
        }

        // The trie key for an account is keccak256(address)
        bytes memory key = _nibbles(abi.encodePacked(keccak256(abi.encodePacked(account))));

        bytes memory accountRLP = _verifyMPTProof(
            trustedStateRoot,
            key,
            proof.accountProof
        );

        // Decode the account RLP and check the storageRoot
        Account memory acc = _decodeAccount(accountRLP);
        if (acc.storageRoot != proof.storageRoot) {
            revert MPT__NodeHashMismatch();
        }

        return true;
    }

    /**
     * @notice Verify that storage `slot` in the account's trie contains `expectedValue`.
     * @param proof         The state proof with storageProof nodes.
     * @param slot          The storage slot key (32 bytes).
     * @param expectedValue The expected value stored at the slot (32 bytes).
     * @return true on success; reverts on any proof failure.
     */
    function verifyStorageSlot(
        StateProof calldata proof,
        bytes32 slot,
        bytes32 expectedValue
    ) internal pure returns (bool) {
        if (proof.storageProof.length == 0) {
            revert MPT__InvalidProofLength();
        }

        // Storage trie key is keccak256(slot)
        bytes memory key = _nibbles(abi.encodePacked(keccak256(abi.encodePacked(slot))));

        bytes memory valueRLP = _verifyMPTProof(
            proof.storageRoot,
            key,
            proof.storageProof
        );

        // Storage values are RLP-encoded big-endian integers stripped of leading zeros.
        bytes32 decoded = _decodeStorageValue(valueRLP);
        if (decoded != expectedValue) {
            revert MPT__InvalidStorageValue();
        }

        return true;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                     CORE MPT TRAVERSAL
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @dev Walk the trie from `root`, consuming nibbles from `key`, verifying
     *      each node's hash against its parent reference, and returning the
     *      value at the leaf.
     */
    function _verifyMPTProof(
        bytes32 root,
        bytes memory key,
        bytes[] calldata proof
    ) private pure returns (bytes memory value) {
        bytes32 expectedHash = root;
        uint256 keyOffset = 0;

        for (uint256 i; i < proof.length; ++i) {
            bytes calldata node = proof[i];

            // Verify this node's hash matches the reference from parent
            // (short nodes < 32 bytes are embedded directly, not hashed)
            if (node.length >= 32) {
                if (keccak256(node) != expectedHash) {
                    revert MPT__NodeHashMismatch();
                }
            }

            // RLP decode the node into its list items
            bytes[] memory items = _rlpDecodeList(node);

            if (items.length == 17) {
                // ── Branch node ───────────────────────────────────────────
                if (keyOffset == key.length) {
                    // We've consumed the whole key — value is in slot [16]
                    return items[16];
                }
                uint8 nibble = uint8(key[keyOffset]);
                keyOffset++;
                bytes memory child = items[nibble];
                if (child.length == 0) revert MPT__PathMismatch();
                expectedHash = _nodeRef(child);

            } else if (items.length == 2) {
                // ── Leaf or Extension node ────────────────────────────────
                (bool isLeaf, bytes memory pathNibbles) = _decodePath(items[0]);

                // Consume the shared prefix from key
                for (uint256 j; j < pathNibbles.length; ++j) {
                    if (keyOffset >= key.length) revert MPT__PathMismatch();
                    if (key[keyOffset] != pathNibbles[j]) revert MPT__PathMismatch();
                    keyOffset++;
                }

                if (isLeaf) {
                    // Must have consumed all key nibbles
                    if (keyOffset != key.length) revert MPT__PathMismatch();
                    return items[1];
                } else {
                    // Extension: items[1] is next node reference
                    expectedHash = _nodeRef(items[1]);
                }
            } else {
                revert MPT__UnexpectedNodeType();
            }
        }

        revert MPT__PathMismatch();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                     PATH / NIBBLE HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @dev Expand a 32-byte key into a 64-nibble array.
     */
    function _nibbles(bytes memory input) private pure returns (bytes memory out) {
        out = new bytes(input.length * 2);
        for (uint256 i; i < input.length; ++i) {
            out[i * 2]     = bytes1(uint8(input[i]) >> 4);
            out[i * 2 + 1] = bytes1(uint8(input[i]) & 0x0f);
        }
    }

    /**
     * @dev Decode a compact-encoded path byte string into (isLeaf, nibbles).
     *      HP encoding: first nibble flags — bits[1] = isLeaf, bits[0] = oddLen.
     */
    function _decodePath(bytes memory encoded) private pure returns (bool isLeaf, bytes memory nibbles) {
        if (encoded.length == 0) revert MPT__InvalidRLPNode();
        uint8 first = uint8(encoded[0]);
        uint8 flag  = first >> 4;
        isLeaf      = (flag & 0x02) != 0;
        bool odd    = (flag & 0x01) != 0;

        uint256 nibbleCount = (encoded.length - 1) * 2 + (odd ? 1 : 0);
        nibbles = new bytes(nibbleCount);
        uint256 ni;
        if (odd) {
            nibbles[ni++] = bytes1(first & 0x0f);
        }
        for (uint256 i = 1; i < encoded.length; ++i) {
            nibbles[ni++] = bytes1(uint8(encoded[i]) >> 4);
            nibbles[ni++] = bytes1(uint8(encoded[i]) & 0x0f);
        }
    }

    /**
     * @dev A node reference is a keccak256 hash if ≥ 32 bytes, otherwise the
     *      node itself is embedded inline (short node).
     */
    function _nodeRef(bytes memory node) private pure returns (bytes32) {
        if (node.length == 32) {
            return bytes32(node);
        }
        if (node.length < 32) {
            // Short node: hash it to get the reference
            return keccak256(node);
        }
        // Longer than 32 bytes should not appear as a child reference
        revert MPT__InvalidRLPNode();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                       MINIMAL RLP DECODER
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @dev Decode a top-level RLP list into its item byte strings.
     *      Only handles the node sizes encountered in Ethereum MPT proofs.
     */
    function _rlpDecodeList(bytes calldata data) private pure returns (bytes[] memory items) {
        if (data.length == 0) revert MPT__InvalidRLPNode();

        uint8 prefix = uint8(data[0]);

        // Must be a list (prefix ≥ 0xc0)
        if (prefix < 0xc0) revert MPT__InvalidRLPNode();

        uint256 offset;
        uint256 totalLen;

        if (prefix <= 0xf7) {
            // Short list: length encoded in low bits of prefix
            totalLen = prefix - 0xc0;
            offset = 1;
        } else {
            // Long list: next (prefix - 0xf7) bytes encode the length
            uint256 lenLen = prefix - 0xf7;
            totalLen = _readUint(data, 1, lenLen);
            offset = 1 + lenLen;
        }

        // Count items first to allocate
        uint256 count;
        uint256 pos = offset;
        while (pos < offset + totalLen) {
            uint256 itemLen = _rlpItemLength(data, pos);
            pos += itemLen;
            count++;
        }

        items = new bytes[](count);
        pos = offset;
        for (uint256 i; i < count; ++i) {
            (bytes memory item, uint256 consumed) = _rlpReadItem(data, pos);
            items[i] = item;
            pos += consumed;
        }
    }

    /**
     * @dev Returns the total byte length of an RLP item (header + content) at `pos`.
     */
    function _rlpItemLength(bytes calldata data, uint256 pos) private pure returns (uint256) {
        uint8 prefix = uint8(data[pos]);
        if (prefix < 0x80) return 1;                          // single byte
        if (prefix <= 0xb7) return 1 + (prefix - 0x80);       // short string
        if (prefix <= 0xbf) {
            uint256 ll2 = prefix - 0xb7;
            return 1 + ll2 + _readUint(data, pos + 1, ll2);   // long string
        }
        if (prefix <= 0xf7) return 1 + (prefix - 0xc0);       // short list
        uint256 ll = prefix - 0xf7;
        return 1 + ll + _readUint(data, pos + 1, ll);         // long list
    }

    /**
     * @dev Read an RLP item's decoded byte content and return (content, bytesConsumed).
     *      For lists, returns the raw RLP bytes of the list (not decoded recursively).
     */
    function _rlpReadItem(bytes calldata data, uint256 pos) private pure returns (bytes memory content, uint256 consumed) {
        uint8 prefix = uint8(data[pos]);

        if (prefix < 0x80) {
            content = abi.encodePacked(data[pos]);
            consumed = 1;
        } else if (prefix <= 0xb7) {
            uint256 len = prefix - 0x80;
            content = _slice(data, pos + 1, len);
            consumed = 1 + len;
        } else if (prefix <= 0xbf) {
            uint256 ll = prefix - 0xb7;
            uint256 len = _readUint(data, pos + 1, ll);
            content = _slice(data, pos + 1 + ll, len);
            consumed = 1 + ll + len;
        } else {
            // List: return raw RLP bytes (caller can recurse if needed)
            uint256 total = _rlpItemLength(data, pos);
            content = _slice(data, pos, total);
            consumed = total;
        }
    }

    /**
     * @dev Read a big-endian unsigned integer from `data[pos…pos+len-1]`.
     */
    function _readUint(bytes calldata data, uint256 pos, uint256 len) private pure returns (uint256 result) {
        for (uint256 i; i < len; ++i) {
            result = (result << 8) | uint8(data[pos + i]);
        }
    }

    function _slice(bytes calldata data, uint256 start, uint256 len) private pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) {
            out[i] = data[start + i];
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                    ACCOUNT / STORAGE DECODERS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @dev Decode an Ethereum account RLP: [nonce, balance, storageRoot, codeHash].
     */
    function _decodeAccount(bytes memory data) private pure returns (Account memory acc) {
        // The account is itself an RLP list embedded as the leaf value.
        // We convert to calldata-like slice via a local bytes copy.
        bytes[] memory fields = _rlpDecodeListMem(data);
        if (fields.length != 4) revert MPT__InvalidAccountRLP();

        acc.nonce       = _bytesToUint(fields[0]);
        acc.balance     = _bytesToUint(fields[1]);
        acc.storageRoot = bytes32(fields[2]);
        acc.codeHash    = bytes32(fields[3]);
    }

    /**
     * @dev Decode a storage value. Ethereum stores slot values as RLP(compact uint).
     *      We left-pad to 32 bytes.
     */
    function _decodeStorageValue(bytes memory raw) private pure returns (bytes32) {
        if (raw.length == 0) return bytes32(0);
        // raw is the RLP-encoded integer value
        // For non-zero values, RLP of a string: strip the prefix byte(s)
        uint8 prefix = uint8(raw[0]);
        bytes memory val;
        if (prefix < 0x80) {
            val = abi.encodePacked(raw[0]);
        } else if (prefix <= 0xb7) {
            uint256 len = prefix - 0x80;
            val = new bytes(len);
            for (uint256 i; i < len; ++i) val[i] = raw[1 + i];
        } else {
            revert MPT__InvalidStorageValue();
        }
        // Left-pad to 32 bytes
        bytes32 result;
        assembly {
            result := mload(add(val, 32))
        }
        // Shift right if val.length < 32
        result = bytes32(uint256(result) >> ((32 - val.length) * 8));
        return result;
    }

    /**
     * @dev Memory-based variant of _rlpDecodeList for decoded leaf values.
     */
    function _rlpDecodeListMem(bytes memory data) private pure returns (bytes[] memory items) {
        if (data.length == 0) revert MPT__InvalidRLPNode();
        uint8 prefix = uint8(data[0]);
        if (prefix < 0xc0) revert MPT__InvalidRLPNode();

        uint256 offset;
        uint256 totalLen;
        if (prefix <= 0xf7) {
            totalLen = prefix - 0xc0;
            offset = 1;
        } else {
            uint256 ll = prefix - 0xf7;
            totalLen = 0;
            for (uint256 i = 1; i <= ll; ++i) totalLen = (totalLen << 8) | uint8(data[i]);
            offset = 1 + ll;
        }

        uint256 count;
        uint256 pos = offset;
        while (pos < offset + totalLen) {
            uint256 ilen = _rlpItemLengthMem(data, pos);
            pos += ilen;
            count++;
        }

        items = new bytes[](count);
        pos = offset;
        for (uint256 i; i < count; ++i) {
            (bytes memory item, uint256 consumed) = _rlpReadItemMem(data, pos);
            items[i] = item;
            pos += consumed;
        }
    }

    function _rlpItemLengthMem(bytes memory data, uint256 pos) private pure returns (uint256) {
        uint8 prefix = uint8(data[pos]);
        if (prefix < 0x80) return 1;
        if (prefix <= 0xb7) return 1 + (prefix - 0x80);
        if (prefix <= 0xbf) {
            uint256 ll2 = prefix - 0xb7;
            uint256 len2;
            for (uint256 i = 1; i <= ll2; ++i) len2 = (len2 << 8) | uint8(data[pos + i]);
            return 1 + ll2 + len2;
        }
        if (prefix <= 0xf7) return 1 + (prefix - 0xc0);
        uint256 ll = prefix - 0xf7;
        uint256 len;
        for (uint256 i = 1; i <= ll; ++i) len = (len << 8) | uint8(data[pos + i]);
        return 1 + ll + len;
    }

    function _rlpReadItemMem(bytes memory data, uint256 pos) private pure returns (bytes memory content, uint256 consumed) {
        uint8 prefix = uint8(data[pos]);
        if (prefix < 0x80) {
            content = abi.encodePacked(data[pos]);
            consumed = 1;
        } else if (prefix <= 0xb7) {
            uint256 len = prefix - 0x80;
            content = new bytes(len);
            for (uint256 i; i < len; ++i) content[i] = data[pos + 1 + i];
            consumed = 1 + len;
        } else if (prefix <= 0xbf) {
            uint256 ll = prefix - 0xb7;
            uint256 len;
            for (uint256 i = 1; i <= ll; ++i) len = (len << 8) | uint8(data[pos + i]);
            content = new bytes(len);
            for (uint256 i; i < len; ++i) content[i] = data[pos + 1 + ll + i];
            consumed = 1 + ll + len;
        } else {
            uint256 total = _rlpItemLengthMem(data, pos);
            content = new bytes(total);
            for (uint256 i; i < total; ++i) content[i] = data[pos + i];
            consumed = total;
        }
    }

    function _bytesToUint(bytes memory b) private pure returns (uint256 result) {
        for (uint256 i; i < b.length; ++i) {
            result = (result << 8) | uint8(b[i]);
        }
    }
}
