#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Generate the test vectors in test_vectors/.

Usage: gen_test_vectors.py BLOCKS_DIR

BLOCKS_DIR holds the raw mainnet blocks 1, 586, 481823, 481828, 484645,
489125 and 976497 as <height>.bin, and signet block 331464 as
signet-331464.bin, for example from

    bitcoin-cli getblock $(bitcoin-cli getblockhash 586) 0 | xxd -r -p > 586.bin
    bitcoin-cli -signet getblock $(bitcoin-cli -signet getblockhash 331464) 0 | xxd -r -p > signet-331464.bin

The synthetic blocks are built here. Their transactions are not valid spends
and their headers carry no proof of work, which a proof verifier does not
look at. Some vectors use made-up trees instead of a block: for format 1 of
depth 32 or 33, where only the hashes on the proven paths exist, and for
format 2 with 16,666 or 16,667 made-up leaves.

The output is deterministic. Every vector is checked against the reference
verifier before it is written.
"""

import copy
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

if len(sys.argv) != 2:
    sys.exit(__doc__)
BLOCKS_DIR = sys.argv[1]

from reference import (  # noqa: E402
    COMMITMENT_PREFIX, FORMAT_PARTIAL_TREE, MAX_TREE_TRANSACTIONS, NULL_PREVOUT, ZERO_HASH, Entry,
    PartialTree, Proof, ProofError, build_partial_tree, fold_branch, make_proof, merkle_branch,
    parse_block, parse_proof, parse_transaction, proof_from_json, proof_from_json_text, proof_to_json,
    sha256d, tree_levels, verify, write_compact_size,
)

F2 = FORMAT_PARTIAL_TREE


def display(h: bytes) -> str:
    return h[::-1].hex()


def load_block(name) -> bytes:
    with open(os.path.join(BLOCKS_DIR, f"{name}.bin"), "rb") as f:
        return f.read()


# --- synthetic blocks -------------------------------------------------------

def serialize_tx(inputs, outputs, witness=None, version=2, locktime=0) -> bytes:
    out = struct.pack("<i", version)
    if witness is not None:
        out += b"\x00\x01"
    out += write_compact_size(len(inputs))
    for outpoint, script_sig, sequence in inputs:
        out += outpoint + write_compact_size(len(script_sig)) + script_sig + struct.pack("<I", sequence)
    out += write_compact_size(len(outputs))
    for value, script in outputs:
        out += struct.pack("<q", value) + write_compact_size(len(script)) + script
    if witness is not None:
        for stack in witness:
            out += write_compact_size(len(stack))
            for item in stack:
                out += write_compact_size(len(item)) + item
    return out + struct.pack("<I", locktime)


def dummy_tx(n: int, with_witness: bool) -> bytes:
    outpoint = sha256d(b"prevout %d" % n) + struct.pack("<I", n)
    script = bytes.fromhex("0014") + sha256d(b"key %d" % n)[:20]
    witness = [[sha256d(b"sig %d" % n) * 2, b"\x02" + sha256d(b"pub %d" % n)]] if with_witness else None
    return serialize_tx([(outpoint, b"", 0xfffffffd)], [(50_000 + n, script)], witness)


def merkle_root(leaves):
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def header_for(root: bytes) -> bytes:
    header = struct.pack("<i", 0x20000000) + sha256d(b"previous block") + root
    return header + struct.pack("<III", 1_700_000_000, 0x207fffff, 0)


COINBASE_INPUT = (NULL_PREVOUT, bytes.fromhex("03a08601") + b"synthetic", 0xffffffff)
MINER_OUTPUT = (5_000_000_000, bytes.fromhex("0014") + sha256d(b"miner")[:20])


def commitment_script(witness_root, reserved_value, extra=b""):
    return COMMITMENT_PREFIX + sha256d(witness_root + reserved_value) + extra


def synthetic_block(txs, commitment_scripts=None, witness_stack=None, first_tx=None) -> bytes:
    """Assemble a block from raw transactions.

    `commitment_scripts(witness_root)` returns the scripts of the extra
    coinbase outputs and `witness_stack` is the witness of the coinbase
    input. `first_tx` replaces the coinbase with other bytes.
    """
    witness_root = merkle_root([ZERO_HASH] + [parse_transaction(raw).wtxid for raw in txs])
    if first_tx is None:
        outputs = [MINER_OUTPUT]
        if commitment_scripts is not None:
            outputs += [(0, script) for script in commitment_scripts(witness_root)]
        witness = [witness_stack] if witness_stack is not None else None
        first_tx = serialize_tx([COINBASE_INPUT], outputs, witness)
    all_txs = [first_tx] + list(txs)
    header = header_for(merkle_root([parse_transaction(raw).txid for raw in all_txs]))
    return header + write_compact_size(len(all_txs)) + b"".join(all_txs)


def made_up_tree(depth: int, position: int) -> bytes:
    """A proof for one entry in a tree too deep to exist as a block.

    Only the hashes on the two proven paths are made up. The commitment in
    the coinbase and the Merkle root in the header are computed from them.
    """
    reserved = bytes(32)
    wtxid = sha256d(b"transaction in a made-up tree")
    branch = [sha256d(b"witness tree sibling %d" % i) for i in range(depth)]
    witness_root = fold_branch(wtxid, branch, position)
    coinbase = serialize_tx([COINBASE_INPUT], [MINER_OUTPUT, (0, commitment_script(witness_root, reserved))], [[reserved]])
    coinbase_branch = [sha256d(b"transaction tree sibling %d" % i) for i in range(depth)]
    root = fold_branch(parse_transaction(coinbase).txid, coinbase_branch, 0)
    return Proof(header_for(root), coinbase, coinbase_branch, [Entry(position, wtxid, branch)]).serialize()


def made_up_partial_tree(tx_count: int, position: int) -> bytes:
    """A format 2 proof for one leaf of a tree with tx_count made-up leaves,
    with a coinbase that commits to the made-up witness tree."""
    reserved = bytes(32)
    wleaves = [ZERO_HASH] + [sha256d(b"made-up wtxid %d" % i) for i in range(1, tx_count)]
    witness_root = tree_levels(wleaves)[-1][0]
    coinbase = serialize_tx([COINBASE_INPUT], [MINER_OUTPUT, (0, commitment_script(witness_root, reserved))],
                            [[reserved]])
    tleaves = [parse_transaction(coinbase).txid] + [sha256d(b"made-up txid %d" % i) for i in range(1, tx_count)]
    header = header_for(tree_levels(tleaves)[-1][0])
    tree = build_partial_tree(wleaves, [position])
    return Proof(header, coinbase, merkle_branch(tleaves, 0), tree=tree, format=F2).serialize()


RESERVED = bytes(32)
RESERVED_NONZERO = sha256d(b"reserved value")
WRONG = COMMITMENT_PREFIX + sha256d(b"not the witness root")
MIXED = [dummy_tx(1, True), dummy_tx(2, False), dummy_tx(3, True), dummy_tx(4, True)]
PLAIN = [dummy_tx(1, False), dummy_tx(2, False)]


# --- vectors ----------------------------------------------------------------

valid = []
invalid = []


def add_valid(comment, source, proof, segwit_active):
    result = verify(proof, segwit_active)
    json_form = proof_to_json(proof)
    assert proof_from_json(json_form) == proof
    valid.append({
        "comment": comment,
        "block": source,
        "segwit_active": segwit_active,
        "proof": proof.hex(),
        "json": json_form,
        "expected": {
            "block_hash": display(result.block_hash),
            "has_witness_commitment": result.has_witness_commitment,
            "coinbase_txid": display(result.coinbase_txid),
            "entries": [{"position": p, "wtxid": display(w)} for p, w in result.entries],
        },
    })
    return result


def expect_valid(comment, source, block, positions, segwit_active, fmt=1):
    """A proof built from a full block. The expected values come from the
    block, not from the verifier."""
    proof = make_proof(block, positions, segwit_active, fmt)
    header, txs = parse_block(block)
    result = add_valid(comment, source, proof, segwit_active)
    assert result.block_hash == sha256d(header)
    assert result.coinbase_txid == txs[0].txid
    wanted = sorted(set(p for p in positions if result.has_witness_commitment or p != 0))
    assert [p for p, _ in result.entries] == wanted
    assert all(txs[p].wtxid == w for p, w in result.entries)
    return proof


def expect_invalid(comment, source, proof, segwit_active, error):
    try:
        verify(proof, segwit_active)
    except ProofError as e:
        assert e.code == error, f"{comment}: got {e.code}, wanted {error}"
    else:
        raise AssertionError(f"{comment}: proof was accepted")
    invalid.append({
        "comment": comment,
        "block": source,
        "segwit_active": segwit_active,
        "proof": proof.hex(),
        "error": error,
    })


def mutate(proof: bytes, change) -> bytes:
    p = copy.deepcopy(parse_proof(proof))
    change(p)
    return p.serialize()


def replace_coinbase(proof: bytes, new_coinbase: bytes, wtxid_at_zero: bool = False) -> bytes:
    """Swap the coinbase bytes without parsing them, so that encodings the
    reference rejects can be written. The entry at position 0, if any, can
    be given the hash of the new bytes."""
    p = parse_proof(proof)
    out = proof[:81] + new_coinbase + proof[81 + len(p.coinbase_tx):]
    if wtxid_at_zero:
        assert p.entries and p.entries[0].position == 0
        offset = 81 + len(new_coinbase) + 1 + 32 * len(p.coinbase_branch) + 1 + 4
        out = out[:offset] + sha256d(new_coinbase) + out[offset + 32:]
    return out


def flip(h: bytes) -> bytes:
    return bytes([h[0] ^ 1]) + h[1:]


def position_of(block: bytes, txid_hex: str) -> int:
    return next(i for i, tx in enumerate(parse_block(block)[1]) if display(tx.txid) == txid_hex)


b1, b586, b481823 = load_block(1), load_block(586), load_block(481823)
b481828, b484645, b489125 = load_block(481828), load_block(484645), load_block(489125)

# Blocks before segwit activation.
expect_valid("Block with only a coinbase, no entries", "mainnet 1", b1, [], False)
p586_1 = expect_valid("One transaction in a block of three", "mainnet 586", b586, [1], False)
p586_2 = expect_valid("Last transaction of an odd level: its sibling is its own hash", "mainnet 586", b586, [2], False)
expect_valid("Two entries sharing one coinbase branch", "mainnet 586", b586, [1, 2], False)

n823 = len(parse_block(b481823)[1])
p823 = expect_valid(
    "Last block before activation: the coinbase has an output with the commitment pattern and no witness. "
    "Proven through the transaction tree",
    "mainnet 481823", b481823, [1, n823 - 1], False)

# Blocks after segwit activation.
p828_none = expect_valid(
    "Block with only a coinbase and a witness commitment, no entries: the reserved value is not verified",
    "mainnet 481828", b481828, [], True)
p828 = expect_valid(
    "Block with only a coinbase and a witness commitment: the entry at position 0 verifies the reserved value",
    "mainnet 481828", b481828, [0], True)
expect_valid("Block after activation without a commitment output", "mainnet 489125", b489125, [], True)

segwit_pos = position_of(b484645, "4ec907e083e0b9246a9d06192deba822457fab514baa6c5e7239ce0bc614f7bf")
txs645 = parse_block(b484645)[1]
plain_pos = next(i for i, tx in enumerate(txs645) if i and tx.witness is None)
last645 = len(txs645) - 1
p645 = expect_valid("Transaction with witness data, proven through the witness tree",
                    "mainnet 484645", b484645, [segwit_pos], True)
expect_valid(
    "Transaction without witness data in a block with a witness commitment: also proven through the witness tree",
    "mainnet 484645", b484645, [plain_pos], True)
p645_last = expect_valid("Last transaction of a block with an odd number of transactions",
                         "mainnet 484645", b484645, [last645], True)
expect_valid("Coinbase and three other transactions in one proof",
             "mainnet 484645", b484645, sorted({0, plain_pos, segwit_pos, last645}), True)

# Recent blocks.
b976497, b_signet = load_block(976497), load_block("signet-331464")
txs976 = parse_block(b976497)[1]
cb976 = txs976[0]
commitment_index = max(i for i, (_, script) in enumerate(cb976.outputs)
                       if len(script) >= 38 and script[:6] == COMMITMENT_PREFIX)
assert commitment_index < len(cb976.outputs) - 1
last976 = len(txs976) - 1
first_witness976 = next(i for i, tx in enumerate(txs976) if i and tx.witness is not None)
p976_last = expect_valid(
    "Recent block: the commitment output is followed by other outputs; the coinbase, a transaction "
    "with witness data and the last transaction",
    "mainnet 976497", b976497, [0, first_witness976, last976], True)
txs_signet = parse_block(b_signet)[1]
assert len(txs_signet[0].outputs[1][1]) > 38
expect_valid("Signet block: the commitment output also carries the signet solution",
             "signet 331464", b_signet, [0, next(i for i, tx in enumerate(txs_signet) if i and tx.witness)], True)

# Synthetic blocks.
s_two = synthetic_block(MIXED, lambda root: [WRONG, commitment_script(root, RESERVED)], [RESERVED])
s_first = synthetic_block(MIXED, lambda root: [commitment_script(root, RESERVED), WRONG], [RESERVED])
s_trailing = synthetic_block(
    MIXED, lambda root: [commitment_script(root, RESERVED_NONZERO, b"\x51\x52")], [RESERVED_NONZERO])
s_short = synthetic_block(PLAIN, lambda root: [COMMITMENT_PREFIX + bytes(31)])
s_long = synthetic_block(MIXED, lambda root: [commitment_script(root, RESERVED, bytes(262))], [RESERVED])
s_many = synthetic_block([dummy_tx(i, False) for i in range(1, 254)])

expect_valid("Two outputs match the commitment pattern: the one with the highest index is used",
             "synthetic", s_two, [1, 3], True)
expect_valid("Commitment output longer than 38 bytes, reserved value other than zero",
             "synthetic", s_trailing, [2, 4], True)
expect_valid("An output of 37 bytes that starts with the commitment prefix is not a commitment",
             "synthetic", s_short, [1, 2], True)
expect_valid("Commitment output of 300 bytes: its length takes a three-byte compact size integer",
             "synthetic", s_long, [2], True)
expect_valid("253 entries: the entry count takes a three-byte compact size integer",
             "synthetic", s_many, list(range(1, 254)), True)
add_valid("Depth 32 and position 0xffffffff, in a made-up tree",
          "synthetic", made_up_tree(32, 0xffffffff), True)

# Format 2.
expect_valid("Format 2: two transactions in a block without a commitment", "mainnet 586", b586, [1, 2], False, F2)
spread823 = [1 + (i * (n823 - 1)) // 10 for i in range(10)]
p823_f2 = expect_valid(
    "Format 2: ten transactions spread over the last block before activation, in the transaction tree",
    "mainnet 481823", b481823, spread823, False, F2)
p828_f2 = expect_valid(
    "Format 2: the coinbase alone in a block with a witness commitment; the tree is the zero leaf",
    "mainnet 481828", b481828, [0], True, F2)
p645_f2 = expect_valid("Format 2: the coinbase and three other transactions", "mainnet 484645", b484645,
                       sorted({0, plain_pos, segwit_pos, last645}), True, F2)
p645_f2_one = expect_valid("Format 2: one transaction with witness data", "mainnet 484645", b484645,
                           [segwit_pos], True, F2)
expect_valid(
    "Format 2: recent block; the coinbase, a transaction with witness data, every 500th transaction and the last one",
    "mainnet 976497", b976497, sorted({0, first_witness976, last976} | set(range(1, last976, 500))), True, F2)
p_signet_f2 = expect_valid("Format 2: every transaction of a signet block", "signet 331464", b_signet,
                           list(range(len(txs_signet))), True, F2)
expect_valid("Format 2: two outputs match the commitment pattern, the one with the highest index is used",
             "synthetic", s_two, [1, 3], True, F2)
expect_valid("Format 2: an output of 37 bytes that starts with the commitment prefix is not a commitment; "
             "the transaction tree is used", "synthetic", s_short, [1, 2], True, F2)
expect_valid("Format 2: 253 transactions; the hash count takes a three-byte compact size integer",
             "synthetic", s_many, list(range(1, 254)), True, F2)
add_valid("Format 2: 16,666 made-up leaves, the largest transaction count allowed", "synthetic",
          made_up_partial_tree(MAX_TREE_TRANSACTIONS, MAX_TREE_TRANSACTIONS - 1), True)


# Encoding errors.
expect_invalid("Unknown format byte", "mainnet 586", b"\x03" + p586_1[1:], False, "BAD_FORMAT")
expect_invalid("Proof cut short", "mainnet 586", p586_1[:-1], False, "TRUNCATED")
expect_invalid("One byte after the last entry", "mainnet 586", p586_1 + b"\x00", False, "TRAILING_DATA")
expect_invalid("Depth 33, in a made-up tree where every hash is consistent", "synthetic",
               made_up_tree(33, 0xffffffff), True, "BAD_DEPTH")
count_offset = 81 + len(parse_proof(p586_1).coinbase_tx) + 1 + 32 * len(parse_proof(p586_1).coinbase_branch)
expect_invalid("Entry count not in its shortest encoding", "mainnet 586",
               p586_1[:count_offset] + b"\xfd\x01\x00" + p586_1[count_offset + 1:], False, "BAD_ENCODING")

cb828 = parse_proof(p828).coinbase_tx
# The coinbase of block 481828 ends with: 01 (one item), 20 (32 bytes), the item, and the lock time.
assert cb828[-38:-36] == b"\x01\x20" and cb828[4:6] == b"\x00\x01"
expect_invalid(
    "Number of witness items of the coinbase not in its shortest encoding. "
    "The entry gives the hash of the coinbase bytes as they are in the proof",
    "mainnet 481828", replace_coinbase(p828, cb828[:-38] + b"\xfd\x01\x00" + cb828[-37:], True), True, "BAD_ENCODING")
expect_invalid(
    "Flag byte 0x02 after the marker. The entry gives the hash of the coinbase bytes as they are in the proof",
    "mainnet 481828", replace_coinbase(p828, cb828[:5] + b"\x02" + cb828[6:], True), True, "BAD_ENCODING")
cb586 = parse_proof(p586_1).coinbase_tx
expect_invalid("Coinbase with the marker and flag and a witness without items", "mainnet 586",
               replace_coinbase(p586_1, cb586[:4] + b"\x00\x01" + cb586[4:-4] + b"\x00" + cb586[-4:]),
               False, "BAD_ENCODING")

# Coinbase checks.
txs586 = parse_block(b586)[1]


def not_a_coinbase(p):
    p.coinbase_tx = txs586[1].raw
    p.coinbase_branch = merkle_branch([tx.txid for tx in txs586], 1)


expect_invalid("First transaction of the proof is not a coinbase", "mainnet 586",
               mutate(p586_1, not_a_coinbase), False, "NOT_COINBASE")
other_input = (sha256d(b"another output") + struct.pack("<I", 0), b"", 0xffffffff)
for comment, inputs in (
    ("First transaction has two inputs, and the first one spends the null outpoint", [COINBASE_INPUT, other_input]),
    ("Input of the first transaction has a hash of 32 zero bytes and index 0",
     [(bytes(32) + struct.pack("<I", 0), COINBASE_INPUT[1], 0xffffffff)]),
    ("Input of the first transaction has index 0xffffffff and a hash that is not zero",
     [(sha256d(b"not zero") + b"\xff\xff\xff\xff", COINBASE_INPUT[1], 0xffffffff)]),
):
    block = synthetic_block(PLAIN, first_tx=serialize_tx(inputs, [MINER_OUTPUT]))
    header, txs = parse_block(block)
    proof = Proof(header, txs[0].raw, merkle_branch([tx.txid for tx in txs], 0)).serialize()
    expect_invalid(comment, "synthetic", proof, False, "NOT_COINBASE")
expect_invalid("Coinbase branch with one altered hash", "mainnet 586",
               mutate(p586_1, lambda p: p.coinbase_branch.__setitem__(0, flip(p.coinbase_branch[0]))),
               False, "COINBASE_NOT_IN_BLOCK")

# Entry checks.
expect_invalid("Entries not in increasing order of position", "mainnet 586",
               mutate(make_proof(b586, [1, 2], False), lambda p: p.entries.reverse()), False, "BAD_ENTRY_ORDER")
expect_invalid("The same position twice", "mainnet 586",
               mutate(p586_1, lambda p: p.entries.append(copy.deepcopy(p.entries[0]))), False, "BAD_ENTRY_ORDER")
expect_invalid("Position 5 for the transaction at position 1 of a tree of depth 2: the low bits fold to the root",
               "mainnet 586", mutate(p586_1, lambda p: setattr(p.entries[0], "position", 1 + 4)), False, "BAD_POSITION")
expect_invalid("Position 35 for the transaction at position 3 of a tree of depth 5, in the witness tree",
               "mainnet 484645", mutate(p645, lambda p: setattr(p.entries[0], "position", segwit_pos + 32)),
               True, "BAD_POSITION")
expect_invalid("Position 4, which is 2 to the power of the depth, with the txid and branch of the coinbase transaction",
               "mainnet 586",
               mutate(p586_1, lambda p: p.entries.__setitem__(0, Entry(4, txs586[0].wtxid, list(p.coinbase_branch)))),
               False, "BAD_POSITION")
expect_invalid("Entry branch with one altered hash, in the transaction tree", "mainnet 586",
               mutate(p586_1, lambda p: p.entries[0].branch.__setitem__(0, flip(p.entries[0].branch[0]))),
               False, "MERKLE_ROOT_MISMATCH")
expect_invalid("Entry for the coinbase in a block without a commitment", "mainnet 586",
               mutate(p586_1, lambda p: p.entries.insert(0, Entry(0, txs586[0].wtxid, list(p.coinbase_branch)))),
               False, "COINBASE_ENTRY")
expect_invalid("Position 3 claimed for the transaction at position 2 of a three-transaction block", "mainnet 586",
               mutate(p586_2, lambda p: setattr(p.entries[0], "position", 3)), False, "DUPLICATE_SIBLING")
expect_invalid("Position 29 claimed for the transaction at position 28 of a 29-transaction block", "mainnet 484645",
               mutate(p645_last, lambda p: setattr(p.entries[0], "position", last645 + 1)), True, "DUPLICATE_SIBLING")
assert n823 == 1696
expect_invalid(
    "Position 1727 claimed for the transaction at position 1695 of a 1696-transaction block: "
    "the node that is hashed with itself is five levels above the leaves",
    "mainnet 481823", mutate(p823, lambda p: setattr(p.entries[1], "position", 1695 + 32)), False, "DUPLICATE_SIBLING")

p976_only_last = make_proof(b976497, [last976], True)


def phantom_position(block: bytes, position: int) -> int:
    """The first position past the last transaction where the branch of
    `position` reaches the root if the duplicate check is left out."""
    header, txs = parse_block(block)
    leaves = [ZERO_HASH] + [tx.wtxid for tx in txs[1:]]
    branch = merkle_branch(leaves, position)
    witness_root = merkle_root(leaves)
    for p in range(len(txs), 1 << len(branch)):
        node, q = txs[position].wtxid, p
        for sibling in branch:
            node = sha256d(sibling + node) if q & 1 else sha256d(node + sibling)
            q >>= 1
        if node == witness_root:
            return p
    raise AssertionError("no phantom position")


p_phantom = phantom_position(b976497, last976)
expect_invalid(
    f"Position {p_phantom} claimed for the transaction at position {last976} of a {last976 + 1}-transaction block, "
    "in the witness tree",
    "mainnet 976497", mutate(p976_only_last, lambda p: setattr(p.entries[0], "position", p_phantom)),
    True, "DUPLICATE_SIBLING")

# Commitment checks.
stripped645 = parse_transaction(parse_proof(p645).coinbase_tx).stripped
expect_invalid("Coinbase transaction of a block with a witness commitment, serialized without its witness",
               "mainnet 484645", mutate(p645, lambda p: setattr(p, "coinbase_tx", stripped645)),
               True, "BAD_RESERVED_VALUE")


def txid_entry(p):
    p.entries[0].wtxid = txs645[segwit_pos].txid
    p.entries[0].branch = merkle_branch([tx.txid for tx in txs645], segwit_pos)


def stripped_witness_attack(p):
    # The prover hides the witness of the coinbase and of the transaction, and
    # offers the txid with its branch in the transaction tree.
    p.coinbase_tx = stripped645
    txid_entry(p)


expect_invalid("Coinbase serialized without its witness, with the txid and transaction tree branch "
               "of a transaction that has witness data in the block",
               "mainnet 484645", mutate(p645, stripped_witness_attack), True, "BAD_RESERVED_VALUE")
expect_invalid("Txid and transaction tree branch offered for a transaction that has witness data in the block",
               "mainnet 484645", mutate(p645, txid_entry), True, "COMMITMENT_MISMATCH")
expect_invalid("Entry branch with one altered hash, in the witness tree", "mainnet 484645",
               mutate(p645, lambda p: p.entries[0].branch.__setitem__(0, flip(p.entries[0].branch[0]))),
               True, "COMMITMENT_MISMATCH")
expect_invalid("Wtxid of a transaction that is not in the block", "mainnet 484645",
               mutate(p645, lambda p: setattr(p.entries[0], "wtxid", sha256d(b"absent"))), True, "COMMITMENT_MISMATCH")


def alter_reserved_value(p):
    cb = p.coinbase_tx
    p.coinbase_tx = cb[:-36] + bytes([cb[-36] ^ 1]) + cb[-35:]


expect_invalid("Witness reserved value altered", "mainnet 484645", mutate(p645, alter_reserved_value),
               True, "COMMITMENT_MISMATCH")
expect_invalid("Entry at position 0 with a wtxid that is not the coinbase's", "mainnet 481828",
               mutate(p828, lambda p: setattr(p.entries[0], "wtxid", ZERO_HASH)), True, "COINBASE_WTXID_MISMATCH")
expect_invalid("Only the first of two commitment outputs matches the witness tree", "synthetic",
               make_proof(s_first, [1, 3], True), True, "COMMITMENT_MISMATCH")
long_item = bytes(33)
expect_invalid("Reserved value of 33 bytes, with a commitment hash computed from those 33 bytes", "synthetic",
               make_proof(synthetic_block(MIXED, lambda root: [commitment_script(root, long_item)], [long_item]),
                          [1], True),
               True, "BAD_RESERVED_VALUE")
expect_invalid("Two witness items of 32 bytes, with a commitment hash computed from the first", "synthetic",
               make_proof(synthetic_block(MIXED, lambda root: [commitment_script(root, RESERVED)],
                                          [RESERVED, RESERVED_NONZERO]), [1], True),
               True, "BAD_RESERVED_VALUE")

# The activation input.
expect_invalid("Proof for a block before activation, checked as if segwit were active", "mainnet 481823",
               p823, True, "BAD_RESERVED_VALUE")
expect_invalid("Proof for a block after activation, checked as if segwit were not active", "mainnet 484645",
               p645, False, "UNEXPECTED_WITNESS")


def add_coinbase_witness(p):
    cb = parse_transaction(p.coinbase_tx)
    p.coinbase_tx = serialize_tx(
        [(i[0], i[1], struct.unpack("<I", i[2])[0]) for i in cb.inputs],
        [(struct.unpack("<q", o[0])[0], o[1]) for o in cb.outputs],
        [[bytes(32)]],
        version=struct.unpack("<i", cb.stripped[:4])[0],
        locktime=struct.unpack("<I", cb.stripped[-4:])[0],
    )


expect_invalid("Witness added to the coinbase of a block without a commitment", "mainnet 586",
               mutate(p586_1, add_coinbase_witness), False, "UNEXPECTED_WITNESS")
expect_invalid("Witness added to the coinbase of a block after activation that has no commitment output",
               "mainnet 489125", mutate(make_proof(b489125, [], True), add_coinbase_witness), True,
               "UNEXPECTED_WITNESS")


# Format 2 checks.
def tree_change(proof: bytes, change) -> bytes:
    p = copy.deepcopy(parse_proof(proof))
    change(p.tree)
    return p.serialize()


def with_tree(proof: bytes, tree: PartialTree) -> bytes:
    p = copy.deepcopy(parse_proof(proof))
    p.tree = tree
    return p.serialize()


txids586 = [tx.txid for tx in txs586]
wleaves645 = [ZERO_HASH] + [tx.wtxid for tx in txs645[1:]]
wleaves976 = [ZERO_HASH] + [tx.wtxid for tx in txs976[1:]]
p586_f2 = make_proof(b586, [1, 2], False, F2)

expect_invalid("Format 2: transaction count of zero in a block whose only transaction is the coinbase transaction",
               "mainnet 481828", tree_change(p828_f2, lambda t: setattr(t, "tx_count", 0)), True, "BAD_TX_COUNT")
expect_invalid("Format 2: transaction count whose tree is deeper than the coinbase branch", "mainnet 484645",
               tree_change(p645_f2_one, lambda t: setattr(t, "tx_count", 33)), True, "BAD_TX_COUNT")
expect_invalid("Format 2: transaction count whose tree is shallower than the coinbase branch", "mainnet 484645",
               tree_change(p645_f2_one, lambda t: setattr(t, "tx_count", 16)), True, "BAD_TX_COUNT")
expect_invalid("Format 2: 16,667 made-up leaves, one more than allowed", "synthetic",
               made_up_partial_tree(MAX_TREE_TRANSACTIONS + 1, MAX_TREE_TRANSACTIONS), True, "BAD_TX_COUNT")
expect_invalid("Format 2: more hashes than transactions", "mainnet 481828",
               tree_change(p828_f2, lambda t: t.hashes.append(sha256d(b"extra"))), True, "BAD_PARTIAL_TREE")
expect_invalid("Format 2: fewer flag bits than hashes", "signet 331464",
               tree_change(p_signet_f2, lambda t: setattr(t, "flags", t.flags[:1])), True, "BAD_PARTIAL_TREE")
expect_invalid("Format 2: the flag bits run out during the traversal", "signet 331464",
               tree_change(p_signet_f2, lambda t: setattr(t, "flags", t.flags[:2])), True, "BAD_PARTIAL_TREE")
expect_invalid("Format 2: one hash missing", "signet 331464",
               tree_change(p_signet_f2, lambda t: t.hashes.pop()), True, "BAD_PARTIAL_TREE")
expect_invalid("Format 2: one hash left over", "mainnet 484645",
               tree_change(p645_f2_one, lambda t: t.hashes.append(sha256d(b"extra"))), True, "BAD_PARTIAL_TREE")
expect_invalid("Format 2: one flag byte left over", "mainnet 484645",
               tree_change(p645_f2_one, lambda t: setattr(t, "flags", t.flags + b"\x00")), True, "BAD_PARTIAL_TREE")


def set_padding_bit(t):
    # The tree uses 11 flag bits, so bits 3 to 7 of the second byte are padding.
    assert len(t.flags) == 2 and t.flags[1] >> 3 == 0
    t.flags = t.flags[:1] + bytes([t.flags[1] | 0x80])


expect_invalid("Format 2: a padding bit of the last flag byte is set", "mainnet 484645",
               tree_change(p645_f2_one, set_padding_bit), True, "NONZERO_PADDING")
expect_invalid("Format 2: transaction count of 4 for a three-transaction block, with the third leaf repeated",
               "mainnet 586", with_tree(p586_f2, build_partial_tree(txids586 + [txids586[2]], [3])),
               False, "DUPLICATE_SIBLING")
expect_invalid("Format 2: transaction count of 7072 for a 7064-transaction block, with the last eight leaves repeated",
               "mainnet 976497",
               with_tree(make_proof(b976497, [last976], True, F2),
                         build_partial_tree(wleaves976 + wleaves976[7056:7064], [7071])),
               True, "DUPLICATE_SIBLING")
expect_invalid("Format 2: no transaction matched", "mainnet 484645",
               with_tree(p645_f2_one, build_partial_tree(wleaves645, [])), True, "NO_MATCH")
expect_invalid("Format 2: the coinbase matched in a block without a commitment", "mainnet 586",
               with_tree(p586_f2, build_partial_tree(txids586, [0, 1])), False, "COINBASE_ENTRY")
expect_invalid("Format 2: the coinbase matched with its wtxid as the leaf instead of zero", "mainnet 484645",
               with_tree(p645_f2_one, build_partial_tree([txs645[0].wtxid] + wleaves645[1:], [0])),
               True, "COINBASE_LEAF_NOT_ZERO")
expect_invalid("Format 2: one hash altered, in the witness tree", "mainnet 484645",
               tree_change(p645_f2, lambda t: t.hashes.__setitem__(-1, flip(t.hashes[-1]))), True, "COMMITMENT_MISMATCH")
expect_invalid("Format 2: transaction tree used in a block with a witness commitment", "mainnet 484645",
               with_tree(p645_f2_one, build_partial_tree([tx.txid for tx in txs645], [segwit_pos])),
               True, "COMMITMENT_MISMATCH")
expect_invalid("Format 2: one hash altered, in the transaction tree", "mainnet 481823",
               tree_change(p823_f2, lambda t: t.hashes.__setitem__(0, flip(t.hashes[0]))), False, "MERKLE_ROOT_MISMATCH")
expect_invalid("Format 2: only the first of two commitment outputs matches the witness tree", "synthetic",
               make_proof(s_first, [1, 3], True, F2), True, "COMMITMENT_MISMATCH")


def stripped_witness_attack_f2(p):
    p.coinbase_tx = stripped645
    p.tree = build_partial_tree([tx.txid for tx in txs645], [segwit_pos])


expect_invalid("Format 2: coinbase serialized without its witness, with a transaction tree for a transaction "
               "that has witness data", "mainnet 484645", mutate(p645_f2_one, stripped_witness_attack_f2),
               True, "BAD_RESERVED_VALUE")
expect_invalid("Format 2: proof for a block after activation, checked as if segwit were not active",
               "mainnet 484645", p645_f2, False, "UNEXPECTED_WITNESS")
count_at = 81 + len(parse_proof(p645_f2_one).coinbase_tx) + 1 + 32 * 5 + 4
assert p645_f2_one[count_at] == len(parse_proof(p645_f2_one).tree.hashes)
expect_invalid("Format 2: hash count not in its shortest encoding", "mainnet 484645",
               p645_f2_one[:count_at] + b"\xfd" + bytes([p645_f2_one[count_at], 0]) + p645_f2_one[count_at + 1:],
               True, "BAD_ENCODING")
expect_invalid("Format 2: proof cut short in the flag bytes", "mainnet 484645", p645_f2_one[:-1], True, "TRUNCATED")

# JSON form. These vectors are JSON texts, so that repeated keys and the
# way numbers are written reach the reader as they are.
json_equivalent = []
json_invalid = []


def as_text(value) -> str:
    return value if isinstance(value, str) else json.dumps(value)


def json_same(comment, value, proof):
    text = as_text(value)
    assert proof_from_json_text(text) == proof, comment
    json_equivalent.append({"comment": comment, "text": text, "proof": proof.hex()})


def json_bad(comment, value):
    text = as_text(value)
    try:
        proof_from_json_text(text)
    except ProofError as e:
        assert e.code == "BAD_JSON", comment
    else:
        raise AssertionError(comment)
    json_invalid.append({"comment": comment, "text": text, "error": "BAD_JSON"})


def with_raw(obj, raw: str) -> str:
    """The text of obj with the string "RAW" replaced by raw JSON text."""
    text = json.dumps(obj)
    assert text.count('"RAW"') == 1
    return text.replace('"RAW"', raw)


j1 = proof_to_json(p586_1)
j2 = proof_to_json(p645_f2_one)
json_same("Format 1 with a key the format does not define, which is ignored", dict(j1, blockhash=display(sha256d(b"x"))), p586_1)
json_same("Format 1 with upper case hex digits",
          dict(j1, header=j1["header"].upper(), coinbase_tx=j1["coinbase_tx"].upper(),
               coinbase_branch=[h.upper() for h in j1["coinbase_branch"]]), p586_1)
json_same("Format 2 with a key the format does not define and upper case flags",
          dict(j2, height=484645, flags=j2["flags"].upper()), p645_f2_one)
json_same("Entry with a key the format does not define, which is ignored",
          dict(j1, entries=[dict(j1["entries"][0], note="ignored")]), p586_1)
escaped = json.dumps(j1).replace('"header": "0', '"header": "\\u0030', 1)
assert escaped != json.dumps(j1)
json_same("The first hex digit of the header written as an escape sequence, \\u0030", escaped, p586_1)
json_same("A key the format does not define with a number written with a fraction, which is ignored",
          dict(j1, fee_rate=1.5), p586_1)
json_same("A key the format does not define, given twice, which is ignored",
          json.dumps(dict(j1, extra=1))[:-1] + ', "extra": 2}', p586_1)
json_same("A key repeated inside the value of a key the format does not define, which is ignored",
          with_raw(dict(j1, extra="RAW"), '{"a": 1, "a": 2}'), p586_1)


def without(obj, key):
    return {k: v for k, v in obj.items() if k != key}


json_bad("Not an object", [j1])
json_bad("No format", without(j1, "format"))
json_bad("Format 3", dict(j1, format=3))
json_bad("Format given as a string", dict(j1, format="1"))
json_bad("Format given as true", dict(j1, format=True))
json_bad("Header of 79 bytes", dict(j1, header=j1["header"][:-2]))
json_bad("Coinbase transaction with an odd number of hex digits", dict(j1, coinbase_tx=j1["coinbase_tx"][:-1]))
json_bad("Coinbase transaction with a character that is not a hex digit", dict(j1, coinbase_tx="zz" + j1["coinbase_tx"][2:]))
json_bad("Coinbase branch hash of 31 bytes", dict(j1, coinbase_branch=[j1["coinbase_branch"][0][:-2]] + j1["coinbase_branch"][1:]))
json_bad("Coinbase branch that is not a list", dict(j1, coinbase_branch=j1["coinbase_branch"][0]))
json_bad("Coinbase branch of 33 hashes, with no entries",
         dict(j1, coinbase_branch=[display(sha256d(b"hash %d" % i)) for i in range(33)], entries=[]))
json_bad("Format 1 without entries", without(j1, "entries"))
json_bad("Format 1 entry that is not an object", dict(j1, entries=["00"]))
json_bad("Negative position", dict(j1, entries=[dict(j1["entries"][0], pos=-1)]))
json_bad("Position that is not an integer", dict(j1, entries=[dict(j1["entries"][0], pos=1.5)]))
json_bad("Position given as a string", dict(j1, entries=[dict(j1["entries"][0], pos="1")]))
json_bad("Position of 2 to the power of 32", dict(j1, entries=[dict(j1["entries"][0], pos=1 << 32)]))
json_bad("Entry without a wtxid", dict(j1, entries=[without(j1["entries"][0], "wtxid")]))
json_bad("Entry branch shorter than the coinbase branch",
         dict(j1, entries=[dict(j1["entries"][0], branch=j1["entries"][0]["branch"][:-1])]))
json_bad("Format 2 without hashes", without(j2, "hashes"))
json_bad("Format 2 without a transaction count", without(j2, "tx_count"))
json_bad("Format 2 with a negative transaction count", dict(j2, tx_count=-1))
json_bad("Format 2 without flags", without(j2, "flags"))
json_bad("Format 2 flags with an odd number of hex digits", dict(j2, flags=j2["flags"][:-1]))
json_bad("Position written as 1.0", with_raw(dict(j1, entries=[dict(j1["entries"][0], pos="RAW")]), "1.0"))
json_bad("Position written as -0", with_raw(dict(j1, entries=[dict(j1["entries"][0], pos="RAW")]), "-0"))
assert j2["tx_count"] == 29
json_bad("Transaction count written with an exponent, as 2.9e1", with_raw(dict(j2, tx_count="RAW"), "2.9e1"))

# Repeated keys. With format given twice and the keys of both formats, a
# reader that keeps the first value and one that keeps the last would read
# two different valid proofs.
both = dict(proof_to_json(p586_f2), entries=j1["entries"])
assert proof_from_json(both) == p586_f2 and proof_from_json(dict(both, format=1)) == p586_1
both_text = json.dumps(both)
assert both_text.startswith('{"format": 2,') and both_text.endswith("}")
json_bad("The key format twice, as 2 and then as 1, with the keys of both formats; either value alone gives a valid proof",
         both_text[:-1] + ', "format": 1}')
json_bad("The key format twice, as 2 and then as 1 written with an escape sequence, \\u0066ormat, "
         "with the keys of both formats",
         both_text[:-1] + ', "\\u0066ormat": 1}')
dup_pos = json.dumps(j1).replace('"pos": 1,', '"pos": 1, "pos": 1,')
assert dup_pos.count('"pos": 1,') == 2
json_bad("The key pos twice in an entry, with the same value", dup_pos)
json_bad("NaN, which is not JSON, as the value of a key the format does not define",
         with_raw(dict(j1, extra="RAW"), "NaN"))


def shifted_coinbase(proof: bytes):
    """The JSON form of a format 2 proof with the end of coinbase_tx moved
    into coinbase_branch, so that the fields still serialize to the bytes
    of the proof."""
    p = parse_proof(proof)
    coinbase, depth = p.coinbase_tx, len(p.coinbase_branch)
    for cut in range(len(coinbase) - 32, 0, -32):
        new_depth = coinbase[cut]
        if new_depth != depth + (len(coinbase) - cut) // 32 or new_depth > 32:
            continue
        rest = coinbase[cut + 1:] + bytes([depth]) + b"".join(p.coinbase_branch)
        assert len(rest) == 32 * new_depth
        tail = proof[81 + len(coinbase) + 1 + 32 * depth:]
        assert bytes([p.format]) + p.header + coinbase[:cut] + bytes([new_depth]) + rest + tail == proof
        obj = dict(proof_to_json(proof), coinbase_tx=coinbase[:cut].hex(),
                   coinbase_branch=[display(rest[i:i + 32]) for i in range(0, len(rest), 32)])
        return obj, len(coinbase) - cut
    raise AssertionError("the proof does not allow the shift")


# The coinbase transaction ends with its witness reserved value and its lock
# time, so byte 4 of the reserved value is the byte 32 positions before the
# end. Setting it to the depth plus one lets 32 bytes move.
SHIFT_RESERVED = bytes([0, 0, 0, 0, 4]) + bytes(27)
s_shift = synthetic_block(MIXED, lambda root: [commitment_script(root, SHIFT_RESERVED)], [SHIFT_RESERVED])
p_shift = make_proof(s_shift, [1, 3], True, F2)
assert len(parse_proof(p_shift).coinbase_branch) == 3
verify(p_shift, True)
shifted, moved = shifted_coinbase(p_shift)
json_bad(f"coinbase_tx without its last {moved} bytes, which are moved into coinbase_branch, so that the fields "
         "serialize to a format 2 proof that verifies with segwit active", shifted)
json_bad("Format 2 flags given as a list of numbers", dict(j2, flags=list(bytes.fromhex(j2["flags"]))))
json_bad("Format 2 with a transaction count of 2 to the power of 32", dict(j2, tx_count=1 << 32))
json_bad("Coinbase transaction with spaces between the hex digits",
         dict(j1, coinbase_tx=j1["coinbase_tx"][:2] + " " + j1["coinbase_tx"][2:] + " "))


def write(name, vectors):
    path = os.path.join(HERE, "test_vectors", name)
    with open(path, "w") as f:
        json.dump(vectors, f, indent=2)
        f.write("\n")
    count = len(vectors) if isinstance(vectors, list) else sum(len(v) for v in vectors.values())
    print(f"{name}: {count} vectors, {os.path.getsize(path)} bytes")


write("valid.json", valid)
write("invalid.json", invalid)
write("json.json", {"equivalent": json_equivalent, "invalid": json_invalid})
