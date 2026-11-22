#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Reference implementation of witness transaction inclusion proofs.

Standard library only. Hashes are handled in internal byte order, the
order in which they are hashed. Hex strings shown to users (txids, block
hashes, and the hashes of the JSON form) use the reversed order, as
elsewhere in Bitcoin software.
"""

import bisect
import hashlib
import json
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

FORMAT_BRANCHES = 1
FORMAT_PARTIAL_TREE = 2
MAX_DEPTH = 32
# Bitcoin Core's partial Merkle tree code accepts at most this many
# transactions: the maximum block weight divided by the minimum weight of a
# transaction, 4,000,000 / 240.
MAX_TREE_TRANSACTIONS = 16666
HEADER_SIZE = 80
ZERO_HASH = bytes(32)
NULL_PREVOUT = bytes(32) + b"\xff\xff\xff\xff"
# OP_RETURN, push of 36 bytes, 4-byte commitment header (BIP 141).
COMMITMENT_PREFIX = bytes.fromhex("6a24aa21a9ed")
MIN_COMMITMENT_SCRIPT_SIZE = 38


class ProofError(Exception):
    """A proof that must be rejected. `code` names the first failed check."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ProofError("TRUNCATED")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def compact_size(self) -> int:
        first = self.read(1)[0]
        if first < 0xfd:
            return first
        if first == 0xfd:
            value, minimum = int.from_bytes(self.read(2), "little"), 0xfd
        elif first == 0xfe:
            value, minimum = int.from_bytes(self.read(4), "little"), 0x10000
        else:
            value, minimum = int.from_bytes(self.read(8), "little"), 0x100000000
        # Only the shortest encoding is accepted, as in Bitcoin Core.
        if value < minimum:
            raise ProofError("BAD_ENCODING")
        return value


def write_compact_size(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


@dataclass
class Transaction:
    raw: bytes                    # as serialized, with witness data if any
    stripped: bytes               # serialization without witness data
    inputs: List[Tuple[bytes, bytes, bytes]]    # (outpoint, scriptSig, sequence)
    outputs: List[Tuple[bytes, bytes]]          # (value, scriptPubKey)
    witness: Optional[List[List[bytes]]]        # one stack per input, or None

    @property
    def txid(self) -> bytes:
        return sha256d(self.stripped)

    @property
    def wtxid(self) -> bytes:
        return sha256d(self.raw)

    def is_coinbase(self) -> bool:
        return len(self.inputs) == 1 and self.inputs[0][0] == NULL_PREVOUT


def read_transaction(r: Reader) -> Transaction:
    """Parse one transaction in the BIP 144 serialization."""
    start = r.pos
    version = r.read(4)
    body_start = r.pos
    n_in = r.compact_size()
    has_witness = False
    if n_in == 0:
        # Marker byte seen: the next byte must be the flag 0x01.
        if r.read(1) != b"\x01":
            raise ProofError("BAD_ENCODING")
        has_witness = True
        body_start = r.pos
        n_in = r.compact_size()
    inputs = []
    for _ in range(n_in):
        outpoint = r.read(36)
        script_sig = r.read(r.compact_size())
        sequence = r.read(4)
        inputs.append((outpoint, script_sig, sequence))
    outputs = []
    for _ in range(r.compact_size()):
        value = r.read(8)
        script_pubkey = r.read(r.compact_size())
        outputs.append((value, script_pubkey))
    body_end = r.pos
    witness = None
    if has_witness:
        witness = [[r.read(r.compact_size()) for _ in range(r.compact_size())]
                   for _ in range(n_in)]
        # A witness serialization whose stacks are all empty is not valid.
        if not any(witness):
            raise ProofError("BAD_ENCODING")
    locktime = r.read(4)
    return Transaction(
        raw=r.data[start:r.pos],
        stripped=version + r.data[body_start:body_end] + locktime,
        inputs=inputs,
        outputs=outputs,
        witness=witness,
    )


def parse_transaction(data: bytes) -> Transaction:
    r = Reader(data)
    tx = read_transaction(r)
    if r.pos != len(data):
        raise ProofError("TRAILING_DATA")
    return tx


def witness_commitment(coinbase: Transaction) -> Optional[bytes]:
    """The 32-byte commitment hash from the coinbase, or None.

    BIP 141: if more than one output matches the pattern, the one with the
    highest index is the commitment.
    """
    found = None
    for _, script in coinbase.outputs:
        if len(script) >= MIN_COMMITMENT_SCRIPT_SIZE and script[:6] == COMMITMENT_PREFIX:
            found = script[6:38]
    return found


# --- Merkle trees -----------------------------------------------------------

def tree_width(tx_count: int, height: int) -> int:
    """Number of nodes at `height` (0 is the leaf level), as CalcTreeWidth."""
    return (tx_count + (1 << height) - 1) >> height


def tree_height(tx_count: int) -> int:
    height = 0
    while tree_width(tx_count, height) > 1:
        height += 1
    return height


def tree_levels(leaves: List[bytes]) -> List[List[bytes]]:
    """All levels of the tree, from the leaves to the root. The last node of
    a level with an odd number of nodes is hashed with itself."""
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        level = levels[-1]
        levels.append([sha256d(level[i] + (level[i + 1] if i + 1 < len(level) else level[i]))
                       for i in range(0, len(level), 2)])
    return levels


def merkle_branch(leaves: List[bytes], position: int) -> List[bytes]:
    """Sibling hashes from the leaf level up to the level below the root."""
    branch = []
    for level in tree_levels(leaves)[:-1]:
        sibling = position ^ 1
        branch.append(level[sibling] if sibling < len(level) else level[position])
        position >>= 1
    return branch


def fold_branch(leaf: bytes, branch: List[bytes], position: int) -> bytes:
    """Hash a leaf up to the root along its branch.

    A node that is a right child and equals its left sibling can only be the
    copy the tree makes of the last node of an odd level. No transaction sits
    there, so a proof that claims the position is rejected.
    """
    node = leaf
    for sibling in branch:
        if position & 1:
            if sibling == node:
                raise ProofError("DUPLICATE_SIBLING")
            node = sha256d(sibling + node)
        else:
            node = sha256d(node + sibling)
        position >>= 1
    return node


@dataclass
class PartialTree:
    """A partial Merkle tree in the encoding of BIP 37."""
    tx_count: int
    hashes: List[bytes]
    flags: bytes        # flag bits, least significant bit of each byte first


def build_partial_tree(leaves: List[bytes], positions: List[int]) -> PartialTree:
    """The partial tree that proves the leaves at `positions`, built as in
    Bitcoin Core's CPartialMerkleTree (BIP 37)."""
    tx_count = len(leaves)
    levels = tree_levels(leaves)
    matched = sorted(set(positions))
    bits: List[bool] = []
    hashes: List[bytes] = []

    def parent_of_match(height: int, pos: int) -> bool:
        lo, hi = pos << height, min((pos + 1) << height, tx_count)
        i = bisect.bisect_left(matched, lo)
        return i < len(matched) and matched[i] < hi

    def traverse(height: int, pos: int) -> None:
        match = parent_of_match(height, pos)
        bits.append(match)
        if height == 0 or not match:
            hashes.append(levels[height][pos])
        else:
            traverse(height - 1, pos * 2)
            if pos * 2 + 1 < tree_width(tx_count, height - 1):
                traverse(height - 1, pos * 2 + 1)

    traverse(len(levels) - 1, 0)
    flags = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            flags[i // 8] |= 1 << (i % 8)
    return PartialTree(tx_count, hashes, bytes(flags))


def extract_partial_tree(tree: PartialTree, height: int) -> Tuple[bytes, List[Tuple[int, bytes]]]:
    """Compute the root of a partial tree of the given height and return it
    with the matched (position, leaf) pairs. Raises ProofError if the tree is
    not well formed, with the checks of BIP 37 and Bitcoin Core's
    CPartialMerkleTree::ExtractMatches, plus zero padding bits."""
    if len(tree.hashes) > tree.tx_count or 8 * len(tree.flags) < len(tree.hashes):
        raise ProofError("BAD_PARTIAL_TREE")
    bit_count = 8 * len(tree.flags)
    bits_used = 0
    hashes_used = 0
    matches: List[Tuple[int, bytes]] = []

    def next_bit() -> bool:
        nonlocal bits_used
        if bits_used >= bit_count:
            raise ProofError("BAD_PARTIAL_TREE")
        bit = (tree.flags[bits_used // 8] >> (bits_used % 8)) & 1
        bits_used += 1
        return bool(bit)

    def next_hash() -> bytes:
        nonlocal hashes_used
        if hashes_used >= len(tree.hashes):
            raise ProofError("BAD_PARTIAL_TREE")
        hashes_used += 1
        return tree.hashes[hashes_used - 1]

    def traverse(h: int, pos: int) -> bytes:
        match = next_bit()
        if h == 0 or not match:
            node = next_hash()
            if h == 0 and match:
                matches.append((pos, node))
            return node
        left = traverse(h - 1, pos * 2)
        if pos * 2 + 1 < tree_width(tree.tx_count, h - 1):
            right = traverse(h - 1, pos * 2 + 1)
            if right == left:
                raise ProofError("DUPLICATE_SIBLING")
        else:
            right = left
        return sha256d(left + right)

    root = traverse(height, 0)
    if (bits_used + 7) // 8 != len(tree.flags) or hashes_used != len(tree.hashes):
        raise ProofError("BAD_PARTIAL_TREE")
    if bits_used % 8 and tree.flags[-1] >> (bits_used % 8):
        raise ProofError("NONZERO_PADDING")
    return root, matches


# --- proofs -----------------------------------------------------------------

@dataclass
class Entry:
    position: int
    wtxid: bytes
    branch: List[bytes]


@dataclass
class Proof:
    header: bytes
    coinbase_tx: bytes
    coinbase_branch: List[bytes]
    entries: List[Entry] = field(default_factory=list)      # format 1
    tree: Optional[PartialTree] = None                      # format 2
    format: int = FORMAT_BRANCHES

    def serialize(self) -> bytes:
        depth = len(self.coinbase_branch)
        out = bytes([self.format]) + self.header + self.coinbase_tx
        out += bytes([depth]) + b"".join(self.coinbase_branch)
        if self.format == FORMAT_PARTIAL_TREE:
            assert self.tree is not None
            out += struct.pack("<I", self.tree.tx_count)
            out += write_compact_size(len(self.tree.hashes)) + b"".join(self.tree.hashes)
            out += write_compact_size(len(self.tree.flags)) + self.tree.flags
            return out
        out += write_compact_size(len(self.entries))
        for entry in self.entries:
            assert len(entry.branch) == depth
            out += struct.pack("<I", entry.position) + entry.wtxid + b"".join(entry.branch)
        return out


def parse_proof(data: bytes) -> Proof:
    r = Reader(data)
    fmt = r.read(1)[0]
    if fmt not in (FORMAT_BRANCHES, FORMAT_PARTIAL_TREE):
        raise ProofError("BAD_FORMAT")
    header = r.read(HEADER_SIZE)
    coinbase_start = r.pos
    read_transaction(r)
    coinbase_tx = data[coinbase_start:r.pos]
    depth = r.read(1)[0]
    if depth > MAX_DEPTH:
        raise ProofError("BAD_DEPTH")
    coinbase_branch = [r.read(32) for _ in range(depth)]
    proof = Proof(header, coinbase_tx, coinbase_branch, format=fmt)
    if fmt == FORMAT_PARTIAL_TREE:
        tx_count = struct.unpack("<I", r.read(4))[0]
        hashes = [r.read(32) for _ in range(r.compact_size())]
        flags = r.read(r.compact_size())
        proof.tree = PartialTree(tx_count, hashes, flags)
    else:
        for _ in range(r.compact_size()):
            position = struct.unpack("<I", r.read(4))[0]
            wtxid = r.read(32)
            proof.entries.append(Entry(position, wtxid, [r.read(32) for _ in range(depth)]))
    if r.pos != len(data):
        raise ProofError("TRAILING_DATA")
    return proof


@dataclass
class Result:
    block_hash: bytes
    # True if the transactions were proven against the witness commitment.
    # The witness of the coinbase is then proven only if at least one
    # transaction is.
    has_witness_commitment: bool
    coinbase_txid: bytes
    entries: List[Tuple[int, bytes]]            # (position, wtxid)


def verify(data: bytes, segwit_active: bool) -> Result:
    """Verify a serialized proof. Raises ProofError if it must be rejected.

    `segwit_active` says whether BIP 141 is in force for the block. The
    caller derives it from the block height. The caller also has to check
    that the header in the proof is part of the chain it accepts.
    """
    proof = parse_proof(data)
    merkle_root = proof.header[36:68]
    depth = len(proof.coinbase_branch)

    coinbase = parse_transaction(proof.coinbase_tx)
    if not coinbase.is_coinbase():
        raise ProofError("NOT_COINBASE")
    # The coinbase is the first transaction, the left node at every level.
    if fold_branch(coinbase.txid, proof.coinbase_branch, 0) != merkle_root:
        raise ProofError("COINBASE_NOT_IN_BLOCK")

    commitment = witness_commitment(coinbase) if segwit_active else None
    committed = commitment is not None
    reserved_value = None
    if committed:
        stack = coinbase.witness[0] if coinbase.witness else []
        if len(stack) != 1 or len(stack[0]) != 32:
            raise ProofError("BAD_RESERVED_VALUE")
        reserved_value = stack[0]
    elif coinbase.witness is not None:
        # A block without a commitment has no witness data at all.
        raise ProofError("UNEXPECTED_WITNESS")

    proven: List[Tuple[int, bytes]] = []
    if proof.format == FORMAT_PARTIAL_TREE:
        tree = proof.tree
        if not 1 <= tree.tx_count <= MAX_TREE_TRANSACTIONS or tree_height(tree.tx_count) != depth:
            raise ProofError("BAD_TX_COUNT")
        root, matches = extract_partial_tree(tree, depth)
        if not matches:
            raise ProofError("NO_MATCH")
        for position, leaf in matches:
            if position == 0:
                if not committed:
                    raise ProofError("COINBASE_ENTRY")
                # The coinbase leaf of the witness tree is all zeros.
                if leaf != ZERO_HASH:
                    raise ProofError("COINBASE_LEAF_NOT_ZERO")
                proven.append((0, coinbase.wtxid))
            else:
                proven.append((position, leaf))
        if committed:
            if sha256d(root + reserved_value) != commitment:
                raise ProofError("COMMITMENT_MISMATCH")
        elif root != merkle_root:
            raise ProofError("MERKLE_ROOT_MISMATCH")
    else:
        previous = -1
        for entry in proof.entries:
            if entry.position <= previous:
                raise ProofError("BAD_ENTRY_ORDER")
            previous = entry.position
            if entry.position >> depth:
                raise ProofError("BAD_POSITION")
            if committed:
                leaf = entry.wtxid
                if entry.position == 0:
                    # The coinbase leaf of the witness tree is all zeros.
                    if entry.wtxid != coinbase.wtxid:
                        raise ProofError("COINBASE_WTXID_MISMATCH")
                    leaf = ZERO_HASH
                witness_root = fold_branch(leaf, entry.branch, entry.position)
                if sha256d(witness_root + reserved_value) != commitment:
                    raise ProofError("COMMITMENT_MISMATCH")
            else:
                if entry.position == 0:
                    raise ProofError("COINBASE_ENTRY")
                # No transaction in the block has a witness: wtxid equals txid.
                if fold_branch(entry.wtxid, entry.branch, entry.position) != merkle_root:
                    raise ProofError("MERKLE_ROOT_MISMATCH")
            proven.append((entry.position, entry.wtxid))

    return Result(
        block_hash=sha256d(proof.header),
        has_witness_commitment=committed,
        coinbase_txid=coinbase.txid,
        entries=proven,
    )


# --- JSON form --------------------------------------------------------------

def _display(h: bytes) -> str:
    return h[::-1].hex()


def proof_to_json(data: bytes) -> dict:
    """The JSON form of a serialized proof. Hashes are reversed, as Bitcoin
    software displays them; the header, the coinbase transaction and the
    flag bytes are given as they are in the serialization."""
    p = parse_proof(data)
    out = {
        "format": p.format,
        "header": p.header.hex(),
        "coinbase_tx": p.coinbase_tx.hex(),
        "coinbase_branch": [_display(h) for h in p.coinbase_branch],
    }
    if p.format == FORMAT_PARTIAL_TREE:
        out["tx_count"] = p.tree.tx_count
        out["hashes"] = [_display(h) for h in p.tree.hashes]
        out["flags"] = p.tree.flags.hex()
    else:
        out["entries"] = [{"pos": e.position, "wtxid": _display(e.wtxid),
                           "branch": [_display(h) for h in e.branch]} for e in p.entries]
    return out


def _json_bytes(value, size: Optional[int] = None) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise ProofError("BAD_JSON")
    try:
        out = bytes.fromhex(value)
    except ValueError:
        raise ProofError("BAD_JSON") from None
    if len(out) * 2 != len(value) or (size is not None and len(out) != size):
        raise ProofError("BAD_JSON")
    return out


def _json_hash(value) -> bytes:
    return _json_bytes(value, 32)[::-1]


def _json_uint32(value) -> int:
    # type() and not isinstance(): bool and _SignedInt are subclasses of int.
    if type(value) is not int or not 0 <= value <= 0xffffffff:
        raise ProofError("BAD_JSON")
    return value


def _json_list(obj: dict, key: str) -> list:
    value = obj.get(key)
    if not isinstance(value, list):
        raise ProofError("BAD_JSON")
    return value


KEYS = {
    FORMAT_BRANCHES: {"format", "header", "coinbase_tx", "coinbase_branch", "entries"},
    FORMAT_PARTIAL_TREE: {"format", "header", "coinbase_tx", "coinbase_branch", "tx_count", "hashes", "flags"},
}
ENTRY_KEYS = {"pos", "wtxid", "branch"}


def _check_repeated(obj: dict, keys) -> None:
    # Objects from read_json record the keys that appeared more than once.
    if keys & getattr(obj, "repeated", frozenset()):
        raise ProofError("BAD_JSON")


def proof_from_json(obj) -> bytes:
    """The serialization of a proof in JSON form, given as the value a JSON
    reader returns. Raises ProofError with code BAD_JSON if a key is
    missing, a value has the wrong type or size, the coinbase transaction
    is not exactly one transaction, or the coinbase branch has more than 32
    hashes. Keys other than those of the format are ignored. Numbers have
    to be Python ints, which the json module returns only for numbers
    written without a fraction or an exponent."""
    if not isinstance(obj, dict):
        raise ProofError("BAD_JSON")
    _check_repeated(obj, {"format"})
    fmt = obj.get("format")
    if type(fmt) is not int or fmt not in (FORMAT_BRANCHES, FORMAT_PARTIAL_TREE):
        raise ProofError("BAD_JSON")
    _check_repeated(obj, KEYS[fmt])
    header = _json_bytes(obj.get("header"), HEADER_SIZE)
    coinbase_tx = _json_bytes(obj.get("coinbase_tx"))
    # The field has to be one transaction on its own. Otherwise bytes could
    # move between coinbase_tx and coinbase_branch and still serialize to a
    # valid proof, with a coinbase_tx field that is not the coinbase.
    try:
        parse_transaction(coinbase_tx)
    except ProofError:
        raise ProofError("BAD_JSON") from None
    coinbase_branch = [_json_hash(h) for h in _json_list(obj, "coinbase_branch")]
    depth = len(coinbase_branch)
    if depth > MAX_DEPTH:
        raise ProofError("BAD_JSON")
    out = bytes([fmt]) + header + coinbase_tx + bytes([depth]) + b"".join(coinbase_branch)
    if fmt == FORMAT_PARTIAL_TREE:
        hashes = [_json_hash(h) for h in _json_list(obj, "hashes")]
        flags = _json_bytes(obj.get("flags"))
        out += struct.pack("<I", _json_uint32(obj.get("tx_count")))
        return out + write_compact_size(len(hashes)) + b"".join(hashes) + write_compact_size(len(flags)) + flags
    entries = _json_list(obj, "entries")
    out += write_compact_size(len(entries))
    for entry in entries:
        if not isinstance(entry, dict):
            raise ProofError("BAD_JSON")
        _check_repeated(entry, ENTRY_KEYS)
        branch = [_json_hash(h) for h in _json_list(entry, "branch")]
        if len(branch) != depth:
            raise ProofError("BAD_JSON")
        out += struct.pack("<I", _json_uint32(entry.get("pos"))) + _json_hash(entry.get("wtxid")) + b"".join(branch)
    return out


class _JsonObject(dict):
    """A JSON object that records the keys that appeared more than once.
    The json module decodes escape sequences in keys before this sees them."""
    repeated = frozenset()


def _object(pairs) -> _JsonObject:
    obj = _JsonObject()
    repeated = set()
    for key, value in pairs:
        if key in obj:
            repeated.add(key)
        obj[key] = value
    obj.repeated = frozenset(repeated)
    return obj


class _SignedInt(int):
    """An integer written with a minus sign, such as -0."""


def _int(literal: str) -> int:
    return _SignedInt(literal) if literal.startswith("-") else int(literal)


def _not_json(constant):
    # Python reads NaN, Infinity and -Infinity, which are not JSON.
    raise ProofError("BAD_JSON")


def read_json(text: str):
    """Parse a JSON text as RFC 8259 defines it. Numbers written with a
    fraction or an exponent come back as floats and those written with a
    minus sign as _SignedInt, so proof_from_json can reject them where the
    format needs plain digits."""
    try:
        return json.loads(text, object_pairs_hook=_object, parse_int=_int, parse_constant=_not_json)
    except (ValueError, RecursionError):
        # RecursionError: nesting deeper than the interpreter allows, one of
        # the limits RFC 8259 lets a reader set.
        raise ProofError("BAD_JSON") from None


def proof_from_json_text(text: str) -> bytes:
    return proof_from_json(read_json(text))


def verify_json_text(text: str, segwit_active: bool) -> Result:
    return verify(proof_from_json_text(text), segwit_active)


# --- building proofs --------------------------------------------------------

def parse_block(data: bytes) -> Tuple[bytes, List[Transaction]]:
    r = Reader(data)
    header = r.read(HEADER_SIZE)
    txs = [read_transaction(r) for _ in range(r.compact_size())]
    if r.pos != len(data):
        raise ProofError("TRAILING_DATA")
    return header, txs


def make_proof(block: bytes, positions: List[int], segwit_active: bool, fmt: int = FORMAT_BRANCHES) -> bytes:
    """Build a proof for the transactions at `positions` in a serialized block."""
    header, txs = parse_block(block)
    coinbase = txs[0]
    txids = [tx.txid for tx in txs]
    positions = sorted(set(positions))
    if any(p < 0 or p >= len(txs) for p in positions):
        raise ValueError("position outside the block")
    committed = segwit_active and witness_commitment(coinbase) is not None
    if committed:
        leaves = [ZERO_HASH] + [tx.wtxid for tx in txs[1:]]
    else:
        leaves = txids
        # The coinbase is proven by its own branch and is not an entry here.
        positions = [p for p in positions if p != 0]
    proof = Proof(header, coinbase.raw, merkle_branch(txids, 0), format=fmt)
    if fmt == FORMAT_PARTIAL_TREE:
        if not positions:
            raise ValueError("a format 2 proof needs at least one transaction")
        proof.tree = build_partial_tree(leaves, positions)
    else:
        proof.entries = [Entry(p, txs[p].wtxid, merkle_branch(leaves, p)) for p in positions]
    return proof.serialize()
