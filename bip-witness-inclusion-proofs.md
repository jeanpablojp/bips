```
  BIP: ?
  Layer: Applications
  Title: Witness Transaction Inclusion Proofs
  Authors: jeanpablojp <me@jeanpablo.jp>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause
  Discussion: 2025-10-30: https://github.com/bitcoin/bitcoin/pull/32844#pullrequestreview-3400680165
              2026-11-22: https://groups.google.com/g/bitcoindev/c/TRghxgpNc94
  Requires: 141, 144
```

## Abstract

This document specifies a proof that a transaction with a given wtxid is included in a block, and the rules for verifying it against the block header.
Unlike a Merkle proof of the txid, it covers the witness data of the transaction.
The proof has two formats, one with a Merkle branch for each transaction and one with a partial Merkle tree as in BIP 37, and a JSON form for interfaces that return JSON.

## Motivation

A Merkle branch from a txid to the Merkle root in a block header proves that a transaction is in the block.
It says nothing about the witness, because the txid doesn't commit to it.
A client that gets a transaction from a server it doesn't trust can verify such a branch and still hold a witness that was never mined.
This matters whenever the client keeps the witness or acts on what it contains.
SomberNight asked for these proofs for Electrum's Lightning support[^request].

[BIP 141](bip-0141.mediawiki) added a second Merkle tree, built from wtxids, and a commitment to its root in the coinbase transaction.
With the coinbase transaction and two branches, one from the coinbase to the header and one from the wtxid to the commitment, a client can check the witness as well.
No BIP specifies that proof.
[BIP 37](bip-0037.mediawiki) only covers txids, and [BIP 144](bip-0144.mediawiki) reserves an inventory type for filtered blocks with witness data "for future use".

Several implementations exist or are proposed, each with its own format.
Bitcoin Knots has had a witness mode in `gettxoutproof` since version 29.1, encoded with BIP 37 partial Merkle trees[^knots].
A draft for Bitcoin Core adds `gettxproof` and `verifytxproof`, which use a JSON object with plain branches[^core-draft].
A draft of the Electrum protocol defines `blockchain.transaction.get_merkle_witness` with another set of fields[^electrum], and a pull request to electrs proposes one more[^electrs].
Contracts such as BOB's `WitnessTx` library verify the commitment with their own code[^bob].

These formats carry much the same data in different shapes, except that the electrs proposal leaves out the coinbase transaction and its branch, and the Electrum draft returns them only on request.
No BIP specifies the checks a verifier has to make, so each project writes its own, and they're easy to get wrong[^advisory].
Two of them came up in the test vectors for this document.
A verifier that only has the header can be shown a valid branch for a position past the last transaction of the block.
And the commitment output doesn't say which tree a transaction has to be proven in, because miners were adding it months before segwit activated.

This document specifies the contents of the proof, its two formats, a JSON form and the verification rules.
Its test vectors include proofs that a verifier must reject.

## Specification

### Definitions

`SHA256d(x)` is `SHA256(SHA256(x))`, and `a || b` is the concatenation of two byte strings.
Hashes are 32-byte strings in the order the hash function outputs them.
Software that displays hashes in hexadecimal usually reverses the bytes.
In this document only the JSON form and the `expected` objects of the test vectors do.

The txid of a transaction is `SHA256d` of its serialization without witness data.
Its wtxid is `SHA256d` of its serialization as defined in [BIP 144](bip-0144.mediawiki), with witness data if it has any.
The two are equal for a transaction without witness data.

The transaction tree of a block is the Merkle tree whose leaves are the txids of its transactions in block order.
Its root is the Merkle root of the block, bytes 36 to 67 of the 80-byte header, counting from 0.
The witness tree is built the same way from the wtxids, except that the leaf of the coinbase transaction is 32 zero bytes, as defined in [BIP 141](bip-0141.mediawiki).
In both trees a level with an odd number of nodes, other than the root, has its last node hashed with itself, so all leaves are at the same depth.
The position of a transaction is its zero-based index in the block.

The branch of a leaf is the list of the hashes it is combined with on the way to the root, starting at the leaf level.
Its length is the depth of the tree.

A commitment output is an output of the coinbase transaction whose scriptPubKey is at least 38 bytes long and starts with `0x6a24aa21a9ed`.
If there are several, only the one with the highest index counts.
Bytes 6 to 37 of its scriptPubKey, counting from 0, are the commitment hash.
The witness reserved value is the single 32-byte item in the witness of the coinbase input.
Both are defined in [BIP 141](bip-0141.mediawiki).

Segwit is active for a block if the rules of [BIP 141](bip-0141.mediawiki) apply to it.
On mainnet that is every block from height 481,824, and on testnet3 every block from height 834,624.
On testnet4 ([BIP 94](bip-0094.mediawiki)), testnet5 ([BIP 95](bip-0095.md)) and signet it is every block after the genesis block, and on regtest it is every block unless the node is configured otherwise.

### Folding a branch

`fold(leaf, branch, position)` hashes a leaf up to a root.
Bit 0 of `position` is the least significant bit.

```
node = leaf
for i from 0 to len(branch) - 1:
    if bit i of position is 0:
        node = SHA256d(node || branch[i])
    else:
        fail if branch[i] == node
        node = SHA256d(branch[i] || node)
return node
```

### Partial Merkle trees

A partial Merkle tree, as defined in [BIP 37](bip-0037.mediawiki), proves several leaves of a tree without repeating the hashes their branches have in common.
It consists of the number of leaves `tx_count`, a list of `hashes` and a list of flag bits.
The flag bits are stored 8 to a byte in the byte string `flags`: flag bit `i` is bit `i mod 8` of byte `floor(i / 8)`, where bit 0 is the least significant bit.
The leaves are at height 0, and the number of nodes at height `h` is `width(h) = ceil(tx_count / 2^h)`.

`extract(tx_count, hashes, flags, height)` computes the root of a partial tree of the given height and the list of its matched leaves with their positions.

```
bits_used = 0
hashes_used = 0
matches = []
root = visit(height, 0)
fail unless hashes_used == len(hashes)
fail unless len(flags) == ceil(bits_used / 8)
fail unless flag bits bits_used to 8 * len(flags) - 1 are all 0
return root, matches

visit(h, pos):
    fail if bits_used == 8 * len(flags)
    bit = flag bit bits_used
    bits_used = bits_used + 1
    if h == 0 or bit == 0:
        fail if hashes_used == len(hashes)
        node = hashes[hashes_used]
        hashes_used = hashes_used + 1
        if h == 0 and bit == 1:
            append (pos, node) to matches
        return node
    left = visit(h - 1, 2 * pos)
    if 2 * pos + 1 < width(h - 1):
        right = visit(h - 1, 2 * pos + 1)
        fail if right == left
    else:
        right = left
    return SHA256d(left || right)
```

The matches are in increasing order of position.
These are the rules of BIP 37, with the bits after the last bit used required to be 0.

### Serialization

A proof starts with the following fields.

| Field | Size in bytes | Description |
|---|---|---|
| `format` | 1 | `0x01` for format 1, `0x02` for format 2 |
| `header` | 80 | The block header |
| `coinbase_tx` | variable | The coinbase transaction in the [BIP 144](bip-0144.mediawiki) serialization |
| `depth` | 1 | The depth of the trees, at most 32 |
| `coinbase_branch` | 32 × `depth` | The branch of the coinbase txid in the transaction tree |

The transactions are proven in the witness tree if the block has a witness commitment (step 4 of the verification), and in the transaction tree otherwise.
In format 1 each transaction has its own branch, and the proof ends with the following fields.

| Field | Size in bytes | Description |
|---|---|---|
| `entry_count` | 1 to 9 | The number of entries, as a compact size integer |
| `entries` | (36 + 32 × `depth`) × `entry_count` | The entries, in increasing order of position |

Each entry is the concatenation of the following fields.

| Field | Size in bytes | Description |
|---|---|---|
| `position` | 4 | The position of the transaction in the block, as a little-endian integer |
| `wtxid` | 32 | The wtxid of the transaction |
| `branch` | 32 × `depth` | The branch of the transaction |

In format 2 the transactions are the matched leaves of a partial Merkle tree, and the proof ends with the following fields, serialized as in the `merkleblock` message of [BIP 37](bip-0037.mediawiki).

| Field | Size in bytes | Description |
|---|---|---|
| `tx_count` | 4 | The number of transactions in the block, as a little-endian integer |
| `hash_count` | 1 to 9 | The number of hashes, as a compact size integer |
| `hashes` | 32 × `hash_count` | The hashes of the partial tree |
| `flag_count` | 1 to 9 | The number of bytes of `flags`, as a compact size integer |
| `flags` | `flag_count` | The flag bits of the partial tree |

A compact size integer encodes a value below 253 as a single byte.
A value up to `0xffff` is `0xfd` followed by 2 bytes, a value up to `0xffffffff` is `0xfe` followed by 4 bytes, and a larger value is `0xff` followed by 8 bytes, all in little-endian order.
Every compact size integer in a proof must use the shortest form for its value, including those inside `coinbase_tx`.

`coinbase_tx` consists of the following parts, in this order.

* The version, 4 bytes.
* Optionally the marker `0x00` and the flag `0x01`. A zero byte after the version is the marker.
* The number of inputs as a compact size integer. Each input is the previous output, which is a 32-byte hash and a 4-byte index, the length of the script as a compact size integer, the script, and the sequence number, 4 bytes.
* The number of outputs as a compact size integer. Each output is the value, 8 bytes, the length of the script as a compact size integer, and the script.
* If the marker and flag are present, one witness for each input. A witness is the number of items as a compact size integer, and for each item its length as a compact size integer and its bytes.
* The lock time, 4 bytes.

The transaction is serialized with witness data if the marker and flag are present.
The serialization is not valid if the marker is followed by a byte other than `0x01`, or if the marker and flag are present and no witness has an item.
A verifier must not reject a proof because `coinbase_tx` breaks a rule for transactions that this document does not state, such as the limits on the size of the coinbase script.

A format 1 proof with more than 2 to the power of `depth` entries cannot pass step 6 of the verification, and a parser may reject it before it reads the entries.
A format 2 proof with more hashes than `tx_count`, or with more hashes than flag bits, cannot pass step 7, and a parser may reject it before it computes the tree.
A verifier may also set a limit on the size of the proofs it accepts.

### Verification

The verifier takes a serialized proof and one more input, `segwit_active`, which says whether segwit is active for the block.
Two things are left to the verifier and are not part of this procedure.
It has to check that the header in the proof belongs to the chain it accepts, and it has to derive `segwit_active` from the height of that header.
If `fold` or `extract` fails in any step, verification fails.

1. Parse the proof. Verification fails if the format is not 1 or 2, the depth is greater than 32, a compact size integer is not in its shortest form, the serialization of `coinbase_tx` is not valid, the data ends early, or bytes are left over.
2. Verification fails unless `coinbase_tx` has exactly one input and that input spends the null outpoint, which is 32 zero bytes followed by `0xffffffff`.
3. Verification fails unless `fold(txid of coinbase_tx, coinbase_branch, 0)` equals the Merkle root in `header`.
4. The block has a witness commitment if `segwit_active` is true and `coinbase_tx` has a commitment output.
5. If the block has a witness commitment, verification fails unless the witness of the coinbase input is exactly one item of 32 bytes. Otherwise, verification fails if `coinbase_tx` is serialized with witness data.
6. In format 1, for each entry, in order:
    * Verification fails if the position is not greater than the position of the previous entry, when there is one, or is not less than 2 to the power of `depth`.
    * If the block has a witness commitment, the leaf is `wtxid`, except at position 0, where the leaf is 32 zero bytes and verification fails unless `wtxid` equals the wtxid of `coinbase_tx`, which is `SHA256d` of its bytes in the proof. Verification fails unless `SHA256d(fold(leaf, branch, position) || witness reserved value)` equals the commitment hash.
    * Otherwise, verification fails if the position is 0, or if `fold(wtxid, branch, position)` does not equal the Merkle root in `header`.
7. In format 2:
    * Verification fails unless `tx_count` is at least 1 and at most 16,666, and `depth` is the smallest integer `d` for which 2 to the power of `d` is at least `tx_count`.
    * Compute `root, matches = extract(tx_count, hashes, flags, depth)`. Verification fails if `matches` is empty.
    * If the block has a witness commitment, verification fails if `matches` has position 0 with a leaf other than 32 zero bytes, and unless `SHA256d(root || witness reserved value)` equals the commitment hash.
    * Otherwise, verification fails if `matches` has position 0, or if `root` does not equal the Merkle root in `header`.

If no step fails, the proof is accepted.
The result is the block hash, which is `SHA256d(header)`, whether the block has a witness commitment, the txid of `coinbase_tx`, and the position and wtxid of each proven transaction.
In format 1 these are the entries.
In format 2 they are the matches, in increasing order of position, with the wtxid of `coinbase_tx` at position 0.

For a block that follows the consensus rules, an accepted proof shows that:

* `coinbase_tx`, without its witness data, is the coinbase transaction of the block.
* For each proven transaction, the transaction at that position in the block has that wtxid. If the block has no witness commitment, none of its transactions has witness data and the wtxid is also the txid.
* If the block has a witness commitment and the proof proves at least one transaction, the witness of `coinbase_tx` is the one in the block. A format 1 proof without entries does not verify the witness reserved value.

A client that wants to check a transaction it already has computes the wtxid from the bytes it holds, witness included, and compares it with the wtxid in the result.

A proof does not show that the header is in the chain with the most work, or how many blocks were mined on top of it.
It also does not show how many transactions the block has: the depth only bounds that number, and a format 2 proof can pass with a `tx_count` other than the number of transactions in the block.
A verifier that knows the number of transactions in the block, such as a full node, may reject a format 2 proof whose `tx_count` differs from it.

### Building a proof

A prover builds the proof from the full block.
It proves the transactions in the witness tree if the block has a witness commitment, as defined in step 4, and in the transaction tree otherwise.
In the second case the coinbase transaction is not proven again, since `coinbase_branch` already proves it.

In format 1 each entry gets the branch of its transaction.

In format 2 the prover sets `tx_count` to the number of transactions in the block and builds the partial tree as in [BIP 37](bip-0037.mediawiki).
Starting at the root, it visits the nodes depth first, the left child before the right child, and appends one flag bit for each node it visits: 1 if the node is a leaf to be proven or has one below it, and 0 otherwise.
If the bit is 0 or the node is a leaf, it appends the hash of the node to `hashes` and does not visit the children.
Otherwise it visits the left child, and then the right child if `2 * pos + 1 < width(h - 1)`, as in `visit`.
The bits after the last flag bit are 0.
A format 2 proof proves at least one transaction.
A proof of the coinbase transaction alone in a block without a witness commitment is a format 1 proof without entries.

### JSON form

An interface that returns JSON, such as an RPC method or the Electrum protocol, can give a proof as a JSON text, as defined in RFC 8259[^json], whose value is an object with the following keys.

| Key | Format | Value |
|---|---|---|
| `format` | 1 and 2 | The number 1 or 2 |
| `header` | 1 and 2 | `header` as a hexadecimal string |
| `coinbase_tx` | 1 and 2 | `coinbase_tx` as a hexadecimal string |
| `coinbase_branch` | 1 and 2 | `coinbase_branch` as an array of hashes |
| `entries` | 1 | An array with one object for each entry, with the keys `pos`, the position as a number, `wtxid`, a hash, and `branch`, an array of hashes |
| `tx_count` | 2 | `tx_count` as a number |
| `hashes` | 2 | `hashes` as an array of hashes |
| `flags` | 2 | `flags` as a hexadecimal string |

A hash is a string of 64 hexadecimal digits with its bytes reversed, the way Bitcoin software displays txids.
The other hexadecimal strings keep the byte order of the serialization.
Writers use lower case digits, and readers accept both cases.
Keys and strings are read after their escape sequences are decoded.
The values of `format`, `pos` and `tx_count` are written in decimal digits only, without a sign, a fraction or an exponent.
Readers ignore keys other than those of the format, in the object and in its entries, so an interface can add its own with any JSON value, such as the height of the block.

The object maps to the serialization with the same fields.
`depth` is the length of `coinbase_branch`, `entry_count` and `hash_count` are the lengths of `entries` and `hashes`, and `flag_count` is the number of bytes in `flags`.
The object is not a valid proof if:

* `format` is not 1 or 2, or a key of its format is missing from the object or from one of its entries.
* A key of its format appears more than once in the object or in one of its entries.
* A value of a key of the format has another JSON type than the table gives, or is a number that is not written in digits only or is greater than `0xffffffff`.
* A hexadecimal string has a character that is not a hexadecimal digit, or an odd number of digits.
* `header` is not 80 bytes, a hash is not 32 bytes, or `coinbase_tx` is not exactly one transaction that is valid as described in Serialization, with no bytes left over.
* `coinbase_branch` has more than 32 hashes, or the `branch` of an entry does not have as many hashes as `coinbase_branch`.

Otherwise it is verified as the serialization it maps to.
A reader may set limits on the texts it accepts, such as on their size or on how deeply they nest, as RFC 8259 allows.

## Rationale

### The coinbase transaction is included in full

Finding the commitment means looking at every output of the coinbase transaction, since the last matching output is the one that counts, and the reserved value is in its witness.
A proof with only the commitment output would also have to show that no later output matches.
Sending the whole transaction is simpler, and its bytes are shared by all the transactions a proof covers.

### Two formats

Format 1 gives each transaction its own branch, as the Bitcoin Core draft and the Electrum protocol draft do.
Verifying a branch is a single loop.
The Electrum protocol uses plain branches for txid proofs, Esplora serves both plain branches and BIP 37 `merkleblock` proofs, and BOB's library uses plain branches for witness proofs.

Format 2 uses the partial Merkle tree of [BIP 37](bip-0037.mediawiki), which doesn't repeat the hashes that several branches have in common.
Bitcoin Knots uses partial trees, and Anthony Towns suggested them for the wtxids when reviewing bitcoin/bitcoin#32844[^partial-tree].
For one transaction a format 2 proof is usually a few bytes larger, and smaller for the last transactions of a block, whose format 1 branches repeat the nodes the tree copies.
For ten transactions spread evenly over block 481823, which has 1,696, a format 1 proof takes 4,523 bytes and a format 2 proof 3,325 bytes, header and coinbase transaction included.

Both formats prove the same thing with the same coinbase checks, and only the part after `coinbase_branch` differs.
A verifier that supports both needs `extract` in addition to `fold`.

### Partial trees as in BIP 37

Format 2 encodes the tree exactly as the `merkleblock` message of BIP 37 does, which is also the encoding of Bitcoin Core's `CPartialMerkleTree`.

BIP 37 doesn't say what the padding bits of the last flag byte are.
Bitcoin Core writes them as zeros and doesn't look at them when it reads a tree.
This document requires them to be zero, as it requires compact size integers in their shortest form, so that these bits have one encoding.
Checking them needs the number of flag bits the traversal used, which `CPartialMerkleTree` doesn't expose.

The transaction count isn't proven.
The tree has to be as deep as `coinbase_branch`, but a `tx_count` that only changes the tree where the proof doesn't descend gives the same root.
So a format 2 proof can have more than one encoding.
BIP 37 has the same property, and the result of the verification doesn't include the count.
Bitcoin Core's `verifytxoutproof` compares the count of a partial tree with that of the block, which is why a verifier that knows the count may reject a different one.
The upper limit of 16,666 is the one Bitcoin Core applies to partial trees, the maximum block weight divided by the minimum weight of a transaction, rounded down.

A format 2 proof has to match at least one leaf.
A tree without a match proves no transaction, and a format 1 proof without entries already proves the header and the coinbase transaction alone.

### One depth for all branches

Every leaf of a Bitcoin Merkle tree is at the same depth, so the proof has one `depth` field.
Every branch of format 1 has exactly that many hashes, and the partial tree of format 2 has to have that height.
Format 1 allows any depth up to 32, the size of its position field, although no valid block is deeper than 15.
This is what protects against the ambiguity between a 64-byte transaction and an inner node of the tree[^leaf-node].
A verifier that accepts branches of any length can be shown an inner node as if it were a transaction, or a transaction as if it were an inner node.
With the length fixed by the coinbase branch neither works, and 64-byte transactions don't have to be rejected.
The client checks SomberNight listed for Electrum require the two branches to have the same length for this reason[^checks], and BOB's library checks it too.

[BIP 54](bip-0054.md) would make a transaction invalid if its serialization without witness data is 64 bytes long.
It says nothing about the serialization with witness data, which is what a leaf of the witness tree hashes.
A verifier of these proofs can't rely on it for the witness tree.

Faking the depth itself would take a hash with 28 of its bytes fixed in known positions, 224 bits of work[^zeros].
It would have to be an inner node whose 64-byte preimage parses as a coinbase transaction, or a transaction whose txid is the first half of a 64-byte coinbase transaction.

### Rejecting a node equal to its left sibling

In a level with an odd number of nodes, the last node is hashed with itself.
A branch for the last transaction therefore also verifies at positions to its right, where the block has no transaction.
In block 481823, which has 1,696 transactions, the branch of position 1695 also reaches the root at seven other positions, the highest being 2047.
Inclusion isn't affected, but the position is wrong, and some uses depend on the position, for example the short channel ids of Lightning.
`fold` rejects a right-hand node that equals its left sibling.
A branch that reaches the root from a position past the last transaction always passes through one of these copies as a right-hand node, so every such position is rejected.
An honest branch never has one, because two neighbouring nodes can only be equal if the block contains the same transaction twice, and such a block is invalid.
BIP 37 has the same rule for partial trees, and `extract` keeps it.
With a `tx_count` larger than the real one, a matched leaf can only land past the last transaction if the proof repeats a subtree, and the rule rejects that.

A verifier that knows how many transactions the block has can compare the position with that number instead.
A client that only has headers doesn't know it.

### Segwit activation is an input

Whether the transactions are proven in the witness tree depends on whether the block has a witness commitment, and the commitment output doesn't settle that.
Miners started adding the commitment output months before segwit activated.
In a sample of every 900th mainnet block from height 436,000 to 481,000, 12 of 51 coinbase transactions have it.
In every third block from height 481,700 to 481,823, all 42 do.
None of them has a witness, since witness data wasn't valid yet, and transactions in those blocks can only be proven in the transaction tree.
A verifier that picks the tree from the commitment output can't verify the transactions in these blocks.

A verifier can't tell these blocks from later ones by looking for a witness in the coinbase transaction of the proof.
A prover could take a block from after activation and drop the witness of the coinbase transaction, which doesn't change its txid.
It could then present any transaction of that block without its witness, in the transaction tree.
For this reason the proof is checked with `segwit_active` as an input, and a coinbase transaction with a commitment output and no reserved value is rejected when segwit is active.
A verifier that passes `false` for a block after activation loses this protection, which is why it takes the input from the height of the header in its own chain.

Since [BIP 34](bip-0034.mediawiki), the script of the coinbase input starts with the height of the block, and a verifier could compare that height with the activation height instead of taking an input.
Before BIP 34 that push can hold anything: in block 1 it reads as 486,604,799.
The verifier would still need to know where the block is in its chain, and once it knows that, the coinbase adds nothing.
The input also spares it from decoding script numbers.

### The witness of the coinbase transaction

The coinbase transaction has to be serialized with its witness when the block has a witness commitment and without one otherwise, which leaves one valid encoding of it.
Its witness, the reserved value, is only tied to the block through the commitment hash, and checking that hash needs the root of the witness tree.
Any proven transaction provides the root, and a format 1 proof without entries doesn't.
Proving position 0 covers the case where the coinbase transaction is the only one of interest: its leaf is the zero hash that BIP 141 assigns to the coinbase.
BIP 141 keeps the reserved value for commitments added by future soft forks, and proving it will matter if one of them uses it.

In a block without a witness commitment, proving position 0 again would only repeat `coinbase_branch`.
Both formats reject it, and a proof of the coinbase transaction alone is a format 1 proof without entries.

### Entries state the wtxid

A verifier that already has the transaction could do without the `wtxid` field of format 1.
With the wtxid in the proof, a batch can be checked before the transactions are fetched, and the result says which transactions were proven.
In format 2 the wtxids are the matched leaves of the tree.

### The header is part of the proof

The proof carries the 80-byte header instead of the block hash.
The verifier needs the Merkle root for step 3, and it can hash the header to find the block in its chain and learn the height.

### The JSON form

The Bitcoin Core draft and the Electrum protocol draft both return JSON, with different keys.
If both used this mapping, a client could check a proof from either with the same code, and turn it into the serialization and back without changing what is verified.
The keys follow the names of the serialization, except `pos`, which is what the Electrum protocol and the Core draft call the position.
Hashes are reversed because that's how both show txids and branches.

The keys aren't those of the Bitcoin Core draft.
That draft gives the hash of the block and its number of transactions, and its verifier looks the block up by the hash and compares the number with the one the node has.
A client with only headers doesn't have that number.
This document carries the header, as the serialization does, and checks positions with the depth and by rejecting a node equal to its left sibling.
In the draft each transaction also names the tree of its branch, with a `txid` or a `wtxid` key, and the coinbase transaction is the first in the list.
Here the tree follows from the coinbase transaction and `segwit_active`, so an entry has a single `branch` and the branch of the coinbase transaction has its own key.

`coinbase_tx` has to be exactly one transaction so that the fields of the object are the fields of the proof.
Without that rule, bytes could move from the end of `coinbase_tx` into `coinbase_branch` and still serialize to a proof that verifies, with a `coinbase_tx` field that isn't the coinbase transaction.
A key of the format can't appear twice because JSON readers differ on which of the values they keep.
With the keys of both formats in one object, two readers could find two different valid proofs.
Other keys can repeat, since they don't change the proof.
The numbers are plain digits for a similar reason: readers differ on what they do with `1.0` or `-0`.

### Existing formats

The table compares this document with the formats in use or proposed in November 2026.
The verification rules apply to each of them, with the coinbase transaction and its branch fetched separately where a format leaves them out.

| | This document | Bitcoin Knots 29[^knots] | Bitcoin Core draft[^core-draft] | Electrum protocol draft[^electrum] | electrs pull request[^electrs] |
|---|---|---|---|---|---|
| Block | header | header | hash | hash and height | height |
| Coinbase transaction | yes | yes | yes | optional | no |
| Coinbase branch | plain | partial Merkle tree | plain | plain, optional | no |
| Branch of the transaction | plain or partial Merkle tree | partial Merkle tree | plain | plain | plain |
| Number of transactions in the block | in format 2 | yes | yes | no | no |
| Transactions per proof | several | several | one | one | one |

The electrs proposal returns the root of the witness tree in place of the coinbase transaction.
A client has to fetch the coinbase transaction and its branch separately to check that root.

## Backward Compatibility

This document defines a new format and doesn't change the consensus rules or the P2P protocol.
Proofs of txids, such as those of [BIP 37](bip-0037.mediawiki) and `gettxoutproof`, aren't affected.

## Test Vectors

The directory [test_vectors](bip-witness-inclusion-proofs/test_vectors) has three files.
`valid.json` has 31 proofs that must be accepted, and `invalid.json` has 62 proofs that must be rejected, in both formats.
Each vector gives the serialized proof in hexadecimal and the value of `segwit_active` to verify it with.
A valid vector also gives the proof in JSON form, and its `expected` object is the result of the verification: `block_hash`, `has_witness_commitment`, `coinbase_txid` and the `entries`, each with a `position` and a `wtxid`.
The `error` field of an invalid vector names the first check that fails in the reference implementation.
Other implementations only need to reject the proof.
`json.json` has JSON texts for the reader: 8 that a writer wouldn't produce but that map to the given serialization, and 35 that are not valid proofs.
They are texts and not objects, so that repeated keys and the way numbers are written reach the reader unchanged.

The proofs are for mainnet blocks 1, 586, 481823, 481828, 484645, 489125 and 976497, for signet block 331464, and for synthetic blocks built by the generator.
In the coinbase transaction of block 976497 the commitment output is followed by other outputs, and in the signet block it also carries the signet solution.
The transactions of the synthetic blocks aren't valid spends and their headers have no proof of work.
A verifier of these proofs doesn't look at either.
Some vectors use made-up trees: of depth 32 and 33 for format 1, in which only the hashes on the proven paths exist, and of 16,666 and 16,667 leaves for format 2.
Five of the mainnet blocks are the ones in the fixtures of the Bitcoin Core draft[^core-draft].
For the transactions those fixtures cover, the format 1 proofs here contain the same coinbase transactions and branches.

## Reference Implementation

[reference.py](bip-witness-inclusion-proofs/reference.py) builds and verifies proofs in both formats and converts them to and from the JSON form, in Python 3.9 or later, using only the standard library.
[run_test_vectors.py](bip-witness-inclusion-proofs/run_test_vectors.py) runs the test vectors against it, and [gen_test_vectors.py](bip-witness-inclusion-proofs/gen_test_vectors.py) regenerates them from the raw blocks.

## Acknowledgements

SomberNight described the contents of the proof and the checks a client makes in the discussion of Bitcoin Core pull request 32844.
Luke Dashjr wrote the implementation in that pull request, which Bitcoin Knots ships.
Sjors Provoost wrote the draft that continues it, and its choice of mainnet blocks is reused here.
Anthony Towns asked for the proofs to be documented in a BIP with test vectors, and suggested partial trees for them.

## Copyright

This BIP is licensed under the BSD 2-clause license.
The test vectors are also available under CC0-1.0, as the LICENSE file in their directory states.

[^request]: [bitcoin/bitcoin#32844](https://github.com/bitcoin/bitcoin/pull/32844) was opened at SomberNight's request.
[^checks]: [SomberNight's comment](https://github.com/bitcoin/bitcoin/pull/32844#issuecomment-3021260691) on bitcoin/bitcoin#32844.
[^partial-tree]: [Review comment](https://github.com/bitcoin/bitcoin/pull/32844#discussion_r2478855640) of 2025-10-30.
[^zeros]: Byte 4 of a transaction serialization is the number of inputs, which has to be 1, and bytes 5 to 36 are the hash of the previous output, which is all zeros for a coinbase transaction. Bytes 4 to 31 are in the first 32 bytes. Bitcoin Core's `IsBlockMutated` gives the same 224 bits for a 64-byte coinbase transaction.
[^knots]: The `prove_witness` option of `gettxoutproof` and the `verify_witness` option of `verifytxoutproof`, in the [release notes of Bitcoin Knots 29.1](https://github.com/bitcoinknots/bitcoin/releases/tag/v29.1.knots20250903).
[^core-draft]: [Sjors/bitcoin#116](https://github.com/Sjors/bitcoin/pull/116), which continues [bitcoin/bitcoin#32844](https://github.com/bitcoin/bitcoin/pull/32844).
[^electrum]: [spesmilo/electrum-protocol#16](https://github.com/spesmilo/electrum-protocol/pull/16).
[^electrs]: [Blockstream/electrs#235](https://github.com/Blockstream/electrs/pull/235).
[^bob]: [contracts/src/utils/WitnessTx.sol](https://github.com/bob-collective/bob/blob/15d6e7c0dfebbd07a391069f55edef242c99f4c9/contracts/src/utils/WitnessTx.sol) in the BOB repository.
[^advisory]: In August 2026 the ordspv project published [an advisory](https://github.com/ordspv/ordspv/blob/f449d2fc57d3f51fe2bdfb3610d16229d2030992/docs/advisories/2026-08-04-verification-defects-0.2.x.md) about three defects in its own proof verification.
[^json]: [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259), The JavaScript Object Notation (JSON) Data Interchange Format.
[^leaf-node]: Sergio Demian Lerner, [Leaf-Node weakness in Bitcoin Merkle Tree Design](https://bitslog.com/2018/06/09/leaf-node-weakness-in-bitcoin-merkle-tree-design/), 2018.
