#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run the test vectors against the reference implementation."""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from reference import ProofError, proof_from_json, proof_from_json_text, proof_to_json, verify  # noqa: E402


def display(h: bytes) -> str:
    return h[::-1].hex()


def load(name):
    with open(os.path.join(HERE, "test_vectors", name)) as f:
        return json.load(f)


def check_valid(vector) -> bool:
    proof = bytes.fromhex(vector["proof"])
    try:
        if proof_to_json(proof) != vector["json"] or proof_from_json(vector["json"]) != proof:
            print(f"FAIL (JSON form differs): {vector['comment']}")
            return False
        result = verify(proof, vector["segwit_active"])
    except ProofError as e:
        print(f"FAIL (rejected with {e.code}): {vector['comment']}")
        return False
    got = {
        "block_hash": display(result.block_hash),
        "has_witness_commitment": result.has_witness_commitment,
        "coinbase_txid": display(result.coinbase_txid),
        "entries": [{"position": p, "wtxid": display(w)} for p, w in result.entries],
    }
    if got != vector["expected"]:
        print(f"FAIL (wrong result): {vector['comment']}")
        return False
    return True


def check_invalid(vector) -> bool:
    try:
        verify(bytes.fromhex(vector["proof"]), vector["segwit_active"])
    except ProofError as e:
        if e.code != vector["error"]:
            print(f"FAIL (rejected with {e.code}, expected {vector['error']}): {vector['comment']}")
            return False
        return True
    print(f"FAIL (accepted): {vector['comment']}")
    return False


def check_json_equivalent(vector) -> bool:
    try:
        if proof_from_json_text(vector["text"]) == bytes.fromhex(vector["proof"]):
            return True
    except ProofError as e:
        print(f"FAIL (rejected with {e.code}): {vector['comment']}")
        return False
    print(f"FAIL (different bytes): {vector['comment']}")
    return False


def check_json_invalid(vector) -> bool:
    try:
        proof_from_json_text(vector["text"])
    except ProofError as e:
        if e.code != vector["error"]:
            print(f"FAIL (rejected with {e.code}, expected {vector['error']}): {vector['comment']}")
            return False
        return True
    print(f"FAIL (accepted): {vector['comment']}")
    return False


def main() -> int:
    failures = 0
    json_vectors = load("json.json")
    for name, vectors, check in (
        ("valid.json", load("valid.json"), check_valid),
        ("invalid.json", load("invalid.json"), check_invalid),
        ("json.json equivalent", json_vectors["equivalent"], check_json_equivalent),
        ("json.json invalid", json_vectors["invalid"], check_json_invalid),
    ):
        passed = sum(check(v) for v in vectors)
        failures += len(vectors) - passed
        print(f"{name}: {passed}/{len(vectors)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
