#!/usr/bin/env python3
"""Compare deployed runtime code with a Foundry artifact, resolving UUPS immutables."""

import json
import sys


def hex_bytes(value: str) -> str:
    return (value[2:] if value.startswith("0x") else value).lower()


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: compare_contract_runtime.py ARTIFACT IMPLEMENTATION", file=sys.stderr)
        return 2
    artifact_path, implementation = sys.argv[1:]
    with open(artifact_path, encoding="utf-8") as source:
        artifact = json.load(source)["deployedBytecode"]
    expected = list(hex_bytes(artifact["object"]))
    actual = hex_bytes(sys.stdin.read().strip())
    address = hex_bytes(implementation)
    if len(address) != 40 or len(actual) != len(expected):
        print("runtime length or implementation address mismatch", file=sys.stderr)
        return 1

    for references in artifact.get("immutableReferences", {}).values():
        for reference in references:
            start = reference["start"] * 2
            end = start + reference["length"] * 2
            if reference["length"] != 32 or end > len(expected):
                print("unexpected immutable layout", file=sys.stderr)
                return 1
            expected[start:end] = address.rjust(64, "0")

    if "".join(expected) != actual:
        print("runtime bytecode differs from compiled artifact", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
