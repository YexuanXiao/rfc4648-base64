import argparse
import base64
import random
from dataclasses import dataclass


_CROCKFORD_ALPHABET_UPPER = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_ALPHABET_LOWER = _CROCKFORD_ALPHABET_UPPER.lower()


def _encode_base32_custom(data: bytes, alphabet32: str, padding: bool) -> str:
    if len(alphabet32) != 32:
        raise ValueError("alphabet32 must have exactly 32 characters")

    out: list[str] = []
    bitbuf = 0
    bitlen = 0

    for b in data:
        bitbuf = (bitbuf << 8) | b
        bitlen += 8

        while bitlen >= 5:
            bitlen -= 5
            idx = (bitbuf >> bitlen) & 0x1F
            out.append(alphabet32[idx])

    if bitlen:
        idx = (bitbuf << (5 - bitlen)) & 0x1F
        out.append(alphabet32[idx])

    if padding:
        while len(out) % 8:
            out.append("=")

    return "".join(out)


def _strip_padding(s: str, padding: bool) -> str:
    if padding:
        return s
    return s.rstrip("=")


def _encode_expected(data: bytes, kind: str, padding: bool) -> str:
    if kind == "base64":
        return _strip_padding(base64.b64encode(data).decode("ascii"), padding)
    if kind == "base64_url":
        return _strip_padding(base64.urlsafe_b64encode(data).decode("ascii"), padding)

    if kind == "base32":
        return _strip_padding(base64.b32encode(data).decode("ascii"), padding)
    if kind == "base32_lower":
        return _strip_padding(base64.b32encode(data).decode("ascii").lower(), padding)
    if kind == "base32_mixed":
        return _strip_padding(base64.b32encode(data).decode("ascii"), padding)

    if kind == "base32_hex":
        return _strip_padding(base64.b32hexencode(data).decode("ascii"), padding)
    if kind == "base32_hex_lower":
        return _strip_padding(base64.b32hexencode(data).decode("ascii").lower(), padding)
    if kind == "base32_hex_mixed":
        return _strip_padding(base64.b32hexencode(data).decode("ascii"), padding)

    if kind == "base32_crockford":
        return _strip_padding(_encode_base32_custom(data, _CROCKFORD_ALPHABET_UPPER, True), padding)
    if kind == "base32_crockford_lower":
        return _strip_padding(_encode_base32_custom(data, _CROCKFORD_ALPHABET_LOWER, True), padding)
    if kind == "base32_crockford_mixed":
        return _strip_padding(_encode_base32_custom(data, _CROCKFORD_ALPHABET_UPPER, True), padding)

    if kind == "base16":
        return base64.b16encode(data).decode("ascii")
    if kind == "base16_lower":
        return base64.b16encode(data).decode("ascii").lower()
    if kind == "base16_mixed":
        return base64.b16encode(data).decode("ascii")

    raise ValueError(f"unknown kind: {kind}")


def _dedupe_keep_order(items: list[bytes]) -> list[bytes]:
    seen: set[bytes] = set()
    out: list[bytes] = []
    for x in items:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def _generate_inputs(seed: int) -> list[bytes]:
    inputs: list[bytes] = []

    # RFC 4648's canonical examples for base64/base32.
    inputs += [b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"]

    # Binary edge cases.
    inputs += [
        bytes([0x00]),
        bytes([0x00, 0x00]),
        bytes([0x00, 0x00, 0x00]),
        bytes([0xFF]),
        bytes([0xFF, 0xFF]),
        bytes([0xFF, 0xFF, 0xFF]),
        bytes(range(0, 64)),
        bytes(range(63, -1, -1)),
        bytes([0x00, 0xFF]) * 32,
    ]

    rng = random.Random(seed)

    # Hand-picked lengths to hit boundary conditions of 3/5/6/8-byte inner loops.
    lengths = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 31, 32, 33, 47, 48, 49, 63, 64]
    for n in lengths:
        inputs.append(bytes(rng.randrange(256) for _ in range(n)))

    # Additional random cases (deterministic).
    for _ in range(25):
        n = rng.randrange(0, 65)
        inputs.append(bytes(rng.randrange(256) for _ in range(n)))

    return _dedupe_keep_order(inputs)


@dataclass(frozen=True)
class Vector:
    kind: str
    padding: bool
    input_index: int
    encoded: str


def _generate_vectors(inputs: list[bytes]) -> list[Vector]:
    kinds = [
        "base64",
        "base64_url",
        "base32",
        "base32_lower",
        "base32_mixed",
        "base32_hex",
        "base32_hex_lower",
        "base32_hex_mixed",
        "base32_crockford",
        "base32_crockford_lower",
        "base32_crockford_mixed",
        "base16",
        "base16_lower",
        "base16_mixed",
    ]

    vectors: list[Vector] = []
    for kind in kinds:
        for padding in ([True, False] if not kind.startswith("base16") else [True]):
            for i, data in enumerate(inputs):
                vectors.append(Vector(kind=kind, padding=padding, input_index=i, encoded=_encode_expected(data, kind, padding)))
    return vectors


def _c_array_bytes(data: bytes) -> str:
    return ", ".join(f"0x{b:02X}" for b in data)


def _write_header(path: str, inputs: list[bytes], vectors: list[Vector]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("// This file is generated by tests/gen_vectors.py. Do not edit by hand.\n")
        f.write("#pragma once\n\n")
        f.write('#include "common.hpp"\n\n')
        f.write("#include <cstddef>\n")
        f.write("#include <string_view>\n\n")
        f.write("namespace rfc4648_test_vectors\n")
        f.write("{\n")
        f.write("struct vector\n")
        f.write("{\n")
        f.write("    bizwen::rfc4648_kind kind;\n")
        f.write("    bool padding;\n")
        f.write("    unsigned char const* input;\n")
        f.write("    std::size_t input_size;\n")
        f.write("    std::string_view encoded;\n")
        f.write("};\n\n")

        for i, data in enumerate(inputs):
            if not data:
                continue
            f.write(f"inline constexpr unsigned char input_{i}[] = {{{_c_array_bytes(data)}}};\n")
        f.write("\n")

        f.write("inline constexpr vector vectors[] = {\n")
        for v in vectors:
            kind_expr = f"bizwen::rfc4648_kind::{v.kind}"
            ptr_expr = "nullptr" if len(inputs[v.input_index]) == 0 else f"input_{v.input_index}"
            size_expr = "0" if len(inputs[v.input_index]) == 0 else f"sizeof(input_{v.input_index})"
            f.write(f'    {{{kind_expr}, {"true" if v.padding else "false"}, {ptr_expr}, {size_expr}, "{v.encoded}"}},\n')
        f.write("};\n")
        f.write("} // namespace rfc4648_test_vectors\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    ap.add_argument("--seed", type=int, default=0x0B5A64D5)
    ns = ap.parse_args()

    inputs = _generate_inputs(ns.seed)
    vectors = _generate_vectors(inputs)
    _write_header(ns.output, inputs, vectors)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
