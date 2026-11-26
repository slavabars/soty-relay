#!/usr/bin/env python3
"""Compile a LuCI .po catalog into the .lmo format used by luci.i18n.

The OpenWrt SDK normally provides ``po2lmo``; this script is a dependency-free
fallback for the local noarch package build. It implements the same format:
translated strings padded to four bytes, a sorted index of network-order
``(key_id, val_id, offset, length)`` tuples, and the index offset as the last
uint32. The hash is Paul Hsieh's sfh_hash after LuCI's whitespace canonisation.
"""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

WS = b" \t\n\r\v\f"


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _signed(byte: int) -> int:
    return byte - 256 if byte >= 128 else byte


def sfh_hash(data: bytes) -> int:
    if not data:
        return 0
    length = len(data)
    h = _u32(length)
    rem = length & 3
    length >>= 2
    pos = 0
    for _ in range(length):
        h = _u32(h + (data[pos] | (data[pos + 1] << 8)))
        tmp = _u32(((data[pos + 2] | (data[pos + 3] << 8)) << 11) ^ h)
        h = _u32(((h << 16) ^ tmp))
        pos += 4
        h = _u32(h + (h >> 11))
    if rem == 3:
        h = _u32(h + (data[pos] | (data[pos + 1] << 8)))
        h = _u32(h ^ (h << 16))
        h = _u32(h ^ (_signed(data[pos + 2]) << 18))
        h = _u32(h + (h >> 11))
    elif rem == 2:
        h = _u32(h + (data[pos] | (data[pos + 1] << 8)))
        h = _u32(h ^ (h << 11))
        h = _u32(h + (h >> 17))
    elif rem == 1:
        h = _u32(h + _signed(data[pos]))
        h = _u32(h ^ (h << 10))
        h = _u32(h + (h >> 1))
    h = _u32(h ^ (h << 3))
    h = _u32(h + (h >> 5))
    h = _u32(h ^ (h << 4))
    h = _u32(h + (h >> 17))
    h = _u32(h ^ (h << 25))
    h = _u32(h + (h >> 6))
    return h


def canon_hash(text: str) -> int:
    raw = text.encode("utf-8")
    out = bytearray()
    prev_space = True
    for byte in raw:
        if byte in WS:
            if not prev_space:
                out.append(0x20)
            prev_space = True
        else:
            out.append(byte)
            prev_space = False
    while out and out[-1] == 0x20:
        out.pop()
    return sfh_hash(bytes(out))


def decode_po_string(raw: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            i += 1
            nxt = raw[i]
            out.append({"n": "\n", "t": "\t", "r": "\r",
                        '"': '"', "\\": "\\"}.get(nxt, nxt))
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def parse_po(path: Path) -> tuple[str, list[tuple[str, str]]]:
    entries: list[tuple[str, str]] = []
    header = ""
    msgid: str | None = None
    msgstr: str | None = None
    state: str | None = None

    def flush() -> None:
        nonlocal msgid, msgstr, header
        if msgid is None:
            return
        if msgid == "":
            header = msgstr or ""
        elif msgstr:
            entries.append((msgid, msgstr))
        msgid = None
        msgstr = None

    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("msgctxt "):
            flush()
            state = "skip"
        elif line.startswith("msgid "):
            flush()
            msgid = decode_po_string(re.search(r'"(.*)"', line).group(1))
            state = "msgid"
        elif line.startswith("msgid_plural "):
            state = "skip"
        elif line.startswith("msgstr") or line.startswith("msgstr["):
            match = re.search(r'"(.*)"', line)
            msgstr = decode_po_string(match.group(1)) if match else ""
            state = "msgstr"
        elif line.startswith('"') and state in ("msgid", "msgstr"):
            part = decode_po_string(re.search(r'"(.*)"', line).group(1))
            if state == "msgid":
                msgid = (msgid or "") + part
            else:
                msgstr = (msgstr or "") + part
        elif not line.strip():
            flush()
            state = None
    flush()

    plural = "nplurals=2; plural=(n != 1);"
    for line in header.splitlines():
        if line.startswith("Plural-Forms:"):
            plural = line[len("Plural-Forms:"):].strip()
            break
    return plural, entries


def build(po: Path, out: Path) -> None:
    plural, entries = parse_po(po)
    data = bytearray()
    index: list[tuple[int, int, int, int]] = []

    def append(raw: bytes) -> tuple[int, int]:
        offset = len(data)
        data.extend(raw)
        data.extend(b"\0" * ((4 - (len(raw) % 4)) % 4))
        return offset, len(raw)

    offset, length = append(plural.encode("utf-8"))
    index.append((0, 0, offset, length))

    seen: set[int] = set()
    for msgid, msgstr in entries:
        key_id = canon_hash(msgid)
        val_id = canon_hash(msgstr)
        if key_id == val_id or key_id in seen:
            continue
        seen.add(key_id)
        offset, length = append(msgstr.encode("utf-8"))
        index.append((key_id, 1, offset, length))

    index.sort(key=lambda item: item[0])
    index_offset = len(data)
    for entry in index:
        data.extend(struct.pack(">IIII", *entry))
    data.extend(struct.pack(">I", index_offset))
    out.write_bytes(bytes(data))


def main() -> None:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} input.po output.lmo", file=sys.stderr)
        raise SystemExit(64)
    build(Path(sys.argv[1]), Path(sys.argv[2]))


if __name__ == "__main__":
    main()
