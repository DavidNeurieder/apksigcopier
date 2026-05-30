# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import struct

from typing import Dict, Optional

from ._types import ZipError


def zipflinger_virtual_entry(size: int) -> bytes:
    """Create zipflinger virtual entry."""
    if size < 30:
        raise ValueError("Minimum size for virtual entries is 30 bytes")
    return (
        b"\x50\x4b\x03\x04" b"\x00\x00"         b"\x00\x00"
        b"\x00\x00"         b"\x21\x08\x21\x02" b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00" b"\x00\x00\x00\x00" b"\x00\x00"
    ) + int.to_bytes(size - 30, 2, "little") + b"\x00" * (size - 30)


def detect_zfe(apkfile: str) -> Optional[int]:
    """
    Detect zipflinger virtual entry.

    Returns the size of the virtual entry if found, None otherwise.

    Raises ZipError if the size is less than 30 or greater than 4096, or the
    data isn't all zeroes.
    """
    with open(apkfile, "rb") as fh:
        zfe_start = zipflinger_virtual_entry(30)[:28]
        if fh.read(28) == zfe_start:
            zfe_size = 30 + int.from_bytes(fh.read(2), "little")
            if not (30 <= zfe_size <= 4096):
                raise ZipError("Unsupported virtual entry size")
            if not fh.read(zfe_size - 30) == b"\x00" * (zfe_size - 30):
                raise ZipError("Unsupported virtual entry data")
            return zfe_size
    return None


def detect_apksigner35_align(apk_path: str) -> Dict[str, int]:
    """
    Detect 0xd935 alignment values in a signed APK.

    Returns a dict of ``{filename: alignment_value}`` for uncompressed entries
    that have a ``0xd935`` "Android ZIP Alignment Extra Field" AND are actually
    aligned to that value.  Entries whose ``0xd935`` field requests alignment
    that isn't actually achieved (e.g. golden-unaligned APKs) are excluded.
    """
    alignments: Dict[str, int] = {}
    with open(apk_path, "rb") as fh:
        data = fh.read()
    pos = 0
    while pos + 30 < len(data):
        if data[pos:pos + 4] != b"\x50\x4b\x03\x04":
            pos += 1
            continue
        n, m = struct.unpack("<HH", data[pos + 26:pos + 30])
        name = data[pos + 30:pos + 30 + n].decode("utf-8", errors="replace")
        compress_type = struct.unpack("<H", data[pos + 8:pos + 10])[0]
        if name.endswith("/"):
            pos += 30 + n + m
            continue
        if compress_type != 0:
            compress_size = struct.unpack("<I", data[pos + 18:pos + 22])[0]
            pos += 30 + n + m + compress_size
            continue
        extra = data[pos + 30 + n:pos + 30 + n + m]
        xp = 0
        data_start = pos + 30 + n + m
        while xp + 4 <= len(extra):
            hdr_id, size = struct.unpack("<HH", extra[xp:xp + 4])
            if hdr_id == 0xd935 and size >= 2:
                align = struct.unpack("<H", extra[xp + 4:xp + 6])[0]
                if data_start % align == 0:
                    alignments[name] = align
                break
            xp += 4 + size
        compress_size = struct.unpack("<I", data[pos + 18:pos + 22])[0]
        pos += 30 + n + m + compress_size
    return alignments
