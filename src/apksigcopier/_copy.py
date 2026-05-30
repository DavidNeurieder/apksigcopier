# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import struct
import tempfile
import zipfile

from typing import BinaryIO, Callable, Dict, Optional, Tuple

from . import _state
from ._types import DATETIMEZERO, DateTime, ZipError
from ._utils import exclude_from_copying
from ._sig import zip_data


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


def copy_apk(unsigned_apk: str, output_apk: str, *,
             copy_extra: Optional[bool] = None,
             exclude: Optional[Callable[[str], bool]] = None,
             realign: Optional[bool] = None,
             zfe_size: Optional[int] = None,
             apksigner35_align: Optional[Dict[str, int]] = None) -> DateTime:
    """
    Copy APK like apksigner would, excluding files matched by exclude_from_copying().

    Adds a zipflinger virtual entry of zfe_size bytes if one is not already
    present and zfe_size is not None.

    Returns max date_time.

    The following global variables (which default to False), can be set to
    override the default behaviour:

    * set exclude_all_meta=True to exclude all metadata files
    * set copy_extra_bytes=True to copy extra bytes after data (e.g. a v2 sig)
    * set skip_realignment=True to skip realignment of ZIP entries

    The default behaviour can also be changed using the keyword-only arguments
    exclude, copy_extra, and realign; these take precedence over the global
    variables when not None.  NB: exclude is a callable, not a bool; realign is
    the inverse of skip_realignment.

    >>> import apksigcopier, os, zipfile
    >>> apk = "tests/apks/apks/golden-aligned-in.apk"
    >>> with zipfile.ZipFile(apk, "r") as zf:
    ...     infos_in = zf.infolist()
    >>> with tempfile.TemporaryDirectory() as tmpdir:
    ...     out = os.path.join(tmpdir, "out.apk")
    ...     apksigcopier.copy_apk(apk, out)
    ...     with zipfile.ZipFile(out, "r") as zf:
    ...         infos_out = zf.infolist()
    (2017, 5, 15, 11, 28, 40)
    >>> for i in infos_in:
    ...     print(i.filename)
    META-INF/
    META-INF/MANIFEST.MF
    AndroidManifest.xml
    classes.dex
    temp.txt
    lib/armeabi/fake.so
    resources.arsc
    temp2.txt
    >>> for i in infos_out:
    ...     print(i.filename)
    AndroidManifest.xml
    classes.dex
    temp.txt
    lib/armeabi/fake.so
    resources.arsc
    temp2.txt
    >>> infos_in[2]
    <ZipInfo filename='AndroidManifest.xml' compress_type=deflate file_size=1672 compress_size=630>
    >>> infos_out[0]
    <ZipInfo filename='AndroidManifest.xml' compress_type=deflate file_size=1672 compress_size=630>
    >>> repr(infos_in[2:]) == repr(infos_out)
    True

    """
    if copy_extra is None:
        copy_extra = _state.copy_extra_bytes
    if exclude is None:
        exclude = exclude_from_copying
    if realign is None:
        realign = not _state.skip_realignment
    with zipfile.ZipFile(unsigned_apk, "r") as zf:
        infos = zf.infolist()
    zdata = zip_data(unsigned_apk)
    offsets = {}
    with open(unsigned_apk, "rb") as fhi, open(output_apk, "w+b") as fho:
        if zfe_size:
            zfe = zipflinger_virtual_entry(zfe_size)
            if fhi.read(zfe_size) != zfe:
                fho.write(zfe)
            fhi.seek(0)
        for info in sorted(infos, key=lambda info: info.header_offset):
            off_i = fhi.tell()
            if info.header_offset > off_i:
                fho.write(fhi.read(info.header_offset - off_i))
            hdr = fhi.read(30)
            if hdr[:4] != b"\x50\x4b\x03\x04":
                raise ZipError("Expected local file header signature")
            n, m = struct.unpack("<HH", hdr[26:30])
            hdr += fhi.read(n + m)
            skip = exclude(info.filename)
            if skip:
                fhi.seek(info.compress_size, os.SEEK_CUR)
            else:
                if info.filename in offsets:
                    raise ZipError(f"Duplicate ZIP entry: {info.filename!r}")
                offsets[info.filename] = off_o = fho.tell()
                force_align = (apksigner35_align or {}).get(info.filename)
                if realign and info.compress_type == 0 and \
                        (force_align is not None or off_o != info.header_offset):
                    hdr = _realign_zip_entry(info, hdr, n, m, off_o,
                                             pad_like_apksigner=not zfe_size,
                                             force_align=force_align)
                fho.write(hdr)
                _copy_bytes(fhi, fho, info.compress_size)
            if info.flag_bits & 0x08:
                data_descriptor = fhi.read(12)
                if data_descriptor[:4] == b"\x50\x4b\x07\x08":
                    data_descriptor += fhi.read(4)
                if not skip:
                    fho.write(data_descriptor)
        extra_bytes = zdata.cd_offset - fhi.tell()
        if copy_extra:
            _copy_bytes(fhi, fho, extra_bytes)
        else:
            fhi.seek(extra_bytes, os.SEEK_CUR)
        cd_offset = fho.tell()
        for info in infos:
            hdr = fhi.read(46)
            if hdr[:4] != b"\x50\x4b\x01\x02":
                raise ZipError("Expected central directory file header signature")
            n, m, k = struct.unpack("<HHH", hdr[28:34])
            hdr += fhi.read(n + m + k)
            if not exclude(info.filename):
                off = int.to_bytes(offsets[info.filename], 4, "little")
                hdr = hdr[:42] + off + hdr[46:]
                fho.write(hdr)
        eocd_offset = fho.tell()
        fho.write(zdata.cd_and_eocd[zdata.eocd_offset - zdata.cd_offset:])
        fho.seek(eocd_offset + 8)
        fho.write(struct.pack("<HHLL", len(offsets), len(offsets),
                              eocd_offset - cd_offset, cd_offset))
    return max(info.date_time for info in infos if info.filename in offsets)


def _realign_zip_entry(info: zipfile.ZipInfo, hdr: bytes, n: int, m: int,
                       off_o: int, *, pad_like_apksigner: bool = True,
                       force_align: Optional[int] = None) -> bytes:
    align = force_align or (4096 if info.filename.endswith(".so") else 4)
    old_off = 30 + n + m + info.header_offset
    new_off = 30 + n + m + off_o
    old_xtr = hdr[30 + n:30 + n + m]
    new_xtr = b""
    while len(old_xtr) >= 4:
        hdr_id, size = struct.unpack("<HH", old_xtr[:4])
        if size > len(old_xtr) - 4:
            break
        if not (hdr_id == 0 and size == 0):
            if hdr_id == 0xd935:
                if size >= 2 and force_align is None:
                    align = int.from_bytes(old_xtr[4:6], "little")
            else:
                new_xtr += old_xtr[:size + 4]
        old_xtr = old_xtr[size + 4:]
    needs_pad = force_align is not None or \
        (old_off % align == 0 and new_off % align != 0)
    if needs_pad:
        if pad_like_apksigner or force_align is not None:
            pad = (align - (new_off - m + len(new_xtr) + 6) % align) % align
            xtr = new_xtr + struct.pack("<HHH", 0xd935, 2 + pad, align) + pad * b"\x00"
        else:
            pad = (align - (new_off - m + len(new_xtr)) % align) % align
            xtr = new_xtr + pad * b"\x00"
        m_b = int.to_bytes(len(xtr), 2, "little")
        hdr = hdr[:28] + m_b + hdr[30:30 + n] + xtr
    return hdr


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


def _copy_bytes(fhi: BinaryIO, fho: BinaryIO, size: int, blocksize: int = 4096) -> None:
    while size > 0:
        data = fhi.read(min(size, blocksize))
        if not data:
            break
        size -= len(data)
        fho.write(data)
    if size != 0:
        raise ZipError("Unexpected EOF")
