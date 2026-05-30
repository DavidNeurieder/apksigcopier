# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import os.path as osp
import struct
import zipfile
import zlib

from typing import Optional, Tuple

from . import _state
from ._types import AUTO, COPY_EXCLUDE, NO, NOAUTOYES, YES, \
    NoAutoYes, NoAutoYesBoolNone, ZipData, ZipError


def noautoyes(value: NoAutoYesBoolNone) -> NoAutoYes:
    """
    Turns False into NO, None into AUTO, and True into YES.

    >>> from apksigcopier import noautoyes, NO, AUTO, YES
    >>> noautoyes(False) == NO == noautoyes(NO)
    True
    >>> noautoyes(None) == AUTO == noautoyes(AUTO)
    True
    >>> noautoyes(True) == YES == noautoyes(YES)
    True

    """
    if isinstance(value, str):
        if value not in NOAUTOYES:
            raise ValueError("expected NO, AUTO, or YES")
        return value
    try:
        return {False: NO, None: AUTO, True: YES}[value]
    except KeyError:
        raise ValueError("expected False, None, or True")


def is_meta(filename: str) -> bool:
    """
    Returns whether filename is a v1 (JAR) signature file (.SF), signature block
    file (.RSA, .DSA, or .EC), or manifest (MANIFEST.MF).

    See https://docs.oracle.com/javase/tutorial/deployment/jar/intro.html

    >>> from apksigcopier import is_meta
    >>> is_meta("classes.dex")
    False
    >>> is_meta("META-INF/CERT.SF")
    True
    >>> is_meta("META-INF/CERT.RSA")
    True
    >>> is_meta("META-INF/MANIFEST.MF")
    True
    >>> is_meta("META-INF/OOPS")
    False

    """
    from ._types import APK_META
    return APK_META.fullmatch(filename) is not None


def exclude_from_copying(filename: str) -> bool:
    """
    Returns whether to exclude a file during copy_apk().

    Excludes filenames in COPY_EXCLUDE (i.e. MANIFEST.MF) by default; when
    exclude_all_meta is set to True instead, excludes all metadata files as
    matched by is_meta().

    Directories are always excluded.

    >>> import apksigcopier
    >>> from apksigcopier import exclude_from_copying
    >>> exclude_from_copying("classes.dex")
    False
    >>> exclude_from_copying("foo/")
    True
    >>> exclude_from_copying("META-INF/")
    True
    >>> exclude_from_copying("META-INF/MANIFEST.MF")
    True
    >>> exclude_from_copying("META-INF/CERT.SF")
    False
    >>> exclude_from_copying("META-INF/OOPS")
    False

    >>> from apksigcopier import _state
    >>> _state.DEFAULT_CONFIG = _state.Config(exclude_all_meta=True)
    >>> exclude_from_copying("classes.dex")
    False
    >>> exclude_from_copying("META-INF/")
    True
    >>> exclude_from_copying("META-INF/MANIFEST.MF")
    True
    >>> exclude_from_copying("META-INF/CERT.SF")
    True
    >>> exclude_from_copying("META-INF/OOPS")
    False
    >>> _state.DEFAULT_CONFIG = _state.Config()

    """
    return exclude_meta(filename) if _state.DEFAULT_CONFIG.exclude_all_meta else exclude_default(filename)


def exclude_default(filename: str) -> bool:
    """Like exclude_from_copying(); excludes directories and filenames in
    COPY_EXCLUDE (i.e. MANIFEST.MF)."""
    return is_directory(filename) or filename in COPY_EXCLUDE


def exclude_meta(filename: str) -> bool:
    """Like exclude_from_copying(); excludes directories and all metadata files."""
    return is_directory(filename) or is_meta(filename)


def _find_apksigner(prefix: Optional[str] = None) -> Optional[str]:
    """Find apksigner via ANDROID_HOME/ANDROID_SDK_ROOT.

    With prefix="36" matches 36.0.0, 36.1.0, etc.  With prefix=None returns
    the highest installed version.
    """
    sdk = (os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
           or osp.expanduser("~/Android/Sdk"))
    bt_dir = osp.join(sdk, "build-tools")
    if not osp.isdir(bt_dir):
        return None
    versions = sorted(
        (v for v in os.listdir(bt_dir) if osp.isdir(osp.join(bt_dir, v))),
        key=lambda v: [int(x) for x in v.split(".")],
        reverse=True,
    )
    for v in versions:
        if prefix and not v.startswith(prefix):
            continue
        apk = osp.join(bt_dir, v, "apksigner")
        if osp.isfile(apk):
            return apk
    return None


def zip_data(apkfile: str, count: int = 1024) -> ZipData:
    """
    Extract central directory, EOCD, and offsets from ZIP.

    Returns ZipData.

    >>> import apksigcopier
    >>> apk = "tests/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> data = apksigcopier.zip_data(apk)
    >>> data.cd_offset, data.eocd_offset
    (12288, 12843)
    >>> len(data.cd_and_eocd)
    577

    """
    with open(apkfile, "rb") as fh:
        fh.seek(-count, os.SEEK_END)
        data = fh.read()
        pos = data.rfind(b"\x50\x4b\x05\x06")
        if pos == -1:
            raise ZipError("Expected end of central directory record (EOCD)")
        fh.seek(pos - len(data), os.SEEK_CUR)
        eocd_offset = fh.tell()
        fh.seek(16, os.SEEK_CUR)
        cd_offset = int.from_bytes(fh.read(4), "little")
        fh.seek(cd_offset)
        cd_and_eocd = fh.read()
    return ZipData(cd_offset, eocd_offset, cd_and_eocd)


def _get_compresslevel(apkfile: str, info: zipfile.ZipInfo, data: bytes) -> int:
    if info.compress_type != 8:
        raise ZipError("Unsupported compress_type")
    crc = _get_compressed_crc(apkfile, info)
    for level in (9, 1):
        comp = zlib.compressobj(level, 8, -15)
        if zlib.crc32(comp.compress(data) + comp.flush()) == crc:
            return level
    raise ZipError("Unsupported compresslevel")


def _get_compressed_crc(apkfile: str, info: zipfile.ZipInfo) -> int:
    with open(apkfile, "rb") as fh:
        fh.seek(info.header_offset)
        hdr = fh.read(30)
        if hdr[:4] != b"\x50\x4b\x03\x04":
            raise ZipError("Expected local file header signature")
        n, m = struct.unpack("<HH", hdr[26:30])
        fh.seek(n + m, os.SEEK_CUR)
        return zlib.crc32(fh.read(info.compress_size))


def is_directory(filename: str) -> bool:
    """ZIP entries with filenames that end with a '/' are directories."""
    return filename.endswith("/")
