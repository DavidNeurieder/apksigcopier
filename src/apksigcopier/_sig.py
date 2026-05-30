# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import subprocess
import tempfile

logger = logging.getLogger(__name__)

from typing import Optional, Tuple

from ._types import (APKSigningBlockError, APKSigCopierError, NoAPKSigningBlock,
                     ZipError)
from ._utils import zip_data


def extract_v2_sig(apkfile: str, expected: bool = True) -> Optional[Tuple[int, bytes]]:
    """
    Extract APK Signing Block and offset from APK.

    When successful, returns (sb_offset, sig_block); otherwise raises
    NoAPKSigningBlock when expected is True, else returns None.

    >>> import apksigcopier as asc
    >>> apk = "tests/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> sb_offset, sig_block = asc.extract_v2_sig(apk)
    >>> sb_offset
    8192
    >>> len(sig_block)
    4096

    >>> apk = "tests/apks/apks/golden-aligned-in.apk"
    >>> try:
    ...     asc.extract_v2_sig(apk)
    ... except asc.NoAPKSigningBlock as e:
    ...     print(e)
    No APK Signing Block

    """
    cd_offset = zip_data(apkfile).cd_offset
    with open(apkfile, "rb") as fh:
        fh.seek(cd_offset - 16)
        if fh.read(16) != b"APK Sig Block 42":
            if expected:
                raise NoAPKSigningBlock("No APK Signing Block")
            return None
        fh.seek(-24, os.SEEK_CUR)
        sb_size2 = int.from_bytes(fh.read(8), "little")
        fh.seek(-sb_size2 + 8, os.SEEK_CUR)
        sb_size1 = int.from_bytes(fh.read(8), "little")
        if sb_size1 != sb_size2:
            raise APKSigningBlockError("APK Signing Block sizes not equal")
        fh.seek(-8, os.SEEK_CUR)
        sb_offset = fh.tell()
        sig_block = fh.read(sb_size2 + 8)
    return sb_offset, sig_block


def patch_v2_sig(extracted_v2_sig: Tuple[int, bytes], output_apk: str) -> None:
    """
    Implant extracted v2/v3 signature into APK.

    >>> import apksigcopier as asc
    >>> unsigned_apk = "tests/apks/apks/golden-aligned-in.apk"
    >>> signed_apk = "tests/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> meta = tuple(asc.extract_meta(signed_apk))
    >>> v2_sig = asc.extract_v2_sig(signed_apk)
    >>> with tempfile.TemporaryDirectory() as tmpdir:
    ...     out = os.path.join(tmpdir, "out.apk")
    ...     date_time = asc.copy_apk(unsigned_apk, out)
    ...     asc.patch_meta(meta, out, date_time=date_time)
    ...     asc.extract_v2_sig(out, expected=False) is None
    ...     asc.patch_v2_sig(v2_sig, out)
    ...     asc.extract_v2_sig(out) == v2_sig
    ...     with open(signed_apk, "rb") as a, open(out, "rb") as b:
    ...         a.read() == b.read()
    True
    True
    True

    """
    signed_sb_offset, signed_sb = extracted_v2_sig
    data_out = zip_data(output_apk)
    if signed_sb_offset < data_out.cd_offset:
        raise APKSigningBlockError("APK Signing Block offset < central directory offset")
    padding = b"\x00" * (signed_sb_offset - data_out.cd_offset)
    offset = len(signed_sb) + len(padding)
    with open(output_apk, "r+b") as fh:
        fh.seek(data_out.cd_offset)
        fh.write(padding)
        fh.write(signed_sb)
        fh.write(data_out.cd_and_eocd)
        fh.seek(data_out.eocd_offset + offset + 16)
        fh.write(int.to_bytes(data_out.cd_offset + offset, 4, "little"))


def verify_apk(apk: str, min_sdk_version: Optional[int] = None,
               verify_cmd: Optional[Tuple[str, ...]] = None) -> None:
    """Verifies APK using apksigner."""
    from ._types import VERIFY_CMD
    from ._utils import _find_apksigner
    args = tuple(verify_cmd or VERIFY_CMD)
    if min_sdk_version is not None:
        args += (f"--min-sdk-version={min_sdk_version}",)
    args += ("--", apk)
    logger.info("Using apksigner: %s", args[0])
    try:
        subprocess.run(args, check=True, stdout=subprocess.PIPE)
    except subprocess.CalledProcessError:
        raise APKSigCopierError(f"failed to verify {apk}")
    except FileNotFoundError:
        if verify_cmd is not None:
            raise APKSigCopierError(f"{args[0]} command not found")
        apksigner = _find_apksigner()
        if apksigner is None:
            raise APKSigCopierError("apksigner not found — set APKSIGNER, ANDROID_HOME, "
                                    "or install Android SDK build-tools")
        args = (apksigner, "verify")
        if min_sdk_version is not None:
            args += (f"--min-sdk-version={min_sdk_version}",)
        args += ("--", apk)
        logger.info("Using apksigner: %s", apksigner)
        try:
            subprocess.run(args, check=True, stdout=subprocess.PIPE)
        except subprocess.CalledProcessError:
            raise APKSigCopierError(f"failed to verify {apk}")
        except FileNotFoundError:
            raise APKSigCopierError(f"{apksigner} command not found")



