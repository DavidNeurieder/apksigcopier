# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import glob
import json
import os
import tempfile
import zipfile

from typing import Any, Callable, Dict, Iterator, Optional, Tuple

from ._copy import detect_apksigner35_align, detect_zfe
from ._sig import _get_compresslevel, extract_v2_sig
from ._types import (APKSigCopierError, AUTO, META_EXT, NO, SIGBLOCK,
                     SIGOFFSET, VALID_ZIP_META, YES, APKZipInfo,
                     NoAutoYesBoolNone, ZipError, ZipInfoDataPairs)
from ._utils import is_meta, noautoyes


def extract_meta(signed_apk: str) -> Iterator[Tuple[zipfile.ZipInfo, bytes]]:
    """
    Extract v1 signature metadata files from signed APK.

    Yields (ZipInfo, data) pairs.

    >>> from apksigcopier import extract_meta
    >>> apk = "tests/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> meta = tuple(extract_meta(apk))
    >>> [ x.filename for x, _ in meta ]
    ['META-INF/RSA-2048.SF', 'META-INF/RSA-2048.RSA', 'META-INF/MANIFEST.MF']
    >>> for line in meta[0][1].splitlines()[:4]:
    ...     print(line.decode())
    Signature-Version: 1.0
    Created-By: 1.0 (Android)
    SHA-256-Digest-Manifest: hz7AxDJU9Namxoou/kc4Z2GVRS9anCGI+M52tbCsXT0=
    X-Android-APK-Signed: 2, 3
    >>> for line in meta[2][1].splitlines()[:2]:
    ...     print(line.decode())
    Manifest-Version: 1.0
    Created-By: 1.8.0_45-internal (Oracle Corporation)

    """
    with zipfile.ZipFile(signed_apk, "r") as zf_sig:
        for info in zf_sig.infolist():
            if is_meta(info.filename):
                yield info, zf_sig.read(info.filename)


def extract_differences(signed_apk: str, extracted_meta: ZipInfoDataPairs) \
        -> Optional[Dict[str, Any]]:
    """
    Extract ZIP metadata differences from signed APK.

    >>> import apksigcopier as asc, pprint
    >>> apk = "tests/apks/apks/debuggable-boolean.apk"
    >>> meta = tuple(asc.extract_meta(apk))
    >>> [ x.filename for x, _ in meta ]
    ['META-INF/CERT.SF', 'META-INF/CERT.RSA', 'META-INF/MANIFEST.MF']
    >>> diff = asc.extract_differences(apk, meta)
    >>> pprint.pprint(diff)
    {'files': {'META-INF/CERT.RSA': {'flag_bits': 2056},
               'META-INF/CERT.SF': {'flag_bits': 2056},
               'META-INF/MANIFEST.MF': {'flag_bits': 2056}}}

    >>> meta[2][0].extract_version = 42
    >>> try:
    ...     asc.extract_differences(apk, meta)
    ... except asc.ZipError as e:
    ...     print(e)
    Unsupported extract_version

    >>> asc.validate_differences(diff) is None
    True
    >>> diff["files"]["META-INF/OOPS"] = {}
    >>> asc.validate_differences(diff)
    ".files key 'META-INF/OOPS' is not a metadata file"
    >>> del diff["files"]["META-INF/OOPS"]
    >>> diff["files"]["META-INF/CERT.RSA"]["compresslevel"] = 42
    >>> asc.validate_differences(diff)
    ".files['META-INF/CERT.RSA'].compresslevel has an unexpected value"
    >>> diff["oops"] = 42
    >>> asc.validate_differences(diff)
    'contains unknown key(s)'

    """
    differences: Dict[str, Any] = {}
    files = {}
    for info, data in extracted_meta:
        diffs = {}
        for k in VALID_ZIP_META:
            if k != "compresslevel":
                v = getattr(info, k)
                if v != APKZipInfo._override[k]:
                    if v not in VALID_ZIP_META[k]:
                        raise ZipError(f"Unsupported {k}")
                    diffs[k] = v
        level = _get_compresslevel(signed_apk, info, data)
        if level != APKZipInfo.COMPRESSLEVEL:
            diffs["compresslevel"] = level
        if diffs:
            files[info.filename] = diffs
    if files:
        differences["files"] = files
    zfe_size = detect_zfe(signed_apk)
    if zfe_size:
        differences["zipflinger_virtual_entry"] = zfe_size
    return differences or None


def validate_differences(differences: Dict[str, Any]) -> Optional[str]:
    """
    Validate differences dict.

    Returns None if valid, error otherwise.
    """
    if set(differences) - {"files", "zipflinger_virtual_entry", "apksigner35_align"}:
        return "contains unknown key(s)"
    if "zipflinger_virtual_entry" in differences:
        if type(differences["zipflinger_virtual_entry"]) is not int:
            return ".zipflinger_virtual_entry is not an int"
        if not (30 <= differences["zipflinger_virtual_entry"] <= 4096):
            return ".zipflinger_virtual_entry is < 30 or > 4096"
    if "files" in differences:
        if not isinstance(differences["files"], dict):
            return ".files is not a dict"
        for name, info in differences["files"].items():
            if not is_meta(name):
                return f".files key {name!r} is not a metadata file"
            if not isinstance(info, dict):
                return f".files[{name!r}] is not a dict"
            if set(info) - set(VALID_ZIP_META):
                return f".files[{name!r}] contains unknown key(s)"
            for k, v in info.items():
                if v not in VALID_ZIP_META[k]:
                    return f".files[{name!r}].{k} has an unexpected value"
    return None


def do_extract(signed_apk: str, output_dir: str, v1_only: NoAutoYesBoolNone = NO,
               *, ignore_differences: bool = False) -> None:
    """
    Extract signatures from signed_apk and save in output_dir.

    The v1_only parameter controls whether the absence of a v1 signature is
    considered an error or not:
    * use v1_only=NO (or v1_only=False) to only accept (v1+)v2/v3 signatures;
    * use v1_only=AUTO (or v1_only=None) to automatically detect v2/v3 signatures;
    * use v1_only=YES (or v1_only=True) to ignore any v2/v3 signatures.
    """
    v1_only = noautoyes(v1_only)
    extracted_meta = tuple(extract_meta(signed_apk))
    if len(extracted_meta) not in (len(META_EXT), 0):
        raise APKSigCopierError("Unexpected or missing metadata files in signed_apk")
    for info, data in extracted_meta:
        name = os.path.basename(info.filename)
        with open(os.path.join(output_dir, name), "wb") as fh:
            fh.write(data)
    if v1_only == YES:
        if not extracted_meta:
            raise APKSigCopierError("Expected v1 signature")
        return
    expected = v1_only == NO
    extracted_v2_sig = extract_v2_sig(signed_apk, expected=expected)
    if extracted_v2_sig is None:
        if not extracted_meta:
            raise APKSigCopierError("Expected v1 and/or v2/v3 signature, found neither")
        return
    signed_sb_offset, signed_sb = extracted_v2_sig
    with open(os.path.join(output_dir, SIGOFFSET), "w") as fh:
        fh.write(str(signed_sb_offset) + "\n")
    with open(os.path.join(output_dir, SIGBLOCK), "wb") as fh:
        fh.write(signed_sb)
    if not ignore_differences:
        differences = extract_differences(signed_apk, extracted_meta)
        apksigner35_align = detect_apksigner35_align(signed_apk)
        if apksigner35_align:
            if differences is None:
                differences = {}
            differences["apksigner35_align"] = apksigner35_align
        if differences:
            with open(os.path.join(output_dir, "differences.json"), "w") as fh:
                json.dump(differences, fh, sort_keys=True, indent=2)
                fh.write("\n")


def do_patch(metadata_dir: str, unsigned_apk: str, output_apk: str,
             v1_only: NoAutoYesBoolNone = NO, *,
             exclude: Optional[Callable[[str], bool]] = None,
             ignore_differences: bool = False) -> None:
    """
    Patch signatures from metadata_dir onto unsigned_apk and save as output_apk.

    The v1_only parameter controls whether the absence of a v1 signature is
    considered an error or not:
    * use v1_only=NO (or v1_only=False) to only accept (v1+)v2/v3 signatures;
    * use v1_only=AUTO (or v1_only=None) to automatically detect v2/v3 signatures;
    * use v1_only=YES (or v1_only=True) to ignore any v2/v3 signatures.
    """
    from ._patch import patch_apk

    v1_only = noautoyes(v1_only)
    extracted_meta = []
    differences = None
    for pat in META_EXT:
        files = [fn for ext in pat.split("|") for fn in
                 glob.glob(os.path.join(metadata_dir, "*." + ext))]
        if len(files) != 1:
            continue
        info = zipfile.ZipInfo("META-INF/" + os.path.basename(files[0]))
        with open(files[0], "rb") as fh:
            extracted_meta.append((info, fh.read()))
    if len(extracted_meta) not in (len(META_EXT), 0):
        raise APKSigCopierError("Unexpected or missing files in metadata_dir")
    if v1_only == YES:
        extracted_v2_sig = None
    else:
        sigoffset_file = os.path.join(metadata_dir, SIGOFFSET)
        sigblock_file = os.path.join(metadata_dir, SIGBLOCK)
        if v1_only == AUTO and not os.path.exists(sigblock_file):
            extracted_v2_sig = None
        else:
            with open(sigoffset_file, "r") as fh:
                signed_sb_offset = int(fh.read())
            with open(sigblock_file, "rb") as fh:
                signed_sb = fh.read()
            extracted_v2_sig = signed_sb_offset, signed_sb
            differences_file = os.path.join(metadata_dir, "differences.json")
            if not ignore_differences and os.path.exists(differences_file):
                with open(differences_file, "r") as fh:
                    try:
                        differences = json.load(fh)
                    except json.JSONDecodeError as e:
                        raise APKSigCopierError(f"Invalid differences.json: {e}")
                    error = validate_differences(differences)
                    if error:
                        raise APKSigCopierError(f"Invalid differences.json: {error}")
    if not extracted_meta and extracted_v2_sig is None:
        raise APKSigCopierError("Expected v1 and/or v2/v3 signature, found neither")
    patch_apk(extracted_meta, extracted_v2_sig, unsigned_apk, output_apk,
              differences=differences, exclude=exclude)


def do_copy(signed_apk: str, unsigned_apk: str, output_apk: str,
            v1_only: NoAutoYesBoolNone = NO, *,
            exclude: Optional[Callable[[str], bool]] = None,
            ignore_differences: bool = False) -> None:
    """
    Copy signatures from signed_apk onto unsigned_apk and save as output_apk.

    The v1_only parameter controls whether the absence of a v1 signature is
    considered an error or not:
    * use v1_only=NO (or v1_only=False) to only accept (v1+)v2/v3 signatures;
    * use v1_only=AUTO (or v1_only=None) to automatically detect v2/v3 signatures;
    * use v1_only=YES (or v1_only=True) to ignore any v2/v3 signatures.
    """
    from ._patch import patch_apk

    v1_only = noautoyes(v1_only)
    extracted_meta = tuple(extract_meta(signed_apk))
    differences = None
    apksigner35_align: Optional[Dict[str, int]] = None
    if v1_only == YES:
        extracted_v2_sig = None
    else:
        extracted_v2_sig = extract_v2_sig(signed_apk, expected=v1_only == NO)
        if extracted_v2_sig is not None and not ignore_differences:
            differences = extract_differences(signed_apk, extracted_meta)
            apksigner35_align = detect_apksigner35_align(signed_apk)
    patch_apk(extracted_meta, extracted_v2_sig, unsigned_apk, output_apk,
              differences=differences, exclude=exclude,
              apksigner35_align=apksigner35_align)


def do_compare(first_apk: str, second_apk: str, unsigned: bool = False,
               min_sdk_version: Optional[int] = None, *,
               ignore_differences: bool = False,
               verify_cmd: Optional[Tuple[str, ...]] = None) -> None:
    """
    Compare first_apk to second_apk by:
    * using apksigner to check if the first APK verifies
    * checking if the second APK also verifies (unless unsigned is True)
    * copying the signature from first_apk to a copy of second_apk
    * checking if the resulting APK verifies
    """
    from ._sig import verify_apk
    from ._utils import exclude_default, exclude_meta

    verify_apk(first_apk, min_sdk_version=min_sdk_version, verify_cmd=verify_cmd)
    if not unsigned:
        verify_apk(second_apk, min_sdk_version=min_sdk_version, verify_cmd=verify_cmd)
    with tempfile.TemporaryDirectory() as tmpdir:
        output_apk = os.path.join(tmpdir, "output.apk")
        exclude = exclude_default if unsigned else exclude_meta
        do_copy(first_apk, second_apk, output_apk, AUTO, exclude=exclude,
                ignore_differences=ignore_differences)
        verify_apk(output_apk, min_sdk_version=min_sdk_version, verify_cmd=verify_cmd)
