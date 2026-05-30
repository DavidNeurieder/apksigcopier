# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import tempfile
import zipfile

from typing import Any, Callable, Dict, Optional, Tuple

from ._copy import copy_apk
from ._sig import patch_v2_sig
from ._types import (APKZipInfo, DATETIMEZERO, ZipError, ZipInfoDataPairs)
from ._utils import is_meta


def patch_meta(extracted_meta: ZipInfoDataPairs, output_apk: str,
               date_time: DateTime = DATETIMEZERO, *,
               differences: Optional[Dict[str, Any]] = None) -> None:
    """
    Add v1 signature metadata to APK (removes v2 sig block, if any).

    >>> import apksigcopier as asc
    >>> unsigned_apk = "tests/apks/apks/golden-aligned-in.apk"
    >>> signed_apk = "tests/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> meta = tuple(asc.extract_meta(signed_apk))
    >>> [ x.filename for x, _ in meta ]
    ['META-INF/RSA-2048.SF', 'META-INF/RSA-2048.RSA', 'META-INF/MANIFEST.MF']
    >>> with zipfile.ZipFile(unsigned_apk, "r") as zf:
    ...     infos_in = zf.infolist()
    >>> with tempfile.TemporaryDirectory() as tmpdir:
    ...     out = os.path.join(tmpdir, "out.apk")
    ...     asc.copy_apk(unsigned_apk, out)
    ...     asc.patch_meta(meta, out)
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
    META-INF/RSA-2048.SF
    META-INF/RSA-2048.RSA
    META-INF/MANIFEST.MF

    """
    with zipfile.ZipFile(output_apk, "r") as zf_out:
        for info in zf_out.infolist():
            if is_meta(info.filename):
                raise ZipError("Unexpected metadata")
    with zipfile.ZipFile(output_apk, "a") as zf_out:
        for info, data in extracted_meta:
            if differences and "files" in differences:
                more = differences["files"].get(info.filename, {}).copy()
            else:
                more = {}
            level = more.pop("compresslevel", APKZipInfo.COMPRESSLEVEL)
            zinfo = APKZipInfo(info, date_time=date_time, **more)
            zf_out.writestr(zinfo, data, compresslevel=level)


def patch_apk(extracted_meta: ZipInfoDataPairs,
              extracted_v2_sig: Optional[Tuple[int, bytes]],
              unsigned_apk: str, output_apk: str, *,
              differences: Optional[Dict[str, Any]] = None,
              exclude: Optional[Callable[[str], bool]] = None,
              apksigner35_align: Optional[Dict[str, int]] = None) -> None:
    """
    Patch extracted_meta + extracted_v2_sig (if not None) onto unsigned_apk and
    save as output_apk.
    """
    if differences and "zipflinger_virtual_entry" in differences:
        zfe_size = differences["zipflinger_virtual_entry"]
    else:
        zfe_size = None
    if apksigner35_align is None and differences and "apksigner35_align" in differences:
        apksigner35_align = differences["apksigner35_align"]
    date_time = copy_apk(unsigned_apk, output_apk, exclude=exclude, zfe_size=zfe_size,
                         apksigner35_align=apksigner35_align)
    patch_meta(extracted_meta, output_apk, date_time=date_time, differences=differences)
    if extracted_v2_sig is not None:
        patch_v2_sig(extracted_v2_sig, output_apk)
