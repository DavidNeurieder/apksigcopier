# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import re
import zipfile

from collections import namedtuple
from typing import Any, Dict, Iterable, Optional, Tuple, Union

try:
    from typing import Literal
    NoAutoYes = Literal["no", "auto", "yes"]
except ImportError:
    NoAutoYes = str

DateTime = Tuple[int, int, int, int, int, int]
NoAutoYesBoolNone = Union[NoAutoYes, bool, None]
ZipInfoDataPairs = Iterable[Tuple[zipfile.ZipInfo, bytes]]

SIGBLOCK, SIGOFFSET = "APKSigningBlock", "APKSigningBlockOffset"
NOAUTOYES: Tuple[NoAutoYes, NoAutoYes, NoAutoYes] = ("no", "auto", "yes")
NO, AUTO, YES = NOAUTOYES
APK_META = re.compile(r"^META-INF/([0-9A-Za-z_-]+\.(SF|RSA|DSA|EC)|MANIFEST\.MF)$")
META_EXT: Tuple[str, ...] = ("SF", "RSA|DSA|EC", "MF")
COPY_EXCLUDE: Tuple[str, ...] = ("META-INF/MANIFEST.MF",)
DATETIMEZERO: DateTime = (1980, 0, 0, 0, 0, 0)
VERIFY_CMD: Tuple[str, ...] = ("apksigner", "verify")

VALID_ZIP_META = dict(
    compresslevel=(9, 1),
    create_system=(0, 3),
    create_version=(20, 0),
    external_attr=(0,
                   0o100644 << 16,
                   0o100664 << 16,
                   0o100666 << 16),
    extract_version=(20, 0),
    flag_bits=(0x800, 0, 0x08, 0x808),
)

ZipData = namedtuple("ZipData", ("cd_offset", "eocd_offset", "cd_and_eocd"))


class APKSigCopierError(Exception):
    """Base class for errors."""


class APKSigningBlockError(APKSigCopierError):
    """Something wrong with the APK Signing Block."""


class NoAPKSigningBlock(APKSigningBlockError):
    """APK Signing Block Missing."""


class ZipError(APKSigCopierError):
    """Something wrong with ZIP file."""


class ReproducibleZipInfo(zipfile.ZipInfo):
    """Reproducible ZipInfo hack."""

    _override: Dict[str, Any] = {}

    def __init__(self, zinfo: zipfile.ZipInfo, **override: Any) -> None:
        if override:
            self._override = {**self._override, **override}
        for k in self.__slots__:
            if hasattr(zinfo, k):
                setattr(self, k, getattr(zinfo, k))

    def __getattribute__(self, name: str) -> Any:
        if name != "_override":
            try:
                return self._override[name]
            except KeyError:
                pass
        return object.__getattribute__(self, name)


class APKZipInfo(ReproducibleZipInfo):
    """Reproducible ZipInfo for APK files."""

    COMPRESSLEVEL = 9

    _override = dict(
        compress_type=8,
        create_system=0,
        create_version=20,
        date_time=DATETIMEZERO,
        external_attr=0,
        extract_version=20,
        flag_bits=0x800,
    )
