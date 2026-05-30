# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
apksigcopier - copy/extract/patch Android APK signatures & compare APKs.
"""


from ._version import __version__  # noqa: F401

from ._state import saved_state  # noqa: F401
from ._types import (APKSigCopierError, APKSigningBlockError, AUTO,  # noqa: F401
                     DATETIMEZERO, META_EXT, NO, NOAUTOYES, NoAPKSigningBlock,  # noqa: F401
                     NoAutoYes, NoAutoYesBoolNone, SIGBLOCK, SIGOFFSET,
                     VALID_ZIP_META, YES, APKZipInfo, ZipError,
                     ZipInfoDataPairs)
from ._utils import (_find_apksigner, _get_compresslevel,  # noqa: F401
                     exclude_default, exclude_from_copying, exclude_meta,
                     is_directory, is_meta, noautoyes, zip_data)
from ._sig import (extract_v2_sig, patch_v2_sig, verify_apk)  # noqa: F401
from ._align import (detect_apksigner35_align, detect_zfe,  # noqa: F401
                     zipflinger_virtual_entry)
from ._copy import copy_apk  # noqa: F401
from ._extract import (do_compare, do_copy, do_extract,  # noqa: F401
                       do_patch, extract_differences, extract_meta,
                       validate_differences)
from ._patch import patch_apk, patch_meta  # noqa: F401


from ._config import Config  # noqa: F401


def __getattr__(name: str):
    """Provide live access to mutable state variables."""
    if name in ("copy_extra_bytes", "exclude_all_meta", "skip_realignment"):
        from . import _state
        return getattr(_state.DEFAULT_CONFIG, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
