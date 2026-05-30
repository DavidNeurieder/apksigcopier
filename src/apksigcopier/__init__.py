# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
apksigcopier - copy/extract/patch Android APK signatures & compare APKs.
"""


from ._version import __version__  # noqa: F401

from ._state import (copy_extra_bytes, exclude_all_meta,  # noqa: F401
                     saved_state, skip_realignment)
from ._types import (APKSigCopierError, APKSigningBlockError, AUTO,  # noqa: F401
                     DATETIMEZERO, META_EXT, NO, NOAUTOYES, NoAPKSigningBlock,  # noqa: F401
                     NoAutoYes, NoAutoYesBoolNone, SIGBLOCK, SIGOFFSET,
                     VALID_ZIP_META, YES, APKZipInfo, ZipError,
                     ZipInfoDataPairs)
from ._utils import (_find_apksigner, exclude_default,  # noqa: F401
                     exclude_from_copying, exclude_meta, is_directory,
                     is_meta, noautoyes)
from ._sig import (extract_v2_sig, patch_v2_sig, verify_apk,  # noqa: F401
                   zip_data)
from ._copy import (copy_apk, detect_apksigner35_align,  # noqa: F401
                    detect_zfe)
from ._extract import (do_compare, do_copy, do_extract,  # noqa: F401
                       do_patch, extract_differences, extract_meta,
                       validate_differences)
from ._patch import patch_apk, patch_meta  # noqa: F401
