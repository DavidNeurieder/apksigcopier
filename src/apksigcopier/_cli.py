# encoding: utf-8
# SPDX-FileCopyrightText: 2023 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import sys
import zipfile

from typing import Any

from . import __version__, _state
from ._types import APKSigCopierError, NO, NOAUTOYES, VERIFY_CMD
from ._version import NAME
from ._extract import do_compare, do_copy, do_extract, do_patch


def main() -> None:
    """CLI; requires click."""

    _state.exclude_all_meta = os.environ.get("APKSIGCOPIER_EXCLUDE_ALL_META") in ("1", "yes", "true")
    _state.copy_extra_bytes = os.environ.get("APKSIGCOPIER_COPY_EXTRA_BYTES") in ("1", "yes", "true")
    _state.skip_realignment = os.environ.get("APKSIGCOPIER_SKIP_REALIGNMENT") in ("1", "yes", "true")

    import click

    NAY = click.Choice(NOAUTOYES)

    @click.group(help="""
        apksigcopier - copy/extract/patch android apk signatures & compare apks
    """)
    @click.version_option(__version__)
    def cli() -> None:
        pass

    @cli.command(help="""
        Extract APK signatures from signed APK.
    """)
    @click.option("--v1-only", type=NAY, default=NO, show_default=True,
                  envvar="APKSIGCOPIER_V1_ONLY", help="Expect only a v1 signature.")
    @click.option("--ignore-differences", is_flag=True, help="Don't write differences.json.")
    @click.argument("signed_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_dir", type=click.Path(exists=True, file_okay=False))
    def extract(*args: Any, **kwargs: Any) -> None:
        do_extract(*args, **kwargs)

    @cli.command(help="""
        Patch extracted APK signatures onto unsigned APK.
    """)
    @click.option("--v1-only", type=NAY, default=NO, show_default=True,
                  envvar="APKSIGCOPIER_V1_ONLY", help="Expect only a v1 signature.")
    @click.option("--ignore-differences", is_flag=True, help="Don't read differences.json.")
    @click.argument("metadata_dir", type=click.Path(exists=True, file_okay=False))
    @click.argument("unsigned_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    def patch(*args: Any, **kwargs: Any) -> None:
        do_patch(*args, **kwargs)

    @cli.command(help="""
        Copy (extract & patch) signatures from signed to unsigned APK.
    """)
    @click.option("--v1-only", type=NAY, default=NO, show_default=True,
                  envvar="APKSIGCOPIER_V1_ONLY", help="Expect only a v1 signature.")
    @click.option("--ignore-differences", is_flag=True, help="Don't copy metadata differences.")
    @click.argument("signed_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("unsigned_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    def copy(*args: Any, **kwargs: Any) -> None:
        do_copy(*args, **kwargs)

    @cli.command(help="""
        Compare two APKs by copying the signature from the first to a copy of
        the second and checking if the resulting APK verifies.

        This command requires apksigner.
    """)
    @click.option("--unsigned", is_flag=True, help="Accept unsigned SECOND_APK.")
    @click.option("--min-sdk-version", type=click.INT, help="Passed to apksigner.")
    @click.option("--ignore-differences", is_flag=True, help="Don't copy metadata differences.")
    @click.option("--verify-cmd", metavar="COMMAND", help="Command (with arguments) used to "
                  f"verify APKs.  [default: {' '.join(VERIFY_CMD)!r}]")
    @click.argument("first_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("second_apk", type=click.Path(exists=True, dir_okay=False))
    def compare(*args: Any, **kwargs: Any) -> None:
        if kwargs["verify_cmd"] is not None:
            kwargs["verify_cmd"] = tuple(kwargs["verify_cmd"].split())
        do_compare(*args, **kwargs)

    try:
        cli(prog_name=NAME)
    except (APKSigCopierError, zipfile.BadZipFile) as e:
        click.echo(f"Error: {e}.", err=True)
        sys.exit(1)
