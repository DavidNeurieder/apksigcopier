#!/usr/bin/env python3
# encoding: utf-8

import glob
import os
import os.path as osp
import subprocess
import sys
import zipfile

import apksigcopier as asc

sys.stdout.reconfigure(line_buffering=True)


APKSIGNER = os.environ.get("APKSIGNER") or asc._find_apksigner()
VERIFY_CMD = (APKSIGNER, "verify")


for apk in sorted(glob.glob("apks/apks/*.apk")):
    if "empty" in apk or "negmod" in apk or "weird-compression-method" in apk:
        continue
    print(apk)

    try:
        with zipfile.ZipFile(apk) as zf:
            has_manifest = any(i.filename == "META-INF/MANIFEST.MF"
                               for i in zf.infolist())
    except zipfile.BadZipFile:
        has_manifest = False
    min_sdk_version = None if has_manifest else 24

    verify_args = list(VERIFY_CMD)
    if min_sdk_version is not None:
        verify_args.append(f"--min-sdk-version={min_sdk_version}")
    verify_args += ["--", apk]

    result = subprocess.run(verify_args, capture_output=True)
    if result.returncode != 0:
        print("apksigner: not verified")
        print()
        continue

    print("apksigner: verified")

    try:
        asc.do_compare(apk, apk, min_sdk_version=min_sdk_version,
                       verify_cmd=VERIFY_CMD)
        print("apksigcopier: success")
    except (asc.APKSigCopierError, zipfile.BadZipFile) as e:
        print(f"Error: {e}.")
        print("apksigcopier: failure")
    print()
