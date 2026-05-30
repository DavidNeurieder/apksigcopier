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


def _find_apksigner(prefix=None):
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


APKSIGNER = os.environ.get("APKSIGNER") or _find_apksigner("34")
APKSIGNER34 = os.environ.get("APKSIGNER34") or _find_apksigner("34")
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
