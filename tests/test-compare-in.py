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


APKSIGNER = os.environ.get("APKSIGNER") or _find_apksigner()
VERIFY_CMD = (APKSIGNER, "verify")


def has_manifest(apk):
    try:
        with zipfile.ZipFile(apk) as zf:
            return any(i.filename == "META-INF/MANIFEST.MF" for i in zf.infolist())
    except zipfile.BadZipFile:
        return False


failures = 0

for apk in sorted(glob.glob("apks/apks/golden-aligned-*out.apk")):
    print(apk)
    min_sdk_version = None if has_manifest(apk) else 24
    try:
        asc.do_compare(apk, "apks/apks/golden-aligned-in.apk",
                       unsigned=True, min_sdk_version=min_sdk_version,
                       verify_cmd=VERIFY_CMD)
    except asc.APKSigCopierError as e:
        print(f"ERROR: {e}")
        failures += 1

for apk in sorted(glob.glob("apks/apks/golden-legacy-aligned-*out.apk")):
    print(apk)
    min_sdk_version = None if has_manifest(apk) else 24
    try:
        asc.do_compare(apk, "apks/apks/golden-legacy-aligned-in.apk",
                       unsigned=True, min_sdk_version=min_sdk_version,
                       verify_cmd=VERIFY_CMD)
    except asc.APKSigCopierError as e:
        print(f"ERROR: {e}")
        failures += 1

for apk in sorted(glob.glob("apks/apks/golden-unaligned-*out.apk")):
    print(apk)
    min_sdk_version = None if has_manifest(apk) else 24
    asc._state.skip_realignment = True
    try:
        asc.do_compare(apk, "apks/apks/golden-unaligned-in.apk",
                       unsigned=True, min_sdk_version=min_sdk_version,
                       verify_cmd=VERIFY_CMD)
    except asc.APKSigCopierError as e:
        print(f"ERROR: {e}")
        failures += 1
    asc._state.skip_realignment = False

sys.exit(1 if failures else 0)
