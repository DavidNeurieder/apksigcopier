#!/usr/bin/env python3
# encoding: utf-8

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import glob
import os
import os.path as osp
import subprocess
import sys
import zipfile

import dataclasses

import apksigcopier as asc

sys.stdout.reconfigure(line_buffering=True)


APKSIGNER = os.environ.get("APKSIGNER") or asc._find_apksigner()
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
    with asc.saved_state():
        asc._state.DEFAULT_CONFIG = dataclasses.replace(
            asc._state.DEFAULT_CONFIG, skip_realignment=True)
        try:
            asc.do_compare(apk, "apks/apks/golden-unaligned-in.apk",
                           unsigned=True, min_sdk_version=min_sdk_version,
                           verify_cmd=VERIFY_CMD)
        except asc.APKSigCopierError as e:
            print(f"ERROR: {e}")
            failures += 1

sys.exit(1 if failures else 0)
