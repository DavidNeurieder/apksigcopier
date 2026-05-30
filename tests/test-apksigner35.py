#!/usr/bin/env python3
# encoding: utf-8
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for apksigner 35+ style alignment (0xd935 extra fields)."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import os
import os.path as osp
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

import apksigcopier as asc

APKS_DIR = osp.join(osp.dirname(__file__), "apks", "apks")
KEYSTORE = osp.join(osp.dirname(__file__), "keys", "debug.keystore")


# Both build-tools 34 and 36 must be installed for these tests.
APKSIGNER = os.environ.get("APKSIGNER") or asc._find_apksigner("36")
APKSIGNER34 = os.environ.get("APKSIGNER34") or asc._find_apksigner("34")

if not APKSIGNER:
    raise RuntimeError(
        "apksigner not found. Set APKSIGNER env var or ANDROID_HOME."
    )

VERIFY_CMD = (APKSIGNER, "verify")


def apksigner_sign(apk_path, apksigner=APKSIGNER):
    """Sign an APK in-place using the configured apksigner and keystore."""
    subprocess.run(
        [apksigner, "sign",
         "--ks", KEYSTORE,
         "--ks-key-alias", "android",
         "--ks-pass", "pass:android",
         "--key-pass", "pass:android",
         apk_path],
        check=True, capture_output=True)


def build_unsigned_apk_no_meta(tmpdir):
    """Build an unsigned APK without META-INF entries from golden-aligned-in.apk."""
    src = osp.join(APKS_DIR, "golden-aligned-in.apk")
    dst = osp.join(tmpdir, "unsigned-no-meta.apk")
    with zipfile.ZipFile(src, "r") as zin:
        with zipfile.ZipFile(dst, "w") as zout:
            for info in zin.infolist():
                if not info.filename.startswith("META-INF/"):
                    zout.writestr(info, zin.read(info.filename))
    return dst


def check_d935_fields(apk_path):
    """Return dict {entry_name: alignment} for 0xd935 extra fields.

    Only checks uncompressed entries and skips directories.
    """
    with open(apk_path, "rb") as f:
        data = f.read()
    results = {}
    pos = 0
    while pos + 30 < len(data):
        if data[pos:pos + 4] != b"\x50\x4b\x03\x04":
            pos += 1
            continue
        n, m = struct.unpack("<HH", data[pos + 26:pos + 30])
        name = data[pos + 30:pos + 30 + n].decode("utf-8", errors="replace")
        compress_type = struct.unpack("<H", data[pos + 8:pos + 10])[0]
        compress_size = struct.unpack("<I", data[pos + 18:pos + 22])[0]
        if not name.endswith("/") and compress_type == 0:
            extra = data[pos + 30 + n:pos + 30 + n + m]
            xp = 0
            while xp + 4 <= len(extra):
                hdr_id, size = struct.unpack("<HH", extra[xp:xp + 4])
                if hdr_id == 0xd935 and size >= 2:
                    align = struct.unpack("<H", extra[xp + 4:xp + 6])[0]
                    results[name] = align
                    break
                xp += 4 + size
        pos += 30 + n + m + (0 if name.endswith("/") else compress_size)
    return results


def has_d935(apk_path):
    """Check if any uncompressed entry has 0xd935 extra field."""
    return bool(check_d935_fields(apk_path))


class TestApksigner35:
    """Tests for apksigner 35+ style alignment."""

    UNSIGNED = osp.join(APKS_DIR, "golden-aligned-in.apk")

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir)

    def _sign(self, src, dst, apksigner=APKSIGNER):
        shutil.copy2(src, dst)
        apksigner_sign(dst, apksigner=apksigner)

    # ── Test 1: apksigner 36 adds 0xd935 ──────────────────────────────────

    def test_apksigner36_adds_d935(self):
        """Apksigner 36 should add 0xd935 extra fields to uncompressed entries."""
        signed = osp.join(self.tmpdir, "signed.apk")
        self._sign(self.UNSIGNED, signed)
        assert has_d935(signed), \
            "apksigner 36 should add 0xd935 extra fields"

    # ── Test 2: do_copy with META-INF stripped unsigned ────────────────────

    def test_do_copy_no_meta_replicates_d935(self):
        """do_copy should replicate 0xd935 even when unsigned APK has no META-INF.

        This is the real scenario: the unsigned APK has no META-INF,
        so copy_apk doesn't exclude anything, entries don't shift,
        and _realign_zip_entry is never called — but the output must
        still get 0xd935 extra fields to match the signed APK.
        """
        unsigned = build_unsigned_apk_no_meta(self.tmpdir)
        signed = osp.join(self.tmpdir, "signed.apk")
        self._sign(unsigned, signed)
        signed_align = check_d935_fields(signed)
        assert signed_align, "precondition: signed APK must have 0xd935"

        output = osp.join(self.tmpdir, "output.apk")
        asc.do_copy(signed, unsigned, output)

        out_align = check_d935_fields(output)
        assert out_align, \
            "output should have 0xd935 extra fields (no META-INF case)"
        for name, align in signed_align.items():
            assert name in out_align, \
                f"entry {name!r} missing 0xd935 in output"
            assert out_align[name] == align, \
                f"entry {name!r}: expected alignment {align}, got {out_align[name]}"

    # ── Test 3: compare passes with no-META unsigned ───────────────────────

    def test_compare_no_meta_passes(self):
        """do_compare should succeed when unsigned APK has no META-INF."""
        unsigned = build_unsigned_apk_no_meta(self.tmpdir)
        signed = osp.join(self.tmpdir, "signed.apk")
        self._sign(unsigned, signed)
        asc.do_compare(signed, unsigned, unsigned=True,
                       verify_cmd=VERIFY_CMD)

    # ── Test 4: byte-level match ───────────────────────────────────────────

    def test_byte_identical_no_meta(self):
        """Output should be byte-identical to signed APK (no-META case)."""
        unsigned = build_unsigned_apk_no_meta(self.tmpdir)
        signed = osp.join(self.tmpdir, "signed.apk")
        self._sign(unsigned, signed)
        signed_align = check_d935_fields(signed)
        assert signed_align, "precondition"

        output = osp.join(self.tmpdir, "output.apk")
        asc.do_copy(signed, unsigned, output)

        with open(signed, "rb") as f:
            sdata = f.read()
        with open(output, "rb") as f:
            odata = f.read()
        assert len(sdata) == len(odata), \
            f"size mismatch: {len(sdata)} vs {len(odata)}"
        diff = sum(1 for i in range(len(sdata)) if sdata[i] != odata[i])
        assert diff == 0, \
            f"output differs from signed APK in {diff} bytes"

    # ── Test 5: copy_apk preserves 0xd935 from input ───────────────────────

    def test_copy_apk_preserves_d935(self):
        """copy_apk should not strip 0xd935 when copying a signed APK."""
        unsigned = build_unsigned_apk_no_meta(self.tmpdir)
        signed = osp.join(self.tmpdir, "signed.apk")
        self._sign(unsigned, signed)
        signed_align = check_d935_fields(signed)
        assert signed_align, "precondition"

        output = osp.join(self.tmpdir, "copy-only.apk")
        asc.copy_apk(signed, output, exclude=lambda _: False)

        out_align = check_d935_fields(output)
        assert out_align, "copy_apk should preserve 0xd935"
        for name, align in signed_align.items():
            assert out_align[name] == align, \
                f"entry {name!r}: expected alignment {align}, got {out_align[name]}"

    # ── Test 6: control — do_copy with META-INF present (existing behavior) ─

    def test_do_copy_with_meta(self):
        """do_copy works when unsigned APK has META-INF (existing behavior)."""
        signed = osp.join(self.tmpdir, "signed.apk")
        self._sign(self.UNSIGNED, signed)
        output = osp.join(self.tmpdir, "output.apk")
        asc.do_copy(signed, self.UNSIGNED, output)
        # Should produce 0xd935 (shifted by META-INF exclusion)
        assert has_d935(output), \
            "output should have 0xd935 (META-INF shift case)"

    # ── Test 7: control — apksigner 34 adds 0xd935 (4096 for .so) ──────────

    def test_apksigner34_adds_d935(self):
        """Apksigner 34 also adds 0xd935 (4096 for .so, 4 for others)."""
        if not osp.exists(APKSIGNER34):
            return
        signed = osp.join(self.tmpdir, "signed-34.apk")
        self._sign(self.UNSIGNED, signed, apksigner=APKSIGNER34)
        d935 = check_d935_fields(signed)
        assert d935, "apksigner 34 should add 0xd935"
        assert d935.get("lib/armeabi/fake.so") == 4096, \
            f"apksigner 34 .so align should be 4096, got {d935}"
        for name, align in d935.items():
            if name.endswith(".so"):
                assert align >= 4096, \
                    f".so entry {name!r} should have align >= 4096, got {align}"
            else:
                assert align == 4, \
                    f"non-.so entry {name!r} should have align 4, got {align}"

    def test_do_copy_with_apksigner34(self):
        """do_copy works with apksigner 34 (regression guard)."""
        if not osp.exists(APKSIGNER34):
            return
        signed = osp.join(self.tmpdir, "signed-34.apk")
        self._sign(self.UNSIGNED, signed, apksigner=APKSIGNER34)
        output = osp.join(self.tmpdir, "output.apk")
        asc.do_copy(signed, self.UNSIGNED, output)
        # Should complete without error


if __name__ == "__main__":
    t = TestApksigner35()
    t.setup_method()
    failed = 0
    total = 0
    for name in sorted(dir(t)):
        if not name.startswith("test_"):
            continue
        total += 1
        try:
            getattr(t, name)()
            print(f"  PASS  {name}")
        except Exception as e:
            failed += 1
            print(f"  FAIL  {name}: {e}")
    t.teardown_method()
    print(f"\n{total - failed}/{total} passed")
    sys.exit(1 if failed else 0)
