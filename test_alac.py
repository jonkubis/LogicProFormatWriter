#!/usr/bin/env python3.12
"""Tests for ALAC / CAF (Apple Lossless) audio support (logicx.alac).

Two control sessions made in Logic from identical PCM — `fixtures/ctl_wav.logicx`
(WAV) and `fixtures/ctl_caf.logicx` (ALAC/CAF) — are the ground truth. The WAV->ALAC
`lFuA` transform must reproduce Logic's own CAF record byte-for-byte (§8.6).

Run: python3.12 test_alac.py
"""
import shutil
import struct
import tempfile
from pathlib import Path

from logicx.alac import wav_lfua_to_caf, convert_bundle_to_alac
from logicx.projectdata import ProjectData, _u32

ROOT = Path(__file__).resolve().parent
CTL_WAV = ROOT / "fixtures" / "ctl_wav.logicx"
CTL_CAF = ROOT / "fixtures" / "ctl_caf.logicx"
PASS = 0


def ok(c, m):
    global PASS
    assert c, "FAIL " + m
    PASS += 1


def lfua(bundle):
    pd = ProjectData.parse((Path(bundle) / "Alternatives" / "000" / "ProjectData").read_bytes())
    return next(r.raw for r in pd.records if r.tag == b"lFuA")


# 1) byte-exact: transforming the WAV control's lFuA reproduces the CAF control's -----
W, C = lfua(CTL_WAV), lfua(CTL_CAF)
ok(W.find(b"EVAW") >= 0 and C.find(b"EVAW") < 0, "WAV lFuA has EVAW, CAF lFuA does not")
ok(C.find(b"ffac") >= 0, "CAF lFuA has the ffac (caff) descriptor")
got = wav_lfua_to_caf(W)
# the two controls are independent projects, so the only non-format difference is the
# project name embedded in a path field (ctl_wav vs ctl_caf) — neutralize it
got_norm = got.replace(b"ctl_wav", b"ctl_caf")
ok(len(got) == len(C), f"transform preserves length ({len(got)} vs {len(C)})")
ok(got_norm == C, "WAV->CAF lFuA transform reproduces Logic's CAF lFuA byte-for-byte")

# the 6 documented changes landed
d = got.find(b"ffac")
ok(got[d:d + 4] == b"ffac", "descriptor magic EVAW -> ffac")
ok(_u32(got, d + 0x08) == 0, "format const +0x08 -> 0")
ok(got[d - 0x1c3] == 0x11, "type flag -0x1c3: 0x01 -> 0x11")
ok(got[d - 0x142:d - 0x142 + 4] == b"PMOC", "compressed marker -0x142 -> PMOC")
frames, ch, bits = _u32(got, d + 0x0c), struct.unpack_from("<H", got, d + 0x18)[0], struct.unpack_from("<H", got, d + 0x1a)[0]
ok(_u32(got, d - 0x32) == frames * ch * (bits // 8), "size field -0x32 = decoded PCM bytes")
ok(b".wav".decode().encode("utf-16-le") not in got and b".wav" not in got, "no .wav refs remain")
ok(".caf".encode("utf-16-le") in got, "filename now .caf (UTF-16)")

# 2) transform is idempotent / safe on a non-WAV (no EVAW) record ----------------------
ok(wav_lfua_to_caf(C) == C, "transform is a no-op on a record with no EVAW")

# 3) end-to-end convert_bundle_to_alac on a copy of the WAV control (needs afconvert) ---
have_afconvert = shutil.which("afconvert") is not None
if have_afconvert:
    tmp = Path(tempfile.mkdtemp()) / "ctl.logicx"
    shutil.copytree(CTL_WAV, tmp)
    summary = convert_bundle_to_alac(tmp, verbose=False)
    media = tmp / "Media" / "Audio Files"
    cafs = sorted(p.name for p in media.glob("*.caf"))
    wavs = sorted(media.glob("*.wav"))
    ok(summary["files"] == 1 and summary["lfua_converted"] == 1, f"converted 1 file/1 lFuA ({summary})")
    ok(cafs == ["control.caf"] and not wavs, f"WAV replaced by CAF on disk ({cafs})")
    ok(summary["caf_bytes"] < summary["wav_bytes"], "CAF is smaller than WAV")
    pd = ProjectData.parse((tmp / "Alternatives" / "000" / "ProjectData").read_bytes())
    data = pd.serialize()
    ok(ProjectData.parse(data).serialize() == data, "converted ProjectData round-trips")
    raw_all = data
    ok(b"ffac" in raw_all and b"EVAW" not in raw_all, "lFuA now ffac, no EVAW")
    ok("control.caf".encode("utf-16-le") in raw_all, "lFuA filename matches the on-disk control.caf")
    ok(".wav".encode("utf-16-le") not in raw_all and b".wav" not in raw_all, "no stray .wav refs")
    # the caf is a valid caff container
    ok((media / "control.caf").read_bytes()[:4] == b"caff", "emitted .caf is a valid caff container")
    shutil.rmtree(tmp.parent)
else:
    print("  (skipping convert_bundle_to_alac end-to-end — afconvert not found)")

print(f"OK — {PASS} assertions passed (ALAC / CAF audio support)")
