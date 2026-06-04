#!/usr/bin/env python3.12
"""Regression tests for AUDIO TRACK STEREO format (projectdata.set_track_stereo /
the stereo= options on track synthesis + the combine).

Mono↔stereo is three fixed bytes in the audio `OCuA` channel strip (§10.6.7),
RE'd from a 1-track mono-vs-stereo Logic differential (fixtures/stereo test/). The
load-bearing assertion is GROUND TRUTH: set_track_stereo reproduces Logic's own
stereo strip byte-for-byte. Run: python3.12 test_stereo.py
"""
import tempfile
import shutil
from pathlib import Path
from logicx.projectdata import (ProjectData, IdGen, activate_audio_track, set_track_stereo,
                         _ocua_for_channel, _set_ocua_stereo, _normalize_stereo,
                         _audio_track_count, synthesize_track_region_bundle,
                         OCUA_FMT_CFG, OCUA_FMT_FLAG, OCUA_FMT_NCH, KART_BASE_CHAN, SYNTH_IDX_STRIDE)

ROOT = Path(__file__).resolve().parent
STEREO_DIR = ROOT / "fixtures" / "stereo test"
TMPL = ROOT / "fixtures" / "lots of audio tracks" / "1 from 64 audio tracks.logicx"
PROTO = ROOT / "templates" / "F18_audio.logicx"
F21 = ROOT / "templates" / "F21_multitrack_regions.logicx" / "Media" / "Audio Files"
PASS = 0


def ok(c, m):
    global PASS
    assert c, "FAIL " + m
    PASS += 1


def load(bundle):
    return ProjectData.parse((Path(bundle) / "Alternatives" / "000" / "ProjectData").read_bytes())


def strip_fmt(oc):
    return (oc.raw[OCUA_FMT_CFG], oc.raw[OCUA_FMT_FLAG], oc.raw[OCUA_FMT_NCH])


# 1) GROUND TRUTH — set_track_stereo reproduces Logic's stereo strip byte-for-byte --
if STEREO_DIR.exists():
    mono = load(STEREO_DIR / "mono.logicx")
    ster = load(STEREO_DIR / "stereo.logicx")
    # locate the audio channel strip that Logic changed (mono.logicx track 1 = chan 0x580000)
    oc_mono = _ocua_for_channel(mono, KART_BASE_CHAN)
    ok(oc_mono is not None, "found mono.logicx audio track strip via channel chain")
    ok(strip_fmt(oc_mono) == (0xd3, 0x00, 0x01), f"mono strip format bytes d3/00/01 (got {strip_fmt(oc_mono)})")
    set_track_stereo(mono, 1, True)
    oc_after = _ocua_for_channel(mono, KART_BASE_CHAN).raw
    oc_logic = ster.records[78].raw            # the record the differential flagged
    ok(oc_after == oc_logic, "set_track_stereo strip == Logic's stereo.logicx strip (byte-for-byte)")
    ok(strip_fmt(_ocua_for_channel(mono, KART_BASE_CHAN)) == (0xd7, 0x01, 0x02), "stereo format bytes d7/01/02")
    data = mono.serialize()
    ok(ProjectData.parse(data).serialize() == data, "round-trips after set_track_stereo")
    # reversible
    set_track_stereo(mono, 1, False)
    ok(strip_fmt(_ocua_for_channel(mono, KART_BASE_CHAN)) == (0xd3, 0x00, 0x01), "stereo->mono restores the bytes")
else:
    print("(skipping ground-truth: fixtures/stereo test/ absent)")

# 2) _set_ocua_stereo is a pure idempotent toggle ---------------------------------
sample = load(TMPL)
oc = _ocua_for_channel(sample, KART_BASE_CHAN).raw
s1 = _set_ocua_stereo(oc, True)
ok(_set_ocua_stereo(s1, True) == s1, "stereo set is idempotent")
ok(_set_ocua_stereo(s1, False)[OCUA_FMT_NCH] == 0x01, "mono clear sets channel count back to 1")

# 3) _normalize_stereo spec handling ----------------------------------------------
ok(_normalize_stereo(False, 5) == set(), "False -> no stereo tracks")
ok(_normalize_stereo(True, 5) == {1, 2, 3, 4, 5}, "True -> all tracks")
ok(_normalize_stereo([2, 4], 5) == {2, 4}, "list -> those tracks")

# 4) per-track stereo on synthesized tracks (activate_audio_track stereo=) ---------
pd = load(TMPL)
ids = IdGen(seed=3)
for _ in range(3):
    activate_audio_track(pd, ids=ids, drummer=True)        # -> 4 audio tracks
set_track_stereo(pd, 2, True)
set_track_stereo(pd, 4, True)
fmts = {t: strip_fmt(_ocua_for_channel(pd, KART_BASE_CHAN + (t - 1) * SYNTH_IDX_STRIDE)) for t in range(1, 5)}
ok(fmts[1][2] == 1 and fmts[3][2] == 1, "tracks 1,3 stay mono")
ok(fmts[2][2] == 2 and fmts[4][2] == 2, "tracks 2,4 are stereo")
data = pd.serialize()
ok(ProjectData.parse(data).serialize() == data, "synth + mixed stereo round-trips")

# 5) the combine bundle honors stereo= --------------------------------------------
out = Path(tempfile.mkdtemp()) / "combo_st.logicx"
summary = synthesize_track_region_bundle(
    TMPL, PROTO, out,
    [(1, F21 / "047.wav", 0), (2, F21 / "048.wav", 0), (3, F21 / "049.wav", 0)],
    stereo=[2, 3], seed=7, verbose=False)
ok(summary["stereo"] == [2, 3], f"summary reports stereo tracks {summary['stereo']}")
b = load(out)
bf = {t: strip_fmt(_ocua_for_channel(b, KART_BASE_CHAN + (t - 1) * SYNTH_IDX_STRIDE)) for t in range(1, 4)}
ok(bf[1][2] == 1, "combine track 1 mono")
ok(bf[2][2] == 2 and bf[3][2] == 2, "combine tracks 2,3 stereo")
bd = b.serialize()
ok(ProjectData.parse(bd).serialize() == bd, "combine+stereo bundle round-trips")
shutil.rmtree(out.parent)

# 6) DEFAULT is now ALL-STEREO; stereo=False forces all-mono (authoritative) -------
out2 = Path(tempfile.mkdtemp()) / "combo_def.logicx"
s = synthesize_track_region_bundle(
    TMPL, PROTO, out2,
    [(1, F21 / "047.wav", 0), (2, F21 / "048.wav", 0), (3, F21 / "049.wav", 0)],
    seed=7, verbose=False)                                   # no stereo arg -> default
ok(s["stereo"] == [1, 2, 3], f"DEFAULT makes ALL tracks stereo (got {s['stereo']})")
bd2 = load(out2)
ok(all(strip_fmt(_ocua_for_channel(bd2, KART_BASE_CHAN + (t - 1) * SYNTH_IDX_STRIDE))[2] == 2
       for t in range(1, 4)), "default: every track strip is stereo")
shutil.rmtree(out2.parent)

out3 = Path(tempfile.mkdtemp()) / "combo_mono.logicx"
synthesize_track_region_bundle(
    TMPL, PROTO, out3, [(1, F21 / "047.wav", 0), (2, F21 / "048.wav", 0)],
    stereo=False, seed=7, verbose=False)
bd3 = load(out3)
ok(all(strip_fmt(_ocua_for_channel(bd3, KART_BASE_CHAN + (t - 1) * SYNTH_IDX_STRIDE))[2] == 1
       for t in range(1, 3)), "stereo=False forces all-mono")
shutil.rmtree(out3.parent)

print(f"OK — {PASS} assertions passed (audio track stereo format)")
