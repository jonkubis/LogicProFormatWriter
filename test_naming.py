#!/usr/bin/env python3.12
"""Regression tests for AUDIO TRACK NAMING (projectdata.set_track_name / the names=
option on track synthesis + the combine).

A synth track's displayed name is its ivnE channel name — a variable-length
[u16 len @0xc2][ASCII @0xc4][pad even] field (§10.6.8). Replacing it gives an
arbitrary name AND cures the single-byte-counter garble past track 9 ('Audio :').
Run: python3.12 test_naming.py
"""
import struct
import tempfile
import shutil
from pathlib import Path
from logicx.projectdata import (ProjectData, IdGen, activate_audio_track, set_track_name,
                         _normalize_names, _audio_track_count, synthesize_audio_tracks,
                         synthesize_track_region_bundle, _u32,
                         KART_BASE_CHAN, SYNTH_IDX_STRIDE, IVNE_IDX, IVNE_NAME_LEN, IVNE_NAME)

ROOT = Path(__file__).resolve().parent
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


def tname(pd, track):
    chan = KART_BASE_CHAN + (track - 1) * SYNTH_IDX_STRIDE
    iv = next(r for r in pd.records if r.tag == b"ivnE" and _u32(r.raw, IVNE_IDX) == chan)
    n = struct.unpack_from("<H", iv.raw, IVNE_NAME_LEN)[0]
    return iv.raw[IVNE_NAME:IVNE_NAME + n].decode("latin-1")


# 1) default is 'Audio N'; set_track_name overrides it -----------------------------
pd = load(TMPL)
ok(tname(pd, 1) == "Audio 1", f"default track 1 name is 'Audio 1' (got {tname(pd, 1)!r})")
set_track_name(pd, 1, "Kick Drum")
ok(tname(pd, 1) == "Kick Drum", "set_track_name renames track 1")
data = pd.serialize()
ok(ProjectData.parse(data).serialize() == data, "round-trips after rename")

# 2) various lengths (odd/even, spaces) round-trip exactly -------------------------
for nm in ["X", "Kick", "Snare", "Vocal Lead", "Bass 808 sub bass"]:
    p = load(TMPL)
    set_track_name(p, 1, nm)
    ok(tname(p, 1) == nm, f"name {nm!r} stored verbatim")
    d = p.serialize()
    ok(ProjectData.parse(d).serialize() == d, f"round-trips for {nm!r}")

# 3) _normalize_names spec handling -----------------------------------------------
ok(_normalize_names(None, 3) == {}, "None -> no names")
ok(_normalize_names(["a", "b"], 3) == {1: "a", 2: "b"}, "list -> tracks 1..len")
ok(_normalize_names({2: "Bass"}, 3) == {2: "Bass"}, "dict passes through")
ok(_normalize_names(["a", "", "c"], 3) == {1: "a", 3: "c"}, "empty list entries skipped")

# 4) multi-track + the >9 garble cure (multi-digit names) -------------------------
pd = load(TMPL)
ids = IdGen(seed=2)
for _ in range(11):                                   # -> 12 audio tracks
    activate_audio_track(pd, ids=ids, drummer=True)
ok(_audio_track_count(pd) == 12, "synthesized 12 audio tracks")
for t in range(1, 13):
    set_track_name(pd, t, f"Stem {t}")
ok(tname(pd, 10) == "Stem 10" and tname(pd, 11) == "Stem 11" and tname(pd, 12) == "Stem 12",
   "tracks 10-12 get clean multi-digit names (no 'Audio :' garble)")
data = pd.serialize()
ok(ProjectData.parse(data).serialize() == data, "12-track naming round-trips")

# 5) the combine honors names= (dict) ---------------------------------------------
out = Path(tempfile.mkdtemp()) / "named.logicx"
summary = synthesize_track_region_bundle(
    TMPL, PROTO, out, [(t, F21 / "047.wav", 0) for t in range(1, 4)],
    names={1: "Kick", 2: "Snare", 3: "Vocal Lead"}, seed=1, verbose=False)
ok(summary["names"] == {1: "Kick", 2: "Snare", 3: "Vocal Lead"}, f"summary names {summary['names']}")
b = load(out)
ok([tname(b, t) for t in range(1, 4)] == ["Kick", "Snare", "Vocal Lead"], "combine named the tracks")
ok(tname(b, 1) == "Kick" and tname(b, 2) == "Snare", "combine track names persisted to bundle")
bd = b.serialize()
ok(ProjectData.parse(bd).serialize() == bd, "named combine bundle round-trips")
shutil.rmtree(out.parent)

# 6) names compose with stereo (both applied) -------------------------------------
out2 = Path(tempfile.mkdtemp()) / "ns.logicx"
synthesize_track_region_bundle(
    TMPL, PROTO, out2, [(1, F21 / "047.wav", 0), (2, F21 / "048.wav", 0)],
    names=["Lead", "Sub"], stereo=[2], seed=3, verbose=False)
b2 = load(out2)
ok(tname(b2, 1) == "Lead" and tname(b2, 2) == "Sub", "names applied alongside stereo")
from logicx.projectdata import _ocua_for_channel, OCUA_FMT_NCH
ok(_ocua_for_channel(b2, KART_BASE_CHAN).raw[OCUA_FMT_NCH] == 1, "track 1 mono (stereo=[2])")
ok(_ocua_for_channel(b2, KART_BASE_CHAN + SYNTH_IDX_STRIDE).raw[OCUA_FMT_NCH] == 2, "track 2 stereo")
shutil.rmtree(out2.parent)

print(f"OK — {PASS} assertions passed (audio track naming)")
