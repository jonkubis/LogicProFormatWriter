#!/usr/bin/env python3.12
"""Regression tests for THE COMBINE (projectdata.synthesize_track_region_bundle /
synthesize_audio_regions(prototype=...)).

The combine wires audio TRACK synthesis (§10.6) + audio REGION synthesis (§10.7)
into one call: from a minimal pre-allocated track template ('1 from 64') + a region
PROTOTYPE (F18, any session with >=1 region), emit arbitrary N tracks each carrying
their regions — no per-layout donor. The track-synth base is UNSETTLED and has an
EMPTY arrange EvSq; region synthesis grafts the placement events into it and Logic
regenerates the registry/pool on load.

Run: python3.12 test_combine.py
"""
import struct
import shutil
import tempfile
from pathlib import Path
from logicx.projectdata import (ProjectData, IdGen, activate_audio_track, _audio_track_count,
                         synthesize_track_region_bundle, _u32, REC_HEADER_SIZE, REC_SIZE_OFF)

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


def events(pd):
    out = []
    for r in pd.records:
        if r.tag == b"qSvE":
            ps = _u32(r.raw, REC_SIZE_OFF); bd = r.raw[REC_HEADER_SIZE:REC_HEADER_SIZE + ps]
            o = 0
            while o + 0x50 <= len(bd):
                if _u32(bd, o) == 0x24 and _u32(bd, o + 4) >= 34560 and 0 < bd[o + 0x14] < 64:
                    out.append({"track": bd[o + 0x14], "tick": _u32(bd, o + 4) - 34560,
                                "link": _u32(bd, o + 0x2c)})
                o += 4
    return out


def lfua_names(pd):
    d = {}
    for r in pd.records:
        if r.tag == b"lFuA":
            p = r.raw[0x24:]; n = struct.unpack_from("<H", p, 0x08)[0]
            d[_u32(r.raw, 0x08) // 0x40000] = p[0x0a:0x0a + n * 2].decode("utf-16-le", "replace")
    return d


# 1) in-memory combine: 1->5 audio tracks, 6 regions (beat-slice pair on track 1) --
base = load(TMPL)
proto = load(PROTO)
ok(_audio_track_count(base) == 1, f"template starts at 1 audio track (got {_audio_track_count(base)})")
ids = IdGen(seed=42)
for _ in range(4):                                    # synth up to 5 audio tracks
    activate_audio_track(base, ids=ids, drummer=True)
ok(_audio_track_count(base) == 5, f"synthesized to 5 audio tracks (got {_audio_track_count(base)})")
items = [(1, 0), (1, 3840), (2, 0), (3, 0), (4, 0), (5, 0)]
regions = [dict(track=t, tick=tk, sample_len=22050, region_name=f"r{i}", sample_rate=44100,
                bits=16, channels=2, internal_name=f"f{i}.wav", file_size=88200)
           for i, (t, tk) in enumerate(items)]
pd = ProjectData.synthesize_audio_regions(base, regions, prototype=proto)
data = pd.serialize()
ok(ProjectData.parse(data).serialize() == data, "combine round-trips")
ok(sum(1 for r in pd.records if r.tag == b"lFuA") == 6, "6 lFuA (one per region)")
ok(sorted(_u32(r.raw, 0x08) // 0x40000 for r in pd.records if r.tag == b"lFuA") == list(range(6)),
   "region indices 0..5")
ev = events(pd)
ok(len(ev) == 6, f"6 placement events (got {len(ev)})")
ok([e["track"] for e in ev] == [1, 1, 2, 3, 4, 5], f"tracks 1,1,2,3,4,5 (got {[e['track'] for e in ev]})")
ok([e["tick"] for e in ev] == [0, 3840, 0, 0, 0, 0], "ticks (beat-slice pair on track 1)")
ok([e["link"] for e in ev] == [i * 4 for i in range(6)], "links = regionIndex*4")
ok(len(set(lfua_names(pd).values())) == 6, "6 distinct filenames")
ok(not any(r.tag == b"MneG" and _u32(r.raw, 8) >= 0x40000 for r in pd.records),
   "per-region MneG dropped")
# the arrange EvSq still ends in its 16-B sequence trailer (events were prepended)
aq = next(i for i, r in enumerate(pd.records) if ProjectData._qsve_has_audio_event(r))
abody = pd.records[aq].raw[REC_HEADER_SIZE:]
ok(abody.endswith(bytes.fromhex("f1000000ffffff3f0000000000000000")),
   "arrange EvSq keeps its 16-B trailer after the grafted events")

# 2) channels match a REAL 'N from 64' (track synth produced the right mixer) ------
real4 = load(ROOT / "fixtures" / "lots of audio tracks" / "4 from 64 audio tracks.logicx")
from logicx.projectdata import KART_CHAN, KART_MASTER_CHAN
def chans(p):
    return sorted(_u32(r.raw, KART_CHAN) for r in p.records if r.tag == b"karT" and len(r.raw) == 93
                  and _u32(r.raw, 0x08) == 0x040000 and _u32(r.raw, KART_CHAN) != KART_MASTER_CHAN)
ok(chans(pd)[:4] == chans(real4), "synth channels match a real 4-from-64 mixer")

# 3) full bundle assembly writes a valid, parseable .logicx with the wavs ----------
src = Path(tempfile.mkdtemp())                        # 6 distinct-named wavs, from the F21 fixture
f21wavs = sorted(F21.glob("*.wav"))
names6 = ["047.wav", "048.wav", "049.wav", "a0.wav", "a1.wav", "a2.wav"]
for i, nm in enumerate(names6):
    shutil.copyfile(f21wavs[i % len(f21wavs)], src / nm)
out = Path(tempfile.mkdtemp()) / "combo.logicx"
summary = synthesize_track_region_bundle(
    TMPL, PROTO, out,
    [(1, src / "047.wav", 0), (1, src / "048.wav", 3840), (2, src / "049.wav", 0),
     (3, src / "a0.wav", 0), (4, src / "a1.wav", 0), (5, src / "a2.wav", 0)],
    seed=42, verbose=False)
ok(summary["tracks"] == 5 and summary["synth_tracks"] == 4 and summary["regions"] == 6,
   f"bundle summary {summary}")
b = load(out)
bd = b.serialize()
ok(ProjectData.parse(bd).serialize() == bd, "bundle ProjectData round-trips")
media = out / "Media" / "Audio Files"
disk = sorted(f.name for f in media.glob("*.wav"))
ok(disk == names6, f"6 wavs on disk {disk}")
ok(all(b"LGWV" in (media / n).read_bytes() for n in disk), "every wav carries an LGWV overview")
ok(set(lfua_names(b).values()) == set(disk), "lFuA names == on-disk wavs")
import plistlib
md = plistlib.loads((out / "Alternatives" / "000" / "MetaData.plist").read_bytes())
ok(md.get("NumberOfTracks") == 5 and md.get("SampleRate") == 44100, f"MetaData {md.get('NumberOfTracks')}/{md.get('SampleRate')}")
shutil.rmtree(out.parent)

# 4) refuses to overwrite ----------------------------------------------------------
ow = Path(tempfile.mkdtemp()) / "ow.logicx"
synthesize_track_region_bundle(TMPL, PROTO, ow, [(1, src / "047.wav", 0)], verbose=False)
try:
    synthesize_track_region_bundle(TMPL, PROTO, ow, [(1, src / "047.wav", 0)], verbose=False)
    ok(False, "should refuse to overwrite an existing bundle")
except ValueError:
    ok(True, "refuses to overwrite an existing bundle")
shutil.rmtree(ow.parent)
shutil.rmtree(src)

print(f"OK — {PASS} assertions passed (the combine: track synth + region synth)")
