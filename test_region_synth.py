#!/usr/bin/env python3.12
"""Regression tests for AUDIO REGION SYNTHESIS (projectdata.synthesize_audio_regions).

Region synthesis clones a donor's region-0 record group to an ARBITRARY number of
regions (no per-count template) + rebuilds the placement events. Logic regenerates
the gnoS object-registry + OgnS pool from the records on load (Logic-validated
2026-05-31, fixtures/TEST_synthregions.logicx — 8 distinct files across 4 tracks).
Run: python3.12 test_region_synth.py
"""
import struct
from pathlib import Path
from logicx.projectdata import ProjectData, _u32, REC_HEADER_SIZE, REC_SIZE_OFF

ROOT = Path(__file__).resolve().parent
PASS = 0


def ok(c, m):
    global PASS
    assert c, "FAIL " + m
    PASS += 1


def load(name):
    return ProjectData.parse(next(ROOT.glob(f"**/{name}/Alternatives/000/ProjectData")).read_bytes())


def ridx(raw):
    return _u32(raw, 0x08)


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
            d[ridx(r.raw) // 0x40000] = p[0x0a:0x0a + n * 2].decode("utf-16-le", "replace")
    return d


# 1) F18 (single-track, 1 region) -> synthesize 6 regions on track 1 (beat slices,
#    far beyond the donor's 1) ---------------------------------------------------
donor = load("F18_audio.logicx")
n0 = sum(1 for r in donor.records if r.tag == b"lFuA")
ok(n0 == 1, f"F18 donor has 1 region (got {n0})")
specs = [dict(track=1, tick=i * 3840, sample_len=22050, region_name=f"s{i}",
              sample_rate=44100, bits=16, channels=2, internal_name=f"s{i}.wav",
              file_size=88200) for i in range(6)]
pd = ProjectData.synthesize_audio_regions(donor, specs)
data = pd.serialize()
ok(ProjectData.parse(data).serialize() == data, "6-region synth round-trips")
nl = sum(1 for r in pd.records if r.tag == b"lFuA")
ok(nl == 6, f"6 lFuA records (one per region), got {nl}")
ridxs = sorted(ridx(r.raw) // 0x40000 for r in pd.records if r.tag == b"lFuA")
ok(ridxs == list(range(6)), f"region indices 0..5, got {ridxs}")
ev = events(pd)
ok(len(ev) == 6, f"6 placement events, got {len(ev)}")
ok([e["track"] for e in ev] == [1] * 6, "all on track 1")
ok([e["tick"] for e in ev] == [i * 3840 for i in range(6)], "ticks at consecutive bars")
ok([e["link"] for e in ev] == [i * 4 for i in range(6)], "links = regionIndex*4")
names = lfua_names(pd)
ok(sorted(names.values()) == [f"s{i}.wav" for i in range(6)], f"distinct filenames: {names}")
# the donor's MneG per-region mementos are dropped; OgnS left for Logic to rebuild
ok(not any(r.tag == b"MneG" and _u32(r.raw, 8) >= 0x40000 for r in pd.records),
   "per-region MneG dropped")

# 2) F21 (multi-track, 3 regions) -> synthesize 5 regions across tracks 1/2/3 ----
donor = load("F21_multitrack_regions.logicx")
specs = [dict(track=t, tick=0, sample_len=44100, region_name=f"r{i}", sample_rate=44100,
              bits=16, channels=2, internal_name=f"r{i}.wav", file_size=176400)
         for i, t in enumerate([1, 2, 3, 1, 2])]
pd = ProjectData.synthesize_audio_regions(donor, specs)
data = pd.serialize()
ok(ProjectData.parse(data).serialize() == data, "F21 5-region synth round-trips")
ev = events(pd)
ok(sorted(e["track"] for e in ev) == [1, 1, 2, 2, 3], f"placed across tracks: {[e['track'] for e in ev]}")
ok(len(set(lfua_names(pd).values())) == 5, "5 distinct filenames")

# 3) a region-less base raises ---------------------------------------------------
base = load("F19_multi_base.logicx")
try:
    ProjectData.synthesize_audio_regions(base, specs)
    ok(False, "should raise on a donor with no region")
except ValueError:
    ok(True, "raises when donor has no region-0 prototype")

print(f"OK — {PASS} assertions passed (audio region synthesis, vs F18/F21/F19)")
