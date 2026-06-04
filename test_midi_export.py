#!/usr/bin/env python3.12
"""Regression tests for MIDI multi-region fill + region-name RESIZE (in-memory).

Guards the region-name corruption bug: the name is VARIABLE-LENGTH, so
_set_region_name must RESIZE the record and preserve EVERYTHING after the name
field (an in-place write left stale bytes and corrupted the file in Logic).
Run:  python3.12 test_midi_export.py   (uses fixtures/F22_multimidi.logicx)
"""
import struct
from pathlib import Path
from logicx.projectdata import (ProjectData, _fill_midi_regions, _set_region_name,
                         _u32, REC_SIZE_OFF, REC_HEADER_SIZE)

ROOT = Path(__file__).resolve().parent
PASS = 0


def ok(c, m):
    global PASS
    assert c, "FAIL " + m
    PASS += 1


def load(name):
    p = next(ROOT.glob(f"**/{name}/Alternatives/000/ProjectData"))
    return ProjectData.parse(p.read_bytes())


def region_name(raw):
    n = struct.unpack_from("<H", raw, 0x34)[0]
    return raw[0x36:0x36 + n]


# 1) _set_region_name RESIZE invariant: payload size correct, name re-reads, and
#    the bytes AFTER the name field are byte-for-byte preserved (the in-place bug
#    left 2 stale bytes -> misalignment -> "song is corrupted").
pd = load("F22_multimidi.logicx")
raw0 = next(r.raw for r in pd.records
            if r.tag == b"qeSM" and len(r.raw) >= 0x38 and region_name(r.raw) == b"Inst 1")
old_len = struct.unpack_from("<H", raw0, 0x34)[0]
rest0 = raw0[0x34 + 2 + old_len + (old_len & 1):]            # everything after the name field
for nm in ["x", "ab", "bass", "brass", "strings", "a_very_long_region_name_indeed", ""]:
    out = _set_region_name(raw0, nm)
    nb = nm.encode("latin-1")
    ok(_u32(out, REC_SIZE_OFF) == len(out) - REC_HEADER_SIZE, f"payload size @+0x1c for {nm!r}")
    ok(region_name(out) == nb, f"name re-reads for {nm!r}")
    ok(out[0x34 + 2 + len(nb) + (len(nb) & 1):] == rest0, f"rest preserved (no corruption) for {nm!r}")

# 2) _fill_midi_regions on F22: fill 4 regions with notes + names, round-trip the
#    whole ProjectData, re-read names + note counts.
pd = load("F22_multimidi.logicx")
SETS = [[(0, 36, 100, 480)],
        [(0, 48, 100, 480), (960, 50, 90, 240)],
        [(0, 60, 100, 960)],
        [(0, 72, 100, 480)]]
NAMES = ["bass", "brass", "drums", "winds"]
summ = _fill_midi_regions(pd, SETS, region_names=NAMES)
ok([s["name"] for s in summ] == NAMES, f"fill summary names: {[s['name'] for s in summ]}")
data = pd.serialize()
ok(ProjectData.parse(data).serialize() == data, "filled+named ProjectData round-trips")

pd2 = ProjectData.parse(data)
got = []
for r in pd2.records:
    if r.tag == b"qeSM" and len(r.raw) >= 0x38:
        idx = _u32(r.raw, 0x08)
        nq = next((rr for rr in pd2.records if rr.tag == b"qSvE" and _u32(rr.raw, 0x08) == idx
                   and _u32(rr.raw, REC_SIZE_OFF) >= 4
                   and _u32(rr.raw, REC_HEADER_SIZE) == 0x90), None)
        if nq is not None:
            got.append((idx, region_name(r.raw).decode("latin-1", "replace"),
                        len(ProjectData.decode_note_events(nq.raw))))
got.sort()
ok([n for _, n, _ in got] == NAMES, f"re-read region names: {[n for _, n, _ in got]}")
ok([c for _, _, c in got] == [len(s) for s in SETS], f"re-read note counts: {[c for _, _, c in got]}")

# 3) too many note-lists for the template's region count -> clear error
try:
    _fill_midi_regions(load("F22_multimidi.logicx"), [[]] * 99, region_names=None)
    ok(False, "should have raised for too many regions")
except ValueError:
    ok(True, "raises when note-lists exceed template region count")

print(f"OK — {PASS} assertions passed (MIDI multi-region fill + name-resize, vs F22)")
