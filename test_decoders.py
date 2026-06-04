#!/usr/bin/env python3.12
"""Round-trip tests for the ProjectData meter/tempo DECODERS.

Covers ProjectData.decode_sig_events / get_meter_map / get_tempo_map and
TimeMap.from_project. Run:  python3.12 test_decoders.py  (sweeps every fixture).

Proof strategy for the meter decoder:
  (a) STABILITY — decode -> encode -> decode reproduces the map exactly.
  (b) BYTE round-trip — decode -> set_meter_map rebuilds the signature qSvE; it
      is byte-identical wherever set_meter_map's canonical form matches Logic's.
      Some Logic-made fixtures encode the NON-map change flag (+0x0f) / secidx
      (+0x18) by a different-but-equivalent scheme (e.g. F9_tempometer, when
      tempo changes coexist: consecutive secidx + flag 0x01) that set_meter_map
      normalizes (odd secidx 1,3,5..., terminal flag 0x80 — Logic accepts both;
      TEST_exportall_multi proves our form opens). We assert any diffs are
      CONFINED to those metadata bytes, proving the decoder captured every
      map-bearing byte (position/num/den) — a diff anywhere else is a real fail.
  (c) ENCODER-INVERSE — synthetic map -> set_meter_map -> get_meter_map == map.
Tempo re-encoding regenerates each event's altpos, so tempo is checked at the
(tick, bpm) MAP level (idempotence) instead of byte-for-byte.
"""
import sys
from pathlib import Path
from logicx.projectdata import ProjectData, TimeMap

ROOT = Path(__file__).resolve().parent
PASS = 0


def ok(cond, msg):
    global PASS
    assert cond, "FAIL " + msg
    PASS += 1


def load(name):
    p = next(ROOT.glob(f"**/{name}/Alternatives/000/ProjectData"))
    return ProjectData.parse(p.read_bytes())


def sig_meta_offsets(nchanges):
    """Raw-record offsets set_meter_map may legitimately normalize: the header
    terminal flag, and each change record's flag (+0x0f) and secidx (+0x18)."""
    allowed = {0x24 + ProjectData.SIG_INIT_FLAG_OFF}
    base = 0x24 + ProjectData.SIG_HEADER_SIZE
    for c in range(nchanges):
        allowed.add(base + c * 48 + 0x0f)
        allowed.add(base + c * 48 + 0x18)
    return allowed


pds = sorted(set(ROOT.glob("**/Alternatives/000/ProjectData")))
ok(len(pds) >= 20, f"found {len(pds)} ProjectData fixtures")

# 1) METER decoder fidelity --------------------------------------------------
meter_changes = byte_ident = meta_only = 0
for p in pds:
    name = p.parent.parent.parent.name
    pd = ProjectData.parse(p.read_bytes())
    idx = pd._find_sig_qsve()
    if idx is None:
        continue
    before = bytes(pd.records[idx].raw)
    m1 = pd.get_meter_map()
    if len(m1) > 1:
        meter_changes += 1
    pd.set_meter_map(m1)                          # rebuild purely from decoded map
    after = bytes(pd.records[idx].raw)
    ok(pd.get_meter_map() == m1, f"meter decode stable: {name}")   # (a)
    if after == before:
        byte_ident += 1
    else:                                          # (b)
        diffs = [k for k in range(min(len(before), len(after))) if before[k] != after[k]]
        ok(len(before) == len(after) and set(diffs) <= sig_meta_offsets(len(m1) - 1),
           f"meter round-trip {name}: diffs OUTSIDE flag/secidx metadata: "
           f"{[hex(d) for d in diffs]}")
        meta_only += 1
ok(meter_changes >= 5, f"exercised {meter_changes} fixtures WITH meter changes")

# 1c) encoder-inverse on synthetic maps (exercises every denominator) --------
base = load("F0_baseline.logicx")
for synth in ([(0, 7, 8)],
              [(0, 4, 4), (3840, 3, 4), (6720, 5, 8), (9600, 13, 16)],
              [(0, 2, 2), (1920, 6, 8), (3840, 4, 4)]):
    base.set_meter_map(synth)
    ok(base.get_meter_map() == synth, f"encoder-inverse: {synth}")

# 2) TEMPO: map-level idempotence (altpos is regenerated on re-encode) --------
tempo_multi = 0
for p in pds:
    name = p.parent.parent.parent.name
    pd = ProjectData.parse(p.read_bytes())
    if pd._find_tempo_qsve() is None:
        continue
    t1 = pd.get_tempo_map()
    if len(t1) > 1:
        tempo_multi += 1
    pd.set_tempo_map(t1)
    ok(pd.get_tempo_map() == t1, f"tempo map idempotent: {name} ({len(t1)} ev)")
ok(tempo_multi >= 3, f"exercised {tempo_multi} fixtures WITH tempo changes")

# 3) KNOWN VALUES ------------------------------------------------------------
ok(load("F9_meter.logicx").get_meter_map() == [(0, 4, 4), (3840, 3, 4)],
   "F9_meter values")
ok(load("F10_sigs.logicx").get_meter_map()
   == [(0, 4, 4), (3840, 5, 8), (8640, 9, 16), (12960, 11, 2)],
   "F10_sigs exotic denominators (den = 2**exp inverse)")
ok(load("F9_tempometer.logicx").get_meter_map()
   == [(0, 4, 4), (3840, 3, 4), (6720, 7, 8)], "F9_tempometer meter (with tempo)")

em = load("TEST_exportall_multi.logicx")
ok(em.get_meter_map() == [(0, 4, 4), (3840, 3, 4)], "exportall_multi meter")
ok(em.get_tempo_map() == [(0, 120.0), (3840, 90.0)], "exportall_multi tempo")

sd = load("TEST_all_steelydan.logicx")            # real song: big maps
ok(len(sd.get_meter_map()) == 7, "steelydan 7 meter entries")
ok(len(sd.get_tempo_map()) == 250, "steelydan 250 tempo events")

# 4) from_project reproduces Jon's LOGIC-OBSERVED placement ------------------
# Jon validated TEST_exportall_multi in Logic: with the 3/4 change at bar 2,
# regions at 4/4-ticks 0 / 7680 / 15360 landed at bar1, bar3-beat2, bar6.
t = TimeMap.from_project(em)
ok(t.tick_to_bar_beat(0) == (1, 1.0), "from_project tick0 -> bar1 beat1")
ok(t.tick_to_bar_beat(7680) == (3, 2.0),
   "from_project tick7680 -> bar3 beat2 (Jon observed in Logic)")
ok(t.tick_to_bar_beat(15360) == (6, 1.0),
   "from_project tick15360 -> bar6 (Jon observed in Logic)")
ok(t.bar_to_tick(6) == 15360, "from_project bar6 -> tick15360")
ok(abs(t.tick_to_seconds(3840) - 2.0) < 1e-9,
   "from_project bar2 onset = 2.0s (4 beats @120)")

print(f"OK — {PASS} assertions passed "
      f"({len(pds)} fixtures; meter: {byte_ident} byte-identical / {meta_only} "
      f"metadata-only diffs; {meter_changes} meter-change / {tempo_multi} tempo-change)")
