#!/usr/bin/env python3.12
"""Tests for logicx.session — the port-ready SessionModel (timeline + audio/MIDI regions
with absolute positions + content). Audio regions (file / position / trim / length / fades)
are the fully-solved core; markers and the timeline round out the model.

Run: python3.12 test_session.py
"""
import struct
from pathlib import Path

from logicx.projectdata import ProjectData
from logicx.session import session_model, markers, _grua_region

ROOT = Path(__file__).resolve().parent
PASS = 0


def ok(c, m):
    global PASS
    assert c, "FAIL " + m
    PASS += 1


def load(bundle):
    return ProjectData.parse((ROOT / bundle / "Alternatives" / "000" / "ProjectData").read_bytes())


# --- audio regions: files, tracks, positions, trim (§8 + §17) -----------------
m = session_model(load("templates/F23_av.logicx"))
ar = m["audio_regions"]
ok(len(ar) == 3, f"F23_av: 3 audio regions ({len(ar)})")
ok(sorted(r["file"].split(".")[0] for r in ar) == ["047", "048", "049"],
   f"audio region files == the media ({[r['file'] for r in ar]})")
ok(sorted({r["track"] for r in ar}) == [5, 6, 7], f"audio regions on tracks 5/6/7 ({sorted({r['track'] for r in ar})})")
ok(all(r["trim_in_samples"] == 0 for r in ar), "untrimmed regions -> trim_in 0")
ok(all(r["length_samples"] > 0 for r in ar), "every region has a positive sample length")
ok(all("fade_in" in r and "position_tick" in r for r in ar), "regions carry fades + position")

# the trim decode reads a nonzero trim from a synthetic gRuA (session A proves it on real data)
g = bytearray(0x24 + 0x80)
g[0:4] = b"gRuA"
struct.pack_into("<I", g, 0x24 + 0x06, 44100)          # trim-in 44100 samples
struct.pack_into("<I", g, 0x24 + 0x16, 22050)          # length 22050
struct.pack_into("<H", g, 0x24 + 0x4a, 0)              # empty name
info = _grua_region(bytes(g))
ok(info["trim_in_samples"] == 44100 and info["length_samples"] == 22050,
   f"gRuA trim-in + length decode ({info['trim_in_samples']}/{info['length_samples']})")

# --- markers (§6) -------------------------------------------------------------
mk = markers(load("fixtures/F11_markers.logicx"))
ok(mk == [(3840, "MARKERONE"), (11520, "MARKERTWO"), (19200, "MARKERTHREE")],
   f"F11 markers decoded (tick, name) ({mk})")

# --- timeline -----------------------------------------------------------------
ok(m["initial_bpm"] == 120.0, f"initial_bpm ({m['initial_bpm']})")
ok(len(m["tempo_map"]) >= 1 and m["tempo_map"][0][0] == 0, "tempo map starts at tick 0")
ok(m["meter_map"] and m["meter_map"][0] == (0, 4, 4), f"meter map 4/4 ({m['meter_map'][:1]})")
ok(m["ppq"] == 960, "PPQ 960")

# --- MIDI regions enumerated (positions); note-linking is best-effort ---------
ok(len(m["midi_regions"]) >= 1, f"MIDI regions enumerated ({len(m['midi_regions'])})")
ok(all("track" in r and "position_tick" in r and "notes" in r for r in m["midi_regions"]),
   "MIDI regions carry track/position/notes")

# --- tracks are the real arrange tracks used, not the pre-allocated pool -------
ok(m["tracks"] == sorted(m["tracks"]) and len(m["tracks"]) < 64, f"tracks = arrange rows used ({m['tracks']})")

# --- §41 placement -> gRuA(file_idx, region_k): several regions cut from ONE file ----
# (every comp/edit does this). Synthetic: file 3 has regions k=0 'whole' and k=1 'cut';
# the placement names k=1 and must get the cut's own trim/length/name, not its sibling's.
from logicx.session import audio_regions


class _R:
    def __init__(self, tag, raw):
        self.tag, self.raw = tag, raw


class _PD:
    def __init__(self, recs):
        self.records = recs


def _grua(file_idx, k, trim, length, name):
    nb = name.encode()
    raw = bytearray(0x24 + 0x4c + len(nb) + (len(nb) & 1) + 0x80)
    raw[0:4] = b"gRuA"
    struct.pack_into("<I", raw, 0x08, file_idx << 18)
    struct.pack_into("<I", raw, 0x0c, k << 16)
    struct.pack_into("<I", raw, 0x24 + 0x06, trim)
    struct.pack_into("<I", raw, 0x24 + 0x16, length)
    struct.pack_into("<H", raw, 0x24 + 0x4a, len(nb))
    raw[0x24 + 0x4c:0x24 + 0x4c + len(nb)] = nb
    return _R(b"gRuA", bytes(raw))


def _place(tick, track, file_idx, k):
    ev = bytearray(0x50)
    struct.pack_into("<I", ev, 0x00, 0x24)
    struct.pack_into("<I", ev, 0x04, 34560 + tick)
    struct.pack_into("<H", ev, 0x14, track)            # track = u16
    ev[0x17], ev[0x37] = 0x89, 0x8A                    # constant placement word tags
    struct.pack_into("<I", ev, 0x20, 0xFFFFFFFF)       # no child sequence (audio region)
    struct.pack_into("<I", ev, 0x28, k)
    struct.pack_into("<I", ev, 0x2c, file_idx * 4)
    body = bytes(ev)
    raw = bytearray(0x24) + body
    raw[0:4] = b"qSvE"
    struct.pack_into("<I", raw, 0x1c, len(body))
    return _R(b"qSvE", bytes(raw))


_pd = _PD([_grua(3, 0, 0, 352800, "whole"), _grua(3, 1, 88200, 44100, "cut"), _place(1920, 2, 3, 1)])
_ar = audio_regions(_pd)
ok(len(_ar) == 1 and _ar[0]["region_k"] == 1, f"§41 placement carries region_k@+0x28 ({_ar})")
ok(_ar[0]["trim_in_samples"] == 88200 and _ar[0]["length_samples"] == 44100 and _ar[0]["name"] == "cut",
   f"§41 resolves gRuA(file_idx, k) — the placed cut, not its sibling ({_ar[0]})")
_pd0 = _PD([_grua(3, 0, 0, 352800, "whole"), _grua(3, 1, 88200, 44100, "cut"), _place(0, 2, 3, 0)])
ok(audio_regions(_pd0)[0]["name"] == "whole", "§41 region_k=0 resolves the file's first region")

print(f"OK — {PASS} assertions passed (logicx.session SessionModel)")
