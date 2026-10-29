#!/usr/bin/env python3.12
"""Tests for logicx.takes — take folders + Quick Swipe comps (PROJECTDATA_FORMAT.md §41).

Ground truth = `fixtures/TAKES3.logicx`, a chain of Logic-made project alternatives where each
step changes exactly one thing (take1/2/3.wav = 220/330/440 Hz, 4 bars @120 BPM, 44.1 kHz):

  000 b00_three_tracks  take1/2/3 on tracks 1/2/3 at bar 1
  001 b01_packed        Pack Take Folder (3 takes; take #1 = take3 active)
  002 b01s_view         view only (expand, Snap=Bar, zoom)
  003 b02_swipe         Quick Swipe: take1 bars 1-2, take2 2-3, take3 3-5  -> Comp A
  004 b03_compB         Duplicate Comp -> Comp B = take2 whole (active)
  005 b04_compA         Comp A active again
  006 b05_rename        Comp A -> 'Best', take2 -> 'Lead Two'
  007 b06_moved         folder moved to bar 3
  008 b07_flatten       Flatten (Logic's own rendering of the active comp)

Run: python3.12 test_takes.py
"""
from pathlib import Path

from logicx.projectdata import ProjectData
from logicx.session import audio_regions, session_model
from logicx.takes import take_folders, playing_regions, playlists, sequence_kind

ROOT = Path(__file__).resolve().parent
PASS = 0
BAR = 3840                      # ticks per 4/4 bar @960 PPQ
SPB = 88200                     # samples per bar @120 BPM, 44.1 kHz


def ok(c, m):
    global PASS
    assert c, "FAIL " + m
    PASS += 1


def alt(n, bundle="fixtures/TAKES3.logicx"):
    return ProjectData.parse((ROOT / bundle / "Alternatives" / f"{n:03d}" / "ProjectData").read_bytes())


def one_folder(pd):
    tf = take_folders(pd)
    assert len(tf) == 1, f"expected one take folder, got {len(tf)}"
    return tf[0]


def sections(comp):
    return [(s["start_tick"], s["end_tick"], s["region"]["file"], s["region"]["trim_in_samples"],
             s["region"]["length_samples"]) for s in comp["sections"]]


COMP_A = [(0, BAR, "take1.wav", 0, SPB), (BAR, 2 * BAR, "take2.wav", SPB, SPB),
          (2 * BAR, 4 * BAR, "take3.wav", 2 * SPB, 2 * SPB)]

# --- b00: no folder; three plain regions ---------------------------------------------
ok(take_folders(alt(0)) == [], "b00: no take folder before packing")
ok(len(audio_regions(alt(0))) == 3, "b00: three plain audio regions")

# --- b01: packed -> one folder, 3 take lanes, take #1 (= take3) active --------------
f = one_folder(alt(1))
ok([l["kind"] for l in f["lanes"]] == ["take", "take", "take"], f"b01: 3 take lanes ({f['lanes']})")
ok([(t["lane"], t["name"], t["take_number"]) for t in f["takes"]] ==
   [(1, "take1", 3), (2, "take2", 2), (3, "take3", 1)], f"b01: lanes/names/take numbers ({f['takes']})")
ok(f["active"] == {"kind": "take", "lane": 3, "letter": None}, f"b01: take3 lane active ({f['active']})")
ok(not f["has_comp"] and f["comps"] == [], "b01: no comp yet")
ok([(r["file"], r["position_tick"]) for r in playing_regions(f)] == [("take3.wav", 0)], "b01: plays take3")
ok(sequence_kind(alt(1), f["child_seq"]) == "take_folder", "b01: child sequence classified as take folder")

# --- b02: Quick Swipe -> Comp A on a comp lane, sections cut sample-exact -------------
f = one_folder(alt(3))
ok([l["kind"] for l in f["lanes"]] == ["take", "take", "take", "comp"], "b02: comp lane appended (lane 4)")
ok(f["has_comp"] and f["active"] == {"kind": "comp", "lane": 4, "letter": "A"}, f"b02: Comp A active ({f['active']})")
ca = f["comps"][0]
ok(ca["name"] == "Comp A" and sections(ca) == COMP_A, f"b02: Comp A sections exact ({sections(ca)})")
ok([s["source_lane"] for s in ca["sections"]] == [1, 2, 3], "b02: section source take lanes 1/2/3")
ok(all(not t["active"] for t in f["takes"]), "b02: takes inactive once a comp exists")

# --- b03: Duplicate Comp -> Comp B (take2 whole) active; Comp A preserved -------------
f = one_folder(alt(4))
cb = {c["letter"]: c for c in f["comps"]}
ok(set(cb) == {"A", "B"} and cb["B"]["active"] and not cb["A"]["active"], "b03: Comp B active, Comp A kept")
ok(sections(cb["B"]) == [(0, 4 * BAR, "take2.wav", 0, 4 * SPB)], f"b03: Comp B = take2 whole ({sections(cb['B'])})")
ok(sections(cb["A"]) == COMP_A, "b03: inactive Comp A unchanged")

# --- b04: switching back is the only change -------------------------------------------
f = one_folder(alt(5))
ok(f["active"]["letter"] == "A", "b04: Comp A active again")
ok([(r["file"], r["position_tick"], r["trim_in_samples"]) for r in playing_regions(f)] ==
   [("take1.wav", 0, 0), ("take2.wav", BAR, SPB), ("take3.wav", 2 * BAR, 2 * SPB)], "b04: plays Comp A")

# --- b05: renames land on the comp's section regions and the take's region ------------
f = one_folder(alt(6))
ok({c["letter"]: c["name"] for c in f["comps"]} == {"A": "Best", "B": "Comp B"}, "b05: Comp A renamed 'Best'")
ok([t["name"] for t in f["takes"]] == ["take1", "Lead Two", "take3"], "b05: take2 renamed 'Lead Two'")

# --- b06: moving the folder moves the folder, not its (folder-relative) contents -------
f = one_folder(alt(7))
ok(f["position_tick"] == 2 * BAR, f"b06: folder at bar 3 ({f['position_tick']})")
ok(sections(f["comps"][0]) == COMP_A, "b06: section ticks stay folder-relative")
playing = [(r["position_tick"], r["file"], r["trim_in_samples"], r["length_samples"]) for r in playing_regions(f)]

# --- b07: Logic's own Flatten must equal our decoded active comp ----------------------
flat = sorted((r["position_tick"], r["file"], r["trim_in_samples"], r["length_samples"])
              for r in audio_regions(alt(8)))
ok(take_folders(alt(8)) == [], "b07: no folder after Flatten")
ok(flat == playing, f"b07: Logic's Flatten == decoded comp of b06 ({flat} vs {playing})")

# --- playlists: the Pro Tools view -------------------------------------------------------
pls = playlists(one_folder(alt(7)))
ok([(p["kind"], p["name"], p["main"]) for p in pls] ==
   [("comp", "Best", True), ("comp", "Comp B", False), ("take", "take1", False),
    ("take", "Lead Two", False), ("take", "take3", False)], f"playlists: 2 comps + 3 takes ({pls})")
ok([c["position_tick"] for c in pls[0]["clips"]] == [2 * BAR, 3 * BAR, 4 * BAR], "playlists: absolute clip ticks")

# --- session_model: lanes no longer leak in as tracks; the comp plays on track 1 --------
m = session_model(alt(7))
ok(m["tracks"] == [1], f"session_model: only arrange track 1 ({m['tracks']})")
ok(sorted((r["position_tick"], r["file"]) for r in m["audio_regions"]) ==
   [(2 * BAR, "take1.wav"), (3 * BAR, "take2.wav"), (4 * BAR, "take3.wav")], "session_model: plays the comp")
ok(len(m["take_folders"]) == 1 and len(m["take_folders"][0]["playlists"]) == 5, "session_model: playlists exposed")

# --- TAKES a01: packing 3 EXACTLY-overlapping regions on one track keeps only one take ---
f = one_folder(alt(1, "fixtures/TAKES.logicx"))
ok(len(f["takes"]) == 1 and f["takes"][0]["name"] == "take1", "TAKES a01: single-take folder")

print(f"OK — {PASS} assertions passed (logicx.takes take folders / comps)")
