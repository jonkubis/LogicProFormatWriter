#!/usr/bin/env python3
"""Take folders and Quick Swipe comps — read path (PROJECTDATA_FORMAT.md §41).

Every `0x20` placement in a track's region list is a *sequence region*: its `+0x20` link
(/4) names a CHILD sequence (the qeSM / qSvE / karT records whose idx@0x08 = child << 18).
The child is one of three things:

  * a MIDI region         — the child qSvE holds note / controller events;
  * an automation holder  — the child qeSM is named '*Automation' (these placements live
                            in the automation root sequence, not a track's region list);
  * a TAKE FOLDER         — the child is a mini-arrangement whose "tracks" are LANES.

Take-folder anatomy (proven on controlled saves, `fixtures/TAKES3.logicx` alternatives):

  lane rows    karT records under the child idx, in order; header +0x12 = 0-based lane
               index; rowType raw[0x24]: 1 = take lane, 6 = comp lane; raw[0x27] bit 0x08 =
               lane inactive; a header+0x12 == 0x7fffffff stub ends the list.
  lane content 0x24 audio placements whose trk byte = lane (1-based). Positions are
               FOLDER-RELATIVE (34560 origin). +0x0c bit 0x10 = not audible (inactive take /
               inactive comp).
  takes        ordinary gRuA regions (file_idx, region_k); tail+0x6e = the take's ID;
               flags16_b low byte = the take number Logic displays ("3 - take1").
  comps        one comp lane per comp (letter A, B, ... in lane order). Each comp SECTION is
               a gRuA cut from the source take — trim/length are the section — named after
               the comp ('Comp A', or the user's name); tail+0x6a = SOURCE TAKE ID (= the
               take's own tail+0x6e id); tail+0x36 / tail+0x3e = section [start, end) in
               absolute event ticks — a cache Logic rewrites when the folder moves, whose
               origin shifts with the project start, so only its span is trusted.

So a comp is literally a list of clips cut from the takes — the same thing as a Pro Tools
comp playlist — and each take lane is a Pro Tools alternate playlist.
"""
from __future__ import annotations

import struct

from .projectdata import _u32
from .session import (REGION_ORIGIN, is_placement, _AUDIO_PLACE, _MIDI_PLACE,
                      _grua_region, _lfua_filename, _region_records)

LANE_TAKE, LANE_COMP = 1, 6           # karT rowType of a take-folder lane row
INACTIVE = 0x10                       # placement +0x0c: lane/region not audible
_LANE_STUB = 0x7FFFFFFF


def _u16(b, o): return struct.unpack_from("<H", b, o)[0] if o + 2 <= len(b) else 0


def iter_placements(raw):
    """(offset, 80-byte event) for every region placement (0x20 / 0x24) in a qSvE record."""
    ps = _u32(raw, 0x1c) or 0
    bd = raw[0x24:0x24 + ps]
    o = 0
    while o + 0x50 <= len(bd):
        if is_placement(bd, o):
            yield o, bd[o:o + 0x50]
            o += 0x50
        else:
            o += 4


def child_link(ev):
    """Child-sequence index of a 0x20 placement (+0x20 / 4), or None."""
    v = _u32(ev, 0x20)
    return None if v in (None, 0xFFFFFFFF) else v // 4


def _sequences(pd):
    """seq index -> {'qsves': [qSvE recs], 'qesm': rec, 'lanes': [karT recs]} (idx@0x08 >> 18).
    A sequence index can own several qSvE records (e.g. a track's region list alongside other
    event lists), so all of them are kept."""
    seqs = {}
    for r in pd.records:
        if r.tag in (b"qSvE", b"qeSM", b"karT") and len(r.raw) >= 0x24:
            s = seqs.setdefault((_u32(r.raw, 0x08) or 0) >> 18, {"qsves": [], "qesm": None, "lanes": []})
            if r.tag == b"qSvE":
                s["qsves"].append(r)
            elif r.tag == b"qeSM":
                s["qesm"] = s["qesm"] or r
            else:
                s["lanes"].append(r)
    return seqs


def _seq_name(qesm):
    if qesm is None:
        return ""
    n = qesm.raw[0x24 + 0x10] if len(qesm.raw) > 0x34 else 0
    return qesm.raw[0x24 + 0x12:0x24 + 0x12 + n].decode("latin-1", "replace")


def _lane_rows(seq):
    """[{lane, kind, active}] from the child's karT lane rows (stub-terminated)."""
    out = []
    for r in seq["lanes"]:
        li = _u32(r.raw, 0x12)
        if li is None or li == _LANE_STUB or len(r.raw) <= 0x28:
            continue
        rt = r.raw[0x24]
        kind = "take" if rt == LANE_TAKE else "comp" if rt == LANE_COMP else f"row{rt}"
        out.append({"lane": li + 1, "kind": kind, "active": not (r.raw[0x27] & 0x08)})
    return out


def _grua_tail(raw):
    """Take/comp fields of a gRuA, relative to its name end (§17 / §41)."""
    nl = _u16(raw, 0x24 + 0x4a)
    ne = 0x24 + 0x4c + nl
    ne += ne & 1
    return {"take_number": _u16(raw, 0x28) & 0xFF,          # flags16_b low byte
            "in_take_folder": bool(_u16(raw, 0x28) & 0x1000),
            "take_id": _u16(raw, ne + 0x6e),          # a take's own id (0 on comp sections)
            "source_take_id": _u16(raw, ne + 0x6a),   # a comp section's source take id
            "abs_start": _u32(raw, ne + 0x36) or 0,
            "abs_end": _u32(raw, ne + 0x3e) or 0}


def sequence_kind(pd_or_seqs, child):
    """What a 0x20 placement's child sequence is: 'take_folder' | 'automation' | 'region'
    (a MIDI region's content) | None (no such sequence)."""
    seqs = pd_or_seqs if isinstance(pd_or_seqs, dict) else _sequences(pd_or_seqs)
    s = seqs.get(child)
    if not s:
        return None
    if _seq_name(s["qesm"]).startswith("*Automation"):
        return "automation"
    if s["qsves"] and any(l["kind"] in ("take", "comp") for l in _lane_rows(s)):
        return "take_folder"
    return "region"


def is_take_folder(pd_or_seqs, child):
    seqs = pd_or_seqs if isinstance(pd_or_seqs, dict) else _sequences(pd_or_seqs)
    s = seqs.get(child)
    return bool(s) and bool(s["qsves"]) and any(l["kind"] in ("take", "comp") for l in _lane_rows(s))


def take_folders(pd) -> list:
    """Every take folder in the arrangement, decoded:

      [{track, position_tick, child_seq, name, expanded, has_comp,
        lanes:  [{lane, kind: 'take'|'comp', active}],
        takes:  [{lane, take_id, take_number, name, active, empty, regions:[region]}],
        comps:  [{lane, letter, name, active,
                  sections:[{start_tick, end_tick, source_take_id, source_lane, region}]}],
        active: {'kind': 'comp'|'take', 'lane': n, 'letter': 'A'|None} | None}]

    region = {file, file_index, region_k, position_tick (folder-relative), trim_in_samples,
    length_samples, name, active, fade_in, fade_out}. Section ticks are folder-relative."""
    seqs = _sequences(pd)
    grua, lfua = _region_records(pd)
    out = []
    for r in pd.records:
        if r.tag != b"qSvE":
            continue
        for _o, ev in iter_placements(r.raw):
            if ev[0] != _MIDI_PLACE:
                continue
            child = child_link(ev)
            if child is None or not is_take_folder(seqs, child):
                continue
            out.append(_decode_folder(ev, child, seqs[child], grua, lfua, pd))
    return out


def _region(pd, grua, lfua, ev):
    fi, k = _u32(ev, 0x2c) // 4, _u32(ev, 0x28)
    gi = grua.get((fi, k))
    li = lfua.get(fi)
    reg = _grua_region(pd.records[gi].raw) if gi is not None else {}
    tail = _grua_tail(pd.records[gi].raw) if gi is not None else {}
    return {"file": _lfua_filename(pd.records[li].raw) if li is not None else None,
            "file_index": fi, "region_k": k,
            "position_tick": _u32(ev, 4) - REGION_ORIGIN,
            "active": not (_u32(ev, 0x0c) & INACTIVE),
            **reg, "_tail": tail}


def _decode_folder(ev, child, seq, grua, lfua, pd):
    lanes = _lane_rows(seq)
    kind_of = {l["lane"]: l["kind"] for l in lanes}
    by_lane = {}
    for q in seq["qsves"]:
        for _o, cev in iter_placements(q.raw):
            if cev[0] == _AUDIO_PLACE:
                by_lane.setdefault(_u16(cev, 0x14), []).append(_region(pd, grua, lfua, cev))
    folder_abs = _u32(ev, 4) - REGION_ORIGIN               # folder start, song ticks

    takes, comps, active = [], [], None
    comp_lanes = sorted(l for l, k in kind_of.items() if k == "comp")
    for lane in sorted(set(kind_of) | set(by_lane)):
        regs = sorted(by_lane.get(lane, []), key=lambda r: r["position_tick"])
        is_active = any(r["active"] for r in regs)
        if kind_of.get(lane) == "comp":
            letter = chr(ord("A") + comp_lanes.index(lane))
            sections = []
            for r in regs:
                t = r.pop("_tail")
                # the absolute [start,end) cache has a project-dependent origin (a project
                # start offset shifts it), so only its DIFFERENCE is used
                span = (t["abs_end"] - t["abs_start"]) if t.get("abs_end") and t.get("abs_start") else None
                sections.append({"start_tick": r["position_tick"],
                                 "end_tick": r["position_tick"] + span if span else None,
                                 "source_take_id": t.get("source_take_id"), "region": r})
            names = {s["region"].get("name") for s in sections}
            comps.append({"lane": lane, "letter": letter, "active": is_active,
                          "name": names.pop() if len(names) == 1 else sorted(n for n in names if n),
                          "sections": sections})
            if is_active:
                active = {"kind": "comp", "lane": lane, "letter": letter}
        else:
            tails = [r.pop("_tail") for r in regs]
            takes.append({"lane": lane, "take_id": tails[0]["take_id"] if tails else None,
                          "take_number": tails[0]["take_number"] if tails else None,
                          "name": regs[0].get("name") if regs else "", "active": is_active,
                          "empty": not regs, "regions": regs})
            if is_active and active is None:
                active = {"kind": "take", "lane": lane, "letter": None}
    lane_of_take = {t["take_id"]: t["lane"] for t in takes if t["take_id"]}
    for c in comps:                       # None = the source take was deleted from the folder
        for sct in c["sections"]:
            sct["source_lane"] = lane_of_take.get(sct["source_take_id"])
    return {"track": _u16(ev, 0x14), "position_tick": folder_abs, "child_seq": child,
            "name": _seq_name(seq["qesm"]),
            "expanded": bool(_u32(ev, 0x0c) & 0x100), "has_comp": bool(_u32(ev, 0x0c) & 0x00200000),
            "lanes": lanes, "takes": takes, "comps": comps, "active": active}


def playing_regions(folder) -> list:
    """What the folder actually plays, as plain regions on the folder's track at ABSOLUTE
    song ticks: the active comp's sections, else the active take's regions."""
    a = folder.get("active")
    if not a:
        return []
    if a["kind"] == "comp":
        comp = next(c for c in folder["comps"] if c["lane"] == a["lane"])
        regs = [s["region"] for s in comp["sections"]]
    else:
        regs = next(t for t in folder["takes"] if t["lane"] == a["lane"])["regions"]
    out = []
    for r in regs:
        q = {k: v for k, v in r.items() if k != "active"}
        q.update(track=folder["track"], position_tick=folder["position_tick"] + r["position_tick"],
                 take_folder=folder["child_seq"], comp=a["letter"], lane=a["lane"])
        out.append(q)
    return out


def playlists(folder) -> list:
    """DAW-neutral playlists of one take folder — the Pro Tools view: one playlist per take
    lane and one per comp, each a list of clips at ABSOLUTE song ticks. `main` marks the one
    Logic is playing (the PT main playlist); the rest are alternates."""
    a = folder.get("active") or {}
    base = folder["position_tick"]
    out = []
    for c in folder["comps"]:
        out.append({"name": c["name"] if isinstance(c["name"], str) else f"Comp {c['letter']}",
                    "kind": "comp", "letter": c["letter"], "main": a.get("lane") == c["lane"],
                    "clips": [{**_clip(s["region"]), "position_tick": base + s["start_tick"]}
                              for s in c["sections"]]})
    for t in folder["takes"]:
        if t["empty"]:
            continue
        out.append({"name": t["name"], "kind": "take", "take_number": t["take_number"],
                    "main": a.get("lane") == t["lane"],
                    "clips": [{**_clip(r), "position_tick": base + r["position_tick"]} for r in t["regions"]]})
    return out


def _clip(r):
    return {"file": r.get("file"), "file_index": r.get("file_index"),
            "trim_in_samples": r.get("trim_in_samples"), "length_samples": r.get("length_samples"),
            "name": r.get("name"), "fade_in": r.get("fade_in", 0), "fade_out": r.get("fade_out", 0)}
