#!/usr/bin/env python3
"""Assemble a DAW-agnostic **SessionModel** from a Logic `ProjectData` — the port-ready
extraction that a Logic→(Pro Tools / AAF / SMF / …) converter consumes.

It ties the verified decoders together into one model: the timeline (tempo/meter/markers),
and every AUDIO and MIDI region with its **absolute position, content, and edits**:

    from logicx.session import session_model
    m = session_model(pd)
    # m["audio_regions"]  -> [{track, position_tick, length_samples, trim_in_samples,
    #                          file, fade_in, fade_out, in_curve, out_curve, name}]
    # m["midi_regions"]   -> [{track, position_tick, notes:[(tick,pitch,vel,len)]}]
    # m["tempo_map"] / ["meter_map"] / ["markers"] / ["initial_bpm"]

Positions are 960-PPQ ticks from song start (bar1 = 0); audio trim/length are in SAMPLES.
Everything here is verified against real sessions (see PROJECTDATA_FORMAT.md §3–§8, §17/§35.1,
§36); the audio-region trim-in (`gRuA pay+0x06`) is §17.
"""
from __future__ import annotations

import re
import struct

from .projectdata import ProjectData, _u32, REC_HEADER_SIZE, REC_SIZE_OFF
from . import inspect as _lx

REGION_ORIGIN = 34560          # placement position field = 34560 + tick@960  (§3)
MARKER_ORIGIN = 38400          # marker/tempo event position = 38400 + tick@960  (§3/§6)
_AUDIO_PLACE = 0x24            # audio region placement event marker (§3/§8.1)
_MIDI_PLACE = 0x20            # MIDI region placement event marker


def _u16(b, o): return struct.unpack_from("<H", b, o)[0]


# Region-reference field inside an 80-byte placement event, per event type:
#   audio (0x24): the shared region-index pool link @+0x2c  -> gRuA/lFuA at (idx*0x40000)
#   MIDI  (0x20): the per-track content-cluster link  @+0x08 -> note qSvE at (idx*0x40000)
_LINK_OFF = {_AUDIO_PLACE: 0x2c, _MIDI_PLACE: 0x08}
# Audio placements also carry the 0-based REGION NUMBER within that file's region cluster
# @+0x28: the placed region is gRuA(idx@0x08 = file_idx<<18, ordinal@0x0c = k<<16) (§41).
# One audio file cut into several regions (every comp/edit) shares one idx; ordinal 0 is
# the first region. Resolving on idx alone picks an arbitrary sibling.
_REGION_K_OFF = 0x28


def is_placement(bd, o):
    """True if an 80-byte region placement starts at bd[o] (§3/§41). Anchored on the event's
    constant word tags (+0x17 == 0x89, +0x37 == 0x8a; 2183/2183 placements over 70 sessions)
    rather than a track-number range: the track is a u16 @+0x14 and real sessions exceed
    64 (session B2 reaches 139), so a byte/range test silently drops regions."""
    return (o + 0x50 <= len(bd) and bd[o] in (_AUDIO_PLACE, _MIDI_PLACE) and bd[o + 1:o + 4] == b"\0\0\0"
            and _u32(bd, o + 4) >= REGION_ORIGIN and bd[o + 0x16] == 0
            and bd[o + 0x17] == 0x89 and bd[o + 0x37] == 0x8A and _u16(bd, o + 0x14) >= 1)


def _placements(pd, marker):
    """All region-placement events of `marker` (0x24 audio / 0x20 MIDI) across EVERY qSvE —
    real sessions spread them over per-track region lists, not one container (§8.1).
    Returns [{track, position_tick, region_index, region_k, seq, child, flags}]: `seq` is the
    sequence the placement lives in (idx@0x08 >> 18 of its qSvE), `child` the +0x20 child
    sequence link (MIDI region content / take folder / automation holder, §41), `flags` +0x0c."""
    link_off = _LINK_OFF[marker]
    out = []
    for r in pd.records:
        if r.tag != b"qSvE":
            continue
        ps = _u32(r.raw, REC_SIZE_OFF)
        bd = r.raw[REC_HEADER_SIZE:REC_HEADER_SIZE + ps]
        seq = (_u32(r.raw, 0x08) or 0) >> 18
        o = 0
        while o + 0x50 <= len(bd):
            if _u32(bd, o) == marker and is_placement(bd, o):
                ch = _u32(bd, o + 0x20)
                out.append({"track": _u16(bd, o + 0x14),
                            "position_tick": _u32(bd, o + 4) - REGION_ORIGIN,
                            "region_index": _u32(bd, o + link_off) // 4,
                            "region_k": _u32(bd, o + _REGION_K_OFF) if marker == _AUDIO_PLACE else None,
                            "seq": seq, "child": None if ch == 0xFFFFFFFF else ch // 4,
                            "flags": _u32(bd, o + 0x0c)})
                o += 0x50
            else:
                o += 4
    return out


def _region_records(pd):
    """(gRuA by (file_idx, region_k), lFuA by file_idx) — record indices."""
    grua, lfua = {}, {}
    for i, r in enumerate(pd.records):
        if r.tag not in (b"gRuA", b"lFuA") or len(r.raw) < 0x10:
            continue
        rid, ordv = _u32(r.raw, 0x08), _u32(r.raw, 0x0c)
        if rid % 0x40000:
            continue
        if r.tag == b"gRuA" and ordv % 0x10000 == 0:
            grua[(rid // 0x40000, ordv >> 16)] = i
        elif r.tag == b"lFuA":
            lfua.setdefault(rid // 0x40000, i)
    return grua, lfua


def audio_regions(pd, exclude_seqs=()) -> list:
    """Every placed audio region with its OWN edit params (trim/length/fades/name) and
    source file. Each placement resolves to gRuA(file_idx, region_k) — not merely to the
    file — so several regions cut from one file (comps, edits) each get their own values.
    Placements inside `exclude_seqs` (take-folder lanes, §41) are skipped: their trk byte is
    a LANE and their position folder-relative, so they are not track-level regions."""
    grua, lfua = _region_records(pd)
    out = []
    for ev in _placements(pd, _AUDIO_PLACE):
        if ev["seq"] in exclude_seqs:
            continue
        gi = grua.get((ev["region_index"], ev["region_k"]))
        if gi is None:                                  # unknown k: fall back to the file's first
            gi = grua.get((ev["region_index"], 0))
        li = lfua.get(ev["region_index"])
        reg = _grua_region(pd.records[gi].raw) if gi is not None else {}
        f = _lfua_filename(pd.records[li].raw) if li is not None else None
        out.append({"track": ev["track"], "position_tick": ev["position_tick"], "file": f,
                    "file_index": ev["region_index"], "region_k": ev["region_k"], **reg})
    return out


def _grua_region(raw):
    """Audio-region edit params from a gRuA record (§17/§35.1)."""
    pay = raw[0x24:]
    nlen = _u16(pay, 0x4a)
    e = raw.find(b"EDAF")
    fin = fout = ic = oc = 0
    if e >= 0:
        fin, fout = _u32(raw, e + 0x10) or 0, _u32(raw, e + 0x14) or 0
        ic, oc = raw[e + 0x1c], raw[e + 0x1d]
    return {"trim_in_samples": _u32(pay, 0x06), "length_samples": _u32(pay, 0x16),
            "fade_in": fin, "fade_out": fout,
            "in_curve": ic - 256 if ic > 127 else ic, "out_curve": oc - 256 if oc > 127 else oc,
            "name": pay[0x4c:0x4c + nlen].decode("latin-1", "replace")}


def _lfua_filename(raw):
    pay = raw[0x24:]
    n = _u16(pay, 0x08)
    return pay[0x0a:0x0a + n * 2].decode("utf-16-le", "replace")


def markers(pd):
    """Song markers as [(tick, name)] (§6). Positions are always recovered; names are
    paired from the marker-name qSxT records by link-id."""
    idx = pd._find_marker_qsve()
    if idx is None:
        return []
    raw = pd.records[idx].raw
    ps = _u32(raw, REC_SIZE_OFF)
    body = raw[REC_HEADER_SIZE:REC_HEADER_SIZE + ps]
    evs, o = [], 0                                   # marker events start at payload offset 0
    while o + 48 <= len(body) and body[o:o + 4] == b"\x12\x00\x00\x00":
        evs.append((_u32(body, o + 0x10), _u32(body, o + 0x04) - MARKER_ORIGIN))
        o += 48
    names = {}
    for r in pd.records:
        if r.tag == b"qSxT":
            m = re.search(rb"\\cf2 (.*?)\}", r.raw, re.S)
            if m:
                names[_u16(r.raw, 0x0a)] = m.group(1).decode("latin-1", "replace").strip()
    return [(tick, names.get(lid, "")) for lid, tick in evs]


def session_model(pd) -> dict:
    """Full port-ready SessionModel (see module docstring)."""
    from . import takes as _tk
    folders = _tk.take_folders(pd)
    inside = {f["child_seq"] for f in folders}

    # audio: track-level regions + what each take folder actually plays (active comp/take)
    audio = audio_regions(pd, exclude_seqs=inside)
    for f in folders:
        audio.extend(r for r in _tk.playing_regions(f) if r.get("kind", "audio") == "audio")

    # MIDI: every 0x20 placement is a sequence region whose content is the CHILD sequence
    # (+0x20 / 4, §41). Skip '*Automation' holders and take folders; fall back to +0x08.
    notes_by_seq = {r["idx"] >> 18: r["notes"] for r in _lx.midi_notes(pd)}
    seqs = _tk._sequences(pd)
    midi = []
    for ev in _placements(pd, _MIDI_PLACE):
        if ev["seq"] in inside or (ev["child"] is not None
                                   and _tk.sequence_kind(seqs, ev["child"]) in ("take_folder", "automation")):
            continue
        seq = ev["child"] if ev["child"] is not None else ev["region_index"]
        midi.append({"track": ev["track"], "position_tick": ev["position_tick"],
                     "notes": notes_by_seq.get(seq, notes_by_seq.get(ev["region_index"], []))})

    si = _lx.song_info(pd)
    return {
        "ppq": 960,
        "initial_bpm": si.get("initial_bpm"),
        "sample_rate": si.get("sample_rate"),
        "tempo_map": pd.get_tempo_map(),       # [(tick, bpm)]
        "meter_map": pd.get_meter_map(),       # [(tick, num, den)]
        "markers": markers(pd),                # [(tick, name)]
        "tracks": sorted({r["track"] for r in audio} | {r["track"] for r in midi}),
        "audio_regions": audio,
        "midi_regions": midi,
        # take folders as DAW-neutral playlists (one per comp + one per take; `main` = what
        # Logic plays) — the Pro Tools playlist view (§41)
        "take_folders": [{"track": f["track"], "position_tick": f["position_tick"], "name": f["name"],
                          "active": f["active"], "playlists": _tk.playlists(f)} for f in folders],
    }
