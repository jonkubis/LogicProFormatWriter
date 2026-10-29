#!/usr/bin/env python3
"""Read-only decoders for the reverse-engineered ProjectData subsystems.

Turns the byte layouts documented in PROJECTDATA_FORMAT.md §14–§24 into executable
readers — the "read path" of the format. Every offset here is a verified fact from the
production-corpus RE (1293 real sessions, 12 Logic versions); these functions are validated
across that corpus by `test_corpus_decode.py`.

    from logicx import inspect as lx
    pd = ProjectData.parse(open(".../ProjectData","rb").read())
    lx.song_info(pd)        # {version, schema, initial_bpm, headerForm, n_records}
    lx.coremidi_ports(pd)   # [{direction, uid, endpoint, device}]           (§14 MroC)
    lx.mixer_strips(pd)     # [{type, name, fader, pan}]                      (§15 OCuA)
    lx.tracks(pd)           # [{cluster, ordinal, row_type, channel_slot, uuid}] (§18 karT)
    lx.environment(pd)      # [{slot, kind, name, uuid}]                      (§19 ivnE)
    lx.audio_pool(pd)       # [loop/sample names from the pool bplists]       (§22 OgnS)
    lx.audio_files(pd)      # [{name, container, sample_rate, bits, ...}]      (§8.7 lFuA)
    lx.plugins(pd)          # [{strip, slot, name, au_type, native, preset}]   (§16.2 UCuA)
    lx.environment_cables(pd) # the Environment routing graph (cable edges)   (§19.2 ivnE)
    lx.region_takes(pd)     # take/comp groups of audio regions               (§17.2 gRuA)
    lx.tag_census(pd)       # {tag: count}

Fields added in the §39 byte-coverage push are marked with their sub-section (§8.7/§15.4/
§17.2/§18.2/§19.2) — e.g. `mixer_strips` now carries channel_format/channel_count/output_ref,
and `tracks` carries color_index.
"""
from __future__ import annotations

import plistlib
import struct
from collections import Counter


def _u16(b, o): return int.from_bytes(b[o:o + 2], "little") if o + 2 <= len(b) else None
def _u32(b, o): return int.from_bytes(b[o:o + 4], "little") if o + 4 <= len(b) else None
def _cstr(b, o, n):
    """Fixed n-byte field at o, decoded ASCII/latin-1 up to the first NUL, stripped."""
    if o + n > len(b):
        n = len(b) - o
    return b[o:o + n].split(b"\x00", 1)[0].decode("latin-1", "replace").strip()


# --- §21 gnoS : root Song record --------------------------------------------
def song_info(pd) -> dict:
    """Global song facts from the root `gnoS` record (§21). `initial_bpm` is read from
    the authoritative tempo slot C @ gnoS+0x3A6 (NOT the playhead-dependent slot A)."""
    g = next((r for r in pd.records if r.tag == b"gnoS"), None)
    if g is None:
        return {}
    raw = g.raw
    slotC = _u32(raw, 0x3A6)
    slotB = _u32(raw, 0xEA)
    return {
        "schema": _u16(raw, 0x04),
        "headerForm": raw[0x1a] if len(raw) > 0x1a else None,     # 1=compact, 2=settled
        "initial_bpm": round(slotC / 10000, 4) if slotC else None,
        "tempo_slots_consistent": slotB == slotC,                  # §21 invariant (1293/1293)
        "gnoS_size": len(raw),
        "n_records": len(pd.records),
    }


# --- §14 MroC : CoreMIDI endpoint table -------------------------------------
_MROC_DIR = {0xE80000: "in", 0xEC0000: "out"}


def coremidi_ports(pd) -> list:
    """CoreMIDI endpoints cached in the two `MroC` records (§14). 100-byte slots =
    u32 UniqueID + 64B endpoint name + 32B device name, after a 6-byte payload prefix."""
    out = []
    for r in pd.records:
        if r.tag != b"MroC":
            continue
        direction = _MROC_DIR.get(_u32(r.raw, 0x08), "?")
        count = _u16(r.raw, 0x26) or 0
        base = 0x24 + 6
        for k in range(count):
            s = base + k * 100
            uid = _u32(r.raw, s)
            if uid is None:
                break
            out.append({"direction": direction, "uid": uid,
                        "endpoint": _cstr(r.raw, s + 0x04, 64),
                        "device": _cstr(r.raw, s + 0x44, 32)})
    return out


# --- §15 OCuA : mixer channel strips -----------------------------------------
_OCUA_TYPE = {0x40: "Audio", 0x41: "Input", 0x42: "Aux", 0x43: "Inst", 0x44: "Output",
              0x45: "Bus", 0x46: "Master", 0x49: "Input", 0x4c: "Output", 0x4b: "Rewire"}


_CHAN_FORMAT = {0: "mono", 1: "stereo", 4: "surround"}


def mixer_strips(pd) -> list:
    """Full channel strips from `OCuA` (§15 / §39 §15.4) — skips the 14-byte STUB
    placeholders (type byte 0xff). `fader`/`pan` are the 0–127 byte values (default 90 /
    64=center); `fader` is the MSB of a 32-bit fixed-point volume (mirrored @pay+0x77).
    `channel_format`/`channel_count` (0x56/0x7b) give mono/stereo/surround; `output_ref`
    is the u16 routing ref @pay+0x5c (0xFFFF = source/summing strip)."""
    out = []
    for r in pd.records:
        if r.tag != b"OCuA":
            continue
        pay = r.raw[0x24:]
        if len(pay) < 0x5a or _u16(pay, 0x0a) != 0x1235:
            continue                                    # not a full strip
        t = pay[0x04]
        if t == 0xff or t not in _OCUA_TYPE:
            continue                                    # stub / anomaly
        cfmt = pay[0x56] if len(pay) > 0x56 else None
        ccnt = pay[0x7b] if len(pay) > 0x7b else None
        out.append({"type": _OCUA_TYPE[t], "type_id": t,
                    "name": _cstr(pay, 0x3c, 16),
                    "ordinal": _u16(pay, 0x06),
                    "fader": pay[0x55], "pan": pay[0x59],
                    "channel_format": _CHAN_FORMAT.get(cfmt, cfmt),
                    "channel_count": ccnt,
                    "output_ref": _u16(pay, 0x5c)})
    return out


# --- §18 karT : arrange / track rows -----------------------------------------
def tracks(pd, populated_only: bool = True) -> list:
    """Track/arrange rows from `karT` (§18). `link2@0x14` is the populated(0x0000) /
    empty(0x7FFF) discriminator. `channel_slot` links to an ivnE/OCuA channel; the
    16-byte `uuid` keys MneG drummer state."""
    out = []
    for r in pd.records:
        if r.tag != b"karT":
            continue
        link2 = _u16(r.raw, 0x14)
        populated = link2 == 0x0000
        if populated_only and not populated:
            continue
        cluster = _u32(r.raw, 0x08)
        row = {"cluster": cluster, "ordinal": _u16(r.raw, 0x12), "populated": populated}
        if populated and len(r.raw) >= 0x4c:
            # color palette index (§39 §18.2) — only meaningful on arrange rows (cluster
            # 0x040000); raw[0x28] is always a multiple of 4 = paletteIndex<<2, default 0.
            color = (r.raw[0x28] >> 2) if cluster == 0x00040000 and len(r.raw) > 0x28 else None
            row.update({"row_type": r.raw[0x24],                 # 1 normal, 3 master
                        "channel_slot": _u32(r.raw, 0x2c),
                        "color_index": color,
                        "uuid": r.raw[0x3c:0x4c].hex()})
        out.append(row)
    return out


# --- §19 ivnE : MIDI Environment objects -------------------------------------
_IVNE_KIND = {0: "terminator", 2: "monitor", 3: "device/folder", 4: "channel-strip",
              5: "channel-strip", 6: "terminator", 0xFFFF: "folder/context"}


def environment(pd) -> list:
    """Environment objects from `ivnE` (§19). `slot = idx>>16` (unique, no pool). KIND
    @pay+0x5a; canonical name length @pay+0x9e, name @pay+0xa0 (fixed across sv2-12)."""
    out = []
    for r in pd.records:
        if r.tag != b"ivnE":
            continue
        pay = r.raw[0x24:]
        kind = _u16(pay, 0x5a)
        name = ""
        nlen = _u16(pay, 0x9e)
        if nlen and 0 < nlen < 256 and 0xa0 + nlen <= len(pay):
            name = pay[0xa0:0xa0 + nlen].split(b"\x00", 1)[0].decode("latin-1", "replace")
        out.append({"slot": (_u32(r.raw, 0x08) or 0) >> 16,
                    "kind": kind, "kind_name": _IVNE_KIND.get(kind, "?"), "name": name})
    return out


# --- §22 OgnS : project audio pool -------------------------------------------
AUDIO_POOL_IDX = 0x01080000          # §22 role slot for the audio pool
_SUBBLOCK_MAGIC = 0xED99
_SUBBLOCK_TAG = bytes([0xA0, 0x28, 0x00, 0x00])


def ogns_subblocks(rec_raw: bytes):
    """Walk the §22 container grammar inside an OgnS payload. Each sub-block header is
    `[4B a0280000][u16 subtype][u16 0xED99][u32 length]` followed by `length` body bytes.
    Yields (offset, subtype, body). Entries are a 0x0003 + 0x0002 pair per pool item;
    the 0x0002 body wraps exactly one NSKeyedArchiver bplist."""
    pay = rec_raw[0x24:]
    o = 0
    while True:
        i = pay.find(_SUBBLOCK_TAG, o)
        if i < 0 or i + 12 > len(pay):
            return
        subtype = _u16(pay, i + 4)
        magic = _u16(pay, i + 6)
        ln = _u32(pay, i + 8) or 0
        if magic == _SUBBLOCK_MAGIC:
            yield i, subtype, pay[i + 12:i + 12 + ln]
        o = i + 4


def _unarchive(plist: dict) -> dict:
    """Flatten an NSKeyedArchiver plist into {key: value} by resolving NS.keys/NS.objects
    UID references against $objects."""
    objs = plist.get("$objects", [])

    def deref(x):
        if isinstance(x, plistlib.UID):
            i = x.data
            return objs[i] if 0 <= i < len(objs) else None
        return x

    out = {}
    for o in objs:
        if isinstance(o, dict) and "NS.keys" in o and "NS.objects" in o:
            for k, v in zip(o["NS.keys"], o["NS.objects"]):
                k, v = deref(k), deref(v)
                if isinstance(k, str):
                    out[k] = v
    return out


def audio_pool(pd) -> list:
    """Entries of the project audio pool (`OgnS` idx 0x01080000, §22). Each entry's
    `0x0002` sub-block holds `[u32 flag][u32 blobLen][bplist00 …]`; the bplist decodes to
    {Shared → LoopFamily → LoopName, LoopId}, where LoopName is the real sample basename.
    Returns [{name, loop_id, family}] — length matches ENTRY_COUNT @payload+0x1c."""
    out = []
    for r in pd.records:
        if r.tag != b"OgnS" or _u32(r.raw, 0x08) != AUDIO_POOL_IDX:
            continue
        for _off, subtype, body in ogns_subblocks(r.raw):
            if subtype != 0x0002 or len(body) < 12:
                continue
            blob_len = _u32(body, 0x04) or 0
            blob = body[0x08:0x08 + blob_len]
            if blob[:8] != b"bplist00":
                continue
            try:
                flat = _unarchive(plistlib.loads(blob))
            except Exception:
                continue
            out.append({"name": flat.get("LoopName"), "loop_id": flat.get("LoopId"),
                        "family": flat.get("LoopFamily")})
    return out


def movie_ref(pd):
    """The movie/video file referenced by the project, or None. Logic stores it in the OgnS
    **movie container** (idx 0x00FC0000, §22/§37) as an NSKeyedArchiver `MovieData` bplist
    holding a `file://` URL + a macOS bookmark (alias). NOTE: `ediV` (§30) stays EMPTY even
    with a movie loaded — it is only video-track display state; presence of THIS container is
    what marks a movie as loaded. Returns {'url', 'path'} or None."""
    import re
    from urllib.parse import unquote, urlparse
    for r in pd.records:
        if r.tag != b"OgnS" or _u32(r.raw, 0x08) != 0x00FC0000:
            continue
        urls = re.findall(rb"file://[\x20-\x7e]+", r.raw)      # greedy printable URL runs
        if urls:
            vids = [u for u in urls if u.lower().endswith(
                (b".mp4", b".mov", b".m4v", b".avi", b".mpg", b".mpeg", b".mkv"))]
            url = max(vids or urls, key=len).decode("latin-1")
            return {"url": url, "path": unquote(urlparse(url).path)}
        return {"url": None, "path": None}       # container present but no URL found
    return None


def audio_pool_count(pd):
    """ENTRY_COUNT @payload+0x1c of the audio-pool OgnS (§22) — should equal len(audio_pool)."""
    for r in pd.records:
        if r.tag == b"OgnS" and _u32(r.raw, 0x08) == AUDIO_POOL_IDX:
            return _u32(r.raw, 0x24 + 0x1c)
    return None


# --- §17 / §35.1 gRuA : region fades -----------------------------------------
def region_fades(pd) -> list:
    """Fade descriptors of every gRuA region that has fades set (the `EDAF` tail
    marker, §35.1). Returns [{idx, fade_in, fade_out, in_curve, out_curve}] with fade
    lengths in samples (0 = no fade); regions with no `EDAF` are omitted."""
    out = []
    for r in pd.records:
        if r.tag != b"gRuA":
            continue
        e = r.raw.find(b"EDAF")
        if e < 0:
            continue
        fin, fout = _u32(r.raw, e + 0x10) or 0, _u32(r.raw, e + 0x14) or 0
        if fin == 0 and fout == 0:
            continue                            # descriptor present but no actual fade
        ic = r.raw[e + 0x1c] if e + 0x1c < len(r.raw) else 0
        oc = r.raw[e + 0x1d] if e + 0x1d < len(r.raw) else 0
        out.append({"idx": _u32(r.raw, 0x08),
                    "fade_in": fin, "fade_out": fout,
                    "in_curve": ic - 256 if ic > 127 else ic,      # signed
                    "out_curve": oc - 256 if oc > 127 else oc})
    return out


# --- §16 / §35.2 UCuA : loaded plugin presets --------------------------------
def plugin_presets(pd) -> list:
    """Loaded-preset filenames of the native-plugin `UCuA` slots (KIND 1/2, §35.2).
    Returns [{strip, slot, preset}] — `preset` is the NUL-terminated filename @pay+0x0e
    (e.g. 'SPX90-16-GateReverb.pst'). KIND 0/5/7 slots (reserved / Smart Controls) are skipped."""
    out = []
    for r in pd.records:
        if r.tag != b"UCuA":
            continue
        pay = r.raw[0x24:]
        if len(pay) < 0x10 or _u16(pay, 0x04) not in (1, 2):
            continue
        preset = pay[0x0e:].split(b"\x00", 1)[0].decode("latin-1", "replace")
        if preset:
            out.append({"strip": (_u32(r.raw, 0x0c) or 0) >> 16,
                        "slot": _u16(r.raw, 0x12), "preset": preset})
    return out


# --- §16.2 UCuA : plugin insert IDENTITY (which plugin in which slot) ---------
# kAudioUnitType 4CCs (stored reversed in the record). 'GAME' at pay+0x84 = a native
# Logic plugin (the display name is the whole identity, no AU triple).
_AU_TYPES = {b"aufx", b"aumu", b"aumf", b"augn", b"aumi", b"auol", b"aupn", b"aufc",
             b"aumx", b"avol", b"adsp", b"aunt"}


def _fourcc(pay, o):
    """Reversed 4CC at payload offset o -> str (record stores AU OSTypes byte-reversed)."""
    return pay[o:o + 4][::-1].decode("latin-1", "replace") if o + 4 <= len(pay) else ""


def plugins(pd) -> list:
    """Every identifiable plugin insert, from the native framing of `UCuA` (§16.2).
    Returns [{strip, slot, name, native, au_type, au_subtype, au_manufacturer, preset}]:
      - `strip` = owning channel strip (ordinal@hdr+0x0c >> 16, joins an OCuA record),
      - `slot`  = insert slot index (link1@hdr+0x12; the OCuA occupancy bitmap @pay+0x84
                  has bit `slot` set iff this record exists — §15.5),
      - `name`  = display name @pay+0x78 (e.g. 'Channel EQ', 'AmpliTube 5'),
      - `native`= True when containerTag@pay+0x84 == 'GAME' (a built-in Logic plugin;
                  the AU fields are None), else it is an AudioUnit and the triple
                  (au_type @0x88 'aufx'/'aumu'/'aumf', au_subtype @0x8c, au_manufacturer
                  @0x84) identifies the component,
      - `preset`= loaded preset filename @pay+0x0e (extension is a format oracle:
                  .aupreset->AU, .exs->Sampler, .def/.pst->native).
    Only KIND 1/2 records whose framing carries a `GAME` tag or a valid AU type are
    reported; KIND 5/7 slots keep their identity inside an opaque bplist/AU blob and are
    skipped (see `plugin_presets` for their preset filenames)."""
    out = []
    for r in pd.records:
        if r.tag != b"UCuA":
            continue
        pay = r.raw[0x24:]
        if len(pay) < 0x90:
            continue
        native = pay[0x84:0x88] == b"GAME"              # 'GAME' is a literal sentinel, not a 4CC
        atype = pay[0x88:0x8c][::-1]                    # AU OSTypes are stored byte-reversed
        if not (native or atype in _AU_TYPES):
            continue                                    # bplist/opaque or non-plugin slot
        raw_name = pay[0x78:0x84].split(b"\x00", 1)[0]
        name = raw_name.decode("latin-1", "replace") if all(0x20 <= c < 0x7f for c in raw_name) else ""
        preset = pay[0x0e:].split(b"\x00", 1)[0].decode("latin-1", "replace")
        out.append({"strip": (_u32(r.raw, 0x0c) or 0) >> 16, "slot": _u16(r.raw, 0x12),
                    "name": name, "native": native,
                    "au_type": None if native else _fourcc(pay, 0x88),
                    "au_subtype": None if native else _fourcc(pay, 0x8c),
                    "au_manufacturer": None if native else _fourcc(pay, 0x84),
                    "preset": preset})
    return out


# --- §8.7 lFuA : audio-file references (the audio bin) -----------------------
_CONTAINER = {b"WAVE": "wav", b"AIFF": "aiff", b"caff": "caf", b"M4A ": "m4a"}


def audio_files(pd) -> list:
    """Every audio-file reference (`lFuA`, §8 / §39 §8.7) with its decoded descriptor.
    Returns [{folder, container, compression, frames, sample_rate, channels, bits,
    audio_file_id, pool_ordinal}]. The descriptor sits at the container 4CC (EVAW/ffac/
    FFIA/' A4M', stored reversed); `audio_file_id` (EVAW+0x38) is the authoritative 1-based
    per-file pool id; `folder` (EVAW-0x13e) is a plain UTF-8 path (relative `Audio Files`
    or absolute) — there is NO macOS bookmark/alias anywhere in the record (§39 §8.7). The
    file *basename* is not in lFuA; it lives in the pool bplist (see `audio_pool`), keyed by
    `audio_file_id`. `compression` is 'pcm' for uncompressed, else the codec 4CC ('COMP'=ALAC)."""
    out = []
    for r in pd.records:
        if r.tag != b"lFuA":
            continue
        raw = r.raw
        d = -1
        for tag in (b"EVAW", b"ffac", b"FFIA", b" A4M"):        # reversed container 4CCs
            d = raw.find(tag)
            if d >= 0:
                break
        if d < 0:
            continue
        container = _CONTAINER.get(raw[d:d + 4][::-1], raw[d:d + 4][::-1].decode("latin-1", "replace"))
        comp = raw[d - 0x142:d - 0x13e][::-1] if d >= 0x142 else b""     # codec 4CC (reversed)
        compression = "pcm" if comp in (b"\0\0\0\0", b"NONE") else comp.decode("latin-1", "replace").strip("\0")
        folder = _cstr(raw, d - 0x13e, 220) if d >= 0x13e else ""
        # optional redundant basename copy in the LFUA sub-block (§8.8 LFUA+0x0a);
        # present in ~24% of records — the file's actual name when Logic wrote it here.
        lf = raw.find(b"LFUA")
        name = _cstr(raw, lf + 0x0a, 128) if lf >= 0 else ""
        out.append({"name": name, "folder": folder, "container": container, "compression": compression,
                    "frames": _u32(raw, d + 0x0c), "sample_rate": _u32(raw, d + 0x14),
                    "channels": _u16(raw, d + 0x18), "bits": _u16(raw, d + 0x1a),
                    "audio_file_id": _u32(raw, d + 0x38),
                    "pool_ordinal": _u16(raw, 0x24 + 0x02)})
    return out


# --- §19.2 ivnE : Environment cable graph ------------------------------------
def environment_cables(pd) -> list:
    """The MIDI-Environment routing graph from `ivnE` (§39 §19.2). Each object has a slot
    id @pay+0x10; the four cable refs (0x14 serial, 0x26 shared-target, 0x96, 0x22) point
    at other objects' slot ids. Returns [{slot, kind, name, cables}] where `cables` lists
    the resolved target slots (only refs that resolve to a real object are kept)."""
    nodes = {}
    for r in pd.records:
        if r.tag != b"ivnE":
            continue
        pay = r.raw[0x24:]
        if len(pay) <= 0x96 + 2:
            continue
        slot = _u16(pay, 0x10)
        nodes[slot] = {"raw": pay, "kind": pay[0x5a] if len(pay) > 0x5a else None}
    slots = set(nodes)
    out = []
    for slot, nd in nodes.items():
        pay = nd["raw"]
        name = ""
        nlen = _u16(pay, 0x9e)
        if nlen and 0 < nlen < 256 and 0xa0 + nlen <= len(pay):
            name = pay[0xa0:0xa0 + nlen].split(b"\x00", 1)[0].decode("latin-1", "replace")
        cables = []
        for off in (0x14, 0x26, 0x96, 0x22):
            ref = _u16(pay, off)
            if ref and ref in slots:
                cables.append(ref)
        out.append({"slot": slot, "kind": nd["kind"],
                    "kind_name": _IVNE_KIND.get(nd["kind"], "?"),
                    "name": name, "cables": cables})
    return out


# --- §17.2 gRuA : take / comp groups -----------------------------------------
def _grua_name_end(raw: bytes) -> int:
    """Offset just past the gRuA name field (§17): 0x24+0x4c + u16 name-len@0x24+0x4a,
    rounded up to even. This is the base of the region 'tail' parameter block."""
    nl = _u16(raw, 0x24 + 0x4a) or 0
    e = 0x24 + 0x4c + nl
    return e + (e & 1)


def region_takes(pd) -> list:
    """Take/comp grouping of audio regions from `gRuA` (§39 §17.2). Regions that belong to
    the same take folder share a `take_group` id (tail+0x34); `take_sub` (tail+0x38) is
    the position within the group and is nonzero exactly when `take_group` is. Returns the
    regions that carry a take group: [{idx, take_group, take_sub, region_mode, take_index}]."""
    out = []
    for r in pd.records:
        if r.tag != b"gRuA":
            continue
        e = _grua_name_end(r.raw)
        if e + 0x39 > len(r.raw):
            continue
        tg = _u32(r.raw, e + 0x34)
        if not tg:
            continue                                    # not part of a take/comp group
        out.append({"idx": _u32(r.raw, 0x08), "take_group": tg,
                    "take_sub": _u32(r.raw, e + 0x38),
                    "region_mode": r.raw[e + 0x21],
                    "take_index": _u16(r.raw, e + 0x30)})
    return out


# --- §20 / §8.5 qSvE : MIDI note content -------------------------------------
def midi_notes(pd) -> list:
    """MIDI note content of every note-bearing region (§8.5 / §20). Finds each role-0x17
    `qSvE` (classId@0x06 = 0x17) whose payload is a `90 00 00 00` note-event array and
    decodes it. Returns [{idx, notes}], notes = [(tick, pitch, velocity, length)],
    tick region-relative at 960 PPQ. Pairs with ProjectData.build_note_qsve_payload."""
    from .projectdata import ProjectData
    out = []
    for r in pd.records:
        if r.tag != b"qSvE" or _u16(r.raw, 0x06) != 0x17:
            continue
        ps = _u32(r.raw, 0x1c) or 0
        if r.raw[0x24:0x28] != b"\x90\x00\x00\x00":     # payload must start with a note event
            continue
        notes = [(t, p, v, ln) for (t, p, v, ln, _flag, _fine) in ProjectData.decode_note_events(r.raw)]
        if notes:
            out.append({"idx": _u32(r.raw, 0x08), "notes": notes})
    return out


# --- §36 qSvE : general typed-event decode (notes + CC/automation/lanes) -----
_QSVE_TAIL = bytes.fromhex("f1000000ffffff3f0000000000000000")
_EVENT_TYPE = {0x90: "note", 0x80: "note_off", 0xA0: "poly_at", 0xB0: "cc",
               0xD0: "chan_pressure", 0xE0: "pitch_bend", 0x20: "midi_region", 0x24: "audio_region"}


def _event_size(body, i):
    """Event size per the §36 stride table, or None if unknown (sysex 0xF0 / unrecognized)."""
    st = body[i]
    if (st & 0xF0) == 0x90:                                # note (any channel)
        n, j = 32, i + 32                                 # word0 + word1 (0x89 core)
        while j + 16 <= len(body) and body[j + 0x07] in (0xa3, 0xa4, 0xa7):
            n, j = n + 16, j + 16                          # extended-note extension words
        return n
    if st in (0x20, 0x24):
        return 80
    if (st & 0xF0) in (0x80, 0xA0, 0xB0, 0xD0, 0xE0) or 0x50 <= st <= 0x57:
        return 16
    return None                                           # sysex 0xF0 etc.: variable, unhandled


def region_events(pd) -> list:
    """Decode the typed events of every role-0x17 `qSvE` via the §36 stride table. Returns
    [{idx, complete, events}] where events = [{type, status, channel, pos, data1, data2}]
    (pos region-relative @960 PPQ). `complete` is False if the walk hit an extended note or
    unknown stride (the events up to that point are still returned). Empty regions are omitted."""
    out = []
    for r in pd.records:
        if r.tag != b"qSvE" or _u16(r.raw, 0x06) != 0x17:
            continue
        ps = _u32(r.raw, 0x1c) or 0
        body = r.raw[0x24:0x24 + ps]
        if len(body) <= 16 or body[:16] == _QSVE_TAIL:
            continue
        evs, i, complete = [], 0, True
        while i < len(body):
            if body[i:i + 16] == _QSVE_TAIL:
                break
            sz = _event_size(body, i)
            if sz is None or i + sz > len(body):
                complete = False
                break
            st = body[i]
            lane = 0x50 <= st <= 0x57
            evs.append({"type": "lane" if lane else _EVENT_TYPE.get(st & 0xF0, "?"),
                        "status": st, "channel": st & 0x0F if not lane else None,
                        "pos": _u32(body, i + 0x04) - 38400,
                        "data1": body[i + 0x0c], "data2": body[i + 0x0b]})
            i += sz
        if evs:
            out.append({"idx": _u32(r.raw, 0x08), "complete": complete, "events": evs})
    return out


# --- misc --------------------------------------------------------------------
def tag_census(pd) -> dict:
    """{tag(str): count} over all records."""
    c = Counter(r.tag.decode("latin-1") for r in pd.records)
    return dict(c.most_common())


def _load(path):
    """Accept a `.logicx` bundle dir, an `Alternatives/000` dir, or a raw ProjectData file."""
    from pathlib import Path
    from .projectdata import ProjectData
    p = Path(path)
    if p.is_dir():
        cand = p / "Alternatives" / "000" / "ProjectData"
        p = cand if cand.exists() else (p / "ProjectData" if (p / "ProjectData").exists() else p)
    return ProjectData.parse(p.read_bytes())


def dump(pd) -> None:
    """Print a human-readable summary of everything the decoders can read."""
    si = song_info(pd)
    print(f"song: schema={si.get('schema')} headerForm={si.get('headerForm')} "
          f"initial_bpm={si.get('initial_bpm')} records={si.get('n_records')}")
    cen = tag_census(pd)
    print("tags: " + ", ".join(f"{k}:{v}" for k, v in list(cen.items())[:12]))
    ports = coremidi_ports(pd)
    print(f"\ncoremidi ports ({len(ports)}):")
    for p in ports[:12]:
        print(f"  [{p['direction']:3}] {p['endpoint'] or '-':<24} {p['device']}  uid={p['uid']:#010x}")
    strips = mixer_strips(pd)
    by_type = Counter(m["type"] for m in strips)
    print(f"\nmixer strips ({len(strips)}): {dict(by_type)}")
    for m in strips[:10]:
        print(f"  {m['type']:<7} {m['name']:<16} fader={m['fader']:>3} pan={m['pan']:>3}")
    trk = tracks(pd)
    print(f"\ntracks ({len(trk)} populated):")
    for t in trk[:10]:
        print(f"  rowType={t.get('row_type')} ch={t.get('channel_slot')} uuid={t.get('uuid','')[:12]}")
    env = [e for e in environment(pd) if e["name"]]
    print(f"\nenvironment ({len(env)} named): " + ", ".join(f"{e['name']}[{e['kind_name']}]" for e in env[:10]))
    pool = audio_pool(pd)
    print(f"\naudio pool ({len(pool)}): " + ", ".join(str(e["name"]) for e in pool[:16]))
    afs = audio_files(pd)
    print(f"\naudio files ({len(afs)}):")
    for a in afs[:8]:
        print(f"  #{a['audio_file_id']} {a['container']}/{a['compression']:<4} "
              f"{a['sample_rate']}Hz {a['bits']}bit ch{a['channels']} {a['frames']}fr  {a['name'] or a['folder'][:40]}")
    plg = plugins(pd)
    print(f"\nplugins ({len(plg)}):")
    for pl in plg[:12]:
        ident = "native" if pl["native"] else f"AU {pl['au_type']}/{pl['au_subtype']}/{pl['au_manufacturer']}"
        print(f"  strip{pl['strip']:>4} slot{pl['slot']:>2}  {pl['name']:<14} {ident}")
    cab = environment_cables(pd)
    wired = [c for c in cab if c["cables"]]
    print(f"\nenvironment cables ({len(wired)} wired of {len(cab)} objects): " +
          ", ".join(f"{c['slot']}→{c['cables']}" for c in wired[:8]))
    takes = region_takes(pd)
    if takes:
        from collections import Counter as _C
        grp = _C(t["take_group"] for t in takes)
        print(f"\nregion takes ({len(takes)} regions in {len(grp)} groups)")
    notes = midi_notes(pd)
    print(f"\nmidi note regions ({len(notes)}): " +
          ", ".join(f"idx{r['idx']:#x}:{len(r['notes'])}notes" for r in notes[:10]))
    mv = movie_ref(pd)
    if mv:
        print(f"\nmovie: {mv['path']}")


def main(argv=None):
    import sys
    argv = argv or sys.argv[1:]
    if not argv:
        print("usage: python3.12 -m logicx.inspect <session.logicx | ProjectData>")
        return 1
    dump(_load(argv[0]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
