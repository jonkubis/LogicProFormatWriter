#!/usr/bin/env python3
"""
re_probe.py — low-level reverse-engineering probe for Logic ProjectData.

Focused on cracking the *chunk framing*: every record appears to start with
the 6-byte magic `23 47 c0 ab d0 09`, followed by a header that contains a
little-endian length. Goal: confirm the length field and that frames tile /
nest to cover the whole file exactly.

Usage:
  re_probe.py frames <ProjectData>   # enumerate 2347c0ab frames + length test
  re_probe.py findlen <ProjectData>  # for each frame, brute-find the length field
"""
from __future__ import annotations
import struct
import sys
from pathlib import Path

MAGIC = bytes([0x23, 0x47, 0xC0, 0xAB])
MAGIC6 = bytes([0x23, 0x47, 0xC0, 0xAB, 0xD0, 0x09])

# ============================================================================
# DECODED FINDINGS (from fixtures/ differential analysis
# ----------------------------------------------------------------------------
# ROOT FRAME (offset 0): 24-byte header, then payload to EOF.
#   bytes 0..3   magic 2347c0ab
#   bytes 4..5   version code: D0 09  / CF 09
#                byte +4 varies by Logic version; +5 = 0x09 stable.
#   bytes 6..0xf  03 00 04 00 00 00 01 00 08 00  (stable)
#   bytes 0x10..0x13  uint32 LE LENGTH = filesize - 24   [VERIFIED all 9 fixtures]
#   bytes 0x14..0x17  00 00 00 00
#
# TEMPO (single value): uint32 LE = round(BPM * 10000).  120.0 -> 0x00124F80.
#   Authoritative copies (verified by F0->F1 120->137.5 diff): file offsets
#   0xAA, 0x102, 0x3BE (inside gnoS) + the tempo-track qSvE event at qSvE+0x34
#   (file 0x2E4E in F0). NOTE: 0xAE also holds 0x00124F80 in a 120 project but
#   is NOT tempo (unchanged in F1) — never blind-scan for the old value.
#
# TEMPO MAP (fully decoded from F9_tempometer, 4 events): the tempo-track qSvE
#   (header has +6 == 0x0003; first event's tempo at qSvE+0x34). Payload @ +0x24
#   = N x 32-byte TEMPO EVENT, then a 16-byte TAIL. payload_size(+0x1c) = 32N+16.
#     ev+0x00: 60 00 00 00              constant (event marker)
#     ev+0x04: uint64 LE position = 38400 + tick@960PPQ   (38400 = tempo origin)
#     ev+0x0c: 7f 00 00 [flag]          flag: 0x00 for the FIRST/initial event,
#                                       0x01 for explicit points (|0x80 = UI-selected)
#     ev+0x10: uint32 LE tempo (BPM*10000)
#     ev+0x14: 00 00 40 88              constant
#     ev+0x18: uint32 LE altpos         absolute-time cache (~ +2000/sec from
#                                       origin 7,200,000 = 1hr; tempo-derived,
#                                       Logic likely recomputes it on load)
#     ev+0x1c: 00 00 00 00
#   TAIL (16B): f1 00 00 00 ff ff ff 3f 00 00 00 00 00 00 00 00
#
# METER (time-signature) MAP: a signature qSvE grows +24 bytes per signature
#   change (located via F9_meter: 132->180 for +2 changes). Event layout TBD.
#
# POSITION/TIME UNIT: ticks at 960 PPQ => 3840 ticks per 4/4 bar. Confirmed by
#   F4(region@bar1)->F5(region@bar2): a qSvE+0x28 field 34560->38400 (+3840)
#   and a qeSM+0x11c field 0->3840 (+3840). Two conventions coexist:
#     - ABSOLUTE w/ origin offset: region bar N = 34560 + (N-1)*3840
#       (bar 1 sits at tick 34560 = 9 bars; Logic's internal time origin).
#     - ZERO-BASED: bar 1 = 0, bar 2 = 3840.
#   F2 tempo events use the absolute form (event+0x04 u64: bar1=38400).
#
# TRACK NAME: uint16 LE length + ASCII string, at qeSM(MIDISeq)+0x34, in the
#   track's main qeSM record. (Reference repos missed this: they looked near
#   karT; the name is in the paired qeSM.)
#
# ID/REFERENCE fields renumbered across saves: qeSM+0x2c and qSvE+0x0e.
# ============================================================================

# Known reversed-FourCC chunk tags (literal bytes as they appear in the file).
TAGS = {
    b"karT": "Track", b"qeSM": "MIDISeq", b"qSvE": "EventSeq", b"gRuA": "AudioRegion",
    b"tSxT": "TextStyle", b"LFUA": "AudioFileRef", b"lFuA": "AudioFileRef",
    b"PMOC": "Comp", b"MroC": "CoreMIDI", b"tSnI": "Instrument", b"snrT": "Transform",
    b"gnoS": "Song",
}


def u32le(b, o): return struct.unpack_from("<I", b, o)[0]
def u16le(b, o): return struct.unpack_from("<H", b, o)[0]


def all_magic_offsets(data: bytes):
    offs, i = [], 0
    while True:
        j = data.find(MAGIC, i)
        if j == -1:
            break
        offs.append(j)
        i = j + 1
    return offs


def ascii4(data, o):
    if o + 4 > len(data):
        return ""
    s = data[o:o + 4]
    return s.decode("latin-1") if all(0x20 <= c < 0x7f for c in s) else s.hex()


def cmd_frames(path: Path):
    data = path.read_bytes()
    n = len(data)
    offs = all_magic_offsets(data)
    print(f"file size      : {n:,}")
    print(f"2347c0ab count : {len(offs)}")
    has_d009 = sum(1 for o in offs if data[o:o + 6] == MAGIC6)
    print(f"...with d009   : {has_d009}/{len(offs)}")
    print("=" * 100)
    print(f"{'#':>4} {'offset':>10} {'hdr[4:24] (hex)':<42} {'len@0x10':>10} "
          f"{'end=o+0x18+len':>14} {'tag@0x18':>8}")
    print("-" * 100)
    magic_set = set(offs)
    for idx, o in enumerate(offs):
        hdr = data[o + 4:o + 24].hex()
        length = u32le(data, o + 0x10) if o + 0x14 <= n else -1
        end = o + 0x18 + length
        tag = ascii4(data, o + 0x18)
        # annotate what 'end' lands on
        if end == n:
            note = "EOF"
        elif end in magic_set:
            note = f"->magic#{offs.index(end)}"
        else:
            # nearest magic after 'end'
            nxt = next((x for x in offs if x >= end), None)
            note = f"~{end-nxt if nxt else 0:+d} to next" if nxt else "?"
        print(f"{idx:>4} {o:>10} {hdr:<42} {length:>10} {end:>14} {tag:>8}  {note}")


def cmd_findlen(path: Path):
    """For each frame, find any u32le in its header that points to the next frame/EOF."""
    data = path.read_bytes()
    n = len(data)
    offs = all_magic_offsets(data)
    boundaries = set(offs) | {n}
    print(f"{'#':>4} {'offset':>10}  candidate length fields (header_pos -> end target)")
    print("-" * 80)
    for idx, o in enumerate(offs):
        nxt = offs[idx + 1] if idx + 1 < len(offs) else n
        hits = []
        # scan header region o+4 .. o+0x28 for a u32le that lands on a boundary
        for hp in range(o + 4, min(o + 0x28, n - 4)):
            v = u32le(data, hp)
            for base_name, base in (("o", o), ("o+0x18", o + 0x18), ("hp+4", hp + 4)):
                if base + v in boundaries and 0 < v < n:
                    hits.append(f"[+0x{hp-o:02x}]={v} via {base_name}->{'EOF' if base+v==n else base+v}")
        tag = "".join(c if 32 <= ord(c) < 127 else "." for c in data[o+0x18:o+0x1c].decode("latin-1", "replace"))
        marker = f"next@{nxt}"
        print(f"{idx:>4} {o:>10}  {marker:<12} " + (" | ".join(hits[:4]) if hits else "(no header u32le hits boundary)"))


def all_tag_offsets(data: bytes):
    """All known FourCC tag offsets, sorted."""
    hits = []
    for tag in TAGS:
        i = 0
        while True:
            j = data.find(tag, i)
            if j == -1:
                break
            hits.append((j, tag))
            i = j + 1
    hits.sort()
    return hits


def cmd_tags(path: Path):
    """Dump byte context around each FourCC tag; test for a length field that
    reaches a later boundary (sibling tag / magic / EOF)."""
    data = path.read_bytes()
    n = len(data)
    tagoffs = all_tag_offsets(data)
    boundaries = sorted(set(o for o, _ in tagoffs) | set(all_magic_offsets(data)) | {n})
    bset = set(boundaries)
    print(f"file size {n:,}   tags {len(tagoffs)}")
    print("=" * 110)
    for idx, (o, tag) in enumerate(tagoffs):
        nxt = tagoffs[idx + 1][0] if idx + 1 < len(tagoffs) else n
        gap = nxt - o
        before = data[max(0, o - 8):o].hex()
        after = data[o + 4:o + 20].hex()
        # hunt for a u32 (LE & BE) near the tag that lands on a boundary via base o or o+4...
        hits = []
        for hp in range(o - 8, o + 24):
            if hp < 0 or hp + 4 > n:
                continue
            for endian, fn in (("LE", u32le), ("BE", lambda b, p: struct.unpack_from(">I", b, p)[0])):
                v = fn(data, hp)
                if 0 < v < n:
                    for bn, base in (("o", o), ("o+4", o + 4)):
                        if base + v in bset:
                            tgt = "EOF" if base + v == n else f"{base+v}"
                            hits.append(f"[{hp-o:+d}]{endian}={v}->{tgt}")
        print(f"{idx:>3} @{o:<8} {TAGS[tag]:<11} gap={gap:<7} "
              f"pre={before:<16} post={after}")
        if hits:
            print(f"       LENHITS: " + " | ".join(hits[:6]))


def _tag_index(data: bytes):
    """Return sorted [(offset, label)] of known tags, for annotating diffs."""
    return [(o, TAGS[t]) for o, t in all_tag_offsets(data)]


def _annot(idx, off):
    """Nearest preceding tag for an offset: 'Track+0x12' style."""
    prev = None
    for o, lbl in idx:
        if o <= off:
            prev = (o, lbl)
        else:
            break
    if prev is None:
        return f"@0x{off:x} (pre-tags)"
    return f"@0x{off:x} ={prev[1]}+0x{off-prev[0]:x}"


def segment(data: bytes):
    """Split file into records on known-tag and magic boundaries.
    Returns list of dicts: {off, end, label, bytes}."""
    bounds = set(o for o, _ in all_tag_offsets(data)) | set(all_magic_offsets(data))
    bounds = sorted(bounds | {0, len(data)})
    # label each boundary by what starts there
    def label_at(o):
        if data[o:o + 4] == MAGIC:
            return "MAGIC"
        for t in TAGS:
            if data[o:o + 4] == t:
                return TAGS[t]
        return "head" if o == 0 else "raw"
    segs = []
    for i in range(len(bounds) - 1):
        o, e = bounds[i], bounds[i + 1]
        segs.append({"off": o, "end": e, "label": label_at(o), "bytes": data[o:e]})
    return segs


def cmd_diff(a_path: Path, b_path: Path):
    import difflib
    A = a_path.read_bytes()
    B = b_path.read_bytes()
    sa, sb = segment(A), segment(B)
    keysA = [(s["label"], s["bytes"]) for s in sa]
    keysB = [(s["label"], s["bytes"]) for s in sb]
    sm = difflib.SequenceMatcher(None, keysA, keysB, autojunk=False)
    print(f"A={a_path.name} ({len(A):,}, {len(sa)} recs)   "
          f"B={b_path.name} ({len(B):,}, {len(sb)} recs)")
    print("=" * 110)
    eqrec = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            eqrec += i2 - i1
            continue
        print(f"\n### {tag.upper()}  A[recs {i1}:{i2}]  B[recs {j1}:{j2}]")
        if tag in ("replace", "delete"):
            for s in sa[i1:i2]:
                print(f"  A {s['label']:<12} @0x{s['off']:06x} ({len(s['bytes']):>5}B)  {s['bytes'][:24].hex()}")
        if tag in ("replace", "insert"):
            for s in sb[j1:j2]:
                print(f"  B {s['label']:<12} @0x{s['off']:06x} ({len(s['bytes']):>5}B)  {s['bytes'][:24].hex()}")
        # byte-level sub-diff for 1:1 same-label same-length replaces
        if tag == "replace" and (i2 - i1) == (j2 - j1):
            for s, t in zip(sa[i1:i2], sb[j1:j2]):
                if s["label"] == t["label"] and len(s["bytes"]) == len(t["bytes"]):
                    diffs = [(k, s["bytes"][k], t["bytes"][k])
                             for k in range(len(s["bytes"])) if s["bytes"][k] != t["bytes"][k]]
                    if diffs and len(diffs) <= 24:
                        ds = " ".join(f"+0x{k:x}:{a:02x}->{b:02x}" for k, a, b in diffs)
                        print(f"    {s['label']} byte-diffs ({len(diffs)}): {ds}")
    print("-" * 110)
    print(f"equal-records={eqrec}")


def cmd_region(path: Path, start_hex: str, length_hex: str = "0x80"):
    data = path.read_bytes()
    start = int(start_hex, 0)
    length = int(length_hex, 0)
    end = min(start + length, len(data))
    for off in range(start, end, 16):
        row = data[off:off + 16]
        hexs = " ".join(f"{b:02x}" for b in row)
        asci = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in row)
        print(f"0x{off:06x}  {hexs:<47}  {asci}")


def main(argv=None):
    argv = argv or sys.argv[1:]
    if len(argv) < 2:
        print(__doc__)
        return 1
    cmd = argv[0]
    if cmd == "diff":
        return cmd_diff(Path(argv[1]), Path(argv[2]))
    if cmd == "region":
        return cmd_region(Path(argv[1]), argv[2], argv[3] if len(argv) > 3 else "0x80")
    target = Path(argv[1])
    {"frames": cmd_frames, "findlen": cmd_findlen, "tags": cmd_tags}[cmd](target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
