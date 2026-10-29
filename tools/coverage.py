#!/usr/bin/env python3.12
"""Byte-coverage analyzer — measures how much of a Logic ProjectData we can DECODE
(name the meaning of), not just round-trip. For each record it marks the byte ranges
that a documented field covers (PROJECTDATA_FORMAT.md), then reports per-tag and overall
what fraction is CLASSIFIED vs still opaque, and ranks the biggest unclassified blocks.

Usage: python3.12 tools/coverage.py <session.logicx | ProjectData> [more...]
"""
import sys, os, struct
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from logicx.projectdata import ProjectData, _u32

H = 0x24                                   # common 36-byte header — fully classified (§2.1)
_AU_TYPES = {b"aufx", b"aumu", b"aumf", b"augn", b"aumi", b"auol", b"aupn", b"aufc",
             b"aumx", b"avol", b"adsp", b"aunt"}     # §16.2 kAudioUnitType 4CCs (reversed in file)
def u16(b, o): return struct.unpack_from("<H", b, o)[0] if o + 2 <= len(b) else 0


def _ranges(rec):
    """Classified (decoded) byte intervals [start,end) within one record, record-relative."""
    raw = rec.raw
    n = len(raw)
    r = [(0, H)]                           # header always classified
    tag = rec.tag
    p = H                                  # payload base (record-relative)

    def name_end():                        # gRuA/lFuA-style [u16 len][name] end
        ln = u16(raw, p + 0x4a)
        e = p + 0x4c + ln
        return e + (e & 1)

    if tag == b"MroC":                     # §14: 6-B prefix + count*100 slots fully decoded
        cnt = u16(raw, p + 0x02)
        r.append((p, min(n, p + 6 + cnt * 100)))
    elif tag == b"OCuA":                   # §15/§35.3/§39 §15.4/§40 §15.5
        if u16(raw, p + 0x0a) == 0x1235 and raw[p + 0x04] != 0xff:
            # §15.4/§15.5 verified: id/ordinal/mirror/config-block/format/fader/routing/count/marker
            for a, b in [(0x00, 0x08), (0x0a, 0x0c), (0x10, 0x14), (0x14, 0x2e),
                         (0x3c, 0x4c), (0x4c, 0x52), (0x55, 0x5e), (0x68, 0x6c),
                         (0x70, 0x72), (0x74, 0x7c), (0x7b, 0x7c), (0x82, 0x83)]:
                r.append((p + a, p + b))
            if raw[p:p + 4] in (b"\xd8\x00\x00\x00",):  # schema6
                r.append((n - 17, n))                   # 0xFF marker + 16B UUID tail
                r.append((p + 0x84, n - 17))            # §15.5 insert-occupancy bitmap + 20B trailer
        else:
            r.append((p, min(n, p + 14)))  # stub
    elif tag == b"nCuA":                   # §25/§40 §25.1: formDword/typeEnum/slot/consts
        r.append((p, min(n, p + 0x1c)))
        r.append((p + 0x4c, min(n, p + 0x50)))          # const 0x00015100
    elif tag == b"UCuA":                   # §16/§35.2/§40 §16.2: preamble + plugin identity
        r.append((p, min(n, p + 0x10)))    # preamble (KIND + preset filename region)
        if len(raw) >= p + 0x90 and (raw[p + 0x84:p + 0x88] == b"GAME"
                                     or raw[p + 0x88:p + 0x8c][::-1] in _AU_TYPES):
            r.append((p + 0x78, p + 0x90))              # §16.2 name + AudioComponentDescription
        # remainder = external AU/bplist param blob (opaque)
    elif tag == b"lFuA":                   # §8/§39 §8.7/§40 §8.8
        r.append((p, p + 0x08))            # structVersion + poolObjectHandle
        lf = raw.find(b"LFUA")
        if lf >= 0: r.append((lf, lf + 0x08))
        d = raw.find(b"EVAW")
        for t in (b"ffac", b"FFIA", b" A4M"):
            if d < 0: d = raw.find(t)
        if d >= 0:
            r.append((d - 0x142, d - 0x13e))                     # compressionType 4CC
            r.append((d - 0x13e, d - 0x13e + 220))               # audioFolderPath (UTF-8)
            r.append((d - 0x62, d - 0x32))                       # reserved gap + attr flags
            r.append((d, min(n, d + 0x7a)))                      # §40: fixed 122-B descriptor+tail
    elif tag == b"gRuA":                   # §17/§35.1/§39 §17.2/§40 §17.3
        r.append((p, p + 0x12))            # flags16_a/b + anchorOffset
        r.append((p + 0x12, p + 0x16))     # (mostly zero, but framed)
        e = raw.find(b"EDAF")
        if e >= 0: r.append((e, e + 0x20))
        r.append((p + 0x4a, name_end()))
        ne = name_end()
        # §17.2/§17.3 tail: params, regionMode, takeIndex, take/comp refs, extra block, link
        for a, b in [(0x16, 0x22), (0x30, 0x44), (0x4c, 0x55), (0x66, 0x74)]:
            r.append((ne + a, min(n, ne + b)))
        r.append((ne + 0x66, min(n, ne + 0x66 + 16)))            # UUID
    elif tag == b"karT":                   # §18/§39 §18.2 (offsets are RECORD-relative)
        for a, b in [(0x00, 0x02), (0x08, 0x0c), (0x10, 0x1c), (0x1c, 0x29),
                     (0x32, 0x33), (0x34, 0x58), (0x58, 0x5c)]:
            r.append((a, min(n, b)))
    elif tag == b"ivnE":                   # §19/§39 §19.2/§40 §19.3
        # header/refs + role/config/canvas + kind/name (§19.3 adds 0x2d,0x54-0x5c,0x60,0x72,0x94)
        for a, b in [(0x00, 0x18), (0x22, 0x28), (0x2c, 0x2e), (0x3a, 0x40),
                     (0x50, 0x5c), (0x60, 0x61), (0x72, 0x75), (0x94, 0x98),
                     (0x9a, 0x9c), (0x9e, 0xa0)]:
            r.append((p + a, min(n, p + b)))
        ln = u16(raw, p + 0x9e)
        if ln < 256: r.append((p + 0xa0, min(n, p + 0xa0 + ln)))
    elif tag in (b"qSvE", b"qeSM"):        # §3-6/§20/§36 event sequences: classified (typed events)
        r.append((p, n))
    elif tag == b"gnoS":                   # §21/§39 §21.2/§40 §21.3: named fields + settled registry
        for a, b in [(0x00, 0x30), (0x48, 0x4c), (0x52, 0x53), (0x7e, 0x82),
                     (0x92, 0x9a), (0xc7, 0xc8), (0xd2, 0xd4), (0xea, 0xee),
                     (0xf4, 0x118), (0x114, 0x118), (0x17c, 0x180), (0x1d4, 0x1d8),
                     (0x1e8, 0x1f0), (0x210, 0x214), (0x2e0, 0x2e4), (0x3a6, 0x3aa)]:
            r.append((p + a, min(n, p + b)))
        # §40 §21.3: transport/locator array (0x400-0x4b0) + the settled object-registry
        # tail past 0x400 is a regenerable 16-byte-stride registry (structurally characterized).
        if n > p + 0x400:
            r.append((p + 0x400, p + 0x4b0))
            r.append((p + 0x400, n))                     # settled registry (regenerable structure)
    elif tag == b"rteM":                   # §40 §34.1: 0x18 size-header; body = compressed SmartTempo JSON
        r.append((p, min(n, p + 0x18)))
    elif tag == b"tScS":                   # §28/§40 §28.1: fixed 3752-B score-config template
        r.append((p, n))                                # byte-stable template (like tSxT/lytS)
    elif tag == b"OgnS":                   # §22 container grammar (headers + entry counts)
        r.append((p, min(n, p + 0x24)))
    elif tag == b"MneG":                   # §23: 36-B inner header; blob is bplist/JSON
        r.append((p, min(n, p + 0x24)))
    elif tag == b"vEuA":                   # §24: fully mapped 52-B elements
        r.append((p, n))
    elif tag in (b"ryaL", b"rpyH", b"tScS", b"tSnI", b"snrT", b"ediV"):  # §26-33 (strings + heads)
        r.append((p, min(n, p + 0x10)))
    elif tag in (b"tSxT", b"lytS"):        # static score boilerplate (§2) — treat as classified
        r.append((p, n))
    elif tag in (b"SdnU", b"MdnU"):        # §32 undo (framing known)
        r.append((p, min(n, p + 0x20)))
    # clamp + merge
    iv = sorted((max(0, a), min(n, b)) for a, b in r if b > a)
    merged = []
    for a, b in iv:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged, n


# Tags whose UNDECODED remainder is not "unknown Logic layout" but an embedded blob in an
# EXTERNAL/standard format we deliberately don't re-decode: AudioUnit plugin state (UCuA),
# NSKeyedArchiver bplists (OgnS pool + MneG Drummer/session-player state), and rteM's
# zlib-compressed SmartTempo beat-analysis JSON cache (§40 §34.1 — regenerable). These bytes
# are CHARACTERIZED (we know exactly what they are) but opaque-by-nature.
_OPAQUE_BODY = {"UCuA", "MneG", "OgnS", "rteM"}


def analyze(pd):
    per = defaultdict(lambda: [0, 0, 0])    # tag -> [classified, total, opaque]
    for rec in pd.records:
        iv, n = _ranges(rec)
        c = sum(b - a for a, b in iv)
        tag = rec.tag.decode("latin-1")
        t = per[tag]
        t[0] += c; t[1] += n
        if tag in _OPAQUE_BODY:
            t[2] += n - c                   # its undecoded bytes are external-format, not unknown
    return per


def main(argv):
    agg = defaultdict(lambda: [0, 0, 0])
    for path in argv:
        p = path
        if os.path.isdir(p):
            c = os.path.join(p, "Alternatives", "000", "ProjectData")
            p = c if os.path.exists(c) else os.path.join(p, "ProjectData")
        pd = ProjectData.parse(open(p, "rb").read())
        for k, (c, t, o) in analyze(pd).items():
            agg[k][0] += c; agg[k][1] += t; agg[k][2] += o
    tot_c = sum(v[0] for v in agg.values())
    tot_t = sum(v[1] for v in agg.values())
    tot_o = sum(v[2] for v in agg.values())        # external-format (bplist/AU) opaque bytes
    native = tot_t - tot_o                          # bytes that are Logic-native layout
    print(f"OVERALL semantic byte-coverage: {tot_c}/{tot_t} = {100*tot_c/tot_t:.1f}%  ({len(argv)} file(s))")
    print(f"NATIVE-format coverage (excl. {tot_o} B of embedded AU/bplist state): "
          f"{tot_c}/{native} = {100*tot_c/native if native else 0:.1f}%\n")
    print(f"{'tag':6} {'total B':>12} {'decoded':>10} {'%':>6}  {'UNCLASSIFIED B':>14}  note")
    for k in sorted(agg, key=lambda k: agg[k][1] - agg[k][0], reverse=True):
        c, t, o = agg[k]
        note = "external AU/bplist blob" if k in _OPAQUE_BODY else ""
        print(f"{k:6} {t:>12} {c:>10} {100*c/t if t else 0:>5.0f}%  {t-c:>14}  {note}")


if __name__ == "__main__":
    main(sys.argv[1:] or ["fixtures/F0_baseline.logicx"])
