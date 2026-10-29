#!/usr/bin/env python3.12
"""Record-level diff of two ProjectData files — the workbench for control-session RE.

Records are matched by identity key (tag, idx@0x08, ordinal@0x0c, classId@0x06) plus an
occurrence counter for duplicates. Reports ADDED / REMOVED records and, for CHANGED ones,
every differing byte run (record-relative offsets, payload base 0x24). qSvE payloads are
additionally decoded into 80-byte placements / 16-byte events so sequence edits are legible.

Usage:
    python3.12 tools/altdiff.py A.logicx B.logicx          # Alternatives/000 of each
    python3.12 tools/altdiff.py TAKES.logicx:000 TAKES.logicx:001
    python3.12 tools/altdiff.py A/ProjectData B/ProjectData [--full]
"""
import os
import struct
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from logicx.projectdata import ProjectData  # noqa: E402


def u16(b, o): return struct.unpack_from("<H", b, o)[0] if o + 2 <= len(b) else None
def u32(b, o): return struct.unpack_from("<I", b, o)[0] if o + 4 <= len(b) else None


def load(spec):
    """'X.logicx' | 'X.logicx:NNN' | path/to/ProjectData -> (label, ProjectData)."""
    path, alt = spec, "000"
    if ":" in os.path.basename(spec):
        path, alt = spec.rsplit(":", 1)
    if os.path.isdir(path):
        path = os.path.join(path, "Alternatives", alt, "ProjectData")
    return spec, ProjectData.parse(open(path, "rb").read())


def key(r):
    return (r.tag.decode("latin-1"), u32(r.raw, 0x08), u32(r.raw, 0x0c), u16(r.raw, 0x06))


def keyed(pd):
    seen = defaultdict(int)
    out = {}
    for i, r in enumerate(pd.records):
        k = key(r)
        out[k + (seen[k],)] = (i, r)
        seen[k] += 1
    return out


def runs(a, b):
    """Differing byte runs between a and b, over the common prefix + a length tail note."""
    out, n, i = [], min(len(a), len(b)), 0
    while i < n:
        if a[i] != b[i]:
            j = i
            while j < n and a[j] != b[j]:
                j += 1
            out.append((i, j))
            i = j
        else:
            i += 1
    return out


def fmt_key(k):
    tag, idx, ordv, cls, dup = k
    return (f"{tag} idx={idx:#010x}(>>18={idx >> 18}) ord={ordv:#010x}(>>16={ordv >> 16}) "
            f"cls={cls:#06x}" + (f" #{dup}" if dup else ""))


def qsve_events(raw):
    """Decode a qSvE payload into events: 80-B placements (0x20/0x24) and 16-B others."""
    ps = u32(raw, 0x1c) or 0
    bd = raw[0x24:0x24 + ps]
    evs, o = [], 0
    while o + 16 <= len(bd):
        st = bd[o]
        if st in (0x20, 0x24) and bd[o + 1:o + 4] == b"\0\0\0" and o + 0x50 <= len(bd):
            evs.append((o, 0x50, bd[o:o + 0x50]))
            o += 0x50
        else:
            evs.append((o, 16, bd[o:o + 16]))
            o += 16
    return evs


def describe_placement(ev):
    return (f"st={ev[0]:#04x} pos={u32(ev, 4)}(tick {u32(ev, 4) - 34560}) +08={u32(ev, 8):#x} "
            f"+0c={u32(ev, 0x0c):#x} +10={u32(ev, 0x10):#x} trk={ev[0x14]} +18={u32(ev, 0x18):#x} "
            f"+20={u32(ev, 0x20):#x} k@28={u32(ev, 0x28)} file@2c={u32(ev, 0x2c) // 4} "
            f"+30={u32(ev, 0x30):#x} +34={u32(ev, 0x34):#x} +38={u32(ev, 0x38):#x} "
            f"+3c={u32(ev, 0x3c):#x} +40={u32(ev, 0x40):#x} +44={u32(ev, 0x44):#x} +48={u32(ev, 0x48):#x}")


def dump_qsve(raw, indent="      "):
    for o, n, ev in qsve_events(raw):
        if n == 0x50:
            print(f"{indent}@{o:#06x} PLACE {describe_placement(ev)}")
        else:
            print(f"{indent}@{o:#06x} {ev.hex(' ')}")


def main(argv):
    full = "--full" in argv
    a_spec, b_spec = [x for x in argv if not x.startswith("--")][:2]
    la, A = load(a_spec)
    lb, B = load(b_spec)
    ka, kb = keyed(A), keyed(B)
    print(f"A = {la}  ({len(A.records)} records)\nB = {lb}  ({len(B.records)} records)\n")
    added = [k for k in kb if k not in ka]
    removed = [k for k in ka if k not in kb]
    changed = [k for k in kb if k in ka and ka[k][1].raw != kb[k][1].raw]
    print(f"ADDED {len(added)}  REMOVED {len(removed)}  CHANGED {len(changed)}\n")
    for k in added:
        i, r = kb[k]
        print(f"+ [{i}] {fmt_key(k)} size={len(r.raw)}")
        if r.tag == b"qSvE":
            dump_qsve(r.raw)
        elif full or len(r.raw) <= 0x24 + 0x200:
            pay = r.raw[0x24:]
            for o in range(0, len(pay), 16):
                print(f"      pay+{o:#05x}: {pay[o:o + 16].hex(' ')}")
    for k in removed:
        i, r = ka[k]
        print(f"- [{i}] {fmt_key(k)} size={len(r.raw)}")
        if r.tag == b"qSvE":
            dump_qsve(r.raw)
    for k in changed:
        (ia, ra), (ib, rb) = ka[k], kb[k]
        a, b = ra.raw, rb.raw
        print(f"~ [{ia}->{ib}] {fmt_key(k)} size {len(a)}->{len(b)}")
        if ra.tag == b"qSvE":
            print("    A:"); dump_qsve(a)
            print("    B:"); dump_qsve(b)
            continue
        rr = runs(a, b)
        for s, e in rr[:40]:
            rel = f"pay+{s - 0x24:#05x}" if s >= 0x24 else f"hdr+{s:#04x}"
            print(f"    {rel} [{e - s}B]  {a[s:e][:24].hex(' ')}  ->  {b[s:e][:24].hex(' ')}")
        if len(rr) > 40:
            print(f"    ... {len(rr) - 40} more runs")
        if len(a) != len(b):
            print(f"    (length differs by {len(b) - len(a):+d}; runs above cover the common prefix)")


if __name__ == "__main__":
    main(sys.argv[1:])
