#!/usr/bin/env python3.12
"""Validate activate_audio_track's CORE against real `2 from 64` (modulo ids).

Targeted checks on the load-bearing records (gnoS registry, the source+new ivnE,
the activated OCuA strip), masking only the freshly-generated id bytes. Plus a
census of the recency-order reindex records (expected to differ when skipped).
"""
import struct
from pathlib import Path
from collections import Counter
from logicx.projectdata import ProjectData, _u32, REC_HEADER_SIZE, REC_SIZE_OFF
import logicx.projectdata as st   # audio-track synthesis now lives in projectdata.py

FIX = Path(__file__).resolve().parent / "fixtures" / "lots of audio tracks"
PASS = 0


def ok(c, m):
    global PASS
    assert c, "FAIL " + m
    PASS += 1


def load(n):
    return ProjectData.parse((FIX / f"{n} from 64 audio tracks.logicx" / "Alternatives" / "000" / "ProjectData").read_bytes())


def ridx(raw):
    return _u32(raw, 0x08)


def diffs(a, b, mask=()):
    ms = set()
    for s, e in mask:
        ms.update(range(s, e))
    return [i for i in range(min(len(a), len(b))) if a[i] != b[i] and i not in ms]


syn = load(1)
ids = st.IdGen(seed=99)
new_idx = st.activate_audio_track(syn, ids=ids, reindex=False, drummer=False)
real = load(2)
cur_max = new_idx - st.SYNTH_IDX_STRIDE
slot = new_idx >> 16

synb = syn.serialize()
ok(ProjectData.parse(synb).serialize() == synb, "synth round-trips")
print(f"activated -> ivnE 0x{new_idx:06x} (slot 0x{slot:x}); synth {len(synb)} bytes, round-trips")

# --- gnoS: mask the Table1 row (16B), Table2 row (8B), Table3 rows (8B each) --
def gnos(pd):
    return next(r.raw for r in pd.records if r.tag == b"gnoS")
gs, gr = gnos(syn), gnos(real)
t1 = {idx: off for off, idx in st._synth_walk_rows(bytearray(gs), st.GNOS_T1_ROW0, st.GNOS_T1_STRIDE, 0, 4)}
t2 = {idx: off for off, idx in st._synth_walk_rows(bytearray(gs), st.GNOS_T2_ROW0, st.GNOS_T2_STRIDE, 8, 12)}
t3 = [off for off, ri in st._synth_walk_rows(bytearray(gs), st.GNOS_T3_ROW0, st.GNOS_T3_STRIDE, 8, 12, tag_val=0x17) if ri in (0x08, 0x0c)]
gmask = [(t1[slot] + 8, t1[slot] + 24), (t2[slot + 4], t2[slot + 4] + 8)] + [(o, o + 8) for o in t3]
gd = diffs(gs, gr, gmask)
ok(not gd, f"gnoS CORE clean (residuals: {[hex(x) for x in gd[:20]]})")
print(f"  gnoS: {'CLEAN' if not gd else str([hex(x) for x in gd])}")

# --- ivnE source + new (mask UUID @0x1eb) ------------------------------------
def envi(pd, idx):
    return next(r.raw for r in pd.records if r.tag == b"ivnE" and ridx(r.raw) == idx)
um = [(st.IVNE_UUID, st.IVNE_UUID + 16)]
sd = diffs(envi(syn, cur_max), envi(real, cur_max), um)
nd = diffs(envi(syn, new_idx), envi(real, new_idx), um)
ok(not sd, f"ivnE source clean (residuals {[hex(x) for x in sd[:20]]})")
ok(not nd, f"ivnE new clean (residuals {[hex(x) for x in nd[:20]]})")
print(f"  ivnE source: {'CLEAN' if not sd else sd}; new: {'CLEAN' if not nd else nd}")

# --- OCuA activated strip: find each by its UUID == new ivnE UUID -------------
chan = envi(syn, new_idx)[st.IVNE_UUID:st.IVNE_UUID + 16]
chan_r = envi(real, new_idx)[st.IVNE_UUID:st.IVNE_UUID + 16]
os_ = next((r.raw for r in syn.records if r.tag == b"OCuA" and r.raw[st.OCUA_UUID:st.OCUA_UUID + 16] == chan), None)
or_ = next((r.raw for r in real.records if r.tag == b"OCuA" and r.raw[st.OCUA_UUID:st.OCUA_UUID + 16] == chan_r), None)
ok(os_ is not None, "synth activated an OCuA strip (UUID linked to new ivnE)")
ok(or_ is not None, "real has the OCuA strip")
if os_ and or_:
    od = diffs(os_, or_, [(st.OCUA_UUID, st.OCUA_UUID + 16)])
    ok(not od, f"OCuA strip clean (residuals {[hex(x) for x in od[:20]]})")
    print(f"  OCuA strip: {'CLEAN' if not od else od}")

# --- new karT entry: compare by ordinal @0x12 (mask the 8-byte id) -----------
def new_kart(pd, T):
    rows = [r.raw for r in pd.records if r.tag == b"karT" and len(r.raw) == 93 and ridx(r.raw) == 0x040000]
    # the new one has [0x10:0x18]=ff ff <T-1> 00 00 00 02 00 and was last-added
    cand = [x for x in rows if x[0x10:0x12] == b"\xff\xff" and x[0x12] == (T - 1) & 0xff]
    return cand[-1] if cand else None
ks, kr = new_kart(syn, 1), new_kart(real, 2 - 1)
if ks and kr:
    kd = diffs(ks, kr, [(st.KART_ID16, st.KART_ID16 + 16)])
    print(f"  new karT: {'CLEAN' if not kd else [hex(x) for x in kd]}")

# --- reindex census ----------------------------------------------------------
ca = Counter((r.tag, r.raw) for r in syn.records)
cb = Counter((r.tag, r.raw) for r in real.records)
miss = Counter()
for (t, raw), c in (cb - ca).items():
    miss[t] += c
print(f"\nreindex census (real images not in synth, expected when reindex=False):")
for t in sorted(miss, key=lambda t: t):
    print(f"  {t.decode('latin1')[::-1]}: {miss[t]}")

print(f"\nOK — {PASS} core assertions passed" if PASS else "")
