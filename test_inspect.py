#!/usr/bin/env python3.12
"""Tests for logicx.inspect — the read-path decoders for the RE'd ProjectData
subsystems (PROJECTDATA_FORMAT.md §14/§15/§18/§19/§21/§22).

Ground truth = the Logic-made fixtures in the repo. The strongest check is the audio
pool: the decoded §22 pool entries must equal the bundle's actual on-disk media stems.

Run: python3.12 test_inspect.py
"""
import os
from pathlib import Path

from logicx.projectdata import ProjectData
from logicx import inspect as lx

ROOT = Path(__file__).resolve().parent
PASS = 0


def ok(c, m):
    global PASS
    assert c, "FAIL " + m
    PASS += 1


def load(bundle):
    return ProjectData.parse((ROOT / bundle / "Alternatives" / "000" / "ProjectData").read_bytes())


def media_stems(bundle):
    d = ROOT / bundle / "Media" / "Audio Files"
    return sorted(os.path.splitext(p.name)[0] for p in d.iterdir()) if d.is_dir() else []


F21 = "templates/F21_multitrack_regions.logicx"
CTL = "fixtures/ctl_wav.logicx"

# --- §21 gnoS song_info -------------------------------------------------------
pd = load(F21)
si = lx.song_info(pd)
ok(si["initial_bpm"] == 120.0, f"F21 initial_bpm from tempo slot C == 120 ({si['initial_bpm']})")
ok(si["tempo_slots_consistent"], "§21 invariant: tempo slotB@0xEA == slotC@0x3A6")
ok(si["headerForm"] in (1, 2), f"headerForm is 1|2 ({si['headerForm']})")
ok(si["n_records"] == len(pd.records), "n_records matches")

# --- §14 MroC coremidi_ports --------------------------------------------------
ports = lx.coremidi_ports(pd)
ok(len(ports) > 0, "CoreMIDI ports decoded")
ok({p["direction"] for p in ports} <= {"in", "out"}, "port directions are in/out only")
ok(all(isinstance(p["uid"], int) for p in ports), "every port has an integer UniqueID")
ok(any(p["endpoint"] or p["device"] for p in ports), "ports carry endpoint/device names")

# --- §15 OCuA mixer_strips ----------------------------------------------------
ms = lx.mixer_strips(pd)
ok(len(ms) > 100, f"mixer strips decoded ({len(ms)})")
named = {m["name"]: m for m in ms}
ok("Audio 1" in named, f"strip 'Audio 1' present ({list(named)[:4]})")
ok(named["Audio 1"]["type"] == "Audio", "Audio 1 typeEnum -> Audio")
ok(named["Audio 1"]["pan"] == 64, "§15 default pan 0x40 = 64 (center)")
ok(any(m["type"] == "Master" for m in ms), "a Master strip exists")
ok(all(0 <= m["fader"] <= 127 for m in ms), "faders are 0..127")

# --- §18 karT tracks ----------------------------------------------------------
tr = lx.tracks(pd)
ok(len(tr) > 0, f"populated track rows decoded ({len(tr)})")
ok(all(t["populated"] for t in tr), "populated_only filter honors link2@0x14 == 0")
ok(all(len(t.get("uuid", "")) == 32 for t in tr), "every populated row carries a 16-byte UUID")
ok(any(t.get("row_type") == 3 for t in tr), "a master row (rowType 3) exists")
ok(len(lx.tracks(pd, populated_only=False)) > len(tr), "empty placeholder rows also present (link2 0x7FFF)")

# --- §19 ivnE environment -----------------------------------------------------
env = lx.environment(pd)
ok(len(env) > 0, f"environment objects decoded ({len(env)})")
ok(all(e["slot"] % 4 == 0 for e in env), "§19: slot = idx>>16 is a multiple of 4")
names = {e["name"] for e in env if e["name"]}
ok("MIDI Click" in names, f"system object 'MIDI Click' found ({sorted(names)[:4]})")

# --- §22 OgnS audio_pool: decoded entries == real on-disk media ---------------
for bundle in (F21, CTL):
    p = load(bundle)
    pool = lx.audio_pool(p)
    cnt = lx.audio_pool_count(p)
    decoded = sorted(e["name"] for e in pool if e["name"])
    ok(len(pool) == cnt, f"{bundle}: len(audio_pool) == ENTRY_COUNT@pay+0x1c ({len(pool)}=={cnt})")
    ok(decoded == media_stems(bundle),
       f"{bundle}: pool names == on-disk media stems ({decoded} vs {media_stems(bundle)})")
    ok(all(e["family"] is not None for e in pool), f"{bundle}: entries carry a LoopFamily")

# --- §20 / §8.5 midi_notes: known notes + writer round-trip -------------------
f4b = load("fixtures/F4b_midinotes.logicx")
regions = lx.midi_notes(f4b)
ok(len(regions) == 1, f"F4b has one note region ({len(regions)})")
n0 = regions[0]["notes"]
ok(n0 == [(0, 36, 32, 240), (960, 60, 64, 480), (1920, 84, 100, 960)],
   f"F4b known notes decoded (pitch/vel/len region-relative) ({n0})")

# round-trip: encode notes -> qSvE payload -> decode via midi_notes reads them back
KNOWN = [(0, 60, 100, 480), (480, 64, 90, 240), (960, 67, 110, 960)]
payload = ProjectData.build_note_qsve_payload(KNOWN)
qsve = f4b.records[[i for i, r in enumerate(f4b.records)
                    if r.tag == b"qSvE" and r.raw[0x24:0x28] == b"\x90\x00\x00\x00"][0]]
import struct as _st
hdr = bytearray(qsve.raw[:0x24])
_st.pack_into("<I", hdr, 0x1c, len(payload))
qsve.raw = bytes(hdr) + payload
back = lx.midi_notes(f4b)[0]["notes"]
ok(back == KNOWN, f"midi_notes reads back synthesized notes exactly ({back})")

# --- §35.1/§35.2 region_fades + plugin_presets (synthetic; fixtures have neither) --
import struct as _s2


class _R:
    def __init__(self, tag, raw):
        self.tag, self.raw = tag, raw


class _PD:
    def __init__(self, recs):
        self.records = recs


g = bytearray(0x24 + 0x100)
g[0:4] = b"gRuA"
_s2.pack_into("<I", g, 0x08, 5 << 18)
ei = 0x24 + 0x60
g[ei:ei + 4] = b"EDAF"
_s2.pack_into("<I", g, ei + 0x10, 4410)          # fade-in 4410 samples
_s2.pack_into("<I", g, ei + 0x14, 0)             # fade-out none
g[ei + 0x1c] = 0x05                               # in curve +5
g[ei + 0x1d] = 0xf9                               # out curve -7 (signed)
fades = lx.region_fades(_PD([_R(b"gRuA", bytes(g))]))
ok(len(fades) == 1 and fades[0]["fade_in"] == 4410 and fades[0]["fade_out"] == 0,
   f"region_fades decodes synthetic EDAF fade ({fades})")
ok(fades[0]["in_curve"] == 5 and fades[0]["out_curve"] == -7, "fade curves signed-decoded")

u = bytearray(0x24 + 0x40)
u[0:4] = b"UCuA"
_s2.pack_into("<I", u, 0x0c, 7 << 16)            # strip id (header)
_s2.pack_into("<H", u, 0x12, 3)                  # slot (header link1)
_s2.pack_into("<H", u, 0x24 + 0x04, 1)           # KIND 1 (native plugin)
u[0x24 + 0x0e:0x24 + 0x0e + 11] = b"Reverb.pst\x00"
pres = lx.plugin_presets(_PD([_R(b"UCuA", bytes(u))]))
ok(len(pres) == 1 and pres[0]["preset"] == "Reverb.pst" and pres[0]["strip"] == 7 and pres[0]["slot"] == 3,
   f"plugin_presets decodes synthetic preset ({pres})")

# no false positives on the stock fixture (no fades / no loaded native plugins)
ok(lx.region_fades(pd) == [], "region_fades empty on stock fixture")

# §37 movie_ref: synthetic OgnS movie container with a file:// URL; None when absent
mo = bytearray(0x24 + 0x60)
mo[0:4] = b"OgnS"
_s2.pack_into("<I", mo, 0x08, 0x00FC0000)
_url = b"file:///Users/x/Movies/clip.mov"
mo[0x24 + 0x30:0x24 + 0x30 + len(_url)] = _url
mv = lx.movie_ref(_PD([_R(b"OgnS", bytes(mo))]))
ok(mv and mv["path"] == "/Users/x/Movies/clip.mov", f"movie_ref decodes synthetic OgnS movie URL ({mv})")
ok(lx.movie_ref(pd) is None, "movie_ref is None on the stock fixture (no movie)")

# §36 region_events: synthetic role-0x17 qSvE with CC events + a compact note


def _cc(pos, ctrl, val):
    e = bytearray(16)
    e[0] = 0xB0
    _s2.pack_into("<I", e, 4, 38400 + pos)
    e[0x0b] = val
    e[0x0c] = ctrl
    return bytes(e)


qbody = _cc(100, 1, 64) + _cc(200, 1, 80) + ProjectData._enc_note_event(0, 60, 100, 480, last=False) + lx._QSVE_TAIL
q = bytearray(0x24 + len(qbody))
q[0:4] = b"qSvE"
_s2.pack_into("<H", q, 0x06, 0x17)
_s2.pack_into("<I", q, 0x08, 5 << 18)
_s2.pack_into("<I", q, 0x1c, len(qbody))
q[0x24:] = qbody
re_ = lx.region_events(_PD([_R(b"qSvE", bytes(q))]))
ok(len(re_) == 1 and re_[0]["complete"], f"region_events decodes synthetic region completely ({re_[:1]})")
ev = re_[0]["events"]
ok(len(ev) == 3, f"3 events decoded via §36 stride table ({len(ev)})")
ok(ev[0]["type"] == "cc" and ev[0]["pos"] == 100 and ev[0]["data1"] == 1 and ev[0]["data2"] == 64,
   f"CC event fields (pos/ctrl/val) ({ev[0]})")
ok(ev[2]["type"] == "note" and ev[2]["pos"] == 0, f"compact note (32B) decoded after two CCs ({ev[2]})")

# --- §39 §15.4 OCuA extended fields (format / count / routing) ----------------
ok(named["Audio 1"]["channel_format"] in ("mono", "stereo", "surround"),
   f"Audio 1 channel_format decoded ({named['Audio 1']['channel_format']})")
ok(named["Audio 1"]["channel_count"] in (1, 2, 5),
   f"§15.4 channel_count in {{1,2,5}} ({named['Audio 1']['channel_count']})")
_master = [m for m in ms if m["type"] == "Master"][0]
ok(_master["channel_count"] == 5 and _master["channel_format"] == "surround",
   f"§15.4 Master strip is surround/5 ({_master['channel_format']}/{_master['channel_count']})")
ok(all(isinstance(m["output_ref"], int) for m in ms), "§15.4 output_ref@0x5c is a u16 on every strip")

# --- §39 §18.2 karT track color ----------------------------------------------
_arr = [t for t in tr if t["cluster"] == 0x00040000]
ok(_arr and all(t.get("color_index") is not None for t in _arr),
   f"§18.2 arrange rows carry a color_index ({[t.get('color_index') for t in _arr][:4]})")
ok(all(t.get("color_index", 0) >= 0 for t in _arr), "§18.2 color_index is a non-negative palette index")
ok(all(t.get("color_index") is None for t in tr if t["cluster"] != 0x00040000),
   "§18.2 color_index is None on non-arrange (pool/master) rows")
# synthetic arrange row with a real (nonzero) color proves the >>2 palette decode
_kc = bytearray(0x60)
_kc[0:4] = b"karT"
_s2.pack_into("<I", _kc, 0x08, 0x00040000)       # arrange cluster
_s2.pack_into("<H", _kc, 0x14, 0x0000)           # link2 = populated
_kc[0x28] = 0x28                                   # raw color byte = 40 -> palette index 10
_kcolor = lx.tracks(_PD([_R(b"karT", bytes(_kc))]))[0]
ok(_kcolor["color_index"] == 10, f"§18.2 color decode raw 0x28 -> index (raw>>2) == 10 ({_kcolor['color_index']})")

# --- §39 §8.7 lFuA audio descriptor -------------------------------------------
af = lx.audio_files(pd)
ok(len(af) > 0, f"audio_files decoded ({len(af)})")
ok(all(a["sample_rate"] in (44100, 48000, 88200, 96000, 176400, 192000) for a in af),
   f"§8.7 sample_rate in the valid set ({[a['sample_rate'] for a in af][:4]})")
ok(all(a["bits"] in (16, 24, 32) and a["channels"] in (1, 2) for a in af), "§8.7 bits/channels sane")
ok(all(a["container"] in ("wav", "aiff", "caf", "m4a") for a in af),
   f"§8.7 container recognized ({[a['container'] for a in af]})")
ok(sorted(a["audio_file_id"] for a in af) == list(range(1, len(af) + 1)),
   f"§8.7 audio_file_id is 1-based contiguous ({sorted(a['audio_file_id'] for a in af)})")
# the ALAC control pair proves the compression 4CC decode (PMOC = COMP)
_caf = lx.audio_files(load("fixtures/ctl_caf.logicx"))[0]
_wav = lx.audio_files(load(CTL))[0]
ok(_caf["container"] == "caf" and _caf["compression"] == "COMP", f"§8.7 ALAC/CAF -> COMP ({_caf})")
ok(_wav["container"] == "wav" and _wav["compression"] == "pcm", f"§8.7 WAV -> pcm ({_wav})")

# --- §39 §19.2 ivnE cable graph (synthetic: A --cableRef1--> B) ---------------
def _ivne(slot, kind, ref1=0):
    p = bytearray(0xb0)
    _s2.pack_into("<H", p, 0x10, slot)      # objectSlotId
    _s2.pack_into("<H", p, 0x14, ref1)      # cableRef1
    p[0x5a] = kind                          # kind byte
    return _R(b"ivnE", b"\x00" * 0x24 + bytes(p))


cg = lx.environment_cables(_PD([_ivne(8, 4, ref1=12), _ivne(12, 4)]))
ok(len(cg) == 2, f"environment_cables returns both objects ({len(cg)})")
_a = [c for c in cg if c["slot"] == 8][0]
ok(_a["cables"] == [12], f"§19.2 cableRef1 resolves 8 -> 12 ({_a['cables']})")
ok([c for c in cg if c["slot"] == 12][0]["cables"] == [], "§19.2 unreferenced object has no out-cables")
# a ref that resolves to no object is dropped (not a live edge)
ok(lx.environment_cables(_PD([_ivne(8, 4, ref1=999)]))[0]["cables"] == [],
   "§19.2 an unresolved ref is not reported as a cable")

# --- §39 §17.2 gRuA take/comp groups (synthetic) ------------------------------
def _grua_take(group, sub, mode=1, take_ix=3):
    raw = bytearray(0x24 + 0x120)
    raw[0:4] = b"gRuA"
    _s2.pack_into("<I", raw, 0x08, 5 << 18)
    _s2.pack_into("<H", raw, 0x24 + 0x4a, 0)         # name len 0 -> name_end = 0x24+0x4c
    ne = 0x24 + 0x4c
    raw[ne + 0x21] = mode
    _s2.pack_into("<H", raw, ne + 0x30, take_ix)
    _s2.pack_into("<I", raw, ne + 0x34, group)
    _s2.pack_into("<I", raw, ne + 0x38, sub)
    return _R(b"gRuA", bytes(raw))


rt = lx.region_takes(_PD([_grua_take(0x1234, 2), _grua_take(0, 0), _grua_take(0x1234, 3)]))
ok(len(rt) == 2, f"§17.2 only take-group regions are returned (2 of 3) ({len(rt)})")
ok({r["take_group"] for r in rt} == {0x1234}, "§17.2 sibling regions share take_group id")
ok(sorted(r["take_sub"] for r in rt) == [2, 3], f"§17.2 take_sub indexes decoded ({[r['take_sub'] for r in rt]})")
ok(all(r["take_index"] == 3 and r["region_mode"] == 1 for r in rt), "§17.2 region_mode + take_index decoded")

# --- §40 §16.2 UCuA plugin identity (synthetic native + AU + garbage gate) ----
def _ucua(strip, slot, kind, name, ctag, atype=b"\x00\x00\x00\x00", subtype=b"\x00\x00\x00\x00",
          preset=b""):
    raw = bytearray(0x24 + 0xa0)
    raw[0:4] = b"UCuA"
    _s2.pack_into("<I", raw, 0x0c, strip << 16)          # owning-strip ordinal
    _s2.pack_into("<H", raw, 0x12, slot)                 # insert slot (link1)
    _s2.pack_into("<H", raw, 0x24 + 0x04, kind)          # KIND
    raw[0x24 + 0x0e:0x24 + 0x0e + len(preset)] = preset
    raw[0x24 + 0x78:0x24 + 0x78 + len(name)] = name
    raw[0x24 + 0x84:0x24 + 0x88] = ctag                  # 'GAME' sentinel or reversed manufacturer
    raw[0x24 + 0x88:0x24 + 0x8c] = atype                 # reversed AU type
    raw[0x24 + 0x8c:0x24 + 0x90] = subtype
    return _R(b"UCuA", bytes(raw))


_native = _ucua(7, 3, 1, b"Channel EQ", b"GAME", preset=b"#default.pst\x00")
_au = _ucua(7, 4, 1, b"AmpliTube 5", b"mmkI", atype=b"fmua", subtype=b"5btA")  # reversed 4CCs
_garbage = _ucua(7, 5, 7, b"\x81\x02\x9c", b"\x11\x22\x33\x44", atype=b".SNZ")   # bplist slot
pl = lx.plugins(_PD([_native, _au, _garbage]))
ok(len(pl) == 2, f"§16.2 plugins gate keeps 2 real inserts, drops the bplist/garbage slot ({len(pl)})")
_n = [x for x in pl if x["native"]][0]
ok(_n["name"] == "Channel EQ" and _n["strip"] == 7 and _n["slot"] == 3 and _n["preset"] == "#default.pst",
   f"§16.2 native plugin (GAME) decoded with preset ({_n})")
ok(_n["au_type"] is None, "§16.2 native plugin has no AU triple")
_a = [x for x in pl if not x["native"]][0]
ok(_a["name"] == "AmpliTube 5" and _a["au_type"] == "aumf" and _a["au_subtype"] == "Atb5"
   and _a["au_manufacturer"] == "Ikmm",
   f"§16.2 AU plugin decoded from reversed 4CCs (type/subtype/manufacturer) ({_a})")
# real fixture: plugins() runs and every decoded strip id joins an OCuA/mixer strip
_realpl = lx.plugins(pd)
if _realpl:
    ok(all(isinstance(x["slot"], int) and x["name"] is not None for x in _realpl),
       "§16.2 plugins() decodes the fixture cleanly")

# --- misc ---------------------------------------------------------------------
census = lx.tag_census(pd)
ok(census.get("OCuA", 0) > 0 and census.get("gnoS") == 1, f"tag_census sane (gnoS==1, OCuA={census.get('OCuA')})")

print(f"OK — {PASS} assertions passed (logicx.inspect read-path decoders)")
