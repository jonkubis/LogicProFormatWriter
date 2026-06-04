#!/usr/bin/env python3.12
"""Proof tests for the MIDI note-event encoder/decoder (projectdata.py).

Run:  python3.12 test_midi_notes.py

The note encoder is a PURE function of (tick, pitch, velocity, length, last,
fine), so a faithful decode -> encode must reproduce the region qSvE payload
BYTE-FOR-BYTE — proven against F4b_midinotes (3 known notes) and F4c (same notes,
region dragged to bar 2). F4b vs F4c also proves note positions are
REGION-RELATIVE (identical note bytes; only the placement event moved).
"""
import struct
from pathlib import Path
from logicx.projectdata import ProjectData

ROOT = Path(__file__).resolve().parent
PASS = 0


def ok(cond, msg):
    global PASS
    assert cond, "FAIL " + msg
    PASS += 1


def load(name):
    return ProjectData.parse(next(ROOT.glob(f"**/{name}/Alternatives/000/ProjectData")).read_bytes())


def first_word(raw):
    return struct.unpack_from("<I", raw, 0x24)[0]


def find_qsve(pd, marker):
    for r in pd.records:
        if (r.tag == b"qSvE" and struct.unpack_from("<I", r.raw, 0x1c)[0] >= 8
                and first_word(r.raw) == marker):
            return r.raw
    return None


def payload(raw):
    return raw[0x24:0x24 + struct.unpack_from("<I", raw, 0x1c)[0]]


f4b, f4c = load("F4b_midinotes.logicx"), load("F4c_midinotes_bar2.logicx")
b_notes = find_qsve(f4b, 0x90)        # region qSvE carrying note events
c_notes = find_qsve(f4c, 0x90)
ok(b_notes is not None and c_notes is not None, "found note-bearing qSvE in F4b & F4c")

# 1) decode matches the drawn notes (tick, pitch, vel, length, flag, fine) -----
dec = ProjectData.decode_note_events(b_notes)
ok(dec == [(0, 36, 32, 240, 0x01, 0x5c),
           (960, 60, 64, 480, 0x01, 0xb8),
           (1920, 84, 100, 960, 0x81, 0xac)], f"F4b decoded notes: {dec}")

# 2) decode -> encode reproduces the region qSvE payload BYTE-FOR-BYTE ----------
for name, raw in [("F4b", b_notes), ("F4c", c_notes)]:
    notes = ProjectData.decode_note_events(raw)
    rebuilt = b"".join(
        ProjectData._enc_note_event(t, p, v, ln, last=bool(fl & 0x80), fine=fine)
        for (t, p, v, ln, fl, fine) in notes) + ProjectData.NOTE_QSVE_TAIL
    ok(rebuilt == payload(raw), f"{name} note qSvE reproduced byte-for-byte")

# 3) REGION-RELATIVE proof: F4b@bar1 and F4c@bar2 note bytes are IDENTICAL,
#    yet their placement events differ by exactly one bar (3840) ---------------
ok(payload(b_notes) == payload(c_notes), "F4b/F4c note qSvE identical (region-relative)")
pb, pc = find_qsve(f4b, 0x20), find_qsve(f4c, 0x20)      # placement events (0x20 marker)
posb = struct.unpack_from("<I", pb, 0x28)[0]
posc = struct.unpack_from("<I", pc, 0x28)[0]
ok((posb, posc) == (34560, 38400) and posc - posb == 3840,
   f"placement moved one bar: {posb} -> {posc}")

# 4) build_note_qsve_payload(fine=0) matches EXCEPT the +0x0a fine-velocity byte
notes4 = [(t, p, v, ln) for (t, p, v, ln, _f, _fine) in ProjectData.decode_note_events(b_notes)]
built = ProjectData.build_note_qsve_payload(notes4)
orig = payload(b_notes)
ok(len(built) == len(orig), "build_note_qsve_payload length matches")
diffs = [i for i in range(len(orig)) if orig[i] != built[i]]
expect = [k * 0x20 + 0x0a for k in range(3)]             # +0x0a of each of 3 events
ok(diffs == expect, f"fine=0 build differs ONLY at +0x0a of each note: {[hex(d) for d in diffs]}")

# 5) decode is stable on a freshly-built (fine=0) payload ----------------------
hdr = bytearray(b_notes[:0x24])
struct.pack_into("<I", hdr, 0x1c, len(built))
synth = bytes(hdr) + built
ok([(t, p, v, ln) for (t, p, v, ln, _f, _fine) in ProjectData.decode_note_events(synth)] == notes4,
   "decode(build(notes)) == notes")

# 6) MIDI-file note source: midimap note capture + rescale + build->decode -----
from logicx import midimap
import struct as _st
_ev = bytearray()
def _add(dt, *b):
    _ev.extend(midimap._vlq(dt)); _ev.extend(bytes(b))
_add(0, 0x90, 60, 100); _add(240, 0x80, 60, 64)          # C  @0   len240 v100
_add(240, 0x90, 64, 80); _add(240, 0x80, 64, 64)         # E  @480 len240 v80
_add(240, 0x90, 67, 120); _add(480, 0x80, 67, 64)        # G  @960 len480 v120
_add(0, 0xFF, 0x2F, 0x00)
_smf = midimap._chunk(b"MThd", _st.pack(">HHH", 0, 1, 480)) + midimap._chunk(b"MTrk", bytes(_ev))
_resc = midimap.parse(_smf).rescaled_notes(960)
ok(_resc == [(0, 60, 100, 480), (960, 64, 80, 480), (1920, 67, 120, 960)],
   f"midimap note capture + 480->960 rescale: {_resc}")
_pl = ProjectData.build_note_qsve_payload(_resc)
_rec = bytearray(0x24) + _pl
_st.pack_into("<I", _rec, 0x1c, len(_pl))
_back = [(t, p, v, l) for (t, p, v, l, f, fine) in ProjectData.decode_note_events(bytes(_rec))]
ok(_back == _resc, f"SMF notes -> build_note_qsve_payload -> decode round-trip: {_back}")

print(f"OK — {PASS} assertions passed (note encoder/decoder + SMF source, vs F4b/F4c)")
