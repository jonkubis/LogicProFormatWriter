#!/usr/bin/env python3.12
"""Regression tests for SOFTWARE-INSTRUMENT (MIDI) track synthesis — the per-track
"light" operation (projectdata.activate_instrument_track), §10.9.

Validated against the Logic differentials fixtures/midi test/mixed_template + N inst
(N=2,3,4): activating one instrument on +N must reproduce Logic's +N+1 structurally
(channel set, track-list ranks, record count). Logic-validated 2026-06-01
(fixtures/TEST_inst_lightop.logicx — a full working synthesized instrument track).
Run: python3.12 test_inst_synth.py
"""
import struct
from pathlib import Path
from logicx.projectdata import ProjectData, IdGen, activate_instrument_track, _u32
import logicx.projectdata as st

ROOT = Path(__file__).resolve().parent
MIDI = ROOT / "fixtures" / "midi test"
PASS = 0


def ok(c, m):
    global PASS
    assert c, "FAIL " + m
    PASS += 1


def load(n):
    return ProjectData.parse((MIDI / f"mixed_template + {n} inst.logicx" / "Alternatives" / "000" / "ProjectData").read_bytes())


def chans(pd):
    return sorted(_u32(r.raw, st.KART_CHAN) for r in pd.records if r.tag == b"karT" and len(r.raw) == 93
                  and _u32(r.raw, 0x08) == 0x040000 and _u32(r.raw, st.KART_CHAN) != st.KART_MASTER_CHAN)


def ranks(pd):
    return {_u32(r.raw, st.TRK_SLOT): r.raw[st.TRK_RANK] for r in pd.records
            if r.tag == b"karT" and _u32(r.raw, 0x08) == st.TRK_IDX and len(r.raw) == 93}


def inames(pd):
    """Instrument channel display names (ivnE @0xc4) in channel order."""
    out = []
    for r in pd.records:
        if r.tag == b"ivnE" and st._is_instrument_ivne(pd, r):
            nlen = struct.unpack_from("<H", r.raw, st.IVNE_NAME_LEN)[0]
            out.append((_u32(r.raw, st.IVNE_IDX), r.raw[st.IVNE_NAME:st.IVNE_NAME + nlen].decode("latin-1")))
    return [n for _, n in sorted(out)]


def arrh(pd):
    """The arrange container's visible-track HEIGHT (u16 @ name_end+0xa) — the gate
    that caps how many tracks Logic draws (§10.6.4/§10.9). Uses the same container
    selector as synthesis (`_arrange_container`) so it reads the REAL arrange container,
    not the larger 'Untitled' qeSM@0x040000 decoy (height always 0)."""
    rec = st._arrange_container(pd.records)
    return struct.unpack_from("<H", rec.raw, st._arr_height_off(rec.raw))[0]


if not MIDI.exists():
    print("(skipping: fixtures/midi test/ absent)")
else:
    # 1) one activation on +N reproduces Logic's +N+1 (structure) -------------------
    for n in (2, 3):
        pd = load(n)
        before = len(chans(pd))
        nidx = activate_instrument_track(pd, ids=IdGen(seed=7))
        logic = load(n + 1)
        ok(chans(pd) == chans(logic), f"+{n}->+{n+1}: channel set matches Logic ({[hex(c) for c in chans(pd)]})")
        ok(len(chans(pd)) == before + 1, f"+{n}->+{n+1}: exactly one track added")
        rm, rl = ranks(pd), ranks(logic)
        mismatch = [s for s in set(rm) & set(rl) if rm[s] != rl[s]]
        ok(not mismatch, f"+{n}->+{n+1}: track-list ranks match Logic ({len(mismatch)} mismatches)")
        ok(len(pd.records) == len(logic.records), f"+{n}->+{n+1}: record count matches ({len(pd.records)})")
        ok(arrh(pd) == arrh(logic), f"+{n}->+{n+1}: arrange visible-track height matches Logic (0x{arrh(pd):x})")
        data = pd.serialize()
        ok(ProjectData.parse(data).serialize() == data, f"+{n}->+{n+1}: round-trips")
        # the new channel is instrument-typed with a linked strip
        oc = st._ocua_for_channel(pd, nidx)
        ok(oc is not None and oc.raw[0x70:0x72] == st.INST_OCUA_CFG, f"+{n}->+{n+1}: new channel is an instrument strip")

    # 2) repeated activation generalizes: +2 then x2 == +4 --------------------------
    pd = load(2)
    ids = IdGen(seed=7)
    activate_instrument_track(pd, ids=ids)
    activate_instrument_track(pd, ids=ids)
    logic4 = load(4)
    ok(chans(pd) == chans(logic4), "two activations on +2 reproduce +4's channels")
    rm, rl = ranks(pd), ranks(logic4)
    ok(not [s for s in set(rm) & set(rl) if rm[s] != rl[s]], "two activations: ranks match +4")
    ok(len(pd.records) == len(logic4.records), "two activations: record count matches +4")

    # 3) refuses when cur_max isn't an instrument / template exhaustion handled ------
    # (cur_max in these templates is always the last instrument — sanity that it runs)
    ok(activate_instrument_track(load(3), ids=IdGen(seed=1)) == 0x6c0000, "next instrument lands at the next channel slot")

    # 4) the FULL chain: synthesize M instruments from the MINIMAL template (heavy op
    #    + light ops + UCuA version) reproduces Logic's +M inst -------------------------
    from logicx.projectdata import (instrument_infrastructure, synthesize_instrument_tracks, _instrument_track_count)
    base = ProjectData.parse((MIDI / "mixed_template.logicx" / "Alternatives" / "000" / "ProjectData").read_bytes())
    ref1, ref2 = load(1), load(2)
    infra = instrument_infrastructure(ref1, ref2, base)
    ok(_instrument_track_count(base) == 1, "minimal mixed template has 1 instrument")
    for m in (1, 2, 3):
        pd = ProjectData.parse((MIDI / "mixed_template.logicx" / "Alternatives" / "000" / "ProjectData").read_bytes())
        synthesize_instrument_tracks(pd, m, infra=infra, ids=IdGen(seed=7))
        logic = load(m)
        ok(chans(pd) == chans(logic), f"synth {m} inst from minimal == +{m}inst channels")
        rm, rl = ranks(pd), ranks(logic)
        ok(not [s for s in set(rm) & set(rl) if rm[s] != rl[s]], f"synth {m} inst: ranks match +{m}inst")
        ok(len(pd.records) == len(logic.records), f"synth {m} inst: record count matches +{m}inst")
        mu = sorted(len(r.raw) for r in pd.records if r.tag == b"UCuA")
        lu = sorted(len(r.raw) for r in logic.records if r.tag == b"UCuA")
        ok(mu == lu, f"synth {m} inst: UCuA plist set matches +{m}inst {mu}")
        ok(arrh(pd) == arrh(logic), f"synth {m} inst: arrange visible-track height matches +{m}inst (0x{arrh(pd):x})")
        ok(inames(pd) == inames(logic), f"synth {m} inst: instrument names match Logic {inames(pd)}")
        data = pd.serialize()
        ok(ProjectData.parse(data).serialize() == data, f"synth {m} inst: round-trips")

print(f"OK — {PASS} assertions passed (software-instrument track synthesis)")
