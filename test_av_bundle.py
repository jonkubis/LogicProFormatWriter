#!/usr/bin/env python3.12
"""Regression tests for the UNIFIED audio+MIDI track synthesis (§10.9):
projectdata.synthesize_av_tracks / synthesize_av_bundle — arbitrary M instrument + N
audio tracks onto a minimal mixed base, in one call, named.

Logic-validated 2026-06-01 (fixtures/TEST_av_bundle.logicx — 2 inst + 2 audio, all 6
tracks open clean). Exercises: instrument heavy+light, audio heavy+light (incl. the
audio light op _light_activate_audio), the two heavy ops composing, and sequential
naming. Run: python3.12 test_av_bundle.py
"""
import struct
import tempfile
import shutil
from pathlib import Path
from logicx.projectdata import (ProjectData, IdGen, instrument_infrastructure, audio_infrastructure,
                         synthesize_av_tracks, synthesize_av_bundle, synthesize_av_region_bundle,
                         synthesize_midi_regions, _audio_track_arrange_positions,
                         _instrument_arrange_positions, _is_instrument_ivne,
                         _ocua_for_ivne, _arrange_container, _arr_height_off, _u32,
                         IVNE_NAME, IVNE_NAME_LEN)
import logicx.projectdata as st

ROOT = Path(__file__).resolve().parent
MIDI = ROOT / "fixtures" / "midi test"
PASS = 0


def ok(c, m):
    global PASS
    assert c, "FAIL " + m
    PASS += 1


def load(b):
    return ProjectData.parse((Path(b) / "Alternatives" / "000" / "ProjectData").read_bytes())


def channels(pd):
    """[(chan, 'INST'|'AUD', name)] for the visible mixer tracks, in channel order."""
    arr = {_u32(r.raw, st.KART_CHAN) for r in pd.records if r.tag == b"karT" and len(r.raw) == 93
           and _u32(r.raw, 0x08) == 0x040000 and _u32(r.raw, st.KART_CHAN) != st.KART_MASTER_CHAN}
    out = []
    for r in pd.records:
        if r.tag == b"ivnE" and _u32(r.raw, 0x08) in arr:
            ch = _u32(r.raw, 0x08)
            nlen = struct.unpack_from("<H", r.raw, IVNE_NAME_LEN)[0]
            out.append((ch, "INST" if _is_instrument_ivne(pd, r) else "AUD",
                        r.raw[IVNE_NAME:IVNE_NAME + nlen].decode("latin-1")))
    return sorted(out)


if not (MIDI / "mixed_template + 1 audio.logicx").exists():
    print("(skipping: mixed differentials absent)")
else:
    base = load(MIDI / "mixed_template.logicx")
    inst_infra = instrument_infrastructure(load(MIDI / "mixed_template + 1 inst.logicx"),
                                           load(MIDI / "mixed_template + 2 inst.logicx"), base)
    aud_infra = audio_infrastructure(load(MIDI / "mixed_template + 1 audio.logicx"), base)

    # 1) unified 2 inst + 2 audio: channels, types, sequential names --------------------
    pd = load(MIDI / "mixed_template.logicx")
    inst_idxs, aud_idxs = synthesize_av_tracks(pd, instruments=2, audio=2, inst_infra=inst_infra,
                                               audio_infra=aud_infra, ids=IdGen(7))
    ok(inst_idxs == [0x600000, 0x640000], f"instruments at next 2 slots {[hex(x) for x in inst_idxs]}")
    ok(aud_idxs == [0x680000, 0x6c0000], f"audio at the following 2 slots {[hex(x) for x in aud_idxs]}")
    ok(channels(pd) == [(0x580000, "INST", "Inst 1"), (0x5c0000, "AUD", "Audio 1"),
                        (0x600000, "INST", "Inst 2"), (0x640000, "INST", "Inst 3"),
                        (0x680000, "AUD", "Audio 2"), (0x6c0000, "AUD", "Audio 3")],
       f"6 correctly-typed, sequentially-named tracks {[(hex(c), t, n) for c, t, n in channels(pd)]}")

    # every synth channel is strip-linked and correctly typed
    for ch in inst_idxs:
        iv = next(r for r in pd.records if r.tag == b"ivnE" and _u32(r.raw, 0x08) == ch)
        ok(_ocua_for_ivne(pd, iv) is not None and _is_instrument_ivne(pd, iv), f"inst 0x{ch:x} linked+instrument")
    for ch in aud_idxs:
        iv = next(r for r in pd.records if r.tag == b"ivnE" and _u32(r.raw, 0x08) == ch)
        oc = _ocua_for_ivne(pd, iv)
        ok(oc is not None and oc.raw[0x70:0x72] == b"\xab\xf7", f"audio 0x{ch:x} linked+audio strip")

    # 2) structural invariants: 1 shared 241 strip, 2 heavy trios, arrange height ---------
    ok(sum(1 for r in pd.records if r.tag == b"OCuA" and len(r.raw) == 221) == 0
       and sum(1 for r in pd.records if r.tag == b"OCuA" and len(r.raw) == 241) == 1,
       "exactly one 221->241 strip (grown once, shared by both heavy ops)")
    ok(sum(1 for r in pd.records if r.tag == b"qeSM" and _u32(r.raw, 0x08) == 0x4000000) == 2,
       "exactly 2 trios at 0x4000000 (one per heavy op; lights add none)")
    rc = _arrange_container(pd.records)
    ok(struct.unpack_from("<H", rc.raw, _arr_height_off(rc.raw))[0] == 0x3c * 7,
       "arrange visible-track height = 0x3c*7 (6 tracks + ruler)")
    data = pd.serialize()
    ok(ProjectData.parse(data).serialize() == data, "unified 2+2 round-trips")

    # 3) custom names + audio-only + instrument-only -------------------------------------
    pd2 = load(MIDI / "mixed_template.logicx")
    synthesize_av_tracks(pd2, instruments=1, audio=1, inst_infra=inst_infra, audio_infra=aud_infra,
                         ids=IdGen(3), inst_names=["Bass"], audio_names={1: "Kick"})
    names = {n for _, _, n in channels(pd2)}
    ok("Bass" in names and "Kick" in names, f"custom names applied {names}")

    pd3 = load(MIDI / "mixed_template.logicx")    # audio-only (no instruments)
    _, a3 = synthesize_av_tracks(pd3, audio=3, audio_infra=aud_infra, ids=IdGen(5))
    ok([t for _, t, _ in channels(pd3) if t == "AUD"] == ["AUD"] * 4, "audio-only: 1 template + 3 synth audio")
    ok([n for _, t, n in channels(pd3) if t == "AUD"][-1] == "Audio 4", "audio-only names run to 'Audio 4'")
    ok(ProjectData.parse(pd3.serialize()).serialize() == pd3.serialize(), "audio-only round-trips")

    pd4 = load(MIDI / "mixed_template.logicx")    # instrument-only
    i4, _ = synthesize_av_tracks(pd4, instruments=3, inst_infra=inst_infra, ids=IdGen(9))
    ok(len(i4) == 3 and [n for _, t, n in channels(pd4) if t == "INST"] == ["Inst 1", "Inst 2", "Inst 3", "Inst 4"],
       "instrument-only: 4 instruments named Inst 1..4")

    # 4) the bundle writer: NumberOfTracks + refuses overwrite ---------------------------
    out = Path(tempfile.mkdtemp()) / "av.logicx"
    synthesize_av_bundle(MIDI / "mixed_template.logicx", out, instruments=1, audio=1,
                         inst_ref1_bundle=MIDI / "mixed_template + 1 inst.logicx",
                         inst_ref2_bundle=MIDI / "mixed_template + 2 inst.logicx",
                         audio_ref_bundle=MIDI / "mixed_template + 1 audio.logicx",
                         seed=1, verbose=False)
    import plistlib
    meta = plistlib.loads((out / "Alternatives" / "000" / "MetaData.plist").read_bytes())
    ok(meta.get("NumberOfTracks") == 4, f"bundle NumberOfTracks = 4 (got {meta.get('NumberOfTracks')})")
    try:
        synthesize_av_bundle(MIDI / "mixed_template.logicx", out, audio=1,
                             audio_ref_bundle=MIDI / "mixed_template + 1 audio.logicx", verbose=False)
        ok(False, "should refuse to overwrite")
    except FileExistsError:
        ok(True, "refuses to overwrite an existing bundle")
    shutil.rmtree(out.parent)

    # 5) audio REGIONS on the synth audio tracks (§10.9.2) -------------------------------
    F21 = ROOT / "templates" / "F21_multitrack_regions.logicx"
    if F21.exists():
        wavs = sorted((F21 / "Media" / "Audio Files").glob("*.wav"))[:3]
        # audio-ordinal -> arrange stream position (interleaved with instruments)
        pdx = load(MIDI / "mixed_template.logicx")
        synthesize_av_tracks(pdx, instruments=2, audio=2, inst_infra=inst_infra, audio_infra=aud_infra, ids=IdGen(7))
        ordpos = _audio_track_arrange_positions(pdx)
        ok(ordpos == {1: 2, 2: 5, 3: 6}, f"audio ordinal->arrange position (interleaved) {ordpos}")

        out2 = Path(tempfile.mkdtemp()) / "avr.logicx"
        summary = synthesize_av_region_bundle(
            MIDI / "mixed_template.logicx", out2, instruments=2, audio=2,
            audio_regions=[(1, wavs[0], 0), (2, wavs[1], 0), (3, wavs[2], 0)],
            prototype_bundle=F21,
            inst_ref1_bundle=MIDI / "mixed_template + 1 inst.logicx",
            inst_ref2_bundle=MIDI / "mixed_template + 2 inst.logicx",
            audio_ref_bundle=MIDI / "mixed_template + 1 audio.logicx", seed=7, verbose=False)
        ok(summary["audio_regions"] == 3 and summary["instruments"] == 2 and summary["audio"] == 2,
           f"region-bundle summary {summary}")
        b = load(out2)
        # events land in the qSvE AFTER the real arrange container, on the audio rows' stream positions
        arrpos = b.records.index(_arrange_container(b.records))
        ev_pos = next(i for i, r in enumerate(b.records)
                      if r.tag == b"qSvE" and _u32(r.raw, 0x08) == 0x040000 and ProjectData._qsve_has_audio_event(r))
        ok(ev_pos > arrpos, "region events land in the EvSq after the REAL arrange container (not the decoy)")
        body = b.records[ev_pos].raw[st.REC_HEADER_SIZE:st.REC_HEADER_SIZE + _u32(b.records[ev_pos].raw, st.REC_SIZE_OFF)]
        e0 = ProjectData._first_audio_event_off(body)
        tracks = []
        k = 0
        while e0 is not None and e0 + (k + 1) * ProjectData.PLACEMENT_EVENT_SIZE <= len(body) \
                and _u32(body, e0 + k * ProjectData.PLACEMENT_EVENT_SIZE) == 0x24:
            tracks.append(body[e0 + k * ProjectData.PLACEMENT_EVENT_SIZE + ProjectData.PLACEMENT_TRACK_OFF])
            k += 1
        ok(tracks == [2, 5, 6], f"placement track fields = audio rows' stream positions {tracks}")
        ok(sum(1 for r in b.records if r.tag == b"gRuA") == 3, "3 region gRuA present")
        import plistlib
        md = plistlib.loads((out2 / "Alternatives" / "000" / "MetaData.plist").read_bytes())
        ok(md.get("NumberOfTracks") == 6, f"region-bundle NumberOfTracks=6 ({md.get('NumberOfTracks')})")
        ok(len(md.get("AudioFiles", [])) == 3 and len(list((out2 / "Media" / "Audio Files").glob("*.wav"))) == 3,
           "3 wavs in AudioFiles + Media")
        ok(ProjectData.parse(b.serialize()).serialize() == b.serialize(), "region-bundle round-trips")
        shutil.rmtree(out2.parent)

    # 6) MIDI note regions on the instrument tracks (§10.9.3) ----------------------------
    F23 = ROOT / "templates" / "F23_av.logicx"
    if F23.exists():
        proto = load(F23)
        pdm = load(MIDI / "mixed_template.logicx")
        synthesize_av_tracks(pdm, instruments=2, audio=0, inst_infra=inst_infra, ids=IdGen(7))
        ipos = _instrument_arrange_positions(pdm)
        ok(set(ipos) == {1, 2, 3} and ipos[1][0] == 1 and ipos[2][0] == 3 and ipos[3][0] == 4,
           f"instrument ordinal->(arrange pos, chan) {ipos}")
        ridxs = synthesize_midi_regions(pdm, [
            (1, [(0, 60, 100, 960), (960, 64, 100, 960)], 0, "Lead"),
            (2, [(0, 48, 90, 3840)], 0, "Bass"),
            (3, [(0, 72, 110, 480)], 1920, "Stab")], prototype=proto)
        ok(len(ridxs) == 3 and ridxs[0] >= 0x1200000, f"3 MIDI regions at fresh high indices {[hex(r) for r in ridxs]}")
        # region containers: names + re-stamped channel + note decode
        names, chans, notecounts = [], [], []
        for ri, it in zip(ridxs, [1, 2, 3]):
            qe = next(r for r in pdm.records if r.tag == b"qeSM" and _u32(r.raw, 0x08) == ri)
            nl = struct.unpack_from("<H", qe.raw, 0x34)[0]
            names.append(qe.raw[0x36:0x36 + nl].decode("latin-1"))
            # the channel ref is name-RELATIVE (it shifts with _set_region_name); in the
            # 'Inst 1' (nlen 6, name_end 0x3c) prototype it sits at 0x106 = name_end + 0xca
            name_end = 0x36 + nl + (nl & 1)
            chans.append(_u32(qe.raw, name_end + 0xca))
            nq = next(r for r in pdm.records if r.tag == b"qSvE" and _u32(r.raw, 0x08) == ri
                      and _u32(r.raw, st.REC_HEADER_SIZE) == 0x90)
            notecounts.append(len(ProjectData.decode_note_events(nq.raw)))
        ok(names == ["Lead", "Bass", "Stab"], f"MIDI region names {names}")
        ok(chans == [ipos[1][1], ipos[2][1], ipos[3][1]], f"region qeSM channel ref re-stamped to each instrument {[hex(c) for c in chans]}")
        ok(notecounts == [2, 1, 1], f"notes filled per region {notecounts}")
        # 0x20 placement events grafted into the real arrange EvSq, track fields = arrange positions
        arrpos = pdm.records.index(_arrange_container(pdm.records))
        ev_i = next(i for i, r in enumerate(pdm.records) if i > arrpos and r.tag == b"qSvE"
                    and _u32(r.raw, 0x08) == 0x040000 and _u32(r.raw, st.REC_HEADER_SIZE) != 0xf1
                    and any(_u32(r.raw, st.REC_HEADER_SIZE + o) == 0x20 for o in range(0, 4)))
        ebody = pdm.records[ev_i].raw[st.REC_HEADER_SIZE:st.REC_HEADER_SIZE + _u32(pdm.records[ev_i].raw, st.REC_SIZE_OFF)]
        mtracks = [ebody[o + st.ProjectData.PLACEMENT_TRACK_OFF] for o in range(0, len(ebody) - 80, 4)
                   if _u32(ebody, o) == 0x20]
        ok(sorted(mtracks) == [1, 3, 4], f"MIDI placement track fields = instrument arrange positions {sorted(mtracks)}")
        ok(ProjectData.parse(pdm.serialize()).serialize() == pdm.serialize(), "MIDI-region synth round-trips")

        # the FULLY unified bundle: instruments+notes AND audio+regions in one call
        if F21.exists():
            out3 = Path(tempfile.mkdtemp()) / "full.logicx"
            s = synthesize_av_region_bundle(
                MIDI / "mixed_template.logicx", out3, instruments=2, audio=2,
                midi_regions=[(1, [(0, 60, 100, 960)], 0, "Lead"), (2, [(0, 48, 90, 1920)], 0, "Bass")],
                audio_regions=[(2, sorted((F21 / "Media" / "Audio Files").glob("*.wav"))[0], 0)],
                prototype_bundle=F21, midi_prototype_bundle=F23,
                inst_ref1_bundle=MIDI / "mixed_template + 1 inst.logicx",
                inst_ref2_bundle=MIDI / "mixed_template + 2 inst.logicx",
                audio_ref_bundle=MIDI / "mixed_template + 1 audio.logicx", seed=7, verbose=False)
            ok(s["midi_regions"] == 2 and s["audio_regions"] == 1, f"unified summary {s}")
            full = load(out3)
            arr2 = full.records.index(_arrange_container(full.records))
            evr = next(r for i, r in enumerate(full.records) if i > arr2 and r.tag == b"qSvE"
                       and _u32(r.raw, 0x08) == 0x040000 and ProjectData._qsve_has_audio_event(r))
            fb = evr.raw[st.REC_HEADER_SIZE:st.REC_HEADER_SIZE + _u32(evr.raw, st.REC_SIZE_OFF)]
            n20 = sum(1 for o in range(0, len(fb) - 80, 4) if _u32(fb, o) == 0x20)
            n24 = sum(1 for o in range(0, len(fb) - 80, 4) if _u32(fb, o) == 0x24)
            ok(n20 == 2 and n24 == 1, f"arrange EvSq holds both MIDI(0x20)={n20} and audio(0x24)={n24} events")
            ok(ProjectData.parse(full.serialize()).serialize() == full.serialize(), "fully-unified bundle round-trips")
            shutil.rmtree(out3.parent)

print(f"OK — {PASS} assertions passed (unified audio+MIDI track synthesis)")
