#!/usr/bin/env python3.12
"""Regression tests for AUDIO track synthesis onto a SETTLED mixed base — the HEAVY op
(projectdata._heavy_activate_audio / synthesize_audio_on_mixed_bundle), §10.9.1.

Adding an audio track to a settled mixed template (1 inst + 1 audio, not a pre-allocated
mixer) materializes new channel infrastructure (2 UCuA + the 0x4000000 trio + a grown
221->241 strip) cloned from the base+1-audio differential. Validated against
fixtures/midi test/mixed_template + 1 audio.logicx; Logic-validated 2026-06-01
(fixtures/TEST_mixed_1audio.logicx — opens clean: Inst 1, Audio 1, Audio 2).
Run: python3.12 test_audio_mixed.py
"""
import struct
from pathlib import Path
from collections import Counter
from logicx.projectdata import (ProjectData, IdGen, audio_infrastructure, _heavy_activate_audio,
                         _ocua_for_ivne, _is_instrument_ivne, _arrange_container,
                         _arr_height_off, _synth_find, _u32)
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


def chans(pd):
    return sorted(_u32(r.raw, st.KART_CHAN) for r in pd.records if r.tag == b"karT" and len(r.raw) == 93
                  and _u32(r.raw, 0x08) == 0x040000 and _u32(r.raw, st.KART_CHAN) != st.KART_MASTER_CHAN)


def ranks(pd):
    return {_u32(r.raw, st.TRK_SLOT): r.raw[st.TRK_RANK] for r in pd.records
            if r.tag == b"karT" and _u32(r.raw, 0x08) == st.TRK_IDX and len(r.raw) == 93}


def sig(r):
    return (r.tag, _u32(r.raw, 0x08), len(r.raw))


if not (MIDI / "mixed_template + 1 audio.logicx").exists():
    print("(skipping: fixtures/midi test/mixed_template + 1 audio.logicx absent)")
else:
    base = load(MIDI / "mixed_template.logicx")
    ref = load(MIDI / "mixed_template + 1 audio.logicx")
    infra = audio_infrastructure(ref, base)

    # infra shape: new ivnE + 2 UCuA + the trio + the grown 241 strip
    ok(len(infra["ucua"]) == 2 and sorted(len(u) for u in infra["ucua"]) == [867, 1957],
       f"infra has the 2 audio UCuA plists {sorted(len(u) for u in infra['ucua'])}")
    ok(len(infra["trio"]) == 3, "infra has the 0x4000000 trio")
    ok(len(infra["strip241"]) == 241, "infra has the grown 241 strip")

    # heavy op reproduces +1 audio structurally
    pd = load(MIDI / "mixed_template.logicx")
    nidx = _heavy_activate_audio(pd, IdGen(7), infra, stereo=False)
    ok(nidx == 0x600000, f"new audio channel at the next slot 0x600000 (got 0x{nidx:x})")
    ok(len(pd.records) == len(ref.records), f"record count matches +1audio ({len(pd.records)})")
    ok(chans(pd) == chans(ref), f"channel set matches +1audio ({[hex(c) for c in chans(pd)]})")
    rm, rl = ranks(pd), ranks(ref)
    ok(not [s for s in set(rm) & set(rl) if rm[s] != rl[s]], "track-list ranks match +1audio")

    # only known-openable structural diffs (gnoS regenerated + arrange-container name)
    ms, ls = Counter(sig(r) for r in pd.records), Counter(sig(r) for r in ref.records)
    only = {k[0] for k in (ms - ls)} | {k[0] for k in (ls - ms)}
    ok(only <= {b"gnoS", b"qeSM"}, f"only known-openable struct diffs remain ({only})")

    # the new channel is a linked, AUDIO-typed strip named 'Audio 2'
    nv = _synth_find(pd.records, b"ivnE", nidx)[1]
    oc = _ocua_for_ivne(pd, nv)
    ok(oc is not None and oc.raw[0x70:0x72] == b"\xab\xf7", "new channel is an AUDIO strip (cfg abf7)")
    ok(not _is_instrument_ivne(pd, nv), "new channel is not instrument-typed")
    nlen = struct.unpack_from("<H", nv.raw, st.IVNE_NAME_LEN)[0]
    ok(nv.raw[st.IVNE_NAME:st.IVNE_NAME + nlen] == b"Audio 2", "new channel named 'Audio 2'")

    # arrange visible-track height grew to 3 tracks (0x3c*4)
    rc = _arrange_container(pd.records)
    ok(struct.unpack_from("<H", rc.raw, _arr_height_off(rc.raw))[0] == 0x3c * 4,
       "arrange visible-track height = 0x3c*4 (3 tracks + ruler)")

    # link76 churn: the master (0x500000) shifted +0x42, existing Audio 1 (0x5c0000) did not
    def link76(pd, ch):
        r = _synth_find(pd.records, b"ivnE", ch)[1]
        return struct.unpack_from("<H", r.raw, st.IVNE_LINK76)[0]
    ok(link76(pd, 0x500000) == link76(base, 0x500000) + 0x42, "master link76 shifted +0x42")
    ok(link76(pd, 0x5c0000) == link76(base, 0x5c0000), "existing Audio 1 link76 unchanged")

    data = pd.serialize()
    ok(ProjectData.parse(data).serialize() == data, "synthesized ProjectData round-trips")

print(f"OK — {PASS} assertions passed (audio track synthesis on a mixed base)")
