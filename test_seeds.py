#!/usr/bin/env python3.12
"""Regression tests for the EMBEDDED donor seeds (§13) — the self-contained data/ that
lets the library generate .logicx with no loose donors at runtime.

Verifies: (1) the loader reproduces the donor fixtures byte-for-byte (the bake→load
round-trip is faithful); (2) building from the embedded defaults (donor params = None)
produces self-contained MINIMAL bundles (ProjectData + MetaData + ProjectInformation +
Media — no WindowImage, no DisplayState); (3) the file-path override path still works and
matches. Regenerate data/ with `python3.12 bake_seeds.py` (see DONORS.md).
Run: python3.12 test_seeds.py
"""
import re
import shutil
import tempfile
from pathlib import Path
from logicx.projectdata import (ProjectData, _seed_base_pd, _baked_infra, _SEED_DIR,
                         instrument_infrastructure, audio_infrastructure, _midi_region_prototype,
                         synthesize_av_region_bundle, synthesize_instrument_bundle,
                         synthesize_track_region_bundle, _u32)
import logicx.projectdata as st

ROOT = Path(__file__).resolve().parent
MIDI = ROOT / "fixtures" / "midi test"
WAVS = ROOT / "templates" / "F21_multitrack_regions.logicx" / "Media" / "Audio Files"
PASS = 0


def ok(c, m):
    global PASS
    assert c, "FAIL " + m
    PASS += 1


def _pd(b):
    return ProjectData.parse((Path(b) / "Alternatives" / "000" / "ProjectData").read_bytes())


def files_of(bundle):
    return sorted(str(p.relative_to(bundle)) for p in Path(bundle).rglob("*") if p.is_file())


def tracks(pd):
    return [_u32(r.raw, st.KART_CHAN) for r in pd.records if r.tag == b"karT" and len(r.raw) == 93
            and _u32(r.raw, 0x08) == 0x040000 and _u32(r.raw, st.KART_CHAN) != st.KART_MASTER_CHAN]


if not (_SEED_DIR / "audio_base.seed").exists():
    print("(skipping test_seeds: data/ absent — run `python3.12 bake_seeds.py`)")
else:
    # 1) loader reproduces the donor fixtures byte-for-byte --------------------------------
    ok(_seed_base_pd("audio_base").serialize()
       == _pd(ROOT / "fixtures" / "lots of audio tracks" / "1 from 64 audio tracks.logicx").serialize(),
       "audio_base seed == fixture ProjectData")
    ok(_seed_base_pd("mixed_base").serialize() == _pd(MIDI / "mixed_template.logicx").serialize(),
       "mixed_base seed == fixture ProjectData")
    infra = _baked_infra()
    base = _pd(MIDI / "mixed_template.logicx")
    ok(infra["instrument_infra"] == instrument_infrastructure(
        _pd(MIDI / "mixed_template + 1 inst.logicx"), _pd(MIDI / "mixed_template + 2 inst.logicx"), base),
       "baked instrument_infra == live extraction")
    ok(infra["audio_infra"] == audio_infrastructure(_pd(MIDI / "mixed_template + 1 audio.logicx"), base),
       "baked audio_infra == live extraction")
    mg, me, mc = _midi_region_prototype(_pd(ROOT / "templates" / "F23_av.logicx"))
    ok(infra["midi_region_proto"]["group"] == [(t, d) for t, d in mg]
       and infra["midi_region_proto"]["event"] == me and infra["midi_region_proto"]["proto_chan"] == mc,
       "baked midi_region_proto == live extraction")
    ok(len(infra["audio_region_proto"]["group"]) >= 2 and len(infra["audio_region_proto"]["event"]) == 80,
       "baked audio_region_proto present (gRuA/lFuA group + 80-B event)")

    MINIMAL = {"Alternatives/000/ProjectData", "Alternatives/000/MetaData.plist",
               "Resources/ProjectInformation.plist"}

    # 2) build from EMBEDDED defaults (donor params None) -> minimal self-contained bundle --
    tmp = Path(tempfile.mkdtemp())
    try:
        # full av: 2 inst (notes) + 2 audio (a region), all donor params None
        out = tmp / "av.logicx"
        synthesize_av_region_bundle(None, out, instruments=2, audio=2,
                                    midi_regions=[(1, [(0, 60, 100, 960)], 0, "Lead")],
                                    audio_regions=[(2, WAVS / "047.wav", 0)], seed=7, verbose=False)
        fs = set(files_of(out))
        ok(MINIMAL <= fs and "Media/Audio Files/047.wav" in fs, f"embedded av bundle files {sorted(fs)}")
        ok(not any("WindowImage" in f or "DisplayState" in f for f in fs),
           "embedded bundle drops WindowImage + DisplayState")
        avpd = _pd(out)
        ok(len(tracks(avpd)) == 6, f"embedded av: 6 tracks (2 inst + 2 audio synth + base) ({len(tracks(avpd))})")
        ok(ProjectData.parse(avpd.serialize()).serialize() == avpd.serialize(), "embedded av round-trips")
        raw = (out / "Alternatives" / "000" / "ProjectData").read_bytes()
        ok(not (re.findall(rb"/Users/[ -~]{3,40}", raw) + re.findall(rb"/var/folders/[ -~]{3,40}", raw)),
           "embedded av bundle has no absolute-path leaks")

        # instrument-only from embedded
        out2 = tmp / "inst.logicx"
        synthesize_instrument_bundle(None, out2, 3, seed=7, verbose=False)
        ok(set(files_of(out2)) == MINIMAL, f"embedded instrument bundle = minimal file set {files_of(out2)}")
        ok(len(tracks(_pd(out2))) == 5, "embedded instruments: 1 inst + 1 audio base + 3 synth = 5 tracks")

        # the combine from embedded (track_template + prototype both None)
        out3 = tmp / "combine.logicx"
        synthesize_track_region_bundle(None, None, out3, [(1, WAVS / "047.wav", 0), (3, WAVS / "048.wav", 0)],
                                       seed=1, verbose=False)
        ok(MINIMAL <= set(files_of(out3)), "embedded combine = minimal file set")
        ok(len(tracks(_pd(out3))) == 3, "embedded combine: 3 audio tracks")

        # 3) file-path OVERRIDE still works + matches embedded (same track count) -----------
        out4 = tmp / "override.logicx"
        synthesize_instrument_bundle(MIDI / "mixed_template.logicx", out4, 3,
                                     ref1_bundle=MIDI / "mixed_template + 1 inst.logicx",
                                     ref2_bundle=MIDI / "mixed_template + 2 inst.logicx", seed=7, verbose=False)
        ok(tracks(_pd(out4)) == tracks(_pd(out2)), "file-path override == embedded (same channels)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

print(f"OK — {PASS} assertions passed (embedded donor seeds §13)")
