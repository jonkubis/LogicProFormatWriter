#!/usr/bin/env python3.12
"""Regenerate the embedded donor SEEDS in logicx/data/ from the donor `.logicx` fixtures.

★ THIS SCRIPT IS THE BREADCRUMB. ★  The library ships small gzipped data files so it can
generate Logic sessions with NO loose `.logicx` donors at runtime. Those data files are
NOT hand-authored — they are *derived* from the donor fixtures by this script. To update a
donor (new Logic version, a different layout, more pre-allocated tracks): re-make the
donor `.logicx` in Logic (see DONORS.md for the exact click-by-click), drop it in the path
below, and re-run `python3.12 bake_seeds.py`. The fixtures in fixtures/ are the SOURCE OF
TRUTH; the data/ files are generated artifacts (regenerable, never edited by hand).

Outputs (logicx/data/):
  audio_base.seed   — the `1 from 64` pre-allocated audio mixer bundle (ProjectData +
                      MetaData + ProjectInformation + DisplayState), minus WindowImage.jpg.
                      The base the combine / export_beatmap synthesize onto + assemble from.
  mixed_base.seed   — the minimal mixed (1 instrument + 1 audio) bundle, same file set.
                      The base §10.9 instrument/audio synthesis runs on.
  infra.json.gz     — PRE-EXTRACTED constant records (not whole sessions): the instrument
                      + audio heavy-op infrastructure, the MIDI-region prototype, and the
                      audio-region prototype. This is what lets us DROP the +1inst / +2inst
                      / +1audio / F23 / F21 reference bundles from the runtime path — we
                      bake only the few KB of records the extractors pull, with full
                      provenance recorded in `infra.json.gz`'s `_provenance` block + DONORS.md.

Run: python3.12 bake_seeds.py        (writes logicx/data/, then self-verifies the round-trip)
"""
import base64
import gzip
import json
import struct
from pathlib import Path

import logicx.projectdata as st
from logicx.projectdata import (ProjectData, instrument_infrastructure, audio_infrastructure,
                         _midi_region_prototype, _u32, REC_HEADER_SIZE, REC_SIZE_OFF)

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "logicx" / "data"
MIDI = ROOT / "fixtures" / "midi test"

# --- DONOR FIXTURE MAP (source of truth) — see DONORS.md for how each was made in Logic --
DONORS = {
    "audio_base": ROOT / "fixtures" / "lots of audio tracks" / "1 from 64 audio tracks.logicx",
    "mixed_base": MIDI / "mixed_template.logicx",
    "mixed_1inst": MIDI / "mixed_template + 1 inst.logicx",
    "mixed_2inst": MIDI / "mixed_template + 2 inst.logicx",
    "mixed_1audio": MIDI / "mixed_template + 1 audio.logicx",
    "f23_midi_proto": ROOT / "templates" / "F23_av.logicx",
    "f21_audio_proto": ROOT / "templates" / "F21_multitrack_regions.logicx",
}
# bundle files baked into a base seed (everything Logic needs MINUS the 154KB cosmetic
# WindowImage.jpg; the assembler regenerates MetaData and may drop DisplayState* — see code)
SEED_FILES = ["Alternatives/000/ProjectData", "Alternatives/000/MetaData.plist",
              "Alternatives/000/DisplayState.plist", "Alternatives/000/DisplayStateArchive",
              "Resources/ProjectInformation.plist"]


# --- seed container (mirrored by projectdata._unpack_seed) -----------------------------
def pack_seed(files: dict) -> bytes:
    out = bytearray()
    for path in sorted(files):
        p = path.encode("utf-8"); d = files[path]
        out += struct.pack("<H", len(p)) + p + struct.pack("<I", len(d)) + d
    return gzip.compress(bytes(out), 9)


def unpack_seed(blob: bytes) -> dict:
    raw = gzip.decompress(blob); files = {}; i = 0
    while i < len(raw):
        pl = struct.unpack_from("<H", raw, i)[0]; i += 2
        path = raw[i:i + pl].decode("utf-8"); i += pl
        dl = struct.unpack_from("<I", raw, i)[0]; i += 4
        files[path] = bytes(raw[i:i + dl]); i += dl
    return files


# --- infra serialization (JSON + base64; human-inspectable for maintainability) --------
def enc(v):
    if isinstance(v, bytes):
        return {"__b64__": base64.b64encode(v).decode("ascii")}
    if isinstance(v, tuple):
        return {"__tuple__": [enc(x) for x in v]}
    if isinstance(v, list):
        return [enc(x) for x in v]
    if isinstance(v, dict):
        return {k: enc(x) for k, x in v.items()}
    return v


def dec(v):
    if isinstance(v, dict):
        if "__b64__" in v:
            return base64.b64decode(v["__b64__"])
        if "__tuple__" in v:
            return tuple(dec(x) for x in v["__tuple__"])
        return {k: dec(x) for k, x in v.items()}
    if isinstance(v, list):
        return [dec(x) for x in v]
    return v


def _pd(p):
    return ProjectData.parse((Path(p) / "Alternatives" / "000" / "ProjectData").read_bytes())


def extract_audio_region_prototype(proto: ProjectData):
    """The audio-region clone prototype from a ≥1-region session (e.g. F21): the region-0
    gRuA/lFuA group + the 80-byte placement event. (Mirrors ProjectData.synthesize_audio_
    regions' internal extraction; baked so we don't ship F21 at runtime.)"""
    group = [(r.tag.decode("latin-1"), bytes(r.raw)) for r in proto.records
             if r.tag in (b"gRuA", b"lFuA") and _u32(r.raw, 0x08) == 0]
    qi = next(i for i, r in enumerate(proto.records) if ProjectData._qsve_has_audio_event(r))
    body = proto.records[qi].raw[REC_HEADER_SIZE:REC_HEADER_SIZE + _u32(proto.records[qi].raw, REC_SIZE_OFF)]
    event = body[ProjectData._first_audio_event_off(body):][:ProjectData.PLACEMENT_EVENT_SIZE]
    return {"group": group, "event": event}


def main():
    DATA.mkdir(exist_ok=True)
    missing = [n for n, p in DONORS.items() if not Path(p).exists()]
    if missing:
        raise SystemExit(f"missing donor fixtures {missing} — see DONORS.md to (re)create them in Logic")

    # 1) base seeds (the sessions we synthesize onto + assemble bundles from) -------------
    for name in ("audio_base", "mixed_base"):
        bundle = Path(DONORS[name])
        files = {f: (bundle / f).read_bytes() for f in SEED_FILES if (bundle / f).exists()}
        blob = pack_seed(files)
        (DATA / f"{name}.seed").write_bytes(blob)
        assert unpack_seed(blob) == files, f"{name} seed round-trip failed"
        print(f"  audio/mixed base: {name}.seed  ({len(blob)//1024} KB gz)  <- {bundle.name}  [{len(files)} files]")

    # 2) pre-extracted infrastructure (eliminates 5 reference donors from runtime) --------
    base = _pd(DONORS["mixed_base"])
    inst_infra = instrument_infrastructure(_pd(DONORS["mixed_1inst"]), _pd(DONORS["mixed_2inst"]), base)
    aud_infra = audio_infrastructure(_pd(DONORS["mixed_1audio"]), base)
    mgroup, mevent, mchan = _midi_region_prototype(_pd(DONORS["f23_midi_proto"]))
    midi_proto = {"group": [(t.decode("latin-1"), d) for t, d in mgroup], "event": mevent, "proto_chan": mchan}
    aud_region_proto = extract_audio_region_prototype(_pd(DONORS["f21_audio_proto"]))
    infra = {
        "_provenance": {  # ← breadcrumb: which donor each piece came from + the extractor
            "instrument_infra": "instrument_infrastructure(mixed_1inst, mixed_2inst, mixed_base)",
            "audio_infra": "audio_infrastructure(mixed_1audio, mixed_base)",
            "midi_region_proto": "_midi_region_prototype(f23_midi_proto)  # 5-record group + 0x20 event",
            "audio_region_proto": "extract_audio_region_prototype(f21_audio_proto)  # gRuA/lFuA-0 + 0x24 event",
            "regenerate": "python3.12 bake_seeds.py   (see DONORS.md)",
        },
        "instrument_infra": inst_infra,
        "audio_infra": aud_infra,
        "midi_region_proto": midi_proto,
        "audio_region_proto": aud_region_proto,
    }
    payload = gzip.compress(json.dumps(enc(infra)).encode("utf-8"), 9)
    (DATA / "infra.json.gz").write_bytes(payload)
    assert dec(json.loads(gzip.decompress(payload).decode("utf-8")))["instrument_infra"] == inst_infra, \
        "infra round-trip failed"
    print(f"  infra (pre-extracted): infra.json.gz  ({len(payload)//1024} KB gz)  "
          f"<- mixed +1/+2 inst, +1 audio, F23, F21")
    total = sum((DATA / f).stat().st_size for f in ("audio_base.seed", "mixed_base.seed", "infra.json.gz"))
    print(f"\nOK — wrote logicx/data/ ({total//1024} KB total). Regenerate any time with this script.")


if __name__ == "__main__":
    main()
