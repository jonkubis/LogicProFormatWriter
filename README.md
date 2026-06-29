# LogicProFormatWriter

**Generate native Logic Pro `.logicx` sessions from a MIDI file + audio — no Logic required.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Runtime deps](https://img.shields.io/badge/runtime%20deps-stdlib%20only-green.svg)

Logic Pro's project file is an undocumented little-endian binary blob
(`Alternatives/000/ProjectData`). This library **reverse-engineers it from scratch** and writes
valid sessions directly — tempo · meter · markers · audio regions · MIDI notes · synthesized
audio + software-instrument tracks — and every content type is **Logic-validated** (the output
opens clean in Logic Pro, no repair prompts).

The importable Python package is named **`logicx`**.

```python
from logicx import export_beatmap

# a MIDI (tempo/meter/markers + a CC#119/ch16 head-sync marker) + audio files -> one .logicx
export_beatmap("song.mid", ["drums.mp3", "bass.wav", "vox.aif"], "out.logicx")
```

```bash
logicx exportbeatmap song.mid out.logicx drums.mp3 bass.wav vox.aif \
    [--head-sync TICK] [--sample-rate 44100|48000] [--mono] [--names a,b,c]
```

The result is a **self-contained** `.logicx` — audio synced to the head-sync, at the song's
native rate (44.1 or 48 kHz), with all media packed inside — that opens straight in Logic.

## Why this exists

`.logicx` is a closed, undocumented format. If you build music tooling (beatmappers, stem
splitters, arrangers, batch processors) and want to hand users a real Logic session instead of a
folder of loose files, your only options were to script Logic itself or give up. This library is
the third option: it emits the bytes Logic writes, from pure Python, on any machine.

The full byte-level reverse-engineering is written up in
**[`PROJECTDATA_FORMAT.md`](PROJECTDATA_FORMAT.md)** — record framing, the tempo/meter/marker
encodings, the audio-region and MIDI-note layouts, and the track-synthesis deltas.

## Features

- **`export_beatmap()`** — the one-call pipeline: a MIDI (tempo/meter/markers + a CC#119/ch16
  head-sync convention) + 1–16 audio files → one self-contained session. Takes `wav` / `mp3` /
  `aif` (compressed/off-format audio is transcoded to the WAV format Logic expects), names tracks
  after the source files, and lines every clip up to the head-sync.
- **Tempo / meter / marker maps** parsed straight from a Standard MIDI File.
- **Audio regions** and **MIDI note regions** placed at arbitrary bar/beat positions.
- **Track synthesis from scratch** — arbitrary *M* software-instrument + *N* audio tracks, named,
  each carrying its own regions, in a single `synthesize_av_region_bundle()` call. No need for a
  per-layout donor session.
- **Native 44.1 and 48 kHz**, mono or stereo.
- **Apple Lossless (ALAC/CAF)** — optional `lossless=True` (CLI `--alac`) re-encodes stems to ALAC
  in `.caf` containers, which Logic plays natively: lossless, typically **3–4× smaller** than WAV.
- **Self-contained at runtime** — no loose `.logicx` files in the import path (see below).
- **Stdlib only** at runtime. (macOS `afconvert`/`afinfo` are used *only* to decode/normalize
  off-format audio; conformant WAVs need nothing but Python.)

## Install

Not on PyPI — install from source:

```bash
pip install git+https://github.com/jonkubis/LogicProFormatWriter.git
# or, for development:
git clone https://github.com/jonkubis/LogicProFormatWriter.git
cd LogicProFormatWriter && pip install -e .
```

Requires Python ≥ 3.10. Audio transcoding (mp3/aif → wav) uses macOS's built-in `afconvert`;
on other platforms, pre-convert your audio to 44.1/48 kHz WAV.

## How it works (no donor `.logicx` at runtime)

The library bundles ~62 KB of donor data in **`logicx/data/`** and synthesizes sessions from
it — there are no loose `.logicx` files in the import path. `data/` holds two base sessions
(`audio_base.seed`, `mixed_base.seed`) plus `infra.json.gz` (pre-extracted constant records).
The byte-level format spec is **[`PROJECTDATA_FORMAT.md`](PROJECTDATA_FORMAT.md)** (§13 covers
this packaging layer; §10.6–§10.9 the synthesis).

## ★ Where `logicx/data/` comes from — and how to reconstitute it

**`logicx/data/` is a GENERATED ARTIFACT, reconstituted from real Logic "control" sessions.**
It is never hand-edited. The full provenance + recovery path:

1. **[`DONORS.md`](DONORS.md)** — the manifest. A table mapping each donor `.logicx` →
   **the click-by-click Logic recipe to remake it** → what's extracted from it → which `data/`
   file it feeds. (e.g. *"`mixed_base`: new project → add 1 Software Instrument + 1 Audio track,
   save."*)
2. **The donor sessions** live in `fixtures/` and `templates/` — the **source of truth** (and
   the test suite's). Keep them.
3. **[`bake_seeds.py`](bake_seeds.py)** — the regeneration script. It re-derives every file in
   `logicx/data/` from those donor sessions and self-verifies the round-trips.

So to update the bundled data for a new Logic version (or a different layout): remake the
relevant donor `.logicx` per `DONORS.md`, drop it into `fixtures/`/`templates/`, and run:

```bash
python3.12 bake_seeds.py        # re-derives logicx/data/ from the donor fixtures
```

`test_seeds.py` proves the loader reproduces the donor sessions byte-for-byte and that the
embedded path matches the original file-path donors.

## Repo layout

```
logicx/                 the importable package (pip-installable)
  __init__.py           public API: export_beatmap, ProjectData, TimeMap, synthesize_* …
  projectdata.py        the .logicx parser/writer + all synthesis + the CLI (main)
  midimap.py            stdlib Standard-MIDI-File reader (tempo/meter/markers/notes + CC#119 head/tail)
  data/                 ★ generated donor seeds (regenerate via ../bake_seeds.py)
bake_seeds.py           regenerates logicx/data/ from the donor fixtures   ← reconstitution
DONORS.md               donor provenance + Logic recipes                    ← reconstitution
PROJECTDATA_FORMAT.md   the byte-level format spec (the reverse-engineering)
fixtures/ , templates/  donor sessions (source of truth) + test fixtures
tools/                  the reverse-engineering workbench used to crack the format
test_*.py               the test suite (run each: `python3.12 test_X.py`)
```

## Other entry points

Beyond `export_beatmap`, the package exposes the lower-level synthesizers (all default to the
embedded data; pass a `.logicx` path to override): `synthesize_av_region_bundle` (M instrument
+ N audio tracks, each with MIDI notes / audio regions), `synthesize_instrument_bundle`,
`synthesize_track_region_bundle` (the audio combine), `synthesize_audio_tracks`, plus the
template-driven `export_all_multi` / `export_av_multi` / `export_midi_multi` and the meter/tempo
helper `TimeMap`.

## Development

The donor data, tests, and source are all in-repo and self-contained:

```bash
python3.12 bake_seeds.py                        # regenerate logicx/data/ from the donor fixtures
for t in test_*.py; do python3.12 "$t"; done    # run the test suite (~548 assertions)
```

`fixtures/` and `templates/` hold the donor + test `.logicx` sessions (the source of truth
for both the tests and `bake_seeds.py`). `tools/` has the reverse-engineering workbench used
to crack the format. `PROJECTDATA_FORMAT.md` is the full byte-level spec.

## Caveats

- Reverse-engineered against a specific Logic Pro version's `ProjectData` layout. A future Logic
  release could change the format; if it does, re-bake from fresh donor sessions per `DONORS.md`.
- Not affiliated with or endorsed by Apple. "Logic Pro" is a trademark of Apple Inc.
- The bundled audio in `fixtures/`/`templates/` is throwaway test material (sine tones,
  placeholders, sub-second slices) used purely to exercise the format.

## License

MIT — see [`LICENSE`](LICENSE).
