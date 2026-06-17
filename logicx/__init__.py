"""logicx — generate native Logic Pro ``.logicx`` sessions from a MIDI + audio files,
no Logic required. Reverse-engineered from scratch; every content type is Logic-validated.

Self-contained: the donor data needed to seed sessions is bundled in ``logicx/data/`` (62 KB),
so there are NO loose ``.logicx`` donors at runtime.

★ The bundled ``data/`` is a GENERATED ARTIFACT, reconstituted from real Logic "control"
sessions. To rebuild or update it: see ``DONORS.md`` (each donor's click-by-click Logic
recipe + what's extracted) and run ``python3.12 bake_seeds.py`` (the regeneration script,
at the repo root). The byte-level format spec is ``PROJECTDATA_FORMAT.md`` (§13 = this layer).

Quick start:
    from logicx import export_beatmap
    export_beatmap("song.mid", ["drums.mp3", "bass.wav", "vox.aif"], "out.logicx")
"""
from . import midimap, projectdata, alac
from .midimap import MidiMap, parse_file as parse_midi
from .projectdata import (
    ProjectData, TimeMap, IdGen,
    # ★ the beatmap pipeline (MIDI + audio files -> one self-contained .logicx)
    export_beatmap,
    # unified track + content synthesis (audio + MIDI), from the embedded mixed base
    synthesize_av_region_bundle, synthesize_av_bundle, synthesize_av_tracks,
    synthesize_instrument_bundle, synthesize_audio_on_mixed_bundle,
    # audio-only: track + region synthesis (the combine) and bare track synthesis
    synthesize_track_region_bundle, synthesize_audio_tracks,
    # template-driven exporters (tempo/meter/markers + audio/MIDI from donor templates)
    export_logicx, export_all_multi, export_av_multi, export_midi_multi,
)
# ALAC / CAF (Apple Lossless) audio — shrink a WAV bundle ~3-4x; Logic plays it natively
from .alac import convert_bundle_to_alac, wav_lfua_to_caf

__all__ = [
    "export_beatmap", "ProjectData", "TimeMap", "IdGen", "MidiMap", "parse_midi",
    "synthesize_av_region_bundle", "synthesize_av_bundle", "synthesize_av_tracks",
    "synthesize_instrument_bundle", "synthesize_audio_on_mixed_bundle",
    "synthesize_track_region_bundle", "synthesize_audio_tracks",
    "export_logicx", "export_all_multi", "export_av_multi", "export_midi_multi",
    "convert_bundle_to_alac", "wav_lfua_to_caf",
    "midimap", "projectdata", "alac",
]
