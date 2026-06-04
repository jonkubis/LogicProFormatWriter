#!/usr/bin/env python3.12
"""Regression test for the end-to-end BEATMAP export (projectdata.export_beatmap):
a beatmap MIDI + audio files (wav/aif/… any CoreAudio format) -> one self-contained
.logicx (audio tracks at the head-sync point, named after the files, + tempo/meter/
markers from the MIDI). Logic-validated 2026-06-01 (fixtures/TEST_beatmap.logicx).

Environment-dependent (needs macOS `afconvert` + a `~/Music/temp/*.mid`); SKIPS cleanly
if either is absent. Exercises the multi-format normalize path: a same-format WAV (copied
verbatim), an AIFF (decoded), and an off-format 48 kHz/mono WAV (resampled + upmixed).
Run: python3.12 test_beatmap.py
"""
import re
import shutil
import subprocess
import tempfile
import plistlib
from pathlib import Path
from logicx.projectdata import export_beatmap, ProjectData, _u32
import logicx.projectdata as st

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "templates" / "F21_multitrack_regions.logicx" / "Media" / "Audio Files" / "047.wav"
MIDIS = sorted(Path.home().glob("Music/temp/*.mid"))
PASS = 0


def ok(c, m):
    global PASS
    assert c, "FAIL " + m
    PASS += 1


if not shutil.which("afconvert") or not SRC.exists() or not MIDIS:
    print("(skipping test_beatmap: needs macOS afconvert + F21 wav + a ~/Music/temp/*.mid)")
else:
    tmp = Path(tempfile.mkdtemp())
    try:
        wav = tmp / "song_a.wav"
        shutil.copyfile(SRC, wav)                                            # already 44100/2/16
        aif = tmp / "song_b.aif"
        subprocess.run(["afconvert", "-f", "AIFF", "-d", "BEI16@44100", str(SRC), str(aif)],
                       check=True, capture_output=True)                      # AIFF, decoded
        off = tmp / "song_c.wav"
        subprocess.run(["afconvert", "-f", "WAVE", "-d", "LEI16@48000", "-c", "1", str(SRC), str(off)],
                       check=True, capture_output=True)                      # 48k MONO -> resample+upmix
        out = tmp / "bm.logicx"

        s = export_beatmap(MIDIS[0], [wav, aif, off], out, head_sync=3840, verbose=False)
        ok(s["tracks"] == 3, f"3 audio tracks ({s['tracks']})")
        ok(s["names"] == ["song_a", "song_b", "song_c"], f"tracks named after sources {s['names']}")
        ok(s["head_sync_tick"] == 3840, "explicit head-sync honored")

        pd = ProjectData.parse((out / "Alternatives" / "000" / "ProjectData").read_bytes())
        ok(ProjectData.parse(pd.serialize()).serialize() == pd.serialize(), "bundle round-trips")

        # self-contained: media inside, relative AudioFiles, NO absolute-path leaks
        raw = (out / "Alternatives" / "000" / "ProjectData").read_bytes()
        leaks = (re.findall(rb"/Users/[ -~]{3,40}", raw) + re.findall(rb"/private/[ -~]{3,40}", raw)
                 + re.findall(rb"/var/folders/[ -~]{3,40}", raw) + re.findall(rb"/tmp/[ -~]{3,40}", raw))
        ok(not leaks, f"no absolute-path leaks ({leaks[:2]})")
        media = sorted(p.name for p in (out / "Media" / "Audio Files").glob("*.wav"))
        ok(media == ["song_a.wav", "song_b.wav", "song_c.wav"], f"3 normalized WAVs in Media ({media})")
        md = plistlib.loads((out / "Alternatives" / "000" / "MetaData.plist").read_bytes())
        ok(md.get("NumberOfTracks") == 3, f"MetaData NumberOfTracks=3 ({md.get('NumberOfTracks')})")
        ok(md.get("AudioFiles") == [f"Audio Files/{n}" for n in media], "AudioFiles relative + complete")

        # the off-format 48k/mono input was normalized to 44100/stereo/16
        import wave
        with wave.open(str(out / "Media" / "Audio Files" / "song_c.wav"), "rb") as w:
            ok(w.getframerate() == 44100 and w.getnchannels() == 2 and w.getsampwidth() == 2,
               "off-format input normalized to 44100/stereo/16")

        # all three clips placed at the head-sync (one 0x24 audio event per track @ that tick)
        from logicx.projectdata import _arrange_container
        arr = pd.records.index(_arrange_container(pd.records))
        ev = next(r for i, r in enumerate(pd.records) if i > arr and r.tag == b"qSvE"
                  and _u32(r.raw, 0x08) == 0x040000 and ProjectData._qsve_has_audio_event(r))
        body = ev.raw[st.REC_HEADER_SIZE:st.REC_HEADER_SIZE + _u32(ev.raw, st.REC_SIZE_OFF)]
        ticks = [_u32(body, o + 0x04) - ProjectData.AUDIO_REGION_ORIGIN
                 for o in range(0, len(body) - 80, 4) if _u32(body, o) == 0x24]
        ok(len(ticks) == 3 and all(t == 3840 for t in ticks), f"3 clips all at the head-sync tick {ticks}")

        # tempo from the MIDI made it in
        from logicx import midimap
        if midimap.parse_file(MIDIS[0]).tempo_map:
            ok(len(pd.get_tempo_map()) >= 1, "tempo map applied from the MIDI")

        # NATIVE 48 kHz: a 48 kHz source auto-detects -> project SR 48000 (Logic-validated)
        out48 = tmp / "bm48.logicx"
        export_beatmap(MIDIS[0], [off], out48, head_sync=0, verbose=False)   # `off` is 48 kHz
        md48 = plistlib.loads((out48 / "Alternatives" / "000" / "MetaData.plist").read_bytes())
        ok(md48.get("SampleRate") == 48000, f"48 kHz source -> project SR auto-detected 48000 ({md48.get('SampleRate')})")
        with wave.open(str(out48 / "Media" / "Audio Files" / "song_c.wav"), "rb") as w:
            ok(w.getframerate() == 48000 and w.getnchannels() == 2 and w.getsampwidth() == 2,
               "48 kHz source kept native at 48000/stereo/16")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

print(f"OK — {PASS} assertions passed (export_beatmap pipeline)")
