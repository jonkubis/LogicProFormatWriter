#!/usr/bin/env python3
"""ALAC / CAF audio — shrink a WAV-based `.logicx` by re-encoding its audio as Apple
Lossless (ALAC) in `.caf` containers, which Logic plays natively. Lossless, typically
3-4x smaller across a stem-heavy project.

THE FORMAT DELTA (RE'd from Logic control sessions — see PROJECTDATA_FORMAT.md §8.6):
a region's audio is described by an `lFuA` record carrying a format descriptor. The WAV
and ALAC forms of that record are byte-identical except **6 descriptor-anchored changes**
(locate `b"EVAW"` at offset `d`):

  1. filename extension `.wav` -> `.caf`     (the UTF-16LE + any ASCII copy)
  2. type flag        `d-0x1c3` (u8) : 0x01 -> 0x11
  3. compressed mark  `d-0x142` (4B) : 0    -> "PMOC"  (= "COMP", reversed)
  4. descriptor magic `d+0x00`  (4B) : EVAW (WAVE) -> ffac (caff)
  5. format const     `d+0x08`  (u32): 0x2c -> 0
  6. size field       `d-0x32`  (u32): on-disk file size -> DECODED PCM bytes

frames/rate/channels/bits (d+0x0c/0x14/0x18/0x1a) are unchanged (ALAC is lossless).
The region/pool/registry records are container-agnostic — nothing else changes. The
size field switching to *decoded* size (not file size) is what makes this robust: unlike
WAV — where the file-size field must equal the on-disk size, so Logic's overview rewrite
breaks it — the CAF reference is independent of the compressed file, so plain `afconvert`
output works. (Logic appends a cosmetic `ovvw` overview chunk to CAFs on import.)

Requires macOS `afconvert` for the transcode.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import wave
from pathlib import Path

from .projectdata import ProjectData


def _u16(b, o): return int.from_bytes(b[o:o + 2], "little")
def _u32(b, o): return int.from_bytes(b[o:o + 4], "little")


def wav_lfua_to_caf(raw: bytes) -> bytes:
    """Transform a WAV-style `lFuA` record into its ALAC/CAF form. Returns `raw`
    unchanged if it carries no `EVAW` (WAVE) descriptor (already CAF / not a file ref)."""
    d = raw.find(b"EVAW")
    if d < 0:
        return raw
    frames = _u32(raw, d + 0x0c)
    channels = _u16(raw, d + 0x18)
    bits = _u16(raw, d + 0x1a) or 16
    pcm_bytes = frames * channels * (bits // 8)          # ALAC size field = DECODED size

    # filename extension .wav -> .caf (UTF-16LE copy + any ASCII copy); equal length -> no shift
    out = (raw.replace(".wav".encode("utf-16-le"), ".caf".encode("utf-16-le"))
              .replace(b".wav", b".caf"))
    b = bytearray(out)
    d = bytes(b).find(b"EVAW")                            # offset stable (replaces are equal-length)
    b[d:d + 4] = b"ffac"                                  # 4. descriptor  WAVE -> caff
    struct.pack_into("<I", b, d + 0x08, 0)               # 5. format const 0x2c -> 0
    struct.pack_into("<I", b, d - 0x32, pcm_bytes)        # 6. size field  file-size -> PCM bytes
    b[d - 0x1c3] = 0x11                                   # 2. type flag   0x01 -> 0x11
    b[d - 0x142:d - 0x142 + 4] = b"PMOC"                  # 3. compressed marker  COMP (reversed)
    return bytes(b)


def convert_bundle_to_alac(bundle, *, verbose: bool = True) -> dict:
    """In place: transcode every WAV in `bundle` to ALAC/CAF (`afconvert`) and rewrite
    the `lFuA` records (`wav_lfua_to_caf`). The session is byte-for-byte what Logic writes
    for an ALAC import. Returns a summary dict. Requires macOS `afconvert`."""
    bundle = Path(bundle)
    alt = bundle / "Alternatives" / "000"
    media = bundle / "Media" / "Audio Files"
    pdp = alt / "ProjectData"
    if not pdp.exists():
        raise FileNotFoundError(f"not a .logicx bundle: {bundle}")

    wavs = sorted(media.glob("*.wav")) if media.is_dir() else []
    wav_bytes = caf_bytes = 0
    for w in wavs:
        caf = w.with_suffix(".caf")
        subprocess.run(["afconvert", "-f", "caff", "-d", "alac", str(w), str(caf)],
                       check=True, capture_output=True)
        wav_bytes += w.stat().st_size
        caf_bytes += caf.stat().st_size
        w.unlink()

    pd = ProjectData.parse(pdp.read_bytes())
    converted = 0
    for r in pd.records:
        if r.tag == b"lFuA" and r.raw.find(b"EVAW") >= 0:
            r.raw = wav_lfua_to_caf(r.raw)
            converted += 1
    data = pd.serialize()
    if ProjectData.parse(data).serialize() != data:
        raise RuntimeError("ALAC ProjectData failed round-trip")
    pdp.write_bytes(data)

    summary = {"files": len(wavs), "lfua_converted": converted,
               "wav_bytes": wav_bytes, "caf_bytes": caf_bytes,
               "ratio": (caf_bytes / wav_bytes) if wav_bytes else None}
    if verbose:
        pct = f"{summary['ratio'] * 100:.0f}%" if summary["ratio"] else "n/a"
        print(f"ALAC: {len(wavs)} files, {converted} lFuA rewritten; "
              f"{wav_bytes // (1024 * 1024)} MB WAV -> {caf_bytes // (1024 * 1024)} MB CAF ({pct})")
    return summary
