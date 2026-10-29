#!/usr/bin/env python3
"""Write-path mutators for the reverse-engineered ProjectData subsystems.

Where `inspect.py` reads the RE'd byte layouts (§14–§34), this edits them — proving the
format is not just round-trippable but *modifiable*. These are FIXED-SIZE, in-place edits
(no record grows/shrinks), so the change is a handful of bytes and the rest of the file
stays byte-identical; the result re-parses and round-trips.

    pd = ProjectData.parse(raw)
    set_mixer(pd, "Audio 1", fader=100, pan=32)   # §15 OCuA
    open(out,"wb").write(pd.serialize())
"""
from __future__ import annotations

from .inspect import _OCUA_TYPE, _u16


def _mixer_records(pd):
    """Yield (record, payload_offset) for every full OCuA strip (skips 14-byte stubs)."""
    for r in pd.records:
        if r.tag != b"OCuA":
            continue
        pay = r.raw[0x24:]
        if len(pay) < 0x5a or _u16(pay, 0x0a) != 0x1235:
            continue
        if pay[0x04] == 0xff or pay[0x04] not in _OCUA_TYPE:
            continue
        yield r


def set_mixer(pd, name: str, *, fader: int | None = None, pan: int | None = None) -> int:
    """Set a mixer strip's fader and/or pan by strip name (§15 OCuA). `fader`/`pan` are
    0..127 bytes (fader default 90, pan 64 = center). Fader is written to BOTH the value
    (@pay+0x55) and its mirror (@pay+0x77), which §15 requires to stay equal. Returns the
    number of strips matched (names are not globally unique)."""
    n = 0
    for r in _mixer_records(pd):
        pay_off = 0x24
        base = pay_off + 0x3c
        strip_name = r.raw[base:base + 16].split(b"\x00", 1)[0].decode("latin-1", "replace").strip()
        if strip_name != name:
            continue
        raw = bytearray(r.raw)
        if fader is not None:
            if not 0 <= fader <= 127:
                raise ValueError("fader must be 0..127")
            raw[pay_off + 0x55] = fader
            raw[pay_off + 0x77] = fader            # §15: mirror must equal the value
        if pan is not None:
            if not 0 <= pan <= 127:
                raise ValueError("pan must be 0..127")
            raw[pay_off + 0x59] = pan
        r.raw = bytes(raw)
        n += 1
    return n
