#!/usr/bin/env python3.12
"""Self-tests for the `LGWV` waveform-overview writer (`_ensure_wav_lgwv`).

Run:  python3.12 test_lgwv.py
Pure-Python; no Logic round-trip needed. Exits non-zero on first failure.

The 24-bit path has a FAST implementation (widen to int32, let `min`/`max` run at C speed)
and a portable per-sample fallback. 24-bit is the professional norm, so the fast path runs
on essentially every real export — these tests pin it byte-identical to the fallback,
especially on the inputs where the two could plausibly diverge:

  * negative samples — the fast path recovers `v` by floor-dividing, the fallback decodes
    directly, and `_i8` truncates TOWARD ZERO; those disagree for negatives unless the
    recovery is exact
  * exact multiples of the int8 divisor, and values one below them
  * a partial final bin (frame count not a multiple of 256)
"""
import random
import struct

from logicx.projectdata import _ensure_wav_lgwv

PASS = 0


def eq(got, want, msg):
    global PASS
    assert got == want, f"FAIL {msg}: got {got!r}, want {want!r}"
    PASS += 1


def wav24(frames, ch, value_of):
    """A 24-bit WAVE whose sample i on each channel is `value_of(i)`."""
    pcm = bytearray()
    for i in range(frames * ch):
        pcm += (value_of(i) & 0xFFFFFF).to_bytes(3, "little")
    return (b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVEfmt "
            + struct.pack("<IHHIIHH", 16, 1, ch, 48000, 48000 * ch * 3, ch * 3, 24)
            + b"data" + struct.pack("<I", len(pcm)) + bytes(pcm))


def peaks(data):
    """The peak bytes of the appended LGWV chunk: [tag][u32 size][u32 frames][u32 cksum]."""
    out = _ensure_wav_lgwv(data)
    assert out is not data and b"LGWV" in out, "no LGWV chunk appended"
    return out[out.rfind(b"LGWV") + 16:]


def reference(data):
    """The portable per-sample implementation, kept here as the oracle."""
    i, ch, bits, off, sz = 12, 2, 16, None, 0
    while i + 8 <= len(data):
        cid = data[i:i + 4]
        n = struct.unpack_from("<I", data, i + 4)[0]
        if cid == b"fmt " and n >= 16:
            _af, ch, _sr, _br, _ba, bits = struct.unpack_from("<HHIIHH", data, i + 8)
        elif cid == b"data":
            off, sz = i + 8, n
        i += 8 + n + (n & 1)
    bps = bits // 8
    frames = sz // (ch * bps)
    pcm = data[off:off + frames * ch * bps]
    div = 1 << (bits - 8)
    out = bytearray()
    for b in range((frames + 255) // 256):
        mn, mx = 0x7FFFFFFF, -0x80000000
        for o in range(b * 256 * ch * 3, min((b + 1) * 256 * ch, frames * ch) * 3, 3):
            v = int.from_bytes(pcm[o:o + 3], "little", signed=True)
            mn = min(mn, v)
            mx = max(mx, v)
        if mn > mx:
            mn = mx = 0
        out += struct.pack("<bb", max(-128, min(127, int(mn / div))),
                           max(-128, min(127, int(mx / div))))
    return bytes(out)


random.seed(7)
CASES = {
    "silence":            wav24(700, 1, lambda i: 0),
    "negative ramp":      wav24(700, 1, lambda i: -i),
    "exact -div multiples": wav24(700, 1, lambda i: -65536 * (i % 40)),
    "one below -div":     wav24(700, 1, lambda i: -65536 * (i % 40) - 1),
    "positive ramp":      wav24(700, 1, lambda i: i * 4096),
    "full-scale extremes": wav24(600, 1, lambda i: -8388608 if i % 2 else 8388607),
    "random stereo":      wav24(1000, 2, lambda i: random.randint(-8388608, 8388607)),
    "partial final bin":  wav24(257, 1, lambda i: (-1) ** i * i * 4096),
    "single frame":       wav24(1, 1, lambda i: -12345),
}
for name, data in CASES.items():
    eq(peaks(data), reference(data), f"24-bit fast path matches the fallback: {name}")

# the chunk SIZE is the load-bearing part (it must equal what Logic itself would write)
for name, data in CASES.items():
    out = _ensure_wav_lgwv(data)
    k = out.rfind(b"LGWV")
    body = struct.unpack_from("<I", out, k + 4)[0]
    frames = struct.unpack_from("<I", out, k + 8)[0]
    eq(body, 8 + 2 * ((frames + 255) // 256), f"LGWV body size = 8 + 2*ceil(frames/256): {name}")

# idempotent: a file that already carries an overview is returned untouched
once = _ensure_wav_lgwv(CASES["random stereo"])
eq(_ensure_wav_lgwv(once), once, "already-LGWV input is unchanged")

# a 16-bit file still round-trips through its own (array-based) path
pcm16 = b"".join(struct.pack("<h", (i * 137) % 32767 - 16000) for i in range(600))
w16 = (b"RIFF" + struct.pack("<I", 36 + len(pcm16)) + b"WAVEfmt "
       + struct.pack("<IHHIIHH", 16, 1, 1, 44100, 88200, 2, 16)
       + b"data" + struct.pack("<I", len(pcm16)) + pcm16)
eq(len(peaks(w16)), 2 * ((600 + 255) // 256), "16-bit path still produces one peak pair per bin")

print(f"OK — {PASS} assertions passed (LGWV 24-bit fast path vs fallback)")
