#!/usr/bin/env python3
"""
midimap.py — extract the tempo map and meter (time-signature) map from a
Standard MIDI File (SMF), for feeding Logic's ProjectData tempo map.

Pure stdlib. Use python3.12 (default python3 here is broken).

We parse every track fully (delta-times, running status, sysex, meta) so the
absolute tick of each event is correct, and collect:
  - tempo map : FF 51 03  Set Tempo      -> (tick, us_per_qn, bpm)
  - meter map : FF 58 04  Time Signature -> (tick, num, den, clocks, n32)
  - markers   : FF 06     Marker         -> (tick, text)   [bonus, for later]
plus the header division (ticks per quarter note).

Tempo in SMF is microseconds per quarter note; BPM = 60_000_000 / us.
Time-signature denominator is a power of two: actual = 2**dd.

Usage:
  midimap.py <file.mid>     # dump tempo + meter map
  midimap.py selftest       # build a known MIDI in memory, parse, assert
"""
from __future__ import annotations
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class MidiMap:
    format: int
    ntracks: int
    division: int                       # ticks per quarter note (PPQN)
    is_smpte: bool = False
    tempo_map: list = field(default_factory=list)   # (tick, us_per_qn, bpm)
    meter_map: list = field(default_factory=list)    # (tick, num, den, clocks, n32)
    markers: list = field(default_factory=list)      # (tick, text)
    notes: list = field(default_factory=list)        # (start, pitch, velocity, length, channel)
    start_ticks: list = field(default_factory=list)  # MIDI Start (0xFA) positions — head-sync
    stop_ticks: list = field(default_factory=list)   # MIDI Stop (0xFC) positions — audio tail
    end_tick: int = 0

    def head_sync_tick(self, target_ppq: int = 960):
        """The audio head-sync position (the FIRST MIDI Start 0xFA), rescaled to
        `target_ppq`; falls back to the earliest note-on, else None. (Pair with a
        MIDI Stop 0xFC for the tail — see `stop_ticks`/`audio_span`.)"""
        s = target_ppq / self.division
        if self.start_ticks:
            return round(min(self.start_ticks) * s)
        if self.notes:
            return round(min(t for t, *_ in self.notes) * s)
        return None

    def audio_span(self, target_ppq: int = 960):
        """(start, stop) ticks from the first MIDI Start (0xFA) and first MIDI Stop
        (0xFC), rescaled to `target_ppq`; either is None if absent."""
        s = target_ppq / self.division
        start = round(min(self.start_ticks) * s) if self.start_ticks else None
        stop = round(min(self.stop_ticks) * s) if self.stop_ticks else None
        return start, stop

    def bpm_at(self, tick: int) -> float:
        bpm = 120.0
        for t, _us, b in self.tempo_map:
            if t <= tick:
                bpm = b
            else:
                break
        return bpm

    def rescaled_tempo_map(self, target_ppq: int = 960):
        """Tempo map with ticks converted from file PPQN to target PPQN."""
        if self.is_smpte:
            raise ValueError("SMPTE division not supported for PPQ rescale")
        return [(round(t * target_ppq / self.division), us, bpm)
                for (t, us, bpm) in self.tempo_map]

    def rescaled_notes(self, target_ppq: int = 960, channel=None):
        """Notes as [(tick, pitch, velocity, length)] rescaled to target PPQN,
        sorted by start. `channel` (0-based) filters to one MIDI channel."""
        if self.is_smpte:
            raise ValueError("SMPTE division not supported for PPQ rescale")
        s = target_ppq / self.division
        return sorted((round(t * s), p, v, max(1, round(ln * s)))
                      for (t, p, v, ln, ch) in self.notes
                      if channel is None or ch == channel)


def _read_vlq(data: bytes, i: int):
    """Read a MIDI variable-length quantity. Returns (value, next_index)."""
    val = 0
    while True:
        b = data[i]
        i += 1
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            return val, i


def _parse_track(data: bytes, start: int, length: int, mm: MidiMap):
    i = start
    end = start + length
    abstick = 0
    running = None
    active = {}
    while i < end:
        dt, i = _read_vlq(data, i)
        abstick += dt
        b = data[i]
        if b == 0xFF:                       # meta event
            mtype = data[i + 1]
            mlen, j = _read_vlq(data, i + 2)
            mdata = data[j:j + mlen]
            i = j + mlen
            running = None
            if mtype == 0x51 and mlen == 3:
                us = (mdata[0] << 16) | (mdata[1] << 8) | mdata[2]
                bpm = 60_000_000 / us if us else 0.0
                mm.tempo_map.append((abstick, us, round(bpm, 6)))
            elif mtype == 0x58 and mlen >= 4:
                mm.meter_map.append((abstick, mdata[0], 1 << mdata[1], mdata[2], mdata[3]))
            elif mtype == 0x06:
                mm.markers.append((abstick, mdata.decode("latin-1", "replace")))
            elif mtype == 0x2F:             # end of track
                mm.end_tick = max(mm.end_tick, abstick)
        elif b in (0xF0, 0xF7):             # sysex
            slen, j = _read_vlq(data, i + 1)
            i = j + slen
            running = None
        elif b >= 0xF1:                     # system common (0xF1-0xF6) + real-time (0xF8-0xFE)
            if b == 0xFA:                   # MIDI Start  -> audio head-sync position
                mm.start_ticks.append(abstick)
            elif b == 0xFC:                 # MIDI Stop   -> audio tail position
                mm.stop_ticks.append(abstick)
            i += 1 + {0xF1: 1, 0xF2: 2, 0xF3: 1}.get(b, 0)   # consume any data bytes
            if b <= 0xF6:                   # system common resets running status; real-time doesn't
                running = None
        else:                               # channel message (+ running status)
            if b & 0x80:
                running = b
                status = b
                i += 1
            else:
                status = running
                if status is None:
                    raise ValueError(f"running status with no prior status at 0x{i:x}")
            nbytes = 1 if (status & 0xF0) in (0xC0, 0xD0) else 2
            if nbytes == 2:                     # capture note on/off pairs
                d1, d2 = data[i], data[i + 1]
                kind, chan = status & 0xF0, status & 0x0F
                if kind == 0x90 and d2 > 0:                          # note on
                    active[(chan, d1)] = (abstick, d2)
                elif kind == 0x80 or (kind == 0x90 and d2 == 0):     # note off
                    st = active.pop((chan, d1), None)
                    if st is not None:
                        mm.notes.append((st[0], d1, st[1], abstick - st[0], chan))
            i += nbytes
    for (chan, pitch), (start, vel) in active.items():               # close dangling
        mm.notes.append((start, pitch, vel, max(0, abstick - start), chan))


def parse(data: bytes) -> MidiMap:
    if data[:4] != b"MThd":
        raise ValueError("not an SMF (missing MThd)")
    hlen = struct.unpack_from(">I", data, 4)[0]
    fmt, ntracks, division = struct.unpack_from(">HHH", data, 8)
    is_smpte = bool(division & 0x8000)
    mm = MidiMap(format=fmt, ntracks=ntracks,
                 division=(division & 0x7FFF) if not is_smpte else division,
                 is_smpte=is_smpte)
    pos = 8 + hlen
    for _ in range(ntracks):
        if data[pos:pos + 4] != b"MTrk":
            raise ValueError(f"expected MTrk at 0x{pos:x}, got {data[pos:pos+4]!r}")
        tlen = struct.unpack_from(">I", data, pos + 4)[0]
        _parse_track(data, pos + 8, tlen, mm)
        pos += 8 + tlen
    mm.tempo_map.sort(key=lambda r: r[0])
    mm.meter_map.sort(key=lambda r: r[0])
    mm.markers.sort(key=lambda r: r[0])
    if not mm.tempo_map:
        mm.tempo_map.append((0, 500000, 120.0))      # SMF default
    if not mm.meter_map:
        mm.meter_map.append((0, 4, 4, 24, 8))         # SMF default
    return mm


def parse_file(path) -> MidiMap:
    return parse(Path(path).read_bytes())


# --- test SMF builder (ground truth, independent of the parser) -------------

def _vlq(n: int) -> bytes:
    out = bytearray([n & 0x7F])
    n >>= 7
    while n:
        out.insert(0, (n & 0x7F) | 0x80)
        n >>= 7
    return bytes(out)


def _chunk(tag: bytes, body: bytes) -> bytes:
    return tag + struct.pack(">I", len(body)) + body


def build_test_midi() -> bytes:
    """Format-1, 480 PPQN. Conductor: 4/4 @120 at tick 0; 3/4 @90 at tick 1920.
    Plus a note track exercising running status."""
    div = 480
    # conductor track
    cond = bytearray()
    cond += _vlq(0) + b"\xFF\x58\x04" + bytes([4, 2, 24, 8])     # 4/4
    cond += _vlq(0) + b"\xFF\x51\x03" + (500000).to_bytes(3, "big")  # 120 BPM
    cond += _vlq(1920) + b"\xFF\x58\x04" + bytes([3, 2, 24, 8])  # 3/4 after 1 bar
    cond += _vlq(0) + b"\xFF\x51\x03" + (666667).to_bytes(3, "big")  # ~90 BPM
    cond += _vlq(0) + b"\xFF\x2F\x00"
    # note track: a MIDI Start (head-sync), two Note Ons via running status, a MIDI Stop (tail)
    notes = bytearray()
    notes += _vlq(0) + b"\xFA"                 # MIDI Start (0xFA) @ tick 0 — head-sync
    notes += _vlq(0) + b"\x90\x3C\x64"        # note on C4
    notes += _vlq(480) + b"\x3C\x00"          # running status: note on C4 vel0 (off)
    notes += _vlq(0) + b"\xFC"                 # MIDI Stop (0xFC) @ tick 480 — tail
    notes += _vlq(0) + b"\xFF\x2F\x00"
    hdr = struct.pack(">HHH", 1, 2, div)
    return _chunk(b"MThd", hdr) + _chunk(b"MTrk", bytes(cond)) + _chunk(b"MTrk", bytes(notes))


def _selftest() -> int:
    mm = parse(build_test_midi())
    print(f"format={mm.format} ntracks={mm.ntracks} division={mm.division} end_tick={mm.end_tick}")
    print("tempo_map:", mm.tempo_map)
    print("meter_map:", mm.meter_map)
    ok = True

    def check(name, got, exp):
        nonlocal ok
        status = "OK " if got == exp else "BAD"
        if got != exp:
            ok = False
        print(f"  [{status}] {name}: got {got} exp {exp}")

    check("division", mm.division, 480)
    check("tempo count", len(mm.tempo_map), 2)
    check("tempo[0]", mm.tempo_map[0][:2], (0, 500000))
    check("tempo[0] bpm", round(mm.tempo_map[0][2]), 120)
    check("tempo[1] tick", mm.tempo_map[1][0], 1920)
    check("tempo[1] bpm", round(mm.tempo_map[1][2]), 90)
    check("meter count", len(mm.meter_map), 2)
    check("meter[0]", mm.meter_map[0][:3], (0, 4, 4))
    check("meter[1]", mm.meter_map[1][:3], (1920, 3, 4))
    check("rescale->960 bar2 tick", mm.rescaled_tempo_map(960)[1][0], 3840)
    check("note survives transport msgs", mm.rescaled_notes(960), [(0, 60, 100, 960)])
    check("MIDI Start (0xFA) tick", mm.start_ticks, [0])
    check("MIDI Stop (0xFC) tick", mm.stop_ticks, [480])
    check("head_sync_tick(960)", mm.head_sync_tick(960), 0)
    check("audio_span(960)", mm.audio_span(960), (0, 960))
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


def _dump(path: str) -> int:
    mm = parse_file(path)
    print(f"{path}")
    print(f"  format={mm.format}  tracks={mm.ntracks}  division={mm.division} PPQN"
          f"{'  (SMPTE!)' if mm.is_smpte else ''}  end_tick={mm.end_tick}")
    print(f"  tempo map ({len(mm.tempo_map)}):")
    for t, us, bpm in mm.tempo_map:
        print(f"    tick {t:>10}  {bpm:>8.3f} BPM  ({us} us/qn)")
    print(f"  meter map ({len(mm.meter_map)}):")
    for t, num, den, clk, n32 in mm.meter_map:
        print(f"    tick {t:>10}  {num}/{den}  (clocks/click={clk}, 32nds/qn={n32})")
    if mm.markers:
        print(f"  markers ({len(mm.markers)}):")
        for t, txt in mm.markers:
            print(f"    tick {t:>10}  {txt!r}")
    return 0


def main(argv=None):
    argv = argv or sys.argv[1:]
    if not argv:
        print(__doc__)
        return 1
    if argv[0] == "selftest":
        return _selftest()
    return _dump(argv[0])


if __name__ == "__main__":
    raise SystemExit(main())
