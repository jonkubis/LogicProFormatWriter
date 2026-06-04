#!/usr/bin/env python3
"""
projectdata.py — structural parser/writer for Logic Pro `ProjectData`.

Foundation for the from-scratch `.logicx` exporter. Models ProjectData as:

    ROOT frame (24-byte header; uint32 LE length @ +0x10 = filesize - 24)
      payload = a flat sequence of RECORDS, each:
        36-byte header, then a payload of `uint32 LE size @ +0x1c` bytes.
      (The first record is `gnoS` (Song); its payload contains nested
       2347c0ab sub-frames + global settings + tempo — kept opaque for now.)

Round-trip invariant: parse(data).serialize() == data, byte-for-byte.

Stdlib only. Use python3.12 (default python3 on this machine is broken).

Primary entry point — write a Logic project from a MIDI file's maps:
    projectdata.py export <base.logicx> <file.mid> <out.logicx>
  (base must be a SETTLED template with a marker track; see export_logicx.)
Synthesize N extra audio tracks onto a pre-allocated template (task #34):
    projectdata.py synthtracks <template.logicx> <out.logicx> <count> [--seed N]
  (template = a session of N audio tracks with all-but-one deleted; see
   synthesize_audio_tracks / activate_audio_track.)
Synthesize arbitrary audio regions from a donor with >=1 region (task #35):
    projectdata.py synthregions <donor.logicx> <out.logicx> track:wav:tick ...
THE COMBINE — N synth tracks each with their synth regions, one call (task #36):
    projectdata.py synthtrackregions <track_template> <prototype> <out> track:wav:tick ...
  (track_template = a '1 from 64'-style pre-allocated template; prototype = any
   session with >=1 audio region, e.g. F18; see synthesize_track_region_bundle.)
Also: validate <paths...> | settempo | settempomap | setmidimaps
"""
from __future__ import annotations
import os
import struct
import sys
import random
from pathlib import Path

MAGIC = b"\x23\x47\xc0\xab"
ROOT_HEADER_SIZE = 0x18   # 24-byte root frame header
REC_HEADER_SIZE = 0x24    # 36-byte record header
REC_SIZE_OFF = 0x1c       # uint32 LE payload size within a record header

KNOWN_TAGS = {
    b"karT", b"qeSM", b"qSvE", b"gRuA", b"tSxT", b"LFUA", b"lFuA",
    b"PMOC", b"MroC", b"tSnI", b"snrT", b"gnoS",
}


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


class Record:
    __slots__ = ("tag", "raw")

    def __init__(self, tag: bytes, raw: bytes):
        self.tag = tag
        self.raw = raw

    @property
    def is_magic(self):
        return self.tag == MAGIC

    @property
    def payload_size(self):
        return _u32(self.raw, REC_SIZE_OFF)

    def tagstr(self):
        return self.tag.decode("latin-1")

    def __len__(self):
        return len(self.raw)

    def __repr__(self):
        return f"<Record {self.tagstr()!r} {len(self.raw)}B>"


class ProjectData:
    def __init__(self, root_header: bytes, records: list[Record]):
        self.root_header = bytes(root_header)
        self.records = records

    @classmethod
    def parse(cls, data: bytes) -> "ProjectData":
        if data[:4] != MAGIC:
            raise ValueError(f"bad magic {data[:4].hex()}")
        root_len = _u32(data, 0x10)
        end = ROOT_HEADER_SIZE + root_len
        if end != len(data):
            raise ValueError(f"root len {root_len} -> end {end} != filesize {len(data)}")
        records = []
        pos = ROOT_HEADER_SIZE
        while pos < end:
            tag = data[pos:pos + 4]
            if tag == MAGIC:
                size = ROOT_HEADER_SIZE + _u32(data, pos + 0x10)
            else:
                # Trust the structural rule for any record. A 4-byte printable
                # tag is the desync canary: if our size math drifts, the next
                # "tag" lands on non-printable bytes and we bail loudly.
                if not all(0x20 <= c < 0x7f for c in tag):
                    raise ValueError(f"desync: non-printable tag {tag.hex()} at 0x{pos:x}")
                size = REC_HEADER_SIZE + _u32(data, pos + REC_SIZE_OFF)
            if size < REC_HEADER_SIZE or pos + size > end:
                raise ValueError(f"bad size {size} for {tag!r} at 0x{pos:x} (end 0x{end:x})")
            records.append(Record(tag, data[pos:pos + size]))
            pos += size
        if pos != end:
            raise ValueError(f"walk ended at 0x{pos:x} != end 0x{end:x}")
        return cls(data[:ROOT_HEADER_SIZE], records)

    def serialize(self) -> bytes:
        body = b"".join(r.raw for r in self.records)
        hdr = bytearray(self.root_header)
        struct.pack_into("<I", hdr, 0x10, len(body))  # root length = body size
        return bytes(hdr) + bytes(body)

    def histogram(self):
        h = {}
        for r in self.records:
            h[r.tagstr()] = h.get(r.tagstr(), 0) + 1
        return h

    # --- mutations -----------------------------------------------------------
    # Tempo (uint32 LE, BPM*10000) is replicated at FOUR authoritative slots,
    # verified by diffing F0(120)->F1(137.5):
    #   three inside the gnoS (record 0) payload at file 0xAA, 0x102, 0x3BE
    #     => gnoS-relative 0x92, 0xEA, 0x3A6 (gnoS starts at file 0x18);
    #   one in the tempo-track qSvE event at qSvE+0x34.
    # NOTE: file 0xAE *also* holds 0x00124F80 in a 120-BPM project but is NOT
    # tempo (it did not change in F1) — never blind-scan for the old value.
    GNOS_TEMPO_RELOFFS = (0x92, 0xea, 0x3a6)
    QSVE_TEMPO_OFF = 0x34

    def current_tempo_raw(self) -> int:
        # 0x3a6 is the stable "initial tempo" slot (0x92 can hold a
        # playhead-dependent value once a tempo map exists).
        return _u32(self.records[0].raw, self.GNOS_TEMPO_RELOFFS[2])

    def set_tempo(self, bpm: float) -> int:
        """Patch the four authoritative tempo fields in place. Returns #changed."""
        oldv = self.current_tempo_raw()
        newv = round(bpm * 10000)
        changed = 0
        g = bytearray(self.records[0].raw)
        for off in self.GNOS_TEMPO_RELOFFS:
            assert _u32(g, off) == oldv, f"gnoS+0x{off:x} != current tempo {oldv}"
            struct.pack_into("<I", g, off, newv)
            changed += 1
        self.records[0].raw = bytes(g)
        for r in self.records:
            if r.tag == b"qSvE" and len(r.raw) > self.QSVE_TEMPO_OFF + 4 \
                    and _u32(r.raw, self.QSVE_TEMPO_OFF) == oldv:
                raw = bytearray(r.raw)
                struct.pack_into("<I", raw, self.QSVE_TEMPO_OFF, newv)
                r.raw = bytes(raw)
                changed += 1
        return changed

    # --- tempo MAP (multi-point) --------------------------------------------
    TEMPO_EVENT_SIZE = 0x20
    TEMPO_PAYLOAD_OFF = 0x24                  # events begin here (= header size)
    TEMPO_ORIGIN = 38400                      # position of bar 1 (960-PPQ ticks)
    TEMPO_TAIL = bytes.fromhex("f1000000ffffff3f0000000000000000")
    ALTPOS_ORIGIN = 7_200_000                 # 1hr SMPTE @ ~2000/sec
    ALTPOS_PER_SEC = 2000

    def _find_tempo_qsve(self):
        # The tempo track is the unique qSvE whose payload begins with a tempo
        # event marker (60 00 00 00). Identify structurally, not by value.
        for idx, r in enumerate(self.records):
            if (r.tag == b"qSvE" and len(r.raw) > 0x38
                    and r.raw[0x24:0x28] == b"\x60\x00\x00\x00"):
                return idx
        return None

    @staticmethod
    def _enc_tempo_event(pos: int, bpm: float, altpos: int, flag: int) -> bytes:
        ev = (b"\x60\x00\x00\x00"
              + struct.pack("<Q", pos)
              + b"\x7f\x00\x00" + bytes([flag])
              + struct.pack("<I", round(bpm * 10000))
              + b"\x00\x00\x40\x88"
              + struct.pack("<I", altpos)
              + b"\x00\x00\x00\x00")
        assert len(ev) == 0x20
        return ev

    @staticmethod
    def decode_tempo_events(qsve_raw: bytes):
        """Return [(position, flag, bpm_raw, altpos)] from a tempo qSvE record."""
        psize = _u32(qsve_raw, REC_SIZE_OFF)
        body = qsve_raw[0x24:0x24 + psize]
        out = []
        i = 0
        while i + 0x20 <= len(body) and body[i:i + 4] == b"\x60\x00\x00\x00":
            pos = struct.unpack_from("<Q", body, i + 4)[0]
            flag = body[i + 0x0f]
            tempo = _u32(body, i + 0x10)
            altpos = _u32(body, i + 0x18)
            out.append((pos, flag, tempo, altpos))
            i += 0x20
        return out

    def set_tempo_map(self, points, ppq: int = 960):
        """points = [(tick, bpm)] with tick at `ppq` resolution from song start
        (tick 0 = bar 1). Rebuilds the tempo qSvE. Returns the event count."""
        idx = self._find_tempo_qsve()
        if idx is None:
            raise ValueError("tempo qSvE not found")
        # normalize: scale to 960 PPQ, sort, dedup same tick (last wins), ensure t0
        scaled = {}
        for tick, bpm in points:
            scaled[round(tick * 960 / ppq)] = float(bpm)
        items = sorted(scaled.items())
        if not items or items[0][0] != 0:
            items.insert(0, (0, items[0][1] if items else 120.0))
        # build events with altpos integrated from the tempo curve
        events = bytearray()
        cum_sec = 0.0
        prev_tick = prev_bpm = None
        for n, (tick, bpm) in enumerate(items):
            if prev_tick is not None:
                cum_sec += ((tick - prev_tick) / 960.0) * (60.0 / prev_bpm)
            altpos = self.ALTPOS_ORIGIN + round(cum_sec * self.ALTPOS_PER_SEC)
            flag = 0x00 if n == 0 else 0x01
            events += self._enc_tempo_event(self.TEMPO_ORIGIN + tick, bpm, altpos, flag)
            prev_tick, prev_bpm = tick, bpm
        # capture old tempo BEFORE rebuilding (gnoS slots still hold it)
        oldv = self.current_tempo_raw()
        payload = bytes(events) + self.TEMPO_TAIL
        r = self.records[idx]
        hdr = bytearray(r.raw[:self.TEMPO_PAYLOAD_OFF])
        struct.pack_into("<I", hdr, REC_SIZE_OFF, len(payload))
        r.raw = bytes(hdr) + payload
        # keep the 3 gnoS single-tempo slots consistent with the first point
        newv0 = round(items[0][1] * 10000)
        g = bytearray(self.records[0].raw)
        for off in self.GNOS_TEMPO_RELOFFS:
            if _u32(g, off) == oldv:
                struct.pack_into("<I", g, off, newv0)
        self.records[0].raw = bytes(g)
        return len(items)

    # --- meter (time-signature) MAP -----------------------------------------
    # Signature qSvE: 80-byte header (holds the initial signature at +0x0b
    # [den-exponent] / +0x0c [numerator], flag at +0x0f) + one 48-byte record
    # per signature CHANGE + 16-byte tail. den = 2**den_exponent.
    SIG_HEADER_SIZE = 80
    SIG_INIT_DENEXP_OFF = 0x0b
    SIG_INIT_NUM_OFF = 0x0c
    SIG_INIT_FLAG_OFF = 0x0f
    SIG_TAIL = bytes.fromhex("f1000000ffffff3f0000000000000000")

    def _find_sig_qsve(self):
        # signature track = the qSvE whose payload begins with 30 00 00 00.
        for idx, r in enumerate(self.records):
            if (r.tag == b"qSvE" and len(r.raw) > 0x24 + self.SIG_HEADER_SIZE
                    and r.raw[0x24:0x28] == b"\x30\x00\x00\x00"):
                return idx
        return None

    @staticmethod
    def _den_exp(den: int) -> int:
        assert den & (den - 1) == 0 and den > 0, f"denominator {den} not power of two"
        return den.bit_length() - 1

    @classmethod
    def _enc_sig_record(cls, pos, num, den, flag, secidx) -> bytes:
        r = bytearray(48)
        r[0:4] = b"\x30\x00\x00\x00"
        struct.pack_into("<I", r, 0x04, pos)
        r[0x0b] = cls._den_exp(den)
        r[0x0c] = num
        r[0x0f] = flag
        r[0x10:0x14] = b"\x30\x00\x00\x00"
        r[0x17] = 0x88
        r[0x18] = secidx
        struct.pack_into("<I", r, 0x1c, pos)
        r[0x27] = 0x88
        return bytes(r)

    @classmethod
    def decode_sig_events(cls, qsve_raw: bytes):
        """Return [(position, num, den, flag, secidx)] for each signature CHANGE
        record in a signature qSvE — the inverse of _enc_sig_record. `position`
        is absolute (= TEMPO_ORIGIN + tick); `den` = 2**exponent. The INITIAL
        signature lives in the 80-byte header, NOT here (see get_meter_map).
        Change count is fixed by the payload: (psize - 80 header - 16 tail) / 48."""
        psize = _u32(qsve_raw, REC_SIZE_OFF)
        body = qsve_raw[0x24:0x24 + psize]
        out = []
        off = cls.SIG_HEADER_SIZE
        end = len(body) - len(cls.SIG_TAIL)
        while off + 48 <= end and body[off:off + 4] == b"\x30\x00\x00\x00":
            out.append((
                _u32(body, off + 0x04),       # position (TEMPO_ORIGIN-relative)
                body[off + 0x0c],             # numerator
                1 << body[off + 0x0b],        # denominator = 2**exponent
                body[off + 0x0f],             # flag (0x80 on the last change)
                body[off + 0x18],             # secidx
            ))
            off += 48
        return out

    # --- markers (decoded; encoders validated byte-exact vs F11_markers) -----
    # Marker EVENT (48B) lives in the marker qSvE (events start 12 00 00 00):
    #   +0x00 12 00 00 00 | +0x04 pos u32 (=TEMPO_ORIGIN+tick) | +0x10 link-id u32
    #   | +0x17 0x88 | +0x1c 01 | +0x27 0x88 ; sequence = 36hdr + N*48 + 16 tail.
    # NAME = RTF doc in a qSxT record: 36hdr (link-id u16 @ hdr+0x0a) + payload
    #   [u32 size | 12B zero | u32 rtf_off=0x62 | u32 size | 13 00 00 00 |
    #    1b 1b 2f 2f 52 52 | zero-pad to 0x62 | RTF...]. RTF wraps "\cf2 NAME}".
    # link-id = (marker_index+1)*4, shared between event (+0x10) and qSxT (+0x0a).
    MARKER_RTF_PREFIX = (
        b"{\\rtf1\\ansi\\ansicpg1252\\cocoartf2867\n"
        b"\\cocoatextscaling0\\cocoaplatform0{\\fonttbl\\f0\\fnil\\fcharset0 HelveticaNeue;}\n"
        b"{\\colortbl;\\red255\\green255\\blue255;\\red255\\green255\\blue255;}\n"
        b"{\\*\\expandedcolortbl;;\\cssrgb\\c100000\\c100000\\c100000\\c67000;}\n"
        b"\\pard\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480"
        b"\\tx5040\\tx5600\\tx6160\\tx6720\\pardirnatural\\partightenfactor0\n"
        b"\n\\f0\\fs24 \\cf2 ")
    MARKER_QSXT_PREHDR_TAG = bytes.fromhex("1b1b2f2f5252")   # the "//RR" tag at +0x1c
    # A marker-name qSxT 36-byte record header (constant boilerplate, identical
    # across F11/F12/F17). Used to SYNTHESIZE name records on a base that has a
    # marker track but no name-qSxT template yet (e.g. F19/F21). link-id@+0x0a
    # and size@+0x1c are patched per marker by _build_marker_name_qsxt.
    MARKER_NAME_QSXT_HEADER = bytes.fromhex(
        "7153785401002000000004000000ffffffffffffffff020000000200e401000000000000")

    @staticmethod
    def _enc_marker_event(pos: int, linkid: int) -> bytes:
        e = bytearray(48)
        e[0:4] = b"\x12\x00\x00\x00"
        struct.pack_into("<I", e, 0x04, pos)
        struct.pack_into("<I", e, 0x10, linkid)
        e[0x17] = 0x88
        e[0x1c] = 0x01
        e[0x27] = 0x88
        return bytes(e)

    @classmethod
    def _build_marker_name_qsxt(cls, template_hdr36: bytes, name: str, linkid: int) -> bytes:
        """Build a marker-name qSxT record. template_hdr36 = a 36-byte record
        header to clone (tag/flags); link-id and size are patched here."""
        rtf = cls.MARKER_RTF_PREFIX + name.encode("latin-1") + b"}"
        rtf_off = 0x62
        payload = bytearray(rtf_off) + rtf
        size = len(payload)
        struct.pack_into("<I", payload, 0x00, size)
        struct.pack_into("<I", payload, 0x10, rtf_off)
        struct.pack_into("<I", payload, 0x14, size)
        struct.pack_into("<I", payload, 0x18, 0x13)
        payload[0x1c:0x1c + len(cls.MARKER_QSXT_PREHDR_TAG)] = cls.MARKER_QSXT_PREHDR_TAG
        hdr = bytearray(template_hdr36)
        struct.pack_into("<H", hdr, 0x0a, linkid)
        struct.pack_into("<I", hdr, REC_SIZE_OFF, size)
        return bytes(hdr) + bytes(payload)

    # marker event qSvE = 36hdr + N*48 events + 16 tail (same tail as tempo).
    # On a SETTLED base with an empty marker track (e.g. F13: F0 + marker
    # added & removed), this record exists empty (52B); filling it + the name
    # qSxT + a small gnoS range edit is all markers need (no track creation).
    MARKER_TAIL = bytes.fromhex("f1000000ffffff3f0000000000000000")
    GNOS_MARKER_RANGE_OFF = 0x1d0   # gnoS-payload: [u32 range-start][..][u32 last-marker pos]

    def _find_marker_qsve(self):
        # filled: payload starts with a marker event (12 00 00 00)
        for idx, r in enumerate(self.records):
            if r.tag == b"qSvE" and r.raw[0x24:0x28] == b"\x12\x00\x00\x00":
                return idx
        # empty: the unique 52-byte qSvE marker list (sub 0x16, u32@+8 == 0x40000).
        cands = [idx for idx, r in enumerate(self.records)
                 if r.tag == b"qSvE" and len(r.raw) == 52
                 and struct.unpack_from("<H", r.raw, 6)[0] == 0x16
                 and _u32(r.raw, 8) == 0x40000]
        return cands[0] if len(cands) == 1 else None

    def _marker_name_qsxt_indices(self):
        """Indices of marker NAME qSxT records (those containing RTF)."""
        return [i for i, r in enumerate(self.records)
                if r.tag == b"qSxT" and b"{\\rtf1" in r.raw]

    def _marker_meta_qsxt_index(self):
        """The marker-track metadata qSxT (the non-RTF qSxT, ~135B). Name records
        are inserted right AFTER it. Returns None if no marker qSxT exists."""
        cands = [i for i, r in enumerate(self.records)
                 if r.tag == b"qSxT" and b"{\\rtf1" not in r.raw]
        return cands[-1] if cands else None

    def set_markers(self, markers, ppq: int = 960):
        """markers = [(tick, name)] at `ppq` (tick 0 = bar 1). Requires a
        settled base whose marker track already exists (see F13). Returns count."""
        scaled = sorted((round(t * 960 / ppq), str(n)) for t, n in markers)
        # 1) fill the marker event qSvE
        mi = self._find_marker_qsve()
        if mi is None:
            raise ValueError("marker qSvE not found (need a settled base with a marker track)")
        events = bytearray()
        for k, (tick, _name) in enumerate(scaled):
            events += self._enc_marker_event(self.TEMPO_ORIGIN + tick, (k + 1) * 4)
        payload = bytes(events) + self.MARKER_TAIL
        r = self.records[mi]
        hdr = bytearray(r.raw[:0x24])
        struct.pack_into("<I", hdr, REC_SIZE_OFF, len(payload))
        r.raw = bytes(hdr) + payload
        # 2) build the name qSxT records. Clone an existing RTF qSxT header if the
        #    base already has marker names; otherwise SYNTHESIZE from the constant
        #    boilerplate header (lets a base with a marker track but no name
        #    template — e.g. F19/F21 — get markers).
        name_idx = self._marker_name_qsxt_indices()
        tmpl_hdr = (self.records[name_idx[0]].raw[:0x24] if name_idx
                    else self.MARKER_NAME_QSXT_HEADER)
        new_qsxt = [Record(b"qSxT", self._build_marker_name_qsxt(tmpl_hdr, name, (k + 1) * 4))
                    for k, (_tick, name) in enumerate(scaled)]
        if name_idx:
            # replace existing RTF name qSxT in place (splice at the first slot)
            rebuilt, inserted = [], False
            for rec in self.records:
                if rec.tag == b"qSxT" and b"{\\rtf1" in rec.raw:
                    if not inserted:
                        rebuilt.extend(new_qsxt)
                        inserted = True
                else:
                    rebuilt.append(rec)
            self.records = rebuilt
        else:
            # no existing names: insert right after the marker metadata qSxT
            anchor = self._marker_meta_qsxt_index()
            if anchor is None:
                raise ValueError("no marker metadata qSxT anchor in base")
            self.records[anchor + 1:anchor + 1] = new_qsxt
        # 3) gnoS marker range: [origin .. last marker pos]
        if scaled:
            g = bytearray(self.records[0].raw)
            base = 0x24 + self.GNOS_MARKER_RANGE_OFF
            struct.pack_into("<I", g, base, self.TEMPO_ORIGIN)
            struct.pack_into("<I", g, base + 8, self.TEMPO_ORIGIN + scaled[-1][0])
            self.records[0].raw = bytes(g)
        return len(scaled)

    # --- project sample rate (gnoS global setting) ---------------------------
    # Primary SR fields in the gnoS payload (verified: identical across compact
    # & settled 44.1k projects, differ only at 48k). +0x11e is SR-linear
    # (delta == SR delta). A larger +0x11cc+ block is SR-DERIVED (Logic should
    # recompute it on load). Known-rate byte values:
    SR_GNOS = {44100: (0x00, 0xe970), 48000: (0x16, 0xf8ac)}   # (byte@+0xdf, u16@+0x11e/+0x120)

    def set_project_sample_rate(self, rate: int):
        if rate not in self.SR_GNOS:
            raise ValueError(f"sample rate {rate} not in known table {sorted(self.SR_GNOS)}")
        b, v = self.SR_GNOS[rate]
        g = bytearray(self.records[0].raw)
        g[0x24 + 0xdf] = b
        struct.pack_into("<H", g, 0x24 + 0x11e, v)
        struct.pack_into("<H", g, 0x24 + 0x120, v)
        self.records[0].raw = bytes(g)

    # --- audio regions (delta-replay from a base->withRegion fixture pair) ----
    # Decoded from F14 (settled, empty audio track) -> F15 (region @ bar5):
    # adds lFuA(file ref) + gRuA(region: length=sample-count @+0x14, name @+0x4a)
    # + a PLACEMENT EVENT in the audio track's qSvE (marker 24 00 00 00, u32
    # position @+0x04 = 34560+tick region-origin) + OgnS audio-pool bplist
    # (Shared->LoopFamily->{LoopName, LoopId}) + gnoS counter/range/UUID edits.
    AUDIO_REGION_ORIGIN = 34560     # bar 1 = tick 34560 (region-origin)

    def _find_audio_placement_qsve(self):
        """qSvE holding an audio placement event (payload starts 24 00 00 00)."""
        for idx, r in enumerate(self.records):
            if r.tag == b"qSvE" and r.raw[0x24:0x28] == b"\x24\x00\x00\x00":
                return idx
        return None

    # in-place audio fields (fixed-width; no resize when filename is kept).
    GRUA_SAMPLELEN_OFF = 0x16        # gRuA payload: u32 frame count (region length)
    GRUA_NAME_OFF = 0x4a            # gRuA payload: u16 len + ASCII region name
    GRUA_NAME_SLOT = 0x28           # bytes available for [len][name][pad]
    # lFuA audio-format = the 'EVAW' (WAVE, reversed-FourCC) descriptor. Its
    # ABSOLUTE offset SHIFTS with the UTF-16 filename length, so ALWAYS locate
    # 'EVAW' and patch RELATIVE to it. (The old fixed 0x1f8/0x200/0x206 only
    # aligned for the 13-char 'ZZAUDIOZZ.wav'; they silently corrupt any other
    # filename length — confirmed across F15/F18 vs F20/F21.)
    EVAW_FRAMES_OFF = 0x0c           # u32 file frame count
    EVAW_RATE_OFF = 0x14             # u32 sample rate
    EVAW_CHANS_OFF = 0x18            # u16 channel count
    EVAW_BITS_OFF = 0x1a             # u16 bit depth
    EVAW_FILESIZE_OFF = -0x32        # u32 audio FILE byte size, 0x32 before "EVAW"
    # EVAW+0x04 (a format checksum) and EVAW+0x08 are FORMAT-only (same for any
    # audio of a given rate/ch/bits; verified across files). Opaque → lookup; left
    # at the template's values for unknown formats. Stored as the LE-u32 form.
    _EVAW_FMT_FIELDS = {
        (44100, 2, 16): (0xe63f5263, 0x2c),    # EVAW+0x04 → bytes 63 52 3f e6
        (44100, 2, 24): (0x00000000, 0x400),
    }
    EVAW_PATH_OFF = -0x13e           # audio-folder path string starts here
    EVAW_PATHEND_OFF = -0x62         # ...and ends before the format flags here

    @staticmethod
    def _set_lfua_relpath(raw: bytearray, relpath: str = "Audio Files") -> bool:
        """Replace the lFuA's audio-folder path with a RELATIVE one (default
        'Audio Files'). Logic stores an absolute path here when it makes a project;
        a STALE absolute path (e.g. to the template bundle, where the swapped-in
        wav doesn't exist) makes Logic FAIL to resolve the file for the Project
        Audio pool + region selection — even though the relative fallback still
        plays it. Confirmed by diffing against a Logic-re-saved control, which uses
        the bare relative 'Audio Files'. Path field = [EVAW-0x13e, EVAW-0x62)."""
        ev = raw.find(b"EVAW", REC_HEADER_SIZE)
        if ev < 0:
            return False
        ps, pe = ev + ProjectData.EVAW_PATH_OFF, ev + ProjectData.EVAW_PATHEND_OFF
        if ps < REC_HEADER_SIZE or pe > len(raw):
            return False
        raw[ps:pe] = b"\x00" * (pe - ps)
        enc = relpath.encode("latin-1") + b"\x00"
        raw[ps:ps + len(enc)] = enc
        return True

    @staticmethod
    def _patch_lfua_evaw(raw: bytearray, *, frames=None, rate=None,
                         channels=None, bits=None, file_size=None) -> bool:
        """Patch a lFuA record's audio-format fields in place (located via the
        'EVAW' marker). `file_size` is the audio file's on-disk byte size, stored
        0x32 before EVAW — Logic compares it to the actual file and DROPS the
        region from the Project Audio pool + disables selection on mismatch (while
        still playing it), so it MUST be updated when swapping in a wav of a
        different size. Returns True if an EVAW block was found."""
        ev = raw.find(b"EVAW", REC_HEADER_SIZE)
        if ev < 0:
            return False
        if file_size is not None and ev + ProjectData.EVAW_FILESIZE_OFF >= REC_HEADER_SIZE:
            struct.pack_into("<I", raw, ev + ProjectData.EVAW_FILESIZE_OFF, file_size)
        if frames is not None:
            struct.pack_into("<I", raw, ev + ProjectData.EVAW_FRAMES_OFF, frames)
        if rate is not None:
            struct.pack_into("<I", raw, ev + ProjectData.EVAW_RATE_OFF, rate)
        if channels is not None:
            struct.pack_into("<H", raw, ev + ProjectData.EVAW_CHANS_OFF, channels)
        if bits is not None:
            struct.pack_into("<H", raw, ev + ProjectData.EVAW_BITS_OFF, bits)
        if rate is not None and channels is not None and bits is not None:
            fmt = ProjectData._EVAW_FMT_FIELDS.get((rate, channels, bits))
            if fmt is not None:                          # format-only fields (else keep template's)
                struct.pack_into("<I", raw, ev + 0x04, fmt[0])
                struct.pack_into("<I", raw, ev + 0x08, fmt[1])
        if ev + 0x4e <= len(raw):                        # clear per-file residue from the template
            struct.pack_into("<I", raw, ev + 0x4a, 0)
        return True

    def _set_grua_name(self, name: str):
        for r in self.records:
            if r.tag == b"gRuA":
                r.raw = self._patch_grua_name(r.raw, name)

    def _set_lfua_format(self, rate: int = None, bits: int = None, channels: int = None):
        for r in self.records:
            if r.tag == b"lFuA":
                raw = bytearray(r.raw)
                self._patch_lfua_evaw(raw, rate=rate, bits=bits, channels=channels)
                r.raw = bytes(raw)

    @classmethod
    def with_audio_region(cls, base: "ProjectData", template: "ProjectData",
                          tick: int = 0, sample_len: int = None,
                          region_name: str = None, sample_rate: int = None,
                          bits: int = None, file_size: int = None):
        """Return base + one audio region, by replaying the base->template
        record delta (template = base with a region already added, e.g. F15).
        `tick` (960 PPQ from bar 1) repositions the placement event;
        `sample_len` (frames) sets the region's audio length; `file_size` (the
        wav's on-disk byte size) MUST be set or Logic drops the region from the
        Project Audio pool + disables selection (see _patch_lfua_evaw)."""
        import difflib
        A = [bytes(r.raw) for r in base.records]
        B = [bytes(r.raw) for r in template.records]
        sm = difflib.SequenceMatcher(None, A, B, autojunk=False)
        recs = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag in ("equal", "delete"):
                recs += [Record(r.tag, r.raw) for r in base.records[i1:i2]]
            else:                                   # insert / replace -> take template's
                recs += [Record(r.tag, r.raw) for r in template.records[j1:j2]]
        pd = cls(base.root_header, recs)
        mi = pd._find_audio_placement_qsve()         # reposition placement event
        if mi is not None:
            raw = bytearray(pd.records[mi].raw)
            struct.pack_into("<I", raw, 0x24 + 0x04, cls.AUDIO_REGION_ORIGIN + tick)
            pd.records[mi].raw = bytes(raw)
        if sample_len is not None:                   # set region audio length
            for r in pd.records:                     # gRuA: region length on timeline
                if r.tag == b"gRuA" and len(r.raw) > 0x24 + cls.GRUA_SAMPLELEN_OFF + 4:
                    raw = bytearray(r.raw)
                    struct.pack_into("<I", raw, 0x24 + cls.GRUA_SAMPLELEN_OFF, sample_len)
                    r.raw = bytes(raw)
                elif r.tag == b"lFuA":               # lFuA: file frame count (EVAW)
                    raw = bytearray(r.raw)
                    cls._patch_lfua_evaw(raw, frames=sample_len)
                    r.raw = bytes(raw)
        if region_name is not None:
            pd._set_grua_name(region_name)
        if sample_rate is not None or bits is not None or file_size is not None:
            for r in pd.records:
                if r.tag == b"lFuA":
                    raw = bytearray(r.raw)
                    cls._patch_lfua_evaw(raw, rate=sample_rate, bits=bits, file_size=file_size)
                    r.raw = bytes(raw)
        return pd

    # --- MULTIPLE audio regions (one per track) ------------------------------
    # Decoded from F19 (base, 3 empty audio tracks) -> F20/F21 (a region on each
    # of tracks 1/2/3). ALL audio regions live in ONE shared region-list qSvE
    # (payload starts 24 00 00 00) holding N 80-byte PLACEMENT EVENTS:
    #   ev+0x00 24 00 00 00 | ev+0x04 u32 pos = AUDIO_REGION_ORIGIN + tick |
    #   ev+0x0c u32 selection flag (cosmetic) | ev+0x10 u32 event id (0x58+i*4) |
    #   ev+0x14 BYTE track (1-based) ; +0x17 0x89 | ev+0x2c u32 link = regionIndex*4
    # Each region adds a gRuA + lFuA (id@+0x08 = regionIndex*0x40000) + a MneG
    # (id = (regionIndex+1)*0x40000), grows OgnS (one pool entry/file) + gnoS
    # (per-region UUIDs/timestamps). link@0x2c // 4 == regionIndex == the gRuA/lFuA
    # id // 0x40000 the event uses. MetaData.AudioFiles is in TRACK order.
    PLACEMENT_EVENT_SIZE = 0x50
    PLACEMENT_POS_OFF = 0x04
    PLACEMENT_SEL_OFF = 0x0c
    PLACEMENT_ID_OFF = 0x10
    PLACEMENT_TRACK_OFF = 0x14
    PLACEMENT_LINK_OFF = 0x2c

    def audio_placements(self):
        """Decode the shared audio region-list qSvE's 80-byte placement events.
        Returns a list (in payload order) of dicts:
        {body_off, track, pos, link, region_index, sel}."""
        idx = self._find_audio_placement_qsve()
        if idx is None:
            return []
        raw = self.records[idx].raw
        psize = _u32(raw, REC_SIZE_OFF)
        body = raw[0x24:0x24 + psize]
        out, o = [], 0
        while (o + self.PLACEMENT_EVENT_SIZE <= len(body)
               and body[o:o + 4] == b"\x24\x00\x00\x00"):
            link = _u32(body, o + self.PLACEMENT_LINK_OFF)
            out.append({
                "body_off": o,
                "track": body[o + self.PLACEMENT_TRACK_OFF],
                "pos": _u32(body, o + self.PLACEMENT_POS_OFF),
                "link": link,
                "region_index": link // 4,
                "sel": _u32(body, o + self.PLACEMENT_SEL_OFF),
            })
            o += self.PLACEMENT_EVENT_SIZE
        return out

    def _region_records_by_index(self):
        """regionIndex -> {'gRuA': rec_idx, 'lFuA': rec_idx} via id@+0x08 = idx*0x40000."""
        m = {}
        for i, r in enumerate(self.records):
            if r.tag in (b"gRuA", b"lFuA") and len(r.raw) > 0x0c:
                rid = _u32(r.raw, 0x08)
                if rid % 0x40000 == 0:
                    m.setdefault(rid // 0x40000, {})[r.tag.decode("latin-1")] = i
        return m

    def audio_track_filenames(self):
        """track (1-based) -> internal wav filename, read from the linked lFuA
        (UTF-16LE, u16 count @ payload+0x08). Used to copy a user's wav over the
        right Media file. Returns {} if there is no audio region list."""
        out = {}
        by_idx = self._region_records_by_index()
        for ev in self.audio_placements():
            li = by_idx.get(ev["region_index"], {}).get("lFuA")
            if li is None:
                continue
            p = self.records[li].raw[0x24:]
            nlen = struct.unpack_from("<H", p, 0x08)[0]
            out[ev["track"]] = p[0x0a:0x0a + nlen * 2].decode("utf-16-le", "replace")
        return out

    @staticmethod
    def _patch_grua_name(raw: bytes, name: str) -> bytes:
        """Return `raw` with the gRuA display name replaced, RESIZING the record.
        The name is stored as `[u16 len][ASCII name][pad to even]` at payload +0x4a
        and Logic SIZES THE RECORD to fit it (e.g. '047'→242 B, 'w0'→240 B). A
        fixed-slot write that leaves the record the template's size makes the region
        VANISH from the Project Audio bin + become unselectable when the name is
        shorter than the template's. So resize: everything after the name field
        shifts; the record payload size @+0x1c is updated."""
        no = REC_HEADER_SIZE + ProjectData.GRUA_NAME_OFF
        old_len = struct.unpack_from("<H", raw, no)[0]
        old_field = 2 + old_len + (old_len & 1)          # [u16 len][name][pad→even]
        nb = name.encode("latin-1", "replace")
        new_field = struct.pack("<H", len(nb)) + nb + (b"\x00" if len(nb) & 1 else b"")
        new = bytearray(raw[:no]) + new_field + raw[no + old_field:]
        struct.pack_into("<I", new, REC_SIZE_OFF, len(new) - REC_HEADER_SIZE)
        return bytes(new)

    def patch_audio_region(self, region_index, sample_len=None, region_name=None,
                           sample_rate=None, bits=None, channels=None, file_size=None):
        """Patch one region's gRuA (length/name) + lFuA (EVAW format + file size)."""
        slots = self._region_records_by_index().get(region_index)
        if not slots:
            raise ValueError(f"region index {region_index} not found")
        if "gRuA" in slots:
            r = self.records[slots["gRuA"]]
            raw = bytearray(r.raw)
            if sample_len is not None:
                struct.pack_into("<I", raw, 0x24 + self.GRUA_SAMPLELEN_OFF, sample_len)
            rawb = bytes(raw)
            if region_name is not None:                  # resizes the record
                rawb = self._patch_grua_name(rawb, region_name)
            r.raw = rawb
        if "lFuA" in slots:
            r = self.records[slots["lFuA"]]
            raw = bytearray(r.raw)
            self._patch_lfua_evaw(raw, frames=sample_len, rate=sample_rate,
                                  bits=bits, channels=channels, file_size=file_size)
            self._set_lfua_relpath(raw)          # stale absolute path breaks the pool
            r.raw = bytes(raw)

    def set_audio_placement_position(self, track, tick):
        """Reposition the placement event on `track` to region-origin + tick."""
        idx = self._find_audio_placement_qsve()
        if idx is None:
            raise ValueError("no audio region-list qSvE")
        r = self.records[idx]
        raw = bytearray(r.raw)
        psize = _u32(raw, REC_SIZE_OFF)
        o = 0
        while (o + self.PLACEMENT_EVENT_SIZE <= psize
               and raw[0x24 + o:0x24 + o + 4] == b"\x24\x00\x00\x00"):
            if raw[0x24 + o + self.PLACEMENT_TRACK_OFF] == track:
                struct.pack_into("<I", raw, 0x24 + o + self.PLACEMENT_POS_OFF,
                                 self.AUDIO_REGION_ORIGIN + tick)
            o += self.PLACEMENT_EVENT_SIZE
        r.raw = bytes(raw)

    @classmethod
    def with_audio_regions(cls, base: "ProjectData", template: "ProjectData",
                           placements: dict):
        """Return base + N audio regions (one per track), by replaying the
        base->template delta (template = base with one region already on each
        track, e.g. F19->F20/F21) then patching each track's placement position
        and its linked region content.

        placements : {track(1-based): {tick, sample_len, region_name,
                      sample_rate, bits}}. Its track set MUST equal the
                      template's (v1: one region per track, no add/remove)."""
        import difflib
        A = [bytes(r.raw) for r in base.records]
        B = [bytes(r.raw) for r in template.records]
        sm = difflib.SequenceMatcher(None, A, B, autojunk=False)
        recs = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag in ("equal", "delete"):
                recs += [Record(r.tag, r.raw) for r in base.records[i1:i2]]
            else:
                recs += [Record(r.tag, r.raw) for r in template.records[j1:j2]]
        pd = cls(base.root_header, recs)
        evs = pd.audio_placements()
        tmpl_tracks = sorted(e["track"] for e in evs)
        if sorted(placements) != tmpl_tracks:
            raise ValueError(f"placement tracks {sorted(placements)} != "
                             f"template tracks {tmpl_tracks} (v1 needs one region per track)")
        track_region = {e["track"]: e["region_index"] for e in evs}
        for track, spec in placements.items():
            if spec.get("tick") is not None:
                pd.set_audio_placement_position(track, spec["tick"])
            pd.patch_audio_region(track_region[track],
                                  sample_len=spec.get("sample_len"),
                                  region_name=spec.get("region_name"),
                                  sample_rate=spec.get("sample_rate"),
                                  bits=spec.get("bits"),
                                  channels=spec.get("channels"))
        return pd

    # --- multiple / repositioned audio regions (REUSE template identities) ---
    # CORRECTION (Logic-verified): the gnoS object-registry + OgnS audio pool ARE
    # load-bearing — for the Project Audio file list + region SELECTION (not for
    # playback). Cloning regions with fresh/perturbed gRuA UUIDs made them PLAY but
    # vanish from the pool and become unselectable. FIX: REUSE the template's region
    # records (identity intact: gRuA/lFuA/MneG ids + the gRuA UUID @raw+0xca + their
    # registry/OgnS entries) and only rebuild the 80-B placement events (free
    # track/pos, multiple per track). Region count is BOUNDED by the template's
    # region count K; truly unbounded N needs registry+OgnS synthesis (TODO).
    PLACEMENT_TAIL = bytes.fromhex("f1000000ffffff3f0000000000000000")

    @staticmethod
    def _set_lfua_filename(raw: bytes, name: str) -> bytes:
        """Return `raw` with the lFuA internal filename (UTF-16LE, len-prefixed @
        payload+0x08) replaced by `name`. RESIZES the record: everything after the
        name (LFUA block, path, EVAW…) shifts and the payload size @+0x1c is
        updated. Verified safe — changing name length shifts those by exactly
        Δchars×2 with no other stored offsets (the two payload+0x00/+0x04 = 0x370
        fields are name-independent)."""
        nlen_off = REC_HEADER_SIZE + 0x08
        name_off = REC_HEADER_SIZE + 0x0a
        old_chars = struct.unpack_from("<H", raw, nlen_off)[0]
        new = bytearray(raw[:name_off]) + name.encode("utf-16-le") + raw[name_off + old_chars * 2:]
        struct.pack_into("<H", new, nlen_off, len(name))
        struct.pack_into("<I", new, REC_SIZE_OFF, len(new) - REC_HEADER_SIZE)
        return bytes(new)

    @classmethod
    def place_audio_regions(cls, base: "ProjectData", template: "ProjectData", regions):
        """Place audio regions by REUSING the template's region records (identity
        preserved → the gnoS object-registry + OgnS pool stay valid, which Logic
        needs for the Project Audio list + region selection).

        len(regions) MUST equal the template's region count K (use a K-region
        template). Each region freely sets track / position / file / length, and
        MULTIPLE regions may share a track. Region i reuses template region i's
        records (id i*0x40000) and is placed by a rebuilt 80-B event (link = i*4).
        gnoS / OgnS are left untouched.

        regions = list (order = region index) of dicts:
          {track, tick, sample_len, region_name, sample_rate, bits, channels,
           internal_name}."""
        import difflib
        A = [bytes(r.raw) for r in base.records]
        B = [bytes(r.raw) for r in template.records]
        sm = difflib.SequenceMatcher(None, A, B, autojunk=False)
        recs = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            src = base.records[i1:i2] if tag in ("equal", "delete") else template.records[j1:j2]
            recs += [Record(r.tag, r.raw) for r in src]
        pd = cls(base.root_header, recs)

        bi = pd._region_records_by_index()
        slots = sorted(i for i in bi if "gRuA" in bi[i] and "lFuA" in bi[i])
        K, N = len(slots), len(regions)
        if slots != list(range(K)):
            raise ValueError(f"template region indices {slots} are not 0..{K-1}")
        if N != K:
            raise ValueError(
                f"template has {K} audio region slot(s) but {N} region(s) were requested. "
                f"Use a template with exactly {N} audio regions. Region identities must be reused "
                f"to keep the Project Audio pool + selection valid; unbounded counts need "
                f"gnoS-registry + OgnS synthesis (not yet implemented).")
        qi = pd._find_audio_placement_qsve()
        if qi is None:
            raise ValueError("template has no audio placement qSvE")
        # Capture the template's K per-region events. Reuse event i for region i
        # so its flag (+0x0c), id (+0x10) and link (+0x2c) are PRESERVED — only the
        # position + track are changed. (Rebuilding from one prototype + zeroing the
        # flag made regions vanish from the Project Audio pool + become unselectable
        # in Logic, even though they played.)
        tmpl_body = pd.records[qi].raw[REC_HEADER_SIZE:REC_HEADER_SIZE + _u32(pd.records[qi].raw, REC_SIZE_OFF)]
        proto_evs = [tmpl_body[j * cls.PLACEMENT_EVENT_SIZE:(j + 1) * cls.PLACEMENT_EVENT_SIZE]
                     for j in range(K)]
        allowed = {e["track"] for e in pd.audio_placements()}

        events = bytearray()
        for i, spec in enumerate(regions):
            if spec["track"] not in allowed:
                raise ValueError(f"track {spec['track']} not in template tracks "
                                 f"{sorted(allowed)} (audio tracks must exist in the base)")
            li = bi[i]["lFuA"]                         # resize the real filename in place
            if spec.get("internal_name"):
                pd.records[li].raw = cls._set_lfua_filename(pd.records[li].raw, spec["internal_name"])
            pd.patch_audio_region(i, sample_len=spec.get("sample_len"),
                                  region_name=spec.get("region_name"),
                                  sample_rate=spec.get("sample_rate"),
                                  bits=spec.get("bits"), channels=spec.get("channels"),
                                  file_size=spec.get("file_size"))
            ev = bytearray(proto_evs[i])              # reuse region i's own event (keep flag/id/link)
            struct.pack_into("<I", ev, cls.PLACEMENT_POS_OFF, cls.AUDIO_REGION_ORIGIN + spec["tick"])
            ev[cls.PLACEMENT_TRACK_OFF] = spec["track"]
            events += ev

        qhdr = bytearray(pd.records[qi].raw[:REC_HEADER_SIZE])
        payload = bytes(events) + cls.PLACEMENT_TAIL
        struct.pack_into("<I", qhdr, REC_SIZE_OFF, len(payload))
        pd.records[qi].raw = bytes(qhdr) + payload

        # Match what Logic produces for plain audio regions (verified vs a
        # Logic-re-saved control): (1) the audio-pool OgnS bplist is EMPTIED to the
        # base's form — a stale loop-family entry (e.g. '047') breaks the Project
        # Audio bin; (2) the per-region MneG records (Session-Player mementos,
        # id >= 0x40000) are dropped — they don't belong to plain audio regions.
        base_ogns = {_u32(r.raw, 8): r.raw for r in base.records if r.tag == b"OgnS"}
        for r in pd.records:
            if r.tag == b"OgnS" and b"bplist00" in r.raw and _u32(r.raw, 8) in base_ogns:
                r.raw = base_ogns[_u32(r.raw, 8)]
        pd.records = [r for r in pd.records
                      if not (r.tag == b"MneG" and _u32(r.raw, 8) >= 0x40000)]
        return pd

    GRUA_UUID_OFF = 0xca            # record-relative 16-B region UUID (time-based)
    ARR_AUDIO_IDX = 0x040000        # arrange MSeq/EvSq idx (holds audio placement events)

    @classmethod
    def synthesize_audio_regions(cls, donor: "ProjectData", regions, *, prototype=None,
                                 proto_group=None, proto_event=None):
        """Synthesize an ARBITRARY number of audio regions by CLONING a region-0
        record group — no per-count template needed.

        Logic REGENERATES the gnoS object-registry + OgnS pool from the records on
        load (Logic-verified 2026-05-31), so a region just needs its gRuA(s) + lFuA
        + an 80-B placement event. Each requested region clones region 0's group at
        a fresh index (i*0x40000) with a fresh gRuA UUID, is patched (file/length/
        name/format), and is placed by a rebuilt event (link=i*4, track/pos).

        `donor` supplies the destination TRACKS. The region PROTOTYPE (the gRuA/lFuA
        group + the 80-B placement event) comes from `prototype` if given, else from
        `donor` itself (which must then already hold region 0). The `prototype=` form
        is what lets region synthesis run on a track-SYNTHESIZED base — which has the
        tracks but no region and an EMPTY arrange EvSq — i.e. the combine (§10.8).

        regions = list (order = region index) of dicts:
          {track, tick, sample_len, region_name, sample_rate, bits, channels,
           internal_name, file_size}.  Multiple regions may share a track."""
        pd = cls(donor.root_header, [Record(r.tag, r.raw) for r in donor.records])
        if proto_group is not None and proto_event is not None:
            # PRE-EXTRACTED prototype (the embedded baked audio-region proto — no F21 needed)
            proto_raw = [(t, bytes(d)) for t, d in proto_group]
            proto_ev = bytes(proto_event)
        else:
            psrc = prototype if prototype is not None else donor
            # region-0 prototype group (ALL gRuA + lFuA whose id@0x08 == 0), in order
            proto = [r for r in psrc.records
                     if r.tag in (b"gRuA", b"lFuA") and _u32(r.raw, 0x08) == 0]
            if not any(r.tag == b"gRuA" for r in proto) or not any(r.tag == b"lFuA" for r in proto):
                raise ValueError("prototype has no region 0 (needs >=1 audio region as the prototype)")
            proto_raw = [(r.tag, bytes(r.raw)) for r in proto]
            # 80-B placement-event prototype, from the prototype source's audio EvSq
            pqi = next((i for i, r in enumerate(psrc.records) if cls._qsve_has_audio_event(r)), None)
            if pqi is None:
                raise ValueError("prototype has no audio placement event (needs a placed region)")
            pb = psrc.records[pqi].raw[REC_HEADER_SIZE:
                                       REC_HEADER_SIZE + _u32(psrc.records[pqi].raw, REC_SIZE_OFF)]
            proto_ev = pb[cls._first_audio_event_off(pb):][:cls.PLACEMENT_EVENT_SIZE]
        N = len(regions)

        # Does the BASE already hold region 0? (donor-region-synth: yes — region 0
        # is the donor's own; combine: no — clone region 0 too.)
        base_r0 = [i for i, r in enumerate(pd.records)
                   if r.tag in (b"gRuA", b"lFuA") and _u32(r.raw, 0x08) == 0]
        start = 1 if base_r0 else 0
        clones = []
        for i in range(start, N):
            for tag, raw in proto_raw:
                b = bytearray(raw)
                struct.pack_into("<I", b, 0x08, i * 0x40000)           # region index id
                if tag == b"gRuA" and len(b) >= cls.GRUA_UUID_OFF + 16:  # fresh UUID, keep session middle
                    u = cls.GRUA_UUID_OFF
                    b[u:u + 16] = os.urandom(4) + b[u + 4:u + 8] + os.urandom(8)
                clones.append(Record(tag, bytes(b)))
        if base_r0:
            ins = base_r0[-1] + 1                          # right after the region-0 group
        else:                                              # combine: the audio-bin slot
            ins = next((i for i, r in enumerate(pd.records) if r.tag == b"Styl"),
                       next((i for i, r in enumerate(pd.records) if r.tag == b"OgnS"), len(pd.records)))
        pd.records[ins:ins] = clones

        # patch each region's gRuA(s) + lFuA
        for i, spec in enumerate(regions):
            for r in pd.records:
                if _u32(r.raw, 0x08) != i * 0x40000:
                    continue
                if r.tag == b"gRuA":
                    raw = bytearray(r.raw)
                    if spec.get("sample_len") is not None:
                        struct.pack_into("<I", raw, 0x24 + cls.GRUA_SAMPLELEN_OFF, spec["sample_len"])
                    rb = bytes(raw)
                    if spec.get("region_name") is not None:
                        rb = cls._patch_grua_name(rb, spec["region_name"])
                    r.raw = rb
                elif r.tag == b"lFuA":
                    if spec.get("internal_name"):
                        r.raw = cls._set_lfua_filename(r.raw, spec["internal_name"])
                    raw = bytearray(r.raw)
                    cls._patch_lfua_evaw(raw, frames=spec.get("sample_len"), rate=spec.get("sample_rate"),
                                         bits=spec.get("bits"), channels=spec.get("channels"),
                                         file_size=spec.get("file_size"))
                    cls._set_lfua_relpath(raw)
                    r.raw = bytes(raw)

        # Rebuild the audio region-list EvSq: N events from the prototype event. A
        # base with regions has audio events -> replace them in place; a track-synth
        # base has an EMPTY arrange EvSq (just a 16-B sequence trailer) -> prepend
        # the events before that trailer (yielding F18's [events][trailer] shape).
        qi = next((i for i, r in enumerate(pd.records) if cls._qsve_has_audio_event(r)),
                  cls._arrange_audio_evsq(pd.records))
        if qi is None:
            raise ValueError("base has no arrange audio EvSq to place regions into")
        raw = pd.records[qi].raw
        body = raw[REC_HEADER_SIZE:REC_HEADER_SIZE + _u32(raw, REC_SIZE_OFF)]
        e0 = cls._first_audio_event_off(body)
        if e0 is None:                                     # empty arrange EvSq (combine)
            pre, tail = b"", bytes(body)                   # the whole body is the trailer
        else:
            k = 0
            while (e0 + (k + 1) * cls.PLACEMENT_EVENT_SIZE <= len(body)
                   and _u32(body, e0 + k * cls.PLACEMENT_EVENT_SIZE) == 0x24):
                k += 1
            pre, tail = bytes(body[:e0]), bytes(body[e0 + k * cls.PLACEMENT_EVENT_SIZE:])
        events = bytearray()
        for i, spec in enumerate(regions):
            ev = bytearray(proto_ev)
            struct.pack_into("<I", ev, cls.PLACEMENT_POS_OFF, cls.AUDIO_REGION_ORIGIN + spec["tick"])
            ev[cls.PLACEMENT_TRACK_OFF] = spec["track"]
            struct.pack_into("<I", ev, cls.PLACEMENT_LINK_OFF, i * 4)
            events += ev
        newbody = pre + bytes(events) + tail
        nh = bytearray(raw[:REC_HEADER_SIZE])
        struct.pack_into("<I", nh, REC_SIZE_OFF, len(newbody))
        pd.records[qi].raw = bytes(nh) + newbody

        # drop per-region MneG (Session-Player mementos, id>=0x40000) — Logic
        # rebuilds the pool/registry from the records, so leave OgnS as the base's.
        pd.records = [r for r in pd.records
                      if not (r.tag == b"MneG" and _u32(r.raw, 8) >= 0x40000)]
        return pd

    @staticmethod
    def _arrange_audio_evsq(records):
        """The arrange EvSq (idx 0x040000) that carries audio placement events — the
        EvSq following the REAL arrange container (`_arrange_container`, the same record
        `_synth_arrange_height` targets), NOT the larger 'Untitled' qeSM@0x040000 decoy a
        settled mixed base also carries (whose trailing EvSq Logic ignores for the
        arrange — picking it leaves placed regions invisible). On a track-synth base this
        EvSq is empty (a 16-B trailer) and we graft the events in; None if absent."""
        arr = _arrange_container(records)
        if arr is None:
            return None
        aqe = records.index(arr)
        return next((i for i, r in enumerate(records) if i > aqe and r.tag == b"qSvE"
                     and _u32(r.raw, 0x08) == ProjectData.ARR_AUDIO_IDX), None)

    @staticmethod
    def _qsve_has_audio_event(r):
        if r.tag != b"qSvE":
            return False
        ps = _u32(r.raw, REC_SIZE_OFF)
        body = r.raw[REC_HEADER_SIZE:REC_HEADER_SIZE + ps]
        return ProjectData._first_audio_event_off(body) is not None

    @staticmethod
    def _first_audio_event_off(body):
        o = 0
        while o + ProjectData.PLACEMENT_EVENT_SIZE <= len(body):
            if (_u32(body, o) == 0x24 and _u32(body, o + ProjectData.PLACEMENT_POS_OFF) >= ProjectData.AUDIO_REGION_ORIGIN
                    and 0 < body[o + ProjectData.PLACEMENT_TRACK_OFF] < 64):
                return o
            o += 4
        return None

    def set_meter_map(self, points, ppq: int = 960):
        """points = [(tick, num, den)] at `ppq` resolution (tick 0 = bar 1)."""
        idx = self._find_sig_qsve()
        if idx is None:
            raise ValueError("signature qSvE not found")
        scaled = {}
        for tick, num, den in points:
            scaled[round(tick * 960 / ppq)] = (int(num), int(den))
        items = sorted(scaled.items())
        if not items or items[0][0] != 0:
            items.insert(0, (0, items[0][1] if items else (4, 4)))
        (init_num, init_den) = items[0][1]
        changes = items[1:]
        r = self.records[idx]
        header = bytearray(r.raw[0x24:0x24 + self.SIG_HEADER_SIZE])
        header[self.SIG_INIT_DENEXP_OFF] = self._den_exp(init_den)
        header[self.SIG_INIT_NUM_OFF] = init_num
        header[self.SIG_INIT_FLAG_OFF] = 0x00 if changes else 0x80
        body = bytearray()
        for i, (tick, (num, den)) in enumerate(changes):
            flag = 0x80 if i == len(changes) - 1 else 0x00
            body += self._enc_sig_record(self.TEMPO_ORIGIN + tick, num, den, flag, 2 * (i + 1) - 1)
        payload = bytes(header) + bytes(body) + self.SIG_TAIL
        hdr = bytearray(r.raw[:0x24])
        struct.pack_into("<I", hdr, REC_SIZE_OFF, len(payload))
        r.raw = bytes(hdr) + payload
        return (init_num, init_den), len(changes)

    def get_meter_map(self, ppq: int = 960):
        """Decode the meter map -> [(tick, num, den)] at `ppq` resolution, with
        tick 0 == bar 1 (the initial signature, read from the header). The clean
        inverse of set_meter_map: `pd.set_meter_map(pd.get_meter_map())` rewrites
        the signature qSvE byte-for-byte. Feed straight to set_meter_map(...) or
        TimeMap(meter_map=...). Returns [] if the project has no signature track."""
        idx = self._find_sig_qsve()
        if idx is None:
            return []
        raw = self.records[idx].raw
        hdr = raw[0x24:0x24 + self.SIG_HEADER_SIZE]
        out = [(0, hdr[self.SIG_INIT_NUM_OFF], 1 << hdr[self.SIG_INIT_DENEXP_OFF])]
        for pos, num, den, _flag, _secidx in self.decode_sig_events(raw):
            out.append((round((pos - self.TEMPO_ORIGIN) * ppq / 960), num, den))
        return out

    def get_tempo_map(self, ppq: int = 960):
        """Decode the tempo map -> [(tick, bpm)] at `ppq` resolution (tick 0 ==
        bar 1). Inverse of set_tempo_map at the MAP level — note set_tempo_map
        recomputes each event's altpos from the tempo curve, so a byte round-trip
        can differ in altpos alone; the (tick, bpm) values round-trip exactly.
        Returns [] if the project has no tempo track."""
        idx = self._find_tempo_qsve()
        if idx is None:
            return []
        out = []
        for pos, _flag, tempo_raw, _altpos in self.decode_tempo_events(self.records[idx].raw):
            out.append((round((pos - self.TEMPO_ORIGIN) * ppq / 960), tempo_raw / 10000.0))
        return out

    # --- MIDI note regions --------------------------------------------------
    # Notes live in the REGION's paired qSvE (same cluster idx as the region
    # qeSM) as 32-byte events; payload = 32*N + 16-byte tail. Note position is
    # REGION-RELATIVE (origin 38400) — moving the region does NOT change it
    # (proven F4b@bar1 vs F4c@bar2: identical note bytes). See spec §8.5.
    MIDI_NOTE_ORIGIN = 38400          # note pos field = 38400 + region-relative tick@960
    NOTE_EVENT_SIZE = 0x20            # 32-byte note event
    NOTE_QSVE_TAIL = bytes.fromhex("f1000000ffffff3f0000000000000000")

    @classmethod
    def _enc_note_event(cls, tick, pitch, velocity, length, last, fine=0):
        """One 32-byte MIDI note event. `tick` = region-relative 960-PPQ start
        (stored as MIDI_NOTE_ORIGIN+tick); `length` = duration in ticks; `last`
        sets the 0x80 terminal flag bit; `fine` = the +0x0a fine-velocity low
        byte (0 ⇒ exact integer velocity)."""
        e = bytearray(cls.NOTE_EVENT_SIZE)
        e[0x00] = 0x90                                       # note-on marker
        struct.pack_into("<I", e, 0x04, cls.MIDI_NOTE_ORIGIN + tick)
        e[0x0a] = fine & 0xff
        e[0x0b] = velocity & 0xff
        e[0x0c] = pitch & 0xff
        e[0x0f] = 0x01 | (0x80 if last else 0x00)
        e[0x10] = 0x40
        e[0x17] = 0x89
        struct.pack_into("<I", e, 0x1c, int(length))
        return bytes(e)

    @classmethod
    def build_note_qsve_payload(cls, notes):
        """Region qSvE payload for notes=[(tick, pitch, velocity, length)] (tick
        region-relative @960 PPQ). Sorted by start; the last note gets the
        terminal flag. Empty ⇒ just the 16-byte tail."""
        ns = sorted(notes)
        body = bytearray()
        for i, (tick, pitch, vel, length) in enumerate(ns):
            body += cls._enc_note_event(tick, pitch, vel, length, last=(i == len(ns) - 1))
        return bytes(body) + cls.NOTE_QSVE_TAIL

    @staticmethod
    def decode_note_events(qsve_raw: bytes):
        """Inverse of _enc_note_event: [(tick, pitch, velocity, length, flag,
        fine)] from a region qSvE carrying 0x90 note events (tick = pos -
        MIDI_NOTE_ORIGIN, region-relative). Empty/non-note qSvE ⇒ []."""
        psize = _u32(qsve_raw, REC_SIZE_OFF)
        body = qsve_raw[REC_HEADER_SIZE:REC_HEADER_SIZE + psize]
        out, i = [], 0
        while i + 0x20 <= len(body) and body[i:i + 4] == b"\x90\x00\x00\x00":
            out.append((_u32(body, i + 0x04) - ProjectData.MIDI_NOTE_ORIGIN,
                        body[i + 0x0c], body[i + 0x0b], _u32(body, i + 0x1c),
                        body[i + 0x0f], body[i + 0x0a]))
            i += 0x20
        return out


class TimeMap:
    """Meter/tempo-aware musical-position conversions on Logic's 960-PPQ grid.

    Logic positions everything in 960-PPQ ticks measured from bar 1 (tick 0 ==
    bar 1, beat 1). Turning a *musical* position (bar/beat) or a *wall-clock*
    position (seconds) into that tick requires the meter map (for bar/beat) and
    the tempo map (for seconds) — you can NOT assume 4/4 or a constant tempo.
    This class is the meter/tempo-aware replacement for the old 4/4 shortcut.

    Construct from the SAME lists you pass to set_meter_map / set_tempo_map
    (and normalized the same way: rescaled to 960 PPQ, sorted, dedup last-wins,
    an implicit point at tick 0):
        meter_map : [(tick, num, den)]   meter changes; defaults to 4/4 @ 0
        tempo_map : [(tick, bpm)]        tempo changes; defaults to 120 @ 0
    `ppq` is the resolution of the *input* ticks (mirrors the setters).

    Conventions (all 1-based, matching Logic's bar ruler):
      * bar 1, beat 1 == tick 0.
      * One *beat* is one denominator note: 4/4 -> quarter, 3/4 -> quarter,
        6/8 -> eighth; a bar therefore holds `num` beats. Pass a float beat for
        sub-beat positions (beat 2.5 == half-way through beat 2). Beats/bars may
        exceed their nominal range and simply spill forward. NOTE: bar-downbeat
        placement (bar_to_tick) is convention-independent and exact; only the
        sub-bar beat interpretation depends on this rule.
      * Meter changes are assumed bar-aligned (Logic enforces this). A mid-bar
        change is tolerated but bar numbering past it may be fractional.

    Tick outputs are ints (Logic stores integer ticks) and are bar-1-relative:
    add ProjectData.TEMPO_ORIGIN (tempo/meter/markers) or .AUDIO_REGION_ORIGIN
    (audio regions) when placing events — the writers already do this for you.
    """

    PPQ = 960
    WHOLE = 4 * PPQ            # 3840 ticks per whole note

    def __init__(self, tempo_map=None, meter_map=None, ppq: int = 960):
        # meter segments: (start_tick, num, den, start_bar) -----------------
        msc = {}
        for tick, num, den in (meter_map or []):
            msc[round(tick * self.PPQ / ppq)] = (int(num), int(den))
        mitems = sorted(msc.items())
        if not mitems or mitems[0][0] != 0:
            mitems.insert(0, (0, mitems[0][1] if mitems else (4, 4)))
        self._meters = []
        start_bar = 1.0
        for i, (tick, (num, den)) in enumerate(mitems):
            if i > 0:
                ptick, (pnum, pden) = mitems[i - 1]
                start_bar += (tick - ptick) / (pnum * self.WHOLE / pden)
            self._meters.append((tick, num, den, start_bar))

        # tempo segments: (start_tick, bpm, cum_sec) -----------------------
        tsc = {}
        for tick, bpm in (tempo_map or []):
            tsc[round(tick * self.PPQ / ppq)] = float(bpm)
        titems = sorted(tsc.items())
        if not titems or titems[0][0] != 0:
            titems.insert(0, (0, titems[0][1] if titems else 120.0))
        self._tempos = []
        cum = 0.0
        for i, (tick, bpm) in enumerate(titems):
            if i > 0:
                ptick, pbpm = titems[i - 1]
                cum += ((tick - ptick) / self.PPQ) * (60.0 / pbpm)
            self._tempos.append((tick, bpm, cum))

    @classmethod
    def from_midimap(cls, mm) -> "TimeMap":
        """Build from a parsed midimap.MidiMap, using its native PPQN."""
        tempo = [(t, bpm) for (t, _us, bpm) in mm.tempo_map]
        meter = [(t, num, den) for (t, num, den, *_rest) in mm.meter_map]
        return cls(tempo, meter, ppq=mm.division)

    @classmethod
    def from_project(cls, pd) -> "TimeMap":
        """Build from a parsed ProjectData by decoding its tempo + meter maps
        (uses ProjectData.get_tempo_map / get_meter_map)."""
        return cls(pd.get_tempo_map(), pd.get_meter_map())

    # ---- meter / bar-beat ------------------------------------------------
    def _meter_for_bar(self, bar):
        seg = self._meters[0]
        for m in self._meters:
            if m[3] <= bar + 1e-9:
                seg = m
            else:
                break
        return seg

    def _meter_for_tick(self, tick):
        seg = self._meters[0]
        for m in self._meters:
            if m[0] <= tick:
                seg = m
            else:
                break
        return seg

    def bar_beat_to_tick(self, bar: float, beat: float = 1.0) -> int:
        """960-PPQ tick (from bar 1) of (bar, beat). 1-based; bar1 beat1 == 0."""
        stick, num, den, sbar = self._meter_for_bar(bar)
        tpb = num * self.WHOLE / den          # ticks per bar
        tpbeat = self.WHOLE / den             # ticks per beat
        return int(round(stick + (bar - sbar) * tpb + (beat - 1.0) * tpbeat))

    def bar_to_tick(self, bar: float) -> int:
        """960-PPQ tick of a bar downbeat (== bar_beat_to_tick(bar, 1))."""
        return self.bar_beat_to_tick(bar, 1.0)

    def tick_to_bar_beat(self, tick: float):
        """Inverse of bar_beat_to_tick -> (bar:int, beat:float), both 1-based."""
        if tick <= 0:
            return (1, 1.0)
        stick, num, den, sbar = self._meter_for_tick(tick)
        tpb = num * self.WHOLE / den
        tpbeat = self.WHOLE / den
        off = tick - stick
        bars = int(off // tpb)
        return (int(round(sbar)) + bars, 1.0 + (off - bars * tpb) / tpbeat)

    # ---- tempo / seconds -------------------------------------------------
    def tick_to_seconds(self, tick: float) -> float:
        """Elapsed seconds from bar 1 to `tick`, honoring the tempo map."""
        if tick <= 0:
            return 0.0
        seg = self._tempos[0]
        for t in self._tempos:
            if t[0] <= tick:
                seg = t
            else:
                break
        stick, bpm, cum = seg
        return cum + ((tick - stick) / self.PPQ) * (60.0 / bpm)

    def seconds_to_tick(self, seconds: float) -> int:
        """960-PPQ tick (from bar 1) at `seconds` of elapsed time."""
        if seconds <= 0:
            return 0
        seg = self._tempos[0]
        for t in self._tempos:
            if t[2] <= seconds + 1e-12:
                seg = t
            else:
                break
        stick, bpm, cum = seg
        return int(round(stick + (seconds - cum) * self.PPQ * bpm / 60.0))

    # ---- convenience composites -----------------------------------------
    def bar_beat_to_seconds(self, bar: float, beat: float = 1.0) -> float:
        return self.tick_to_seconds(self.bar_beat_to_tick(bar, beat))

    def seconds_to_bar_beat(self, seconds: float):
        return self.tick_to_bar_beat(self.seconds_to_tick(seconds))


# --- CLI: validate round-trip across files ---------------------------------

def _validate(path: Path) -> bool:
    data = path.read_bytes()
    try:
        pd = ProjectData.parse(data)
    except ValueError as e:
        print(f"  FAIL parse  {path}\n        {e}")
        return False
    out = pd.serialize()
    if out == data:
        print(f"  OK   {len(pd.records):>3} recs  {len(data):>8}B  {path.name}  {pd.histogram()}")
        return True
    # locate first divergence
    n = min(len(out), len(data))
    i = next((k for k in range(n) if out[k] != data[k]), n)
    print(f"  DIFF first@0x{i:x}  outlen={len(out)} inlen={len(data)}  {path}")
    return False


def make_tempo_test(src_bundle: Path, dst_bundle: Path, bpm: float):
    """Copy a .logicx bundle and rewrite tempo (ProjectData + MetaData.plist)."""
    import plistlib
    import shutil
    if dst_bundle.exists():
        raise ValueError(f"refusing to overwrite existing {dst_bundle}")
    shutil.copytree(src_bundle, dst_bundle)
    alt = dst_bundle / "Alternatives" / "000"

    pd_path = alt / "ProjectData"
    pd = ProjectData.parse(pd_path.read_bytes())
    n = pd.set_tempo(bpm)
    out = pd.serialize()
    # re-parse to confirm structure still walks + tempo reads back
    rt = ProjectData.parse(out)
    assert rt.current_tempo_raw() == round(bpm * 10000), "tempo readback mismatch"
    pd_path.write_bytes(out)

    md_path = alt / "MetaData.plist"
    md = plistlib.loads(md_path.read_bytes())
    md["BeatsPerMinute"] = float(bpm)
    md_path.write_bytes(plistlib.dumps(md, fmt=plistlib.FMT_BINARY))
    print(f"wrote {dst_bundle}")
    print(f"  patched {n} ProjectData tempo field(s) + MetaData.plist -> {bpm} BPM")
    print(f"  ProjectData round-trips: {len(out)}B, {len(pd.records)} records")


def make_tempomap_test(src_bundle: Path, dst_bundle: Path, midi_path: Path):
    """Copy a .logicx and write the tempo map parsed from a MIDI file into it."""
    import plistlib
    import shutil
    from . import midimap
    if dst_bundle.exists():
        raise ValueError(f"refusing to overwrite existing {dst_bundle}")
    mm = midimap.parse_file(midi_path)
    points = [(t, bpm) for (t, _us, bpm) in mm.rescaled_tempo_map(960)]
    shutil.copytree(src_bundle, dst_bundle)
    alt = dst_bundle / "Alternatives" / "000"
    pd = ProjectData.parse((alt / "ProjectData").read_bytes())
    n = pd.set_tempo_map(points, ppq=960)
    out = pd.serialize()
    rt = ProjectData.parse(out)                      # must still walk cleanly
    got = rt.decode_tempo_events(rt.records[rt._find_tempo_qsve()].raw)
    assert len(got) == n, f"readback {len(got)} != {n}"
    (alt / "ProjectData").write_bytes(out)
    md = plistlib.loads((alt / "MetaData.plist").read_bytes())
    md["BeatsPerMinute"] = float(points[0][1]) if points else 120.0
    (alt / "MetaData.plist").write_bytes(plistlib.dumps(md, fmt=plistlib.FMT_BINARY))
    print(f"wrote {dst_bundle}")
    print(f"  source MIDI: {midi_path.name}  (division {mm.division} PPQN)")
    print(f"  tempo events written: {n}  (first {points[0][1]} BPM)")
    print(f"  ProjectData {len(out)}B, {len(pd.records)} records, round-trips OK")


def make_midimaps_test(src_bundle: Path, dst_bundle: Path, midi_path: Path):
    """Write BOTH the tempo map and meter map parsed from a MIDI into a .logicx."""
    import plistlib
    import shutil
    from . import midimap
    if dst_bundle.exists():
        raise ValueError(f"refusing to overwrite existing {dst_bundle}")
    mm = midimap.parse_file(midi_path)
    div = mm.division
    tempo_pts = [(round(t * 960 / div), bpm) for (t, _us, bpm) in mm.tempo_map]
    meter_pts = [(round(t * 960 / div), num, den) for (t, num, den, _c, _n) in mm.meter_map]
    shutil.copytree(src_bundle, dst_bundle)
    alt = dst_bundle / "Alternatives" / "000"
    pd = ProjectData.parse((alt / "ProjectData").read_bytes())
    nt = pd.set_tempo_map(tempo_pts, ppq=960)
    (init_num, init_den), nch = pd.set_meter_map(meter_pts, ppq=960)
    out = pd.serialize()
    ProjectData.parse(out)                      # must still walk cleanly
    (alt / "ProjectData").write_bytes(out)
    md = plistlib.loads((alt / "MetaData.plist").read_bytes())
    md["BeatsPerMinute"] = float(tempo_pts[0][1]) if tempo_pts else 120.0
    md["SongSignatureNumerator"] = init_num
    md["SongSignatureDenominator"] = init_den
    (alt / "MetaData.plist").write_bytes(plistlib.dumps(md, fmt=plistlib.FMT_BINARY))
    print(f"wrote {dst_bundle}")
    print(f"  source MIDI: {midi_path.name} ({div} PPQN)")
    print(f"  tempo events: {nt} (first {tempo_pts[0][1]} BPM)")
    print(f"  signature: initial {init_num}/{init_den} + {nch} change(s)")
    print(f"  meter changes: {[(t, f'{n}/{d}') for t, n, d in meter_pts]}")
    print(f"  ProjectData {len(out)}B, {len(pd.records)} records, round-trips OK")


def export_logicx(base_bundle: Path, midi_path: Path, out_bundle: Path,
                  *, tempo: bool = True, meter: bool = True, markers: bool = True,
                  verbose: bool = True) -> dict:
    """Write a native Logic `.logicx` from a MIDI file's tempo/meter/marker maps.

    base_bundle : a SETTLED .logicx template (must already contain a marker
                  track if markers=True — make one in Logic by adding then
                  removing a marker and saving; see project notes).
    midi_path   : a Standard MIDI File carrying tempo (FF51), meter (FF58),
                  and/or marker (FF06) events.
    out_bundle  : destination .logicx (must not exist).

    Returns a summary dict; the heavy lifting is set_tempo_map / set_meter_map /
    set_markers, all driven from midimap and rescaled to Logic's 960 PPQ.
    """
    import plistlib
    import shutil
    from . import midimap
    if out_bundle.exists():
        raise ValueError(f"refusing to overwrite existing {out_bundle}")

    mm = midimap.parse_file(midi_path)
    div = mm.division
    rescale = lambda t: round(t * 960 / div)

    shutil.copytree(base_bundle, out_bundle,
                    ignore=shutil.ignore_patterns("Project File Backups"))
    alt = out_bundle / "Alternatives" / "000"
    pd = ProjectData.parse((alt / "ProjectData").read_bytes())

    summary = {"midi": midi_path.name, "ppq": div}
    if tempo:
        pts = [(rescale(t), bpm) for (t, _us, bpm) in mm.tempo_map]
        summary["tempo_events"] = pd.set_tempo_map(pts, ppq=960)
        summary["initial_bpm"] = pts[0][1] if pts else None
    if meter:
        pts = [(rescale(t), n, d) for (t, n, d, _c, _n) in mm.meter_map]
        (init_num, init_den), nch = pd.set_meter_map(pts, ppq=960)
        summary["initial_sig"] = f"{init_num}/{init_den}"
        summary["meter_changes"] = nch
    if markers:
        if pd._find_marker_qsve() is None:
            raise ValueError("base has no marker track; markers require a settled "
                             "base with a marker track (add+remove a marker in Logic)")
        summary["markers"] = pd.set_markers([(rescale(t), txt) for (t, txt) in mm.markers], ppq=960)

    out = pd.serialize()
    ProjectData.parse(out)                       # round-trip / walk sanity check
    (alt / "ProjectData").write_bytes(out)

    md = plistlib.loads((alt / "MetaData.plist").read_bytes())
    if tempo and summary.get("initial_bpm") is not None:
        md["BeatsPerMinute"] = float(summary["initial_bpm"])
    if meter and "initial_sig" in summary:
        md["SongSignatureNumerator"] = init_num
        md["SongSignatureDenominator"] = init_den
    (alt / "MetaData.plist").write_bytes(plistlib.dumps(md, fmt=plistlib.FMT_BINARY))
    summary["bytes"] = len(out)
    summary["records"] = len(pd.records)

    if verbose:
        print(f"exported {out_bundle}")
        for k in ("midi", "ppq", "tempo_events", "initial_bpm", "initial_sig",
                  "meter_changes", "markers", "bytes", "records"):
            if k in summary:
                print(f"  {k:14}: {summary[k]}")
    return summary


def add_audio_region(base_bundle: Path, template_bundle: Path, audio_wav: Path,
                     out_bundle: Path, tick: int = 0, verbose: bool = True) -> dict:
    """Place an audio file as a region in a .logicx (v1: position + length).

    base_bundle     : settled base with an empty audio track (F14-style).
    template_bundle : same base + one audio region already added (F15-style);
                      supplies the region/file-ref/pool record templates + the
                      Media/ scaffold. The user's audio is copied in under the
                      template's internal filename (region name stays templated).
    audio_wav       : the user's PCM .wav to place.
    tick            : 960-PPQ position from bar 1 (0 = bar 1).
    """
    import shutil
    import wave
    if out_bundle.exists():
        raise ValueError(f"refusing to overwrite existing {out_bundle}")
    with wave.open(str(audio_wav), "rb") as wf:
        nframes = wf.getnframes()
        framerate = wf.getframerate()
        bits = wf.getsampwidth() * 8
    region_name = audio_wav.stem                     # shown on the region in Logic
    base = ProjectData.parse((base_bundle / "Alternatives/000/ProjectData").read_bytes())
    tmpl = ProjectData.parse((template_bundle / "Alternatives/000/ProjectData").read_bytes())
    pd = ProjectData.with_audio_region(base, tmpl, tick=tick, sample_len=nframes,
                                       region_name=region_name, sample_rate=framerate,
                                       bits=bits, file_size=audio_wav.stat().st_size)
    if framerate in ProjectData.SR_GNOS:            # match the project rate to the file
        pd.set_project_sample_rate(framerate)
    out = pd.serialize()
    ProjectData.parse(out)                       # walk sanity check
    shutil.copytree(template_bundle, out_bundle,
                    ignore=shutil.ignore_patterns("Project File Backups"))
    (out_bundle / "Alternatives/000/ProjectData").write_bytes(out)
    # replace the templated wav with the user's audio (same internal filename)
    media = out_bundle / "Media" / "Audio Files"
    existing = sorted(media.glob("*.wav"))
    target = existing[0] if existing else media / "ZZAUDIOZZ.wav"
    shutil.copyfile(audio_wav, target)
    # match the project sample rate to the audio so it plays at the right speed
    import plistlib
    mdp = out_bundle / "Alternatives/000/MetaData.plist"
    md = plistlib.loads(mdp.read_bytes())
    md["SampleRate"] = int(framerate)
    mdp.write_bytes(plistlib.dumps(md, fmt=plistlib.FMT_BINARY))
    summary = {"audio": audio_wav.name, "frames": nframes, "rate": framerate,
               "region_name": region_name, "tick": tick,
               "internal_name": target.name, "project_SR": framerate, "bytes": len(out)}
    if verbose:
        print(f"exported {out_bundle}")
        for k, v in summary.items():
            print(f"  {k:14}: {v}")
    return summary


# Logic's LGWV peak-checksum is FORMAT-only (constant for a given rate/ch/bits;
# verified across files with different audio content). Algorithm opaque → lookup of
# observed values (stored as the LE u32 that struct.pack("<I", v) emits as those bytes).
_LGWV_FMT_CHECKSUM = {
    (44100, 2, 16): 0xe63fb4d3,   # → bytes d3 b4 3f e6
    (44100, 2, 24): 0xe63ada78,   # → bytes 78 da 3a e6
}


def _ensure_wav_lgwv(data: bytes) -> bytes:
    """Append a Logic `LGWV` waveform-overview chunk to a WAV that lacks one, so
    Logic won't REWRITE the file on import (which changes its byte size and breaks
    the lFuA file-size match → the region drops from the Project Audio bin while
    still playing). The chunk's SIZE is fixed by the frame count
    (`8 + 2*ceil(frames/256)` bytes of body), so the resulting file size is exactly
    what Logic itself would produce — even if Logic regenerates the (cosmetic) peak
    overview, the size stays put. Body = `[u32 frameCount][u32 checksum=0]
    [u16 abs-peak per 256-frame bin]`; the checksum + exact peak scaling are cosmetic
    (Logic recomputes them) so we use 0 + best-effort peaks. No-op if the WAV already
    has LGWV or isn't a parseable PCM WAV."""
    import array as _array
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return data
    i, bits, ch, sr, data_off, data_sz = 12, 16, 2, 44100, None, None
    while i + 8 <= len(data):
        cid = data[i:i + 4]
        sz = struct.unpack_from("<I", data, i + 4)[0]
        if cid == b"LGWV":
            return data
        if cid == b"fmt " and sz >= 16:
            _af, ch, sr, _br, _ba, bits = struct.unpack_from("<HHIIHH", data, i + 8)
        elif cid == b"data":
            data_off, data_sz = i + 8, sz
        i += 8 + sz + (sz & 1)
    if data_off is None or bits < 8 or ch < 1:
        return data
    import zlib as _zlib
    bps = bits // 8
    frames = data_sz // (ch * bps)
    bins = (frames + 255) // 256
    pcm = data[data_off:data_off + frames * ch * bps]
    div = 1 << (bits - 8)                                 # int8 scale: 256 (16b), 65536 (24b)

    def _i8(v):                                           # → signed int8, truncate toward zero
        return max(-128, min(127, int(v / div)))

    peaks = bytearray()
    if bps == 2:                                          # 16-bit: fast path via array
        a = _array.array("h"); a.frombytes(pcm)
        for b in range(bins):
            sl = a[b * 256 * ch:(b + 1) * 256 * ch]
            mn, mx = (min(sl), max(sl)) if sl else (0, 0)
            peaks += struct.pack("<bb", _i8(mn), _i8(mx))
    elif bps == 3:                                        # 24-bit
        for b in range(bins):
            mn, mx = 0x7fffffff, -0x80000000
            for o in range(b * 256 * ch * 3, min((b + 1) * 256 * ch, frames * ch) * 3, 3):
                v = int.from_bytes(pcm[o:o + 3], "little", signed=True)
                if v < mn:
                    mn = v
                if v > mx:
                    mx = v
            if mn > mx:
                mn = mx = 0
            peaks += struct.pack("<bb", _i8(mn), _i8(mx))
    elif bps == 1:                                        # 8-bit unsigned (centered 128)
        for b in range(bins):
            blk = pcm[b * 256 * ch:(b + 1) * 256 * ch]
            vals = [c - 128 for c in blk] or [0]
            peaks += struct.pack("<bb", max(-128, min(127, min(vals))),
                                 max(-128, min(127, max(vals))))
    else:                                                 # other depths: flat (size still correct)
        peaks = bytearray(2 * bins)
    # overview is int8 [min,max] per 256-frame bin; the u32 after frameCount is a
    # FORMAT checksum Logic VALIDATES (same for any audio of a given rate/ch/bits —
    # verified: all 24-bit files share one value, all 16-bit another). Its algorithm
    # is opaque, so use a lookup of known (rate, ch, bits) values; fall back to a
    # crc32 of the peaks for unknown formats (Logic will reject/re-import those).
    cksum = _LGWV_FMT_CHECKSUM.get((sr, ch, bits))
    if cksum is None:
        cksum = _zlib.crc32(bytes(peaks)) & 0xffffffff
    body = struct.pack("<II", frames, cksum) + bytes(peaks)
    chunk = b"LGWV" + struct.pack("<I", len(body)) + body
    if len(chunk) & 1:
        chunk += b"\x00"
    out = bytearray(data) + chunk
    struct.pack_into("<I", out, 4, len(out) - 8)          # fix RIFF size
    return bytes(out)


def _build_region_specs(template: "ProjectData", items):
    """Read each (track, wav, tick) item's wav, ensure it carries a Logic `LGWV`
    overview chunk (so Logic won't rewrite + resize it), and assign its REAL internal
    Media filename (basename, de-duplicated). Region display name = wav stem.
    Returns (regions, wav_assignments=[(internal_name, content_bytes)], rates)."""
    import wave
    regions, wav_assign, rates, seen = [], [], set(), {}
    for track, wav, tick in items:
        wav = Path(wav)
        with wave.open(str(wav), "rb") as wf:
            nframes, framerate = wf.getnframes(), wf.getframerate()
            bits, channels = wf.getsampwidth() * 8, wf.getnchannels()
        content = _ensure_wav_lgwv(wav.read_bytes())     # append LGWV if missing
        file_size = len(content)                          # post-LGWV size → lFuA
        internal = wav.name                              # real on-disk name
        if internal in seen:                             # de-dup collisions
            seen[internal] += 1
            internal = f"{wav.stem}_{seen[wav.name]}{wav.suffix}"
        else:
            seen[wav.name] = 0
        regions.append({"track": int(track), "tick": int(tick), "sample_len": nframes,
                        "region_name": wav.stem, "sample_rate": framerate, "bits": bits,
                        "channels": channels, "internal_name": internal, "file_size": file_size})
        wav_assign.append((internal, content))
        rates.add(framerate)
    return regions, wav_assign, rates


def _assemble_audio_bundle(template_bundle: Path, out_bundle: Path, out_bytes: bytes,
                           wav_assign, rates):
    """Write ProjectData, copy each wav to its internal Media name, prune orphan
    wavs, update MetaData.AudioFiles + SampleRate."""
    import plistlib
    import shutil
    shutil.copytree(template_bundle, out_bundle,
                    ignore=shutil.ignore_patterns("Project File Backups"))
    (out_bundle / "Alternatives/000/ProjectData").write_bytes(out_bytes)
    media = out_bundle / "Media" / "Audio Files"
    referenced = set()
    for internal, content in wav_assign:
        referenced.add(internal)
        (media / internal).write_bytes(content)
    for f in media.glob("*.wav"):
        if f.name not in referenced:
            f.unlink()
    mdp = out_bundle / "Alternatives/000/MetaData.plist"
    md = plistlib.loads(mdp.read_bytes())
    md["AudioFiles"] = [f"Audio Files/{internal}" for internal, _ in wav_assign]
    if len(rates) == 1:
        md["SampleRate"] = int(next(iter(rates)))
    mdp.write_bytes(plistlib.dumps(md, fmt=plistlib.FMT_BINARY))


def add_audio_regions(base_bundle: Path, template_bundle: Path, items,
                      out_bundle: Path, verbose: bool = True) -> dict:
    """Place an ARBITRARY number of audio regions (any tracks, multiple per track).

    base_bundle     : settled base with N empty audio tracks (F19-style).
    template_bundle : same base + one region on each track (F21-style) — the clone
                      prototype + Media scaffold. (Tracks must exist in it: 1..K.)
    items           : [(track, wav_path, tick)] — 1-based track, 960-PPQ tick.
                      Count is unbounded; multiple regions may share a track.

    Each region gets its own fixed-length internal Media filename; the user's wav
    is copied there. gnoS/OgnS are left untouched (Logic regenerates them)."""
    if out_bundle.exists():
        raise ValueError(f"refusing to overwrite existing {out_bundle}")
    base = ProjectData.parse((base_bundle / "Alternatives/000/ProjectData").read_bytes())
    tmpl = ProjectData.parse((template_bundle / "Alternatives/000/ProjectData").read_bytes())
    regions, wav_assign, rates = _build_region_specs(tmpl, items)
    pd = ProjectData.place_audio_regions(base, tmpl, regions)
    if len(rates) == 1 and next(iter(rates)) in ProjectData.SR_GNOS:
        pd.set_project_sample_rate(next(iter(rates)))
    out = pd.serialize()
    ProjectData.parse(out)                       # walk sanity check
    _assemble_audio_bundle(template_bundle, out_bundle, out, wav_assign, rates)
    summary = {"regions": len(items), "project_SR": (next(iter(rates)) if len(rates) == 1 else "mixed"),
               "placements": [(r["track"], r["region_name"], r["tick"], r["internal_name"])
                              for r in regions],
               "bytes": len(out), "records": len(pd.records)}
    if verbose:
        print(f"exported {out_bundle}")
        for k, v in summary.items():
            print(f"  {k:14}: {v}")
    return summary


def synthesize_audio_region_bundle(donor_bundle: Path, out_bundle: Path, items,
                                   verbose: bool = True) -> dict:
    """Emit a `.logicx` with an ARBITRARY number of audio regions — no per-count
    template (region synthesis, §10.7). Logic regenerates the gnoS object-registry
    + OgnS pool from the records on load (verified), so each region is just a
    cloned gRuA/lFuA + an 80-B placement event.

    donor_bundle : any session that has the TRACKS you want + at least ONE audio
                   region (the clone prototype + Media scaffold). E.g. a settled
                   N-track session with one region dragged onto track 1.
    items        : [(track, wav_path, tick)] — 1-based track, 960-PPQ tick. Count
                   is UNBOUNDED; multiple regions may share a track (beat slices)."""
    donor_bundle, out_bundle = Path(donor_bundle), Path(out_bundle)
    if out_bundle.exists():
        raise ValueError(f"refusing to overwrite existing {out_bundle}")
    donor = ProjectData.parse((donor_bundle / "Alternatives/000/ProjectData").read_bytes())
    regions, wav_assign, rates = _build_region_specs(donor, items)
    pd = ProjectData.synthesize_audio_regions(donor, regions)
    if len(rates) == 1 and next(iter(rates)) in ProjectData.SR_GNOS:
        pd.set_project_sample_rate(next(iter(rates)))
    out = pd.serialize()
    ProjectData.parse(out)                       # walk sanity check
    _assemble_audio_bundle(donor_bundle, out_bundle, out, wav_assign, rates)
    summary = {"regions": len(items), "tracks": sorted({r["track"] for r in regions}),
               "project_SR": (next(iter(rates)) if len(rates) == 1 else "mixed"),
               "bytes": len(out), "records": len(pd.records)}
    if verbose:
        print(f"exported {out_bundle}")
        for k, v in summary.items():
            print(f"  {k:12}: {v}")
    return summary


def _audio_track_count(pd: "ProjectData") -> int:
    """Number of arrange AUDIO-track rows = non-master karT (len 93) at idx 0x040000.
    (gnoS @0xf4 counts ALL tracks and is unreliable on settled files; the arrange
    rows are exact — they match the real 'N from 64' channel set.)"""
    return sum(1 for r in pd.records if r.tag == b"karT" and len(r.raw) == 93
               and _u32(r.raw, 0x08) == 0x040000 and _u32(r.raw, KART_CHAN) != KART_MASTER_CHAN)


# --- EMBEDDED DONOR SEEDS (§13) — self-contained data so the library needs NO loose -----
# .logicx donors at runtime. The data/ files are GENERATED by bake_seeds.py from the donor
# fixtures (provenance + how-to-regenerate: DONORS.md); never hand-edit them. Seeds pack a
# donor bundle's files (minus the cosmetic WindowImage.jpg); infra.json.gz holds the few
# pre-extracted constant records (so the 5 reference donors are NOT shipped at runtime).
import functools as _functools

_SEED_DIR = Path(__file__).resolve().parent / "data"


def _unpack_seed(blob: bytes) -> dict:
    """Unpack a baked seed → {relative_path: bytes} (mirror of bake_seeds.pack_seed)."""
    import gzip
    raw = gzip.decompress(blob)
    files, i = {}, 0
    while i < len(raw):
        pl = struct.unpack_from("<H", raw, i)[0]; i += 2
        path = raw[i:i + pl].decode("utf-8"); i += pl
        dl = struct.unpack_from("<I", raw, i)[0]; i += 4
        files[path] = bytes(raw[i:i + dl]); i += dl
    return files


@_functools.lru_cache(maxsize=None)
def _seed_files(name: str) -> dict:
    p = _SEED_DIR / f"{name}.seed"
    if not p.exists():
        raise FileNotFoundError(f"missing donor seed {p} — run `python3.12 bake_seeds.py` (see DONORS.md)")
    return _unpack_seed(p.read_bytes())


def _seed_base_pd(name: str) -> "ProjectData":
    """A FRESH ProjectData parse of a base seed (callers mutate it, so never cache the obj)."""
    return ProjectData.parse(_seed_files(name)["Alternatives/000/ProjectData"])


def _infra_dec(v):
    import base64
    if isinstance(v, dict):
        if "__b64__" in v:
            return base64.b64decode(v["__b64__"])
        if "__tuple__" in v:
            return tuple(_infra_dec(x) for x in v["__tuple__"])
        return {k: _infra_dec(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_infra_dec(x) for x in v]
    return v


@_functools.lru_cache(maxsize=1)
def _baked_infra() -> dict:
    """The pre-extracted infrastructure dict (instrument/audio infra + region prototypes),
    deserialized from data/infra.json.gz. Tags in (tag,bytes) pairs come back as bytes."""
    import gzip
    import json
    p = _SEED_DIR / "infra.json.gz"
    if not p.exists():
        raise FileNotFoundError(f"missing {p} — run `python3.12 bake_seeds.py` (see DONORS.md)")
    raw = _infra_dec(json.loads(gzip.decompress(p.read_bytes()).decode("utf-8")))

    def _retag(group):                                       # restore (b"tag", bytes) pairs
        return [(t.encode("latin-1") if isinstance(t, str) else t, d) for t, d in group]
    for key in ("instrument_infra", "audio_infra"):
        raw[key]["trio"] = _retag(raw[key]["trio"])
    raw["midi_region_proto"]["group"] = _retag(raw["midi_region_proto"]["group"])
    raw["audio_region_proto"]["group"] = _retag(raw["audio_region_proto"]["group"])
    return raw


# default donor providers (embedded) — file-path params on the public APIs override these
def _default_audio_base():
    return _seed_base_pd("audio_base")


def _default_mixed_base():
    return _seed_base_pd("mixed_base")


def _resolve_base(template_bundle, default_seed):
    """(base ProjectData, base bundle-files dict) from a `.logicx` PATH, or the EMBEDDED
    seed when `template_bundle` is None. The files dict carries the small bundle files the
    assembler reuses (MetaData / ProjectInformation)."""
    if template_bundle is None:
        files = dict(_seed_files(default_seed))
        return ProjectData.parse(files["Alternatives/000/ProjectData"]), files
    b = Path(template_bundle)
    files = {"Alternatives/000/ProjectData": (b / "Alternatives/000/ProjectData").read_bytes()}
    for f in ("Alternatives/000/MetaData.plist", "Resources/ProjectInformation.plist"):
        if (b / f).exists():
            files[f] = (b / f).read_bytes()
    return ProjectData.parse(files["Alternatives/000/ProjectData"]), files


def _assemble_bundle(base_files, out_bundle, out_bytes, *, wav_assign=(), rates=(), added_tracks=0):
    """Write a SELF-CONTAINED `.logicx` from `base_files` (the seed/donor's small files) +
    the synthesized `out_bytes` (ProjectData). Generates the MINIMAL file set Logic needs —
    ProjectData + MetaData (patched: AudioFiles/NumberOfTracks/SampleRate) + ProjectInformation
    + Media — and DROPS the cosmetic 154 KB WindowImage.jpg + the DisplayState* files
    (Logic-confirmed unneeded, 2026-06-01). No `copytree`, no donor cruft."""
    import plistlib
    alt = out_bundle / "Alternatives" / "000"
    alt.mkdir(parents=True)
    (alt / "ProjectData").write_bytes(out_bytes)
    if wav_assign:
        media = out_bundle / "Media" / "Audio Files"
        media.mkdir(parents=True)
        for internal, content in wav_assign:
            (media / internal).write_bytes(content)
    md = plistlib.loads(base_files["Alternatives/000/MetaData.plist"])
    md["AudioFiles"] = [f"Audio Files/{internal}" for internal, _ in wav_assign]
    md["NumberOfTracks"] = int(md.get("NumberOfTracks", 1)) + int(added_tracks)
    if len(set(rates)) == 1:
        md["SampleRate"] = int(next(iter(rates)))
    (alt / "MetaData.plist").write_bytes(plistlib.dumps(md, fmt=plistlib.FMT_BINARY))
    pi = base_files.get("Resources/ProjectInformation.plist")
    if pi:
        (out_bundle / "Resources").mkdir(parents=True, exist_ok=True)
        (out_bundle / "Resources" / "ProjectInformation.plist").write_bytes(pi)
    return out_bundle


def _assemble_combine_bundle(template_bundle: Path, out_bundle: Path, out_bytes: bytes,
                             wav_assign, rates, added_tracks: int):
    """Assemble a combine bundle from a track-synth template (which has no audio
    Media yet): create Media/Audio Files, write the wavs, and update MetaData
    (AudioFiles + SampleRate + NumberOfTracks += added_tracks, as the track-synth
    path does — a NumberOfTracks mismatch makes Logic reject the file)."""
    import plistlib
    import shutil
    shutil.copytree(template_bundle, out_bundle,
                    ignore=shutil.ignore_patterns("Project File Backups"))
    (out_bundle / "Alternatives/000/ProjectData").write_bytes(out_bytes)
    media = out_bundle / "Media" / "Audio Files"
    media.mkdir(parents=True, exist_ok=True)
    referenced = set()
    for internal, content in wav_assign:
        referenced.add(internal)
        (media / internal).write_bytes(content)
    for f in media.glob("*.wav"):
        if f.name not in referenced:
            f.unlink()
    mdp = out_bundle / "Alternatives/000/MetaData.plist"
    md = plistlib.loads(mdp.read_bytes())
    md["AudioFiles"] = [f"Audio Files/{internal}" for internal, _ in wav_assign]
    md["NumberOfTracks"] = int(md.get("NumberOfTracks", 1)) + int(added_tracks)
    if len(rates) == 1:
        md["SampleRate"] = int(next(iter(rates)))
    mdp.write_bytes(plistlib.dumps(md, fmt=plistlib.FMT_BINARY))


def synthesize_track_region_bundle(track_template_bundle: Path, prototype_bundle: Path,
                                   out_bundle: Path, items, *, seed=None, drummer=True,
                                   stereo=True, names=None, verbose: bool = True) -> dict:
    """THE COMBINE (§10.8): synthesize N audio TRACKS *and* their audio REGIONS in
    one call — arbitrary track count AND arbitrary regions, from a minimal template.

    track_template_bundle : a pre-allocated track-synth template (audio tracks made
                            in Logic then all-but-one deleted; e.g. '1 from 64'). The
                            combine activates exactly as many free slots as `items`
                            needs (track synthesis, §10.6).
    prototype_bundle      : ANY session with >=1 audio region (e.g. F18) — the region
                            clone prototype + the 80-B placement-event prototype
                            (region synthesis, §10.7). No Media is taken from it.
    items                 : [(track, wav, tick)] — 1-based audio track, 960-PPQ tick.
                            Tracks AND regions are both unbounded; multiple regions
                            may share a track (beat slices).
    stereo                : channel format per track (§10.6.7), AUTHORITATIVE — True
                            = all stereo (DEFAULT), False = all mono, or an iterable
                            of 1-based track numbers to make stereo (rest mono).
    names                 : display names (§10.6.8) — None = keep 'Audio N', a dict
                            {track: name}, or a list (names for tracks 1..len).

    The track-synth base is UNSETTLED (the big pre-allocated gnoS); region synthesis
    leaves gnoS/OgnS untouched and Logic regenerates the registry/pool on load.

    `track_template_bundle` / `prototype_bundle` may be None → use the EMBEDDED audio
    mixer seed + baked audio-region prototype (§13); pass a `.logicx` path to override."""
    out_bundle = Path(out_bundle)
    if out_bundle.exists():
        raise ValueError(f"refusing to overwrite existing {out_bundle}")
    if not items:
        raise ValueError("no regions given")
    pd, base_files = _resolve_base(track_template_bundle, "audio_base")
    have = _audio_track_count(pd)
    want = max(int(t) for t, _, _ in items)
    need = max(0, want - have)
    ids = IdGen(seed)
    for _ in range(need):
        activate_audio_track(pd, ids=ids, drummer=drummer)
    regions, wav_assign, rates = _build_region_specs(None, items)
    if prototype_bundle is not None:                          # explicit prototype session
        proto = ProjectData.parse((Path(prototype_bundle) / "Alternatives/000/ProjectData").read_bytes())
        pd = ProjectData.synthesize_audio_regions(pd, regions, prototype=proto)
    else:                                                    # embedded baked prototype (no F21)
        arp = _baked_infra()["audio_region_proto"]
        pd = ProjectData.synthesize_audio_regions(pd, regions, proto_group=arp["group"], proto_event=arp["event"])
    stereo_set = _normalize_stereo(stereo, have + need)
    for t in range(1, have + need + 1):
        set_track_stereo(pd, t, t in stereo_set)
    for t, nm in _normalize_names(names, have + need).items():    # names LAST (resizes ivnE)
        set_track_name(pd, t, nm)
    if len(rates) == 1 and next(iter(rates)) in ProjectData.SR_GNOS:
        pd.set_project_sample_rate(next(iter(rates)))
    out = pd.serialize()
    if ProjectData.parse(out).serialize() != out:
        raise RuntimeError("combined ProjectData failed round-trip")
    _assemble_bundle(base_files, out_bundle, out, wav_assign=wav_assign, rates=rates, added_tracks=need)
    summary = {"tracks": have + need, "synth_tracks": need, "regions": len(items),
               "track_list": sorted({int(t) for t, _, _ in items}),
               "stereo": sorted(_normalize_stereo(stereo, have + need)),
               "names": _normalize_names(names, have + need),
               "project_SR": (next(iter(rates)) if len(rates) == 1 else "mixed"),
               "bytes": len(out), "records": len(pd.records)}
    if verbose:
        print(f"exported {out_bundle}")
        for k, v in summary.items():
            print(f"  {k:13}: {v}")
    return summary


def export_all(base_bundle: Path, audio_template_bundle: Path, midi_path: Path,
               audio_wav: Path, out_bundle: Path, tick: int = 0, verbose: bool = True) -> dict:
    """One call: a complete .logicx with tempo + meter + markers (from MIDI) and
    an audio region (from a wav), on a unified base.

    base_bundle           : settled base with BOTH a marker track and an audio
                            track (F17-style).
    audio_template_bundle : base + one audio region (F18-style) — the delta template.
    midi_path             : SMF carrying tempo (FF51) / meter (FF58) / markers (FF06).
    audio_wav             : the song's PCM .wav.
    """
    import plistlib
    import shutil
    import wave
    from . import midimap
    if out_bundle.exists():
        raise ValueError(f"refusing to overwrite existing {out_bundle}")
    with wave.open(str(audio_wav), "rb") as wf:
        nframes, framerate, bits = wf.getnframes(), wf.getframerate(), wf.getsampwidth() * 8
    base = ProjectData.parse((base_bundle / "Alternatives/000/ProjectData").read_bytes())
    tmpl = ProjectData.parse((audio_template_bundle / "Alternatives/000/ProjectData").read_bytes())
    # 1) audio region (delta-replay), then 2) the MIDI maps on the result
    pd = ProjectData.with_audio_region(base, tmpl, tick=tick, sample_len=nframes,
                                       region_name=audio_wav.stem, sample_rate=framerate, bits=bits,
                                       file_size=audio_wav.stat().st_size)
    if framerate in ProjectData.SR_GNOS:
        pd.set_project_sample_rate(framerate)
    mm = midimap.parse_file(midi_path)
    div = mm.division
    nt = pd.set_tempo_map([(round(t * 960 / div), b) for t, _u, b in mm.tempo_map], ppq=960)
    (inn, ind), nch = pd.set_meter_map([(round(t * 960 / div), n, d) for t, n, d, _c, _n in mm.meter_map], ppq=960)
    nmk = pd.set_markers([(round(t * 960 / div), txt) for t, txt in mm.markers], ppq=960)
    out = pd.serialize()
    ProjectData.parse(out)                                   # walk sanity check
    # 3) assemble the bundle (template has the Media scaffold + MetaData.AudioFiles)
    shutil.copytree(audio_template_bundle, out_bundle,
                    ignore=shutil.ignore_patterns("Project File Backups"))
    (out_bundle / "Alternatives/000/ProjectData").write_bytes(out)
    media = out_bundle / "Media" / "Audio Files"
    existing = sorted(media.glob("*.wav"))
    shutil.copyfile(audio_wav, existing[0] if existing else media / "ZZAUDIOZZ.wav")
    mdp = out_bundle / "Alternatives/000/MetaData.plist"
    md = plistlib.loads(mdp.read_bytes())
    md["BeatsPerMinute"] = float(mm.tempo_map[0][2])
    md["SongSignatureNumerator"], md["SongSignatureDenominator"] = inn, ind
    md["SampleRate"] = int(framerate)
    mdp.write_bytes(plistlib.dumps(md, fmt=plistlib.FMT_BINARY))
    summary = {"midi": midi_path.name, "audio": audio_wav.name, "tempo_events": nt,
               "initial_sig": f"{inn}/{ind}", "meter_changes": nch, "markers": nmk,
               "audio_frames": nframes, "project_SR": framerate, "tick": tick,
               "bytes": len(out), "records": len(pd.records)}
    if verbose:
        print(f"exported {out_bundle}")
        for k, v in summary.items():
            print(f"  {k:14}: {v}")
    return summary


def export_all_multi(base_bundle: Path, audio_template_bundle: Path, midi_path: Path,
                     audio_items, out_bundle: Path, *, tempo: bool = True, meter: bool = True,
                     markers: bool = True, verbose: bool = True) -> dict:
    """One call: a complete MULTI-TRACK .logicx — tempo + meter + markers (from a
    MIDI) and one audio region per track (from a list of (track, wav, tick)).

    base_bundle           : settled base with a marker track AND N empty audio
                            tracks (F19-style).
    audio_template_bundle : same base + one region on each track (F21-style) —
                            the delta template. Its track set defines N.
    midi_path             : SMF carrying tempo (FF51) / meter (FF58) / markers (FF06).
    audio_items           : [(track, wav_path, tick)] — one per audio track; the
                            track set MUST equal the template's.

    Pipeline: with_audio_regions (multi-audio delta-replay) -> set_tempo_map ->
    set_meter_map -> set_markers, then assemble the bundle (copy each wav over its
    track's internal filename, prune orphans, write MetaData). Markers are skipped
    if the base has no marker track.
    """
    import plistlib
    from . import midimap
    if out_bundle.exists():
        raise ValueError(f"refusing to overwrite existing {out_bundle}")
    base = ProjectData.parse((base_bundle / "Alternatives/000/ProjectData").read_bytes())
    tmpl = ProjectData.parse((audio_template_bundle / "Alternatives/000/ProjectData").read_bytes())

    # 1) audio: build region specs (arbitrary count), place by cloning the prototype
    regions, wav_assign, rates = _build_region_specs(tmpl, audio_items)
    pd = ProjectData.place_audio_regions(base, tmpl, regions)
    if len(rates) == 1 and next(iter(rates)) in ProjectData.SR_GNOS:
        pd.set_project_sample_rate(next(iter(rates)))

    # 2) MIDI maps on the result
    mm = midimap.parse_file(midi_path)
    div = mm.division
    summary = {"midi": midi_path.name, "regions": len(audio_items)}
    if tempo:
        summary["tempo_events"] = pd.set_tempo_map(
            [(round(t * 960 / div), b) for t, _u, b in mm.tempo_map], ppq=960)
    inn = ind = None
    if meter:
        (inn, ind), nch = pd.set_meter_map(
            [(round(t * 960 / div), n, d) for t, n, d, _c, _n in mm.meter_map], ppq=960)
        summary["initial_sig"], summary["meter_changes"] = f"{inn}/{ind}", nch
    if markers:
        if pd._find_marker_qsve() is not None and pd._marker_meta_qsxt_index() is not None:
            summary["markers"] = pd.set_markers(
                [(round(t * 960 / div), txt) for t, txt in mm.markers], ppq=960)
        else:
            summary["markers"] = "skipped (base has no marker track)"

    out = pd.serialize()
    ProjectData.parse(out)                                   # walk sanity check

    # 3) assemble bundle (audio media + MetaData.AudioFiles/SR), then add BPM/sig
    _assemble_audio_bundle(audio_template_bundle, out_bundle, out, wav_assign, rates)
    mdp = out_bundle / "Alternatives/000/MetaData.plist"
    md = plistlib.loads(mdp.read_bytes())
    if tempo and mm.tempo_map:
        md["BeatsPerMinute"] = float(mm.tempo_map[0][2])
    if meter and inn is not None:
        md["SongSignatureNumerator"], md["SongSignatureDenominator"] = inn, ind
    mdp.write_bytes(plistlib.dumps(md, fmt=plistlib.FMT_BINARY))

    summary["placements"] = [(r["track"], r["region_name"], r["tick"]) for r in regions]
    summary["project_SR"] = next(iter(rates)) if len(rates) == 1 else "mixed"
    summary["bytes"], summary["records"] = len(out), len(pd.records)
    if verbose:
        print(f"exported {out_bundle}")
        for k, v in summary.items():
            print(f"  {k:14}: {v}")
    return summary


def with_midi_region(template_bundle: Path, out_bundle: Path, notes, *,
                     region_tick=None, region_length=None, region_name: str = "Inst 1"):
    """Write `template_bundle` (a .logicx with ONE empty MIDI region — e.g.
    fixtures/F4_midiregion.logicx) to `out_bundle`, injecting `notes` into the
    region's note sequence. `notes` = [(tick, pitch, velocity, length)] with
    `tick` region-RELATIVE (960 PPQ from the region start) and `length` in ticks.
    The region keeps its template TRACK. Pass `region_tick` (960-PPQ from bar 1)
    to move it to a given position: patches the placement pos (+0x04 = 34560+tick)
    + the region qeSM start (+0x11c = tick) + the placement's +0x0c (shifted by the
    bar delta, ×0x100/4-4-bar, matching F4→F5); track-cluster display caches are
    left for Logic to recompute (proven safe for audio). Without it, the region
    keeps the template position. Refuses to overwrite an existing bundle."""
    import shutil
    if out_bundle.exists():
        raise ValueError(f"refusing to overwrite existing {out_bundle}")
    shutil.copytree(template_bundle, out_bundle)
    alt = out_bundle / "Alternatives" / "000"
    pd = ProjectData.parse((alt / "ProjectData").read_bytes())

    # region container = qeSM whose name (u16 len @ RECORD+0x34, string @+0x36;
    # i.e. payload+0x10) == region_name
    want = region_name.encode("latin-1")
    region_idxs = set()
    for r in pd.records:
        if r.tag == b"qeSM" and len(r.raw) >= 0x38:
            ln = struct.unpack_from("<H", r.raw, 0x34)[0]
            if r.raw[0x36:0x36 + ln] == want:
                region_idxs.add(_u32(r.raw, 0x08))
    if not region_idxs:
        raise ValueError(f"no region qeSM named {region_name!r} in template")

    # the note qSvE: at a region idx, an event seq that's empty (0xf1 tail) or
    # already carries notes (0x90) — NOT a placement seq (0x20)
    target = next((r for r in pd.records
                   if r.tag == b"qSvE" and _u32(r.raw, 0x08) in region_idxs
                   and _u32(r.raw, REC_SIZE_OFF) >= 4
                   and _u32(r.raw, REC_HEADER_SIZE) in (0x90, 0xf1)), None)
    if target is None:
        raise ValueError(f"no note qSvE for region named {region_name!r}")
    rid = _u32(target.raw, 0x08)

    payload = ProjectData.build_note_qsve_payload(notes)
    hdr = bytearray(target.raw[:REC_HEADER_SIZE])
    struct.pack_into("<I", hdr, REC_SIZE_OFF, len(payload))
    target.raw = bytes(hdr) + payload

    # the region qeSM (same cluster idx as the note qSvE)
    region_q = next((r for r in pd.records if r.tag == b"qeSM"
                     and _u32(r.raw, 0x08) == rid and len(r.raw) > 0x120), None)

    # region LENGTH @ region qeSM +0x78 (960-PPQ ticks) — contain the notes:
    # default rounds up to the next 4/4 bar (min 1 bar); else use `region_length`.
    length = None
    if region_q is not None:
        maxend = max((t + ln for (t, _p, _v, ln) in notes), default=0)
        length = int(region_length) if region_length is not None \
            else max(3840, -(-maxend // 3840) * 3840)
        raw = bytearray(region_q.raw)
        struct.pack_into("<I", raw, 0x78, length)
        region_q.raw = bytes(raw)

    # optional: move the region to `region_tick` (960-PPQ from bar 1)
    if region_tick is not None:
        rt = int(region_tick)
        if region_q is not None:                               # region start @ qeSM +0x11c
            raw = bytearray(region_q.raw)
            struct.pack_into("<I", raw, 0x11c, rt)
            region_q.raw = bytes(raw)
        plc = next((r for r in pd.records                      # placement event (0x20 marker)
                    if r.tag == b"qSvE" and _u32(r.raw, REC_SIZE_OFF) >= 8
                    and _u32(r.raw, REC_HEADER_SIZE) == 0x20), None)
        if plc is None:
            raise ValueError("placement event (0x20) not found")
        raw = bytearray(plc.raw)
        old_pos = _u32(raw, 0x28)
        new_pos = ProjectData.AUDIO_REGION_ORIGIN + rt
        struct.pack_into("<I", raw, 0x28, new_pos)             # placement pos +0x04
        dbars = (new_pos - old_pos) // 3840                    # +0x0c shifts ×0x100/bar
        struct.pack_into("<I", raw, 0x30, _u32(raw, 0x30) + dbars * 0x100)
        plc.raw = bytes(raw)

    (alt / "ProjectData").write_bytes(pd.serialize())
    where = "template pos" if region_tick is None else f"tick {int(region_tick)}"
    print(f"wrote {out_bundle}")
    print(f"  injected {len(notes)} note(s) into region idx 0x{rid:x} @ {where}, "
          f"length {length} ticks (note qSvE {len(payload)}B)")
    return {"region_idx": rid, "notes": len(notes), "qsve_payload": len(payload),
            "region_tick": region_tick, "region_length": length}


def with_midi_file_region(template_bundle: Path, midi_path: Path, out_bundle: Path,
                          *, channel=None, region_tick=None, region_name: str = "Inst 1"):
    """Place the NOTES from a Standard MIDI File as ONE MIDI region (rescaled to
    960 PPQ). `channel` (0-based) keeps only that MIDI channel (None = all). The
    region sits at `region_tick` (960-PPQ from bar 1; None = the template's
    position); note ticks are file-absolute from bar 1, so a region at bar 1
    preserves the file's timing. Builds on `with_midi_region`."""
    from . import midimap
    mm = midimap.parse_file(midi_path)
    notes = mm.rescaled_notes(960, channel=channel)
    if not notes:
        raise ValueError(f"no notes in {midi_path}"
                         + (f" on channel {channel}" if channel is not None else ""))
    res = with_midi_region(template_bundle, out_bundle, notes,
                           region_tick=region_tick, region_name=region_name)
    res["midi"] = str(midi_path)
    return res


def _set_region_name(raw, name):
    """Set a MIDI region qeSM's display name, RESIZING the record. The name is
    VARIABLE-LENGTH — [u16 len @RECORD+0x34][ASCII @+0x36][pad→even][rest…] — with
    `rest` immediately after the string; writing in place / leaving stale bytes
    CORRUPTS the file (Logic walks len→name→rest). Mirrors the validated
    `ProjectData._patch_grua_name`. The +0x78 length / +0x11c position fields sit
    after the name and shift on resize (values preserved), so patch them BEFORE
    calling this."""
    no = 0x34
    old_len = struct.unpack_from("<H", raw, no)[0]
    old_field = 2 + old_len + (old_len & 1)            # [u16 len][name][pad→even]
    nb = name.encode("latin-1", "replace")
    new_field = struct.pack("<H", len(nb)) + nb + (b"\x00" if len(nb) & 1 else b"")
    new = bytearray(raw[:no]) + new_field + raw[no + old_field:]
    struct.pack_into("<I", new, REC_SIZE_OFF, len(new) - REC_HEADER_SIZE)
    return bytes(new)


def _fill_midi_regions(pd, region_notes, *, region_names=None, region_lengths=None,
                       name_prefix="Inst "):
    """Fill `pd`'s K empty MIDI regions (qeSM named `name_prefix`+N, paired with
    an empty/note qSvE), in cluster-index order, with notes. Mutates `pd`;
    returns a per-region summary list. Raises if more note-lists than regions."""
    want = name_prefix.encode("latin-1")
    regions = []                                    # (idx, name, region_qeSM, note_qSvE)
    for r in pd.records:
        if r.tag == b"qeSM" and len(r.raw) > 0x120:
            ln = struct.unpack_from("<H", r.raw, 0x34)[0]
            nm = r.raw[0x36:0x36 + ln] if ln < 64 else b""
            if nm.startswith(want):
                idx = _u32(r.raw, 0x08)
                nq = next((rr for rr in pd.records if rr.tag == b"qSvE"
                           and _u32(rr.raw, 0x08) == idx and _u32(rr.raw, REC_SIZE_OFF) >= 4
                           and _u32(rr.raw, REC_HEADER_SIZE) in (0x90, 0xf1)), None)
                if nq is not None:
                    regions.append((idx, nm, r, nq))
    regions.sort(key=lambda t: t[0])
    if len(region_notes) > len(regions):
        raise ValueError(f"{len(region_notes)} note-lists but template has "
                         f"{len(regions)} {name_prefix!r} regions")
    summary = []
    for i, notes in enumerate(region_notes):
        idx, nm, region_q, note_q = regions[i]
        payload = ProjectData.build_note_qsve_payload(notes)
        hdr = bytearray(note_q.raw[:REC_HEADER_SIZE])
        struct.pack_into("<I", hdr, REC_SIZE_OFF, len(payload))
        note_q.raw = bytes(hdr) + payload
        maxend = max((t + ln for (t, _p, _v, ln) in notes), default=0)
        length = (int(region_lengths[i]) if region_lengths and region_lengths[i] is not None
                  else max(3840, -(-maxend // 3840) * 3840))
        raw = bytearray(region_q.raw)
        struct.pack_into("<I", raw, 0x78, length)
        region_q.raw = bytes(raw)
        shown = nm.decode("latin-1", "replace")
        if region_names and i < len(region_names) and region_names[i]:
            region_q.raw = _set_region_name(region_q.raw, region_names[i])
            n2 = struct.unpack_from("<H", region_q.raw, 0x34)[0]
            shown = region_q.raw[0x36:0x36 + n2].decode("latin-1", "replace")
        summary.append({"name": shown, "notes": len(notes), "length": length})
    return summary


def place_midi_regions(template_bundle: Path, out_bundle: Path, region_notes, *,
                       region_names=None, region_lengths=None, name_prefix: str = "Inst "):
    """Fill the K empty MIDI regions of `template_bundle` (regions named
    `name_prefix`+N — e.g. F22_multimidi.logicx with 'Inst 1'..'Inst 4') with
    notes: one note-list per region in cluster-index order. `region_notes` =
    list of [(tick, pitch, velocity, length)] (region-relative @960 PPQ);
    len(region_notes) <= K. Each region's note qSvE is filled and its length
    (+0x78) auto-sized to contain the notes (or set from `region_lengths[i]`).
    Regions keep their template track + position (you pre-placed them in Logic)."""
    import shutil
    if out_bundle.exists():
        raise ValueError(f"refusing to overwrite existing {out_bundle}")
    shutil.copytree(template_bundle, out_bundle)
    alt = out_bundle / "Alternatives" / "000"
    pd = ProjectData.parse((alt / "ProjectData").read_bytes())
    summary = _fill_midi_regions(pd, region_notes, region_names=region_names,
                                 region_lengths=region_lengths, name_prefix=name_prefix)
    (alt / "ProjectData").write_bytes(pd.serialize())
    print(f"wrote {out_bundle}")
    for s in summary:
        print(f"  {s['name']}: {s['notes']} notes, length {s['length']} ticks")
    return {"regions": summary}


def place_midi_files(template_bundle: Path, out_bundle: Path, midi_paths, *,
                     channel=None, name_prefix: str = "Inst ", rename: bool = True):
    """Place each Standard MIDI File's notes into its own region (one region per
    file, in order). Builds on place_midi_regions; len(midi_paths) <= K. With
    `rename` (default), each region is named after its file (the last '_'-segment
    of the stem, capped to the template's region-name length)."""
    from . import midimap
    region_notes = [midimap.parse_file(p).rescaled_notes(960, channel=channel)
                    for p in midi_paths]
    names = [Path(p).stem.split("_")[-1] for p in midi_paths] if rename else None
    res = place_midi_regions(template_bundle, out_bundle, region_notes,
                             region_names=names, name_prefix=name_prefix)
    res["midi_files"] = [str(p) for p in midi_paths]
    return res


def export_midi_multi(template_bundle: Path, out_bundle: Path, part_midis, *,
                      master_midi=None, channel=None, name_prefix: str = "Inst ",
                      rename: bool = True, verbose: bool = True) -> dict:
    """Unified MIDI export: write `template_bundle` (a multi-region MIDI template
    like F22_multimidi.logicx) to `out_bundle` with the song's tempo + meter (and
    markers, if the template has a marker track) taken from `master_midi`, AND
    each part MIDI's notes placed in its own region. One region per `part_midis`
    entry, in order (len <= K). `master_midi=None` skips the tempo/meter/markers.
    Mirrors export_all_multi, but for MIDI parts instead of audio."""
    import shutil
    import plistlib
    from . import midimap
    if out_bundle.exists():
        raise ValueError(f"refusing to overwrite existing {out_bundle}")
    shutil.copytree(template_bundle, out_bundle)
    alt = out_bundle / "Alternatives" / "000"
    pd = ProjectData.parse((alt / "ProjectData").read_bytes())
    summary = {"parts": len(part_midis)}

    inn = ind = bpm0 = None
    if master_midi is not None:
        mm = midimap.parse_file(master_midi)
        div = mm.division
        summary["tempo_events"] = pd.set_tempo_map(
            [(round(t * 960 / div), b) for t, _u, b in mm.tempo_map], ppq=960)
        (inn, ind), nch = pd.set_meter_map(
            [(round(t * 960 / div), n, d) for t, n, d, _c, _n in mm.meter_map], ppq=960)
        summary["initial_sig"], summary["meter_changes"] = f"{inn}/{ind}", nch
        if pd._find_marker_qsve() is not None and pd._marker_meta_qsxt_index() is not None:
            summary["markers"] = pd.set_markers(
                [(round(t * 960 / div), txt) for t, txt in mm.markers], ppq=960)
        else:
            summary["markers"] = "skipped (template has no marker track)"
        bpm0 = mm.tempo_map[0][2] if mm.tempo_map else None

    # parts -> regions (named after each part file when `rename`)
    region_notes = [midimap.parse_file(p).rescaled_notes(960, channel=channel)
                    for p in part_midis]
    names = [Path(p).stem.split("_")[-1] for p in part_midis] if rename else None
    summary["regions"] = _fill_midi_regions(pd, region_notes, region_names=names,
                                            name_prefix=name_prefix)

    out = pd.serialize()
    ProjectData.parse(out)                                   # walk sanity check
    (alt / "ProjectData").write_bytes(out)

    if master_midi is not None:                              # MetaData BPM + signature
        mdp = alt / "MetaData.plist"
        md = plistlib.loads(mdp.read_bytes())
        if bpm0 is not None:
            md["BeatsPerMinute"] = float(bpm0)
        if inn is not None:
            md["SongSignatureNumerator"], md["SongSignatureDenominator"] = inn, ind
        mdp.write_bytes(plistlib.dumps(md, fmt=plistlib.FMT_BINARY))

    summary["bytes"], summary["records"] = len(out), len(pd.records)
    if verbose:
        print(f"exported {out_bundle}")
        for k, v in summary.items():
            print(f"  {k:14}: {v}")
    return summary


# Empty audio-pool OgnS payload (id 0x1080000) — byte-identical across F17/F19/F22,
# so a project-independent constant. Used to reset a populated pool without a base.
_EMPTY_AUDIO_OGNS_PAYLOAD = bytes.fromhex(
    "20000000000000000000000000000000a0280000010099ed1000000000000000")


def _patch_audio_inplace(pd, regions):
    """Patch a combined template's EXISTING audio regions IN PLACE (file / length /
    format + placement position), preserving the MIDI (0x20) placement events that
    share the arrange qSvE — so this does NOT rebuild the qSvE the way
    place_audio_regions does. `regions` = `_build_region_specs` output, one per
    audio slot (slot order). Also empties the audio-pool OgnS + drops per-region
    audio MneG (id >= 0x40000; MIDI regions carry none)."""
    bi = pd._region_records_by_index()
    slots = sorted(i for i in bi if "gRuA" in bi[i] and "lFuA" in bi[i])
    if len(regions) != len(slots):
        raise ValueError(f"{len(regions)} audio item(s) but template has "
                         f"{len(slots)} audio region(s)")
    for i, spec in enumerate(regions):                 # gRuA/lFuA per region
        if spec.get("internal_name"):
            li = bi[i]["lFuA"]
            pd.records[li].raw = ProjectData._set_lfua_filename(pd.records[li].raw, spec["internal_name"])
        pd.patch_audio_region(i, sample_len=spec.get("sample_len"), region_name=spec.get("region_name"),
                              sample_rate=spec.get("sample_rate"), bits=spec.get("bits"),
                              channels=spec.get("channels"), file_size=spec.get("file_size"))
    # patch each 0x24 (audio) placement event IN PLACE, by link = regionIndex*4
    EV = ProjectData.PLACEMENT_EVENT_SIZE
    qi = next((j for j, r in enumerate(pd.records) if r.tag == b"qSvE"
               and _u32(r.raw, REC_SIZE_OFF) >= EV
               and any(_u32(r.raw, REC_HEADER_SIZE + o) == 0x24
                       for o in range(0, _u32(r.raw, REC_SIZE_OFF) - 16, EV))), None)
    if qi is None:
        raise ValueError("no audio placement event (0x24) found")
    raw = bytearray(pd.records[qi].raw)
    ps = _u32(raw, REC_SIZE_OFF)
    for o in range(0, ps - 16, EV):
        off = REC_HEADER_SIZE + o
        if _u32(raw, off) != 0x24:                     # skip MIDI (0x20) events
            continue
        ri = _u32(raw, off + 0x2c) // 4                # link @+0x2c = regionIndex*4
        if 0 <= ri < len(regions):
            struct.pack_into("<I", raw, off + ProjectData.PLACEMENT_POS_OFF,
                             ProjectData.AUDIO_REGION_ORIGIN + regions[ri]["tick"])
    pd.records[qi].raw = bytes(raw)
    # empty the populated audio pool (keep header/id, swap to the empty payload)
    for r in pd.records:
        if r.tag == b"OgnS" and b"bplist00" in r.raw:
            hdr = bytearray(r.raw[:REC_HEADER_SIZE])
            struct.pack_into("<I", hdr, REC_SIZE_OFF, len(_EMPTY_AUDIO_OGNS_PAYLOAD))
            r.raw = bytes(hdr) + _EMPTY_AUDIO_OGNS_PAYLOAD
    pd.records = [r for r in pd.records
                  if not (r.tag == b"MneG" and _u32(r.raw, 8) >= 0x40000)]


def export_av_multi(template_bundle: Path, out_bundle: Path, *, master_midi=None,
                    audio_items=None, midi_parts=None, channel=None,
                    name_prefix: str = "Inst ", rename: bool = True, verbose: bool = True) -> dict:
    """ONE call: a COMBINED audio + MIDI .logicx from a single template (F23_av-style
    = M audio tracks w/ placeholder regions + N empty MIDI regions 'Inst N' + a
    marker track). `audio_items` = [(wav, tick)] one per audio region (slot order,
    len == M); `midi_parts` = [midi_path] one per MIDI region (len <= N); the song
    tempo/meter/markers come from `master_midi`. Audio regions are patched IN PLACE
    (preserving the MIDI placements); MIDI regions are filled; then the maps."""
    import plistlib
    from . import midimap
    if out_bundle.exists():
        raise ValueError(f"refusing to overwrite existing {out_bundle}")
    audio_items = list(audio_items or [])
    midi_parts = list(midi_parts or [])
    pd = ProjectData.parse((template_bundle / "Alternatives/000/ProjectData").read_bytes())
    summary = {"audio": len(audio_items), "midi_parts": len(midi_parts)}

    # 1) audio — in place
    wav_assign, rates = [], set()
    if audio_items:
        regions, wav_assign, rates = _build_region_specs(pd, [(0, w, t) for w, t in audio_items])
        _patch_audio_inplace(pd, regions)
        if len(rates) == 1 and next(iter(rates)) in ProjectData.SR_GNOS:
            pd.set_project_sample_rate(next(iter(rates)))

    # 2) MIDI parts -> regions
    if midi_parts:
        region_notes = [midimap.parse_file(p).rescaled_notes(960, channel=channel) for p in midi_parts]
        names = [Path(p).stem.split("_")[-1] for p in midi_parts] if rename else None
        summary["regions"] = _fill_midi_regions(pd, region_notes, region_names=names, name_prefix=name_prefix)

    # 3) tempo / meter / markers from the master MIDI
    inn = ind = bpm0 = None
    if master_midi is not None:
        mm = midimap.parse_file(master_midi)
        div = mm.division
        summary["tempo_events"] = pd.set_tempo_map(
            [(round(t * 960 / div), b) for t, _u, b in mm.tempo_map], ppq=960)
        (inn, ind), _nch = pd.set_meter_map(
            [(round(t * 960 / div), n, d) for t, n, d, _c, _n in mm.meter_map], ppq=960)
        summary["initial_sig"] = f"{inn}/{ind}"
        if pd._find_marker_qsve() is not None and pd._marker_meta_qsxt_index() is not None:
            summary["markers"] = pd.set_markers(
                [(round(t * 960 / div), txt) for t, txt in mm.markers], ppq=960)
        bpm0 = mm.tempo_map[0][2] if mm.tempo_map else None

    out = pd.serialize()
    ProjectData.parse(out)                                   # walk sanity check
    _assemble_audio_bundle(template_bundle, out_bundle, out, wav_assign, rates)

    mdp = out_bundle / "Alternatives/000/MetaData.plist"     # BPM + signature
    md = plistlib.loads(mdp.read_bytes())
    if bpm0 is not None:
        md["BeatsPerMinute"] = float(bpm0)
    if inn is not None:
        md["SongSignatureNumerator"], md["SongSignatureDenominator"] = inn, ind
    mdp.write_bytes(plistlib.dumps(md, fmt=plistlib.FMT_BINARY))

    summary["bytes"], summary["records"] = len(out), len(pd.records)
    if verbose:
        print(f"exported {out_bundle}")
        for k, v in summary.items():
            print(f"  {k:14}: {v}")
    return summary


# ======================================================================
# AUDIO TRACK SYNTHESIS — activate pre-allocated mixer slots (task #34).
#
# A template made by creating N audio tracks in Logic then deleting all but
# one KEEPS the N-channel mixer (pre-allocated OCuA strips + gnoS registry
# slots). `activate_audio_track(pd)` replays Logic's exact per-add byte-delta,
# so calling it K times synthesizes K extra EMPTY audio tracks WITHOUT a
# per-count donor. Full byte spec + the visibility-gate saga: PROJECTDATA_FORMAT
# §10.6 / §10.6.1. Validated in Logic at 4/9/13 tracks (≤ template's free slots).
#
# NOTE: this adds EMPTY tracks. Putting audio/MIDI REGION content on synthesized
# tracks needs REGION synthesis (cloning gRuA/lFuA per track) — a separate
# follow-on; the existing region exporters remain template-bound for now.
# ======================================================================
SYNTH_IDX_STRIDE = 0x40000

# gnoS offsets
GNOS_MAXIVNE = 0x80      # u32: highest ivnE idx in use (== last activated)
GNOS_TRACKCOUNT = 0xf4   # u32: (track count) << 16
GNOS_COUNT_HI = 0xf8     # u32: (trackcount<<16)|1
GNOS_T1_ROW0 = 0x1e20    # Table1 (ivnE registry) rows: [0x14][idx][uuid16], stride 0x18
GNOS_T1_STRIDE = 0x18
GNOS_T1_HDR = 0x1e10
GNOS_T2_ROW0 = 0x4db0    # Table2 rows: [id8][0x14][idx], stride 0x10
GNOS_T2_STRIDE = 0x10
GNOS_T3_ROW0 = 0x5240    # Table3 rows: [id8][0x17][idx] (running stamps)
GNOS_T3_STRIDE = 0x10

# ivnE clone offsets
IVNE_IDX = 0x08
IVNE_IDX2 = 0x34
IVNE_LINK76 = 0x76
IVNE_ORD_CA = 0xca
IVNE_ORD_CC = 0xcc
IVNE_ORD_CF = 0xcf
IVNE_UUID = 0x1eb
IVNE_ISLAST = 0x74
IVNE_SRC51 = 0x51
# Channel/track DISPLAY NAME — variable-length [u16 char-count @0xc2][ASCII @0xc4][pad
# to even]. This is the name a synth track SHOWS (the @0xca counter above is just its
# last char → "Audio :" past track 9). Replace the whole field (RESIZE) for an
# arbitrary name; this also cures the >9 garble. §10.6.8.
IVNE_NAME_LEN = 0xc2
IVNE_NAME = 0xc4

# karT arrange-track row (93B, idx 0x040000 group) — what the arrange/mixer SHOWS
KART_ORD = 0x12
KART_BLK = 0x10
KART_CHAN = 0x2a         # u32: channel idx this arrange-track points at
KART_ID16 = 0x3c         # 16B: row id (== its MneG Session-Player key)
KART_LAST = 0x4c         # 0x20 on most-recently-created audio track, else 0x00
KART_BASE_CHAN = 0x580000
KART_MASTER_CHAN = 0x500000

# OCuA channel-strip activation (@0x08==0x240000 is a TYPE tag, not a unique idx)
OCUA_SEQ = 0x82
OCUA_F3C = 0x3c
OCUA_F3D = 0x3d
OCUA_UUID = 0xbd
# Channel FORMAT (mono↔stereo). RE'd 2026-05-31 from a 1-track mono-vs-stereo Logic
# differential (fixtures/stereo test/): an audio track's `OCuA` strip encodes stereo
# in exactly THREE bytes (identical across all 426 mono strips → fixed constants, not
# per-channel). The Song @0x102 byte that also moved is incidental UI state (mono
# files carry both values), NOT load-bearing.
OCUA_FMT_CFG = 0x72      # config word byte: bit 0x04 = stereo (mono 0xd3 → stereo 0xd7)
OCUA_FMT_FLAG = 0x7a     # format flag: mono 0x00 → stereo 0x01
OCUA_FMT_NCH = 0x9f      # channel count: mono 0x01 → stereo 0x02

# MneG (Session-Player) JSON length counters
MNEG_CNT_24 = 0x24
MNEG_CNT_40 = 0x40

ARR_ORDER_IDX = 0x080000    # qSvE arrange-order table
ARR_ORDER_ROW0 = 0x38
ARR_QESM_IDX = 0x040000     # arrange qeSM carrying the name @0x34 + track-area height
ARR_MT_OFF = 0xa            # u16 (name_end + 0xa) = arrange track-area height
ARR_ROW_H = 0x3c            # per-track row height; total = 0x3c * (N tracks + 1 master)
TRK_IDX = 0x080000          # karT per-slot "Track" objects
TRK_SLOT = 0x2c
TRK_RANK = 0x12
TRK_FIXED = 4
TRK_SLOT0 = 0x48
QESM_ORD = 0x114

MNEG_DICT_MARK = b'drummerModelTrackStates":{'
MNEG_ENTRY_BODY = ('{"keepDrumKitWhenChangingDrummer":false,"selectedCharacterIdentifier":'
                   '"Acoustic Drummer - Pop Rock","isUsingProducerKit":false,"stateVersion":3,'
                   '"keepSettingsWhenChangingDrummer":false,'
                   '"selectedPersistentCharacterTypeIdentifier":"Type_AcousticDrummerV2",'
                   '"parametersWhereChangedAfterCharacterRecall":false}')


class IdGen:
    """Fresh 'time-UUID'-shaped ids. Seedable for reproducible tests; default is
    os.urandom (every synthesized track gets unique ids)."""
    def __init__(self, seed=None):
        self.r = random.Random(seed) if seed is not None else None

    def _b(self, n):
        if self.r is not None:
            return bytes(self.r.randrange(256) for _ in range(n))
        return os.urandom(n)

    def time_low(self):
        return self._b(4)

    def node(self):
        return self._b(8)

    def uuid16(self, const_a):
        return self.time_low() + const_a + self.node()


def _synth_find(recs, tag, idx):
    for i, r in enumerate(recs):
        if r.tag == tag and _u32(r.raw, IVNE_IDX) == idx:
            return i, r
    return None, None


def _synth_next_strip(recs, T):
    """Pre-allocated channel strip to activate: zero UUID @0xbd, ordinal @0x82==T."""
    for r in recs:
        if (r.tag == b"OCuA" and len(r.raw) >= OCUA_UUID + 16
                and r.raw[OCUA_UUID:OCUA_UUID + 16] == b"\x00" * 16
                and r.raw[OCUA_SEQ] == T):
            return r
    return None


def _set_ocua_stereo(raw, stereo):
    """Set an audio `OCuA` channel strip to stereo (True) or mono (False) — the three
    format bytes (§10.6.7). Idempotent; returns new bytes. Safe on any 205-B audio strip."""
    if len(raw) <= OCUA_FMT_NCH:
        return raw
    b = bytearray(raw)
    if stereo:
        b[OCUA_FMT_CFG] |= 0x04
        b[OCUA_FMT_FLAG] = 0x01
        b[OCUA_FMT_NCH] = 0x02
    else:
        b[OCUA_FMT_CFG] &= ~0x04
        b[OCUA_FMT_FLAG] = 0x00
        b[OCUA_FMT_NCH] = 0x01
    return bytes(b)


def _ivne_uuid(raw):
    """The ivnE channel's 16-B UUID. Located RELATIVE to the variable-length name
    field (UUID = name-field-end + 0x11f) so it still resolves after a rename — the
    fixed 0x1eb only holds for the default 'Audio N' name (§10.6.8)."""
    n = struct.unpack_from("<H", raw, IVNE_NAME_LEN)[0]
    off = IVNE_NAME + n + (n & 1) + 0x11f
    return raw[off:off + 16]


def _ocua_for_channel(pd, chan_idx):
    """The `OCuA` channel strip for environment channel `chan_idx`, via the UUID link:
    ivnE(idx@0x08==chan_idx).UUID == OCuA.UUID@0xbd (name-length-robust)."""
    iv = next((r for r in pd.records if r.tag == b"ivnE" and _u32(r.raw, IVNE_IDX) == chan_idx), None)
    if iv is None:
        return None
    uuid = _ivne_uuid(iv.raw)
    return next((r for r in pd.records if r.tag == b"OCuA" and len(r.raw) >= OCUA_UUID + 16
                 and r.raw[OCUA_UUID:OCUA_UUID + 16] == uuid), None)


def set_track_stereo(pd, track, stereo=True):
    """Set audio track `track` (1-based) to stereo/mono in `pd` (mutates in place).
    Track k uses environment channel `KART_BASE_CHAN + (k-1)*0x40000`; its strip is
    resolved through the ivnE→OCuA UUID link. Raises if the track has no strip."""
    chan = KART_BASE_CHAN + (int(track) - 1) * SYNTH_IDX_STRIDE
    oc = _ocua_for_channel(pd, chan)
    if oc is None:
        raise ValueError(f"no channel strip for audio track {track} (chan 0x{chan:06x})")
    oc.raw = _set_ocua_stereo(oc.raw, stereo)


def _normalize_stereo(stereo, ntracks):
    """Normalize a `stereo` spec to a set of 1-based track numbers. Accepts:
    False/None (none), True (all `ntracks`), or an iterable of 1-based track numbers."""
    if not stereo:
        return set()
    if stereo is True:
        return set(range(1, ntracks + 1))
    return {int(t) for t in stereo}


def _set_ivne_name(raw, name):
    """Replace an ivnE channel's display name — variable-length [u16 char-count @0xc2]
    [ASCII @0xc4][pad to even] — and fix the record payload size. RESIZES the record,
    so call AFTER any absolute-offset ivnE reads (the UUID @0x1eb shifts)."""
    raw = bytearray(raw)
    nb = name.encode("latin-1", "replace")
    field = struct.pack("<H", len(nb)) + nb + (b"\x00" if len(nb) % 2 else b"")
    old_n = struct.unpack_from("<H", raw, IVNE_NAME_LEN)[0]
    old_end = IVNE_NAME + old_n + (old_n & 1)
    raw[IVNE_NAME_LEN:old_end] = field
    struct.pack_into("<I", raw, REC_SIZE_OFF, len(raw) - REC_HEADER_SIZE)
    return bytes(raw)


def set_track_name(pd, track, name):
    """Set audio track `track` (1-based) display name in `pd` (mutates in place), via
    its ivnE channel (chan KART_BASE_CHAN + (k-1)*0x40000). Overrides the default
    'Audio N' and cures the single-byte-counter garble past track 9 (§10.6.8). Raises
    if the track has no ivnE channel."""
    chan = KART_BASE_CHAN + (int(track) - 1) * SYNTH_IDX_STRIDE
    iv = next((r for r in pd.records if r.tag == b"ivnE" and _u32(r.raw, IVNE_IDX) == chan), None)
    if iv is None:
        raise ValueError(f"no channel for audio track {track} (chan 0x{chan:06x})")
    iv.raw = _set_ivne_name(iv.raw, name)


def _normalize_names(names, ntracks):
    """Normalize a `names` spec to a {1-based track: name} dict. Accepts None (no
    names → keep 'Audio N'), a dict {track: name}, or a list/tuple (tracks 1..len)."""
    if not names:
        return {}
    if isinstance(names, dict):
        return {int(k): str(v) for k, v in names.items() if v}
    return {i + 1: str(v) for i, v in enumerate(names) if v}


def _synth_walk_rows(buf, row0, stride, tag_off, idx_off, tag_val=0x14):
    off = row0
    while off + max(tag_off, idx_off) + 4 <= len(buf):
        if _u32(buf, off + tag_off) != tag_val:
            break
        yield off, _u32(buf, off + idx_off)
        off += stride


def _uuid_str(id16):
    return "%08X-%04X-%04X-%04X-%012X" % (
        int.from_bytes(id16[0:4], "big"), int.from_bytes(id16[4:6], "big"),
        int.from_bytes(id16[6:8], "big"), int.from_bytes(id16[8:10], "big"),
        int.from_bytes(id16[10:16], "big"))


def _kart_blk(ord_):
    return bytes([0xff, 0xff, ord_ & 0xff, 0x00, 0x00, 0x00, 0x02, 0x00])


def activate_audio_track(pd, *, ids=None, reindex=False, drummer=True, stereo=False, verbose=False):
    """Activate the next free pre-allocated audio slot, mutating `pd` in place.
    Returns the new ivnE idx. Raises RuntimeError if the template is exhausted.

    All the load-bearing visibility gates are applied: gnoS counters+registry,
    the ivnE clone, the OCuA channel-strip UUID link, the karT arrange-track row,
    the karT 0x080000 active-ranks (re-sorted by rank), the qSvE arrange order,
    the qeSM arrange track-area height, and the MneG Session-Player binding.
    `reindex` adds the cosmetic qeSM @0x116 recency churn (off by default)."""
    ids = ids or IdGen()
    recs = pd.records

    grec = next((r for r in recs if r.tag == b"gnoS"), None)
    if grec is None:
        raise RuntimeError("no gnoS record")
    g = bytearray(grec.raw)
    T = _u32(g, GNOS_TRACKCOUNT) >> 16
    cur_max = _u32(g, GNOS_MAXIVNE)
    new_idx = cur_max + SYNTH_IDX_STRIDE
    slot = new_idx >> 16

    t1_rows = {idx: off for off, idx in _synth_walk_rows(g, GNOS_T1_ROW0, GNOS_T1_STRIDE, 0, 4)}
    if slot not in t1_rows:
        raise RuntimeError(f"template exhausted at {T} tracks (no free slot 0x{slot:x})")
    const_a = bytes(g[GNOS_T1_HDR + 4:GNOS_T1_HDR + 8])
    const_b = b"\x22\x5c\xf1\x01"
    for off, idx in _synth_walk_rows(g, GNOS_T2_ROW0, GNOS_T2_STRIDE, 8, 12):
        if g[off:off + 8] != b"\x00" * 8:
            const_b = bytes(g[off + 4:off + 8])

    # gnoS counters
    struct.pack_into("<I", g, GNOS_MAXIVNE, new_idx)
    struct.pack_into("<I", g, GNOS_TRACKCOUNT, (T + 1) << 16)
    struct.pack_into("<I", g, GNOS_COUNT_HI, ((T + 1) << 16) | 1)
    # gnoS Table1 + Table2 registry (shared id)
    reg_tl, reg_node = ids.time_low(), ids.node()
    t1_off = t1_rows[slot]
    g[t1_off + 8:t1_off + 24] = reg_tl + const_a + reg_node
    t2_rows = {idx: off for off, idx in _synth_walk_rows(g, GNOS_T2_ROW0, GNOS_T2_STRIDE, 8, 12)}
    if slot + 4 in t2_rows:
        o = t2_rows[slot + 4]
        g[o:o + 8] = reg_tl[::-1] + const_b
    # gnoS Table3 running stamps
    for idx in (0x08, 0x0c):
        for off, ridx in _synth_walk_rows(g, GNOS_T3_ROW0, GNOS_T3_STRIDE, 8, 12, tag_val=0x17):
            if ridx == idx:
                g[off:off + 8] = ids.time_low()[::-1] + const_b
                break
    grec.raw = bytes(g)

    chan_uuid = ids.uuid16(const_a)      # shared: new ivnE @0x1eb AND its OCuA @0xbd
    kart_id = ids.uuid16(const_a)        # karT @0x3c AND (as UUID str) the MneG key

    # ivnE clone (source = current max)
    si, srec = _synth_find(recs, b"ivnE", cur_max)
    if srec is None:
        raise RuntimeError(f"no source ivnE at idx 0x{cur_max:06x}")
    src = bytearray(srec.raw)
    new = bytearray(src)
    struct.pack_into("<I", new, IVNE_IDX, new_idx)
    struct.pack_into("<I", new, IVNE_IDX2, slot)
    new[IVNE_LINK76] = (src[IVNE_LINK76] + 0x42) & 0xff
    new[IVNE_ORD_CA] = (src[IVNE_ORD_CA] + 1) & 0xff      # NOTE single-byte name
    new[IVNE_ORD_CC] = (src[IVNE_ORD_CC] + 1) & 0xff      # counter -> "Audio :" past 9
    new[IVNE_ORD_CF] = (src[IVNE_ORD_CF] + 1) & 0xff
    new[IVNE_UUID:IVNE_UUID + 16] = chan_uuid
    new[IVNE_ISLAST] = 0x01
    src[IVNE_ISLAST] = 0x00
    src[IVNE_SRC51] = (src[IVNE_SRC51] + 0x02) & 0xff
    srec.raw = bytes(src)
    recs.insert(si + 1, Record(b"ivnE", bytes(new)))

    _synth_add_kart(recs, T, new_idx, kart_id)            # arrange-track row
    orec = _synth_next_strip(recs, T)                     # OCuA strip LINK
    if orec is not None:
        o = bytearray(orec.raw)
        o[OCUA_F3C] = 0x01
        o[OCUA_F3D] = 0x01
        o[OCUA_SEQ] = 0x00
        o[OCUA_UUID:OCUA_UUID + 16] = chan_uuid
        orec.raw = _set_ocua_stereo(bytes(o), stereo)     # mono by default; stereo on request
    if drummer:
        _synth_grow_mneg(recs, kart_id)                  # Session-Player binding
    _synth_arrange_order(recs, T + 1)                    # qSvE 0x080000 rows
    _synth_track_ranks(recs, T + 1)                      # karT 0x080000 ranks + reorder
    _synth_arrange_height(recs, T + 1)                   # qeSM 0x040000 track-area height
    if reindex:
        for r in recs:                                   # cosmetic qeSM @0x116 recency
            raw = r.raw
            if (r.tag == b"qeSM" and len(raw) >= QESM_ORD + 4 and raw[QESM_ORD] == 0
                    and raw[QESM_ORD + 1] == 0 and raw[QESM_ORD + 3] == 0xff
                    and raw[QESM_ORD + 2] >= 0xc0):
                b = bytearray(raw)
                b[QESM_ORD + 2] = 0xc0 if b[QESM_ORD + 2] == 0xff else (b[QESM_ORD + 2] + 1) & 0xff
                r.raw = bytes(b)
    if verbose:
        print(f"  activated slot 0x{slot:02x} -> ivnE 0x{new_idx:06x}, tracks {T}->{T+1}")
    return new_idx


def _synth_add_kart(recs, T, new_idx, kart_id):
    rows = [(i, r) for i, r in enumerate(recs)
            if r.tag == b"karT" and len(r.raw) == 93 and _u32(r.raw, IVNE_IDX) == 0x040000]
    if not rows:
        return
    base = next((r.raw for _, r in rows if _u32(r.raw, KART_CHAN) == KART_BASE_CHAN), rows[0][1].raw)
    master = next(((i, r) for i, r in rows if _u32(r.raw, KART_CHAN) == KART_MASTER_CHAN), None)
    if master is None:
        master = max(rows, key=lambda ir: ir[1].raw[KART_ORD])
    for _, r in rows:
        if _u32(r.raw, KART_CHAN) != KART_MASTER_CHAN and r.raw[KART_LAST] == 0x20:
            b = bytearray(r.raw); b[KART_LAST] = 0x00; r.raw = bytes(b)
    nk = bytearray(base)
    struct.pack_into("<I", nk, KART_CHAN, new_idx)
    nk[KART_BLK:KART_BLK + 8] = _kart_blk(T)
    nk[KART_ID16:KART_ID16 + 16] = kart_id
    nk[KART_LAST] = 0x20
    mi, mr = master
    m = bytearray(mr.raw); m[KART_BLK:KART_BLK + 8] = _kart_blk(T + 1); mr.raw = bytes(m)
    recs.insert(mi, Record(b"karT", bytes(nk)))


def _synth_arrange_order(recs, n):
    r = next((rr for rr in recs if rr.tag == b"qSvE" and _u32(rr.raw, IVNE_IDX) == ARR_ORDER_IDX), None)
    if r is None:
        return
    b = bytearray(r.raw)
    k = 0
    while ARR_ORDER_ROW0 + k * 0x50 < len(b):
        o = ARR_ORDER_ROW0 + k * 0x50
        b[o] = 0x43 if k == 0 else ((0x40 - n + k) & 0xff if k <= n else (k - n) & 0xff)
        k += 1
    r.raw = bytes(b)


def _arr_height_off(raw):
    """Offset of the arrange track-area HEIGHT u16 within a qeSM@0x040000 (name-relative)."""
    nlen = struct.unpack_from("<H", raw, 0x34)[0]
    return 0x34 + 2 + nlen + (nlen & 1) + ARR_MT_OFF


def _arrange_container(recs):
    """The arrange track-area qeSM@0x040000 whose HEIGHT field caps how many tracks Logic
    draws — NOT simply the largest qeSM@0x040000. A settled template carries a *larger*
    'Untitled' qeSM@0x040000 DECOY whose height field is always 0; the real arrange
    container is the one whose height is a nonzero multiple of the per-track row height
    (0x3c*(rows+1)). (max(len) coincidentally hit the right record on the audio template
    where the arrange container outgrows the decoy, but hits the DECOY on the mixed
    template — clobbering the decoy's must-be-zero field CORRUPTS the file.)"""
    cands = [r for r in recs if r.tag == b"qeSM" and _u32(r.raw, IVNE_IDX) == ARR_QESM_IDX]

    def h(r):
        o = _arr_height_off(r.raw)
        return struct.unpack_from("<H", r.raw, o)[0] if o + 2 <= len(r.raw) else 0

    arrange = [r for r in cands if h(r) and h(r) % ARR_ROW_H == 0]
    if arrange:
        return max(arrange, key=lambda r: len(r.raw))
    return max(cands, key=lambda r: len(r.raw)) if cands else None


def _synth_arrange_height(recs, n):
    rec = _arrange_container(recs)
    if rec is None:
        return
    off = _arr_height_off(rec.raw)
    if off + 2 <= len(rec.raw):
        b = bytearray(rec.raw)
        struct.pack_into("<H", b, off, (ARR_ROW_H * (n + 1)) & 0xffff)
        rec.raw = bytes(b)


def _synth_track_ranks(recs, n):
    positions = []
    for i, r in enumerate(recs):
        if r.tag == b"karT" and _u32(r.raw, IVNE_IDX) == TRK_IDX and len(r.raw) > TRK_SLOT + 4:
            idx = (_u32(r.raw, TRK_SLOT) - TRK_SLOT0) // 4
            if idx < TRK_FIXED:
                rank = 0x40 + idx
            elif idx < TRK_FIXED + n:
                rank = 0x40 - n + (idx - TRK_FIXED)
            else:
                rank = idx - (TRK_FIXED + n)
            b = bytearray(r.raw); b[TRK_RANK] = rank & 0xff; r.raw = bytes(b)
            positions.append(i)
    ordered = sorted((recs[i] for i in positions), key=lambda r: r.raw[TRK_RANK])
    for pos, rec in zip(positions, ordered):
        recs[pos] = rec


def _synth_grow_mneg(recs, kart_id):
    mrec = next((r for r in recs if r.tag == b"MneG" and _u32(r.raw, IVNE_IDX) == 0), None)
    if mrec is None:
        return
    raw = mrec.raw
    pos = raw.find(MNEG_DICT_MARK)
    if pos < 0:
        return
    ins_at = pos + len(MNEG_DICT_MARK)
    entry = ('"' + _uuid_str(kart_id) + '":' + MNEG_ENTRY_BODY + ',').encode("latin-1")
    m = bytearray(raw[:ins_at]) + entry + bytearray(raw[ins_at:])
    for off in (MNEG_CNT_24, MNEG_CNT_40):
        struct.pack_into("<I", m, off, _u32(m, off) + len(entry))
    struct.pack_into("<I", m, REC_SIZE_OFF, len(m) - REC_HEADER_SIZE)
    mrec.raw = bytes(m)


# --- Software-instrument (MIDI) track synthesis (§10.9) -----------------------------
# Instrument channels carry heavy serialized state (NSKeyedArchiver UCuA plists) that
# can't be conjured by flag-flipping (§10.6.7 lesson). But once a base has the
# instrument INFRASTRUCTURE (>=2 instrument tracks — the "steady state"), each further
# instrument is a clean, repeatable per-track op (RE'd 2026-06-01 from the mixed_template
# +1/+2/+3/+4 differentials, Logic-validated). Logic REGENERATES the gnoS registry on
# load (the gnoS-swap finding), so we touch only the gnoS counters.
INST_OCUA_CFG = b"\x29\xf5"        # OCuA config word @0x70 marking an instrument strip (vs audio 0xabf7)
INST_BUS_CHANS = (0x4c0000, 0x500000, 0x540000)   # master + outputs: link76 churn on each add
INST_SYSTEM_RANKS = 3              # top-N track-list ranks are pinned (master+outputs), don't shift


def _ocua_for_ivne(pd, ivne_rec):
    """The OCuA strip linked to an ivnE (by UUID), or None."""
    u = _ivne_uuid(ivne_rec.raw)
    return next((r for r in pd.records if r.tag == b"OCuA" and len(r.raw) >= OCUA_UUID + 16
                 and r.raw[OCUA_UUID:OCUA_UUID + 16] == u), None)


def _is_instrument_ivne(pd, ivne_rec):
    oc = _ocua_for_ivne(pd, ivne_rec)
    return oc is not None and oc.raw[0x70:0x72] == INST_OCUA_CFG


def _relrank_instrument(recs, new_slot):
    """Track-list re-rank for an instrument add: the new slot takes the top TRACK rank;
    all other tracks/free slots shift down 1; the top INST_SYSTEM_RANKS rows (master +
    outputs) stay pinned. Then re-sort by rank (Logic reads stream order)."""
    rows = [r for r in recs if r.tag == b"karT" and _u32(r.raw, 0x08) == TRK_IDX and len(r.raw) == 93]
    if len(rows) <= INST_SYSTEM_RANKS:
        return
    by = sorted(rows, key=lambda r: r.raw[TRK_RANK], reverse=True)
    sysids = {id(r) for r in by[:INST_SYSTEM_RANKS]}
    new_rank = by[INST_SYSTEM_RANKS].raw[TRK_RANK]            # highest non-system (track) rank
    pos = [i for i, r in enumerate(recs)
           if r.tag == b"karT" and _u32(r.raw, 0x08) == TRK_IDX and len(r.raw) == 93]
    for i in pos:
        r = recs[i]; b = bytearray(r.raw)
        if _u32(r.raw, TRK_SLOT) == new_slot:
            b[TRK_RANK] = new_rank
        elif id(r) not in sysids:
            b[TRK_RANK] = (b[TRK_RANK] - 1) & 0xff
        r.raw = bytes(b)
    ordered = sorted((recs[i] for i in pos), key=lambda r: r.raw[TRK_RANK])
    for p, rec in zip(pos, ordered):
        recs[p] = rec


def activate_instrument_track(pd, *, ids=None, drummer=True, verbose=False):
    """Add one software-instrument (MIDI) track, mutating `pd` in place; returns the new
    ivnE idx. §10.9. The base must be in the instrument STEADY STATE (>=2 instrument
    tracks, e.g. a 'mixed' template + a couple of instruments) and `cur_max` must be an
    instrument channel — instruments are added in a block. Logic regenerates the gnoS
    registry, so only counters are written."""
    ids = ids or IdGen()
    recs = pd.records
    grec = next((r for r in recs if r.tag == b"gnoS"), None)
    if grec is None:
        raise RuntimeError("no gnoS record")
    g = bytearray(grec.raw)
    T = _u32(g, GNOS_TRACKCOUNT) >> 16
    cur_max = _u32(g, GNOS_MAXIVNE)
    new_idx = cur_max + SYNTH_IDX_STRIDE
    slot = new_idx >> 16
    struct.pack_into("<I", g, GNOS_MAXIVNE, new_idx)
    struct.pack_into("<I", g, GNOS_TRACKCOUNT, (T + 1) << 16)
    struct.pack_into("<I", g, GNOS_COUNT_HI, ((T + 1) << 16) | 1)
    grec.raw = bytes(g)
    chan_uuid = ids.uuid16(b"\x00\x80\x00\x00")
    kart_id = ids.uuid16(b"\x00\x80\x00\x00")
    # clone the cur_max (instrument) ivnE — re-stamp idx/link76/UUID/islast ONLY (the
    # name-relative ordinals @0xca+ must NOT be bumped: that overshoot hollows the strip)
    cmrec = _synth_find(recs, b"ivnE", cur_max)[1]
    if cmrec is None or not _is_instrument_ivne(pd, cmrec):
        raise RuntimeError("cur_max is not an instrument channel (add instruments in a block)")
    cm = bytearray(cmrec.raw)
    new = bytearray(cmrec.raw)
    struct.pack_into("<I", new, IVNE_IDX, new_idx)
    struct.pack_into("<I", new, IVNE_IDX2, slot)
    new[IVNE_LINK76] = (cm[IVNE_LINK76] + 0x42) & 0xff
    nn = struct.unpack_from("<H", new, IVNE_NAME_LEN)[0]
    uo = IVNE_NAME + nn + (nn & 1) + 0x11f
    new[uo:uo + 16] = chan_uuid
    new[IVNE_ISLAST] = 0x01
    cm[IVNE_ISLAST] = 0x00
    cm[IVNE_SRC51] = (cm[IVNE_SRC51] + 0x02) & 0xff
    cmrec.raw = bytes(cm)
    recs.insert(recs.index(cmrec) + 1, Record(b"ivnE", bytes(new)))
    for bc in INST_BUS_CHANS:                                # master/output link76 churn
        r = _synth_find(recs, b"ivnE", bc)[1]
        if r is not None:
            b = bytearray(r.raw); b[IVNE_LINK76] = (b[IVNE_LINK76] + 0x42) & 0xff; r.raw = bytes(b)
    orec = next((r for r in recs if r.tag == b"OCuA" and len(r.raw) >= OCUA_UUID + 16
                 and r.raw[OCUA_UUID:OCUA_UUID + 16] == b"\x00" * 16
                 and r.raw[0x70:0x72] == INST_OCUA_CFG), None)
    if orec is None:
        raise RuntimeError("no free instrument strip (template exhausted)")
    o = bytearray(orec.raw)
    o[OCUA_F3C] = 0x01
    o[OCUA_F3D] = 0x01
    o[OCUA_SEQ] = 0x00
    o[OCUA_UUID:OCUA_UUID + 16] = chan_uuid
    orec.raw = bytes(o)
    _synth_add_kart(recs, T, new_idx, kart_id)               # arrange-track row (before master)
    _relrank_instrument(recs, slot)                          # track-list re-rank
    _synth_arrange_height(recs, _arrange_track_count(pd))    # qeSM 0x040000 visible-track height
    if drummer:
        _synth_grow_mneg(recs, kart_id)                      # Session-Player binding
    if verbose:
        print(f"  activated instrument slot 0x{slot:02x} -> ivnE 0x{new_idx:06x}, tracks {T}->{T+1}")
    return new_idx


# --- The HEAVY first-instrument op + the arbitrary-M chain (§10.9) ------------------
# The 1st instrument synthesized onto a MINIMAL base (one with <2 instruments, no
# instrument infrastructure) is a one-time "heavy" op: it materializes the shared
# instrument apparatus (NSKeyedArchiver UCuA plists + the 0x4000000 trio + a grown
# 221->241 strip). Those records are CONSTANT (the op always transitions the same
# template 1->2), so we clone them from REFERENCE differentials (base + 1 / + 2
# instruments). After the heavy op every further add is the light op (above), and the
# shared UCuA plists are finally set to the version matching the total instrument count.
_INST_UCUA_BASE_LEN = 288          # the template's own (single) UCuA record length


def _instrument_track_count(pd):
    return sum(1 for r in pd.records if r.tag == b"ivnE" and _is_instrument_ivne(pd, r))


def instrument_infrastructure(ref1, ref2, base):
    """Extract the heavy-op infrastructure from the reference differentials:
    `ref1` = `base` + 1 instrument, `ref2` = `base` + 2 instruments (all ProjectData).
    Returns the dict consumed by `synthesize_instrument_tracks`."""
    base_idxs = {_u32(r.raw, 0x08) for r in base.records if r.tag == b"ivnE"}
    new_ivne = next(bytes(r.raw) for r in ref1.records
                    if r.tag == b"ivnE" and _u32(r.raw, 0x08) not in base_idxs)
    base_raw = {(r.tag, bytes(r.raw)) for r in base.records}
    ucua_v1 = [bytes(r.raw) for r in ref1.records if r.tag == b"UCuA" and (r.tag, bytes(r.raw)) not in base_raw]
    ucua_v2 = [bytes(r.raw) for r in ref2.records if r.tag == b"UCuA" and len(r.raw) > _INST_UCUA_BASE_LEN]
    trio = [(r.tag, bytes(r.raw)) for r in ref1.records
            if _u32(r.raw, 0x08) == 0x4000000 and r.tag in (b"qeSM", b"karT", b"qSvE")]
    strip241 = next(bytes(r.raw) for r in ref1.records if r.tag == b"OCuA" and len(r.raw) == 241)
    # NOTE: the arrange container qeSM@0x040000 is NOT cloned — it does not grow structurally
    # per track (the activate ops grow only its u16 height field in place; see §10.9).
    return {"new_ivne": new_ivne, "ucua_v1": ucua_v1, "ucua_v2": ucua_v2, "trio": trio,
            "strip241": strip241}


def _set_instrument_ucua(pd, ucua):
    """Replace the shared instrument UCuA plists with the given version (the >288-B ones)."""
    big = [r for r in pd.records if r.tag == b"UCuA" and len(r.raw) > _INST_UCUA_BASE_LEN]
    for r, d in zip(big, ucua):
        r.raw = d


def _heavy_activate_instrument(pd, ids, infra):
    """Add the FIRST instrument to a minimal base — establishes the infrastructure.
    Clones the (constant) reference new-instrument ivnE + UCuA(v1) + 0x4000000 trio +
    the grown 241-B strip, then the same arrange/track-list edits as the light op."""
    recs = pd.records
    grec = next(r for r in recs if r.tag == b"gnoS"); g = bytearray(grec.raw)
    T = _u32(g, GNOS_TRACKCOUNT) >> 16
    cur_max = _u32(g, GNOS_MAXIVNE)
    new_idx = cur_max + SYNTH_IDX_STRIDE
    slot = new_idx >> 16
    struct.pack_into("<I", g, GNOS_MAXIVNE, new_idx)
    struct.pack_into("<I", g, GNOS_TRACKCOUNT, (T + 1) << 16)
    struct.pack_into("<I", g, GNOS_COUNT_HI, ((T + 1) << 16) | 1)
    grec.raw = bytes(g)
    chan_uuid = ids.uuid16(b"\x00\x80\x00\x00")
    kart_id = ids.uuid16(b"\x00\x80\x00\x00")
    new = bytearray(infra["new_ivne"])                       # clone the reference new-instrument ivnE
    nn = struct.unpack_from("<H", new, IVNE_NAME_LEN)[0]
    uo = IVNE_NAME + nn + (nn & 1) + 0x11f
    new[uo:uo + 16] = chan_uuid
    cmrec = _synth_find(recs, b"ivnE", cur_max)[1]
    cm = bytearray(cmrec.raw); cm[IVNE_ISLAST] = 0; cm[IVNE_SRC51] = (cm[IVNE_SRC51] + 2) & 0xff
    cmrec.raw = bytes(cm)
    recs.insert(recs.index(cmrec) + 1, Record(b"ivnE", bytes(new)))
    for bc in INST_BUS_CHANS:
        r = _synth_find(recs, b"ivnE", bc)[1]
        if r is not None:
            b = bytearray(r.raw); b[IVNE_LINK76] = (b[IVNE_LINK76] + 0x42) & 0xff; r.raw = bytes(b)
    for i, r in enumerate(recs):                             # grow the special 221->241 strip
        if r.tag == b"OCuA" and len(r.raw) == 221:
            recs[i] = Record(b"OCuA", infra["strip241"]); break
    orec = next((r for r in recs if r.tag == b"OCuA" and len(r.raw) >= OCUA_UUID + 16
                 and r.raw[OCUA_UUID:OCUA_UUID + 16] == b"\x00" * 16
                 and r.raw[0x70:0x72] == INST_OCUA_CFG), None)
    if orec is None:
        raise RuntimeError("no free instrument strip (template exhausted)")
    o = bytearray(orec.raw)
    o[OCUA_F3C] = 1; o[OCUA_F3D] = 1; o[OCUA_SEQ] = 0; o[OCUA_UUID:OCUA_UUID + 16] = chan_uuid
    orec.raw = bytes(o)
    ui = max(i for i, r in enumerate(recs) if r.tag == b"UCuA")    # UCuA grouped after existing
    for k, d in enumerate(infra["ucua_v1"]):
        recs.insert(ui + 1 + k, Record(b"UCuA", d))
    gi = max(i for i, r in enumerate(recs) if r.tag == b"MneG")    # 0x4000000 trio at the end
    recs[gi:gi] = [Record(t, d) for t, d in infra["trio"]]
    _synth_add_kart(recs, T, new_idx, kart_id)
    _relrank_instrument(recs, slot)
    _synth_arrange_height(recs, _arrange_track_count(pd))    # qeSM 0x040000 visible-track height
    _synth_grow_mneg(recs, kart_id)
    return new_idx


def _arrange_track_count(pd):
    return sum(1 for r in pd.records if r.tag == b"karT" and len(r.raw) == 93
               and _u32(r.raw, 0x08) == 0x040000 and _u32(r.raw, KART_CHAN) != KART_MASTER_CHAN)


def _name_instruments(pd, new_idxs, names=None):
    """Name the synthesized instrument channels `new_idxs`. Default: 'Inst K' where K is
    the channel's 1-based ordinal among ALL instrument channels (matching Logic, which
    numbers instruments 1..N in channel order). `names` overrides per synthesized
    instrument — a list (in `new_idxs` order) or a dict {1-based synth index: name}.
    Uses the same `_set_ivne_name` resize the audio naming path does (§10.6.8): it
    REPLACES the name field, preserving the name-relative ordinals + UUID, so the
    instrument strip stays linked (unlike BUMPING the ordinals, which hollows it)."""
    inst_idxs = sorted(_u32(r.raw, IVNE_IDX) for r in pd.records
                       if r.tag == b"ivnE" and _is_instrument_ivne(pd, r))
    spec = _normalize_names(names, len(new_idxs))
    for j, idx in enumerate(new_idxs, start=1):
        nm = spec.get(j) or f"Inst {inst_idxs.index(idx) + 1}"
        iv = next((r for r in pd.records if r.tag == b"ivnE" and _u32(r.raw, IVNE_IDX) == idx), None)
        if iv is not None:
            iv.raw = _set_ivne_name(iv.raw, nm)


def synthesize_instrument_tracks(pd, count, *, infra, ids=None, drummer=True, names=None):
    """Synthesize `count` software-instrument tracks onto `pd` (a minimal mixed base
    whose cur_max is the last channel; instruments are added in a block). Heavy op for
    the first (if the base lacks infrastructure), light op for the rest, then the shared
    UCuA plists are set for the resulting instrument count, and the new tracks are named
    ('Inst K' by default, or per `names` — a list/dict; §10.6.8). §10.9.
    Returns the list of new channel idxs.

    The arrange-container visible-track HEIGHT is grown per-add inside the activate ops
    (`_synth_arrange_height`, the same gate the audio path uses): the mixed template's
    arrange qeSM@0x040000 does NOT grow structurally per track — its only per-track-count
    field is the u16 height at name_end+0xa = 0x3c*(rows+1). The earlier `_set_arrange_container`
    that CLONED a +Ninst container corrupted the file (it imported that fixture's project
    name + arrange-view state); growing the template's own height in place is correct."""
    ids = ids or IdGen()
    have = _instrument_track_count(pd)
    out = []
    for i in range(count):
        if i == 0 and have < 2:
            out.append(_heavy_activate_instrument(pd, ids, infra))
        else:
            out.append(activate_instrument_track(pd, ids=ids, drummer=drummer))
    total = have + count
    if total >= 2:
        _set_instrument_ucua(pd, infra["ucua_v1"] if total == 2 else infra["ucua_v2"])
    _name_instruments(pd, out, names)                        # names LAST (resizes ivnE)
    return out


def synthesize_instrument_bundle(template_bundle=None, out_bundle=None, count=1, *,
                                 ref1_bundle=None, ref2_bundle=None, seed=None, drummer=True,
                                 names=None, verbose=True):
    """Synthesize `count` software-instrument (MIDI) tracks onto a minimal mixed base
    (§10.9), writing a fresh self-contained bundle. Refuses to overwrite.

    `template_bundle` / `ref1_bundle` / `ref2_bundle` may be None → use the EMBEDDED mixed
    base + baked instrument infrastructure (§13). Pass paths to override: `template_bundle`
    = a settled 1-instrument+1-audio session; `ref1/2_bundle` = that + 1 / 2 instruments.
    `names` names the new tracks ('Inst K' by default, or a list/dict; §10.6.8)."""
    out_bundle = Path(out_bundle)
    if out_bundle.exists():
        raise FileExistsError(f"refusing to overwrite {out_bundle}")

    def _pd(b):
        return ProjectData.parse((Path(b) / "Alternatives" / "000" / "ProjectData").read_bytes())

    pd, base_files = _resolve_base(template_bundle, "mixed_base")
    infra = (instrument_infrastructure(_pd(ref1_bundle), _pd(ref2_bundle), pd)
             if ref1_bundle and ref2_bundle else _baked_infra()["instrument_infra"])
    synthesize_instrument_tracks(pd, count, infra=infra, ids=IdGen(seed), drummer=drummer, names=names)
    data = pd.serialize()
    if ProjectData.parse(data).serialize() != data:
        raise RuntimeError("synthesized ProjectData failed round-trip")
    _assemble_bundle(base_files, out_bundle, data, added_tracks=count)
    if verbose:
        print(f"wrote {out_bundle} (+{count} instrument tracks)")
    return out_bundle


# --- AUDIO track synthesis onto a SETTLED mixed base (§10.9.1) -----------------------
# Adding an audio track to a settled mixed template (1 instrument + 1 audio, NOT a
# pre-allocated "N from 64" mixer) is a HEAVY op, structurally identical to the first
# instrument: it materializes the new channel's apparatus (NSKeyedArchiver UCuA plists +
# the 0x4000000 trio + the grown 221->241 strip), which we clone from a reference
# differential (base + 1 audio). RE'd & Logic-validated 2026-06-01 (TEST_mixed_1audio).
AUDIO_MIXER_CHAN_BASE = 0x480000   # first mixer-strip channel (buses/outputs/master start here)


def _mixer_audio_chans(pd):
    """Channels of the real AUDIO arrange-tracks (excludes the master and instruments)."""
    out = set()
    for r in pd.records:
        if r.tag == b"karT" and len(r.raw) == 93 and _u32(r.raw, 0x08) == 0x040000:
            ch = _u32(r.raw, KART_CHAN)
            if ch == KART_MASTER_CHAN:
                continue
            iv = _synth_find(pd.records, b"ivnE", ch)[1]
            if iv is not None and not _is_instrument_ivne(pd, iv):
                out.add(ch)
    return out


def _relrank_audio(recs, new_slot, audio_chans):
    """Track-list re-rank for an AUDIO add: the new slot takes the highest existing
    AUDIO-track rank; every row ranked <= that shifts down 1; higher rows (master,
    outputs, aux buses, INSTRUMENTS — which outrank audio) stay pinned. Re-sort by rank."""
    rows = [r for r in recs if r.tag == b"karT" and _u32(r.raw, 0x08) == TRK_IDX and len(r.raw) == 93]
    aud_slots = {ch >> 16 for ch in audio_chans}
    audranks = [r.raw[TRK_RANK] for r in rows if _u32(r.raw, TRK_SLOT) in aud_slots]
    if not audranks:
        return
    R = max(audranks)
    pos = [i for i, r in enumerate(recs)
           if r.tag == b"karT" and _u32(r.raw, 0x08) == TRK_IDX and len(r.raw) == 93]
    for i in pos:
        r = recs[i]; b = bytearray(r.raw); slot = _u32(r.raw, TRK_SLOT); rank = r.raw[TRK_RANK]
        if slot == new_slot:
            b[TRK_RANK] = R
        elif rank <= R:
            b[TRK_RANK] = (rank - 1) & 0xff
        r.raw = bytes(b)
    ordered = sorted((recs[i] for i in pos), key=lambda r: r.raw[TRK_RANK])
    for p, rec in zip(pos, ordered):
        recs[p] = rec


def audio_infrastructure(ref, base):
    """Extract the heavy-op infrastructure for adding the next AUDIO track to a settled
    mixed base. `ref` = `base` + 1 audio track (Logic differential); both ProjectData."""
    bidx = {_u32(r.raw, 0x08) for r in base.records if r.tag == b"ivnE"}
    new_ivne = next(bytes(r.raw) for r in ref.records if r.tag == b"ivnE" and _u32(r.raw, 0x08) not in bidx)
    braw = {(r.tag, bytes(r.raw)) for r in base.records}
    bucua = {bytes(r.raw) for r in base.records if r.tag == b"UCuA"}
    ucua = [bytes(r.raw) for r in ref.records if r.tag == b"UCuA"
            and _u32(r.raw, 0x08) == 0x240000 and bytes(r.raw) not in bucua]
    trio = [(r.tag, bytes(r.raw)) for r in ref.records if _u32(r.raw, 0x08) == 0x4000000
            and r.tag in (b"qeSM", b"karT", b"qSvE") and (r.tag, bytes(r.raw)) not in braw]
    strip241 = next(bytes(r.raw) for r in ref.records if r.tag == b"OCuA" and len(r.raw) == 241)
    return {"new_ivne": new_ivne, "ucua": ucua, "trio": trio, "strip241": strip241}


def _heavy_activate_audio(pd, ids, infra, *, stereo=True):
    """Add one audio track to a settled mixed base (the HEAVY op): clone the reference
    new-audio ivnE + 2 UCuA + the 0x4000000 trio + the grown 241 strip, stamp a free
    pre-allocated audio strip, link76 churn, arrange row + re-rank + MneG + height.
    Returns the new channel idx."""
    recs = pd.records
    grec = next(r for r in recs if r.tag == b"gnoS"); g = bytearray(grec.raw)
    T = _u32(g, GNOS_TRACKCOUNT) >> 16
    cur_max = _u32(g, GNOS_MAXIVNE)
    new_idx = cur_max + SYNTH_IDX_STRIDE
    slot = new_idx >> 16
    audio_chans = _mixer_audio_chans(pd)
    struct.pack_into("<I", g, GNOS_MAXIVNE, new_idx)
    struct.pack_into("<I", g, GNOS_TRACKCOUNT, (T + 1) << 16)
    struct.pack_into("<I", g, GNOS_COUNT_HI, ((T + 1) << 16) | 1)
    grec.raw = bytes(g)
    chan_uuid = ids.uuid16(b"\x00\x80\x00\x00")
    kart_id = ids.uuid16(b"\x00\x80\x00\x00")
    new = bytearray(infra["new_ivne"])                       # clone the reference new-audio ivnE
    struct.pack_into("<I", new, IVNE_IDX, new_idx)
    struct.pack_into("<I", new, IVNE_IDX2, slot)
    nn = struct.unpack_from("<H", new, IVNE_NAME_LEN)[0]
    uo = IVNE_NAME + nn + (nn & 1) + 0x11f
    new[uo:uo + 16] = chan_uuid
    cmrec = _synth_find(recs, b"ivnE", cur_max)[1]
    if cmrec is not None:
        cm = bytearray(cmrec.raw); cm[IVNE_ISLAST] = 0; cmrec.raw = bytes(cm)
    recs.insert(recs.index(cmrec) + 1, Record(b"ivnE", bytes(new)))
    # link76 churn: mixer-band channels [0x480000, new_idx) that aren't real audio tracks
    # (the master 0x500000 DOES shift; existing audio tracks do NOT) get @0x76 (u16) += 0x42
    for r in recs:
        if r.tag == b"ivnE":
            ch = _u32(r.raw, IVNE_IDX)
            if AUDIO_MIXER_CHAN_BASE <= ch < new_idx and ch not in audio_chans:
                b = bytearray(r.raw)
                struct.pack_into("<H", b, IVNE_LINK76, (struct.unpack_from("<H", b, IVNE_LINK76)[0] + 0x42) & 0xffff)
                r.raw = bytes(b)
    orec = _synth_next_strip(recs, T)                        # stamp a free pre-allocated audio strip
    if orec is not None:
        o = bytearray(orec.raw)
        o[OCUA_F3C] = 1; o[OCUA_F3D] = 1; o[OCUA_SEQ] = 0
        o[OCUA_UUID:OCUA_UUID + 16] = chan_uuid
        orec.raw = _set_ocua_stereo(bytes(o), stereo)
    for i, r in enumerate(recs):                             # grow the lone 221->241 strip
        if r.tag == b"OCuA" and len(r.raw) == 221:
            recs[i] = Record(b"OCuA", infra["strip241"]); break
    ui = max(i for i, r in enumerate(recs) if r.tag == b"UCuA")    # UCuA grouped after existing
    for k, d in enumerate(infra["ucua"]):
        recs.insert(ui + 1 + k, Record(b"UCuA", d))
    gi = max(i for i, r in enumerate(recs) if r.tag == b"MneG")    # 0x4000000 trio at the end
    recs[gi:gi] = [Record(t, d) for t, d in infra["trio"]]
    _synth_add_kart(recs, T, new_idx, kart_id)
    _relrank_audio(recs, slot, audio_chans)
    _synth_grow_mneg(recs, kart_id)
    _synth_arrange_height(recs, _arrange_track_count(pd))
    return new_idx


def _light_activate_audio(pd, ids, *, stereo=True):
    """Add a SUBSEQUENT audio track to a mixed base that already has the audio
    infrastructure (i.e. after a `_heavy_activate_audio`): clones cur_max's (audio) ivnE
    — NO new UCuA / trio / strip growth — stamps a free pre-allocated audio strip, does
    the link76 churn, arrange row, audio re-rank, MneG, height. Mirrors how the
    instrument light op relates to its heavy op. Returns the new channel idx."""
    recs = pd.records
    grec = next(r for r in recs if r.tag == b"gnoS"); g = bytearray(grec.raw)
    T = _u32(g, GNOS_TRACKCOUNT) >> 16
    cur_max = _u32(g, GNOS_MAXIVNE)
    new_idx = cur_max + SYNTH_IDX_STRIDE
    slot = new_idx >> 16
    audio_chans = _mixer_audio_chans(pd)
    struct.pack_into("<I", g, GNOS_MAXIVNE, new_idx)
    struct.pack_into("<I", g, GNOS_TRACKCOUNT, (T + 1) << 16)
    struct.pack_into("<I", g, GNOS_COUNT_HI, ((T + 1) << 16) | 1)
    grec.raw = bytes(g)
    chan_uuid = ids.uuid16(b"\x00\x80\x00\x00")
    kart_id = ids.uuid16(b"\x00\x80\x00\x00")
    cmrec = _synth_find(recs, b"ivnE", cur_max)[1]
    if cmrec is None or _is_instrument_ivne(pd, cmrec):
        raise RuntimeError("cur_max is not an audio channel (add audio tracks in a block)")
    cm = bytearray(cmrec.raw)
    new = bytearray(cmrec.raw)
    struct.pack_into("<I", new, IVNE_IDX, new_idx)
    struct.pack_into("<I", new, IVNE_IDX2, slot)
    new[IVNE_LINK76] = (cm[IVNE_LINK76] + 0x42) & 0xff
    nn = struct.unpack_from("<H", new, IVNE_NAME_LEN)[0]
    uo = IVNE_NAME + nn + (nn & 1) + 0x11f
    new[uo:uo + 16] = chan_uuid
    new[IVNE_ISLAST] = 0x01
    cm[IVNE_ISLAST] = 0x00
    cmrec.raw = bytes(cm)
    recs.insert(recs.index(cmrec) + 1, Record(b"ivnE", bytes(new)))
    for r in recs:                                           # link76 band churn (same as heavy)
        if r.tag == b"ivnE":
            ch = _u32(r.raw, IVNE_IDX)
            if AUDIO_MIXER_CHAN_BASE <= ch < new_idx and ch not in audio_chans:
                b = bytearray(r.raw)
                struct.pack_into("<H", b, IVNE_LINK76, (struct.unpack_from("<H", b, IVNE_LINK76)[0] + 0x42) & 0xffff)
                r.raw = bytes(b)
    orec = _synth_next_strip(recs, T)
    if orec is not None:
        o = bytearray(orec.raw)
        o[OCUA_F3C] = 1; o[OCUA_F3D] = 1; o[OCUA_SEQ] = 0
        o[OCUA_UUID:OCUA_UUID + 16] = chan_uuid
        orec.raw = _set_ocua_stereo(bytes(o), stereo)
    _synth_add_kart(recs, T, new_idx, kart_id)
    _relrank_audio(recs, slot, audio_chans)
    _synth_grow_mneg(recs, kart_id)
    _synth_arrange_height(recs, _arrange_track_count(pd))
    return new_idx


def _name_audio_chans(pd, new_idxs, names=None):
    """Name synthesized audio channels — default 'Audio K' (K = 1-based ordinal among
    audio channels, matching Logic); `names` (list/dict) overrides. Uses `_set_ivne_name`
    (the resize that preserves the strip), so it also cures the >9 'Audio :' garble."""
    aud_idxs = sorted(_u32(r.raw, IVNE_IDX) for r in pd.records
                      if r.tag == b"ivnE" and not _is_instrument_ivne(pd, r)
                      and _u32(r.raw, IVNE_IDX) in {_u32(rr.raw, KART_CHAN) for rr in pd.records
                          if rr.tag == b"karT" and len(rr.raw) == 93 and _u32(rr.raw, 0x08) == 0x040000
                          and _u32(rr.raw, KART_CHAN) != KART_MASTER_CHAN})
    spec = _normalize_names(names, len(new_idxs))
    for j, idx in enumerate(new_idxs, start=1):
        nm = spec.get(j) or f"Audio {aud_idxs.index(idx) + 1}"
        iv = next((r for r in pd.records if r.tag == b"ivnE" and _u32(r.raw, IVNE_IDX) == idx), None)
        if iv is not None:
            iv.raw = _set_ivne_name(iv.raw, nm)


def synthesize_audio_on_mixed_bundle(template_bundle=None, out_bundle=None, *, ref_bundle=None,
                                     seed=None, stereo=True, verbose=True):
    """Synthesize ONE audio track onto a minimal mixed base (§10.9.1, the HEAVY op),
    writing a fresh self-contained bundle. Refuses to overwrite. `template_bundle` /
    `ref_bundle` may be None → use the EMBEDDED mixed base + baked audio infrastructure
    (§13); pass paths to override (`ref_bundle` = the template + 1 audio differential)."""
    out_bundle = Path(out_bundle)
    if out_bundle.exists():
        raise FileExistsError(f"refusing to overwrite {out_bundle}")

    def _pd(b):
        return ProjectData.parse((Path(b) / "Alternatives" / "000" / "ProjectData").read_bytes())

    pd, base_files = _resolve_base(template_bundle, "mixed_base")
    infra = audio_infrastructure(_pd(ref_bundle), pd) if ref_bundle else _baked_infra()["audio_infra"]
    _heavy_activate_audio(pd, IdGen(seed), infra, stereo=stereo)
    data = pd.serialize()
    if ProjectData.parse(data).serialize() != data:
        raise RuntimeError("synthesized ProjectData failed round-trip")
    _assemble_bundle(base_files, out_bundle, data, added_tracks=1)
    if verbose:
        print(f"wrote {out_bundle} (+1 audio track)")
    return out_bundle


def synthesize_av_tracks(pd, *, instruments=0, audio=0, inst_infra=None, audio_infra=None,
                         ids=None, drummer=True, stereo=True, inst_names=None, audio_names=None):
    """Synthesize `instruments` software-instrument tracks AND `audio` audio tracks onto a
    minimal mixed base `pd`, in one pass (§10.9). Both are HEAVY for the first of their
    kind (materializing that type's infrastructure) then LIGHT for the rest; the two heavy
    ops compose (the shared 221->241 strip is identical, each add gets its own 0x4000000
    trio — Logic-validated). Instruments are added first (block), then audio (block);
    each new channel takes the next mixer slot. Returns (instrument_idxs, audio_idxs).

    `inst_infra` = instrument_infrastructure(...) (required if instruments>0);
    `audio_infra` = audio_infrastructure(...) (required if audio>0). Names default to
    'Inst K' / 'Audio K' (or per `inst_names` / `audio_names`; §10.6.8)."""
    ids = ids or IdGen()
    inst_idxs = []
    if instruments:
        if inst_infra is None:
            raise ValueError("instruments>0 requires inst_infra")
        inst_idxs = synthesize_instrument_tracks(pd, instruments, infra=inst_infra, ids=ids,
                                                 drummer=drummer, names=inst_names)
    aud_idxs = []
    if audio:
        if audio_infra is None:
            raise ValueError("audio>0 requires audio_infra")
        have = len(_mixer_audio_chans(pd))
        for i in range(audio):
            if i == 0 and have < 2:
                aud_idxs.append(_heavy_activate_audio(pd, ids, audio_infra, stereo=stereo))
            else:
                aud_idxs.append(_light_activate_audio(pd, ids, stereo=stereo))
        _name_audio_chans(pd, aud_idxs, audio_names)
    return inst_idxs, aud_idxs


def synthesize_av_bundle(template_bundle, out_bundle, *, instruments=0, audio=0,
                         inst_ref1_bundle=None, inst_ref2_bundle=None, audio_ref_bundle=None,
                         seed=None, drummer=True, stereo=True, inst_names=None, audio_names=None,
                         verbose=True):
    """Copy a minimal mixed `.logicx` template and synthesize `instruments` MIDI tracks +
    `audio` audio tracks into it in ONE call (§10.9), writing a fresh bundle. Refuses to
    overwrite; keeps MetaData.plist NumberOfTracks in sync.

    Reference differentials (each = the template + the noted track(s), made once in Logic):
    `inst_ref1_bundle`/`inst_ref2_bundle` = +1 / +2 instruments (required if instruments>0);
    `audio_ref_bundle` = +1 audio (required if audio>0). Compose with the map writers /
    note-region / audio-region synthesis to add content to the synthesized tracks."""
    import shutil
    import plistlib
    template_bundle, out_bundle = Path(template_bundle), Path(out_bundle)
    if out_bundle.exists():
        raise FileExistsError(f"refusing to overwrite {out_bundle}")

    def _pd(b):
        return ProjectData.parse((Path(b) / "Alternatives" / "000" / "ProjectData").read_bytes())

    pd = _pd(template_bundle)
    inst_infra = instrument_infrastructure(_pd(inst_ref1_bundle), _pd(inst_ref2_bundle), pd) if instruments else None
    aud_infra = audio_infrastructure(_pd(audio_ref_bundle), pd) if audio else None
    synthesize_av_tracks(pd, instruments=instruments, audio=audio, inst_infra=inst_infra,
                         audio_infra=aud_infra, ids=IdGen(seed), drummer=drummer, stereo=stereo,
                         inst_names=inst_names, audio_names=audio_names)
    data = pd.serialize()
    if ProjectData.parse(data).serialize() != data:
        raise RuntimeError("synthesized ProjectData failed round-trip")
    shutil.copytree(template_bundle, out_bundle)
    (out_bundle / "Alternatives" / "000" / "ProjectData").write_bytes(data)
    mp = out_bundle / "Alternatives" / "000" / "MetaData.plist"
    if mp.exists():
        meta = plistlib.loads(mp.read_bytes())
        meta["NumberOfTracks"] = int(meta.get("NumberOfTracks", 1)) + instruments + audio
        mp.write_bytes(plistlib.dumps(meta, fmt=plistlib.FMT_BINARY))
    if verbose:
        print(f"wrote {out_bundle} (+{instruments} instrument, +{audio} audio tracks)")
    return out_bundle


def _audio_track_arrange_positions(pd):
    """{1-based AUDIO ordinal: arrange stream position} — the placement event's track
    field is the 1-based position of the track in the karT@0x040000 arrange-row STREAM
    order (RE'd from F23_av, §10.9.2), and on a synth av base the audio tracks are
    INTERLEAVED with instruments, so the audio ordinal != the arrange position."""
    pos = 0
    chan_pos = {}
    for r in pd.records:
        if r.tag == b"karT" and len(r.raw) == 93 and _u32(r.raw, 0x08) == 0x040000:
            ch = _u32(r.raw, KART_CHAN)
            if ch == KART_MASTER_CHAN:
                continue
            pos += 1
            chan_pos[ch] = pos
    aud = sorted(ch for ch in chan_pos if not _is_instrument_ivne(
        pd, next(r for r in pd.records if r.tag == b"ivnE" and _u32(r.raw, 0x08) == ch)))
    return {i + 1: chan_pos[ch] for i, ch in enumerate(aud)}


def synthesize_av_region_bundle(template_bundle, out_bundle, *, instruments=0, audio=0,
                                audio_regions=None, midi_regions=None, prototype_bundle=None,
                                midi_prototype_bundle=None,
                                inst_ref1_bundle=None, inst_ref2_bundle=None, audio_ref_bundle=None,
                                inst_names=None, audio_names=None, stereo=True, seed=None,
                                drummer=True, verbose=True):
    """THE UNIFIED av CONTENT CALL (§10.9.2/.3): synthesize `instruments` MIDI tracks +
    `audio` audio tracks onto a minimal mixed template AND place audio REGIONS on the
    audio tracks + MIDI note REGIONS on the instrument tracks — one call, one fresh
    bundle. Logic-validated 2026-06-01.

    audio_regions : [(audio_track, wav, tick)] — `audio_track` is the 1-based AUDIO
                    ordinal (1 = the template's Audio 1, ...), `wav` an on-disk PCM file,
                    `tick` a 960-PPQ position. Multiple regions may share a track.
    midi_regions  : [(inst_track, notes, tick, name)] — `inst_track` is the 1-based
                    INSTRUMENT ordinal, `notes` = [(tick,pitch,vel,len)] region-relative
                    @960 PPQ, `tick` the region start, `name` optional (§10.9.3).
    prototype_bundle      : any session with >=1 AUDIO region (F21/F18) — required for
                    audio_regions. midi_prototype_bundle : any session with >=1 MIDI
                    region (F23_av) — required for midi_regions.
    inst_ref1/2_bundle, audio_ref_bundle : the heavy-op reference differentials (the
                    template + 1/2 instruments, + 1 audio); required per track type used.

    Names default to 'Inst K' / 'Audio K' (or per inst_names / audio_names). Compose with
    the map writers (tempo/meter/markers) on the result for a full export.

    ALL donor params (template_bundle + the ref/prototype bundles) may be None → use the
    EMBEDDED mixed base + baked infrastructure/prototypes (§13); pass paths to override."""
    out_bundle = Path(out_bundle)
    if out_bundle.exists():
        raise FileExistsError(f"refusing to overwrite {out_bundle}")
    audio_regions = list(audio_regions or [])
    midi_regions = list(midi_regions or [])

    def _pd(b):
        return ProjectData.parse((Path(b) / "Alternatives" / "000" / "ProjectData").read_bytes())

    pd, base_files = _resolve_base(template_bundle, "mixed_base")
    if instruments:
        inst_infra = (instrument_infrastructure(_pd(inst_ref1_bundle), _pd(inst_ref2_bundle), pd)
                      if inst_ref1_bundle and inst_ref2_bundle else _baked_infra()["instrument_infra"])
    else:
        inst_infra = None
    aud_infra = (audio_infrastructure(_pd(audio_ref_bundle), pd) if audio_ref_bundle
                 else _baked_infra()["audio_infra"]) if audio else None
    synthesize_av_tracks(pd, instruments=instruments, audio=audio, inst_infra=inst_infra,
                         audio_infra=aud_infra, ids=IdGen(seed), drummer=drummer, stereo=stereo,
                         inst_names=inst_names, audio_names=audio_names)

    wav_assign, rates = [], set()
    if audio_regions:
        ordpos = _audio_track_arrange_positions(pd)
        items = []
        for trk, wav, tick in audio_regions:
            if int(trk) not in ordpos:
                raise ValueError(f"audio track {trk} out of range (have {len(ordpos)} audio tracks)")
            items.append((ordpos[int(trk)], wav, tick))
        regions, wav_assign, rates = _build_region_specs(None, items)
        if prototype_bundle is not None:
            pd = ProjectData.synthesize_audio_regions(pd, regions, prototype=_pd(prototype_bundle))
        else:
            arp = _baked_infra()["audio_region_proto"]
            pd = ProjectData.synthesize_audio_regions(pd, regions, proto_group=arp["group"], proto_event=arp["event"])
        if len(rates) == 1 and next(iter(rates)) in ProjectData.SR_GNOS:
            pd.set_project_sample_rate(next(iter(rates)))

    if midi_regions:
        mproto = _pd(midi_prototype_bundle) if midi_prototype_bundle else _baked_infra()["midi_region_proto"]
        synthesize_midi_regions(pd, midi_regions, prototype=mproto)

    data = pd.serialize()
    if ProjectData.parse(data).serialize() != data:
        raise RuntimeError("synthesized ProjectData failed round-trip")
    _assemble_bundle(base_files, out_bundle, data, wav_assign=wav_assign, rates=rates,
                     added_tracks=instruments + audio)
    summary = {"instruments": instruments, "audio": audio, "audio_regions": len(audio_regions),
               "midi_regions": len(midi_regions),
               "project_SR": (next(iter(rates)) if len(rates) == 1 else "mixed" if rates else None)}
    if verbose:
        print(f"wrote {out_bundle} (+{instruments} inst, +{audio} audio, "
              f"{len(audio_regions)} audio regions, {len(midi_regions)} MIDI regions)")
    return summary


# --- MIDI note regions on synthesized instrument tracks (§10.9.3) --------------------
# A MIDI region is a 5-record group (tSxT/lytS/qeSM/karT/qSvE-notes) cloned from a region
# prototype (F23_av) at a fresh index, with the qeSM's channel ref re-stamped to the
# target instrument channel and the note qSvE filled; it is placed by a 0x20 event in the
# SAME real-arrange EvSq as the audio (0x24) events. Logic regenerates the registry, so
# only the records + the placement event are needed. RE'd & Logic-validated 2026-06-01.
MIDI_REGION_CHAN_OFF = 0x106     # u32 channel ref inside a MIDI region's qeSM container
MIDI_REGION_INDEX_BASE = 0x1200000   # first synth MIDI-region cluster (free high range)


def _instrument_arrange_positions(pd):
    """{1-based instrument ordinal: (arrange stream position, channel)}. The 0x20 MIDI
    placement event references the track by arrange-row stream position (@0x14) and by
    channel slot (@0x10)."""
    pos = 0
    out = []
    for r in pd.records:
        if r.tag == b"karT" and len(r.raw) == 93 and _u32(r.raw, 0x08) == 0x040000:
            ch = _u32(r.raw, KART_CHAN)
            if ch == KART_MASTER_CHAN:
                continue
            pos += 1
            iv = next((x for x in pd.records if x.tag == b"ivnE" and _u32(x.raw, 0x08) == ch), None)
            if iv is not None and _is_instrument_ivne(pd, iv):
                out.append((pos, ch))
    return {i + 1: pc for i, pc in enumerate(out)}


def _midi_region_prototype(proto):
    """Extract a MIDI region clone prototype from `proto` (a session with >=1 MIDI region,
    e.g. F23_av): found VIA the first 0x20 placement event in the arrange EvSq (which
    references a MIDI region by cluster @0x20 — distinguishing it from audio's 0x24
    events), then the 5-record region group at that cluster + the region's channel ref.
    Returns (group, event, proto_chan)."""
    aq = ProjectData._arrange_audio_evsq(proto.records)
    if aq is None:
        raise ValueError("prototype has no arrange EvSq")
    body = proto.records[aq].raw[REC_HEADER_SIZE:REC_HEADER_SIZE + _u32(proto.records[aq].raw, REC_SIZE_OFF)]
    EV = ProjectData.PLACEMENT_EVENT_SIZE
    ev, o = None, 0
    while o + EV <= len(body):
        if _u32(body, o) == 0x20:
            ev = body[o:o + EV]
            break
        o += 4
    if ev is None:
        raise ValueError("prototype has no MIDI (0x20) placement event")
    ridx = _u32(ev, 0x20) << 16                             # region cluster the event references
    group = [(r.tag, bytes(r.raw)) for r in proto.records if _u32(r.raw, 0x08) == ridx
             and r.tag in (b"tSxT", b"lytS", b"qeSM", b"karT", b"qSvE")]
    qe = next((r for r in proto.records if r.tag == b"qeSM" and _u32(r.raw, 0x08) == ridx), None)
    if qe is None:
        raise ValueError("prototype MIDI region group not found")
    return group, ev, _u32(qe.raw, MIDI_REGION_CHAN_OFF)


def synthesize_midi_regions(pd, specs, *, prototype, region_index_base=MIDI_REGION_INDEX_BASE):
    """Synthesize MIDI note regions on instrument tracks (§10.9.3), mutating `pd` in
    place; returns the new region indices. `prototype` = a ProjectData with >=1 MIDI
    region (e.g. F23_av) — the clone source — OR the pre-extracted baked prototype dict
    {group, event, proto_chan} (§13, embedded).

    specs = [(inst_track, notes, tick, name)]:
      inst_track : 1-based INSTRUMENT ordinal (1 = first instrument track)
      notes      : [(tick, pitch, velocity, length)] region-RELATIVE @960 PPQ
      tick       : region START, 960-PPQ from bar 1 (default 0 = bar 1)
      name       : region display name (optional; else keeps the prototype's)
    Region cluster indices start at `region_index_base` (a free high range that doesn't
    collide with audio regions, which use low clusters)."""
    if isinstance(prototype, dict):
        group, proto_ev, proto_chan = prototype["group"], prototype["event"], prototype["proto_chan"]
    else:
        group, proto_ev, proto_chan = _midi_region_prototype(prototype)
    instpos = _instrument_arrange_positions(pd)
    clones, events, out = [], [], []
    for i, spec in enumerate(specs):
        inst_track, notes = spec[0], list(spec[1])
        tick = int(spec[2]) if len(spec) > 2 and spec[2] is not None else 0
        name = spec[3] if len(spec) > 3 else None
        if int(inst_track) not in instpos:
            raise ValueError(f"instrument track {inst_track} out of range (have {len(instpos)})")
        apos, chan = instpos[int(inst_track)]
        ridx = region_index_base + i * SYNTH_IDX_STRIDE
        for tag, raw in group:
            b = bytearray(raw)
            for o in range(len(b) - 3):                        # re-stamp the channel ref(s)
                if _u32(b, o) == proto_chan:
                    struct.pack_into("<I", b, o, chan)
            struct.pack_into("<I", b, 0x08, ridx)              # region cluster index
            if tag == b"qSvE":                                 # the note sequence -> fill
                payload = ProjectData.build_note_qsve_payload(notes)
                nb = bytearray(raw[:REC_HEADER_SIZE])
                struct.pack_into("<I", nb, REC_SIZE_OFF, len(payload))
                struct.pack_into("<I", nb, 0x08, ridx)
                b = bytearray(bytes(nb) + payload)
            elif tag == b"qeSM":                               # region container
                maxend = max((t + ln for (t, _p, _v, ln) in notes), default=0)
                struct.pack_into("<I", b, 0x78, max(3840, -(-maxend // 3840) * 3840))   # length
                struct.pack_into("<I", b, 0x11c, tick)                                   # start
                rb = _set_region_name(bytes(b), name) if name else bytes(b)
                b = bytearray(rb)
            clones.append(Record(tag, bytes(b)))
        ev = bytearray(proto_ev)
        struct.pack_into("<I", ev, ProjectData.PLACEMENT_POS_OFF, ProjectData.AUDIO_REGION_ORIGIN + tick)
        struct.pack_into("<I", ev, 0x10, chan >> 16)           # channel slot
        ev[ProjectData.PLACEMENT_TRACK_OFF] = apos             # arrange-row stream position
        struct.pack_into("<I", ev, 0x20, ridx >> 16)           # region cluster link
        struct.pack_into("<I", ev, 0x30, _u32(proto_ev, 0x30) + (tick // 3840) * 0x100)  # bar advance
        events.append(bytes(ev))
        out.append(ridx)
    ins = next((i for i, r in enumerate(pd.records) if r.tag == b"OgnS"), len(pd.records))
    pd.records[ins:ins] = clones
    aq = ProjectData._arrange_audio_evsq(pd.records)
    if aq is None:
        raise ValueError("no arrange EvSq to place MIDI regions into")
    raw = pd.records[aq].raw
    body = raw[REC_HEADER_SIZE:REC_HEADER_SIZE + _u32(raw, REC_SIZE_OFF)]
    newbody = b"".join(events) + bytes(body)                   # 0x20 events before the rest
    nh = bytearray(raw[:REC_HEADER_SIZE])
    struct.pack_into("<I", nh, REC_SIZE_OFF, len(newbody))
    pd.records[aq].raw = bytes(nh) + newbody
    return out


def _normalize_audio(src, dst, sample_rate=44100):
    """Decode/normalize any CoreAudio-readable file (wav/mp3/aif/m4a/…) to a `sample_rate`
    Hz / STEREO / 16-bit PCM WAV via macOS `afconvert` — the format Logic's region writer
    supports (§8.1). A WAV ALREADY in that exact format is copied verbatim (no re-encode).
    Returns `dst`. Raises if the decode fails (unreadable/unsupported source)."""
    import subprocess
    import shutil
    import wave
    src, dst = Path(src), Path(dst)
    if src.suffix.lower() == ".wav":
        try:
            with wave.open(str(src), "rb") as w:
                if w.getframerate() == sample_rate and w.getnchannels() == 2 and w.getsampwidth() == 2:
                    shutil.copyfile(src, dst)
                    return dst
        except Exception:
            pass
    if not shutil.which("afconvert"):
        raise RuntimeError("afconvert not found (macOS CoreAudio) — needed to decode/normalize "
                           f"{src.name}; pre-convert inputs to {sample_rate}Hz/stereo/16-bit WAV")
    r = subprocess.run(["afconvert", "-f", "WAVE", "-d", f"LEI16@{sample_rate}", "-c", "2",
                        str(src), str(dst)], capture_output=True, text=True)
    if r.returncode != 0 or not dst.exists():
        raise RuntimeError(f"audio normalize failed for {src.name}: {r.stderr.strip() or 'afconvert error'}")
    return dst


def _probe_sample_rate(path):
    """Source sample rate (Hz) of any audio file — `wave` for WAV, else macOS `afinfo`
    ('… , 48000 Hz, …'). Returns None if undeterminable."""
    import subprocess
    import shutil
    import wave
    import re
    path = Path(path)
    if path.suffix.lower() == ".wav":
        try:
            with wave.open(str(path), "rb") as w:
                return w.getframerate()
        except Exception:
            pass
    if shutil.which("afinfo"):
        out = subprocess.run(["afinfo", str(path)], capture_output=True, text=True).stdout
        m = re.search(r"(\d+)\s*Hz", out)
        if m:
            return int(m.group(1))
    return None


def export_beatmap(midi_path, audio_files, out_bundle, *, track_template=None, prototype=None,
                   head_sync=None, names=None, stereo=True, sample_rate=None, verbose=True):
    """★ THE BEATMAP EXPORT (one call): a beatmap MIDI + audio files (wav/mp3/aif/…) →
    a self-contained Logic `.logicx`, no externalities.

    Reads tempo / meter / markers AND the head-sync note from `midi_path`; normalizes each
    audio file to `sample_rate`Hz/stereo/16-bit WAV (`afconvert`); synthesizes one audio
    TRACK per file, each clip starting at the head-sync tick, named after the source file;
    applies the tempo/meter/markers; packs all media inside the bundle.

    audio_files : 1..~63 paths (wav/mp3/aif/m4a/…); the clip + track take the file's stem.
    head_sync   : None = the MIDI Start (0xFA) position in the MIDI (the head-sync marker;
                  falls back to the first note-on); or an explicit 960-PPQ tick (e.g. via
                  `TimeMap.bar_beat_to_tick`). A MIDI Stop (0xFC) marks the tail (reported).
    track_template : a pre-allocated audio-track-synth session (`1 from 64`-style; default
                  the bundled one); prototype : any session with ≥1 audio region (default F21).
    sample_rate : project rate; None (default) = match the source files NATIVELY (44100 or
                  48000 — both Logic-validated), else force 44100/48000. Off-rate sources
                  are resampled. Requires macOS `afconvert` for compressed / off-format inputs."""
    import tempfile
    import shutil
    import plistlib
    from . import midimap
    midi_path, out_bundle = Path(midi_path), Path(out_bundle)
    audio_files = [Path(a) for a in audio_files]
    if out_bundle.exists():
        raise FileExistsError(f"refusing to overwrite {out_bundle}")
    if not audio_files:
        raise ValueError("no audio files given")
    if sample_rate is None:                                  # native: match the source files' rate
        probed = _probe_sample_rate(audio_files[0])
        sample_rate = probed if probed in ProjectData.SR_GNOS else 44100
    # None -> the EMBEDDED audio seed + baked region prototype (§13); a path overrides
    track_template = Path(track_template) if track_template else None
    prototype = Path(prototype) if prototype else None

    mm = midimap.parse_file(midi_path)
    div = mm.division or 960
    if head_sync is None:                                    # head-sync = MIDI Start (0xFA), else 1st note-on
        sync = mm.head_sync_tick(960)
        sync = 0 if sync is None else sync
    else:
        sync = int(head_sync)
    _start, stop = mm.audio_span(960)

    tmp = Path(tempfile.mkdtemp())
    try:
        wavs, stems, seen = [], [], {}
        for a in audio_files:
            stem = a.stem
            if stem in seen:                                 # de-dup display names / filenames
                seen[stem] += 1
                stem = f"{stem}_{seen[a.stem]}"
            else:
                seen[stem] = 0
            dst = tmp / f"{stem}.wav"
            _normalize_audio(a, dst, sample_rate)
            wavs.append(dst)
            stems.append(stem)
        items = [(i + 1, wavs[i], sync) for i in range(len(wavs))]
        nm = list(names) if names is not None else stems
        synthesize_track_region_bundle(track_template, prototype, out_bundle, items,
                                        stereo=stereo, names=nm, verbose=False)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    alt = out_bundle / "Alternatives" / "000"
    pd = ProjectData.parse((alt / "ProjectData").read_bytes())
    summary = {"tracks": len(wavs), "head_sync_tick": sync, "names": stems}
    if stop is not None:
        summary["tail_tick"] = stop
    if mm.tempo_map:
        summary["tempo_events"] = pd.set_tempo_map(
            [(round(t * 960 / div), b) for t, _u, b in mm.tempo_map], ppq=960)
    if mm.meter_map:
        pd.set_meter_map([(round(t * 960 / div), n, d) for t, n, d, _c, _n in mm.meter_map], ppq=960)
        summary["meter_changes"] = len(mm.meter_map)
    if mm.markers:
        summary["markers"] = pd.set_markers([(round(t * 960 / div), txt) for t, txt in mm.markers], ppq=960)
    (alt / "ProjectData").write_bytes(pd.serialize())
    mdp = alt / "MetaData.plist"
    md = plistlib.loads(mdp.read_bytes())
    if mm.tempo_map:
        md["BeatsPerMinute"] = float(mm.tempo_map[0][2])
    mdp.write_bytes(plistlib.dumps(md, fmt=plistlib.FMT_BINARY))
    if verbose:
        print(f"wrote {out_bundle}: {len(wavs)} audio tracks @ head-sync tick {sync}")
        for k, v in summary.items():
            print(f"  {k:14}: {v}")
    return summary


def synthesize_audio_tracks(template_bundle, out_bundle, count, *,
                            seed=None, reindex=False, drummer=True, stereo=True, names=None, verbose=True):
    """Copy a `.logicx` template and synthesize `count` extra EMPTY audio tracks.

    The template is a session built with N audio tracks then all-but-one deleted
    (keeps an N-channel pre-allocated mixer; `count` <= free slots). Refuses to
    overwrite an existing output bundle. Keeps MetaData.plist NumberOfTracks in
    sync (a mismatch makes Logic reject the file). Validated in Logic at 4/9/13.

    `stereo` sets channel format per track (§10.6.7) — AUTHORITATIVE (every track is
    set explicitly): True = all stereo (DEFAULT), False = all mono, or an iterable of
    1-based track numbers to make stereo (rest mono). Numbering spans the template's
    pre-existing tracks + the `count` new ones.

    `names` sets display names per track (§10.6.8): None = keep 'Audio N' (default), a
    dict {track: name}, or a list (names for tracks 1..len). Naming cures the >9
    single-byte-counter garble ('Audio :').

    Compose with the map writers for content: parse the result, call
    set_tempo_map / set_meter_map / set_markers, re-serialize. (Audio/MIDI REGION
    content on synthesized tracks needs region synthesis — a follow-on.)"""
    import shutil
    import plistlib
    template_bundle, out_bundle = Path(template_bundle), Path(out_bundle)
    if out_bundle.exists():
        raise FileExistsError(f"refusing to overwrite {out_bundle}")
    pd = ProjectData.parse((template_bundle / "Alternatives" / "000" / "ProjectData").read_bytes())
    have = _audio_track_count(pd)
    ids = IdGen(seed)
    for _ in range(count):
        activate_audio_track(pd, ids=ids, reindex=reindex, drummer=drummer, verbose=verbose)
    stereo_set = _normalize_stereo(stereo, have + count)
    for t in range(1, have + count + 1):
        set_track_stereo(pd, t, t in stereo_set)
    for t, nm in _normalize_names(names, have + count).items():   # names LAST (resizes ivnE)
        set_track_name(pd, t, nm)
    data = pd.serialize()
    if ProjectData.parse(data).serialize() != data:
        raise RuntimeError("synthesized ProjectData failed round-trip")
    shutil.copytree(template_bundle, out_bundle)
    (out_bundle / "Alternatives" / "000" / "ProjectData").write_bytes(data)
    mp = out_bundle / "Alternatives" / "000" / "MetaData.plist"
    if mp.exists():
        meta = plistlib.loads(mp.read_bytes())
        meta["NumberOfTracks"] = int(meta.get("NumberOfTracks", 1)) + count
        mp.write_bytes(plistlib.dumps(meta, fmt=plistlib.FMT_BINARY))
    if verbose:
        print(f"wrote {out_bundle} (+{count} audio tracks)")
    return out_bundle


def main(argv=None):
    argv = argv or sys.argv[1:]
    if argv and argv[0] == "synthtracks":
        # synthtracks <template> <out> <count> [--seed N] [--reindex]
        #             [--mono | --stereo-tracks N,M,..] [--names A,B,C]  (stereo default)
        kw = dict(reindex="--reindex" in argv)
        if "--seed" in argv:
            kw["seed"] = int(argv[argv.index("--seed") + 1])
        if "--mono" in argv:
            kw["stereo"] = False
        elif "--stereo" in argv:
            kw["stereo"] = True
        elif "--stereo-tracks" in argv:
            kw["stereo"] = [int(x) for x in argv[argv.index("--stereo-tracks") + 1].split(",")]
        if "--names" in argv:
            kw["names"] = argv[argv.index("--names") + 1].split(",")
        synthesize_audio_tracks(Path(argv[1]), Path(argv[2]), int(argv[3]), **kw)
        return 0
    if argv and argv[0] == "midiregion":
        # midiregion <template> <out> [@<region_tick>] tick:pitch:vel:length ...
        rest = argv[3:]
        region_tick = None
        if rest and rest[0].startswith("@"):
            region_tick, rest = int(rest[0][1:]), rest[1:]
        notes = [tuple(int(x) for x in spec.split(":")) for spec in rest]
        with_midi_region(Path(argv[1]), Path(argv[2]), notes, region_tick=region_tick)
        return 0
    if argv and argv[0] == "midifile":
        # midifile <template> <midi> <out> [channel] [@<region_tick>]
        chan, rt = None, None
        for a in argv[4:]:
            if a.startswith("@"):
                rt = int(a[1:])
            else:
                chan = int(a)
        with_midi_file_region(Path(argv[1]), Path(argv[2]), Path(argv[3]),
                              channel=chan, region_tick=rt)
        return 0
    if argv and argv[0] == "multimidi":
        # multimidi <template> <out> <midi1> [<midi2> ...]  (one region per file)
        place_midi_files(Path(argv[1]), Path(argv[2]), [Path(p) for p in argv[3:]])
        return 0
    if argv and argv[0] == "exportmidi":
        # exportmidi <template> <master.mid> <out> <part1.mid> [<part2.mid> ...]
        export_midi_multi(Path(argv[1]), Path(argv[3]), [Path(p) for p in argv[4:]],
                          master_midi=Path(argv[2]))
        return 0
    if argv and argv[0] == "exportav":
        # exportav <template> <master.mid> <out> [--audio wav:tick ...] [--midi part.mid ...]
        audio, midi, mode = [], [], None
        for a in argv[4:]:
            if a in ("--audio", "--midi"):
                mode = a
            elif mode == "--audio":
                w, t = a.rsplit(":", 1); audio.append((Path(w), int(t)))
            elif mode == "--midi":
                midi.append(Path(a))
        export_av_multi(Path(argv[1]), Path(argv[3]), master_midi=Path(argv[2]),
                        audio_items=audio, midi_parts=midi)
        return 0
    if argv and argv[0] == "exportall":
        tick = int(argv[6]) if len(argv) > 6 else 0
        export_all(Path(argv[1]), Path(argv[2]), Path(argv[3]), Path(argv[4]), Path(argv[5]), tick)
        return 0
    if argv and argv[0] == "audio":
        tick = int(argv[5]) if len(argv) > 5 else 0
        add_audio_region(Path(argv[1]), Path(argv[2]), Path(argv[3]), Path(argv[4]), tick)
        return 0
    if argv and argv[0] == "multiaudio":
        # multiaudio <base> <template> <out> track:wav:tick [track:wav:tick ...]
        items = []
        for spec in argv[4:]:
            track, wav, tick = spec.split(":")
            items.append((int(track), Path(wav), int(tick)))
        add_audio_regions(Path(argv[1]), Path(argv[2]), items, Path(argv[3]))
        return 0
    if argv and argv[0] == "synthregions":
        # synthregions <donor.logicx> <out.logicx> track:wav:tick [track:wav:tick ...]
        items = []
        for spec in argv[3:]:
            track, wav, tick = spec.rsplit(":", 2) if spec.count(":") >= 2 else spec.split(":")
            items.append((int(track), Path(wav), int(tick)))
        synthesize_audio_region_bundle(Path(argv[1]), Path(argv[2]), items)
        return 0
    if argv and argv[0] == "synthtrackregions":
        # synthtrackregions <track_template> <prototype> <out> track:wav:tick [...]
        #                   [--seed N] [--mono | --stereo-tracks N,M,..]  (stereo default)
        kw = {}
        rest = argv[4:]
        if "--seed" in rest:
            i = rest.index("--seed")
            kw["seed"] = int(rest[i + 1])
            rest = rest[:i] + rest[i + 2:]
        if "--mono" in rest:
            kw["stereo"] = False
            rest = [a for a in rest if a != "--mono"]
        elif "--stereo" in rest:
            kw["stereo"] = True
            rest = [a for a in rest if a != "--stereo"]
        elif "--stereo-tracks" in rest:
            i = rest.index("--stereo-tracks")
            kw["stereo"] = [int(x) for x in rest[i + 1].split(",")]
            rest = rest[:i] + rest[i + 2:]
        if "--names" in rest:
            i = rest.index("--names")
            kw["names"] = rest[i + 1].split(",")
            rest = rest[:i] + rest[i + 2:]
        items = []
        for spec in rest:
            track, wav, tick = spec.rsplit(":", 2) if spec.count(":") >= 2 else spec.split(":")
            items.append((int(track), Path(wav), int(tick)))
        synthesize_track_region_bundle(Path(argv[1]), Path(argv[2]), Path(argv[3]), items, **kw)
        return 0
    if argv and argv[0] == "exportbeatmap":
        # exportbeatmap <midi> <out> audio1 audio2 … [--head-sync TICK] [--sample-rate 44100|48000]
        #               [--mono] [--names a,b,c]
        #   audio = wav/mp3/aif/… (any CoreAudio format; sample rate matches the source by default)
        kw = {}
        rest = argv[3:]
        if "--head-sync" in rest:
            i = rest.index("--head-sync"); kw["head_sync"] = int(rest[i + 1]); rest = rest[:i] + rest[i + 2:]
        if "--sample-rate" in rest:
            i = rest.index("--sample-rate"); kw["sample_rate"] = int(rest[i + 1]); rest = rest[:i] + rest[i + 2:]
        if "--mono" in rest:
            kw["stereo"] = False; rest = [a for a in rest if a != "--mono"]
        if "--names" in rest:
            i = rest.index("--names"); kw["names"] = rest[i + 1].split(","); rest = rest[:i] + rest[i + 2:]
        export_beatmap(Path(argv[1]), [Path(a) for a in rest], Path(argv[2]), **kw)
        return 0
    if argv and argv[0] == "exportallmulti":
        # exportallmulti <base> <template> <midi> <out> track:wav:tick [track:wav:tick ...]
        items = []
        for spec in argv[5:]:
            track, wav, tick = spec.split(":")
            items.append((int(track), Path(wav), int(tick)))
        export_all_multi(Path(argv[1]), Path(argv[2]), Path(argv[3]), items, Path(argv[4]))
        return 0
    if argv and argv[0] == "export":
        export_logicx(Path(argv[1]), Path(argv[2]), Path(argv[3]))
        return 0
    if argv and argv[0] == "settempo":
        make_tempo_test(Path(argv[1]), Path(argv[2]), float(argv[3]))
        return 0
    if argv and argv[0] == "settempomap":
        make_tempomap_test(Path(argv[1]), Path(argv[2]), Path(argv[3]))
        return 0
    if argv and argv[0] == "setmidimaps":
        make_midimaps_test(Path(argv[1]), Path(argv[2]), Path(argv[3]))
        return 0
    if argv and argv[0] == "validate":
        targets = argv[1:]
        files = []
        for t in targets:
            p = Path(t)
            files.extend(sorted(p.rglob("ProjectData")) if p.is_dir() else [p])
        ok = sum(_validate(f) for f in files)
        print(f"\n{ok}/{len(files)} round-tripped byte-for-byte")
        return 0 if ok == len(files) else 1
    print(__doc__)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
