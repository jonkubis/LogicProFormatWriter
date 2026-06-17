# Logic Pro `ProjectData` — Reverse-Engineering Spec

Authoritative byte-level findings for **writing** Logic Pro's `Alternatives/NNN/ProjectData`
binary from scratch. Reverse-engineered by differential analysis of single-change `.logicx`
fixtures exported from **Logic Pro 11.2.2** (each finding validated by opening generated files
in Logic). 

**Solved & Logic-validated capabilities** (each its own section): the container/record framing (§2),
the unifying event model (§3), **tempo** (§4), **meter / time-signature** maps (§5), **markers** (§6),
**track names** (§7), **audio regions** — multi-track, real filenames, any rate (§8/§8.1), **MIDI note
regions** (§8.5), **project sample rate** (§9), **audio-track synthesis** — adding an arbitrary number of
working audio tracks by activating a pre-allocated mixer (§10.6) — incl. per-track **mono/stereo** (§10.6.7,
stereo by default) and arbitrary **track names** (§10.6.8), **audio-region synthesis** — placing an arbitrary
number of audio regions / beat slices with no per-count template (§10.7), **the combine** — arbitrary N audio tracks
each carrying their regions in one call, from a minimal template + a baked prototype (§10.8), and **mixed-template
synthesis** — arbitrary M software-instrument + N audio tracks, named, EACH with content (MIDI note regions on
instruments + audio regions on audio), in one call (§10.9, the capstone). Read order: §2–3 give the model; §4–9 are
the content writers; §10.6 is the track-cluster anatomy + synthesis (incl. stereo/names), §10.7 the region synthesis,
§10.8 wires the two together, §10.9 generalizes to instrument+audio tracks with both content types.
The reference code (`projectdata.py`) and CLI are catalogued in §12.

Companion code (all stdlib, run with **`python3.12`** — the machine's default `python3`/3.14 has a
broken `pyexpat`/plistlib):
- `projectdata.py` — lossless round-trip parser + all writers + `export`/`audio` CLIs.
- `midimap.py` — Standard MIDI File reader (tempo/meter/marker maps).
- `re_probe.py` — RE workbench (`frames`/`tags`/`diff`/`region`) + a FINDINGS comment block.

All multi-byte integers are **little-endian** unless noted. (The reference repos were stuck partly
because they assumed big-endian.)

---

## 1. Bundle layout (the easy part)
`.logicx` is a macOS bundle/folder. Plists are trivially writable (binary plists via `plistlib`):
- `Resources/ProjectInformation.plist` — `LastSavedFrom`, `HasProjectFolder`, `VariantNames`…
- `Alternatives/000/MetaData.plist` — `BeatsPerMinute`, `SampleRate`, `SongSignatureNumerator/Denominator`, `AudioFiles`…
- `Alternatives/000/ProjectData` — **the binary; this spec.**
- `Alternatives/000/{DisplayState.plist, DisplayStateArchive, WindowImage.jpg, Project File Backups/}`
- `Media/Audio Files/*.wav` — audio (or `Audio Files/` at the outer folder level in folder format).

`MetaData.plist` values are mostly display/caches; the authoritative data is in `ProjectData`
(e.g. tempo, signature, and sample-rate are duplicated in ProjectData and that copy wins —
see §9).

---

## 2. Container framing (SOLVED — the wall both repos hit)
```
ROOT FRAME (offset 0), 24-byte header:
  +0x00  4   magic 23 47 C0 AB
  +0x04  2   version code: D0 09 / CF 09 (Logic 11.2.2). byte +4 varies by version.
  +0x06  10  03 00  04 00 00 00  01 00  08 00   (stable)
  +0x10  4   uint32 LENGTH = filesize - 24      <-- the size field everyone missed (LE, precedes the FourCC)
  +0x14  4   00 00 00 00
  +0x18 ...  PAYLOAD = a flat sequence of RECORDS, to EOF.
```
**Every RECORD** (the first is `gnoS`):
```
  +0x00  4   tag (reversed FourCC, ASCII)
  +0x04 ...  header fields (kind@+4, subtype@+6, ...)
  +0x1c  4   uint32 PAYLOAD SIZE
  +0x24 ...  payload  (record total = 0x24 + payload_size)   <-- 36-byte header
```
So a parser walks: read tag, `size = 0x24 + u32@(rec+0x1c)`, advance. This round-trips **byte-for-byte**
on all known fixtures. `gnoS` (Song) is the first record; its payload contains nested `2347c0ab`
sub-frames + global settings + tempo/SR (kept mostly opaque, patched at fixed offsets). All other
records are flat siblings of `gnoS` inside the root frame.

**No absolute-offset pointers**: growing/inserting a record and fixing the root LENGTH produces a
file Logic accepts (validated by writing an 8 KB-larger tempo map). This is what makes writing feasible.

### Record tags (reversed FourCC)
`gnoS`=Song(root) · `karT`=Track · `qeSM`=MIDISeq · `qSvE`=EventSeq · `gRuA`=AudioRegion ·
`lFuA`=AudioFileRef · `tSxT`/`lytS`=score Text/Style (static 32-entry boilerplate tables) ·
`qSxT`=TextSequence (marker RTF names) · `MroC`=CoreMIDI · `tSnI`=Instrument · `ivnE`=Environment ·
`OCuA`/`nCuA`/`UCuA`=audio-channel objects (`OCuA` ×hundreds — bulk of file) · `OgnS`=SongObject
(incl. the audio-pool bplist) · `MneG`=Session-Player GeneratorMemento · `ryaL`=Layer · `ediV`=Video.

---

## 3. THE UNIFYING MODEL — everything time-positioned is a typed event in a `qSvE`
Tempo points, signature changes, markers, and region placements are all **typed events** living in
`qSvE` (EventSeq) records, each event starting with a constant marker dword and carrying a position:

| Thing            | event marker | event size | host qSvE (how to find) |
|------------------|-------------|-----------|--------------------------|
| Tempo point      | `60 00 00 00` | 32 B | the qSvE whose payload starts `60 00 00 00` |
| Signature change | `30 00 00 00` | 48 B | the qSvE whose payload starts `30 00 00 00` |
| Marker           | `12 00 00 00` | 48 B | filled: payload starts `12 00 00 00`; empty: 52-B qSvE, sub(+6)=0x16, u32@+8=0x40000 |
| Audio placement  | `24 00 00 00` | — | the qSvE whose payload starts `24 00 00 00` |

Each `qSvE` payload = `[events...]` + a **16-byte TAIL** `F1 00 00 00 FF FF FF 3F 00 00 00 00 00 00 00 00`.
Payload size (rec+0x1c) updates with the event count.

### Position / time units (SOLVED)
- **960 PPQ.** 1 bar of 4/4 = 3840 ticks. Confirmed by F4→F5 (region moved 1 bar = +3840).
- Two origins:
  - **Region-origin 34560** (= 9 bars). Used by MIDI/audio **regions**: `pos = 34560 + (bar-1)*3840`.
  - **Tempo/marker-origin 38400** (= 34560 + 3840). Used by **tempo & marker** events.
- For MIDI-driven export, source ticks come straight from the MIDI (rescale to 960:
  `tick960 = round(midi_tick * 960 / midi_division)`); `position = origin + tick960`.

---

## 4. Tempo (SOLVED + Logic-validated)
Tempo value = **`uint32` = round(BPM × 10000)** (120.0 → `80 4F 12 00` = 1,200,000). No float anywhere.

**Single/initial tempo** is replicated at 3 fixed offsets in the `gnoS` payload (file offsets given;
gnoS payload starts at file 0x18, so gnoS-relative = file − 0x18):
`file 0xAA, 0x102, 0x3BE`. (NB: file `0xAE` also holds 1,200,000 in a 120-BPM project but is NOT
tempo — it didn't change in the 137.5 fixture; never blind-scan.)

**Tempo MAP** = the tempo-track `qSvE`. Each 32-byte event:
```
ev+0x00  60 00 00 00                 const
ev+0x04  uint64 position = 38400 + tick@960
ev+0x0c  7F 00 00 [flag]             flag: 0x00 first/initial event, 0x01 explicit point (|0x80 = UI-selected)
ev+0x10  uint32 tempo (BPM*10000)
ev+0x14  00 00 40 88                 const
ev+0x18  uint32 altpos               absolute-time cache, EXACT formula:
                                      altpos = 7_200_000 + round( Σ (Δtick/960)*(60/bpm_seg) * 2000 )
                                      (origin 7.2M = 1hr SMPTE; 2000 units/sec)
ev+0x1c  00 00 00 00
```
Payload = N events + 16-B tail; `payload_size = 32N + 16`. Writer: `set_tempo_map([(tick960,bpm)])`.
Also patch the 3 gnoS slots to the first point's tempo (NB: gnoS+0x92 a.k.a. file 0xAA can hold a
playhead-dependent value once a map exists — read the initial tempo from the 0x3A6/file-0x3BE slot).

---

## 5. Meter / time-signature map (SOLVED + Logic-validated)
Signature value = **`[denominator-exponent][numerator]`** bytes (den = 2^exp): `02 04`=4/4, `02 03`=3/4,
`03 05`=5/8, `04 09`=9/16, `01 0B`=11/2.

Signature `qSvE` layout = **80-byte header + one 48-byte record per signature CHANGE + 16-byte tail**
(`payload_size = 80 + 48*changes + 16`). The **initial** signature lives IN the header: den-exp@+0x0B,
num@+0x0C, flag@+0x0F (0x80 if there are no changes). Each 48-byte CHANGE record:
```
+0x00  30 00 00 00            const (also the inner length 48)
+0x04  uint32 position        = 38400 + tick@960 (meter-aware cumulative ticks)
+0x0b  den-exponent
+0x0c  numerator
+0x0f  flag                   0x80 on the LAST change, else 0x00
+0x10  30 00 00 00 ; +0x17 0x88
+0x18  secidx                 1,3,5,... (= 2*changeNumber-1)
+0x1c  uint32 position        (repeated) ; +0x27 0x88
```
Writer: `set_meter_map([(tick960, num, den)])`. Also set MetaData SongSignatureNumerator/Denominator.
**Decoder (inverse): `ProjectData.get_meter_map(ppq=960) -> [(tick, num, den)]`** (tick0 = bar1, read from
the header + each CHANGE record), plus low-level `decode_sig_events(qsve_raw) -> [(pos,num,den,flag,secidx)]`.
`pd.set_meter_map(pd.get_meter_map())` rewrites the signature qSvE byte-for-byte **except** the non-map
flag/secidx metadata (see below). Tested in `test_decoders.py` (183 assertions, all 61 fixtures).

⚠️ **The `flag@+0x0f` and `secidx@+0x18` are CONTEXT-DEPENDENT, not a single fixed scheme.** Two valid
forms observed, both accepted by Logic:
- **meter-only** (F10_sigs): change secidx = `1,3,5,…` (`2*changeNumber-1`), change flag `0x00` except `0x80`
  on the last; header flag `0x80` when no changes. `set_meter_map` emits exactly this — and our exports use
  it (TEST_exportall_multi, which has a meter change *and* a tempo change, opened + placed correctly in Logic).
- **meter coexisting with tempo changes** (F9_tempometer): Logic instead writes **consecutive** secidx
  (`1,2,…`) and flag `0x01` on every change. Also the header flag@+0x0f is `0x80` on clean/settled no-change
  projects (F0/F1) but `0x00` on some (F11) — a "settling" artifact (§10), NOT map-bearing.
These bytes do NOT affect the decoded map (position/num/den) and `set_meter_map` normalizes to the first
form, which Logic accepts. `get_meter_map` ignores them. (If a complex meter+tempo export ever misbehaves,
matching Logic's consecutive-secidx/0x01 form is the first thing to try — currently un-needed.)

---

## 6. Markers (SOLVED + Logic-validated)
A marker = a 48-byte **event** in the marker `qSvE` + a **name** record (`qSxT`, RTF):
```
marker event (48B):
  +0x00  12 00 00 00
  +0x04  uint32 position = 38400 + tick@960
  +0x10  uint32 link-id  = (markerIndex+1)*4   (4,8,12,...)
  +0x17  0x88 ; +0x1c 0x01 ; +0x27 0x88
name qSxT record:
  hdr+0x0a  uint16 link-id  (same 4/8/12 — matches the event)
  payload: [u32 size][12B zero][u32 rtf_off=0x62][u32 size][13 00 00 00][1B 1B 2F 2F 52 52][zero-pad to 0x62][RTF]
  RTF = standard Cocoa RTF (cocoartf2867 ...) ending '\f0\fs24 \cf2 <NAME>}'
```
The **marker track** (cluster + a metadata `qSxT` + the empty marker `qSvE`) does NOT exist in a fresh
project. Logic creates it the first time you add a marker. **Easiest base trick:** in Logic, add a
marker then DELETE it and save — the marker-track scaffolding REMAINS (empty marker `qSvE` + a template
name `qSxT`), and `set_markers` just fills it (like tempo/meter). `gnoS` marker position-range is at
gnoS-payload +0x1d0 (range-start) / +0x1d8 (last marker). Marker NAME from MIDI = the `FF 06` text.
Writer: `set_markers([(tick960, name)])`.

**Name-qSxT can be SYNTHESIZED (no template needed).** The name `qSxT`'s 36-byte header is constant
boilerplate, byte-identical across F11/F12/F17:
`7153785401002000000004000000ffffffffffffffff020000000200e401000000000000` (kind=1, sub=0x20;
link-id@+0x0a and size@+0x1c are patched per marker). So a base that has the **empty marker `qSvE`** but
NO name-`qSxT` template (e.g. F19/F21 — their marker `qSvE` is byte-identical to F17's validated one:
52 B, sub=0x16, u32@+8=0x40000, empty tail) can still get markers: `set_markers` clones an existing RTF
`qSxT` header if present, else uses the constant, and **inserts the name records right AFTER the marker
metadata `qSxT`** (the lone non-RTF `qSxT`, ~135 B — the names always sit immediately after it; in a
region-only template it's the last record). `_marker_meta_qsxt_index()` locates that anchor.

---

## 7. Track names (SOLVED — the reference repos' #1 unsolved problem)
The track name is a **`uint16` length + ASCII string at the track's `qeSM` (MIDISeq) record, payload +0x34**.
(The repos looked near `karT`; the name is in the paired `qeSM`.) e.g. `0C 00` + `"F7_trackname"`.

---

## 8. Audio regions (SOLVED + Logic-validated; v1 = position+length+name+rate)
Adding an audio region inserts **`lFuA`** (file ref) + **`gRuA`** (region) + a **placement event** in the
audio track's `qSvE` + grows **`OgnS`** (audio pool) + small `gnoS` edits + the wav in `Media/Audio Files/`.

- **Placement event** (in the track `qSvE`): `24 00 00 00` + `uint32 position @+0x04 = 34560 + tick@960`
  (region-origin) + a link to the `gRuA`. **The region's arrangement position lives HERE, not in `gRuA`.**
- **`gRuA`** (region object): `uint32 frame-count (length) @+0x16`; region display NAME = `uint16 len + ASCII`
  at payload **+0x4a** (fixed ~0x28-byte slot); region UUID @+0xac (time-based); file-link field @+0x20.
- **`lFuA`** (file ref, ~90% zeros, **NO macOS bookmark** → fully synthesizable): filename **UTF-16LE**
  (len-prefixed `0d 00` at payload +0x08), inner `LFUA` block, then an **audio-folder PATH** (null-terminated,
  field = [EVAW-0x13e, EVAW-0x62)).
- **⚠️ POOL/SELECTION FIX (verified vs a Logic-re-saved control):** three things must match what Logic
  writes or the region PLAYS but VANISHES from the Project Audio bin + can't be selected:
  1. **lFuA PATH must be the RELATIVE string `"Audio Files"`** (NOT a stale absolute path to the template
     bundle — Logic can't resolve the swapped-in file for the bin; the relative fallback still plays it).
     Write `b"Audio Files\x00"` at EVAW-0x13e (`_set_lfua_relpath`). [Earlier spec said "non-load-bearing" — WRONG.]
  2. **lFuA FILE BYTE SIZE** @ **EVAW-0x32** (u32) must equal the wav's on-disk size — else Logic flags a
     file mismatch and drops the region from the bin (still plays). Patched via `_patch_lfua_evaw(file_size=)`.
  3. **OgnS audio-pool bplist must be EMPTIED** to the base's 68-B form (a stale `Shared→LoopFamily`
     loop-name like `047` breaks the bin) and **per-region `MneG` records dropped** (id≥0x40000; Session-Player
     mementos, not for plain audio). Both done at the end of `place_audio_regions`.
  (`EVAW+0x04` holds an optional audio checksum; ZERO is valid — F21 has zero.)
- **⚠️ WAV `LGWV` CHUNK (the long pool-bug's true cause):** Logic appends an **`LGWV`** chunk (its
  waveform-overview cache) to any WAV that LACKS one, **rewriting the file (+~120 B)** on import — which
  changes the on-disk size so the lFuA file-size (#2) no longer matches → region drops from the bin. Bare
  WAVs (e.g. Python `wave` = `fmt `+`data` only) trigger this; real DAW audio (`bext`/`LGWV`/`regn`/…) does
  not. **The ProjectData synthesis was always correct — `TEST_realwav` (F21's real wavs) proved it.** Fix for
  bare WAVs: `_ensure_wav_lgwv()` appends an LGWV chunk = `[u32 frameCount][u32 checksum][u16 abs-peak per
  ceil(frames/256)-frame bin]` (1 bin/256 frames, peak normalized to 16-bit). Its SIZE is frame-count-fixed,
  so it equals what Logic produces even if Logic regenerates the cosmetic overview — verified my synthetic
  wavs hit Logic's exact sizes (53084/106108/159132 B). The checksum + exact peak scaling (~×1.0118) are
  cosmetic (Logic recomputes); we use 0 + best-effort peaks.
- **🎯 TRUE ROOT CAUSE of the whole bin/selection saga — the gRuA DISPLAY NAME is VARIABLE-LENGTH and the
  gRuA RECORD is SIZED to fit it.** Name = `[u16 len][ASCII name][pad to even]` at gRuA payload +0x4a;
  record size tracks it ('047'→242 B, 'w0'→240 B; the UUID @ ~+0xa4 and everything after SHIFT with the
  name). Writing the name into a FIXED slot (leaving the record the template's size) makes the region VANISH
  from the Project Audio bin + become UNSELECTABLE whenever the name is SHORTER than the template's '047'
  (audio still plays). **`_patch_grua_name` now RESIZES the gRuA** (like the lFuA filename). Cross-isolation
  proved it: working-audio+short-name broke; broken-audio+long-name worked → it's the name length, NOT bit
  depth (Jon: Logic mixes bit depths per-region, so there is NO session-format field — that whole hypothesis
  was wrong). EVAW+0x04/+0x08 ARE format-only constants (`_EVAW_FMT_FIELDS` lookup, 16b vs 24b) but matching
  them was NOT the trigger; the gRuA size was. **✅✅✅ Logic-validated 2026-05-30 — bin + selection work for
  any filename, any bit depth.** Audio-bin requirements (#1 path, #2 file-size, #3 EVAW+0x04/+0x08 format
  constants, #4 EVAW+0x4a clear, #5 gRuA resized-to-name, #6 event flag preserved, #7 gRuA UUID preserved,
  #8 OgnS emptied, #9 per-region MneG dropped, #10 WAV has LGWV) are ALL required and all in `projectdata.py`.
- **`lFuA` audio-format = the `"EVAW"` (WAVE, reversed) descriptor — patch RELATIVE to it (CORRECTION).**
  Its ABSOLUTE offset **shifts with the UTF-16 filename length**, so the old fixed `+0x1f8/+0x200/+0x206`
  was wrong — it only aligned for the 13-char `ZZAUDIOZZ.wav` (EVAW@+0x1ec); a 7-char `047.wav` puts EVAW
  @+0x1e0, a 6-char `02.wav` @+0x1de. **Always locate `b"EVAW"`** then patch: **frames @EVAW+0x0c (u32),
  sample-rate @EVAW+0x14 (u32), channels @EVAW+0x18 (u16), bits @EVAW+0x1a (u16)** (EVAW+0x08 ≈ const 0x400).
  Consistent across F15/F18/F20/F21. Writer uses `_patch_lfua_evaw()`; this also hardened the single-region
  path (previously correct only by luck of the 13-char internal name).
- **`OgnS`** audio-pool = an `NSKeyedArchiver` bplist (decodable/constructible with plistlib UID):
  `Shared → LoopFamily → {LoopName:<basename>, LoopId:0}`.

Writer: `ProjectData.with_audio_region(base, template, tick, sample_len, region_name, sample_rate, bits)` —
implemented as a **delta-replay** of a base→withRegion fixture pair (e.g. F14→F15): aligns records, takes
the template's inserted/changed records, then repositions the placement event and patches
length/name/rate/bits in place (filename kept = template's internal name; the user's wav is copied in under
that name). Bundle CLI: `audio <base> <template> <user.wav> <out> [tick]`.
(`gRuA` display-name slot ~38 chars.) **Real on-disk filenames = DONE** (multi-track path): the lFuA
filename field RESIZES — see `_set_lfua_filename` and §8.1 "Real filenames". The single-region `audio` CLI
still keeps the template's internal name; the multi path (`multiaudio`/`exportallmulti`) uses real names.

---

## 8.1 Track identity (for multiple tracks)
A record's owning track is encoded in **`u32 @ record+0x08 = trackIndex × 0x40000`**
(track1=`0x40000`, track2=`0x80000`, track3=`0xc0000`, track4=`0x100000`, … i.e. index<<18).
Each track has its own region-list `qSvE` carrying this field; in F18 the audio placement
`qSvE` + its `karT` cluster all have `+8 = 0x40000` (track 1). So **placing a region on track K
= putting the placement event in the `qSvE` whose `+8 = K×0x40000`** (and that track must exist).
Adding a *new* audio track from scratch is the heavy "create track" problem (cluster + 93-B `karT`
track-list entries + `ivnE` environment + `OCuA`/`nCuA`/`UCuA` channel objects + gnoS registration);
the pragmatic path mirrors the rest of the project: use a **base that already has N audio tracks**
(make it once in Logic) and place one region per track. **Multiple audio tracks = the active next step.**

**CORRECTED MODEL (F20 = 3 regions on tracks 1/2/3 @ bars 1/2/3, confirmed by Jon):** all audio regions
live in **ONE shared region-list `qSvE`** (the `24..` qSvE; in F20 rec#522, header `+8`=0x40000) holding
**80-byte placement events** (0x50 apart). The **track is a field INSIDE each event**, NOT the host `qSvE`.
The `record+0x08 = index×0x40000` field tags which track a *track-cluster record* (karT/qeSM/qSvE) belongs
to, but region placement uses the in-event track field below. Audio **placement event (80 B)**:
```
+0x00  24 00 00 00            const
+0x04  u32 position           = 34560 + tick@960 (region-origin)
+0x0c  u32 flag/state         (0x100 / 0x80000000=selected / 0x0)
+0x10  u32 per-region id      (0x58,0x5c,0x60… increments ~4)
+0x14  byte TRACK number (1-based) ; +0x15..+0x16 = 00 00 ; +0x17 = 0x89
+0x2c  u32 region link        → its gRuA (values 0/8/4 in F20; the region reference)
       (+0x18 = const; rest constants: 06 00.., 06 8a, 89, …)
```
So **multi-track writer** = per `(track, wav, position)`: add a `gRuA`+`lFuA`+`MneG` (region records) and
an 80-B placement event (TRACK@+0x14, pos@+0x04, link@+0x2c) into the single shared audio `qSvE`; grow
`OgnS` (one loop entry per file) + `gnoS`. The tracks just need to EXIST in the base (F19 = 3 audio tracks).
Fixtures: **F19** (base, 3 empty audio tracks), **F20** (F19 + region on each of tracks 1/2/3 @ bars 1/2/3),
**F21** (F19 + a region per track). Build via delta-replay of F19→F20/F21 generalized to N (track,wav,pos).

**Region linking (decoded F20/F21, exact):** `link@0x2c // 4 == regionIndex == (gRuA/lFuA id@+0x08) // 0x40000`
— two encodings of the same 0-based region creation index. The placement event's `id@0x10 = 0x58 + evIdx*4`.
`MneG` id = `(regionIndex+1)*0x40000` (the base project already has one `MneG` at id 0). Placement events sit
in the qSvE in **track order**, and `MetaData.AudioFiles` is **also in track order**, so track K's wav ↔ the
K-th `AudioFiles` entry ↔ the lFuA the K-th event links to. F20 event→region map (links 0/8/4) and F21 (links
0/4/8) both decode cleanly; the gRuA/lFuA the writer patches is found via the event's link, NOT record order.

**WRITER BUILT + structurally validated (`projectdata.py`, NOT yet Logic-tested):**
- `ProjectData.with_audio_regions(base, template, placements)` — delta-replays base→template (reproduces F20
  byte-for-byte with no patches), then per track patches the placement **position** (by `TRACK@0x14`) and the
  **linked region's** gRuA(framelen@+0x16, name@+0x4a)+lFuA(frames@+0x1f8, rate@+0x200, bits@+0x206).
  `placements = {track: {tick, sample_len, region_name, sample_rate, bits}}`; its track set MUST equal the
  template's (v1 = one region per track, no add/remove — bigger N needs a bigger base, the gnoS per-region
  UUID/timestamp slots are at fixed offsets for the template's region count).
- Helpers: `audio_placements()` (decode the 80-B events), `_region_records_by_index()` (regionIndex→gRuA/lFuA
  rec), `audio_track_filenames()` (track→internal wav name via the linked lFuA UTF-16), `patch_audio_region()`,
  `set_audio_placement_position()`.
- Module fn `add_audio_regions(base, template, items=[(track,wav,tick)], out)` + CLI
  `multiaudio <base> <template> <out> track:wav:tick …` — copies each wav over its track's templated internal
  filename, **prunes orphan wavs**, rewrites `MetaData.AudioFiles` (track order) + SampleRate. v1 keeps internal
  on-disk names (region DISPLAY name = wav stem); real on-disk filenames remain a follow-on (lFuA UTF-16 resize).
- **TEMPLATE CHOICE: use F21, NOT F20.** F21 is clean — 3 distinct real files, track K → region (K-1) →
  gRuA('047/048/049') → lFuA('0NN.wav'), names matching, positional gRuA↔lFuA pairing. **F20 is muddy**:
  its region 0 is a leftover placeholder (`ZZAUDIOZZ_3.wav`, a degenerate 4096-frame/rate-0 ref that was
  never a real distinct file), so a delta-replay off F20 makes Logic merge/mis-bind it (observed: two
  regions collapsed onto one file, the placeholder dropped from the pool). The writer just replays whatever
  template it's given — so give it a clean one.
- gRuA↔lFuA binding is **positional/by record-adjacency** (each inserted `lFuA,gRuA` pair shares id =
  regionIndex×0x40000); gRuA carries NO explicit lFuA-id field. The writer preserves the template's pairing
  and only patches leaf values, so the binding stays intact regardless of its exact mechanism.
- **OgnS is NOT the per-file pool.** Its grown record (~1.4 KB) is just an NSKeyedArchiver bplist
  `Shared→LoopFamily→{LoopName:<one basename>, LoopId:0}` (a single loop-family entry) + ~930 B trailing.
  Region→file binding does NOT go through it; it's copied wholesale from the template.
- Verified (deconfounded — 3 synthetic wavs NOT from any fixture: 0.5 s/1.5 s/3.0 s, 440/660/880 Hz, stereo
  16-bit): F19→F21 build round-trips; per region the **EVAW** block reads the correct distinct
  frames/rate/channels/bits and gRuA length; Media pruned to exactly the 3 user wavs; MetaData correct;
  mismatched-track-count raises; 8/8 round-trip incl. single-region regression. **✅ LOGIC-VALIDATED
  (2026-05-29):** `fixtures/TEST_multiaudio.logicx` opened clean — `sine_a`@bar1/tr1, `sine_b`@bar3/tr2,
  `sine_c`@bar5/tr3, three distinct files in the pool, correct per-region lengths/audio. Multi-track audio DONE.
- Possible minor follow-on: a `gnoS` cached region-range (near the marker range @+0x1d0; F19→F20 changed
  gnoS-rel +0x1d9) is copied from the template, so placing regions past the template's max bar may leave the
  song-end cache short (likely cosmetic / recomputed on load).

### Arbitrary region counts — structural findings (investigation, 2026-05-29)
Per region, beyond the gRuA/lFuA/MneG records + 80-B placement event, Logic writes into a set of **gnoS
object tables** and grows **OgnS**:
- **gnoS object-UUID registry** (multi base, F19→F20): two 24-B-stride tables — `A`@gnoS+0x1234,
  `B`@gnoS+0x37cc — each entry = `[16-B UUID][u32 type-tag][u32 link=regionIndex*4]`; plus 16-B-stride
  timestamp tables `C`@+0x3b2c and `E`@+0x543c, and a 4-B table `D`@+0x431c (entries `[8-B time][u32 tag]
  [u32 link]`). (Single-track lineage F17→F18 has the SAME tables at shifted bases: A@0x1234, B@0x373c,
  C@0x3a6c, E@0x531c — the base offset moves with track count; the 320-B-larger multi gnoS shifts B/C/E.)
- The registry is **densely packed, NOT a zero-slack array**: right after the 3 region entries sit OTHER
  objects' UUIDs (distinguishable by a different time field, region=`…5b43…` vs neighbor `…5b12…`). So you
  can't freely append a 4th region entry without colliding/shifting.
- BUT in the 0-region base those region slots are **zero** (Logic fills them when regions are added), and
  Logic made/opened that base fine ⇒ **zero gaps in the registry are valid**, and the base **pre-allocates
  capacity = its audio-track count**. Counter `gnoS+0x89`→0x08 = "has audio" flag (not a count);
  `+0x1d9` (multi only) = 0x0159 with 3 regions (region range/count, TBD).
- **OgnS audio pool** scales linearly: **~76-B base + ~468-B per region** (0/1/3 regions = 68/544/1480 B).
  The NSKeyedArchiver bplist (single `Shared→LoopFamily` entry, ~430 B) does NOT scale; the per-region
  growth is in binary blocks after it.
- **Implication:** capacity is bounded by the base's track count (its pre-allocated zero slots). The
  reliable path = a base/template with the MAX track count needed (make once in Logic) + **TRIM** unused
  regions (zero their registry entries → mimics the valid 0-region state, drop their records, shrink OgnS).
  Cloning BEYOND the base's capacity needs dense-registry insertion + bplist-pool extension (hard; load-
  bearing of the UUIDs/timestamps still unverified in Logic). Multiple regions per single track = same
  beyond-capacity problem.

### ⚠️ CORRECTION 2 (2026-05-29): the real culprit for empty-pool + no-selection was the PLACEMENT EVENT
### FLAG field (event +0x0c). `place_audio_regions` rebuilt all events from one prototype and ZEROED the
### flag; the working `with_audio_regions` never touches it. Reproducing F21 via place was a 1-byte diff
### (F21's last event flag 0x80000000 → 0) — and that single change broke the Project Audio list + region
### selection (regions still PLAYED). FIX: reuse each region's OWN template event (preserve flag@+0x0c,
### id@+0x10, link@+0x2c), change only position@+0x04 + track@+0x14 → place now reproduces F21 byte-for-byte.
### (The gRuA-UUID-preservation in CORRECTION 1 below is also necessary; the flag was the missing piece.)

### ⚠️ CORRECTION 1 (2026-05-29): the gnoS registry + OgnS pool ARE load-bearing — for the Project Audio
### list + region SELECTION (just NOT for playback). The clone-and-perturb approach below made regions
### PLAY but they vanished from the Project Audio pool and couldn't be clicked/selected (Jon: "not seeing
### any files in the project audio list … they don't highlight"). Diagnosis: `with_audio_regions` (patches
### template regions IN PLACE) is byte-identical to the Logic-good F21 EXCEPT it preserves the gRuA region
### UUIDs (@+0xca); the rebuild `place_audio_regions` PERTURBED those UUIDs (OgnS + gnoS registry were
### otherwise identical). So each region's identity (gRuA UUID + id + its registry/OgnS entries) must be
### kept INTACT. **FIX: REUSE the template's region records (preserve identity) — don't clone+perturb.**
### Region count is therefore bounded by the template's region count K (use a K-region template); each region
### still freely sets track/position/file/length and multiple regions may share a track. Truly unbounded N
### would require synthesizing matching gnoS-registry (tables A/B/C/D/E) + OgnS-pool entries per region.
### (Kept below for the record — the "regions play without registry/OgnS" finding is real but insufficient.)

### Earlier (INCOMPLETE) finding — regions PLAY without the gnoS registry/OgnS, but aren't fully integrated.
Test `TEST_clone4.logicx`: from the working 3-region project, a **4th region was CLONED** (gRuA+lFuA+MneG
with fresh ids + a unique perturbed region UUID, + an 80-B placement event) and placed as a 2nd region on
**track 1** — with the gnoS object-registry AND OgnS pool **left untouched in their 3-region state**. Logic
opened it with **all 4 regions working** (incl. multiple regions on one track). So Logic **regenerates**
those caches; a region needs only: its **gRuA + lFuA + MneG records** (object id@rec+0x08 = i×0x40000 for
gRuA/lFuA, (i+1)×0x40000 for MneG) with a **unique region UUID** (gRuA payload +0xa6, time-based; perturb
to avoid collision) + a **placement event** (track@+0x14, pos@+0x04, link@+0x2c = i×4, id@+0x10 = 0x58+ev×4).
NO gnoS-registry/OgnS/ivnE/karT edits needed for regions on EXISTING tracks. **⇒ Arbitrary region counts
(any N, multiple per track) = clone the prototype region N times + rebuild the placement qSvE with N events.**
Region count is now unbounded; only TRACK count is still bounded by the base (track creation = separate
heavy problem).

### ✅ Real on-disk filenames (lFuA resize, 2026-05-29)
Each region uses its wav's REAL basename (de-duplicated: `name.wav`, `name_1.wav`…). The lFuA internal
filename (UTF-16LE, u16 char-count @ payload+0x08, string @ +0x0a) is RESIZED in place:
`new = raw[:0x24+0x0a] + name.utf16le + raw[0x24+0x0a + oldChars*2:]`, then set the count @+0x08 and the
record payload-size @+0x1c. Everything after the name (LFUA block, dir-path, EVAW…) shifts by Δchars×2 —
and that's fine: there are NO stored offsets to fix (the two payload+0x00/+0x04 = `0x370` fields are
name-independent; EVAW is relocated by content search). Verified: a 32-char name grew the lFuA to 688 B and
EVAW still read correct frames/rate/bits; round-trips. The dir-PATH string (still the template bundle's) is
left as-is — non-load-bearing (Logic resolves audio relative to the project's own `Media/Audio Files/`).
`_set_lfua_filename` does the resize; `_build_region_specs` assigns the names; `_assemble_audio_bundle`
copies each wav to its real name + writes `MetaData.AudioFiles`.

## 8.5 MIDI note regions (note encoding Logic-VALIDATED 2026-05-30; synthesizer generalizing)
RE'd from **F4_midiregion**/**F5_region_moved** (empty region @bar1/@bar2) and **F4b_midinotes** (= F4 with
3 KNOWN notes added). The note encoding is DECODED (below); synthesis is the remaining work (task #31).

- **No `gRuA`.** MIDI regions do NOT use the audio region record. A MIDI region **IS a `qeSM` (MIDISeq)
  record** with its own track-cluster index @rec+0x08 (e.g. 0x1c0000), distinct from the track's main qeSM.
- **Region qeSM layout** (empty, 303B payload): name = u16 len + ASCII @ **record +0x34** (= payload +0x10;
  ="Inst 1", same offset as the track name in a track's qeSM); region ID @ **+0x2c** (renumbered on save); **internal
  start position @ +0x11c** = zero-based 960-PPQ tick (F4=0, F5=3840); **region LENGTH @ +0x78** = duration in
  960-PPQ ticks (F4=3840 = 1 bar; consistent F4/F4b/F4c; `+0x0c` of the placement is POSITION not length —
  it shifted on F4→F5 *move*). Remainder = zeros + scattered default
  metadata (loop/quantize/color…). The region qeSM is UNCHANGED when notes are added (F4↔F4b byte-identical)
  — **notes live in the region's PAIRED qSvE, not the qeSM** (see NOTE EVENTS below).
- **Placement** = an event in the **track's qSvE**, SAME event family as audio placement (§8) but type
  marker **`20 00 00 00`** (audio = `24`): **pos @ payload +0x04 = 34560 + tick** (region-origin form),
  **id @ +0x10 = 0x58** (+ev×4), **track @ +0x14**, **link @ +0x2c**, then the `f1…3f` tail. So position is
  stored TWICE: placement qSvE+0x04 (34560-based) AND region qeSM+0x11c (zero-based) — both must be set.
- **Linkage** placement↔region: the shared **`0x58`** (placement +0x10 == region qeSM +0x108) is the likely
  link id.
- **Synthesis plan**: mirror the audio delta-replay — reuse a donor's region qeSM + its placement event,
  patch both position fields + the name, and inject the notes. The placement/track machinery transfers from
  `place_audio_regions`; the NEW work is (a) the region qeSM note encoding and (b) wiring region↔placement.
- **NOTE EVENTS (decoded from F4b_midinotes, 3 notes).** Notes live in the region's **PAIRED `qSvE`** (same
  cluster idx 0x1c0000 as the region qeSM), NOT the qeSM. Empty region qSvE payload = just the 16B `f1…3f`
  tail; each note adds a **32-byte event** before the tail (payload = 32·N + 16). The event:
  ```
  +0x00  u32  90 00 00 00      const marker (0x90 = MIDI note-on status byte)
  +0x04  u32  position         = 38400 + tick@960  (tempo/marker origin, NOT region-origin 34560)
  +0x0a  u8   ??? (0x5c/0xb8/0xac across the 3 notes) — UNKNOWN (release-vel? per-note seed?) — INVESTIGATE
  +0x0b  u8   velocity         (1..127)            [F4b: 32 / 64 / 100]
  +0x0c  u8   pitch            (MIDI note number)  [F4b: 36 / 60 / 84];  +0x0d = 0
  +0x0f  u8   flag             0x01, with bit7 (0x80) set on the LAST note (terminal, as in tempo/sig)
  +0x10  u8   0x40             const (=64; likely note-off velocity default);  +0x11..13 = 0
  +0x17  u8   0x89             const  (+0x14..16 = 0)
  +0x1c  u32  length           note duration in 960-PPQ ticks  [F4b: 240 / 480 / 960]
  ```
  (all other bytes 0). Decoded values matched the drawn notes exactly: C1/C3/C5 · vel 32/64/100 · beats
  1/2/3 (pos 38400/39360/40320, +960 each) · 16th/8th/quarter. The region qeSM is untouched by notes.
- **RESOLVED via F4c_midinotes_bar2** (F4b's region dragged to bar 2, same notes): note positions are
  **REGION-RELATIVE** — F4b@bar1 and F4c@bar2 have a **BYTE-IDENTICAL note qSvE** (38400/39360/40320 unchanged)
  while ONLY the placement event moved (+0x04: 34560→38400). So `note.pos = 38400 + region-relative tick`;
  the region's absolute position lives only in the placement (+0x04) and region qeSM (+0x11c). The +0x0a byte
  is STABLE across the re-save (deterministic; the +0x0a/+0x0b u16 ≈ velocity×256+frac = a fine-velocity —
  synthesis writes 0 for an exact integer velocity). Adding notes touched ONLY the region qSvE (+32·N bytes),
  no registry/qeSM change.
- **ENCODER/DECODER (proven, no Logic needed):** `ProjectData._enc_note_event(tick,pitch,velocity,length,
  last,fine=0)`, `build_note_qsve_payload(notes)`, `decode_note_events(qsve_raw)` — `decode→encode` reproduces
  F4b AND F4c region qSvE **byte-for-byte** (every note byte accounted for). `test_midi_notes.py`, 9 assertions.
- **SYNTHESIZER (notes-injection) BUILT 2026-05-30:** `with_midi_region(template, out, notes)` + CLI
  `midiregion <template> <out> tick:pitch:vel:length …` inject notes into a template's empty region — it
  locates the region's note qSvE (by the region-name qeSM's cluster idx) and sets its payload =
  `build_note_qsve_payload(notes)`, touching ONLY that record (matches F4→F4b). `TEST_midinotes.logicx`
  (= F4 + the 3 known notes) is a byte-faithful synthetic F4b — identical except the 3 `+0x0a` fine-vel bytes
  (we write 0) — **✅ Logic-validated 2026-05-30** (Jon: 3 notes + velocities 32/64/100 correct ⇒ +0x0a=0 is
  confirmed don't-care for display; the note encoding is proven end-to-end).
  **POSITION PATCHING BUILT:** `with_midi_region(..., region_tick=)` (CLI `@<tick>`) moves the region —
  patches placement +0x04 (=34560+tick) + region qeSM +0x11c (=tick) + placement +0x0c (shifted ×0x100 per
  4/4 bar, matching F4→F5); leaves track-cluster display caches to Logic. `TEST_midinotes_bar5.logicx`
  (region @bar5 via `TimeMap.from_project(F4).bar_to_tick(5)`, same 3 notes) — only 3 records change vs F4
  (placement qSvE + region qeSM + note qSvE) — **✅ Logic-validated 2026-05-30** (Jon: "perfect" — region at
  bar 5 with notes intact; +0x0c handling correct).
  **MIDI-FILE SOURCE BUILT:** `with_midi_file_region(template, midi, out, channel=, region_tick=)` + CLI
  `midifile` read notes from a Standard MIDI File and place them as a region. `midimap.py` now captures
  note-on/off pairs → `notes` + `rescaled_notes(ppq, channel)` (pairs by (chan,pitch), closes dangling at
  track end). **✅ Logic-validated end-to-end via `TEST_jkbass.logicx`** = a REAL part (wishingyoupeace_jkbass.mid,
  206 notes / ~85 bars) imported with correct notes + auto-sized region LENGTH (Jon: "Sure does!" — full bass
  shows). Also: all 206 `.mid` files in ~/Music/temp parse cleanly (div 480/1920, fmt 0/1, ≤2250 notes, 0 fail).
  **⇒ Single-region MIDI from a MIDI file is COMPLETE (notes + position + length, Logic-validated).**
- **MULTI-REGION / MULTI-TRACK done & ✅ Logic-validated 2026-05-30.** `place_midi_regions(template, out,
  [notes_per_region])` and `place_midi_files(template, out, [midi_paths], channel=)` + CLI `multimidi`. Fills
  the K empty regions of a template (named `Inst N`, found by qeSM-name + paired empty note qSvE, sorted by
  cluster idx) — one note-list / one MIDI file per region — auto-sizing each length. Bounded by the
  template's region count K (like audio); regions keep the template's track+position (you pre-place them).
  Template **F22_multimidi.logicx** = 4 empty regions on 4 tracks. Jon validated `TEST_multimidi.logicx`
  (4 octave-distinct regions) — "All 4 placed perfectly". `TEST_overture.logicx` = 4 real parts
  (usjxmas_overture bass/brass/drums/wws, 94/343/333/236 notes, 48 bars each) imported in one call —
  **✅ Logic-validated 2026-05-30** (Jon: "Looks perfect").
- **UNIFIED MIDI EXPORT BUILT 2026-05-30:** `export_midi_multi(template, out, [part_midis], master_midi=,
  channel=)` + CLI `exportmidi <template> <master.mid> <out> <part1.mid> …` — one call sets tempo + meter
  (+ markers if the template has a marker track) from a master MIDI and places each part's notes as its own
  region (mirrors `export_all_multi`, MIDI instead of audio; region-fill refactored into shared
  `_fill_midi_regions(pd, region_notes)`; writes MetaData BPM/sig). `TEST_overture_full.logicx` = overture
  tempo 127→154 BPM + 4/4 + 4 parts (94/343/333/236 notes) — round-trips, **✅ Logic-validated 2026-05-30**
  (Jon: "Looks good").
- **REGION NAMING BUILT 2026-05-30 (corrected — it RESIZES).** The region qeSM name is VARIABLE-LENGTH
  `[u16 len @RECORD+0x34][ASCII @+0x36][pad→even][rest…]` with `rest` immediately after the string — exactly
  like the gRuA name. An in-place write that kept the record size and left stale bytes CORRUPTED the file
  ("The song you are trying to open is corrupted"), because Logic walks len→name→rest. `_set_region_name`
  now RESIZES the record (mirrors the validated `_patch_grua_name`; updates payload size @+0x1c). The +0x78
  length / +0x11c position fields sit AFTER the name and shift on resize (values preserved), so they're
  patched BEFORE renaming. `place_midi_files` / `export_midi_multi` auto-name each region after its file
  (last `_`-segment of the stem) via `rename=True`; any name length now works. `TEST_overture_named.logicx`
  = parts named bass/brass/drums/wws — round-trips, **✅ Logic-validated 2026-05-30** (Jon: "Opens cleanly.
  That fixed it!").
- **COMBINED AUDIO+MIDI EXPORT BUILT 2026-05-30:** `export_av_multi(template, out, master_midi=,
  audio_items=[(wav,tick)], midi_parts=[mid])` + CLI `exportav` — one call from a SINGLE combined template
  (`F23_av.logicx` = M audio tracks w/ placeholder regions + N empty MIDI regions "Inst N" + marker track).
  KEY: audio (`24`) and MIDI (`20`) placement events SHARE one arrange qSvE (idx 0x40000), so it patches the
  audio events IN PLACE by `link@+0x2c = i*4` (preserving the MIDI ones) instead of rebuilding the qSvE like
  `place_audio_regions`; empties the audio pool via the fixed 32-B `_EMPTY_AUDIO_OGNS_PAYLOAD` (byte-identical
  across F17/F19/F22 — no base needed); drops audio MneG (id≥0x40000; MIDI regions carry none); fills the MIDI
  regions; sets tempo/meter/markers from the master MIDI. `TEST_av.logicx` = 3 audio (bars 1/2/3) + 4 MIDI
  parts + tempo 127→154 — round-trips, **✅ Logic-validated 2026-05-30** (Jon: all good — opens cleanly,
  3 audio regions in the Project Audio bin + selectable, 4 MIDI parts, tempo ramp). ⇒ audio + MIDI + maps
  in one call. **EVERY content type now exports together — the exporter is feature-complete.**
  NOTE: the region's MIDI content lives in its OWN cluster (F4: idx 0x1c0000 = karT+qeSM+qSvE), SEPARATE from
  the visible instrument track (idx 0x40000) whose qSvE holds the placement event. Every idx has karT records,
  so identify the region cluster by its region-name qeSM (name@+0x34, e.g. "Inst 1") + the +0x11c field +
  the placement reference — NOT by "no karT".

## 8.6 ALAC / CAF (Apple Lossless) audio (SOLVED + Logic-validated 2026-06-16)
Logic plays **Apple Lossless (ALAC) in `.caf` containers** natively, ~3-4× smaller than WAV
(measured 27% on a 7-stem song). RE'd by diffing two control sessions made from IDENTICAL PCM —
`fixtures/ctl_wav.logicx` (WAV) vs `fixtures/ctl_caf.logicx` (ALAC) — saved by Logic. Of 530
records only the **`lFuA`** is format-relevant; its WAV and CAF forms are byte-identical except
**6 descriptor-anchored changes** (everything else that differs between the two controls — the
`gRuA` region UUID, `OCuA`/`UCuA`/`ivnE`/`karT` channel/track UUIDs, the `gnoS` registry — is
time-based session identity, since they're independently-saved projects; the `gRuA` region NAME
is byte-identical, so regions/pool/registry need NO change).

Locate `b"EVAW"` at offset `d`, then:

| # | change | offset | WAV | ALAC/CAF |
|---|--------|--------|-----|----------|
| 1 | filename extension | UTF-16LE + ASCII copies | `.wav` | `.caf` |
| 2 | type flag | `d − 0x1c3` (u8) | `0x01` | `0x11` |
| 3 | compressed marker | `d − 0x142` (4B) | `00000000` | `"PMOC"` (= `COMP`, reversed) |
| 4 | descriptor magic | `d + 0x00` (4B) | `EVAW` (WAVE) | `ffac` (caff) |
| 5 | format const | `d + 0x08` (u32) | `0x2c` | `0x00` |
| 6 | size field | `d − 0x32` (u32) | on-disk file size | **decoded PCM bytes** (`frames×ch×bytes`) |

frames (`d+0x0c`) / rate (`d+0x14`) / channels (`d+0x18`) / bits (`d+0x1a`) are UNCHANGED (ALAC
is lossless). Anchors #2/#3 are **descriptor-relative** (verified across 3 fixtures of differing
filename length: the flag is `0x01` at `EVAW−0x1c3` and the COMP slot `0` at `EVAW−0x142` in all).
Applying these to `ctl_wav`'s `lFuA` reproduces `ctl_caf`'s `lFuA` **byte-for-byte**.

**The load-bearing insight — size field = DECODED size, not file size** (CAF: 705600 = 176400×2×2;
the `.caf` file is 134904). This is why ALAC is robust: unlike WAV (§8, where the file-size field
must equal the on-disk size, so Logic's `LGWV` rewrite would break it), the CAF reference is
independent of the compressed file. Logic appends a cosmetic **`ovvw`** overview chunk to the `.caf`
on import (the CAF analog of WAV's `LGWV`) — but since the size field is PCM-based, that rewrite
can't invalidate the reference, so plain `afconvert -f caff -d alac` output works as-is.

Implemented in **`logicx/alac.py`** (`wav_lfua_to_caf` + `convert_bundle_to_alac`); exposed as
`export_beatmap(..., lossless=True)` and CLI `exportbeatmap … --alac`. Tests: `test_alac.py`
(byte-exact vs the controls). Donor recipe: `DONORS.md` → "ALAC control pair".

## 9. Project sample rate (SOLVED + Logic-validated)
`MetaData.plist["SampleRate"]` ALONE does NOT set the session rate (Logic ignores it on open). The
authoritative session rate is in the **`gnoS` payload**:
- byte @+0xDF : 44.1k = `0x00`, 48k = `0x16`
- uint16 @+0x11E and @+0x120 : 44.1k = `0xE970` (59760), 48k = `0xF8AC` (63660)  — SR-LINEAR (Δ = SR Δ = 3900)

Patching just these PRIMARY fields + `MetaData.SampleRate` makes Logic open at the new rate (validated:
F0 patched → opened at 48k). A larger `+0x11cc` gnoS block is SR-DERIVED and Logic recomputes it on load.
Table currently covers 44100/48000 (the common beatmapping rates); high rates would overflow the u16 at
+0x11e and likely use a different field. Writer: `set_project_sample_rate(rate)`, auto-applied in the audio
export to match the wav. (Note: a 48k file in a 48k project on a 44.1k interface plays correctly via output
resampling; a 48k file in a 44.1k project plays slow — Logic doesn't resample files on playback.)

---

## 10. The "settling" phenomenon (important gotcha)
A brand-new minimal project has a **compact `gnoS` (~10,792 B)**. After it gains content (first marker,
audio track, SR change, …) Logic **expands `gnoS` to a "settled" ~21 KB** and keeps it (≈ +10,240 B,
~75% zeros, differs throughout — NOT a clean appendable block; not reproducible by re-saving alone).
Implications:
- Tempo/meter writers work on the compact base (they only touch standalone `qSvE`, never `gnoS`).
- Markers/audio/SR touch `gnoS` → use a **settled base** (the add-then-remove trick settles it cleanly).
- The SR fields (§9) are settling-independent (same value in compact & settled 44.1k projects).
- Don't try to "settle F0" programmatically — use a base template Logic already settled.

---

## 10.5 Preserved donor templates (`templates/`)
The production exporters delta-replay from donor `.logicx` bundles. The canonical donors are preserved in
**`templates/`** (stable, separate from the experimental `fixtures/` ladder which may be pruned):
- `F19_multi_base.logicx` + `F21_multitrack_regions.logicx` — **multi-track AUDIO** base + region-per-track
  template (`export_all_multi` / `multiaudio`). F19 also carries the marker track.
- `F17_base.logicx` + `F18_audio.logicx` — **single-track AUDIO** base + template (`export_all` / `audio`).
- `F4_midiregion.logicx` — **single MIDI region** template (`with_midi_region` / `midifile` / `midiregion`).
- `F22_multimidi.logicx` — **multi MIDI** template, 4 empty `Inst N` regions on 4 tracks
  (`place_midi_files` / `multimidi` / `export_midi_multi`).
- `F23_av.logicx` — **combined audio+MIDI** template, M audio tracks w/ placeholder regions + N empty MIDI
  regions + marker track (`export_av_multi` / `exportav`).
- `F13_settled_or_not.logicx` — **settled marker-track base** for maps-only export (`export_logicx`).
All 8 round-trip byte-for-byte; the exporters run identically from `templates/` or `fixtures/`. **Point the
tool at `templates/`, not `fixtures/`** (the latter is prunable — though the test suite still reads F4b/F4c/F22).

## 10.6 Audio tracks — anatomy & synthesis (SOLVED + Logic-validated 2026-05-30)
A Logic audio **track** is not a single record: it spans a *cluster* of records cross-linked by idx and by UUID.
Adding a track = ACTIVATING one of a mixer's pre-allocated channel "slots" and wiring that cluster. This section
covers (10.6.1) why a pre-allocated template is required, (10.6.2) the track anatomy + cross-links, (10.6.3) the
field-by-field activation procedure, (10.6.4) the **visibility gates** that decide whether a track is actually
DRAWN, (10.6.5) the cosmetic/non-load-bearing parts, and (10.6.6) the reference + RE notes. Implementation:
`activate_audio_track()` / `synthesize_audio_tracks()` in `projectdata.py`; validated in Logic at 4 / 9 / 13
tracks and diff-validated byte-for-byte (modulo fresh ids) against Logic's own 2- and 4-track saves.

### 10.6.1 Why a pre-allocated template (not from-scratch)
Tracks can NOT be synthesized from nothing: creating a brand-new channel triggers Logic's mixer / CoreMIDI-
Environment EXPANSION, which regenerates time-UUIDs and re-indexes the entire `OCuA` channel block — pervasive
and impractical to reproduce. BUT **deleting tracks KEEPS the mixer**: the pre-allocated `OCuA` channel strips
and `gnoS` registry slots are retained. So the strategy is:

> Make a session with **N audio tracks** in Logic, **delete all but one**, and save. The result is a TEMPLATE
> with an **N-channel pre-allocated mixer** = up to N−1 free "slots", each of which can be ACTIVATED into a
> working track without any further Logic interaction.

A 64-track template (`1 from 64 audio tracks.logicx`) gives ~63 free slots. Activation cost is O(mixer size)
(see the re-index note, 10.6.6) — so size the template near your needs (64/128), not 1000.

### 10.6.2 Audio track anatomy — the record cluster
Slots are numbered by their `ivnE` idx, which strides by **0x40000** (slot byte = idx>>16; e.g. 0x580000→slot
0x58, next 0x5c0000→0x5c). One audio track spans these records:

| Record | idx | Role | Key fields |
|---|---|---|---|
| `ivnE` | slot<<16 | **Channel / Environment object** | `@0x1eb` = 16-byte **channel UUID**; `@0x08`,`@0x34` = idx/slot; `@0x74` = is-last flag |
| `OCuA` | type-tag `0x240000`¹ | **Mixer channel STRIP** (fader/pan/mute/sends/plugins), pre-allocated | `@0xbd` = 16-byte UUID (must equal its `ivnE @0x1eb`); `@0x82` = pre-assigned ordinal |
| `karT` | `0x040000` group | **Arrange Track row** (93 B) — what the arrange/mixer DRAWS | `@0x2a` = channel idx it points at; `@0x12` = ordinal; `@0x3c` = 16-byte track id |
| `karT` | `0x080000` group | Per-slot **Track objects** (one per slot) | `@0x2c` = slot#; `@0x12` = active-rank; **stream order = the track list** |
| `qeSM`,`qSvE` | slot<<16 | The slot's **event sequences** (empty for an empty track) | pre-allocated; reused as-is |
| `MneG` | 0 | **Session-Player** global state | a `drummerModelTrackStates` entry keyed by the arrange-track `@0x3c` id |
| `gnoS` | root | counters + object **registries** (Tables 1/2/3) | `@0xf4` = track count<<16; `@0x80` = max ivnE idx; per-slot registry rows |

¹ For `OCuA`, the u32 `@0x08` (`0x240000`) is a TYPE tag shared by ALL ~440 strips — it is **not** a unique idx.

**Cross-links** — these bind the cluster; break one and the track is orphaned (channel exists but no Track drawn):
- `ivnE @0x1eb` (channel UUID) **==** `OCuA @0xbd` → binds a channel to its strip.
- `karT`(0x040000) `@0x2a` **==** the `ivnE` idx → binds the arrange Track to its channel.
- `karT`(0x040000) `@0x3c` (track id), formatted as a UUID string, **==** a key in `MneG.drummerModelTrackStates`
  → binds the Track to its Session-Player state.
- `gnoS` Table 1 / Table 2 rows hold each slot's UUIDs (the object registry).

### 10.6.3 Activation procedure — wiring one new slot
Let `T` = current track count (`gnoS @0xf4 >> 16`), `cur_max` = `gnoS @0x80`, `new_idx` = `cur_max + 0x40000`,
`slot = new_idx >> 16`. `CONST_A` = the 4 bytes at `gnoS @0x1e14` (the session UUID middle, e.g. `5c2211f1`).
Generate two fresh 16-byte ids: `chan_uuid` and `kart_id`, each shaped `[time_low:4][CONST_A:4][node:8]`. Then:
**(a) `gnoS` — counters + registries.** `@0xf4`=`(T+1)<<16`; `@0xf8`=`((T+1)<<16)|1`; `@0x80`=`new_idx`.
Table 1 (ivnE registry; 16-B header UUID then 24-B rows `[u32 0x14][u32 slot][16-B UUID]` from `@0x1e20`): in the
row whose slot==`slot`, write UUID = `[reg_time_low:4][CONST_A:4][reg_node:8]`. Table 2 (parallel registry; 16-B
rows `[id:8][u32 0x14][u32 idx]` from `@0x4db0`): in the row whose idx==`slot+4`, write `[reverse(reg_time_low)]
[CONST_B]` (CONST_B = the `[4:8]` of any filled Table-2 row, e.g. `225cf101`). Table 3 (running stamps, `@0x5240`):
refresh — non-load-bearing.

**(b) `ivnE` — clone the channel.** Clone the current max-idx ivnE and insert the copy immediately after it. On
the copy: `@0x08`=`new_idx`, `@0x34`=`slot`, `@0x1eb`=`chan_uuid`, `@0x74`=1, `@0x76`=src+0x42,
`@0xca`/`@0xcc`/`@0xcf`=src+1 (ordinals; `@0xca` is also the single-byte name counter — §10.6.5). On the SOURCE:
`@0x74`→0, `@0x51`+=2 (linked-list maintenance).

**(c) `OCuA` — link the strip.** Find the pre-allocated strip with `@0xbd`==all-zero AND `@0x82`==`T`; set
`@0x3c`=1, `@0x3d`=1, `@0x82`=0, `@0xbd`=`chan_uuid` (gate 2).

**(d) `karT`(0x040000) — the arrange Track.** Clone the base audio row (`@0x2a`==0x580000); set `@0x2a`=`new_idx`,
ordinal `@0x12`=`T` (`[0x10:0x18]`=`ff ff <T> 00 00 00 02 00`), `@0x3c`=`kart_id`, `@0x4c`=0x20 (clear the previous
last row's 0x20→0). INSERT just before the master row (`@0x2a`==0x500000); bump the master's ordinal to `T+1`
(gate 1).

**(e) `MneG` + (f) the visibility tables** — apply gates 3, 4 and 5 plus the arrange-order table (§10.6.4).

### 10.6.4 Visibility gates — DRAWN vs. merely present
A channel appearing in the **Environment** window is NOT sufficient — the **arrange + mixer** draw a Track only
when ALL of the following hold. (Each was isolated by reverting it in a Logic-made working file until the Track
disappeared.)

1. **Arrange Track row, pointing at the channel** — a `karT`(0x040000) row with `@0x2a` = the new ivnE idx
   (procedure d). Pointing at the wrong channel (e.g. the master) draws no Track.
2. **Channel strip UUID-linked** — `OCuA @0xbd` == `ivnE @0x1eb` (procedure c). Unlinked = dead strip (no
   fader/pan/plugins).
3. **Session-Player binding** — the arrange-Track `@0x3c` id, formatted as a UUID string, is a KEY in
   `MneG.drummerModelTrackStates`. MneG layout: JSON at rec-offset 0x48; dict marker `drummerModelTrackStates":{`;
   insert `"<UUID>":{…343-B body…},` right after the `{`; bump length fields `@0x24`, `@0x40` and record size
   `@0x1c` by the inserted length. Body = `"Acoustic Drummer - Pop Rock"/Type_AcousticDrummerV2/stateVersion:3`.
   Generate `kart_id` ONCE and use for BOTH `@0x3c` and this key. Missing = orphaned Track (channel in
   Environment, no Track drawn). (The template already carries ~17 entries — residue from the deleted session —
   and the count grows +1/track.)
4. **Per-slot active-rank AND stream order** — `karT`(0x080000), one per slot (`@0x2c`=slot#). Rank byte `@0x12`,
   by slot-index `idx=(slot−0x48)/4`: idx 0..3 = fixed 0x40..0x43; idx 4..3+N (the N audio tracks) = HIGH ranks
   `0x40−N+(idx−4)` ending at 0x3f; idx ≥4+N (inactive) = low `idx−(4+N)` (0x00,0x01…). **Logic reads these
   records IN STREAM ORDER as the track list, so after setting the ranks you must RE-SORT the records by `@0x12`
   ascending** (the template has them slot-ordered = rank-ordered only at 1 track). Ranks-without-reorder = no
   Tracks drawn. (Invisible to a `(tag,idx)`-keyed diff — all 68 share idx 0x080000; see 10.6.6.)
5. **Arrange track-area HEIGHT** — the larger `qeSM`(0x040000) (carries a name string `@0x34`) has a u16 at
   `(name_field_end + 0xa)` = **`0x3c × (N+1)`** (per-track row 0x3c=60, +1 master). Linear: N=1→0x78, 4→0x12c,
   8→0x21c, 16→0x3fc. **Too small caps the arrange at ~height/0x3c rows** even when all N channels/Tracks/ranks
   exist (a fixed 0x12c shows 4 fine but only 5 of 9).

Also kept consistent (display order/scroll, not the gate itself): `qSvE`(0x080000) ARRANGE-ORDER table — 64 rows
× 0x50 from rec-offset 0x38; ordinal = each row's first byte: row0=0x43; row k≥1 = `0x40−N+k` if k≤N else `k−N`.

### 10.6.5 Non-load-bearing / cosmetic (safe to skip or approximate)
- **qeSM `@0x116` recency ordinals** (~64 records, `[00 00 XX ff]`, XX≥0xc0 → the 0xff one becomes 0xc0, others
  +1): a most-recently-touched ranking Logic recomputes (`reindex=` toggles reproducing it).
- **karT(0x080000) `@0x3c/@0x44` hashes** — regenerated by Logic per save (NOT byte-reproducible; recomputed on
  load). **gnoS Table-3 timestamps**, **`@0x102`** UI "selected track", neighbour `ivnE @0x76` layout bumps, the
  `MneG` Drummer body content, the `qeSM`(0x040000) **name** string, and **WindowImage.jpg** — all cosmetic.
- **Track NAME**: the cloned channel name is a single-byte counter (`ivnE @0xca` = `'1'+n`), so synthesized track
  10 displays "Audio :" (`'9'+1`). Cosmetic — rename in Logic, or (future) resize the name field for multi-digit
  names.

### 10.6.6 Reference, validation & RE notes
- **API** (`projectdata.py`): `synthesize_audio_tracks(template, out, count, *, seed=None)` (file-level; also
  syncs `MetaData.plist` `NumberOfTracks` — a mismatch makes Logic reject the file); `activate_audio_track(pd)`
  (in-memory, composes with `set_tempo_map`/`set_meter_map`/`set_markers`). CLI: `projectdata.py synthtracks
  <template> <out> <count> [--seed N]`. Test: `test_synth.py`. Logic-validated at 4 / 9 / 13 tracks.
- **Scope**: adds EMPTY audio tracks. Audio/MIDI REGION content on a synthesized track needs REGION synthesis
  (cloning a `gRuA`/`lFuA` region cluster per track — §8 / §8.1); not yet built, so the region exporters remain
  template-bound for now.
- **Re-index scales with mixer size** (a per-slot ordinal touch on every pre-allocated slot): 4-channel→~22
  records, 64→~130, 1000→~2010 — size the template near your needs.
- **RE LESSON — diff POSITIONALLY when records share an idx.** Gate 4 (stream order) was a *pure reorder* of 68
  byte-identical records all sharing idx 0x080000; a `(tag,idx)`-keyed / multiset diff bucketed them as an
  unordered set and reported "byte-match", hiding it. A positional `records[i]` vs `records[i]` diff exposed it.
- **RE LESSON — bisect with known-good files.** Each gate was isolated by taking a Logic-made working file,
  reverting ONE record/field to the template state, and re-opening in Logic — the change that broke it is the
  gate. The same method confirmed which differences are cosmetic.
- (Donor `Media/` keeps dummy wavs + a stale embedded absolute path — both non-load-bearing; the exporter copies
  the user's wavs in and prunes orphans.)

### 10.6.7 Channel format — mono ↔ stereo (SOLVED + Logic-validated 2026-05-31)
The raw pre-allocated mixer strips are **mono**, but the synthesis FUNCTIONS now default to **stereo** (pass
`stereo=False` for mono). Switching a track to **stereo** is **three bytes in that track's `OCuA` channel
strip** — nothing else. RE'd from a 1-audio-track mono-vs-stereo Logic differential
(`fixtures/stereo test/mono.logicx` vs `stereo.logicx`): the whole project diff was 3 bytes in the one `OCuA`
strip (+ incidental UI noise — a track rename and a Song `@0x102` byte that is NOT load-bearing: mono files carry
both of its values). The 3 bytes are **fixed constants**, identical across all 426 mono strips (not per-channel):

| `OCuA` raw offset | mono | stereo | field |
|---|---|---|---|
| `0x72` | `d3` | `d7` | config word — **bit `0x04` = stereo** |
| `0x7a` | `00` | `01` | format flag |
| `0x9f` | `01` | `02` | **channel count (1 = mono, 2 = stereo)** |

**Finding the right strip:** map audio track *k* (1-based) → environment channel `KART_BASE_CHAN + (k-1)*0x40000`
(`0x580000, 0x5c0000, …`) → its `ivnE` (idx `@0x08`) → that ivnE's UUID `@0x1eb` == the `OCuA`'s UUID `@0xbd`.
(`_ocua_for_channel`.) The "active strip" flag `@0x3c` is NOT a clean filter — output/aux strips share it.

**GROUND TRUTH:** `set_track_stereo(mono_pd, 1, True)` produces an `OCuA` strip **byte-for-byte identical** to
Logic's own `stereo.logicx` strip — the strongest possible proof, asserted in `test_stereo.py`.

**API / CLI**: `set_track_stereo(pd, track, stereo=True)`; a `stereo=` option on `synthesize_audio_tracks` and
the combine `synthesize_track_region_bundle` — **AUTHORITATIVE** (every track is set explicitly), **default
`True`** (all stereo); accepts `False` (all mono), `True`, or an iterable of 1-based track numbers to make stereo
(rest mono). The low-level `activate_audio_track(stereo=False)` primitive stays mono-explicit. CLI: `--mono` (all
mono) or `--stereo-tracks N,M,…` on `synthtracks` / `synthtrackregions` (stereo is the default). Logic-validated
`fixtures/TEST_combine_stereo.logicx` (5 tracks, 2 & 4 stereo). Bit depth / file channel count are independent of
this (a mono *track* can host a stereo *file*; §8.1).

### 10.6.8 Track naming (SOLVED + Logic-validated 2026-05-31)
A synthesized track displays its **`ivnE` channel name** — a variable-length **`[u16 char-count @0xc2][ASCII @0xc4]
[pad to even]`** field (default `"Audio 1"`). The single byte the track-synth used to bump (`@0xca`) is just that
name's **last character**, which is why the default counter garbles past 9 (`'9'`→`':'`→`';'` → "Audio :",
"Audio ;"). The fix names the track AND cures the garble: **replace the whole name field** (RESIZE the record,
update payload size `@0x1c`) with an arbitrary string.

**Authority:** the displayed track name comes from the `ivnE` for synth tracks (their per-track `qeSM` is empty,
so it falls back to the channel name; proven by the garble being the `ivnE`'s `@0xca` byte). Logic-validated: a
10-track named combine showed Kick / Snare / … / **Perc** (track 10, no garble). (Renaming a track in Logic's
*arrange* instead writes a per-track `qeSM` name `@0x34` — a SEPARATE layer from the channel name; that's what the
stereo differential's "mono" rename touched, leaving `ivnE`/`OCuA` as "Audio 1". We set the channel name, which
is what an unnamed synth track shows.)

**⚠️ RESIZE GOTCHA:** the `ivnE` UUID at `@0x1eb` is only correct for the *default* name length; renaming shifts
it. The UUID actually sits at **name-field-end + `0x11f`** (`_ivne_uuid`), and naming is applied **LAST** in the
pipeline (after stereo, which reads the UUID via the `ivnE`→`OCuA` chain). Reads that must survive a rename use
the relative offset, not `0x1eb`.

**API / CLI**: `set_track_name(pd, track, name)`; a `names=` option on `synthesize_audio_tracks` and the combine
`synthesize_track_region_bundle` — `None` (keep "Audio N"), a dict `{track: name}`, or a list (tracks 1..len). CLI
`--names Kick,Snare,Vocal`. Logic-validated `fixtures/TEST_combine_named.logicx`; `test_naming.py` (27 assertions).

## 10.7 Audio region synthesis (SOLVED + Logic-validated 2026-05-31)
Place an ARBITRARY number of audio regions (e.g. beat slices) with **no per-count template** — the companion to
track synthesis (§10.6). Combined, they give "N audio tracks each with their regions".

**⭐ Key finding — Logic REGENERATES the gnoS object-registry + `OgnS` pool from the records on load.** §8.1
feared that going beyond a template's region count needed synthesizing the dense 5-table gnoS object-registry
(`0x1250–0x2b64`, front-insertion + renumber). It does NOT: a region cloned with **no** registry entry shows in
the Project Audio list, is selectable, and plays. Verified with **8 DISTINCT files across 4 tracks** (the
load-bearing case — the bin must list each file). So a region only needs its **records + placement event**.

**A region = a record cluster** (idx = `regionIndex × 0x40000`):
- `lFuA` (audio file ref): filename (UTF-16, `[u16 len]` @payload+0x08, RESIZE), EVAW format/frames @`EVAW+0x0c…`,
  byte-size @`EVAW-0x32` (= the wav's on-disk size, else "audio files changed in length"), relative path
  `"Audio Files"` @`EVAW-0x13e`. §8/§8.1.
- `gRuA` (region object): length @payload+0x16, display name @+0x4a (variable → RESIZE the record), 16-B UUID
  @record+0xca. Plain audio = 1 `gRuA`; an Apple-Loop file gets 2 (a bin "loop" region + the arrange region).
- An 80-B placement event in the arrange `qSvE` (idx 0x040000): `24 00 00 00`, pos@+0x04 = `34560 + tick`,
  track@+0x14 (1-based), link@+0x2c = `regionIndex × 4`, id@+0x10 = the track's slot, flag@+0x0c. §8.1.

**Procedure** (`ProjectData.synthesize_audio_regions(donor, regions)`): the **donor** is any session with the
desired TRACKS + at least one audio region (the clone prototype). For each requested region i: CLONE the donor's
region-0 record group (all `gRuA`+`lFuA` at id 0) to id `i×0x40000` with a fresh `gRuA` UUID; patch the file
(name/length/format/size) + the `lFuA` filename; emit an 80-B event (track/pos/link per spec). Drop the
per-region `MneG` mementos; leave `OgnS` as the donor's (Logic rebuilds it). **N is unbounded; multiple regions
may share a track (beat slices); same-file and distinct-file both work.** The donor supplies the track COUNT —
combine with §10.6 track synthesis for arbitrary tracks (follow-on; mind the §10 settling).

**API / CLI / test**: `synthesize_audio_region_bundle(donor, out, [(track, wav, tick)])` (reads each wav →
LGWV + format, copies Media, prunes orphans, writes MetaData) + CLI `synthregions <donor> <out> track:wav:tick …`;
`test_region_synth.py` (14 assertions, vs F18/F21/F19); Logic-validated `fixtures/TEST_synthregions.logicx`.

**RE LESSON**: a same-file clone test (2 regions of ONE file → 1 bin entry) does NOT prove distinct-file
integration; distinct files are the load-bearing case. Always test the distinct case.

## 10.8 The combine — N synth tracks each with their regions, one call (SOLVED + Logic-validated 2026-05-31)
Wire track synthesis (§10.6) + region synthesis (§10.7) into ONE call producing an arbitrary track count AND
arbitrary regions, from a **minimal template + a baked region prototype** — no per-layout donor. This is the
capstone: a beatmapping tool can now emit Audio 1…N each carrying their beat-mapped slices directly.

**The two pieces compose because region synthesis touches neither the mixer nor gnoS.** Track synthesis builds
the N-track mixer (unsettled, the big pre-allocated gnoS); region synthesis only adds `gRuA`/`lFuA` records +
placement events and Logic regenerates the registry/pool on load (§10.7). So: track-synthesize the base, then
run region synthesis on it.

**Two things had to be solved to graft regions onto a track-synth base** (vs. a region donor):
1. **No region-0 prototype** (a fresh track-synth base has zero regions). → `synthesize_audio_regions(donor,
   regions, *, prototype=...)` takes the `gRuA`/`lFuA` group **and** the 80-B event template from a SEPARATE
   `prototype` session (e.g. `F18`); region 0 is cloned too (not assumed present). No Media is taken from it.
2. **Empty arrange EvSq** (a track-synth base has no audio event to clone or replace). The arrange audio EvSq
   (idx `0x040000`) is just a **16-B sequence trailer** `f1 00 00 00 ff ff ff 3f 00…`. A POPULATED audio EvSq is
   `[80-B events…][same 16-B trailer]`. → graft by **prepending** the events before the trailer, reproducing
   that exact shape. The right EvSq = the one **following the largest `qeSM`@0x040000** (the arrange container —
   the same record the §10.6.4 height gate targets); helper `_arrange_audio_evsq`. (The base has TWO empty
   `qSvE`@0x040000 — a MIDI/global one and the arrange one; pick by the arrange-qeSM anchor, not by order.)

**Why track@0x14 = 1-based audio track just works:** synthesized channels come out **byte-identical to a real
"N from 64"** mixer (`0x580000, 0x5c0000, 0x600000, …`), and the synth arrange rows are ordered Audio 1…N, so
the placement event's `track@0x14` maps straight to the k-th audio track (no remap). `id@0x10` stays the
prototype's constant slot (`0x58`) for every region/track — proven non-load-bearing by the multi-track region
tests. Audio-track count = non-master `karT` (len 93) rows @0x040000 (gnoS `@0xf4` is unreliable on settled
files); the combine activates exactly `max(track in items) − current` slots.

**API / CLI / test**: `synthesize_track_region_bundle(track_template, prototype, out, [(track, wav, tick)], *,
seed=, drummer=)` (track-synthesizes to the needed count, region-synthesizes via `prototype=`, creates
`Media/Audio Files`, copies wavs + LGWV, sets MetaData NumberOfTracks/AudioFiles/SampleRate) + CLI
`synthtrackregions <track_template> <prototype> <out> track:wav:tick …`; `test_combine.py` (20 assertions);
Logic-validated `fixtures/TEST_combine.logicx` (5 tracks: 1 real + 4 synth, 6 distinct files incl. a beat-slice
pair on Audio 1). Template = a `1 from 64`-style pre-allocated session; prototype = `F18` (or any ≥1-region
session). Mind the §10 settling: synthesize on the FRESH template (a Logic re-save trims the pre-allocated mixer).

## 10.9 Mixed-template synthesis — instrument + audio TRACKS with MIDI + audio CONTENT, one call (SOLVED + Logic-validated 2026-06-01)
The capstone (task #40): from a **minimal mixed template** (1 instrument + 1 audio track — `fixtures/midi test/mixed_template.logicx`), synthesize **arbitrary M software-instrument + N audio tracks, named, each carrying content** (MIDI note regions on instruments, audio regions on audio) in **one call** — `synthesize_av_region_bundle`. The mixed template is "settled" (NOT a `1 from 64` pre-allocated mixer), so the FIRST track of each type is a HEAVY op (materializes that type's channel infrastructure), the rest LIGHT. **★ Same unlock as §10.7: Logic REGENERATES the `gnoS` registry from the records on load** (gnoS-swap test) → synthesis = clone records + bump minimal `gnoS` counters; no dense-registry decode. The deepest RE in the project; cracked via the Logic differential progression `mixed_template + {1,2,3,4} inst` / `+ 1 audio`.

### 10.9.1 Software-instrument (MIDI) track synthesis
Instrument channels carry heavy NSKeyedArchiver state (`UCuA` plists, idx 0x240000) that CANNOT be flag-flipped (audio→instrument byte-flip = HOLLOW strip — dead end). OCuA config word @0x70: audio=`0xabf7`, instrument=`0x29f5`.
- **HEAVY op (1st inst, `_heavy_activate_instrument`)**: clone the reference new-instrument `ivnE` (re-stamp the UUID @ name_end+0x11f) + add 2 `UCuA` + the `0x4000000` trio (`qeSM`+`karT`+`qSvE`) + grow the special 221→241 `OCuA` strip; prev-last islast→0, bus chans (0x4c/0x50/0x54) link76 += 0x42, stamp a free `0x29f5` strip with the new UUID, add arrange row, re-rank, grow MneG. The new-channel records are CONSTANT (always the same 1→2 transition) → cloned from `instrument_infrastructure(mixed_template + {1,2} inst)`.
- **LIGHT op (2nd+, `activate_instrument_track`)**: clone cur_max's instrument `ivnE` (re-stamp idx/idx2/link76/UUID/islast ONLY — do NOT bump the name-relative ordinals @0xca+, that overshoot HOLLOWS the strip), NO new UCuA/trio; same strip-stamp / re-rank / MneG / height edits.
- UCuA versioning: the shared instrument plists are v1 (2 total inst) or v2 (3+, stable). Re-rank `_relrank_instrument`: new slot → top TRACK rank, others −1, top-3 system rows (master+outputs) pinned, re-sort. Naming `_name_instruments`: 'Inst K' default (K = instrument-channel ordinal) or per `names`. **✅ Logic-validated** `synthesize_instrument_bundle`, `TEST_inst_synth3x.logicx`; `test_inst_synth.py`.

### 10.9.2 Audio track synthesis on a settled mixed base
Like the instrument heavy op (NOT the §10.6 pre-allocated light op) — the mixed base lacks free audio infrastructure, so each add materializes it.
- **HEAVY op (1st audio, `_heavy_activate_audio`)**: clone the reference new-audio `ivnE` + 2 `UCuA`@0x240000 (1957+867 B) + the `0x4000000` trio + grow the 221→241 strip (**BYTE-IDENTICAL to the instrument one** — grown once, shared); stamp a free 205-B audio strip (`_synth_next_strip`, cfg `0xabf7`), link76 churn, arrange row, audio re-rank, MneG, height.
- **LIGHT op (2nd+, `_light_activate_audio`)**: clone cur_max audio `ivnE`, NO new UCuA/trio; same strip-stamp / link76 / re-rank / MneG / height.
- Re-rank `_relrank_audio`: new slot → max rank among existing AUDIO arrange-tracks (excl. master); rows ranked ≤ that shift −1; higher rows (master/outputs/aux/**instruments**, which outrank audio) pinned.
- **link76 churn**: every mixer-band channel `0x480000 ≤ ch < new_idx` that ISN'T a real audio track (master 0x500000 DOES shift; existing audio tracks DON'T) gets `@0x76` (u16 LE) += 0x42. Reference: `audio_infrastructure(mixed_template + 1 audio)`. **✅ Logic-validated** `synthesize_audio_on_mixed_bundle`, `TEST_mixed_1audio.logicx`; `test_audio_mixed.py`.

### 10.9.3 The two heavy ops COMPOSE → the unified track call
The instrument + audio heavy ops compose cleanly (**✅ `TEST_mixed_inst_audio.logicx`**): the 221→241 strip is byte-identical (grown once; the 2nd op finds none), and each heavy add gets its own `0x4000000` trio. `synthesize_av_tracks(pd, instruments=M, audio=N, …)` = instruments first (heavy+light) then audio (heavy+light); each new channel takes cur_max + 0x40000. `synthesize_av_bundle` wraps it to a bundle. **✅ `TEST_av_bundle.logicx`** (2 inst + 2 audio); `test_av_bundle.py`.

### 10.9.4 ★ The arrange-container DECOY (cost TWO corruptions — REMEMBER)
A settled mixed base carries **TWO `qeSM`@0x040000**: a LARGER `'Untitled'` DECOY (height field ALWAYS 0) and the REAL arrange container (smaller; height = `0x3c*(rows+1)` = the visible-track gate §10.6.4, AND the EvSq host for placement events). Selecting by `max(len)` hits the DECOY → (a) clobbering its must-be-zero height CORRUPTS the file; (b) grafting placement events after it leaves placed regions INVISIBLE. **Always select via `_arrange_container`** = the `qeSM`@0x040000 whose height is a NONZERO multiple of 0x3c. (On the §10.6 `1 from 64` audio base the real container IS the largest, so `max(len)` worked there — the trap only bites the mixed base.) The "per-track counter @0x47" / "container grows per track" were RED HERRINGS — the container's post-name tail is constant; it only "grew" because the embedded project name grew, and @0x47 was a digit inside that name.

### 10.9.5 Content — audio regions + MIDI note regions, by ordinal
Both placement-event types (audio `0x24`, MIDI `0x20`) share the REAL arrange container's EvSq. **The event's track field @0x14 = the 1-based position of the track in the `karT`@0x040000 arrange-row STREAM order** (RE'd from `F23_av`: its audio events carry track=5,6,7 = the audio rows' stream positions), NOT the per-type ordinal — and a synth bundle's tracks INTERLEAVE (Inst1,Audio1,Inst2,…), so map each target (by 1-based type ordinal) → arrange stream position.
- **Audio regions**: `synthesize_audio_regions` (§10.7) unchanged; `audio_regions=[(audio_ordinal, wav, tick)]` mapped via `_audio_track_arrange_positions`.
- **MIDI note regions** `synthesize_midi_regions(pd, [(inst_ordinal, notes, tick, name)], prototype=)`: clone a **5-record region group** (`tSxT`+`lytS`+`qeSM`+`karT`+`qSvE`) from a MIDI-region session (`F23_av`) at a FREE HIGH cluster index (`0x1200000`+ — the settled base fills all low clusters 0x0–0x118; a settled base assigns next-free high anyway), re-stamp idx@0x08 + the qeSM's lone channel ref (NAME-RELATIVE: at name_end+0xca, = 0x106 for the "Inst 1"-length name; shifts with `_set_region_name`, value preserved), fill the note qSvE (`build_note_qsve_payload`), set length@0x78 + start@0x11c. The `0x20` event: clone `F23_av`'s (preserves constants @0x0c/@0x1c/@0x24/@0x30/@0x34) + set @0x04=34560+tick, @0x10=channel slot (chan>>16), @0x14=arrange position, @0x20=region cluster, @0x30 += (tick//3840)*0x100; graft before the EvSq body. The prototype region is found VIA the first 0x20 event (distinguishes a MIDI region from audio's 0x24).
- **THE UNIFIED CALL** `synthesize_av_region_bundle(template, out, *, instruments=M, audio=N, midi_regions=, audio_regions=, prototype_bundle=, midi_prototype_bundle=, inst_ref1/2_bundle=, audio_ref_bundle=, inst_names=, audio_names=, stereo=, seed=)` — M inst + N audio tracks + MIDI notes on instruments + audio regions on audio, ONE call. **✅ Logic-validated** `TEST_av_full.logicx` (2 inst w/ Lead/Bass/Stab notes + 2 audio w/ 047/048/049 regions). `test_av_bundle.py` (36 assertions). Reference differentials: `fixtures/midi test/mixed_template{,+ 1 inst,+ 2 inst,+ 1 audio}`; MIDI-region prototype `templates/F23_av.logicx`; audio-region prototype any ≥1-region session (`F21`/`F18`).

## 11. Fixture map (`fixtures/`, all Logic 12.0.1, base = `F0_baseline` unless noted)
Each isolates one change for differential analysis; `main` vs its own `Project File Backups/00/ProjectData`
isolates the single edit cleanly.
- **F0** baseline (1 inst track, 120 BPM, 4/4, compact gnoS 10792).
- **F1** tempo 137.5 · **F2** tempo map (+90@bar5) · **F3** marker "ZZMARKZZ"@bar3.
- **F4** MIDI region@bar1 · **F5** =F4 region moved to bar2 (isolated position) · **F7** track rename · **F8** 2nd track.
- **F9_meter** 4/4+3/4@bar2 · **F9_tempometer** +7/8@bar3 · **F10_sigs** 5/8@bar2,9/16@bar4,11/2@bar6 (distinct).
- **F11_markers** 3 markers@bars2/4/6 · **F12_markers** ="F0+3 markers" (settled lineage).
- **F13_settled_or_not** = F0 + marker added & removed → **settled base w/ empty marker track**.
- **F14_audio_base** = settled base w/ empty audio track · **F15_audio_bar5** = F14 + audio region@bar5.
- **F16_sr48** = F0 saved at 48 kHz (isolates the SR field) · **F17_base** = settled base w/ marker + audio
  tracks (unified base) · **F18_audio** = F17 + audio region (unified audio template).

---

## 12. Writers / CLIs (in `projectdata.py`)
- `ProjectData.parse(data)` / `.serialize()` — lossless round-trip (validated 19/19 fixtures).
- `set_tempo_map`, `set_meter_map`, `set_markers`, `with_audio_region`, `set_project_sample_rate`.
- DECODERS (inverses): `get_meter_map() -> [(tick,num,den)]`, `get_tempo_map() -> [(tick,bpm)]`,
  low-level `decode_sig_events` / `decode_tempo_events`. A parsed project → its maps; `test_decoders.py`.
- `TimeMap(tempo_map, meter_map, ppq)` / `.from_midimap(mm)` — meter/tempo-aware position helpers
  (bar/beat ↔ tick ↔ seconds); see the POSITION UNITS block below. Tested in `test_timemap.py`.
- `export <base.logicx> <file.mid> <out.logicx>` — tempo + meter + markers from a MIDI (base needs a marker track).
- `audio <base> <template> <user.wav> <out> [tick]` — place a wav (position/length/name/rate; auto SR-match).
- `export_all <base> <audio_template> <midi> <wav> <out> [tick]` — UNIFIED one-call export: audio
  region (F17→F18 delta-replay) + tempo + meter + markers + project-SR-match + MetaData + copy wav.
  Validated structurally (250 tempo + meter + 13 markers + audio + 48k, round-trips); base=F17, template=F18.
- `place_audio_regions(base, template, regions)` / `add_audio_regions` / CLI
  `multiaudio <base> <template> <out> track:wav:tick …` — places regions by REUSING the template's region
  records (identity preserved → registry/OgnS stay valid → Project Audio list + selection work; see §8.1
  CORRECTION). **`len(regions)` must == the template's region count K** (use a K-region template); each
  region freely sets track/position/file/length, **multiple regions may share a track**, and **real on-disk
  filenames** are used (lFuA filename RESIZED — §8.1). Region i reuses template region i, placed by a rebuilt
  event (link i*4). gnoS/OgnS untouched. (The earlier clone-prototype version made regions PLAY but vanish
  from the pool + become unselectable — reverted.) The older one-region-per-track `with_audio_regions`
  remains, Logic-validated (`TEST_multiaudio.logicx`).
- `export_all_multi(base, audio_template, midi, audio_items=[(track,wav,tick)], out)` + CLI
  `exportallmulti <base> <template> <midi> <out> track:wav:tick …` — UNIFIED MULTI-TRACK one-call export:
  multi-audio (F19→F21 delta-replay) + tempo + meter + markers (markers synthesized, §6) + project-SR-match
  + MetaData + copy/prune wavs. **✅ Logic-validated** (`fixtures/TEST_exportall_multi.logicx`, 2026-05-29:
  2 tempo + 4/4→3/4 + 3 markers + 3 audio tracks all correct together — incl. synthesized markers on the
  region-only F19/F21 base). base=F19, template=F21.
- `synthesize_audio_tracks(template, out, count, *, seed=None, stereo=True, names=None)` + `activate_audio_track(pd)`
  + CLI `synthtracks <template> <out> <count> [--seed N] [--mono|--stereo-tracks N,M] [--names A,B,C]` — **AUDIO
  TRACK SYNTHESIS** (§10.6): activate `count` extra pre-allocated mixer slots into working (EMPTY) audio tracks.
  `template` = a session of N audio tracks with all but one deleted (keeps the N-channel mixer → N−1 free slots).
  Syncs `MetaData.plist` NumberOfTracks; composes with the map writers. **✅ Logic-validated** at 4 / 9 / 13 tracks
  (`test_synth.py`). Adds tracks only. **`stereo=`** sets channel format per track (§10.6.7; **default stereo**,
  `False` = mono, or a list of 1-based track #s — authoritative, `set_track_stereo`). **`names=`** sets display
  names (§10.6.8; dict/list, cures the >9 garble — `set_track_name`).
- `synthesize_audio_region_bundle(donor, out, [(track, wav, tick)])` + `synthesize_audio_regions(pd, regions)` +
  CLI `synthregions <donor> <out> track:wav:tick …` — **AUDIO REGION SYNTHESIS** (§10.7): clone a donor's region
  prototype into an ARBITRARY number of audio regions (beat slices); `donor` = any session with the tracks + ≥1
  region. Logic regenerates the registry/pool from the records. Unbounded count, multiple per track, distinct
  files. **✅ Logic-validated** (`fixtures/TEST_synthregions.logicx`, 8 distinct files / 4 tracks; `test_region_synth.py`).
- `synthesize_track_region_bundle(track_template, prototype, out, [(track, wav, tick)], *, seed=, stereo=True,
  names=None)` + `synthesize_audio_regions(pd, regions, *, prototype=…)` + CLI `synthtrackregions <track_template>
  <prototype> <out> track:wav:tick … [--mono|--stereo-tracks N,M] [--names A,B,C]` — **THE COMBINE** (§10.8): track
  synthesis (§10.6) + region synthesis (§10.7) in one call → arbitrary N tracks each with their regions, no
  per-layout donor. `track_template` = a `1 from 64`-style pre-allocated session; `prototype` = any session with
  ≥1 region (e.g. F18) supplying the clone group + event template (the `prototype=` form grafts regions into a
  track-synth base's EMPTY arrange EvSq). Unbounded tracks AND regions, multiple per track, distinct files.
  **`stereo=`** sets per-track channel format (§10.6.7; default stereo); **`names=`** sets per-track display names
  (§10.6.8; dict/list). **✅ Logic-validated** (`fixtures/TEST_combine.logicx`, 5 tracks / 6 distinct files incl. a
  beat-slice pair; `…_stereo.logicx`, 2 stereo + 3 mono; `…_named.logicx`, 10 named tracks; `test_combine.py` 20 +
  `test_stereo.py` 21 + `test_naming.py` 27 assertions).
- **MIXED-TEMPLATE SYNTHESIS (§10.9) — instrument + audio tracks WITH content, from a minimal mixed template:**
  - `synthesize_instrument_bundle(template, out, count, *, ref1_bundle, ref2_bundle, names=, …)` — M software-
    instrument tracks (heavy+light). `synthesize_audio_on_mixed_bundle(template, out, *, ref_bundle, …)` — +1 audio
    track on a mixed base (heavy op).
  - `synthesize_av_bundle(template, out, *, instruments=M, audio=N, inst_ref1/2_bundle=, audio_ref_bundle=,
    inst_names=, audio_names=, stereo=, seed=)` + the in-place `synthesize_av_tracks(pd, …)` — M instrument + N
    audio tracks, named, one call.
  - `synthesize_av_region_bundle(…, midi_regions=[(inst_ord, notes, tick, name)], audio_regions=[(audio_ord, wav,
    tick)], prototype_bundle=, midi_prototype_bundle=, …)` — **THE UNIFIED CONTENT CALL**: M inst + N audio tracks +
    MIDI notes on instruments + audio regions on audio, one call. Lower: `synthesize_midi_regions(pd, specs,
    prototype=)`. **✅ Logic-validated** (`TEST_av_full.logicx` = 2 inst w/ notes + 2 audio w/ regions;
    `TEST_inst_synth3x` / `TEST_mixed_1audio` / `TEST_mixed_inst_audio` / `TEST_av_bundle`; `test_inst_synth.py` 40 +
    `test_audio_mixed.py` 15 + `test_av_bundle.py` 36 assertions). Reference differentials: `fixtures/midi test/`.

**POSITION UNITS — region/marker `tick` is an ABSOLUTE 960-PPQ tick, NOT a bar number (meter-independent).**
Under a meter map, bar N does NOT start at `(N-1)*3840` — each bar's length depends on its signature
(4/4 = 3840 ticks, 3/4 = 2880, …). Confirmed in the Logic test: regions passed `tick = (bar-1)*3840`
(4/4 assumption) landed at bar3-beat2 / bar6 once a 3/4 change existed. So a caller must convert musical
positions through the meter map (accumulate per-bar tick lengths) — a 4/4 shortcut only holds in pure 4/4.

**✅ DONE — `TimeMap` class (`projectdata.py`, 2026-05-30) does this conversion.** Construct from the SAME
lists you pass to `set_meter_map`/`set_tempo_map` (`TimeMap(tempo_map=[(tick,bpm)], meter_map=[(tick,num,den)],
ppq=960)`, or `TimeMap.from_midimap(mm)`), then:
- `bar_to_tick(bar)` / `bar_beat_to_tick(bar, beat=1.0)` — meter-aware bar/beat → 960-PPQ tick (bar1 beat1 = 0;
  one beat = one denominator note, so 6/8 has 6 eighth-beats/bar; floats allowed for sub-beat). Bar-downbeat
  placement is exact + convention-independent.
- `tick_to_bar_beat(tick)` → `(bar:int, beat:float)` (inverse).
- `seconds_to_tick(s)` / `tick_to_seconds(tick)` — tempo-aware wall-clock ↔ tick (honors the tempo curve;
  same cumulative-seconds math as `set_tempo_map`'s altpos).
- composites `bar_beat_to_seconds` / `seconds_to_bar_beat`.
All ticks are ints, bar-1-relative (add `TEMPO_ORIGIN`/`AUDIO_REGION_ORIGIN` when emitting — the writers
already do). Pure-Python, no Logic round-trip; **41 assertions in `test_timemap.py`** cover constant 4/4,
4/4→3/4 meter change, 6/8, tempo change, PPQ rescale, `from_midimap`, clamping, and round-trips.

Validated end-to-end in Logic: container/round-trip, tempo, tempo+meter, tempo+meter+markers,
audio region placement, arbitrary-file audio (name/length/rate), **multi-track audio (one region per track)**,
and 48 kHz session rate.

**(All of the above — unified export, real filenames, MIDI note regions, arbitrary counts — are now DONE
and Logic-validated; see §8.1, §10.6–§10.9, §13.)**

## 13. The beatmap pipeline + the SELF-CONTAINED library (SOLVED + Logic-validated 2026-06-01)

### 13.1 `export_beatmap` — a beatmap MIDI + audio files → one `.logicx`
`export_beatmap(midi_path, audio_files, out, *, head_sync=None, names=None, stereo=True, sample_rate=None)`
+ CLI `exportbeatmap <midi> <out> file1 file2 … [--head-sync TICK] [--sample-rate 44100|48000] [--mono] [--names a,b,c]`.
The product entry point: reads tempo/meter/markers + the head-sync from the MIDI, normalizes each audio file,
synthesizes one audio track per file (each clip at the head-sync, named after the file), applies the maps, packs
self-contained. Built on the §10.8 combine + the map writers.
- **Audio input = ANY CoreAudio format** (wav/mp3/aif/m4a/…). `_normalize_audio` → `afconvert -f WAVE -d
  LEI16@<rate> -c 2` → `<rate>`/stereo/16-bit WAV; a WAV already in that exact format is copied verbatim.
- **Sample rate** = `sample_rate` (None ⇒ `_probe_sample_rate` matches the source via `wave`/`afinfo`; 44100 or
  48000 both Logic-validated). **48 kHz needs NO new constants** — the EVAW format-magic (`@+0x04/@+0x08`) +
  the LGWV checksum are COSMETIC for the Project Audio bin; the load-bearing EVAW fields are rate/channels/bits/
  frames (always written from the WAV) + the lFuA file-size match + relative path (§8.1). (`_EVAW_FMT_FIELDS`/
  `_LGWV_FMT_CHECKSUM` are still keyed only by 44100/2/16 & /24, but unknown formats fall back fine.)
- **Head-sync (MIDI transport).** `midimap` parses System Common/Real-Time messages (the `b>=0xF1` branch):
  **`0xFA` (Start) = the audio start position**, **`0xFC` (Stop) = the tail**. `mm.head_sync_tick(ppq)` (0xFA →
  head-sync, falls back to the 1st note-on) / `mm.audio_span(ppq)` → (start, stop). `head_sync=None` auto-reads
  the 0xFA tick. (`tick` is an ABSOLUTE 960-PPQ position — use `TimeMap.bar_beat_to_tick` for musical positions.)

### 13.2 ★ The MINIMAL bundle file set (Logic-validated)
A `.logicx` Logic opens needs only **four things**:
```
out.logicx/Alternatives/000/ProjectData            (the session — §2+)
out.logicx/Alternatives/000/MetaData.plist         (NumberOfTracks/AudioFiles/SampleRate/BPM/Signature…)
out.logicx/Resources/ProjectInformation.plist      (small, mostly constant)
out.logicx/Media/Audio Files/*.wav                 (the audio)
```
**`WindowImage.jpg` (a 154 KB thumbnail) and `DisplayState.plist`/`DisplayStateArchive` are NOT needed** —
markers, MIDI tracks, audio regions all show without them (validated `TEST_minimal_markers.logicx`). The
assembler `_assemble_bundle(base_files, out, pd_bytes, *, wav_assign=, rates=, added_tracks=)` writes exactly
this set (no `copytree`) — outputs are ~170 KB leaner than a donor copy and carry no donor cruft.

### 13.3 Self-contained runtime — embedded donor SEEDS (no loose `.logicx` at runtime)
The importable **`logicx/` package** (`projectdata.py` + `midimap.py` + `data/`, ~62 KB) generates sessions with
NO donor bundles shipped (pip-installable; `pyproject.toml` + `README.md` at the repo root). `logicx/data/`:
- **`audio_base.seed`** (31 KB) / **`mixed_base.seed`** (27 KB) — a gzipped pack of a donor bundle's *files*
  (ProjectData + the small plists, minus WindowImage). The bases the synthesizers mutate + the assembler reuses.
- **`infra.json.gz`** (3.8 KB) — **pre-extracted constant records** (JSON+base64, with a `_provenance` block):
  `instrument_infra`, `audio_infra`, the MIDI-region prototype, the audio-region prototype. This is what lets us
  ship NONE of the 5 reference donors (the `mixed +1/+2 inst`, `+1 audio`, F23, F21 sessions) — only the few KB
  of records the extractors pull.

Loader: `_seed_files` (lru-cached `{path:bytes}`), `_seed_base_pd` (FRESH parse — callers mutate), `_baked_infra`
(lru-cached, `_infra_dec`). `_resolve_base(path_or_None, seed_name)` → `(ProjectData, base_files)` from a `.logicx`
PATH or the embedded seed when None. **Every bundle exporter defaults to the embedded data when its donor params
are None; pass a path to override** (`export_beatmap`, `synthesize_av_region_bundle`, `synthesize_instrument_bundle`,
`synthesize_audio_on_mixed_bundle`, `synthesize_track_region_bundle`). `synthesize_audio_regions(proto_group=,
proto_event=)` + `synthesize_midi_regions(prototype=<dict>)` take the baked prototypes directly.

### 13.4 ★ Regenerating the baked data (maintainability)
`logicx/data/` is a GENERATED ARTIFACT — never hand-edited. **`bake_seeds.py`** derives every `logicx/data/` file from the donor
fixtures and self-verifies the round-trips; **`DONORS.md`** is the manifest (each donor → the click-by-click Logic
recipe to remake it → what's extracted → which `logicx/data/` file). The fixtures in `fixtures/`/`templates/` stay = the
SOURCE OF TRUTH (also the test suite's). To update a donor (e.g. a new Logic version): remake the `.logicx` per
DONORS.md, replace the fixture, run `python3.12 bake_seeds.py`. `test_seeds.py` proves the loader reproduces the
fixtures byte-for-byte, embedded builds are minimal + self-contained, and the override path matches.
