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

**Production-corpus expansion (§14–§36).** Beyond the differential fixtures above, the format was
characterized against a **1,294-file corpus of real Logic sessions** (12 root versions, `ae06`→`cf09`).
This adds the 36-byte record-header census (§2.1) and **all 31 record types** (§14–§36), plus a
read/write library layer: `logicx.inspect` (14 decoders + CLI `python3.12 -m logicx.inspect <session>`)
and `logicx.edit` (round-trip-safe mutators). The whole corpus **round-trips 1293/1293 byte-for-byte**
— the container/record model is losslessly reimplemented across every version.

**Record tag → section index:**
`gnoS` Song root §21 · `karT` track rows §18 · `qeSM`/`qSvE` sequences §3, §20, §36 · `gRuA` audio
region §8, §17, §35.1 · `lFuA` audio-file ref §8, §8.6 · `MroC` CoreMIDI §14 · `ivnE` Environment §19 ·
`OCuA` mixer strip §15, §35.3 · `nCuA` audio channel §25 · `UCuA` plugin insert §16, §35.2 · `OgnS`
project pool §22 · `MneG` Drummer / Session-Player §23 · `vEuA` global params §24 · `tSxT`/`lytS` score
boilerplate §2 · `qSxT` marker RTF §6 · `tSnI` named set §29 · `ryaL` Environment layers §26 · `tScS`
score set §28 · `rpyH` Hyper sets §27 · `ediV` Video §30, §37 · `snrT` Transform §33 · `SdnU`/`MdnU` Undo
(legacy) §32 · `rteM`/`ddAG`/`dlFA`/`pilC`/`braC`/`dirG` rare singletons §34 · sub-object class tags §31.

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

### 2.1 The 36-byte record header — field census (verified on 373 real production sessions)
Every record's `raw[0x00:0x24]` is a fixed 36-byte header. Verified across **373 projects**
(106,245 records parsed byte-clean, all 10 root-version codes; adversarial cross-corpus check):

| off | sz | field | meaning |
|-----|----|-------|---------|
| 0x00 | 4 | tag | reversed FourCC (ASCII) |
| 0x04 | 2 | schemaVersion | per-**tag** record-schema number; tracks the Logic **app generation**, NOT the root-version hex linearly (`eb06` & `d007` both give OCuA=2/karT=4/ivnE=5/gnoS=3; `d606` differs: OCuA=1/karT=3/ivnE=3). Constant per tag within a file. |
| 0x06 | 2 | classId | stable per-tag **globally** (never multi-valued within a file) — **EXCEPT `qeSM`/`qSvE`**, where it is a **sequence-role discriminator** (table below). |
| 0x08 | 4 | idx | object index; **low 16 bits always 0** (only `gnoS`=`0xFFFFFFFF` excepted). Per-**track** records (`karT`, `nCuA`, each track's own `OCuA`) = `trackIndex<<18` (a multiple of `0x40000`). The `UCuA` + `OCuA` channel-strip **pool** all share `0x240000`. |
| 0x0c | 4 | ordinal | on `OCuA`/`UCuA` pool records = `ordinal<<16`, ordinals **contiguous 0..N−1**; on `gnoS`/`vEuA` = `0xFFFF` sentinel. |
| 0x10 | 2 | link0 | `0` on `OCuA`/`UCuA`/`gRuA`/`qSvE`, else `0xFFFF`. |
| 0x12 | 2 | link1 | on `UCuA` = a small-int sub-kind. |
| 0x14 | 2 | link2 | on `karT` = `0x7FFF` or `0x0000`. |
| 0x16 | 2 | — | **`0x0002` universal** (94089/94089). |
| 0x18 | 2 | — | `0` (universal high-half). |
| 0x1a | 1 | headerForm | **FILE-GLOBAL version constant** (⚠️ corrects an earlier guess that it was a per-tag selector): **exactly `cd09`/`ce09`/`cf09` → `2`; every other version → `1`** — incl. `*06`, `c409`, and (verified on fresh sessions) the other 09-family codes `c609`/`cb09`/`d007`, so it is NOT a blanket "09-family" rule. Every record in a file shares one value. |
| 0x1c | 4 | payloadSize | the walk field: `record total = 0x24 + payloadSize`. |
| 0x20 | 4 | — | `0` universal. |

**`qeSM`/`qSvE` sequence-role @0x06** (the one tag-pair whose classId slot encodes a role, not a class):

| role | payload family |
|------|----------------|
| 3 | tempo track (payload starts `60 00 00 00`) |
| 1 | signature track (`30 00 00 00`) |
| 0x0e / 0x19 | empty sequence (`f1 00 00 00`) |
| 0x16 | marker track |
| 0x17 | note events |

*Provenance: the "characterize the production corpus" RE workflow (373 projects byte-clean, adversarially
verified). Two earlier guesses were refuted — `0x1a` is file-global not per-tag; the `0x0c==0xFFFF`
records are `gnoS`+`vEuA`, not `ivnE`/`karT`/`lFuA`.*

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
  **CORRECTION (2026-10-29, §8.9):** the body is `[u32 frameCount][u32 Mac-epoch (1904) timestamp][int8 min,
  int8 max per 256-frame bin]` — two signed BYTES per bin, each the bin's minimum and maximum across all
  channels (the length `8 + 2·ceil(frames/256)` is unchanged). The second word is a time, not a checksum:
  stems of one format in one project carry values minutes apart (F20's reads 2026, F15's 2017).
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
  **CORRECTION (2026-10-29, §8.9):** EVAW+0x08 is not a format constant but the byte offset of the file's
  first sample — 0x400 in F20's 24-bit WAVs because their data starts at byte 1024, 0x1000 in F15's (data at
  4096), 0x2C in `ctl_wav`'s 44-byte-header WAV. Logic reads the file's own header: projects carrying the table's
  value over data elsewhere and projects carrying the true offset both open with every region in the bin. So
  #3 is not load-bearing for +0x08, and the true offset is what Logic itself writes.
- **`lFuA` audio-format = the `"EVAW"` (WAVE, reversed) descriptor — patch RELATIVE to it (CORRECTION).**
  Its ABSOLUTE offset **shifts with the UTF-16 filename length**, so the old fixed `+0x1f8/+0x200/+0x206`
  was wrong — it only aligned for the 13-char `ZZAUDIOZZ.wav` (EVAW@+0x1ec); a 7-char `047.wav` puts EVAW
  @+0x1e0, a 6-char `02.wav` @+0x1de. **Always locate `b"EVAW"`** then patch: **frames @EVAW+0x0c (u32),
  sample-rate @EVAW+0x14 (u32), channels @EVAW+0x18 (u16), bits @EVAW+0x1a (u16)** (EVAW+0x08 = the byte
  offset of the file's first sample, §8.9 — not the constant 0x400 first read here).
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
  +0x0a  u8   fine        low-order (sub-integer) velocity byte; 0 = exact integer velocity.
                          Round-trip-preserved exactly (`_enc_note_event(fine=…)` / `decode_note_events`);
                          the precise sub-velocity mapping is cosmetic and not needed to write notes.
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
  (an overture's bass/brass/drums/wws, 94/343/333/236 notes, 48 bars each) imported in one call —
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

**The `ovvw` chunk (measured 2026-10-29):** body `[u32 BE 1][u32 BE 256]`, then per 256-frame bin the
minimum and maximum as big-endian 16-bit values whose low byte is always 0 — `LGWV`'s signed-byte peaks
shifted up 8. All 690 bins of `ctl_caf`'s `ovvw` equal `ctl_wav`'s `LGWV` bins, and no 24-bit ALAC file in a
1,309-record corpus has a non-zero low byte. Length `8 + 4·ceil(frames/256)`, mono or stereo. A writer that
adds it itself spares Logic the overview on first open. Change #5 is the WAV's first-sample offset (§8.9:
`ctl_wav` has a 44-byte header, so 0x2C) becoming 0, since ALAC has no fixed offset.

**Known gap in `convert_bundle_to_alac`:** it leaves `MetaData.plist`'s `AudioFiles` naming the `.wav` files
it replaced; Logic's own `ctl_caf` lists `Audio Files/control.caf`. Logic opens the bundle either way.

Implemented in **`logicx/alac.py`** (`wav_lfua_to_caf` + `convert_bundle_to_alac`); exposed as
`export_beatmap(..., lossless=True)` and CLI `exportbeatmap … --alac`. Tests: `test_alac.py`
(byte-exact vs the controls). Donor recipe: `DONORS.md` → "ALAC control pair".

## 8.9 Audio files by container — WAV, AIFF, CAF (measured + Logic-validated 2026-10-29)
Measured on every `.logicx` on Jon's Mac — 2,824 bundles, 1,108 with audio, 77,262 `lFuA` records of a
known container and codec, saved by Logic 10.0 to 11.2.2 — reading each record's file where it still
exists. Offsets are from the descriptor's container tag at `d`: `EVAW` (WAVE), `FFIA` (AIFF and AIFC alike)
or `ffac` (CAF). **Logic-validated:** projects written with every field below — WAV copied and encoded at 16
and 32-bit float, AIFF at 24 and AIFC at 32-bit float, ALAC at 24 and 16, mono and stereo, one resampled to
44.1 kHz — open in Logic with every file in the Project Audio bin.

| field | offset | what Logic writes |
|---|---|---|
| container tag | `d+0x00` | `EVAW`, `FFIA` or `ffac`; float AIFC keeps `FFIA` |
| first sample's offset | `d+0x08` (u32) | the byte offset of the file's first sample, on all 40,037 records checked against their files: 39,968 AIFF (`SSND` body + 8 + its offset field), 61 float WAV (`data` body), 8 PCM CAF (`data` body + 4, past the edit count). 0 for ALAC (1,309 of 1,309). |
| codec tag | `d−0x142` (4 B) | 0 for integer PCM (WAV, AIFF); u32 **3** for 32-bit float WAV, the WAVE format tag (108 of 108); `23lf` (`fl32`) for float AIFC; `PMOC` for ALAC; `mcpl` (`lpcm`) for PCM in a CAF |
| type flags | `d−0x1c3` (u8) | bit 0x10 marks compression: set on 1,302 of 1,309 ALAC records and on no PCM record (PCM CAFs carry 0x00 or 0x01 like WAV and AIFF) |
| float byte | `d−0x3d` (u8) | 2 on every float record (114 of 114); 0 on 77,064 of the 77,148 integer and ALAC records (1 on 83 24-bit ones) |
| channel byte | `d−0x38` (u8) | the channel count: 1 on 56,081 of 56,100 mono records, 2 on all 21,126 stereo ones (`d−0x37` is 0 or 0x3C) |
| size | `d−0x32` (u32) | the file's on-disk size, overview chunk included, for every PCM container (AIFF 38,801 of 39,962; float WAV 44 of 61; PCM CAF 7 of 8); the DECODED size `frames×channels×bits/8` for ALAC (1,309 of 1,309; 24-bit counts 3 bytes) |

**Overview chunks, one per container.** WAV and AIFF carry `LGWV`, body `[u32 frames][u32 Mac-epoch
timestamp][int8 min, int8 max per 256-frame bin]`; in AIFF the two header words are big-endian like every
AIFF field (frames equal `COMM`'s), and the `FORM` size covers the chunk. CAF carries `ovvw` (§8.6). The
peaks follow no single rule exactly on real music: an import overview fits truncation toward zero (96.5% of
`ctl_wav`'s bins), Logic's recorded takes fit floor better (90–98%), float files neither (≤54%). They only
draw the waveform; truncation, floats scaled by 128, reproduces an import closely.

**What the writer here leaves at the template's.** `projectdata.py` sets +0x08 from a two-entry table
(`44100/2/16` → 0x2C, `44100/2/24` → 0x400) and otherwise keeps the template's, and keeps the template's
channel byte (2) for mono files: a 24-bit stem whose data starts at byte 750 is recorded at 1024, a mono file
as stereo. Logic tolerates both (it reads the file's own header), but the values above are what it writes.
Logic's own fixtures agree: F15 (16-bit, data at 4096) carries 0x1000, F20 (24-bit, data at 1024) 0x400,
`ctl_wav` (16-bit, 44-byte header) 0x2C; the library-written `TEST_exportall_multi` carries 0x400 over data at 44.

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

**Corpus check (2026-10-29):** all 2,824 projects on Jon's Mac are 44.1 or 48 kHz, so the u16 rule (rate +
15,660) is unconfirmed beyond them and cannot hold 88,200 or 96,000; a Logic-saved empty project at each rate
would settle it. The u16s match the rate in every one of them. The byte at +0xDF is not a rate: it takes 14
values at 44.1 kHz (0, 3, 4, 2, 0x13, …) and 0, 3, 4 or 0x16 at 48 kHz. Patching it is harmless; the u16s
carry the rate.

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

> **CORRECTION (2026-08-08): `@0x82`==`T` only holds for T <= 31.** Logic labels just the FIRST 31 free strips
> with their position; the rest carry an `0xFF` "unassigned" sentinel. Measured on `1 from 64`: the 64 free
> strips run `@0x2a` (position) 1..63, while `@0x82` is 1..31 once each and then `0xFF` x32 — **identical on
> `1 from 1000`**, so it is how Logic writes the pool, not a function of its size. Matching `@0x82` exactly
> therefore returns nothing from track 32 on, and the callers skip the link silently, leaving the channel with
> NO strip: the track still appears in the arrange but has no fader, pan, mute or record button (confirmed in
> Logic 12.2). `_synth_next_strip` now tries the exact match, then an `0xFF` strip, then any free strip.

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
- **Head-sync (MIDI marker).** `midimap` reads a **Control Change #119 on channel 16**: **value 127 = the audio
  start (head)**, **value 0 = the tail**. (Replaces the System Real-Time `0xFA`/`0xFC` it used to read — those
  break strict external SMF parsers; CC#119 is undefined in the MIDI spec, so it's a safe custom marker, and a
  normal channel message every parser handles.) `mm.head_sync_tick(ppq)` (the head CC → head-sync, falls back to
  the 1st note-on) / `mm.audio_span(ppq)` → (start, stop). `head_sync=None` auto-reads the head CC. (`tick` is an
  ABSOLUTE 960-PPQ position — use `TimeMap.bar_beat_to_tick` for musical positions.)

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

---

## 14. CoreMIDI endpoint table (`MroC`) — verified on 427 real production sessions
Every project has **exactly 2 `MroC` records**: the cached CoreMIDI endpoint tables, one for MIDI
**inputs** (`idx@0x08 = 0xE80000`) and one for **outputs** (`0xEC0000`, stride `0x40000`). Census:
854 records / 427 files / 5968 slots — all parse byte-clean. It is the session's snapshot of the
machine's MIDI ports (a subsystem the reference repos never decoded).

**Header** (beyond §2.1): `@0x04` schema/class; **`@0x18` = a per-file endpoint-cache generation
dword ∈ {`0x10000`, `0x20000`}** (identical for both records in a file — it is NOT spare);
`@0x0c`/`@0x0e`/`@0x16`/`@0x20` constant.

**Payload** (`raw[0x24:]`) = a 6-byte prefix + `count` × **100-byte slots**:
```
payload+0x00  6B    prefix — slot count is authoritative at record +0x26; a +0x24 "cached size"
                    dword is either == payload_size or 0.
then count × 100-byte slot:
  slot+0x00   u32   UniqueID       (CoreMIDI kMIDIPropertyUniqueID)
  slot+0x04   64B   endpoint name  (ASCII/UTF-8, NUL-padded; e.g. "Session 1", "MT4 Port 4")
  slot+0x44   32B   device name    (NUL-padded; ≤24 chars seen, e.g. "KOMPLETE KONTROL S61 MK2")
```
`payload_size = 6 + count*100`, and `record total = 0x24 + payload_size` — exact on all 854 records.
No per-slot / trailing tail; the payload ends after the last slot.

**UniqueID stability:** stable per (direction, name) for **hardware** endpoints across a song's
alternatives (`USB MIDI Interface` OUT = `0xbf368a15` in all 9 alternatives of session E; `Session 1`
IN `0xaf91a0d9` / OUT `0x4b0bb785`). **Plugin virtual ports are NOT stable** — `Vienna Instruments
MIDI`, `Superior Drummer 3` take a fresh UID almost every save; don't key cross-file linkage on a
virtual-port UID.

*Provenance: the production-corpus RE workflow — all 854 `MroC` records verified; the byte layout is solid
for read/write. Cross-alternative claims lean on the 2 corpus songs with ≥3 alternatives.*

---

## 15. Mixer channel strips (`OCuA`) — verified on the full production corpus (1293/1294 files)

An `OCuA` record = **one channel-strip object** (Audio / Aux / Bus / Inst / Input / Output / Master).
~1.01M records over 1293 files (285–1178/file, avg ~784). Two record shapes: a 14-byte **STUB**
placeholder and a full **strip**. Identify: `magic 0x1235` at `payload+0x0a` marks 100% of both
(999455/999455 full + all 13702 stubs). Version-grouped into schema families by `pd_bytes[4:6]`:
schema1 (`*06` early), schema2, schema4, schema6 (`cd09`/`ce09`/`cf09` = Logic 11).

Full-strip payload (`raw[0x24:]`):

| off | sz | field | meaning |
|-----|----|-------|---------|
| +0x00 | 4 | formDword | STUB if `0x10`/`0x20` (type byte `0xff`); else full-strip base-struct size, per-schema: `0xd8` schema6 (pure), `0xc0` schema4 (pure), `0xb0` schema2 (~99.4%), content-dependent `0xc0..0xd4` schema1 |
| +0x04 | 1 | typeEnum | `0x40`=Audio, `0x41`=Input(mono), `0x42`=Aux, `0x43`=Inst, `0x44`=Output(mono), `0x45`=Bus, `0x46`=Master, `0x49`=Input(stereo), `0x4c`=Output(stereo); rare `0x4b`=Rewire. 99.99% in-set |
| +0x05 | 1 | pad | `0x00` on proper full strips (996348/999455) |
| +0x06 | 2 | stripOrdinal | 0-based ordinal within its type, contiguous 0..N/file (99.95%). = name-trailing-N minus 1 ONLY for mono-numbered types; Input/Output names carry a channel pair (1-2, 3-4) instead |
| +0x0a | 2 | magic 0x1235 | constant `35 12`, 100% of full strips AND stubs |
| +0x2a | 4 | const 4 | `0x00000004` in ~99% of full strips, all schemas (**NOT** at +0x2c, which is 0) |
| +0x2e..0x3b | 14 | zero pad | runway before the name |
| +0x3c | 16 | name | ASCII, fixed 16-B field, leading space, NUL-terminated (100% within [0x3c:0x4c]); user rename may drop the leading space |
| +0x55 | 1 | volume/fader | default `0x5a`=90 (Bus 99.999%); duplicated at +0x77 (100% equal) |
| +0x59 | 1 | pan | default `0x40`=64 center (96.0%) |
| +0x77 | 1 | volume mirror | exact duplicate of +0x55 (100%) |
| +0x78 | 4 | fixed block | `06 00 7f 0X` in schema2/4/6 (~94%); `00 00 00 0X` in schema1. Structural, not a reference |
| last 17 | 17 | 0xFF + UUID | **schema6 ONLY**: `0xFF` marker + 16-B RFC-4122 v1 UUID (11ef era). 100% of schema6 strips, 0 in schema1/2/4. Usually — not always — unique within a file |

Header (§2.1): full strips share pool `idx@0x08 = 0x240000` (~99.7%); stubs carry `idx = trackIndex<<18`.

```
Three record shapes:
 (1) STUB (14 B, per-track placeholder), TWO forms — both type-byte 0xff, both end '35 12 00 00',
     both carry idx = trackIndex<<18 (low-18-bits==0, 100%):
       form 0x10  '10 00 00 00 ff ff 00 00 00 00 35 12 00 00'  (11661, common)
       form 0x20  '20 00 00 00 ff ff 00 00 00 00 35 12 00 00'  (2041)
 (2) FULL strip = fixed prefix [form|type|pad|ordinal|magic|sub-hdr|const4|zero|name16]
     + settings block [+0x4c variable 4B (appearance-ish, NOT constant) | +0x55 fader=+0x77 | +0x59 pan
     | +0x78 '06 00 7f 0X'] + variable zero pad; schema6 appends the 17-B 0xFF+UUID tail.
 (3) eb06-only anomaly (form 0xa, type 0xff, ~3107 recs) violating pad05/typeEnum/idx240 — handle separately.
No bplists / UTF-16 / length-prefixed strings; the 16-B name is the only string.
```

*Corrections to existing spec:* the const-4 dword is at `payload+0x2a`, not +0x2c (which is always 0);
there are **two** stub forms (0x10 far more common than 0x20), so a classifier keying only on 0x20
misclassifies 11661 stubs as full strips; `+0x06` is a 0-based per-type ordinal (not "name number − 1"
for stereo Input/Output); `typeEnum`→default-name prediction is 99.6% not 100% (user renames + `0x4b`
Rewire break it); schema6 UUID is present-100% but not guaranteed unique (43/233 schema6 files have a dup).

*Provenance: production-corpus RE — every claim tested against the full ~1.01M-record corpus (1293/1294 files;
1 parse failure) with exact match/violation counts and concrete counterexamples, schema-grouped.*

---

## 16. Channel-strip plugin inserts (`UCuA`) — verified on the full production corpus (1293/1294 files)

A `UCuA` record = **one insert/component slot** on a channel strip (plugin state, Smart-Controls graph,
or reserved slot). 236304 records over 1293 files, ~5.15/strip (1–20). ALL are pool records:
`idx@0x08 = 0x240000` (100%), `classId@0x06 = 14` (100%). Two-level structure — group into strips by
`ordinal@0x0c`, then select body form by `KIND` at `payload+0x04`.

| off | sz | field | meaning |
|-----|----|-------|---------|
| 0x04 (hdr) | 2 | schemaVersion | file-global (constant within a file). 1=`ae06/d606/dc06/e106/e606`; 2=`c409/cd09/d007/eb06`; 3=`ce09`; 4=`cf09` |
| 0x06 (hdr) | 2 | classId | ==14 (100%) |
| 0x08 (hdr) | 4 | idx | ==`0x240000` (100%) — shared channel-strip POOL tag, not a unique index. No per-track UCuA |
| 0x0c (hdr) | 4 | ordinal / STRIP-ID | strip id = `value>>16` (low 16 bits always 0, lossless 100%). Shared by all UCuA of a strip |
| 0x10 (hdr) | 2 | link0 | ==0 (100%) |
| 0x12 (hdr) | 2 | link1 / SLOT | insert slot 0..30, **unique per record within a strip** (0 collisions across 45912 strips). Array key = (strip, slot). Slots 0 and 26 are NOT reserved-empty |
| 0x14 (hdr) | 2 | link2 | ==0 (100%) |
| 0x16 (hdr) | 2 | const | ==`0x0002` (100%) |
| pay +0x00 | 4 | leadLen | internal content length; scattered vs payloadSize. **NOT** framing — use header payloadSize@0x1c |
| pay +0x04 | 2 | KIND | body-form enum: 0/5 compact reserved form (44/176 B typical, often NON-zero body); 1/2 native plugin-setting blob; 7 NSKeyedArchiver bplist. 3/4/6 rare |
| pay +0x06 | 2 | seqIndex | intra-strip chain-position index, distinct from slot. Usually (93.6%) a dense 0..N−1 permutation among a strip's kind-1 records, but not guaranteed |
| pay +0x0a | 2 | MAGIC | ==`0x1235` (100%) |
| pay +0x0c | 2 | zero | ==0 (100%) |
| pay +0x0e | var | body (kind1/2) | native plugin setting: NUL-term preset filename (`#default.pst`, `.default.def`) → var-length plugin name (`Channel EQ`, `St-Delay`) → 4CC `GAME` → param data |
| pay +0x10 | 4 | blobLen (kind7) | length of the FIRST embedded bplist. == payloadSize−20 in only 76.6%; 23.4% carry trailing bytes. Not whole-payload framing |
| pay +0x14 | var | bplist (kind7) | `bplist00` NSKeyedArchiver (100% of kind-7). Smart-Controls + channel-identity graph (`MAPlugInParameterMapping`/`MAGraphPoint`/`WsIdentity`/`Smart Knob N`) |

KIND distribution: kind7=87001, kind1=75213, kind5=41662, kind0=21159, kind2=10023, kind4=1002, kind3=147, kind6=97.

```
Two-level array: UCuA records → strips (key ordinal>>16) → slots (key link1, unique per strip).
Fixed payload preamble [leadLen | KIND | seqIndex | zero | MAGIC 0x1235 | zero] then a KIND-selected body.
 KIND=7 : bplist00 at pay+0x14 (Smart-Controls + channel-identity object graph).
 KIND=1/2 : native plugin blob (preset filename → plugin name → 4CC 'GAME' → params).
 KIND=0/5 : compact reserved forms (NOT all-zero — 70.7% have a nonzero body).
```

*Corrections to existing spec:* schemaVersion has a value **3** (`ce09`, previously unenumerated); slots
0 and 26 are NOT reserved-empty (slot 0 can hold real kind-1 plugins; slot 26 is predominantly a
kind-7 bplist slot); kind 0/5 are compact but NOT all-zero; kind-7 `blobLen` frames only the first blob
(23% carry trailing bytes) — use the header payloadSize for framing; `pay+0x08` is not universal zero
(carries a small field in kind-0 records).

*Provenance: production-corpus RE — 236304 records (1293/1294 files), a ~15× larger sample than the original
120-file pass; header/grouping invariants all 100%, KIND body decodes verified end-to-end on live records.*

---

## 16b. Project start bar (`gnoS`) — "Bar position of project start"

Logic can renumber a project to begin at any bar (`-2`, `0`, `5`, …), like Pro Tools' own
start-bar renumber. It is **not** in `MetaData.plist`, `ProjectInformation.plist` or
`DisplayState`; it lives in `gnoS` as **five fields that must all agree**, held in two
domains at once:

| field (record-relative) | domain | bar 1 | bar -2 |
|---|---|---|---|
| `+0x154`, `+0x15c`, `+0x1ac`, `+0x410` | 960-PPQ ticks | `38400` | `26880` |
| `+0x346` | **samples** | `158760000` (3600 s @44.1k) | `158495400` |

`delta = (start_bar - 1) x bar_length`, in ticks for the first four and in samples for the
last. Bar 1 stays anchored to the SMPTE start (01:00:00:00 by default = 3600 s), so a bar
below 1 moves the project start EARLIER.

- **Bar numbering is contiguous and INCLUDES bar 0** — `-2` is *three* bars before bar 1, not
  two. Measured, not assumed: Logic's own `-2` donor shifts by exactly `11520` ticks / `6.0 s`.
- **All five are required.** Any proper subset reads back as bar 1 — verified against Logic
  12.2 with subset probes: the four tick fields alone (playhead moves, ruler does not), the
  sample field alone, and three-of-four ticks + the sample field all leave the start at bar 1.
  `+0x1ac` doubles as the playhead position, which is why it looks droppable and is not.
- `+0x2960..+0x2964` also changes between donors but is save-timestamp churn — reverting it
  leaves the start bar correct.

`projectdata.set_project_start_bar(pd, bar, sample_rate=, bpm=, numerator=, denominator=)`
reproduces Logic's own `-2` donor byte-for-byte on all five fields. The bars being added
precede bar 1, so the INITIAL tempo and meter govern their length.

## 17. Audio-region parameters (`gRuA`) — full-corpus verification (extends §8)

A `gRuA` record = **one audio-region object** (no repeating sub-array). 320787 records over 1293 files.
Identify: `classId@0x06 = 0x000b` (100%). **SIZE FORMULA** (100%): `record_size = 0x24 + name_end + 126`,
where `name_end = 0x4c + u16len@payload+0x4a` rounded up to even; the trailing parameter block is a
**constant 126 bytes**. Because that tail is fixed-length, all post-name fields are addressed relative to
`name_end` (= tail start), NOT payload-start.

| off | sz | field | meaning |
|-----|----|-------|---------|
| hdr 0x06 | 2 | classId | ==`0x000b` (100%) |
| hdr 0x04 (=0x1a) | 2 ea | schemaVersion / headerForm | `u16@0x04 == u16@0x1a` always. Value in {1,2}; ==2 only in `cd09/ce09/cf09`, and those always write a non-zero region UUID |
| hdr 0x08 | 4 | idx | `trackIndex<<18` per-track (310801/310801) or exactly `0x240000` for the 9986 pool records |
| hdr 0x10 | 2 | link0 | ==0 (100%) |
| hdr 0x12 | 4 | hdr_link | ==`0xffffffff` (100%) |
| hdr 0x16 | 2 | hdr_form2 | ==`0x0002` (100%) |
| pay +0x00 | 1 | flag0 | in {0,1} for 99.96% (1→54% / 0→46%); semantics open |
| pay +0x01 | 1 | pad | ==0 (100%) |
| pay +0x02 | 2 | flags16_a | region flags. Co-dominant `0x1000` (110562) and `0x2800` (107439); bits open |
| pay +0x04 | 2 | flags16_b | mostly 0 else `0x4000/0x0200/0x8000/0xc000`; open |
| pay +0x06 | 4 | **trimIn** | region **trim-in** = the start sample within the SOURCE FILE. The region plays file samples `[trimIn, trimIn+frameLength]` — verified `trimIn+frameLength ≤ file frames` in **2810/2810** trimmed regions (100%). This + `frameLength` + the placement tick fully locate a (possibly-trimmed) audio region. |
| pay +0x0a | 4 | const0_a | ==0 (100%) |
| pay +0x0e | 4 | u32_offsetB | 0 in 262468 else large sample value; candidate loop/anchor offset (open) |
| pay +0x12 | 4 | near_const0_b | 0 in 99.99%; 31 records hold near-`0xffffffff` sentinels. **NOT** a hard constant |
| pay +0x16 | 4 | frameLength | region length in samples. Never 0; min 1, max 20201472 (§8) |
| pay +0x1a | 4 | const0_c | ==0 (100%) |
| pay +0x2a | 32 | nameSlot_secondary | fixed 32-B NUL-padded slot (guaranteed by size formula). Content is a display-name prefix in only ~46% of populated cases (weak tendency) |
| pay +0x4a | 2 | displayName_len | u16 length; drives the size formula |
| pay +0x4c | var | displayName | ASCII/UTF-8, padded to even. `name_end = 0x4c + len` (even) = tail start |
| tail +0x12 | 4 | FADE fourCC | bytes `EDAF` present ONLY here (608 records) when fades set; reliable fade-present anchor |
| tail +0x30 | 4 | regionTakeIndex | per-track region/take counter (0,1,2,…); matches region-name numeric suffix in observed cases |
| tail +0x56 | 16 | regionUUID | 16-B region UUID. Non-zero & effectively unique WITHIN a file; schemaVersion==2 → always non-zero. **NOT** globally unique (project copies dup it cross-file) |
| tail +0x66 | 4 | link_field | none-sentinel: `{0xffffffff: 317162, 0x00000000: 3625}` only. Not a live cross-reference |

```
Payload = 3-zone layout + fixed tail:
  (1) fixed 42-B prefix [0x00..0x2a]  (2) fixed 32-B secondary name slot [0x2a..0x4a]
  (3) variable display name (u16 len @0x4a + bytes + pad-to-even)  (4) fixed 126-B trailing param block.
The `EDAF` fade descriptor (fade-in/out lengths + signed curves) is fully decoded in **§35.1**;
the region take-index is at tail+0x30.
```

*Corrections to existing spec:* `near_const0_b@+0x12` is 99.99%-zero, not a hard constant (31 sentinel
records); `regionUUID` is unique only within a file (56338 cross-file duplicate instances corpus-wide);
`frameLength` max is 20201472 (earlier 14233893 was a sample artifact); the `+0x2a` secondary slot is a
name-prefix in under half of populated cases; the gRuA↔lFuA binding is positional (§8), NOT via `tail+0x66`.

*Provenance: production-corpus RE — structural skeleton confirmed on 320787/320787 records (1293 files);
several fine-grained semantic sub-claims (fade layout, gain sentinel, UUID uniqueness) refuted with counts.*

---

## 18. Arrange/track rows (`karT`) — full-corpus verification (1293/1294 files)

A `karT` record = **one arrange/track-row's attributes**. 230860 records over 1293 files (1 file
unparseable — bad magic). Records form parallel per-file streams keyed by
`(idx-cluster, link1-ordinal)`. **The populated/empty discriminator is `link2@0x14`, NOT idx**:
`0x0000` on every populated row (99484/99484), `0x7FFF` on every empty placeholder (131376/131376) — 100% clean.

| off | sz | field | meaning |
|-----|----|-------|---------|
| hdr 0x08 | 4 | idx / cluster | `trackIndex<<18` (stride `0x40000`). Shared by populated AND empty rows. `0x000000`=master stream, `0x040000`=arrange list, `0x080000`=channel pool, `0xC0000+`=per-track/region clusters. NOT a populated/empty selector |
| hdr 0x0c | 4 | ordinal(sentinel) | ==`0xFFFF0000` (100%) |
| hdr 0x10 | 2 | link0 | ==`0xFFFF` (100%) |
| hdr 0x12 | 2 | link1 / ordinal | ordinal within the cluster stream; for `idx 0x040000` populated = arrange row position, contiguous 0..N−1 (1293/1293 files). `0xFFFF` on empties |
| hdr 0x14 | 2 | link2 (discriminator) | `0x0000` populated / `0x7FFF` empty. 100% clean |
| hdr 0x16 | 2 | const | ==`0x0002` (100%) |
| hdr 0x1a | 1 | headerForm | file-global: 2 for `cd09/ce09/cf09`, 1 for older |
| pay 0x00 (raw 0x24) | 1 | rowType | 1=normal (98021); 3=master (1297), where rowType==3 ⇔ channelSlot==0x50 (99.2%). Rare 4/6/7 |
| pay 0x01 (raw 0x25) | 1 | const | `0x00` in 99.85% |
| pay 0x02 (raw 0x26) | 1 | flagsA (unresolved) | base `0x14` common (76% "active"); `0x00` also common across ALL families (22%, NOT master-only). Bit→UI open |
| pay 0x03 (raw 0x27) | 1 | flagsB (unresolved) | base `0x00` (93%); `0x20/0x24` common; open |
| pay 0x04 (raw 0x28) | 4 | near-const | `0x00000000` in 99.24% |
| pay 0x08 (raw 0x2c) | 4 | channelSlot | slot = `ivnE(channel) idx>>16` driven by this row; 0 on master/global. Matches a real ivnE slot or 0 in 98.5% |
| pay 0x0c (raw 0x30) | 4 | secondaryIdx/flag (low conf) | usually 0 (86%), `0x10000` in 13%; meaning open. NOT a reliable region-cluster marker |
| pay 0x10 (raw 0x34) | 8 | const | 8 zero bytes (99484/99484) |
| pay 0x18 (raw 0x3c) | 16 | trackUUID | 16-B track/arrange-track id, never all-zero (0/99484); keys `MneG.drummerModelTrackStates` |
| pay 0x28 (raw 0x4c) | 3 | flags/ordinal block (med conf) | byte@0x28 ∈{0,0x20,0x40,0x60,0x80,0xc0}; @0x29 ∈{0,0x80,0x81…}; @0x2a = 0x10 (86.7%) / 0x00 |
| pay 0x2c..end (raw 0x50+) | 0-13 | version tail | up to two `XX 07` channel-ref pairs; size52 adds a 2nd pair; size56 adds a 4-B field = `ffffffff` ONLY when refs present (else 0); size57 adds one trailing byte. Sentinel is **conditional** |

`payloadSize` is version-driven for populated rows: `ae06`=48; `d606`=52; `dc06`=52&56 (transitional);
`e106/e606/c409/d007/eb06`=56; `cd09/ce09/cf09`=57.

```
No sub-record array inside one karT. Records form parallel streams per file:
  populated (link2==0x0000): idx 0x000000 = 1-2 master/global rows; idx 0x040000 = arrange track list
  (link1 = 0..N-1 row position, contiguous 1293/1293); idx 0x080000 = channel/track pool (all rowType=1);
  PLUS per-track/region clusters idx 0xC0000+ that ALSO carry populated rows in 359/1293 files (7939 rows).
  empty placeholders (link2==0x7FFF): payloadSize 0 or 8, idx = cluster<<18 (all multiples of 0x40000),
  SAME idx space as populated rows. No bplists, no embedded strings (0/99484).
```

*Corrections to existing spec:* use `link2@0x14` (not idx) as the sole populated/empty test — 100% clean;
idx is a uniform `trackIndex<<18` cluster shared by BOTH populated and empty rows, NOT a 3-family tag;
populated rows are NOT limited to three idx families (28% of files carry populated rows at `0xC0000+`);
`flagsA@0x02==0x00` does NOT identify the master row (widespread); channelSlot is at raw 0x2c (pay 0x08);
the size≥56 `ffffffff` tail sentinel is conditional (present only with channel refs), not fixed.

*Provenance: production-corpus RE — 230860 records adversarially verified across 1293 parseable files, each
refutation backed by named counterexample files (e.g. session D's idx 0x40000 populated rows).*

---

## 19. MIDI Environment objects (`ivnE`) — full-corpus verification (1293/1294 files)

An `ivnE` record = **one Environment object** (channel strip, MIDI monitor, multi-instrument/port device,
folder, or terminator). 72058 records over 1293 files (13–1120/file, avg 55.7). Identify:
`classId@0x06 = 0x14` (100%). Each holds a **unique** slot — `idx@0x08 % 0x40000 == 0`, `slot = idx>>16`
(100%); NO shared `0x240000` pool. `schemaVersion@0x04` maps 1:1 to root version (ae06=2, d606=3,
dc06/e106/e606=4, eb06/d007=5, c409=6, cd09/ce09=11, cf09=12).

| off | sz | field | meaning |
|-----|----|-------|---------|
| raw 0x04 | 2 | schemaVersion | u16 version key, constant per file, 1:1 with root version (100%) |
| raw 0x06 | 2 | classId | ==`0x14` (100%) |
| raw 0x08 | 4 | idx (slot<<16) | low16==0, `%0x40000==0`; `slot = idx>>16` (multiple of 4, unique, no pool). 100% |
| raw 0x0c | 4 | ordinal | ==`0xFFFF0000` sentinel (100%) |
| raw 0x1c | 4 | payloadSize | ==`len(raw)-0x24` (100%) |
| pay +0x00 | 2 | defSize | u16 nominal class byte-size; grows monotonically with schemaVersion. Not this record's own size. Echoed at +0x72 only 76% |
| pay +0x02 | 2 | flag 0x4040/0x0000 | per-object display/enable flag. Constant `0x4040` ONLY in sv2-4; ~57% sv5; minority in sv6/11/12 (overall 56%) |
| pay +0x04..0x0f | 12 | zero pad | all-zero (100%) |
| pay +0x10 | 4 | slot | ==`idx>>16` (100%) |
| pay +0x20 | 2 | sv6+ marker | ==`0xFF3E` in sv6/11 (100%), sv12 (99.99%), 0 in sv2-4 (100%); ~2.5% leak in sv5 |
| pay +0x54/0x56/0x58 | 2 ea | geometry (x,y,size) | three u16 Environment-window rect. Channel strips constant (`0x19,0x40,0x1df`); system objects distinct |
| pay +0x5a | 2 | KIND (object class) | in {0,2,3,4,5,6,0xFFFF} (99.70%): 0/6=terminator, 2=MIDI monitor, 3=device/folder, **4 & 5=channel strip** (5 = rare sv11 variant), 0xFFFF=folder/context |
| pay +0x9e | 2 | canonical name length | u16 char count; **FIXED offset across all schema versions 2-12** |
| pay +0xa0 | len@0x9e | canonical name | object/channel display name, ASCII/latin1. Valid ~99.87% (0.13% carry an embedded `0x10` two-segment delimiter, e.g. `NAME`+0x10+`PART`) |
| pay name_end+6 (or +7) | 16 | channel UUID (kind4/5) | ==the strip's `OCuA@0xbd` — the authoritative **ivnE↔OCuA binding** (5663/5663 = 100%) |
| pay +0xf0 (kind-3) | 16×128 | GM patch-name table | 16-B-stride NUL-padded ASCII table of 128 GM program names (`Grand Piano`,`Bright Piano`,`ElectricGrand`,…) |

System-singleton slots occupied in 1293/1293 files: `0x00` No Output, `0x0c` MIDI Click, `0x10` Folder,
`0x14` Sequencer Input, `0x18` Physical Input, `0x40` Input View, `0x44` Input Notes, `0x48` Prelisten,
`0x4c` Click, `0x50` Output/Stereo Out, `0x54` Master.

```
Three kind-keyed tails:
 kind-3 GM Device: 16-B-stride NUL-padded ASCII table of the 128 GM program names begins at EXACTLY pay+0xf0.
 kind-4/5 channel strip: 16-B channel UUID at pay name_end+6 (or +7) == the OCuA record's @0xbd (100%).
 kind-2 fixed-monitor (Input View 0x40, MIDI Click 0x0c): per-channel/metronome row arrays in the tail
   (stride/fields not byte-verified — medium).
```

*Corrections to existing spec:* KIND enum is {0,2,3,4,5,6,0xFFFF} (kind5/kind6 real, rare); the channel
UUID↔OCuA binding is at `name_end+6/+7`, NOT `name_end+0x11f` (which matched only 4.7%); `pay+0x02==0x4040`
is constant only in sv2-4, not the modern default; `pay+0x2c` is NOT const-1 (~40% all schemas); system
slots 0x40-0x54 are near-universal across ALL versions (not modern-template-only).

*Provenance: production-corpus RE — 72058 records exhaustively counted per schema version, with end-to-end
decoded examples (GM patch table, OCuA-UUID binding corrected to 100%, universal system slots).*

---

## 20. Note/content event sequences (`qSvE` role 0x17) — full-corpus verification (extends §3)

A role-0x17 `qSvE` (`classId@0x06 = 0x17`) = **the event list carrying note/CC/lane/placement content**.
167861 of 176826 qSvE records (94.93%) over 1293 files. **Structural bedrock**: the payload body (after
the 36-B header, minus the 16-B tail) is a multiple of **16 bytes** in 100% — the 16-byte-word event
model is real. ~36.7% of role-0x17 sequences are empty (tail only, first dword `f1000000`).

| off | sz | field | meaning |
|-----|----|-------|---------|
| ev+0x00 | 1 | type/status | MIDI status w/ channel in low nibble (`0x8n-0xEn`, `0xF0`) OR Logic lane code `0x50-0x57` OR region placement `0x20` (MIDI region)/`0x24` (audio region). <1% non-status tail exists |
| ev+0x01 | 1 | fmt/ext flag (byte1) | `0x00`=compact (note=32B, others=16B); `0x40`=extended (multi-word, sub-block-tagged). Version-correlated: pure-0x00 in `*06` versions, mixed in the 09-series. Rare `0x20/0x44/0x60` variants |
| ev+0x04 | 4 | position | u32, 960 PPQ, region-relative. Origin **38400** for note/tempo/marker/sig; origin **34560** for region PLACEMENT (0x20/0x24). Spans the whole region — NOT clustered near origin |
| ev+0x0b | 1 | primary data | note-on velocity / CC value. ≤127 in 100% of CC events checked |
| ev+0x0c | 1 | secondary data | note pitch / CC controller number (real CC#s: 1,2,4,7,11,64,101…) |
| note+0x17 (2nd word +0x07) | 1 | core-note tag | ==`0x89` on a compact note's second 16-B word (99.99%) |
| ext word+0x07 | 1 | sub-block tag | in byte1=0x40 extended notes: `0x89` core word, `0xa3/0xa4/0xa7` per-note extension words (internals open) |
| payload end | 16 | TAIL | `f1 00 00 00 ff ff ff 3f 00 00 00 00 00 00 00 00`; present in 99.34% of role-0x17 payloads |

Role census (all qSvE): 0x17=167861, 0x16=2967, 0x19=1571, 0x01=1432, 0x03=1342, 0x0e=1254,
0x05=292, 0x08=80, 0x11=27. (Extends §2.1's qSvE role table.)

```
role-0x17 payload = variable array of 16-B-aligned typed events + 16-B f1..3f tail (99.34%).
Events may be mixed-type in one payload (notes interleaved with CC/lanes).
 Compact (byte1=0x00): MIDI/CC/lane = 16 B; NOTE = 32 B (status word + note-off/length word tagged 0x89@+0x17);
   placement 0x20/0x24 = 80 B.
 Extended (byte1=0x40): note = 48/64/80 B array of 16-B words tagged at word+0x07 (0x89 core, 0xa3/0xa4/0xa7 ext).
A fixed 16-B stride desyncs on notes (32 B) and extended notes; the **complete stride table is now
in §36** (the only residual is sysex `0xF0`, which is variable-length).
```

*Corrections to existing spec:* the position origin is **field-dependent** — notes/tempo/markers use
38400, region PLACEMENT events use **34560** (the blanket "origin 38400" is note-only); lane-code range
is `0x50-0x57` (not …0x56); `link0@0x10==0` is 99.94% not universal (all 101 exceptions are `cf09`);
the "notes within one bar of 38400 in 99.5%" claim is a first-note sampling artifact (only 44% across all
walked notes — positions span the whole song); `ev+0x02` is NOT a sub-tick field on notes.

*Provenance: production-corpus RE — 167861 role-0x17 records; field semantics (type/fmt/pos/vel/pitch/tag/
placement) corpus-verified, but the two headline invariants (link0==100%, notes-within-one-bar) refuted.*

---

## 21. Root Song record (`gnoS`) — full-corpus verification (extends §4)

`gnoS` = **the root Song / global-settings record**. Exactly 1 per file, always the FIRST record at
file offset `0x18` (1293/1293). Identify by its unique sentinel triple: `classId@0x06=0xFFFF`,
`idx@0x08=0xFFFFFFFF`, `ordinal@0x0c=0xFFFFFFFF` (no other record carries all three). Two layouts,
selected by `headerForm@0x1a`: **COMPACT** (=1, fixed size) vs **SETTLED** (=2, variable, 09-era only).

| off | sz | field | meaning |
|-----|----|-------|---------|
| 0x00 | 4 | tag | reversed FourCC `gnoS` (100%) |
| 0x04 | 1 | schemaVersion | clean per-version bands: 1(`ae06`), 2(`d606/dc06/e106/e606`), 3(`c409/d007/eb06`), 5(`cd09`), 6(`ce09/cf09`) |
| 0x06 | 2 | classId | ==`0xFFFF` sentinel (100%) |
| 0x08 | 4 | idx | ==`0xFFFFFFFF` root sentinel (100%) |
| 0x0c | 4 | ordinal | ==`0xFFFFFFFF` (100%) |
| 0x10 | 6 | links | three u16 @0x10/0x12/0x14 all `0xFFFF` (100%) |
| 0x16 | 2 | const0002 | ==`0x0002` (100%) |
| 0x1a | 1 | headerForm | **LAYOUT DISCRIMINATOR**: 1=COMPACT fixed-size (1060 files), 2=SETTLED variable (233 files, `cd09/cf09/ce09` only) |
| 0x1c | 4 | payloadSize | record total = `0x24 + payloadSize` |
| 0x24 | 4 | payloadMagic | `2347c0ab` — start of the gnoS class frame. Always at 0x24, but **NOT unique**: 96 files carry a second nested frame at 0x2e0 |
| 0x28 | 2 | frameClassVersion | u16 LE class-serialization version; ==`file[4:6]` in 984/1293 (306 mismatches are `d007`→`ef06`, plus 3 others) |
| 0x2a | 2 | structRev | struct revision: `0x10`(ae06/d606/dc06/e106) → `0x17`(e606, 82×eb06) → `0x18`(c409/d007/cd09/ce09/cf09, 220×eb06). Clean bands |
| 0x2c | 2 | fieldCount | **u16 (NOT u32)** low-cardinality {14,15,17}; content-dependent (splits within one file version) — LOW confidence |
| 0x2e0 | var | nestedFrameMagic | OPTIONAL nested `2347c0ab` frame (header `ef06`/structRev 0x18) at fixed offset 0x2e0. Present in 96/1293 files (cd09/d007/c409/cf09), absent in the other 1197 |
| 0x92 | 4 | tempoSlotA | `round(BPM*10000)`; **PLAYHEAD-dependent** once a tempo map exists — do NOT read initial tempo here |
| 0xC7 | 1 | srByteRegion | sample-rate byte ==`0x03` across the (all-44.1k) corpus. Variable-SR encoding not exercised |
| 0xEA | 4 | tempoSlotB | tempo replica; ==tempoSlotC ALWAYS (1293/1293) |
| 0x3A6 | 4 | tempoSlotC | **AUTHORITATIVE** initial tempo; ==tempoSlotB (100%); all map to BPM ∈ [20,400]. Read initial BPM here |
| 0x400+ | var | settledExtension | ONLY when headerForm==2: large sparse mostly-zero block inflating gnoS to 9.5KB-155KB; no strings/bplists. 233 files |

```
Payload (raw[0x24:]) = flat binary settings blob (NOT a stride array):
  [4B magic 2347c0ab @0x24][u16 frameClassVersion@0x28][u16 structRev@0x2a][u16 fieldCount@0x2c] + flat block.
Tempo is a fixed replica: slotA@0x92 (playhead-dependent), slotB@0xEA, slotC@0x3A6; slotB==slotC ALWAYS,
  slotA==B==C in 993 (the 300 with a tempo map differ only in slotA). Read initial BPM from slotC.
COMPACT (hf=1) payload sizes fixed per version: ae06→3604, d606/dc06/e106/e606→3636, c409/d007/eb06→3716.
SETTLED (hf=2, cd09/cf09/ce09) appends the large variable extension. No bplists / strings in any payload.
```

*Corrections to existing spec:* the `2347c0ab` magic is NOT once-per-record — 96 files carry a genuine
nested frame at fixed offset 0x2e0; `fieldCount@0x2c` is u16 not u32 (reading u32 yields garbage on 3
files whose next u16 is nonzero); state the tempo invariant as `slotB@0xEA==slotC@0x3A6` (1293/1293) with
slotA diverging in 300 files — read initial BPM from slotC/file-0x3BE (refines §4's 3-slot claim).

*Provenance: production-corpus RE — 1293/1294 files (1 unparseable); header/headerForm/
structRev/tempo-replica all HIGH confidence; the nested-frame refutation has 96 concrete counterexamples.*

---

## 22. Project singleton pool (`OgnS`) — full-corpus verification (1293/1294 files)

An `OgnS` record = **a project-level singleton collection** (audio pool, global/Drummer settings, or a
reserved block). 3690 records over 1293 files. Identify: `classId@0x06 = 0x000E` + `schemaVersion@0x04 = 1`
(both 100%). Role is selected by `idx@0x08` (a role slot, NOT a track index).

| off | sz | field | meaning |
|-----|----|-------|---------|
| 0x04 | 2 | schemaVersion | ==`0x0001` (100%) |
| 0x06 | 2 | classId | ==`0x000E` (100%) |
| 0x08 | 4 | idx (role slot) | FIVE values: `0x00E00000` global/Drummer settings (1293 files), `0x00F40000` reserved block (1099), `0x01080000` AUDIO POOL (1290), `0x00FC0000` movie/video ref (2), `0x01040000` heterogeneous rare (6) |
| 0x0c | 4 | const_FFFF0000 | ==`0xFFFF0000` (100%); low u16==0, high u16==0xFFFF |
| 0x10 | 6 | links | three u16 all `0xFFFF` (100%) |
| 0x16 | 2 | const2 | ==`0x0002` (100%) |
| 0x1a | 2 | headerForm | ==`0x0002` for `cd09/ce09/cf09`, ==`0x0001` otherwise; file-global |
| 0x1c | 4 | payloadSize | role-dependent (0x00F40000 always 1648; 0x01080000 grows with entries) |
| pay+0x00 (0x24) | 4 | container size/capacity | ==payloadSize in only ~49% of pool records — allocated vs used, LOW confidence |
| pay+0x10 (0x34) | 4 | container class-tag | `0x000028A0`=audio pool, `0x00002710`=global/Drummer settings, `0x00016006`=reserved block, `0x000002AC`=movie ref |
| pay+0x14 (0x38) | 2 | subtype/flag | ==`0x0001` for audio-pool container (100%); sole varying byte in the 1648-B reserved block |
| pay+0x16 (0x3a) | 2 | magic 0xED99 | marks every `a0280000` container/sub-block header (100%) |
| pay+0x18 (0x3c) | 4 | container body length | ==payloadSize−16 in only ~51% — MEDIUM/LOW confidence |
| pay+0x1c (0x40) | 4 | ENTRY_COUNT | number of pool entries == number of embedded bplists (1290/1290). Does NOT equal #LoopFamily (only 545/1290). 0 ⇒ empty pool |
| pay+0x20 (0x44) | var | entry array | ENTRY_COUNT variable-length entries; first bplist at payload 0x4C in non-empty pools (1285/1285) |

```
AUDIO-POOL entry array (role 0x01080000), payload-relative:
  32-B preamble [0x00 size/capacity (unreliable) | 0x04..0x0F zero | 0x10 tag=0x000028A0 | 0x14 u16=0x0001
   | 0x16 u16=0xED99 | 0x18 body-len (unreliable) | 0x1C u32 ENTRY_COUNT == #bplist], then entries.
  Sub-block header = [4B a0 28 00 00][2B subtype][2B magic 0xED99][4B length]. Census: one subtype-0x0001
  outer container/pool, then per entry one subtype-0x0003 + one subtype-0x0002 block (90223 each); the
  0x0002 block wraps exactly one NSKeyedArchiver bplist. Loop entries decode to {Shared/LoopFamily/LoopName
  /LoopId}, LoopName == real sample basename. Empty pool = 32-B _EMPTY_AUDIO_OGNS_PAYLOAD, entryCount 0.
  The 0x00E00000 (tag 0x2710) role reuses the SAME a0280000/0xED99 grammar for a settings/Drummer bplist.
Container grammar (tags 0x28A0/0x2710/0x16006, magic 0xED99, ENTRY_COUNT@0x1C, first-bplist@0x4C) is
INVARIANT across all 11 versions.
```

*Corrections to existing spec:* a **fifth** role `0x00FC0000` (movie/video ref) exists beyond the 4-value
set; `ce09` also has `headerForm==0x0002` (value-2 set = {cd09,ce09,cf09}); ENTRY_COUNT == #bplist but
**NOT** == #LoopFamily (42%); `0x01040000` is heterogeneous (6 files, not a single 104-byte type); the
audio pool is absent in 3 files (99.77%, not universal); `ordinal@0x0c` is the full u32 `0xFFFF0000`.

*Provenance: production-corpus RE — 3690 records fully parsed; container grammar holds 99.8-100% across all 11
versions; each refutation backed by a named counterexample file.*

---

## 23. Session-Player / Drummer generator state (`MneG`) — full-corpus verification

`MneG` = **a per-track GeneratorMemento** (LoopFamily / GrooveState-Articulation / Drummer+SmartTempo) —
generic, not Drummer-only. 45445 records over **233 files, versions `cd09/ce09/cf09` ONLY** (absent
elsewhere). Identify: `classId@0x06 = 30 (0x1e)`, `schemaVersion@0x04 = 1`. One MneG per track index
(bijective 233/233); exactly one `idx==0` per file = the Drummer master.

| off | sz | field | meaning |
|-----|----|-------|---------|
| 0x04 | 2 | schemaVersion | ==1 (100%) |
| 0x06 | 2 | classId | ==30 / `0x1e` (100%) |
| 0x08 | 4 | idx | `trackIndex<<18` (low 18 bits 0); `idx==0` = Drummer master (one/file, track 0 only) |
| 0x0c | 4 | ordinal | ==`0xffff0000` (100%) |
| 0x10/0x12/0x14 | 2 ea | link0/1/2 | each ==`0xffff` (100%) |
| 0x1a | 1 | headerForm | ==2 (100%) |
| 0x1c | 4 | payloadSize | walk field; payload = `raw[0x24:]` |
| pay+0x00 | 4 | innerSize | ==record payloadSize@0x1c (100%) |
| pay+0x08 | 4 | typeCode | generator kind: 11=LoopFamily (31109), 20=GrooveState/Articulation (46), 23=Drummer+SmartTempo (14290) |
| pay+0x0c | 4 | handleRef | multiple of 4 (100%); byte-aligned handle/back-reference, target open (MEDIUM) |
| pay+0x10 | 4 | loopSeqIndex/sentinel | ==`0xffffffff` for all tc20+tc23 (100%); small non-negative index for tc11 (100%) — clean LoopFamily separator |
| pay+0x14 | 4 | constFF | ==`0xffffffff` (100%) |
| pay+0x18 | 4 | subKind | 0=per-track memento (45207), 6=Drummer master JSON (231), 5=`.dpst` preset (5), 3=multi-slot master (2). Secondary discriminator within tc23 |
| pay+0x1c | 4 | primaryBlobLen | length of blob at pay+0x24; ==payloadSize−36 for 45438/45445 (single blob); 7 records chain a second framed slot |
| pay+0x24 | primaryBlobLen | blob | `bplist00` NSKeyedArchiver (45207) or JSON (238); schema selected by typeCode + subKind |

```
Record = 36-B §2.1 header + PAYLOAD (raw[0x24:]) = 36-B inner sub-header + blob region.
Three schemas by typeCode@0x08:
 tc11 LoopFamily (31109): bplist Shared>LoopFamily>{LoopName,LoopId} (real sample basenames).
 tc20 GrooveState/Articulation (46): bplist Shared>trackGrooveState and/or ArticulationHandler.
 tc23 Drummer+SmartTempo (14290), split by subKind@0x18:
   subkind0 (14052): bplist Metro>Result embedded SmartTempo beat-analysis JSON (Tempo/Onsets/time_signatures…).
   subkind6/3 (233, always idx0): JSON genInstDrummerBaseModel master (drummerModelTrackStates keyed by track UUID).
   subkind5 (5): JSON .dpst preset with 50 Parameters (fills/swing/groove/humanize/per-piece enables…).
CHAINED framing (7 records, extra bytes != 0): after the primary blob a second slot [u32 tag][u32 subLen][u32]
 + sub-blob — preset slot tag=0 (261-B bplist); master slot tag=6 (primary '{}' then framed genInstDrummer JSON).
```

*Corrections to existing spec:* none — every claim confirmed (this subsystem had 0 refutations). Note
`cf09` (not `cd09`) carries the most records (28955 vs 15580; ce09=910); all 233 `idx==0` records are
Drummer masters and none exist off track 0.

*Provenance: production-corpus RE — 45445 records across all 233 MneG-bearing files, blob schemas decoded
end-to-end (LoopFamily names, SmartTempo JSON, Drummer master/preset JSON).*

---

## 24. Global view/parameter record (`vEuA`) — full-corpus verification

`vEuA` = **a singleton-scoped global view/parameter record** (sibling of `gnoS` in the root frame); its
payload is an array of fixed **52-byte** parameter/range elements. Present in 536/1294 files, 2466 records,
2489 elements. Identify: `idx@0x08 = 0xFFFF0000` (global/singleton sentinel, 100% — never `trackIndex<<18`,
never the `0x240000` pool), `classId@0x06 = 0`, `schemaVersion@0x04 = 1`.

| off | sz | field | meaning |
|-----|----|-------|---------|
| hdr 0x04 | 2 | schemaVersion | ==1 (2466/2466); layout version-stable |
| hdr 0x06 | 2 | classId | ==0 (100%) |
| hdr 0x08 | 4 | idx (scope sentinel) | ==`0xFFFF0000` (100%). Global/singleton marker |
| hdr 0x0c | 4 | ordinal + subtype | low-word ==`0xFFFF`; byte@0x0e = per-record subtype id (distinct=18: 0x50..0x5E, 0xB0/0xB3/0xB8; top 0x50=1769); byte@0x0f==0 |
| hdr 0x10 | 2 | link0 | ==0 (100%) |
| hdr 0x12 | 2 | link1 (graph link) | VARIABLE; distinct=67, dominant value 7 (1822/2466). Medium confidence |
| hdr 0x14 | 2 | link2 | ==0 (100%) |
| hdr 0x16 | 2 | const word | ==`0x0002` (100%) |
| hdr 0x1a | 2 | headerForm | file-global 1 or 2 (§2.1); split 1646/820 |
| hdr 0x1c | 4 | payloadSize | ==`52*N`, N ∈ {1,2} only (52:2443, 104:23). Element stride = 52 |
| elem +0x00 | 4 | value0 / range-lo | VARIABLE 32-bit value. Equals elem+0x30 in 40%. Medium |
| elem +0x04 | 4 | zero | ==0 (100%) |
| elem +0x08 | 4 | sentinel A | default `0x7F000000` (~1.7e38) in 86%; overridable |
| elem +0x0c | 4 | sentinel B | default `0x5A000000` (2^53) in 74%; overridable (weakest sentinel) |
| elem +0x10 | 4 | value1 | VARIABLE 32-bit value (often float 2.0). Medium |
| elem +0x14 | 2 | value2 | **VARIABLE 16-bit field** — NOT constant zero (byte@0x14 zero only 58%). Dominant high byte 0x15=0x96 |
| elem +0x16 | 1 | enumA | in {0..7}: 0(1159),2(584),1(369),3(222),4(90),5(47),6(15),7(3) |
| elem +0x17 | 1 | zero | ==0 (100%) |
| elem +0x18 | 4 | zero | ==0 (99.9%) |
| elem +0x1c | 4 | sentinel C | default `0x3FFFFFFF` (~2.0) in 98% |
| elem +0x20 | 8 | zero | ==0 across 0x20..0x27 (100%) |
| elem +0x28 | 4 | sentinel D (NaN/unset) | default `0x7FFFFFFF` in 99.96% — strongest element invariant (1 counterexample, in one session) |
| elem +0x2c | 1 | enumB / mode | in {1,3,8,9,10,11,35}: 3(1444),1(755),8(243),10(37),11(5),9(4),35(1). Bytes 0x2d..0x2f==0 |
| elem +0x30 | 4 | value0' / range-hi | VARIABLE 32-bit value ending the element. Mirrors elem+0x00 in 40%. Medium |

```
Payload = packed ARRAY of fixed 52-B (0x34) elements; count = payloadSize/52, observed 1 (2443) or 2 (23).
Each element = a parameter/range block with FOUR diagonal 'default/unbounded' sentinel slots:
  +0x08 (0x7F000000, 86%), +0x0c (0x5A000000, 74%), +0x1c (0x3FFFFFFF~2.0, 98%), +0x28 (0x7FFFFFFF NaN, 99.96%).
Zero regions: +0x04, +0x18..0x1b, +0x20..0x27, +0x2d..0x2f, +0x17. Variable value words at the extremes
+0x00 and +0x30 (equal in 40%), +0x10, +0x14 (2-B), plus enums +0x16 (0..7) and +0x2c. No strings/bplists.
count-per-file: min 1, max 51, median 2; corr(count, tracks[karT])=0.57, corr(count, audioRegions[gRuA])=0.24.
```

*Corrections to existing spec:* `elem+0x14` is a variable 2-byte value, NOT a "zero byte + meaningful byte"
(byte@0x14 is zero only 58%); the 104-byte variant's second element carries content values (~`0x64000000`
at +0x08/+0x0c), not the standard sentinels; the subtype high-band is only {0xB0,0xB3,0xB8}, not a full
0xB0-0xB8 band.

*Provenance: production-corpus RE — every header/zero/sentinel field tested on all 2466 records across all 1294
files and 10 versions; one decomposition claim refuted with counts, surviving fields hold at the stated fractions.*

---

## 25. Audio channel objects (`nCuA`) — the third channel-object type

`nCuA` (reversed "AuCn") is the **third member of the channel-object family** alongside `OCuA`
(§15 mixer strip) and `UCuA` (§16 inserts): it carries the same **`magic 0x1235` @payload+0x0a**.
**13 per file** (16809 records / 1293 corpus files); `idx@0x08` is a slot stride of `0x40000`
starting at `0x200000` (`0x200000, 0x240000, 0x280000, …`), `ordinal@0x0c = 0xFFFF0000`, all three
links `0xFFFF`, `classId@0x06 = 14`, `schemaVersion@0x04 = 1`.

| off | sz | field | meaning |
|-----|----|-------|---------|
| pay +0x00 | 4 | formDword | base-struct size, `0xd0` |
| pay +0x04 | 1 | typeEnum | **`0xc0`** on every record — a distinct type band from OCuA's `0x40..0x4c` (§15) |
| pay +0x0a | 2 | magic | `0x1235` — the channel-object family marker (same as OCuA/UCuA) |
| pay +0x10 | 4 | formDword (echo) | repeats `0x000000d0` |
| pay +0x14 | 4 | u32 | `3` |
| pay +0x18 | 4 | u32 | `1` |

One slot (`0x240000` — the same value OCuA/UCuA use for their shared **pool**) carries a much larger
payload (~1.6 KB) than the other twelve (132 B), i.e. the pool slot is the populated one. Carries
**no strings**.

*Provenance: byte layout from the Logic-made repo fixtures (12.0.1 / `cf09`); per-file count and
corpus census (16809 recs / 1293 files) from the production corpus tag inventory.*

---

## 26. Environment layers (`ryaL`)

`ryaL` (reversed "Layr") = the **Environment layer table**. Exactly **1 per file** (1293/1293),
`idx@0x08 = 0x80000`, `classId@0x06 = 14`, `schemaVersion@0x04 = 2`. Its payload is a packed array of
variable-length layer entries — decoding a stock session yields exactly Logic's default Environment
layers: **"All Objects", "Global Objects", "Click & Ports", "MIDI Instr.", "Mixer"**.

```
payload = array of layer entries, each:
  +0x00   4   classTag 0x00000aa0   (a0 0a 00 00 — the layer class tag; see §31)
  +0x04  28   zero / layer params
  +0x20   2   u16 nameLen
  +0x22  len  name (ASCII)
  then pad so that [u16 len + name] occupies an EVEN byte count (pad = 1 if nameLen odd)
entry size = 32 + 2 + nameLen (+1 if nameLen odd); entries run back-to-back to the payload end.
```

*Provenance: fully decoded from the Logic-made repo fixtures (`cf09`) — all five default layers read
back exactly; per-file count (1/file, 1293/1293) from the corpus census.*

---

## 27. Hyper sets (`rpyH`)

`rpyH` (reversed "Hypr") = a **Hyper Set** — the HyperDraw / Hyper Editor event-definition list.
**3 per file** (3619 records / 1293 files), one per default set, keyed by `idx@0x08`;
`classId@0x06 = 15`, `schemaVersion@0x04 = 1`, `ordinal@0x0c = 0xFFFF0000`, links `0xFFFF`.

| idx | set | payload | contents |
|-----|-----|---------|----------|
| `0x000000` | **Automatic** | ~200 B | `Volume` |
| `0x040000` | **MIDI Controls** | ~920 B | `Volume`, `Pan`, `Modulation`, `Pitch Bend`, `Aftertouch`, `Poly Aftertouch`, `Program`, `All Velocities` |
| `0x080000` | **GM Drum Kit** | ~6.2 KB | the full GM drum-name table (`KICK 1`, `KICK 2`, `SIDESTICK`, `SD 1`, `HANDCLAP`, `METROCLICK`, `METROBELL`, `STICKS`, …) |

Event definitions are length-prefixed names (`u16 nameLen` + ASCII) inside elements marked by the
**class tag `0x04b4`** (`b4 04`; see §31). The set's own name appears among the strings alongside its
definitions.

*Provenance: decoded from the Logic-made repo fixtures (`cf09`) — the three sets and their event
definitions read back exactly; counts (3/file, 3619 recs / 1293 files) from the corpus census.*

---

## 28. Score set (`tScS`)

`tScS` (reversed "ScSt") = the **Score Set** — notation/score configuration. Exactly **1 per file**
(1293/1293), `idx@0x08 = 0xC0000`, `classId@0x06 = 14`, `schemaVersion@0x04 = 1`, payload ~3.7 KB
(size stable across the fixtures). The payload opens with the **`0xED99` marker** (u16 @payload+0x00 —
the same magic used by the OgnS container grammar, §22) followed by a flat settings block.

Its ~97 length-prefixed strings (`u16 len` + ASCII) are the score configuration:
- **tablature tunings** — `Guitar`, `Guitar D`, `Guitar G`, `Guitar lo G`, `Guitar D7`, `Guitar CG`,
  `Guitar CD`, `Bass 4`, `Bass 5/C`, `Bass 5/B`, `Bass 6/C`, `Bass 6/B`
- **drum-notation groups** — `Kick`, `Snare`, `HiHat`, `Toms`, `Cymbals`, `Congas`, `Cowbells`, `Bongos`
- `* New Group` placeholders

*Provenance: decoded from the Logic-made repo fixtures (`cf09`); count (1/file, 1293/1293) from the
corpus census. The numeric staff-style / parameter block before the string table is **static
boilerplate** — byte-identical across F0/F21/F23 (a score-config template, not per-session data).*

---

## 29. Named set object (`tSnI`)

`tSnI` (reversed "InSt") — a small **named set object**, **1 per file** (1307 recs / 1293 files),
`idx@0x08 = 0x0`, `classId@0x06 = 2`, `schemaVersion@0x04 = 1`, payload **64 B** (record 100 B).
In stock sessions its name is **"Score Set"** — so it names/anchors the §28 score set rather than
being an instrument, despite the "InSt" reversal.

| off | sz | field | meaning |
|-----|----|-------|---------|
| pay +0x08 | 4 | u16 pair | `0x0010, 0x0010` |
| pay +0x2e | 2 | u16 | `0x0064` (100 = the record's total size) |
| pay +0x34 | 2 | nameLen | u16 length (9) |
| pay +0x36 | len | name | ASCII, NUL-padded — `"Score Set"` |

*Provenance: fully decoded from the Logic-made repo fixtures (`cf09`); count from the corpus census.*

---

## 30. Video (`ediV`)

`ediV` (reversed "Vide") = the **movie/video track state**. Present in **1146 / 1294** corpus files
(absent when a project never had a video), `idx@0x08 = 0x180000`, payload **130 B**.

When **no movie is loaded** the payload is a fixed, essentially all-zero block: `38 00 00 00` at
`+0x00` (0x38 = 56) and `01 00 00 00` at `+0x7e`, everything else zero — an "empty video slot". No
path string is present in that state.

*Provenance: decoded from the Logic-made repo fixtures (`cf09`, no movie loaded); presence count from
the corpus census. **The movie file reference is NOT in `ediV`** — even with a movie loaded, `ediV`
stays this empty form; the reference lives in the `OgnS 0x00FC0000` container (see **§37**).*

---

## 31. Cross-cutting: sub-object CLASS TAGS

Several records embed sub-objects prefixed by a small **class tag** (a u16/u32 that appears to encode
the class's nominal size). Confirmed values so far:

| tag | class | seen in |
|-----|-------|---------|
| `0x28A0` | audio-pool container | §22 `OgnS` (idx 0x01080000) |
| `0x2710` | global / Drummer settings container | §22 `OgnS` (idx 0x00E00000) |
| `0x16006` | reserved block | §22 `OgnS` (idx 0x00F40000) |
| `0x02AC` | movie / video ref container | §22 `OgnS` (idx 0x00FC0000) |
| `0x0AA0` | Environment layer entry | §26 `ryaL` |
| `0x04B4` | Hyper event definition | §27 `rpyH` |
| `0xED99` | sub-block magic accompanying `0x28A0` containers; also opens the §28 `tScS` payload | §22, §28 |

*Provenance: §22 tags from the production-corpus RE; `0x0AA0` / `0x04B4` decoded from the repo fixtures.*

---

## 32. Undo history (`SdnU` / `MdnU`) — legacy (pre-Logic-11) only

The undo stack, stored as two record types (`classId@0x06 = 28`):
- **`SdnU`** (reversed "UndS") = one **undo STEP**. 54960 records / 719 files, **~100 per file**
  (the stack is capped near 100; `percount` peaks at exactly 100). `idx@0x08` is a per-cluster
  stride of `0x40000` (`0x40000, 0x80000, 0xC0000, …`), `ordinal@0x0c = 0xFFFF0000`, links `0xFFFF`.
  Each step carries a **human-readable action name** (ASCII string, e.g. `"Set Beat"`) plus a
  size/handle header (`u32` @payload+0x00, a `0x1243` marker near +0x10, and an id/time field).
- **`MdnU`** (reversed "UndM") = the undo **MASTER/anchor**, exactly **1 per file** (748/730),
  `idx@0x08 = 0`, a fixed **24-byte** payload: `[u16 size=0x18][u16 marker ~0x124b][12× 0]
  [u32 a][u32 a]` where `a` is a step counter/pointer (often 30, sometimes 0).

**⚠️ Reimplementation note — DROPPABLE.** `SdnU`/`MdnU` appear **only in pre-Logic-11 (`*06`)
files** (`ae06/d606/dc06/e106/e606/eb06`) and are **completely absent from the 09-series**
(Logic 11+, `c409/cd09/ce09/cf09/d007`). A modern reimplemented session carries no undo records at
all — so they can be safely omitted when writing (our synthesized `cf09` sessions already have none).

*Provenance: production-corpus RE — 54960 `SdnU` + 748 `MdnU` records; version restriction is a hard split
(0 undo records in any 09-series file).*

---

## 33. MIDI Transform sets (`snrT`)

`snrT` (reversed "Trns") = a **MIDI Transform** parameter set (a Transform-window preset). 530 records
/ 444 files, `classId@0x06 = 10`, `idx@0x08 = 0` (a few at `0x40000`), payload ~468–492 B. Stock
sessions contain the default named **"Transform Parameter Set"** (length-prefixed ASCII @payload+0x9e).

| off | sz | field | meaning |
|-----|----|-------|---------|
| pay +0x00 | 2 | innerSize | u16 payload/class size (~0x3f8) |
| pay +0x02 | 2 | displayFlag | `0x4040` (the same per-object display/enable flag seen in ivnE §19) |
| pay +0x9e | 2+len | name | u16 length + ASCII — `"Transform Parameter Set"` |

*Provenance: production-corpus RE — 530 records; name + `0x4040` flag confirmed across the sample.*

---

## 34. Rare / singleton records

Low-frequency records, characterized from the corpus distillate (byte-level decode is partial for
the opaque ones):

| tag | rev | class | idx | count | what it is |
|-----|-----|-------|-----|------:|------------|
| `dlFA` | "AFld" | 14 | `0xF00000` | 23 / 22 files | a **Track/Folder set** — carries a name string, e.g. `"Multitrack Set 1"` |
| `rteM` | "Metr" | 14 | `0xF80000` | 33 / 23 files | variable-size blob (0 B up to ~111 KB) — a large cached data block, NOT small metronome settings |
| `braC` | "Carb" | 14 | `0x700000` | 4 / 4 files | ~7.4 KB block; role unresolved |
| `pilC` | "Clip" | 7 | `0x0/0x40000/0x80000` | 6 / 2 files | **clipboard** contents (transient); ~85 B, kind-7-like |
| `dirG` | "Grid" | 34 | `0x0` | 1 / 1 file | 36 B grid/quantize settings singleton |
| `ddAG` | "GAdd" | 34 | `0x0` | 54 / 1 file | many tiny (5–20 B) records in a single project; role unresolved |

*Provenance: production-corpus RE tag distillate (counts + header fields exact; payload semantics partial
for the opaque, single-file tags).*

---

## Corpus refinements to §25–§31

Full-corpus verification (1259 files, 11 versions) confirmed the §25–§31 header invariants and per-file
counts, with these version refinements:
- **`ryaL` (§26)** `schemaVersion@0x04` is **version-dependent** (1 on `*06`, 2 on `cf09`), not fixed 2;
  the layer-entry structure and default names are stable across versions.
- **`ediV` (§30)** `schemaVersion@0x04` is version-dependent (3 on the modern corpus majority);
  two payload sizes occur (130 B and 118 B).
- **`tSnI` (§29)** is usually 1/file at `idx 0` named `"Score Set"`, but the corpus also has variants
  at `idx 0x40000/0x80000` with larger payloads (up to ~2.3 KB) — likely other named set/instrument
  definitions; the small `"Score Set"` form is fully decoded, the large variants remain open.

---

## 35. Deep sub-field decodes — refinements to §15 / §16 / §17

Cracked from a targeted corpus re-extraction (full records of the *non-default* cases the stock
fixtures lack): 300 fade-bearing regions, 400 native-plugin slots, 300 non-default channel strips.

### 35.1 gRuA fade descriptor (extends §17)
When a region has fades, its tail carries an **`EDAF`** ("FADE", reversed) descriptor (608 records
corpus-wide — the fade-present anchor). Relative to the `EDAF` 4CC:

| off | sz | field | meaning |
|-----|----|-------|---------|
| EDAF+0x00 | 4 | `"EDAF"` | fade-present marker |
| EDAF+0x10 | 4 | fadeInLen | fade-**in** length, in SAMPLES |
| EDAF+0x14 | 4 | fadeOutLen | fade-**out** length, in SAMPLES |
| EDAF+0x1c | 1 | inCurve | signed fade-in curve shape (`0`=linear; e.g. `0x05`, `0xf9`=−7) |
| EDAF+0x1d | 1 | outCurve | signed fade-out curve shape |
| EDAF+0x1e | 1 | index | fade / take index |

The in/out split is proven by **146 asymmetric** records (e.g. `in=20197 samples, out=0` — a
fade-in only). 108 are symmetric (in==out), 46 carry a zero descriptor (fade slot present, no fade).
Curve-byte census `@EDAF+0x1c`: `0000` (linear, 166), `0505` (81), `0500` (14), `f900`/`00f9` (8 ea).

### 35.2 UCuA loaded-preset filename (extends §16)
For native-plugin `UCuA` slots (KIND 1/2, §16), **`payload+0x0e` is a NUL-terminated preset
filename** naming what is loaded — directly recoverable. Real examples from the corpus:
`#default.pst`, `.default.def`, `Untitled.aupreset`, `0.4s Snare Chamber.pst`,
`SPX90-16-GateReverb.pst`, `Countoff Kit 2.pst`, `CC4 -> CC11.pst` (a MIDI **Modifier**),
`Big Drum.pst`, `Bell Vibes.pst`, `1.8s_Midnight Hall.pst`. A plugin-name string (e.g. `Modifier`)
sometimes follows the preset; then the `GAME` 4CC + an AU parameter blob (plugin-specific, opaque).

### 35.3 OCuA fader/pan on real data (confirms §15)
Verified on 300 **non-default** strips: fader `@pay+0x55` spans `0..127` (`0` = off/muted, very
common on unused strips), pan `@pay+0x59` spans `0..127` (`0` = hard-L, `64` = center, `127` =
hard-R), and the fader mirror invariant `pay+0x55 == pay+0x77` holds **300/300** on real
non-default strips (not just the stock defaults).

*Provenance: production-corpus targeted re-extraction — fade in/out split proven by asymmetric records;
preset filenames read end-to-end; OCuA mirror + ranges confirmed on non-default data.*

---

## 36. qSvE event stride table (extends §3 / §20)

A role-0x17 `qSvE` payload is a sequence of **variable-size typed events** + the 16-byte tail. The
event SIZE is keyed by the status byte `@ev+0x00` and, for notes, the format byte `@ev+0x01`:

| status @ev+0x00 | @ev+0x01 | event | size |
|-----------------|----------|-------|------|
| `0x90` | `0x00` | compact NOTE | **32 B** (two 16-B words) |
| `0x90` | `0x40` | extended NOTE | variable (48/64/80 B); per-note extension words tagged `0x89`/`0xa3`/`0xa4`/`0xa7` `@word+0x07` (§20) |
| `0xB0` | — | Control Change | **16 B** |
| `0xD0` | — | Channel Pressure | **16 B** |
| `0xE0` | — | Pitch Bend | **16 B** |
| `0xA0` | — | Poly Aftertouch | **16 B** |
| `0x50`–`0x57` | — | Logic lane code | **16 B** |
| `0x20` / `0x24` | — | MIDI / audio region PLACEMENT | 80 B (§3 / §8.1) |
| tail | | `f1 00 00 00 ff ff ff 3f 00 …` | 16 B |

**Compact 16-B event fields**: `ev+0x00` status (+ channel in the low nibble), `ev+0x04` u32 position
(region-relative, origin 38400 — §3), `ev+0x0c` data1 (controller #), `ev+0x0b` data2 (value).

**Extended notes** (`@ev+0x01 == 0x40`) = the 32-B compact note **+ 16 B per extension word** (each
tagged `0xa3`/`0xa4`/`0xa7` `@word+0x07`), giving 48/64/80 B (census: 32-B ×1150, 48-B ×44, 64-B ×1).
A variable-stride walk with this rule lands **exactly on the tail for ~246/400** sampled mixed
regions; the residual failures are **sysex** events (status `0xF0`, variable-length — 35 regions) and
a few desync edge cases. **Pure** regions (all-note or all-CC) parse fully. Note byte1 census:
`0x00` (compact) ×1276 vs `0x40` (extended) ×273.

Event-type census (400 sampled controller/automation regions): CC (`0xB0`) 5213, pressure (`0xD0`)
2835, lane (`0x50-57`) 2089, note (`0x90`) 1129, pitch-bend (`0xE0`) 582. Common CC controller
numbers: **1 (Modulation)**, **4 (Foot)**, 0, 64 — decoded values form smooth automation curves
(e.g. a Modulation sweep 71→62→52→38→32).

*Provenance: production-corpus targeted re-extraction (`distill3`) — stride table verified by clean
tail-alignment on the compact case; the extended-note (byte1=0x40) variable length remains the
documented exception (§20). Implemented as `logicx.inspect.region_events`.*

---

## 37. Movie / video reference (`OgnS` 0x00FC0000) — corrects §30

Cracked from a movie-bearing session (10 alternatives, from a client project). **`ediV`
(§30) is NOT the movie reference** — it stays the empty 130-B form in BOTH movie and no-movie
alternatives; it is only video-track *display state*. The movie file is referenced in the **OgnS
movie container, `idx@0x08 = 0x00FC0000`** (§22's fifth role): the container is **present when a
movie is loaded and absent otherwise** (the no-movie alternative has zero such records).

The container payload is an **NSKeyedArchiver `bplist00`** (keys `MovieData`, `FileRef_Bookmark`,
`FileRef_URL`) wrapping:
- a **`file://` URL** — the full movie path, e.g. `file:///Users/<user>/<folder>/<movie>.mp4`;
- a **macOS bookmark / alias blob** (`bookt`): path components (`Users`, the user's short name, …, the `*.mp4`),
  the volume name (`Macintosh HD`) and its UUID, and CNIDs — the standard
  self-healing NSURL bookmark, so Logic can relocate the movie if it moves.

The movie is referenced by **external absolute path** (the bundle's `Media/Movie Files/` is empty).
Decoder: `logicx.inspect.movie_ref(pd)` → `{url, path}`.

*Provenance: one client project (Logic 12.0.1 / `cf09`), all 10 alternatives — movie container
present in the 9 with a movie, absent in the one without; `ediV` empty throughout.*

---

## 38. The SessionModel — port-ready extraction (`logicx.session`)

`session_model(pd)` assembles a **DAW-agnostic model** from the verified decoders — the read side
of a Logic → (Pro Tools / AAF / SMF …) converter. It ties the timeline to every audio and MIDI
region with **absolute position + content + edits**:

```
{ ppq:960, initial_bpm, sample_rate,
  tempo_map:[(tick,bpm)], meter_map:[(tick,num,den)], markers:[(tick,name)],
  tracks:[arrange-track numbers used],
  audio_regions:[{track, position_tick, file, trim_in_samples, length_samples,
                  fade_in, fade_out, in_curve, out_curve, name}],
  midi_regions:[{track, position_tick, notes:[(tick,pitch,vel,len)]}] }
```

**Placement linking.** Region placements are 80-B `0x24`(audio)/`0x20`(MIDI) events scattered across
per-track region-list qSvE (§8.1) — scan ALL qSvE, not one container. The region-reference field
differs by type: **audio → `event+0x2c`//4** = shared region index → `gRuA`/`lFuA`; **MIDI →
`event+0x08`//4** = content-cluster index → the note `qSvE` (idx×0x40000). Position field = `34560 +
tick@960`; note ticks are REGION-RELATIVE (add the placement position for absolute time).

**Markers** (`session.markers`): the marker `qSvE` events start at payload **offset 0** (not 36),
48 B each (`pos = 38400 + tick`, link-id @+0x10); names come from the marker-name `qSxT` RTF
(`\cf2 NAME}`) keyed by link-id @qSxT+0x0a. Verified on F11/F12/F3 and real sessions
(session A → `TOP`/`V1`/`V1A2`/`BR`).

### Status for a DAW port
- **Audio — COMPLETE.** file + timeline position + **trim-in** (§17) + length + fades, per track,
  verified across heavily-edited real sessions (session A 1604 regions, session B 686). This is
  the harder half for stem/audio ports and it is fully solved.
- **MIDI notes — COMPLETE** (byte-exact, §8.5/§36), extracted per region.
- **MIDI region timeline-linking — ~84% (real-Logic multi-region sessions).** The `+0x08` link
  covers 266/317 note regions in session B; the remainder are folder-track / take-folder / alias
  regions and synthesized layouts (F4b) that reference their content cluster differently — there is
  **no single universal link rule** across session structures. Robust fallback for a port:
  Logic → Standard MIDI File (already writable) → the target DAW imports it natively.

### Still-open (minor, not blocking a port)
- **Automation-lane semantics** — controller/lane events decode structurally (§36 `region_events`),
  but the map lane-code → meaning (volume/pan/plugin-param) is not built.
- **Region gain** — no float32 gain field found in `gRuA` (likely an int or stored elsewhere).
- **Sysex `0xF0`** events (variable-length); the universal MIDI-region link above.

*Provenance: `logicx/session.py` + `test_session.py`; audio trim-in verified 2810/2810 (session A); MIDI link 266/317 (session B); markers exact on F11/F12/F3.*


## 39. Byte-coverage push — verified extended fields (extends §8, §15, §17, §18, §19, §21)

*Second-pass deep-decode of the six largest still-unclassified byte regions, run as a 13-agent adversarial workflow (analyze → full-corpus verify → synthesize) over 142 real `~/Music/Logic` sessions and independently re-checked with `logicx.projectdata.ProjectData.parse`. Only fields that reproduced their evidence survived; over-reaching sub-claims were refuted and mis-stated correlates corrected before inclusion. The sub-section numbers below (§8.7 … §21.2) name the parent record each block extends.*

*Provenance: adversarial full-corpus re-verification over 142 `~/Music/Logic` Alternatives sessions (Backups/Autosave excluded). Every field below reproduced its stated evidence on this independent corpus; refuted and over-reaching sub-claims were dropped, and mis-stated correlates/counts corrected before inclusion. Percentages are per-record hit rates on the populated class named in each block.*

---

### §15.4 OCuA extended fields (byte-coverage push)
Channel-strip SETTINGS block, schema 6 (`formDword@pay+0x00 == 0xd8`); verified on **70,177 strips across 142 sessions**. The strip class is fully enumerated at `pay+0x04`, and the volume fader is now understood as a 32-bit fixed-point value whose MSB is mirrored (`pay+0x55 == pay+0x77`, 100%) with the low 3 bytes carrying fractional gain.

| off | sz | field | meaning |
|-----|----|-------|---------|
| pay+0x04 | 1 | typeEnum | Channel-strip class: `0x45` Bus, `0x40` Audio, `0x43` Instrument, `0x44` Output, `0x41` Input-mono, `0x4c` Output-stereo, `0x49` Input-stereo, `0x42` Aux, `0x46` Master. 70177/70177. |
| pay+0x05 | 1 | pad0 | Always `0x00` (70177/70177). |
| pay+0x10 | 4 | formDword_mirror | Exact duplicate of `formDword@pay+0x00` (=`0xd8`, schema-6 base size). 70177/70177. |
| pay+0x4c | 4 | configCapabilityMask | Per-type-**dominant** channel config/capability bitmask. Bus `0xcdd7f5e9` (100%); Audio `0xcfd3f7ab`, Inst `0xcff3f529`, Output `0xedd37749`, etc. (82–97%). Low u16 = "config word" (audio `0xf7ab`, inst `0xf529`). Medium. |
| pay+0x4e | 1 | stereoBit (byte2 of configMask) | Bit `0x04` = **stereo channel flag**; equals `channelCount@0x7b==2` in 99.66%. Bus `0xd7`, Audio `d3`/`d7`, Inst `f3`/`f7`. Correlates with channel COUNT, **not** format@0x56 (the ~4678 mismatches are legitimate stereo-file-on-mono-track strips). |
| pay+0x50 | 1 | stateFlags | Only bits `0x04`/`0x08` ever set; hist `0x00`=66426/`0x08`=2300/`0x0c`=1355/`0x04`=96. Structural flag, semantics unconfirmed (low). |
| pay+0x55 | 1 | fader_coarse | Coarse volume 0..127 (default `0x5a`=90); MSB of the 32-bit fixed-point volume, mirrored at `pay+0x77` (`0x55==0x77` 100%). |
| pay+0x56 | 1 | channelFormat | Format enum 0=mono, 1=stereo, 4=surround. Joint with channelCount@0x7b confirmed (surround pair (4,5)=118). |
| pay+0x5b | 1 | pad1 | Always `0x00` (70177/70177). |
| pay+0x5c | 2 | outputRoutingRef | u16 routing ref keyed by type: source/summing strips carry sentinel `0xFFFF` (Input-mono/stereo 100%, Bus 99.98%); Output/Master/Output-stereo=0 (100%); channel strips 0 (default) or small-int destination. Medium. |
| pay+0x74 | 3 | fader_fractionalPrecision | Low 3 bytes of the 32-bit fixed-point volume. Nonzero ⇒ fader off-default (99.79%, 3391/3398); **NOT** the reverse (5866 off-default strips carry a zero fraction). Not a color field. Medium. |
| pay+0x77 | 1 | fader_volume_MSB | MSB of the 32-bit fixed-point volume; `== fader_coarse@0x55` in 70177/70177. |
| pay+0x7b | 1 | channelCount | 1=mono, 2=stereo, 5=surround. Joint (0x56,0x7b): (1,2)34698,(0,1)30678,(0,2)4561,(4,5)118. High. |
| pay+0x82 | 1 | instrumentChannelMarker | `0x02` **iff** typeEnum==`0x43` (Instrument), else `0x00`. Exact set identity 13055==13055==13055. High. |
| pay[len−17] | 17 | tail (0xFF marker + 16-B UUID) | `0xFF` marker at `len−17` in 70177/70177 across all strip lengths, followed by a 16-byte v1 UUID. Structural tail. |

**Zero-padding / boilerplate now known:** `pay+0x05` and `pay+0x5b` are const-`0x00` (100%). On the 32,873 **base** (169-byte) strips the name-runway `0x2e–0x3b`, plus `0x60–0x61`, `0x6c–0x6f`, `0x72–0x73` are 100% zero and `0x66–0x67` 99.99% zero; `byte 0x71==0x10` is a **base-strip** structural constant (99.82%) that does **not** generalize to extended strips (u32@0x70 varies there). The `0x50`/`0x5a`/`0x68` fields (stateFlags, smallFlagB, opaqueStripId) reproduce their histograms exactly but remain semantically opaque.

---

### §17.2 gRuA extended fields (byte-coverage push)
Audio-region record; verified on **110,732 records, 142/142 files parsed clean**. Tail base = `payload[name_end : name_end+126]`, `name_end = 0x4c + u16len@pay+0x4a` (even). The former "enum @pay+0x11" is dissolved: `pay[0x11]` is provably the **high byte of the u32 anchorOffset@pay+0x0e** (110732/110732).

| off | sz | field | meaning |
|-----|----|-------|---------|
| pay+0x0e | 4 | anchorOffset | LE u32 region anchor/transient reference offset (`pay+0x11` is its high byte, not an enum). Nonzero 71349/110732; > frameLength in 99.88% (a strong tendency, not universal — 89 counter-examples); never `==trimIn+frameLength` (0/71349); sentinel `158760000` (=3600 s × 44100) ×4074. |
| pay+0x02 | 2 | flags16_a | Region flag word: high byte = flag bits (hi `0x10`:53210, `0x28`:20344, `0x90`:6840); the `0x90` family carries a low-byte sub-index; bit12 set in 70774. Exact u16 values differ from family populations (`0x1000` occurs 39133×). Bit→UI names unresolved. |
| pay+0x04 | 2 | flags16_b | Region flag word, zero in 44800; dominant bit9 (`0x0200`) 30991, bit10 (`0x0400`) 20518. Co-varies with regionMode / anchor cluster. Bit names unresolved. |
| pay+0x09 | 1 | flag_minor | Rare enum {0:109287,1:1163,2:282}; 98.7% zero. |
| tail+0x21 | 1 | regionMode | Per-region mode enum {0:75243,1:33472,2:546,3:469,…}; co-varies with anchorOffset!=0 (91.75% when ==1 vs 51.4% when ==0) and flags_b bit9. |
| tail+0x30 | 2 | regionTakeIndex | u16 per-track region/take counter (widened from u8; high byte `tail+0x31` nonzero 6541, range 0..13). Matches the numeric suffix in region display names. |
| tail+0x34 | 4 | takeGroupRef | Reference id shared by sibling take/comp regions; populated 25684, 2358 distinct nonzero, heavy repeats (top 382/300/236). |
| tail+0x38 | 4 | takeSubIndex | Small u32 index {0..4} paired with takeGroupRef; nonzero **exactly** when takeGroupRef!=0 (85048/85048 zero-when-ref-zero, 0 exceptions). |
| tail+0x3c | 8 | takeRef2 (id@0x3c + index@0x40) | Second take-reference slot, same shape as 0x34/0x38; id@0x3c distinct from id@0x34 when populated; index@0x40 census {0:86160,1:7371,3:5863,…}. |
| tail+0x4c | 9 | takeExtraBlock | Third high-entropy comp/take sub-block (`tail+0x4c..0x54`), ~24% populated, terminated by enum `tail+0x54` {0,1,5,17,10,…} (77 distinct). Opaque. |
| tail+0x16 | 9 | smallParamCluster | Sparse small-param cluster `tail+0x16..0x1e` (~2–3% populated; `tail+0x1e` {60:3295,48:16}). Fade/quantize candidate. |
| tail+0x6a | 6 | minorParams | Two sparse trailing param pairs: u16@`tail+0x6a` (nonzero 9622) and u16@`tail+0x6e` (nonzero 12740). |
| tail+0x66 | 4 | link_field | None-sentinel {`0xffffffff`:106545, `0x00000000`:4187} only — not a live cross-reference (matches §17). |

**Zero-padding / boilerplate now known (100% zero, 0 nonzero records each):** `pay+0x01`, `pay+0x0a..0x0d`, `pay+0x12..0x15`, `pay+0x1a..0x1d`, `pay+0x24..0x25`, `pay+0x28..0x29`; and in the tail `0x00..0x15`, `0x18`, `0x19`, `0x1d`, `0x1f`, `0x20`, `0x22..0x2f`, `0x32`, `0x33`, `0x39..0x3b`, `0x41..0x4b`, `0x55`, `0x6c`, `0x6d`, `0x70..0x73`. Note: the **`EDAF` fade descriptor (§35.1) is entirely absent** in this corpus (0/110732 tails), consistent with the always-zero `tail+0x00..0x15` range here.

---

### §18.2 karT extended fields (byte-coverage push)
Arrange/track rows; verified on **142 sessions** (6963 populated arrange rows with record-header `idx@0x08==0x040000`; 11526 channel-pool rows with `idx@0x08==0x080000`; 159 master rows). The arrange-vs-pool split is the **record-header idx field**, not a payload byte. Offsets below are RAW (record start); payload base is `0x24`.

| off | sz | field | meaning |
|-----|----|-------|---------|
| 0x24 | 1 | rowType | Per-row type discriminator: 1=normal (97.7%), 3 (~2%, master/folder), 7, 0. All `0x32==2` rows are rowType 1 (100%). |
| 0x28 | 1 | trackColorIndex | Track color = palette index × 4; decode `paletteIndex = raw[0x28]>>2`. 64-entry palette (63 distinct, 0..252 step 4). 94.5% default 0. **Arrange rows only** — 100% zero on pool + master rows. Confirmed 100% (mult-of-4 invariant). |
| 0x26 | 1 | flagsA (unknown semantics) | Per-track flag; dominant `0x14` (=bits2+4) 75.8%, `0x00` 20.5%, rare `0x16`/`0x15`/`0x01`/`0x1c`/`0x34`. Low confidence — the "channelSlot==0 ⇒ 0" and master/folder-discriminator invariants are refuted. |
| 0x27 | 1 | flagsB (unknown semantics) | Sparse per-track toggle bitfield. 82.3% zero; bits b5(17.2%)/b2(11.4%)/b7(1.3%). Values `0x24`,`0x20`,`0xa4`,`0x04`,`0xa0`. Varies within 52/142 files. Bit→UI mapping unresolved. |
| 0x32 | 1 | trackStateEnum | Per-track 3-state enum {0,1,2}=60.0/29.7/10.3%. Varies within 94/142 files. Pool rows 100% zero. All value-2 rows are rowType 1. Semantic label unresolved. |
| 0x4c | 1 | flagBlockHi | Per-track flag, varies in 142/142 files. 84.3% zero; 100% of nonzero values are high-nibble-only b4–b7 (`0x10`/`0x20`/`0x40`/`0x60`/`0x80`/`0x90`/`0xa0`/`0xc0`/`0xe0`). Pool 100% zero. Function unresolved. |
| 0x4d | 1 | flagBlockB | Per-track flag. 81.6% zero, dominant set bit b7=`0x80` (17.2%), rare low-bit extras (`0x81`,`0x84`,`0x82`,`0x88`). |
| 0x4e | 1 | const0x10 | Near-constant boilerplate; only values {`0x10`,`0x00`}. `0x10` on 96.4% arrange / 98.8% pool. High confidence. |
| 0x4f | 1 | flagBlockC | Per-track flag. `0x0c` (bits2+3) 59.5%, `0x00` 37.7%, `0x4c` 2.0%, `0x40` 0.8%. Low confidence. |
| 0x50 | 4 | outputEndpointRefA | u16 routing ref: `raw 0x50–0x51` pad=`0000`; low byte `raw[0x52]` endpoint slot (`0x50` Stereo Out common, also `0x40`/`0x00`); high byte `raw[0x53]`=`0x07` on 99.3% of routed rows. |
| 0x54 | 4 | outputEndpointRefB | Second u16 routing ref: `raw 0x54–0x55` pad=`0000`; low byte `raw[0x56]`~`0x50` (98%); high byte `raw[0x57]` **toggles** {`0x07` 58.6% / `0x85` 40.4%} — not a fixed `0x07` marker (the earlier "`0x85` at 0x56" reading was a byte-position error). |
| 0x58 | 4 | refTailSentinel | `0xffffffff` on 81.8% of arrange rows, `0x00000000` on ~15%, rare small ints otherwise. Present mainly when the ref pairs are populated. |
| 0x34 | 8 | const8zero | 8 constant zero bytes (`0x34–0x3b`), 100% zero. Boilerplate. |
| 0x3c | 16 | trackUUID | 16-byte random track id (high entropy, opaque) — unchanged from prior spec. |

**Zero-padding / boilerplate now known:** on arrange rows the const-zero bytes `0x2a`, `0x2b`, `0x2e`, `0x2f`, `0x31`, `0x33`, `0x34–0x3b` are 100% zero; `0x25`=99.9%, `0x29`=99.6%; tail pads `0x50–0x51` and `0x54–0x55` are 100% zero. Pool rows additionally read 0 at `0x28`, `0x32`, `0x4c`. The 57-byte-payload trailing byte at `0x5c` is {`0x00`:3923, `0xff`:1534, `0x02`:16}.

---

### §8.7 lFuA extended fields (byte-coverage push)
`AudioFileRef` record; verified on **142 sessions, 17,791 records**. The record carries a plain UTF-8 descriptor and **no macOS bookmark/alias blob anywhere** (0/17738 records contain `book`/`alis`/`bplist`). Reference points: `payload+0x00` (raw+0x24); the `LFUA` sub-header; the `EVAW` container descriptor 4CC (with several fields at negative offsets from it).

| off | sz | field | meaning |
|-----|----|-------|---------|
| payload+0x00 (dup @+0x04) | 4 (+4) | structVersion | Per-file-constant structure/version tag (u32, hi-half always 0), perfectly grouped by `schemaVer@raw+0x04`: `0x1`→{1000,1144}, `0x4`→{880,864,1008}. `payload+0x00==payload+0x04` 17791/17791. |
| payload+0x02 | 2 | poolOrdinalRef | Per-record audio-pool ordinal, value = slot×4 (or `0xFFFF` sentinel), unique within each ProjectData file, often all-zero (50/130 files). Distinct from audioFileID. |
| LFUA+0x04 | 1 | lfuaSubVersion | Const `0x01` (17729/17738). |
| LFUA+0x05 | 1 | lfuaFlag | Flag/enum, 8 values, dominant `0x01` (15077/17738). |
| LFUA+0x07 | 1 | lfuaFlag2 | Mostly `0x00` (17666/17738). |
| EVAW+0x00 | 4 | containerMagic | Reversed container FourCC: `EVAW`(WAVE)=8159, `FFIA`(AIFF)=9535, `ffac`(caff)=44, `' A4M'`(m4a, bytes `20 41 34 4d`)=53. Descriptor layout byte-identical across all four. |
| EVAW−0x1c3 | 1 | containerTypeFlags | Flag byte (not constant): WAV/AIFF {`0x00`,`0x01`,`0x09`,`0x41`}; compressed caff sets bit4 {`0x10`,`0x11`}. Bit 0x10 marks compression, not CAF: PCM CAFs (`mcpl`) carry 0x00/0x01 (§8.9). |
| EVAW−0x142 | 4 | compressionType | Reversed codec FourCC: 0=uncompressed, `PMOC`(COMP)=CAF/ALAC, `fl32`=32-bit float (144 AIFF), `NONE`=2. Also u32 3 = 32-bit float WAV and `mcpl` (`lpcm`) = PCM in a CAF (§8.9). |
| EVAW+0x08 | 4 | firstSampleOffset | The byte offset of the file's first sample (§8.9; 40,037 of 40,037 records checked against their files): the WAV {80,116,4096,44,1024} and AIFF ~512 values are where those files' data starts; 0 for ALAC. |
| EVAW+0x0c/+0x14/+0x18/+0x1a | 4/4/2/2 | frames / sampleRate / channels / bits | Audio descriptor; sampleRate in the valid set for 17791/17791 across all four container formats. |
| EVAW+0x1c | 16 | audioContentHash | 16-byte content hash; ~44% all-zero. Zeros occur **only** under schemaVer `0x4`; schemaVer `0x1` is always populated (3869/3869). Non-zero values collide (2930 repeat). |
| EVAW+0x34 | 4 | smallCount | Small integer, low-skewed monotonic (1:7761,2:3991,3:1154,…). |
| EVAW+0x38 | 4 | audioFileID | **Authoritative** per-file audio-pool ID: unique within every ProjectData file (130/130), 1-based (min==1 all files), contiguous with gaps for deleted files. |
| EVAW+0x4a | 2 | waveformOverviewCacheVal | Cosmetic overview cache, varies widely (2752 distinct values); a writer-clear field. |
| EVAW−0x3e .. −0x33 | 12 | audioFileAttributeFlags | Structured flag block (~220 patterns), not padding; top patterns `030000000002013c…`, `010000000000013c…`, `010000000000020000…`. Partly decoded (§8.9): −0x3d is 2 for float audio; −0x38 is the channel count. |
| EVAW−0x13e | 220 | audioFolderPath | Plain UTF-8 NUL-terminated folder path: `Audio Files` (16945/17791=95.3%) else a real absolute / `~/…` / Apple-Loops path (26 distinct). No bookmark/alias blob anywhere in the record. |
| LFUA+0x40..0x85 (70B) & LFUA+0xea..0x189 (160B) | 230 | reserved-zero (no-bookmark region) | Always-zero runs (17791/17791) — the region where a macOS alias/bookmark would live but does not. |

**Zero-padding / boilerplate now known:** descriptor reserved zeros `EVAW+0x10` (4B), `EVAW+0x16`, `EVAW+0x1b`, `EVAW+0x2c` (8B), `EVAW+0x44` (4B) are 100% zero; the two big no-bookmark runs above and `payload+0x06..07`, `LFUA+0x06`, `LFUA+0x08..09` are 100% zero. **De-listed as padding:** `EVAW+0x3c..0x41` (6B) is only 22% zero (overlaps the live audioFileID/attribute region), and the record-tail `EVAW+0x69..0x77` is only 95.2% zero (breaks on compressed/AIFF records) — downgrade from "always zero" to "mostly zero."

---

### §19.2 ivnE extended fields (byte-coverage push)
Environment objects; verified on **142 sessions, 9471 records, 4,181,989 payload bytes**. The load-bearing key is the **object slot id @pay+0x10** (u16, mult-of-4, unique within file); every `cableRef*` value resolves against it, making the Environment cable graph verifiable. Kind byte @`pay+0x5a`: kind4 (channel strip)=7919, kind2 (system singleton)=714, kind3 (GM/device)=683, kind0/6/255 (folder/terminator)=155. `name_end = 0xa0 + namelen@0x9e`.

| off | sz | field | meaning |
|-----|----|-------|---------|
| pay+0x10 | 2 | objectSlotId | u16 per-record slot id (mult-of-4, unique within file). The slot every `cableRef*` resolves against. |
| pay+0x14 | 2 | cableRef1 | u16 → another object's `pay+0x10` slot in same file. 2544 nz, 2536 resolve (targets kind4:2479/kind2:55/kind3:2), fan-in ≤ 2, 239 self-loops → **serial per-object cable**. Also resolves in kind2 (93/93) and kind3 (165/165). |
| pay+0x26 | 2 | cableRef2 (shared-target ref) | u16 → `pay+0x10` slot, all targets kind4. 2685 nz, 2684 resolve, independent of 0x14 (29 equal), fan-in up to 28 → **shared bus/output-style target**, not a per-object cable. |
| pay+0x96 | 2 | cableRef3 | u16 → `pay+0x10` slot; 1962 nz, 1958 resolve (kind4:1898/kind2:60); equals cableRef1 in ~1009/1962. |
| pay+0x22 | 2 | cableRef4 | u16 → `pay+0x10` slot; rare (131 nz), 131/131 resolve, all kind4. |
| pay+0x3a | 4 | noRefSentinel32 | u32 binary sentinel: exactly `0xFFFFFFFF` (5999) or `0x00000000` (1920), no intermediates. |
| pay+0x74 | 1 | nameEchoFlag | `==0x20` in 1704 kind4 (else 0); gates the 29-B name-echo buffer at `pay+0x75`. |
| pay+0x75 | 29 | nameEchoBuffer | Present iff `0x74==0x20`. **Stale reused buffer** front-overwritten by the display name + NUL; trailing bytes leak the prior occupant (channel-strip default OR patch/plugin name). Non-independent data. |
| name_end+0x05 | 1 | postNameSubForm.a | Serialization sub-form discriminator, complementary with `name_end+0x06`: (a=1,b=0) Form A (3929) vs (a=0,b=1) Form B (3990). `name_end+0x00` nonzero iff Form A. |
| name_end+0x06 | 1 | postNameSubForm.b | See +0x05. Form B tail is exactly 1 byte longer than Form A (A tails {286,287,303}, B tails {287,288,304}). |
| pay+0x2c | 1 | const1Flag | Near-constant enable/valid flag: `0x01` in 7893/7919 kind4, `0x00` in 26. |
| pay+0x3f | 1 | stateFlag3f | Enable/state flag: {1:7208, 0:660, 129:51} (`0x81` = bit7 over base 1). |
| pay+0x2d | 1 | chanConfigEnum | Channel-config/format selector: {3:5367,2:1428,0:686,1:258} + bit6 variants {64,67}. Semantics tentative. |
| pay+0x11 | 1 | objIndex/colorEnum | Low-cardinality per-object index {0:4291,1:2492,2:566,3:335,4:62,5:128,6:45} (value 6 included). Semantics unknown (icon/color/type ordinal). |
| pay+0x50 | 1 | cfgWord50.flag | {0:7533,1:386}; part of a 4-B config slot whose `0x51==0x11` is invariant, `0x52`/`0x53` a high-cardinality param. |
| pay+0x51 | 1 | cfgWord50.const | Invariant `==0x11` across all 7919 kind4. |
| pay+0x9a | 2 | configBitfield9a | Per-object option/routing bitfield: sparse patterns {`0x1080`:1855,`0x2100`:1626,`0x0900`:725,`0x1000`:700,…}. |
| pay+0x5a | 1 | kind | Object-kind discriminator: 4=channel strip (7919), 2=monitor/system singleton (714), 3=GM/device (683), 0/6/255=folder/terminator (155). |

**Zero-padding / boilerplate now known:** kind4 header offsets `0x04`, `0x0c`, `0x12`, `0x19`, `0x1f`, `0x24`, `0x28`, `0x30`, `0x39`, `0x3e`, `0x40`, `0x4f`, `0x55`, `0x5b`, `0x64`, `0x71`, `0x92`, `0x99`, `0x9c`, `0x9d` are 0/7919; constants `0x51==0x11`, `0x54==0x19`, `0x5a==0x04`, and the `0x01`/`0x73` hi-byte `0x06` all hold 7919/7919. Note the `0x3e` false-positive: `pay+0x3e` is always 0 — the apparent "slot-like u16@0x3e" is purely the `0x3f` flag high byte, correctly excluded as a reference field.

---

### §21.2 gnoS extended fields (byte-coverage push)
Root-Song globals, COMPACT/low-region settings blob (`payload 0x24–0x400`); verified on **142 sessions** (all single-`gnoS`; min raw len 3672, so every offset `0x24–0x400` is in-bounds). Authoritative initial tempo is the pair `tB@0xEA == tC@0x3A6` (142/142) — **not** any of the tempo replicas below.

| off | sz | field | meaning |
|-----|----|-------|---------|
| 0xfa | 2 | trackCountU16 | u16 live track count `== (0xf4>>16)`. 142/142; byte `0xfb` always 0. Clean plain-u16 replica of the counter that `0xf4` stores `<<16`. |
| 0xf8 | 4 | trackCountReg2 | Second track-count replica in the HIGH half: `0xf8>>16 == trackCount` (142/142). Low u16 usually 1 (131/142) but 4 or 3 in 11 files — **not** a fixed `\|1`. |
| 0x7e | 4 | globalFlagA | 2-state global boolean {`0x00000000`:84, `0xFFFFFFFF`:58}, 142/142 in-set; per-project (both states in sv3/5/6). Meaning unresolved. **Not** coupled to `0xd2` (joint only 92/142). |
| 0xd2 | 2 | globalFlagA_numeric | Independent 2-state u16 {3840:84, 100:58}, 142/142 in-set. Shares 84/58 marginal with `0x7e` but is uncorrelated with it. Meaning unresolved. |
| 0x1e8 | 4 | globalFloatParam | float32 normalized knob, default 1.0 (128/142); all values in [0.5,1.06]. Level/amount parameter, meaning unresolved. |
| 0x48 | 4 | smallCountA | u32 = `0x01000000\|n`. High byte `0x01` (142/142), bytes `0x49`/`0x4a` always 0, low byte `n` a small count in {0..0x1d}, default 0 (90/142). |
| 0x96 | 4 | tempoSlotD_nonAuthoritative | u32 `round(BPM×1e4)`, byte `0x99` always 0. Fourth tempo replica but **NON-authoritative**: == real tempo (`tC@0x3A6`) in only 77/142, pinned at 120 bpm default in 48/142. Do **not** read initial BPM here — use `tB@0xEA`/`tC@0x3A6`. |
| 0x2e0 | 4 | nestedFrameMagic | Optional nested class-frame magic `0xABC04723` (LE bytes `23 47 c0 ab`) — same magic as payload start `0x24`. Present in 73/142, absent (0) in 69/142. |
| 0xfc | 4 | registryCounter | Large object-registry counter/capacity. Only the TOP BYTE `0x02` is stable (141/142, one `0x03`); second byte varies (`0xC7`/`0xC8`/`0xD8`/`0xE8`…). Not a fixed `0x02C8xxxx` family. |
| 0x1ec | 4 | sentinel_highFFFF | No-link sentinel: upper u16 `== 0xFFFF` in 142/142; low u16 usually 0 (130/142) else `0x0201`/`0x0200`. Full `0xFFFF0000` only 130/142. |
| 0x114 | 4 | const_one | u32 `== 1` in 137/142; terminates the object-registry counter block `0xf4–0x114`. |
| 0x210 | 4 | const_01808300 | u32 `== 0x01808300` in 139/142; mid-payload boilerplate marker. |
| 0x17c | 4 | constFloat_2 | float32 `== 0x3FFFFFFF` (~2.0), bytes `FF FF FF 3F`, 142/142. Fixed boilerplate constant. |
| 0x1d4 | 4 | locatorDefault_8700 | u32 `== 0x00008700` in 142/142 — the invariant template-default slot of the ~`0x1a4–0x1d7` transport-locator block. |
| 0x4b | 1 | const_01 | byte `== 0x01` in 142/142 (top byte of `0x48`). |
| 0x52 | 1 | const_08 | byte `== 0x08` in 142/142. |

**Zero-padding / boilerplate now known:** byte `0xfb` (high byte of the track counter), byte `0x99` (high byte of the `0x96` tempo slot), and bytes `0x49`/`0x4a` (mid-bytes of `smallCountA`) are 0 in 142/142. Constant slots `0x17c` (=~2.0 float), `0x4b` (=`0x01`), `0x52` (=`0x08`) are fixed boilerplate; `0x210` (`0x01808300`, 97.9%), `0x114` (=1, 96.5%), `0x1d4` (=`0x8700`, 100%) are template constants. Within the `0x1a4` locator block only `0x1d4` is rock-solid; `0x1c4==0xA500` and `0x1cc==0xC300` hold only 127/142 (user-modifiable). `0x9a` is an opaque small u16 (cardinality 32, most common `0x50`).


## 40. Native-unknown deep-decode — verified fields (extends §8, §15, §16, §17, §19, §21, §25, §27, §28, §34)

*Third-pass deep-decode of the largest still-unclassified NATIVE byte regions (the external AU/bplist blobs in UCuA/MneG/OgnS excluded). Run as a 15-agent adversarial workflow (analyze -> full-corpus verify -> synthesize + completeness-critic) over 878 unique `~/Music/Logic` ProjectData files (deduped by content hash, 0 parse failures), and independently cross-checked with `logicx.projectdata.ProjectData.parse`. Headline results: the **OCuA->UCuA insert link** (occupancy bitmap), full **UCuA plugin identity** (name + AudioComponentDescription), and the identification of **rteM as the Smart-Tempo beat-analysis JSON cache**. Sub-section numbers (§8.8 ... §34.1) name the parent record each block extends.*

> **Reconciliations (this pass corrects earlier sections):**
> - **EDAF fade descriptor (§17/§35.1) is CORPUS-DEPENDENT.** It appears in 0/1,323,326 gRuA records on the `~/Music/Logic` corpus but was found in 608 records of the 1293-file production corpus. It is a real but session/version-conditional structure — `region_fades()` still decodes it where present; treat its presence as optional, not guaranteed.
> - **lFuA `EVAW+0x08` is NOT constant `0x400`** (§8): it is per-file variable (0x400 only 3.2%; dominant 0x50/0x74). Renamed `formatOverviewParam`.
> - **ivnE `pay+0x58` is a per-FILE constant** (`mixerLayoutSize`), not a per-object size (§19).

All offsets little-endian; tags are reversed 4CCs; payload base = `raw[0x24:]` (pay+0xNN = raw+0x24+0xNN). Adversarially re-verified over **878 unique-by-content-hash `~/Music/Logic` ProjectData files** (0 parse failures). Hit rates are per-record over the stated population. Only fields that survived adversarial verification are listed; refuted sub-claims are noted where they trimmed a surviving field.

### §15.5 OCuA — mixer channel-strip extended config (schema-6, formDword@pay+0x00==0xd8)
Population: 449,249 schema-6 strips across 878 files (4,725,281 insert-slot cells censused).

| off | sz | field | meaning | conf |
|---|---|---|---|---|
| pay+0x84 (raw+0xa8) | arrayLen×4 (u32/slot; slot i at pay+0x84+4i) | insertSlotOccupancyBitmap | u32 array indexed directly by UCuA insert-slot (UCuA raw+0x12). entry[i]==1 iff a UCuA component occupies slot i, ==0 empty. Pure boolean occupancy, never encodes kind — **this IS the OCuA→UCuA link, keyed by slot**. All 4,725,281 cells ∈ {0,1} (4,483,197 zero / 242,084 one); set-bit set == UCuA slot set in 43,658/43,658 joined strips (join key = header ordinal raw+0x0c>>16), 0 mismatches. | high |
| structural: len = 169 + arrayLen×4 | — (length law) | stripLength / insertArrayCapacity | schema-6 payload length fully determined by insert-array capacity. arrayLen = maxUsedSlot+1 (occasionally +2 headroom). len==169 = base/un-activated placeholder, no array (130,802 strips); len==225 = default 14-slot empty capacity (dominant, 245,284). Held 449,249/449,249. | high |
| pay+[0x84+4·arrayLen .. len-17] | 20 | insertArrayTrailer | Constant 20 zero bytes between insert bitmap and the 0xFF+UUID tail. Reserved. All-zero in 449,249/449,249. | high |
| pay+0x5c (raw+0x80) | 2 (u16 LE) | outputRoutingRef (refines §15.4) | Output-bus assignment, type-keyed: Input-mono/stereo & Bus = 0xFFFF sentinel; Output-mono/stereo & Master = 0 (physical out); Audio/Inst/Aux = 0 (default→main out ~88–89%) OR a small-int Aux/Bus destination ∈ {24,31,33,36,37,38,40,55,68}. Audio ==0 in 94,857/106,168; Aux ==0 in 5,660/7,337. | medium |
| pay+0x70 (raw+0x94) | 4 (u32 LE) | typeConfigWord | Opaque type-correlated config/appearance dword (not a cross-reference). Bus 0x00001000 dominant; Audio/Inst default 0x0 plus a populated-strip family {0x118c,0x119a,0x11e3,0x1223,0x1224}. Base-strip byte 0x71==0x10 (§15.4) is its low byte un-extended. | low |
| pay+0x5a (raw+0x7e) | 1 (u8; **size corrected u16→u8**, 0x5b is const-0 pad 449,249/449,249) | stripStateCounter | Small enum/counter ∈ {0,1,2,3,4} (0:385,471 / 2:55,412 / 1:7,590 / 3:772 / 4:4). Bus carries only {0,2}. Co-varies with strip complexity but does **not** partition by a clean automation Read/Latch/Touch/Write mode (refuted). Semantics unproven. | low |
| pay+0x50 (raw+0x74) | 1 (bit0x08) | stateFlags bit0x08 correlation (refines §15.4) | Only bits 0x04/0x08 ever set. bit0x08 set on 34,533 strips, spread across component-count uc=2..7, 100% zero on Bus/Input/Output/Master. Weak tendency toward component presence (99.2% uc≥2) but **not a rule** — 282 strips (0.8%) carry it at uc<2. Candidate's "all at uc=2 / never uc0/1 / 1699×" refuted; only the tendency survives. | low |

**Boilerplate now known:** the 20-byte insertArrayTrailer (all-zero, 449,249/449,249); the tail 0xFF marker @ pay[len-17] + 16-byte v1 UUID (100%, confirms §15.4 at full-corpus scale); pay+0x5b const-0 pad.

### §16.2 UCuA — plugin-insert identity (native framing)
Population: 144,118 kind-1/2 UCuA records (55,421 non-GAME AU slots).

| off | sz | field | meaning | conf |
|---|---|---|---|---|
| pay+0x78 | 12 (fixed, NUL-terminated; name ≤11 chars) | pluginDisplayName | Plugin short display-name string — primary human-readable slot identity for both native Logic and AU/sampler components. Printable NUL-terminated C-string in 144,118/144,118, NUL always before pay+0x84 (0 collisions) → confirms the fixed 12-byte field so the tag at 0x84 sits at a fixed offset. Top: Channel EQ 24,616 · Modifier 20,848 · Sampler 8,387 · Space D 7,062. | high |
| pay+0x84 | 4 (4CC as LE-u32) | containerTag / auManufacturer | Format discriminator at fixed offset. =='GAME' (88,697; 61.5%) → native Logic plugin (name is sole identity). !='GAME' (55,421; 38.5%) → componentManufacturer OSType of an AudioComponentDescription, stored reversed → read as LE-u32 → 4CC (MELC→CLEM Sampler/EXS, VWsk→ksWV Waves, mmkI→Ikmm IK, SLSV→VSLS Vienna, xwrB→Brwx Brainworx). | high |
| pay+0x88 / pay+0x8c | 4 each (LE-u32 → reversed 4CC) | AudioComponentDescription (type, subtype) | Full AU identity for non-GAME slots. type@0x88 = kAudioUnitType (aufx insert-FX / aumu instrument / aumf music-effect); subtype@0x8c = product code. Valid AU type present in 55,004/55,421 (99.25%); triples decode to real plugins (Ikmm/aumf/Atb5=AmpliTube 5, VSLS/aumu/VIN0=Vienna Synchron, ksWV/aufx/LA3M=Waves CLA-3A). **Caveat:** Logic's own MELC/CLEM Sampler stores type=0x00000000 or a small int (0x04/0x05) — the 417 exceptions. | high |
| hdr 0x0c (ordinal>>16) | 4 (u32; strip id = value>>16) | owningStripId → OCuA join | Channel strip owning the insert; strip id = ordinal@0x0c>>16 always matches an existing OCuA strip in the same file (144,118/144,118 = 100%). With slot = link1@0x12 (§16) this fully places the plugin. | high |
| pay+0x0e | var (NUL-term filename) | presetFilename extension → format correlate | Extension correlates with slot format: .aupreset→AU compdesc 28,173/28,173 (100%), .exs→Sampler/EXS 7,023/7,023 (100%), .def→native GAME MIDI plugin 1,222/1,222 (100%), .pst→GAME predominantly (74,908) but 2,206 (2.9%) are AU compdesc, so **.pst is not a pure GAME indicator**. | high |
| ~pay+0xa8 (floats: name_end + trailer) | 4CC '46ia'(=ai64) + u32 len, then body | auPresetBody marker + embedded .aupreset | For AU slots the state follows the 12-byte desc as an embedded .aupreset: '46ia' marker then an XML plist ('<?xml version…'), present/XML-bodied in ~80% of non-GAME AU records (44,244 bodies). Offset floats (name_end-relative), **not** a hard 0xa8. Body opaque per-plugin param state. | medium |

**Boilerplate / refuted now known:** BYPASS is **not** at pay+0x50/0x51 — byte@0x51 is multi-modal {1,2,3,9,8,4,5}, no on/off bimodal (ruled out). subkindMarker@pay+0x76 is a weak/reserved field, no clean format discriminator (0x0000 for all kind-2). pay+0x74 midiPluginClassId (kind-2) **refuted** as identity: zero in 69% of kind-2 records; when nonzero the map is consistent (0x963=Modifier, 0x964=Velocity, 0x965=ChordTrig, 0x960=Scripter) but it cannot serve as a per-plugin id — MIDI-slot identity comes from name@0x78 + .def/GAME framing.

### §17.3 gRuA — audio-region tail params + flag-word semantics
Population: 1,323,326 gRuA records across 878 files. tail = payload[name_end : name_end+126], name_end = 0x4c + u16len@pay+0x4a rounded even. Zero refutations of candidate fields.

| off | sz | field | meaning | conf |
|---|---|---|---|---|
| pay+0x02 (low byte of flags16_a) | 1 | flags16_a low byte = sparse sub-index | NOT flag bits — a sparse sub-index. Zero in 1,104,507/1,323,326 (83.5%); nonzero concentrated in high-byte==0x90 family (58,530/61,427 = 95.3% vs 12.7% elsewhere). High byte carries the region flags (census 0x10:459,031 · 0x28:233,031 · 0x29:77,962 · 0x90:61,427 …). | high |
| pay+0x04 bit9 (0x0200) | 1 bit | flags16_b bit9 = strict superset of flag0@pay+0x00 | Joint (flag0,bit9): (0,0)=561,790 · (1,0)=258,660 · (1,1)=502,876 · **(0,1)=0**. bit9=1 ⇒ flag0=1 in 502,876/502,876, zero exceptions. flag0 broader (761,536) than bit9, so bit9 = flag0 AND (further condition). | high |
| pay+0x04 bit12 (0x1000) | 1 bit | flags16_b bit12 = rare high-regionMode marker | Set in 25,307; 18,699 (73.9%) have regionMode(tail+0x21)≥2 vs 2.12% base = ~34.8× enrichment; conversely 18,699/28,064 (66.6%) of regionMode≥2 set it. Strong, not perfect. | medium |
| pay+0x02 hi bits / pay+0x04 bits | multi-bit | take/comp-membership flag cluster | Correlational (not per-bit-proven). Base tgref!=0 = 0.283, regionMode==1 = 0.413. fa bit14(0x4000)→rm1 0.90/tgref 0.57 (n=196,019); fb bit5(0x0020)→rm1 0.91/tgref 0.61; fb bit7(0x0080)→tgref 0.65; fb bit10(0x0400)→tgref 0.59. Both flag words track take/comp hierarchy position; per-UI toggles not separable. | medium |
| tail+0x21 | 1 | regionMode | Census {0:748,487 (56.6%) · 1:546,775 (41.3%) · 2:9,528 · 3:6,800 · 6:3,145 · 5:3,000 · 4:1,156 · 7:1,056 …}. Flag low bytes ≠ regionTakeIndex@tail+0x30 (fa-low==tkidx 20.4%, fb-low==tkidx 13.16%) → the low-byte sub-index is a distinct counter, not the name take-suffix. | high |
| tail+0x3c vs tail+0x34 | 8 vs 8 | takeRef2 co-allocated with takeGroupRef | (tail+0x3c!=0) == (tail+0x34!=0) in 1,323,326/1,323,326 (100%): both nonzero (374,231; 28.3%) or neither. takeSub@tail+0x38 nonzero when tgref==0: 0/1,323,326. | high |
| pay+0x09 | 1 | flag_minor | Rare enum {0:1,316,415 · 1:5,879 · 2:1,032} = 99.48% zero. Semantics open. | high |
| tail+0x66 | 4 | link_field | None-sentinel, not a live cross-reference: only {0xffffffff:1,270,145 · 0x00000000:53,181}. | high |
| tail+0x16..0x1e | 9 | smallParamCluster | Sparse structured cluster, nonzero in 31,959 (2.42%). Terminator tail+0x1e {0:1,291,399 · 60:31,598 · 48:329}; 0x1a & 0x1b paired (23,230 each), 0x1c (17,532), 0x16 (11,599); 0x18/0x19/0x1d always zero. Meaning open. | low |
| tail+0x4c..0x54 | 9 | takeExtraBlock | Comp/take extra sub-block, nonzero in 852,580 (64.4%). Densest tail+0x53 (507,146), 0x52 (504,797), 0x54 (473,277); terminator tail+0x54 high-cardinality (77 distinct + 850,049 zero). Opaque. | low |
| tail+0x6a / tail+0x6e | 2 + 2 | trailing variable param u16s | Genuine per-region variables (not sentinels): tail+0x6a nonzero 192,536 (14.5%), tail+0x6e nonzero 226,444 (17.1%). Wide flat histograms → continuous quantities (gain/tuning/fade-length candidates). Physical meaning unresolved. | low |

**Refutations now known (spec-affecting):** (1) LOOP is **not** length-derivable — over 553,262 regions whose idx resolves to an lFuA EVAW frame count, frameLength ≤ (fileFrames − trimIn) in 553,262/553,262 (0 overflow, 0 idx collisions across 878 files); loop playback is a flag, not a length overflow. (2) EDAF fade descriptor is **entirely absent** — 'EDAF' in 0/1,323,326 gRuA records. This **contradicts current spec §17** (which lists EDAF at tail+0x12 in 608 records); that 608 figure is from the 1293-file production corpus — on `~/Music/Logic` fades are not stored inline as EDAF. §17 should be reconciled with §17.2/§17.3.

### §8.8 lFuA — audio-file-ref (LFUA sub-header + attr block + EVAW/ffac descriptor tail)
Population: 270,503 lFuA records; **EVAW-anchored fields apply only to the 80,830 descriptor-bearing records** (189,673 = 70% are empty/placeholder refs with no descriptor tail).

| off | sz | field | meaning | conf |
|---|---|---|---|---|
| pay+0x04 | 4 (u32) | structVersion | Build stamp tied to record schemaVersion@raw+0x04 (Logic version), NOT a size. Clean partition over all 270,503: schemaVer1→{1000:139,530 · 1144:2,217}; schemaVer4→{1008:64,629 · 880:62,694 · 864:1,433}. | high |
| pay+0x00 | 4 (u32) | poolObjectHandle | Self/pool handle. ==pay+0x04 in 115,686/270,503 (42.8%); in the large-value regime pay+0x00 = idx(raw+0x08) + 263,144 (=0x403E8) in 137,869 records. pay+0x06 high16 = 0 in all 270,503 → confirms u32. | medium |
| LFUA+0x05 | 1 (u8) | audioFileTypeFlags (bitfield) | Per-bit over 270,503: 0x01=90.3% · 0x08=4.1% · 0x40=1.8% · 0x10=0.1%; 0x02/0x80 never set. **bit0x10 ⇔ descriptor magic 'ffac' (CAF/ALAC): 261/261, 0 mismatches over 80,830.** Refined (§8.9): it marks compression — PCM CAFs (`mcpl`, 15 records) carry 0x00/0x01. This byte IS EVAW-0x1c3 in all 80,830 descriptor recs — generalizes §8.6's single-fixture type flag. | high |
| LFUA+0x0a | var (NUL-term ASCII) | filenameAscii (optional redundant copy) | LFUA body [LFUA+0x08 .. EVAW-0x13e) all-zero in 61,207/80,830; nonzero in 19,623, each an ASCII basename starting at LFUA+0x0a (e.g. 'VOX SCRATCH#01.wav'). UTF-16LE master remains the len-prefixed string at pay+0x08. | high |
| EVAW-0x3e | 4 (u32) | audioFileAttrFlagsA (bitfield) | bit0x01 set in all 80,830 (every value odd). By bit-depth: 16b→{1,3,5,7,19}; 24b→{1,3,0x103,5,9}; 32b→{0x203,0x201}. High bits track bit-depth; individual bit semantics beyond that unproven. Byte +1 = 2 marks FLOAT audio (114 of 114 float records; every 32-bit record here is float) (§8.9). | medium |
| EVAW-0x38 | **2 (u16 — corrected from u32)** | channelCount | overviewMarker | low byte = channel count; high byte = 0x3c 'overview/analysis cache present' marker (else 0x00). Values 0x0001/0x3c01 (1ch), 0x0002/0x3c02 (2ch). u16 at EVAW-0x36 is const 0 (all 80,830), refuting a u32 framing. High-byte-0x3c count = 43,714 = **exactly** the EVAW+0x5c-nonzero count. | high |
| EVAW+0x04 | 4 (u32) | audioChecksum (optional) | =0 in 78,663/80,830, nonzero in 2,167; zero is valid (matches §8). | medium |
| EVAW+0x08 | 4 (u32) | formatOverviewParam | **Per-file variable — refutes spec §8's "≈const 0x400":** 0x50:36,889 · 0x74:30,487 · 0x2c:4,386 · 0x1000:4,279 · 0x400:2,563 (only 3.2%!) · ffac→0x00:261. **Explained (§8.9): it is the byte offset of the file's first sample** — each value is where that file's data starts; 0 for ALAC. | high |
| EVAW+0x1c | 16 | audioFileID (UUID) | Nonzero in 55,363/80,830 (68.5%). Largest cluster has bytes 6–7 = 0x11 0xef (UUIDv1 version/time-hi marker, same family as gRuA region UUIDs) — 20,471 recs; remainder other UUID variants. | high |
| EVAW+0x4a | 4 (u32) | waveformOverviewCacheVal | Highly dispersed per audio file (1,713 distinct); cosmetic Logic-regenerated overview cache — the byte §8 requires cleared when synthesizing. | high |
| EVAW+0x5c | 8 | secondaryOverviewCache | Nonzero in 43,714/80,830 — count **exactly matches** the EVAW-0x38 high-byte=0x3c gate. High-entropy secondary peak/overview cache. | medium |
| EVAW+0x7a | — (record end) | recordEnd / descriptorTailLen | len(raw) − EVAW_offset = 122 in 80,830/80,830: the descriptor+tail is a fixed 122 bytes. | high |
| whole record | — | NO macOS bookmark (proof) | Zero occurrences of book/alis/bookmark/kcob/sila magics across **all 270,503** lFuA records → lFuA is fully synthesizable, confirming §8. | high |

**Boilerplate now known:** LFUA+0x04 = const 1 (270,071/270,503); LFUA+0x06 = const 0 (all); LFUA+0x07 = rare status flag (451/270,503). Reserved-zero regions each 80,830/80,830: [EVAW-0x62,-0x3e) 36B, EVAW-0x34 (u16), EVAW-0x36 (u16), EVAW+0x10 (frames→rate gap), EVAW+0x2c (8B, UUID tail), EVAW+0x42 (before-cache). Low-confidence tail ints EVAW+0x34/0x38 (small ints, no clean correlation) and float EVAW+0x46 (0 in 79,702; else 8/16/32f overview param) noted but not spec-load-bearing.

### §19.3 ivnE — Environment-object config
Population: 79,250 ivnE records (kind4=69,433, kind2=4,496, kind3=4,546).

| off | sz | field | meaning | conf |
|---|---|---|---|---|
| pay+0x72 | 2 | defSizeEcho | u16 second copy of class nominal defSize@pay+0x00 (derived boilerplate, not this record's own size). ==u16@0x00 in 69,433/69,433 kind4; high byte 0x73==0x06 in 69,433/69,433. | high |
| pay+0x2d | 1 | chanStripType | Channel-strip role enum (kind4 only; 0 in all kind2/kind3). **2 = Audio/Output/StereoOut, 3 = Software-Instrument (dominant, 49,269), 0 = Aux/Bus/Master/Prelisten/Click (summing/utility).** Global {3:49,269 · 2:11,999 · 0:5,259 · 1:1,284} + bit6 variants {64,67}. Corrects candidate: Output/StereoOut are 2, not 0. | high |
| pay+0x60 | 1 | objFlags bitfield | Per-object option flags. bit3(0x08) gates the name-echo buffer: 99.1% of bit3-set carry 0x74==0x20 and 99.2% conversely (16,454 joint of 16,597/16,591). Dist {0:45,738 · 8:16,543 · 128:3,671 · 64:2,876 · 2:294 · 192:188}. | high |
| pay+0x94 | 2 | iconId (role-correlated) | Channel-strip icon/type id. Nonzero in 69,433/69,433, ≠defSize (0/69,433), ≠len(pay) (0/69,433). Role-correlated (Inst 0x118c, Aux 0x119c, Master/Output/Prelisten 0x119a, Click 0x1199, Audio 0x1223); hi-byte@0x95 ∈ {0x10,0x11,0x12}. Exact icon-catalog map unproven. | medium |
| pay+0x9a | 2 | configBitfield9a | Per-object routing/option bitfield. bit0x0008 = 'is a signal source' (P(set|nameEcho)=0.726 vs 0.174 base; never co-occurs with cableRef1, P=0.000). bit0x0800 = 'shared-target/side-chain' (P(set|cableRef3!=0)=0.652). Top {0x1080:15,094 · 0x2100:13,162 · 0x1000:7,372 · 0x2104:6,418 · 0x900:4,560}. | medium |
| pay+0x54 | 2 | canvasX (Environment position) | u16 x-position on the Environment canvas. Real per-object data for system (kind2) objects; auto-laid-out constant for kind4 strips (0x54==25 in 69,433/69,433). Candidate's per-name coordinate table refuted; field holds. | high |
| pay+0x56 | 2 | canvasY (Environment position) | u16 y-position. Per-object for system/kind2. In kind4 mostly 0x40 (67,878) but 0x42 in 1,555 — minor real variance, not fully constant. Measured kind2 (x,y) near-fixed per object across 878 files (see below). | high |
| pay+0x58 | 2 | mixerLayoutSize (per-file constant) | u16 mixer-layer layout/size param, identical for every kind4 strip within a file, varying file-to-file. 0/878 files have >1 distinct value among kind4; 16 distinct corpus-wide {0x223,0x212,0x201,0x1ce,0x1df …}. **Refutes §19's "size, per-object."** Exact quantity unproven. | medium |
| name_end+0x00 | 2 | postNameFrame discriminator (Form A/B) | Clean byte test for post-name serialization sub-form: name_end+0 nonzero ⇔ Form A (35,730/35,730), ==0 ⇔ Form B (33,702/33,702). Only 1 of 69,433 outside {A,B}. Sharpens §19.2 to a 100% test. | high |
| name_end+0x05 / name_end+0x06 | 1 + 1 | postNameSubForm (per-object) | Serialization sub-form chosen per object, independent of schema version, kind, chanStripType, and plugin presence. Both forms co-occur in 878/878 files; no version dominance (sv11 20,005A/14,547B). Form B tail is 1 byte longer than Form A. | high |
| raw+0x04 (schemaVersion) | 2 | sv8 generation (adds to §19 sv map) | A schemaVersion 8 exists that §19's sv→root map omits: 526 ivnE (449 kind4) with defSize@0x00==1744 uniformly, ordering sv6(1696) < sv8(1744) < sv11(1752). | high |
| pay+0x5a (kind2/kind3) | 1 | kind2/kind3 identity | kind3 = context/device stubs ('@ (=Context Name)':3,200 · '(Folder)':873 · 'No Output':236 · 'Not Assigned':160 · 'GM Device':77). kind2 = the 5 system singletons each 878/878 (MIDI Click, Sequencer Input, Physical Input, Input View, Input Notes) PLUS '(Channel Splitter)':53 and '(Transformer)':53. Both kinds 0x2d==0, 0x18==0; 0x2c==1 in 4,486/4,496 kind2. | high |
| pay+0x11 | 1 | objIndex/colorEnum (role scoping) | Low-cardinality per-object index. Nonzero concentrated on user Audio/Inst/Aux; predominantly 0 on system strips but not strictly (Master 0 in 878/908 with 30 exceptions; Output/Prelisten/StereoOut 100%). color-vs-group-vs-order meaning unresolved. | low |

**Corrected kind2 canvas (x,y) table (near-fixed across 878 files):** Sequencer Input=(86,25) 878/878 · Physical Input=(13,210) 878/878 · Input Notes=(188,406) 825/878 · Input View=(86,80) 716/878 · MIDI Click=(7,25) 716/878. (The candidate's per-name assignments were cross-rotated between objects and are refuted; the underlying distinct-per-object position field survives.)

### §21.3 gnoS — root Song record tail (payload ≥ pay+0x400)
Population: 241 COMPACT sv3 gnoS (payload 3716B) + 637 SETTLED gnoS (>3716B). Offsets payload-relative.

| off | sz | field | meaning | conf |
|---|---|---|---|---|
| pay+0x414 | 4 | constFloat2p0_replica | Template-constant float32 ~2.0 (0x3FFFFFFF); boilerplate replica of the §21.2 constFloat_2 at 0x17c. 237/241, else 0. | high |
| pay+0x400 (frac) / pay+0x404 (whole) | 8 (32.32 ticks) | transportPositionArray_head | Leading 32.32 fixed-point TICK position immediately before the main tail array. whole@0x404 distinct=44 (bar-aligned ~0x4fb00), frac@0x400 {0:206 · 0xa0000000:23 · 0x36660000:9}. Likely a locator/loop edge. | medium |
| pay+0x438..0x470 | 7 slots × 8B (32.32 ticks); frac@0x438/40/48/50/58/60/68, whole@0x43c/44/4c/54/5c/64/6c | transportPositionArray | Independent transport/locator array of 64-bit 32.32 fixed-point tick positions. Variable per-project whole-tick slots at 0x43c (distinct 33), 0x444 (54), 0x454 (82) = cycle/punch/song-end (exact roles unresolved). Slots 0x45c/0x464/0x46c hold the template-default triple 0xA500/0xC300/0x8700 (fraction words 0x458/0x460/0x468 always 0). 32.32 confirmed: nonzero fraction never accompanies a round whole (fnz&round=0 all slots). | medium |
| pay+0x478 | 4 | transportEnableA | 2-state enable (cycle-on or autopunch-on): 0xFFFFFFFF=on (215/241) / 0=off (26/241). | low |
| pay+0x47c | 4 | transportConfigFlags | Config word of form 0x00010000 | lowbyte. High u16 == 0x0001 in 237/241. Modes 0x00010000:106 · 0x0001000a:49 · 0x00010006:22 · 0x00010009:21. | low |
| pay+0x480 | 4 | transportFloatParam | float32 knob, default 1.0 (232/241), alt 0.7 (9/241). Metronome/varispeed candidate; unproven. | low |
| pay+0x484 | 4 | transportFlagLowWord | 2-state; upper u16 const 0xFFFF (invariant), lower u16 = 0x0000 (140) / 0x0200 (101). | low |
| pay+0x4a8 | 4 | state2_word_A | **Refuted as a constant** — bimodal 2-state: 0x01808300 (119) vs 0x01008300 (118), differing only in bit 0x00800000. Pairs with pay+0x4ac (0x01010807:123 vs 0x00000000:118); likely a version/state gate, not boilerplate. | low |
| pay+0x9b8 | 4 | structConst_0x48 | Const 0x00000048 in 235/241 (else 0xffffffff:4, 0x40:2) marking a small tail config struct (~0x978–0x9c4). Adjacent pay+0x9c0 = small variable count (distinct 35). | medium |
| pay+0xa30 (signed low-u16) / pay+0xa58 | 4 + 4 | signedOffsetField_tuningCandidate | pay+0xa33 high byte const 0x54 (241/241); pay+0xa30 signed low-word {0:218 · -8:17 · -6:6}; companion pay+0xa58 high-u16 0x8a06 (229/241). Small signed offset (global transpose / master-tuning cents candidate), bracketed by constants; meaning unproven. | low |
| pay+0xe10 (id) / pay+0xe14 (terminator) | 4 + 4 | tailIdBlock | High-cardinality 32-bit id at pay+0xe10 (distinct 71/241, near-unique; save-serial/content-hash candidate); block always terminated by const 0x0B000002 at pay+0xe14 (241/241). | low |
| pay+0x400.. (SETTLED, size>3716) | variable (scales with object count) | settledExtension_objectRegistry | The SETTLED-form extension past 0x400 is the gnoS object registry (regenerated on load), NOT new globals. Byte size correlates with object count: corr(size,records)=0.91, corr(size,tracks)=0.929 over n=637, ~7.54 bytes/record. Rows are a **16-byte stride** [u32 typeTag ∈ {0x20,0x21,0x23}][u32 link/index, +4 increments][8-byte tagged-pointer]; block terminates with typeTag 0x23 + 0xFFFFFFFF sentinel + zero pad. | high |

**Refutations now known:** (1) nestedFrameMagic 0xABC04723 occurs ONLY at pay+0x00 (241/241) and pay+0x2bc (11/241) in compact — **zero occurrences at pay≥0x400**; tail transport/locator data and the settled registry are raw binary, not nested frames. (2) The tail locator block is **not** a byte-copy of the compact block: per-file equality of tail 0x45c/0x464/0x46c vs compact 0x1c4/0x1cc/0x1d4 = 0/241 (caveat: compact 0x1c4 is itself a float32 1.0/0.7, so the compact side is not the §21.2 locator triple). (3) Candidate's settled 24-byte / 16-byte-UUID stride is refuted (true stride is 16B with an 8-byte tagged-pointer, and typeTag 0x20 is present, not just 0x21/0x23).

### §25.1 / §27.1 / §28.1 / §34.1 — small-record fields (nCuA, rpyH, tScS, rteM)

#### §34.1 rteM — Metro/SmartTempo beat-analysis cache
Population: 106 rteM records / 106 files (49 empty payloadSize=0, 57 nonzero).

| off | sz | field | meaning | conf |
|---|---|---|---|---|
| whole record (hdr sv1 cid14 idx0xF80000 ordinal0xFFFF0000, const across all 106) | var 0..~111KB | rteM = SmartTempo 'Metro Result' cache (zlib or raw JSON) | Compressed (55 zlib, 0x789c@pay+0x18) or raw (2) 'Metro Result' beat-detection JSON; all 57 decompressed bodies start `{"version":2,"initial":{…}`. **Not tempo/meter settings.** | high |
| pay+0x00 (u16) / pay+0x04 (u32) | 0x18-byte header | variable-length size header + reserved zeros | If payloadSize<0x8000: pay+0x00=payloadSize, pay+0x04=0 (27/27). Else pay+0x00=sentinel 0xED99, pay+0x04=payloadSize (30/30). pay+0x02/0x08/0x0c/0x14=0 (reserved, 57/57). Body starts pay+0x18. | high |
| pay+0x10 | 4 | unresolved small per-record value | Varies 0..228; no correlation to size/compression/JSON length. Opaque. | low |

#### §25.1 nCuA — channel-object stub + pool
Population: 10,536 nCuA stubs + 878 pool records.

| off | sz | field | meaning | conf |
|---|---|---|---|---|
| pay+0x16 | 2 | channelSlotIndex | High word of pay+0x14 dword = channel-object slot number; low word (pay+0x14) = const 0x0003 (10,536/10,536). Slot values 0,2,3,…,12 (value 1 skipped). Perfect idx→slot 1:1 map (878 each). | high |
| pay+0x00 (echoed pay+0x10) | 4 | formDword base-struct size (per-file const) | Base-struct size echoed at pay+0x10 (==pay+0x00 in 10,536/10,536); per-file constant ∈ {0xB0(6,528), 0xD0(3,948), 0x88(60)}. | high |
| pay+0x04 / 0x08 / 0x0a / 0x18 / 0x4c | 2–4 each | typeEnum, flag, magic, stub boilerplate | pay+0x04=typeEnum const 0xC0; pay+0x0a=magic 0x1235; pay+0x08(u16)=0(10,428)/1(108); pay+0x18=const 1; pay+0x4c=const 0x00015100. Rest of 132B stub zero. All 10,536/10,536. | high |
| pool idx 0x240000, pay+0x0e (u16) | 2 (**corrected from 0x0c**) | pool channel-object container; count-like field | idx 0x240000 is the sole large nCuA per file (878/878), reuses formDword@0x00 / typeEnum 0xC0@0x04 / magic 0x1235@0x0a. Count-like field is at pay+0x0e (u16), **not** pay+0x0c (const 0): variable {0x03EA(1002):584 · 0:185 · 0x100:109}. | medium |

#### §28.1 tScS — score-config template
Population: 878 records, payloadSize=3752 const, idx=0xC0000. Two states: 629 populated / 249 name-zeroed.

| off | sz | field | meaning | conf |
|---|---|---|---|---|
| whole record | 3752 (const) | fixed 3752-byte score-config template | Byte-stable fixed-layout template with fixed-offset null-padded name slots (Guitar@0x34, Kick@0x41a, Snare@0x426) — **not** a packed length-prefixed table (corrects §28). name@0x34 = 'Guitar'(629)/zero(249). | high |
| pay+0x4c,0x8a,0xca,0x10a,0x14e,0x190,0x1d2,0x214,0x252,0x292,0x2d2,0x312 | 9–16 B/slot | tablature tuning MIDI-pitch arrays | Each tab-tuning slot holds a fixed-width MIDI-pitch array varying per session (real user data). e.g. 0x4c = 52,57,62,67,71,76,81,86 (472) or std 6-string 40,45,50,55,59,64 (396); 0x214 = bass tunings. Each slot distinct=4 with the 472/396 split. | high |
| pay+0x17 (byte) | 1 | version/mode flag | = 1(474) or 4(404), orthogonal to population. Cross-tab {(1,pop):474 · (4,pop):155 · (4,empty):249} exact. | high |
| pay+0x8a4 (RGB) / pay+0x8e4 (Color-N names) | ~32B RGB + name slots | score color table | RGB table at pay+0x8a4 is **template-constant** (876 identical + a 2-file 16-bit-per-channel variant), NOT population-split (corrects candidate). Only the 'Color 0'..'Color 15' NAME slots (from pay+0x8e4) are gated by the 629/249 population. | medium |

#### §27.1 rpyH — hyper-set definitions
Population: 3 rpyH per file × 878 (Automatic / MIDI Controls / GM Drum).

| off | sz | field | meaning | conf |
|---|---|---|---|---|
| idx 0x0 / 0x40000 / 0x80000 sizes | per-set 200/920/1018/6194 B | 3 hyper sets with version-dependent idx ordering & sizes | Exactly 3 rpyH/file. idx ordering & sizes split along a 404/474 fault line: idx0 {1018:474 · 200:404}; idx0x40000 {6194:472 · 920:404 · 6322:2}; idx0x80000 {200:474 · 6194:404}. All 878 files, hdr (sv1,cid15). | high |
| element open tag 0xB4 0x04; u16-len-prefixed canonical name | element ~0x62 B | hyper element structure (offsets corrected) | Elements opened by class tag 0xB4 0x04 with u16-length-prefixed canonical names (Volume len 6). In the 200B Automatic set: b404 tags @{0x00,0x62}; Volume@0x5c (len prefix 0x0600 @0x5a); 'Automatic'@0xbe. Candidate's name@0x54 / b404@0x5c / label@0x3a / grid-pen@0x4a do NOT reproduce. | low |

**Refuted (spec-affecting):** the rpyH event-name vocabulary (Aftertouch vs Ch./Poly Pressure) does **not** align with the 404/474 rpyH size-family. Cross-tab: famB(474)=all Ch. Pressure/populated, but famA(404) splits into 249 Aftertouch/empty + 155 Ch. Pressure/populated. Vocabulary tracks the **separate 249/629 axis** (= tScS Guitar-population), not the 404/474 axis. There are at least **two independent version axes** — 474/404 (rpyH set sizes/ordering, tScS pay+0x17) and 249/629 (tScS Guitar-population, rpyH event vocabulary) — which prior work conflated. 'Aftertouch' present in exactly 249 files, 'Ch./Poly Pressure' in 629.


## 41. Take folders, Quick Swipe comps, and sequence regions (controlled-save RE)

*Provenance: controlled Logic 12.2 saves made by driving Logic directly — `fixtures/TAKES3.logicx`
(9 project alternatives, one change each: three tracks → Pack Take Folder → Quick Swipe → Duplicate
Comp → switch comp → rename → move → Flatten) and `fixtures/TAKES.logicx` (3 stacked regions →
single-take pack). Source audio = `fixtures/comp_src/take1/2/3.wav` (220/330/440 Hz, 4 bars @120,
44.1 kHz). Each pair diffed with `tools/altdiff.py`; the model was then validated on real sessions
(session C: 13 folders / 106 sections; session B2: 31 folders). Decoder: `logicx.takes`;
tests: `test_takes.py` (30 assertions, incl. "Logic's own Flatten == our decoded comp").*

### 41.1 Every `0x20` placement is a *sequence region*
A `0x20` placement's **`+0x20` / 4 is a CHILD sequence index** (the `qeSM`/`qSvE`/`karT` records
with `idx@0x08 = child << 18`). The child is one of:

| child | how to recognise it |
|---|---|
| MIDI region content | child `qSvE` holds note/controller events (§36) |
| automation holder | child `qeSM` is named `*Automation` (these placements sit in the automation root sequence) |
| **take folder** | child has lane `karT` rows of rowType 1/6 (§41.3) |

The child link resolves **527/527** `0x20` placements on session B2 and reaches **318/318** note
sequences. This replaces `+0x08` as the MIDI content link (`+0x08` is 0 on synthesized regions,
e.g. F4b) and closes the old "MIDI linking ~84%" item: the rest were folders and automation, not
unlinked regions. Placement `+0x0c` bit `0x400` is set on ordinary MIDI regions too — it is **not**
an automation marker.

### 41.2 Placement fields (refines §3 / §8.1)
| off | sz | field |
|---|---|---|
| +0x00 | 4 | status `0x20` (sequence region) / `0x24` (audio region) |
| +0x04 | 4 | position = 34560 + tick (in a take folder: **folder-relative**) |
| +0x0c | 4 | flags: `0x80000000` selected, `0x00000100` folder expanded, `0x00200000` folder has a comp, **`0x10` not audible** (inactive take / inactive comp lane) |
| +0x10 | 4 | channel object = ivnE slot × 4 (all lanes of a folder use the parent track's) |
| +0x14 | **2** | **track (u16)** — real sessions exceed 64 (session B2: 139); in a take folder = lane |
| +0x17 / +0x37 | 1 / 1 | constant word tags `0x89` / `0x8a` — the reliable placement anchor (2183/2183 over 70 sessions) |
| +0x20 | 4 | child sequence × 4 (`0xFFFFFFFF` = none) |
| +0x28 | 4 | **region number k** within the file's region cluster (audio) |
| +0x2c | 4 | file index × 4 (audio) |
| +0x42 / +0x43 / +0x48 | 1/1/4 | comp crossfades: `+0x42 0x80` crossfade-in (active comp only), `+0x43 0x05` on non-final sections, `+0x48` = `0x14` non-final / `0x0a` final |
| +0x44 | 4 | word tag: `0x88000000` sequence region, `0x89000000` audio |

An audio placement resolves to **`gRuA(idx = file << 18, ordinal = k << 16)`** — 100% on 3 real
sessions, all within file bounds; `(k−1)` misses. Resolving on the file index alone (as
`session_model` did before) picks an arbitrary sibling: 341/451 regions of session C were wrong.

### 41.3 Take-folder anatomy
The folder is a `0x20` placement on the track; its child sequence is a mini-arrangement whose
"tracks" are **lanes**:

- **Lane rows** — `karT` under the child idx, in order; header `+0x12` = 0-based lane index;
  **rowType raw`[0x24]`: 1 = take lane, 6 = comp lane**; raw`[0x27]` bit `0x08` = lane inactive,
  raw`[0x4f]` bit `0x04` = active; a `+0x12 = 0x7fffffff` stub ends the list. Empty take lanes
  persist after their takes are deleted.
- **Lane content** — `0x24` placements with track = lane, folder-relative positions.
- **Takes** — ordinary regions; gRuA `tail+0x6e` = **take ID**; `flags16_b` low byte = the take
  number Logic displays (`3 - take1`).
- **Comps** — one comp lane per comp; **letter = order among comp lanes** (A, B, …), stable across
  renames. Each **section is a separate gRuA cut from the source take** (its trim/length *are* the
  section), named after the comp (`Comp A`, or the user's name — Rename Comp renames every section
  region); `tail+0x6a` = **source take ID**; `tail+0x36` / `tail+0x3e` = section `[start, end)` in
  absolute event ticks — a cache rewritten when the folder moves, whose origin shifts with the
  project start (session C: +3840), so only its span is trusted. Sections abut exactly: start + length
  (at the real tempo) = next start, on every real section checked.
- **Active comp/take** is redundant in four places that flip together: placement `+0x0c` bit `0x10`,
  gRuA `flags16_b` bit `0x0200`, lane `karT` raw`[0x27]`/`[0x4f]`, and the crossfade markers.
- gRuA `flags16_b` bit `0x1000` = region belongs to a take folder; `tail+0x21` regionMode = 1 there.
- Folder `qeSM pay+0x24` = 60 × lane count (view height).

| action | what changes |
|---|---|
| Pack Take Folder (regions on N tracks) | N placements → one `0x20` folder placement; new child seq + N lane rows; takes get `flags16_b 0x1000`, take IDs, numbers |
| Pack 3 *exactly overlapping* regions on one track | only **one** take is packed (TAKES a01) |
| Quick Swipe | new comp lane; one new gRuA per section in each source file's cluster (k = next free); lFuA region count +1 |
| Duplicate Comp | another comp lane + its sections; old comp's lane gets the inactive bits |
| Switch comp | only the active flags move |
| Move folder | only the folder placement's position + the sections' absolute-bounds cache |
| Flatten | folder → plain `0x24` placements of the active comp's sections at absolute ticks, renamed `<track>: <comp>`; each gets an empty child seq; inactive comps' regions are deleted |

Logic's own **Flatten** output equals `takes.playing_regions()` of the pre-flatten folder,
sample for sample (`test_takes.py`). The take-folder menu also offers **Unpack to Track
Alternatives** — Logic's built-in folder→alternatives conversion, the cross-check for §41.5.

### 41.4 Pro Tools mapping
A comp **is** a list of clips cut from the takes (= a PT comp/main playlist), and each take lane
is an alternate playlist. `takes.playlists(folder)` emits exactly that: one playlist per comp and
per non-empty take, clips at absolute ticks with file / trim / length, `main` = what Logic plays.
`session_model()` now exposes them as `take_folders`, excludes lane internals from
`audio_regions` (lanes used to leak in as fake tracks 1…N at folder-relative ticks) and adds what
each folder plays on its own track.

### 41.5 Corrections to earlier sections
- **§17.2 / §40 `takeGroupRef@tail+0x34`, `takeSubIndex@tail+0x38`, `takeRef2@tail+0x3c`** were
  misaligned u32 reads of the **comp-section bounds at `tail+0x36` / `tail+0x3e`** (e.g. session C
  `0x96000000` = section start `0x9600`). Their "nonzero together" biconditional is simply "this
  region is a comp section". `tail+0x6a` / `tail+0x6e` ("minorParams") are the source / own take IDs.
- **§40 lFuA `EVAW+0x34` "smallCount"** = the **number of regions referencing the file** (1→2→3 as
  comp sections were cut from it).
- **§3 / `session.py` placement scan**: the track is a u16 and the `track < 64` filter dropped
  every region on higher tracks — on session B2 `session_model` went from 370 to **928** audio
  regions and from 268 to **318/318** linked note regions once anchored on the word tags.

### 41.6 Not yet characterized (needs more controlled saves)
**Track Alternatives** (Logic 10.5+ per-track playlists — no control yet), **MIDI take folders**,
**Unpack to Track Alternatives**, multitrack / grouped-track comps (seen in session C: Audio 3+4 and
7+8 swiped together), and the **write path** (synthesizing folders/comps/alternatives from PT
playlists — needs Logic validation of the output).
