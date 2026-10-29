# Comp / take-folder / track-alternative control sessions — recipe

Ground-truth fixtures for reverse-engineering Logic **take folders + Quick Swipe comps** and
**Track Alternatives** (for Pro Tools playlist ⇄ Logic conversion). Each step changes exactly ONE
thing, so a byte diff between consecutive steps isolates what that change writes.

## Source material (this folder)
| file | content | identifies |
|---|---|---|
| `take1.wav` | 220 Hz + beat clicks, 4 bars @120 = 8.000 s, 44.1 kHz mono | take 1 |
| `take2.wav` | 330 Hz, same length | take 2 |
| `take3.wav` | 440 Hz, same length | take 3 |
| `midiA_C4.mid` | 16 quarter notes C4 vel 100 | MIDI take A |
| `midiB_G4.mid` | 16 quarter notes G4 vel 80 | MIDI take B |

## Conventions
- New empty project: **120 BPM, 4/4, 44.1 kHz**, Snap = **Bar**. Import with "copy files into project".
- Each step = **File ▸ Project Alternatives ▸ New Alternative…** named exactly as below, then make the change
  in the new alternative and **⌘S**. (Separate *Save As* bundles also work if easier.)
- Change only what the step says. Don't move the playhead/zoom more than needed (harmless, but noisier).

## Status (2026-10-15)
- **Done** (made by driving Logic 12.2): the audio take-folder chain, realised as
  `fixtures/TAKES3.logicx` b00–b07 (takes on 3 tracks, then packed — packing 3 regions stacked on
  ONE track only keeps one take, captured separately as `fixtures/TAKES.logicx` a00–a01). Decoded in
  `PROJECTDATA_FORMAT.md` §41 / `logicx.takes`.
- **Pending**: §2 MIDI take folders, §3 Track Alternatives, and an extra step on TAKES3: take-folder
  menu ▸ **Unpack to Track Alternatives** (Logic's own folder→alternatives conversion).

## 1. `TAKES.logicx` — audio take folder + Quick Swipe comping (original plan; see Status)
| alternative | do exactly this |
|---|---|
| `a00_stacked` | Create 1 **mono Audio** track named `Vox`. Drag `take1.wav`, `take2.wav`, `take3.wav` onto `Vox`, each at **bar 1** (they overlap). |
| `a01_packed` | Select the 3 regions ▸ **Functions ▸ Folder ▸ Pack Take Folder**. Nothing else. |
| `a02_swipe` | Quick Swipe Comping on. Comp: **take 1 for bars 1–2, take 2 for bars 2–3, take 3 for bars 3–5**. |
| `a03_compB` | Take-folder menu ▸ **Duplicate Comp** (→ Comp B, active). In Comp B select **take 2 for the whole length**. |
| `a04_compA` | Take-folder menu ▸ select **Comp A** as the active comp. Nothing else. |
| `a05_rename` | Rename **take 2 → `Lead Two`**; rename **Comp A → `Best`**. |
| `a06_moved` | Drag the whole take folder so it starts at **bar 3**. |
| `a07_flatten` | Take-folder menu ▸ **Flatten**. |

## 2. `MIDITAKES.logicx` — MIDI take folder
| alternative | do exactly this |
|---|---|
| `m00_stacked` | 1 **Software Instrument** track named `Keys`. Drag `midiA_C4.mid` and `midiB_G4.mid` onto it, both at **bar 1**. |
| `m01_packed` | Select both ▸ **Pack Take Folder**. |
| `m02_takeA` | In the take folder, make the **other** take (A↔B) the active one. Nothing else. |

## 3. `TRACKALTS.logicx` — Track Alternatives
| alternative | do exactly this |
|---|---|
| `t00_one` | 1 **mono Audio** track named `Gtr`; `take1.wav` at **bar 1**. Show the Track Alternatives control in the track header. |
| `t01_new` | Track Alternatives ▸ **New** (empty alt, now active). Drag `take2.wav` to **bar 2**. |
| `t02_dup` | Track Alternatives ▸ **Duplicate** (copy of the active alt). Move its region to **bar 3**. |
| `t03_switch` | Select **alternative 1** as active. Nothing else. |
| `t04_rename` | Rename the alternatives `Main`, `Second`, `Third` (in order). |
| `t05_midi` | Add a **Software Instrument** track `Keys`: `midiA_C4.mid` at bar 1; Track Alternatives ▸ New; `midiB_G4.mid` at bar 1. |

Drop the three bundles into `fixtures/` (or tell me where they are). What each pair proves is
recorded in `PROJECTDATA_FORMAT.md` §41 once decoded, and `DONORS.md` lists them as control sessions.
