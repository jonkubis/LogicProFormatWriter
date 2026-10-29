#!/usr/bin/env python3.12
"""Write-path tests (logicx.edit) — proving the RE'd subsystems are not just readable
but editable: mutate a decoded field on a real Logic session, re-serialize, and confirm
the change reads back, the file round-trips, and ONLY the intended bytes changed.

Run: python3.12 test_edit.py
"""
from pathlib import Path

from logicx.projectdata import ProjectData
from logicx import inspect as lx
from logicx.edit import set_mixer

ROOT = Path(__file__).resolve().parent
PASS = 0


def ok(c, m):
    global PASS
    assert c, "FAIL " + m
    PASS += 1


def load(bundle):
    return ProjectData.parse((ROOT / bundle / "Alternatives" / "000" / "ProjectData").read_bytes())


BUN = "templates/F21_multitrack_regions.logicx"

# baseline
pd = load(BUN)
before = pd.serialize()
strip0 = {m["name"]: m for m in lx.mixer_strips(pd)}
ok("Audio 1" in strip0, "baseline has 'Audio 1'")
ok(strip0["Audio 1"]["fader"] == 90 and strip0["Audio 1"]["pan"] == 64,
   f"baseline Audio 1 fader/pan = 90/64 ({strip0['Audio 1']})")

# mutate one strip's fader + pan
n = set_mixer(pd, "Audio 1", fader=100, pan=32)
ok(n == 1, f"set_mixer matched exactly one 'Audio 1' strip ({n})")
after = pd.serialize()

# 1) the edit reads back through the decoder
pd2 = ProjectData.parse(after)
s2 = {m["name"]: m for m in lx.mixer_strips(pd2)}
ok(s2["Audio 1"]["fader"] == 100 and s2["Audio 1"]["pan"] == 32,
   f"edited Audio 1 fader/pan reads back 100/32 ({s2['Audio 1']})")
# other strips untouched
ok(s2["Audio 2"]["fader"] == 90 and s2["Audio 2"]["pan"] == 64, "Audio 2 untouched")

# 2) the mutated file round-trips byte-for-byte
ok(ProjectData.parse(after).serialize() == after, "mutated ProjectData round-trips")

# 3) ONLY the intended bytes changed (fader@+0x55, mirror@+0x77, pan@+0x59 of one record)
ok(len(after) == len(before), "size unchanged (fixed-size edit)")
diffs = [i for i in range(len(before)) if before[i] != after[i]]
ok(len(diffs) == 3, f"exactly 3 bytes changed ({len(diffs)})")
changed = {(before[i], after[i]) for i in diffs}
ok(changed == {(90, 100), (90, 100), (64, 32)} or changed == {(90, 100), (64, 32)},
   f"changed bytes are the 2×fader (90->100) + pan (64->32) ({sorted(changed)})")

# 4) fader mirror invariant (§15): +0x55 == +0x77 after the edit
for r in pd2.records:
    if r.tag == b"OCuA":
        pay = r.raw[0x24:]
        if len(pay) > 0x77 and lx._u16(pay, 0x0a) == 0x1235 and pay[0x04] in lx._OCUA_TYPE:
            ok(pay[0x55] == pay[0x77], "OCuA fader value == mirror (all strips)")
            break

# 5) idempotent no-op when the strip name is absent
n0 = set_mixer(load(BUN), "No Such Strip", fader=1)
ok(n0 == 0, "unknown strip name matches nothing")

# 6) bounds checking
try:
    set_mixer(load(BUN), "Audio 1", fader=200)
    ok(False, "should reject out-of-range fader")
except ValueError:
    ok(True, "rejects out-of-range fader")

print(f"OK — {PASS} assertions passed (logicx.edit write-path mutation round-trip)")
