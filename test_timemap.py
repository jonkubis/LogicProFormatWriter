#!/usr/bin/env python3.12
"""Self-tests for projectdata.TimeMap (meter/tempo-aware position helpers).

Run:  python3.12 test_timemap.py
Pure-Python; no Logic round-trip needed. Exits non-zero on first failure.
"""
from logicx.projectdata import TimeMap

PASS = 0


def eq(got, want, msg):
    global PASS
    assert got == want, f"FAIL {msg}: got {got!r}, want {want!r}"
    PASS += 1


def close(got, want, msg, tol=1e-6):
    global PASS
    assert abs(got - want) <= tol, f"FAIL {msg}: got {got!r}, want {want!r}"
    PASS += 1


# 1) Constant 4/4 @ 120 -------------------------------------------------------
t = TimeMap()                                   # defaults: 4/4, 120
eq(t.bar_to_tick(1), 0, "4/4 bar1")
eq(t.bar_to_tick(2), 3840, "4/4 bar2")
eq(t.bar_to_tick(3), 7680, "4/4 bar3")
eq(t.bar_beat_to_tick(1, 3), 1920, "4/4 bar1 beat3")          # 2 quarters
eq(t.bar_beat_to_tick(2, 2.5), 3840 + 1440, "4/4 bar2 beat2.5")
eq(t.tick_to_bar_beat(0), (1, 1.0), "4/4 tick0")
eq(t.tick_to_bar_beat(3840), (2, 1.0), "4/4 tick3840")
eq(t.tick_to_bar_beat(7680 + 960), (3, 2.0), "4/4 tick into bar3 beat2")
# seconds: 1 bar of 4/4 @120 == 4 beats == 2.0 s
close(t.tick_to_seconds(3840), 2.0, "4/4 bar2 seconds")
eq(t.seconds_to_tick(2.0), 3840, "4/4 2s -> tick")
eq(t.seconds_to_tick(0.0), 0, "0s -> tick0")
close(t.tick_to_seconds(0), 0.0, "tick0 -> 0s")

# 2) Meter change 4/4 -> 3/4 at bar 3 (tick 7680) -----------------------------
m = TimeMap(meter_map=[(0, 4, 4), (7680, 3, 4)])
eq(m.bar_to_tick(2), 3840, "mix bar2 (4/4)")
eq(m.bar_to_tick(3), 7680, "mix bar3 (3/4 start)")
eq(m.bar_to_tick(4), 7680 + 2880, "mix bar4 (3/4)")
eq(m.bar_to_tick(5), 7680 + 5760, "mix bar5 (3/4)")
eq(m.bar_beat_to_tick(3, 2.5), 7680 + 1440, "mix bar3 beat2.5 (3/4)")
eq(m.tick_to_bar_beat(7680 + 2880), (4, 1.0), "mix inverse bar4")
eq(m.tick_to_bar_beat(7680 + 1440), (3, 2.5), "mix inverse bar3 beat2.5")

# 3) 6/8 (compound) -----------------------------------------------------------
s = TimeMap(meter_map=[(0, 6, 8)])
eq(s.bar_to_tick(2), 2880, "6/8 bar2 (ticks/bar=2880)")
eq(s.bar_beat_to_tick(1, 4), 1440, "6/8 bar1 beat4 (eighth=480)")
eq(s.tick_to_bar_beat(1440), (1, 4.0), "6/8 inverse beat4")

# 4) Tempo change 120 -> 60 at bar 2 (tick 3840) ------------------------------
tc = TimeMap(tempo_map=[(0, 120), (3840, 60)])
close(tc.tick_to_seconds(3840), 2.0, "tempo bar2 @120 -> 2s")
close(tc.tick_to_seconds(7680), 6.0, "tempo bar3 @60 -> 6s")   # +4 beats @60 = +4s
eq(tc.seconds_to_tick(6.0), 7680, "tempo 6s -> tick7680")
eq(tc.seconds_to_tick(2.0), 3840, "tempo 2s boundary -> tick3840")
# round-trip a handful of ticks through seconds
for tick in (0, 960, 3840, 5000, 7680, 12345):
    eq(tc.seconds_to_tick(tc.tick_to_seconds(tick)), tick, f"tempo rt tick {tick}")

# 5) PPQ scaling: same map at 480 PPQ must rescale to identical results --------
p = TimeMap(tempo_map=[(0, 120), (1920, 60)], meter_map=[(0, 4, 4), (3840, 3, 4)],
            ppq=480)
eq(p.bar_to_tick(3), 7680, "ppq480 bar3 rescaled")
close(p.tick_to_seconds(3840), 2.0, "ppq480 tempo rescaled")

# 6) from_midimap stub --------------------------------------------------------
class _MM:
    division = 480
    tempo_map = [(0, 500000, 120.0), (1920, 1000000, 60.0)]
    meter_map = [(0, 4, 4, 24, 8), (3840, 3, 4, 24, 8)]   # extra MIDI fields ignored
fm = TimeMap.from_midimap(_MM())
eq(fm.bar_to_tick(4), 7680 + 2880, "from_midimap meter")
close(fm.tick_to_seconds(7680), 6.0, "from_midimap tempo")

# 7) Clamping + composites ----------------------------------------------------
eq(t.seconds_to_tick(-5), 0, "negative seconds clamp")
eq(t.tick_to_bar_beat(-100), (1, 1.0), "negative tick clamp")
close(t.tick_to_seconds(-100), 0.0, "negative tick seconds clamp")
close(m.bar_beat_to_seconds(3, 1), 4.0, "bar_beat_to_seconds (bar3@120=4s)")
eq(m.seconds_to_bar_beat(0.0), (1, 1.0), "seconds_to_bar_beat origin")

print(f"OK — {PASS} assertions passed")
