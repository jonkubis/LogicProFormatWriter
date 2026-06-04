# tools/ — development & reverse-engineering utilities

Not part of the importable `logicx` package — standalone scripts used while
reverse-engineering the format. Kept for reference / further RE.

- **`re_probe.py`** — low-level RE workbench for `ProjectData` (chunk framing, record
  diffing, tag dumps) + a `FINDINGS` comment block. The tool the format was cracked with.
- **`logicx_tool.py`** — a CLI to unpack / decode / explore a `.logicx` bundle.

The authoritative byte-level spec these produced is `../PROJECTDATA_FORMAT.md`.
