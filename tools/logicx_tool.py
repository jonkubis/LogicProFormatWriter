#!/usr/bin/env python3
"""
logicx_tool.py — Unpack and decode Apple Logic Pro `.logicx` project bundles.

A CLI for exploring and decoding Logic Pro projects:
  - Detects package vs. project-folder layout.
  - Decodes every plist (ProjectInformation, MetaData, DisplayState) to JSON.
  - Analyzes the opaque `ProjectData` binary: magic check, chunk-marker map,
    embedded JSON (Session Player presets), and ASCII strings.

The `ProjectData` chunk format is only partially understood; chunk *sizes* are
not yet decoded, so chunk boundaries here are INFERRED from marker offsets
(size = distance to the next marker). Treat inferred sizes as a research aid,
not ground truth.

Stdlib only. Python 3.7+.

Usage:
  logicx_tool.py info    <project.logicx | project-folder>
  logicx_tool.py unpack  <project>  [-o OUTDIR] [--raw] [--strings]
  logicx_tool.py chunks  <project | ProjectData>  [--alt 000]
  logicx_tool.py json    <project | ProjectData>  [-o DIR] [--alt 000]
  logicx_tool.py plist   <project>  [--alt 000]
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt
import json
import plistlib
import re
import sys
from pathlib import Path

# --- ProjectData constants ---------------------------------------------------

PROJECTDATA_MAGIC = bytes([0x23, 0x47, 0xC0, 0xAB])

# Known chunk markers as they appear *literally* in the file (reversed FourCC).
# value = (human label, decoded-forwards FourCC)
CHUNK_MARKERS = {
    b"karT": ("Track", "Trak"),
    b"qeSM": ("MIDISequence", "MSeq"),
    b"qSvE": ("EventSequence", "EvSq"),
    b"gRuA": ("AudioRegion", "AuRg"),
    b"tSxT": ("TextStyle", "TxSt"),
    b"LFUA": ("AudioFileRef", "AUFL"),
    b"lFuA": ("AudioFileRef", "AuFl"),
    b"PMOC": ("Comp/Take", "COMP"),
    b"MroC": ("CoreMIDI", "CorM"),
    b"tSnI": ("Instrument", "InSt"),
    b"snrT": ("Transform", "Trns"),
    b"gnoS": ("Song", "Song"),
}

_MARKER_RE = re.compile(b"|".join(re.escape(m) for m in CHUNK_MARKERS))
_UID = getattr(plistlib, "UID", None)


# --- plist <-> JSON ----------------------------------------------------------

def json_safe(obj):
    """Convert plist values into JSON-serializable, *invertible* form.

    bytes -> {"__type__": "data", "base64": ...}; datetime -> ISO; UID -> int.
    The type tags let a future `repack` step rebuild the original plist.
    """
    if isinstance(obj, dict):
        return {str(k): json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [json_safe(v) for v in obj]
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, bytes):
        return {"__type__": "data", "base64": base64.b64encode(obj).decode("ascii")}
    if isinstance(obj, _dt.datetime):
        return {"__type__": "date", "iso": obj.isoformat()}
    if _UID is not None and isinstance(obj, _UID):
        return {"__type__": "uid", "value": obj.data}
    if isinstance(obj, (str, int, float)) or obj is None:
        return obj
    return {"__type__": "repr", "value": repr(obj)}


def load_plist(path: Path) -> dict:
    with open(path, "rb") as f:
        return plistlib.load(f)


# --- ProjectData analysis ----------------------------------------------------

def scan_markers(data: bytes):
    """Find all known chunk markers. Returns (list_of_hits, counts_dict)."""
    hits = []
    counts = {}
    for m in _MARKER_RE.finditer(data):
        marker = m.group()
        label, _fourcc = CHUNK_MARKERS[marker]
        tag = marker.decode("ascii")
        hits.append({"offset": m.start(), "marker": tag, "label": label})
        key = f"{label} ({tag})"
        counts[key] = counts.get(key, 0) + 1
    return hits, counts


def _match_braces(data: bytes, start: int):
    """From an index pointing at b'{', return (object_bytes, end) or (None, start).

    Tracks string state and backslash escapes so braces/quotes inside JSON
    string values don't confuse the depth counter.
    """
    depth = 0
    in_str = False
    esc = False
    n = len(data)
    i = start
    while i < n:
        c = data[i]
        if in_str:
            if esc:
                esc = False
            elif c == 0x5C:        # backslash
                esc = True
            elif c == 0x22:        # double quote
                in_str = False
        else:
            if c == 0x22:
                in_str = True
            elif c == 0x7B:        # {
                depth += 1
            elif c == 0x7D:        # }
                depth -= 1
                if depth == 0:
                    return data[start:i + 1], i + 1
        i += 1
    return None, start


def extract_json_objects(data: bytes):
    """Extract embedded UTF-8 JSON objects (Session Player presets, etc.)."""
    results = []
    i = 0
    while True:
        start = data.find(b'{"', i)
        if start == -1:
            break
        obj, end = _match_braces(data, start)
        if obj is not None:
            try:
                parsed = json.loads(obj.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed = None
            if parsed is not None:
                results.append({"offset": start, "length": len(obj), "value": parsed})
                i = end
                continue
        i = start + 2
    return results


def extract_strings(data: bytes, min_len: int = 4):
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return [{"offset": m.start(), "text": m.group().decode("ascii")}
            for m in pat.finditer(data)]


def analyze_projectdata(data: bytes, want_strings: bool = False) -> dict:
    hits, counts = scan_markers(data)
    ordered = sorted(hits, key=lambda d: d["offset"])
    chunks = []
    for idx, item in enumerate(ordered):
        nxt = ordered[idx + 1]["offset"] if idx + 1 < len(ordered) else len(data)
        chunks.append({**item, "inferred_size": nxt - item["offset"]})
    jsons = extract_json_objects(data)
    out = {
        "size": len(data),
        "magic_ok": data[:4] == PROJECTDATA_MAGIC,
        "magic_hex": data[:4].hex(),
        "header_hex": data[:64].hex(),
        "marker_total": len(hits),
        "marker_counts": counts,
        "embedded_json_count": len(jsons),
        "chunks": chunks,
        "embedded_json": jsons,
    }
    if want_strings:
        out["strings"] = extract_strings(data)
    return out


def json_label(value) -> str:
    """Short slug describing an embedded JSON object, for filenames."""
    if isinstance(value, dict):
        if "RegionType" in value:
            return str(value["RegionType"])
        for k in value:
            if k.endswith(".state"):
                return k.split(".")[0]
        first = next(iter(value), "")
        return re.sub(r"[^A-Za-z0-9_]+", "_", str(first))[:40] or "object"
    return "object"


# --- bundle layout -----------------------------------------------------------

def find_bundle(src: Path) -> dict:
    """Describe a project given a .logicx package or a project folder."""
    src = src.resolve()
    if not src.exists():
        raise FileNotFoundError(src)

    bundle = None
    fmt = None
    audio_files = None

    if src.is_dir() and src.suffix == ".logicx":
        bundle, fmt = src, "package"
    elif src.is_dir():
        inner = sorted(src.glob("*.logicx"))
        if inner:
            bundle, fmt = inner[0], "folder"
            af = src / "Audio Files"
            audio_files = af if af.is_dir() else None
    if bundle is None:
        raise ValueError(f"Not a .logicx package or project folder: {src}")

    proj_info = bundle / "Resources" / "ProjectInformation.plist"
    alts_dir = bundle / "Alternatives"
    alternatives = []
    if alts_dir.is_dir():
        for d in sorted(alts_dir.iterdir()):
            if d.is_dir():
                alternatives.append((d.name, d))
    media_audio = bundle / "Media" / "Audio Files"
    return {
        "source": str(src),
        "format": fmt,
        "bundle": bundle,
        "project_information": proj_info if proj_info.exists() else None,
        "alternatives": alternatives,
        "media_audio": media_audio if media_audio.is_dir() else None,
        "audio_files": audio_files,
    }


METADATA_SUMMARY_KEYS = [
    ("BeatsPerMinute", "tempo"),
    ("SongKey", "key"),
    ("SongGenderKey", "mode"),
    ("SongSignatureNumerator", "sig_num"),
    ("SongSignatureDenominator", "sig_den"),
    ("SampleRate", "sample_rate"),
    ("NumberOfTracks", "num_tracks"),
]


def summarize_metadata(md: dict) -> dict:
    return {dst: md.get(src) for src, dst in METADATA_SUMMARY_KEYS}


def resolve_projectdata(src: Path, alt: str = None) -> bytes:
    """Return ProjectData bytes from a direct file or from a project's alternative."""
    src = src.resolve()
    if src.is_file():
        return src.read_bytes()
    info = find_bundle(src)
    alts = dict(info["alternatives"])
    if not alts:
        raise ValueError("No alternatives found in project")
    name = alt or sorted(alts)[0]
    if name not in alts:
        raise ValueError(f"Alternative {name!r} not found; have {sorted(alts)}")
    pd = alts[name] / "ProjectData"
    if not pd.exists():
        raise FileNotFoundError(pd)
    return pd.read_bytes()


# --- commands ----------------------------------------------------------------

def cmd_info(args) -> int:
    info = find_bundle(Path(args.project))
    print(f"Source : {info['source']}")
    print(f"Format : {info['format']}")
    print(f"Bundle : {info['bundle']}")
    if info["project_information"]:
        pi = load_plist(info["project_information"])
        print(f"Saved from : {pi.get('LastSavedFrom', '?')}")
        print(f"Has project folder : {pi.get('HasProjectFolder')}")
        if pi.get("VariantNames"):
            print(f"Variant names : {pi.get('VariantNames')}")
    print(f"Alternatives : {[n for n, _ in info['alternatives']]}")
    for name, path in info["alternatives"]:
        print(f"\n  [{name}]")
        md_path = path / "MetaData.plist"
        if md_path.exists():
            s = summarize_metadata(load_plist(md_path))
            print(f"    tempo={s['tempo']} key={s['key']} {s['mode']} "
                  f"sig={s['sig_num']}/{s['sig_den']} "
                  f"sr={s['sample_rate']} tracks={s['num_tracks']}")
        pd_path = path / "ProjectData"
        if pd_path.exists():
            data = pd_path.read_bytes()
            a = analyze_projectdata(data)
            print(f"    ProjectData: {a['size']:,} bytes  magic_ok={a['magic_ok']}  "
                  f"markers={a['marker_total']}  json={a['embedded_json_count']}")
            for k, v in sorted(a["marker_counts"].items(), key=lambda kv: -kv[1]):
                print(f"        {v:>5}  {k}")
    return 0


def cmd_unpack(args) -> int:
    src = Path(args.project)
    info = find_bundle(src)
    stem = info["bundle"].stem
    out = Path(args.output) if args.output else Path.cwd() / f"{stem}_unpacked"
    out.mkdir(parents=True, exist_ok=True)

    manifest = {
        "source": info["source"],
        "format": info["format"],
        "bundle_name": info["bundle"].name,
        "alternatives": [],
        "media": {},
    }

    # ProjectInformation.plist
    if info["project_information"]:
        pi = load_plist(info["project_information"])
        _write_json(out / "ProjectInformation.json", json_safe(pi))
        manifest["project_information"] = "ProjectInformation.json"
        manifest["logic_version"] = pi.get("LastSavedFrom")
        manifest["has_project_folder"] = pi.get("HasProjectFolder")
        manifest["variant_names"] = json_safe(pi.get("VariantNames"))

    # Per-alternative
    for name, path in info["alternatives"]:
        alt_out = out / "Alternatives" / name
        alt_out.mkdir(parents=True, exist_ok=True)
        entry = {"name": name, "files": {}}

        for plname, key in (("MetaData.plist", "metadata"),
                            ("DisplayState.plist", "display_state")):
            p = path / plname
            if p.exists():
                pl = load_plist(p)
                fn = plname.replace(".plist", ".json")
                _write_json(alt_out / fn, json_safe(pl))
                entry["files"][key] = f"Alternatives/{name}/{fn}"
                if key == "metadata":
                    entry["summary"] = summarize_metadata(pl)

        # DisplayStateArchive (NSKeyedArchiver bplist) -> decode to JSON
        dsa = path / "DisplayStateArchive"
        if dsa.exists():
            try:
                arch = plistlib.loads(dsa.read_bytes())
                _write_json(alt_out / "DisplayStateArchive.json", json_safe(arch))
                entry["files"]["display_state_archive"] = \
                    f"Alternatives/{name}/DisplayStateArchive.json"
            except Exception as e:  # noqa: BLE001 - best-effort decode
                entry["files"]["display_state_archive_error"] = str(e)
            if args.raw:
                (alt_out / "DisplayStateArchive").write_bytes(dsa.read_bytes())

        # ProjectData
        pd = path / "ProjectData"
        if pd.exists():
            data = pd.read_bytes()
            analysis = analyze_projectdata(data, want_strings=args.strings)
            # Pull embedded JSON out to its own folder for easy browsing.
            ej = analysis.pop("embedded_json")
            if ej:
                ej_dir = alt_out / "embedded_json"
                ej_dir.mkdir(exist_ok=True)
                index = []
                for i, obj in enumerate(ej):
                    label = json_label(obj["value"])
                    fn = f"{i:03d}_{label}.json"
                    _write_json(ej_dir / fn, obj["value"])
                    index.append({"file": fn, "offset": obj["offset"],
                                  "length": obj["length"], "label": label})
                _write_json(ej_dir / "_index.json", index)
            # Chunk map as TSV for quick scanning in an editor.
            _write_chunks_tsv(alt_out / "ProjectData.chunks.tsv", analysis["chunks"])
            chunks = analysis.pop("chunks")
            strings = analysis.pop("strings", None)
            if strings is not None:
                _write_strings(alt_out / "ProjectData.strings.txt", strings)
            _write_json(alt_out / "ProjectData.analysis.json", analysis)
            if args.raw:
                (alt_out / "ProjectData").write_bytes(data)
            entry["files"]["project_data_analysis"] = \
                f"Alternatives/{name}/ProjectData.analysis.json"
            entry["project_data"] = {
                "size": analysis["size"],
                "magic_ok": analysis["magic_ok"],
                "marker_total": analysis["marker_total"],
                "marker_counts": analysis["marker_counts"],
                "embedded_json_count": analysis["embedded_json_count"],
                "chunk_count": len(chunks),
            }

        # Inventory other files in the alternative (not copied).
        entry["other_files"] = sorted(
            p.name for p in path.iterdir()
            if p.name not in {"MetaData.plist", "DisplayState.plist",
                              "ProjectData", "DisplayStateArchive"}
        )
        manifest["alternatives"].append(entry)

    # Media inventory (not copied — can be large).
    for label, mdir in (("media_audio", info["media_audio"]),
                        ("audio_files", info["audio_files"])):
        if mdir:
            manifest["media"][label] = [
                {"name": f.name, "size": f.stat().st_size}
                for f in sorted(mdir.iterdir()) if f.is_file()
            ]

    _write_json(out / "manifest.json", manifest)
    print(f"Unpacked -> {out}")
    for entry in manifest["alternatives"]:
        pd = entry.get("project_data")
        s = entry.get("summary", {})
        line = f"  [{entry['name']}]"
        if s:
            line += f" tempo={s.get('tempo')} sig={s.get('sig_num')}/{s.get('sig_den')}"
        if pd:
            line += (f"  ProjectData {pd['size']:,}B "
                     f"markers={pd['marker_total']} json={pd['embedded_json_count']}")
        print(line)
    return 0


def cmd_chunks(args) -> int:
    data = resolve_projectdata(Path(args.target), args.alt)
    a = analyze_projectdata(data)
    print(f"size={a['size']:,}  magic_ok={a['magic_ok']} ({a['magic_hex']})  "
          f"markers={a['marker_total']}  json={a['embedded_json_count']}")
    print("-" * 64)
    for c in a["chunks"]:
        print(f"  0x{c['offset']:08x}  {c['marker']:<5} {c['label']:<14} "
              f"~{c['inferred_size']:,}B")
    print("-" * 64)
    for k, v in sorted(a["marker_counts"].items(), key=lambda kv: -kv[1]):
        print(f"  {v:>5}  {k}")
    return 0


def cmd_json(args) -> int:
    data = resolve_projectdata(Path(args.target), args.alt)
    objs = extract_json_objects(data)
    if args.output:
        d = Path(args.output)
        d.mkdir(parents=True, exist_ok=True)
        for i, obj in enumerate(objs):
            _write_json(d / f"{i:03d}_{json_label(obj['value'])}.json", obj["value"])
        print(f"Wrote {len(objs)} JSON object(s) -> {d}")
    else:
        for obj in objs:
            print(f"# offset 0x{obj['offset']:08x}  len {obj['length']}")
            print(json.dumps(obj["value"], indent=2, ensure_ascii=False))
            print()
    return 0


def cmd_plist(args) -> int:
    info = find_bundle(Path(args.project))
    bag = {}
    if info["project_information"]:
        bag["ProjectInformation"] = json_safe(load_plist(info["project_information"]))
    for name, path in info["alternatives"]:
        if args.alt and name != args.alt:
            continue
        for plname in ("MetaData.plist", "DisplayState.plist"):
            p = path / plname
            if p.exists():
                bag[f"{name}/{plname}"] = json_safe(load_plist(p))
    print(json.dumps(bag, indent=2, ensure_ascii=False))
    return 0


# --- output helpers ----------------------------------------------------------

def _write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _write_chunks_tsv(path: Path, chunks) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("offset_dec\toffset_hex\tmarker\tlabel\tinferred_size\n")
        for c in chunks:
            f.write(f"{c['offset']}\t0x{c['offset']:08x}\t{c['marker']}\t"
                    f"{c['label']}\t{c['inferred_size']}\n")


def _write_strings(path: Path, strings) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for s in strings:
            f.write(f"0x{s['offset']:08x}\t{s['text']}\n")


# --- argparse ----------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logicx_tool.py",
        description="Unpack and decode Apple Logic Pro .logicx project bundles.")
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("info", help="print a summary of a project")
    pi.add_argument("project")
    pi.set_defaults(func=cmd_info)

    pu = sub.add_parser("unpack", help="explode a project into readable JSON + analysis")
    pu.add_argument("project")
    pu.add_argument("-o", "--output", help="output directory (default: ./<name>_unpacked)")
    pu.add_argument("--raw", action="store_true",
                    help="also copy raw ProjectData / DisplayStateArchive bytes")
    pu.add_argument("--strings", action="store_true",
                    help="also dump extracted ASCII strings from ProjectData")
    pu.set_defaults(func=cmd_unpack)

    pc = sub.add_parser("chunks", help="print the ProjectData chunk-marker map")
    pc.add_argument("target", help="project bundle/folder or a ProjectData file")
    pc.add_argument("--alt", help="alternative name (default: first, e.g. 000)")
    pc.set_defaults(func=cmd_chunks)

    pj = sub.add_parser("json", help="extract embedded JSON objects from ProjectData")
    pj.add_argument("target", help="project bundle/folder or a ProjectData file")
    pj.add_argument("-o", "--output", help="write objects to this directory")
    pj.add_argument("--alt", help="alternative name (default: first, e.g. 000)")
    pj.set_defaults(func=cmd_json)

    pp = sub.add_parser("plist", help="dump all plists as JSON to stdout")
    pp.add_argument("project")
    pp.add_argument("--alt", help="alternative name (default: all)")
    pp.set_defaults(func=cmd_plist)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
