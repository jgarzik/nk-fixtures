#!/usr/bin/env python3
"""Build, collect and publish the WDK driver fixtures described in fixtures.json.

Subcommands (see README.md):
  pin       print upstream repo/commit as key=value lines (for $GITHUB_OUTPUT)
  build     restore the WDK NuGet packages and msbuild each fixture solution (Windows)
  collect   gather build outputs for one arch into dist/: zip, loose .sys, partial manifest
  finalize  merge per-arch manifests and write SHA256SUMS (any OS)

Standard library only.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pe  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
MSBUILD_PLATFORM = {"x64": "x64", "arm64": "ARM64"}
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def die(msg):
    sys.exit(f"fixtures: error: {msg}")


def warn(msg):
    # "::warning::" surfaces in the GitHub Actions run summary.
    print(f"::warning::{msg}", flush=True)


def load_config(path):
    cfg = json.loads(Path(path).read_text())
    if cfg.get("schema") != 1:
        die(f"{path}: unsupported schema {cfg.get('schema')!r}")
    return cfg


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run(cmd, check=True, **kw)


def capture(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


# --- build ------------------------------------------------------------------

def find_vswhere():
    base = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    p = Path(base) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    return p if p.exists() else None


def find_msbuild():
    found = shutil.which("msbuild")
    if found:
        return found
    vswhere = find_vswhere()
    if vswhere:
        out = capture([str(vswhere), "-latest", "-prerelease", "-products", "*",
                       "-requires", "Microsoft.Component.MSBuild",
                       "-find", r"MSBuild\**\Bin\MSBuild.exe"]).split("\n")
        if out and out[0].strip():
            return out[0].strip()
    die("msbuild not found (not on PATH, vswhere found nothing)")


def vs_version():
    vswhere = find_vswhere()
    if not vswhere:
        return None
    return capture([str(vswhere), "-latest", "-prerelease", "-products", "*",
                    "-property", "installationVersion"]).strip() or None


def nuget_packages(wds):
    # Two attributes per line; a regex avoids running an XML parser on fetched input.
    text = (wds / "packages.config").read_text(encoding="utf-8-sig")
    return dict(re.findall(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', text))


def pick_nt_target(versions, want, fallback):
    """versions: [{Version, Tag, Code, Build}]. Returns (chosen, fell_back)."""
    for v in versions:
        if str(v["Tag"]) == str(want):
            return v, False
    have = ", ".join(str(v["Tag"]) for v in versions)
    if fallback != "oldest":
        die(f"_NT_TARGET_VERSION {want} not offered by this WDK (have: {have})")
    chosen = min(versions, key=lambda v: int(v["Build"]))
    warn(f"_NT_TARGET_VERSION {want} not offered by this WDK (have: {have}); "
         f"falling back to oldest, {chosen['Tag']}. Recorded in the manifest.")
    return chosen, True


def discover_nt_targets(wds):
    # Upstream's own script parses the enumeration out of the restored WDK.
    out = capture(["pwsh", "-NoProfile", "-Command",
                   "& ./Get-NtTargetVersions.ps1 | Select-Object Version,Tag,Code,Build "
                   "| ConvertTo-Json -Compress"], cwd=wds)
    data = json.loads(out)
    return data if isinstance(data, list) else [data]


def cmd_build(args):
    cfg = load_config(args.config)
    wds = Path(args.wds).resolve()
    out = Path(args.out).resolve()
    logs = out / "logs"
    logs.mkdir(parents=True, exist_ok=True)

    run(["nuget", "restore", str(wds / "packages.config"),
         "-PackagesDirectory", str(wds / "packages")])
    msbuild = find_msbuild()
    nt, fell_back = pick_nt_target(discover_nt_targets(wds), cfg["nt_target"],
                                   cfg.get("nt_target_fallback"))
    platform = MSBUILD_PLATFORM[args.arch]
    props = {
        "Configuration": cfg["configuration"],
        "Platform": platform,
        "TargetVersion": "Windows10",
        "_NT_TARGET_VERSION": nt["Code"],
        "InfVerif_AdditionalOptions": "/samples",
    }
    for sln in sorted({f["solution"] for f in cfg["fixtures"]}):
        log = logs / (Path(sln).stem + f".{args.arch}.binlog")
        run([msbuild, str(wds / sln), "-t:Rebuild", "-m", "-noLogo", "-clp:Verbosity=m",
             f"-binaryLogger:LogFile={log};ProjectImports=None"]
            + [f"-p:{k}={v}" for k, v in props.items()])

    info = {
        "arch": args.arch,
        "msbuild_properties": props,
        "msbuild_version": capture([msbuild, "-version", "-noLogo"]).strip().split("\n")[-1],
        "visual_studio_version": vs_version(),
        "nuget_packages": nuget_packages(wds),
        "nt_target": {"requested": str(cfg["nt_target"]), "used": str(nt["Tag"]),
                      "version": nt["Version"], "code": nt["Code"], "fell_back": fell_back},
        "runner": {"image_os": os.environ.get("ImageOS"),
                   "image_version": os.environ.get("ImageVersion")},
    }
    (out / f"build-info-{args.arch}.json").write_text(json.dumps(info, indent=2) + "\n")


# --- collect ----------------------------------------------------------------

def find_outputs(sln_dir, name, arch, configuration):
    """All build outputs called `name` for this arch/configuration, shortest path first."""
    want = {MSBUILD_PLATFORM[arch].lower(), configuration.lower()}
    hits = []
    for p in sln_dir.rglob("*"):
        if p.is_file() and p.name.lower() == name.lower():
            parts = {x.lower() for x in p.relative_to(sln_dir).parts[:-1]}
            if want <= parts:
                hits.append(p)
    return sorted(hits, key=lambda p: (len(p.parts), str(p)))


def run_info():
    env = os.environ
    if "GITHUB_RUN_ID" not in env:
        return {"run_url": None, "fixtures_repo": None, "fixtures_commit": None}
    repo = env.get("GITHUB_REPOSITORY")
    return {
        "run_url": f"{env.get('GITHUB_SERVER_URL')}/{repo}/actions/runs/{env['GITHUB_RUN_ID']}",
        "fixtures_repo": repo,
        "fixtures_commit": env.get("GITHUB_SHA"),
    }


def cmd_collect(args):
    cfg = load_config(args.config)
    wds = Path(args.wds).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    arch, conf = args.arch, cfg["configuration"]

    info_path = out / f"build-info-{arch}.json"
    build = json.loads(info_path.read_text()) if info_path.exists() else {"arch": arch}

    files, bundle = [], []
    for fx in cfg["fixtures"]:
        sln_dir = (wds / fx["solution"]).parent
        for name in fx["required"] + fx["optional"]:
            hits = find_outputs(sln_dir, name, arch, conf)
            if not hits:
                if name in fx["required"]:
                    die(f"{fx['id']}: required output {name} not found for {arch} under {sln_dir}")
                continue
            primary, digest = hits[0], sha256(hits[0])
            entry = {
                "fixture": fx["id"], "framework": fx["framework"], "arch": arch,
                "name": primary.name, "bundle_path": f"{fx['id']}/{primary.name}",
                "source_path": primary.relative_to(wds).as_posix(),
                "size": primary.stat().st_size, "sha256": digest,
            }
            # The WDK may leave a second copy (e.g. a package directory). Never
            # pick silently between different bytes: record every variant.
            variants = [{"source_path": h.relative_to(wds).as_posix(), "sha256": sha256(h)}
                        for h in hits[1:]]
            variants = [v for v in variants if v["sha256"] != digest]
            if variants:
                entry["variants"] = variants
                warn(f"{fx['id']}/{name} ({arch}): {len(variants)} differing copies; "
                     f"published {entry['source_path']}")
            if primary.suffix.lower() in (".sys", ".exe"):
                try:
                    entry["pe"] = pe.parse(primary.read_bytes())
                except pe.PeError as e:
                    die(f"{primary}: {e}")
                if entry["pe"]["machine"] != arch:
                    die(f"{primary}: machine {entry['pe']['machine']}, expected {arch}")
            if primary.suffix.lower() == ".sys":
                asset = f"{fx['id']}.{arch}.{primary.name}"
                shutil.copyfile(primary, out / asset)
                entry["asset"] = asset
            files.append(entry)
            bundle.append((entry["bundle_path"], primary))

    lic = wds / "LICENSE"
    if lic.exists():
        bundle.append(("LICENSES/Windows-driver-samples.LICENSE", lic))

    zip_name = f"nk-fixtures-{arch}.zip"
    with zipfile.ZipFile(out / zip_name, "w", zipfile.ZIP_DEFLATED) as z:
        for arcname, src in sorted(bundle):
            zi = zipfile.ZipInfo(arcname, ZIP_EPOCH)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            z.writestr(zi, src.read_bytes())

    manifest = {"arch": arch, "bundle": zip_name, "build": {**build, **run_info()},
                "files": files}
    (out / f"manifest-{arch}.json").write_text(json.dumps(manifest, indent=2) + "\n")
    info_path.unlink(missing_ok=True)
    print(f"collected {len(files)} files for {arch} into {out}")


# --- finalize ---------------------------------------------------------------

def cmd_finalize(args):
    cfg = load_config(args.config)
    dist = Path(args.dist).resolve()
    parts = sorted(dist.glob("manifest-*.json"))
    if not parts:
        die(f"no manifest-*.json in {dist}")
    per_arch = [json.loads(p.read_text()) for p in parts]
    missing = set(cfg["archs"]) - {m["arch"] for m in per_arch}
    if missing:
        die(f"missing arch manifests: {sorted(missing)}")

    manifest = {
        "schema": 1,
        "fixture_set": args.tag,
        "upstream": cfg["upstream"],
        "configuration": cfg["configuration"],
        "builds": {m["arch"]: {"bundle": m["bundle"], **m["build"]} for m in per_arch},
        "files": [f for m in per_arch for f in m["files"]],
    }
    (dist / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for p in parts:
        p.unlink()

    lines = [f"{sha256(p)}  {p.name}\n" for p in sorted(dist.iterdir())
             if p.is_file() and p.name != "SHA256SUMS"]
    (dist / "SHA256SUMS").write_text("".join(lines))
    print(f"finalized {args.tag}: {len(manifest['files'])} files, {len(lines)} assets")


def cmd_pin(args):
    cfg = load_config(args.config)
    print(f"repo={cfg['upstream']['repo']}")
    print(f"commit={cfg['upstream']['commit']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", default=str(ROOT / "fixtures.json"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("pin").set_defaults(fn=cmd_pin)
    for name, fn in (("build", cmd_build), ("collect", cmd_collect)):
        p = sub.add_parser(name)
        p.add_argument("--arch", required=True, choices=sorted(MSBUILD_PLATFORM))
        p.add_argument("--wds", required=True, help="Windows-driver-samples checkout")
        p.add_argument("--out", default="dist")
        p.set_defaults(fn=fn)
    p = sub.add_parser("finalize")
    p.add_argument("--dist", default="dist")
    p.add_argument("--tag", required=True)
    p.set_defaults(fn=cmd_finalize)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
