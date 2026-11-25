# nk-fixtures

Windows kernel-driver test fixtures for the NK
kernel: Microsoft's own driver samples, built unmodified with the genuine
Microsoft WDK on GitHub's Windows runners, published as hash-locked release
assets.

This repo is deliberately separate from the kernel. The fixtures are external
compatibility targets; they must not evolve in step with the kernel that is
tested against them.

## What gets built

Source: [microsoft/Windows-driver-samples](https://github.com/microsoft/Windows-driver-samples)
at the commit pinned in `fixtures.json`. No source or binary patching, ever.

| Fixture id | Driver | Framework | Upstream path |
| --- | --- | --- | --- |
| `wdm-ioctl` | `sioctl.sys` (+ `ioctlapp.exe`) | WDM | `general/ioctl/wdm` |
| `kmdf-echo-autosync` | `echo.sys` (+ `echoapp.exe`) | KMDF | `general/echo/kmdf` |
| `kmdf-echo-driversync` | `echo_2.sys` | KMDF | `general/echo/kmdf` |

| `abi-probe` | `abi-probe.sys` | WDM | this repository, `abi-probe/` |

Each is built `Release` for `x64` and `arm64`.

### The ABI probe

`abi-probe/probe.c` is the one source file here that is not Microsoft's.
It includes only `<ntddk.h>` and declares a table of `sizeof` and
`FIELD_OFFSET` values for driver-visible structures (`DEVICE_OBJECT`,
`IRP`, `MDL`, ...). The WDK compiles it like any driver, so the numbers
are what Microsoft's compiler and headers produce for the pinned target.
The pipeline reads the table back out of the built image and publishes it
as `abi-probe.<arch>.txt`, one fact per line:

```
sizeof DEVICE_OBJECT 336
offsetof IRP Tail.Overlay.CurrentStackLocation 184
```

A kernel can check its own structure definitions against that file. The
driver itself is not meant to be loaded.

## Build settings

- Runner `windows-2025-vs2026`; WDK and SDK come from the NuGet packages named
  in upstream's `packages.config` at the pinned commit.
- `TargetVersion=Windows10`, and `_NT_TARGET_VERSION` for build **19041** (the
  Windows 10 2004–22H2 kernel line NK targets). If the WDK no longer offers
  19041, the build falls back to the oldest version it does offer, prints a
  warning, and records requested vs. used in the manifest.
- Signing is whatever the WDK does by default for these projects (test
  signing with a throwaway certificate). `pe.signed` in the manifest says
  whether a file carries a signature. This is lab test signing, not
  production signing.

Builds are reproducible in procedure, not bit-for-bit. A fixture's identity is
the SHA-256 of the published bytes.

## Releases

Push a tag `vN` to publish release `vN`. Branch pushes, pull requests and
manual runs only upload CI artifacts.

Release assets:

- `<fixture-id>.<arch>.<driver>.sys` — each driver as a directly fetchable file
- `abi-probe.<arch>.txt` — the ABI probe's table as text
- `nk-fixtures-<arch>.zip` — everything for one arch: drivers, PDBs, INF/CAT,
  companion apps, upstream license
- `manifest.json` — upstream commit, toolchain versions, msbuild properties,
  run URL, and per file: size, SHA-256, PE machine/timestamp/image size,
  signature flag and the full import table by DLL
- `SHA256SUMS` — hashes of every asset

A release is immutable: the workflow refuses to overwrite an existing one. Any
change to the pinned commit, toolchain or settings needs a new tag.

Consumers reference a fixture by release URL plus SHA-256 and must reject a
mismatch.

## Changing the pin

Edit `fixtures.json` (`upstream.commit`, `nt_target`, fixture list), push
to a branch, open a pull request, check the CI artifacts, merge, then tag.
`main` takes no direct pushes.

## Local checks

The build itself needs Windows. Everything else is tested on any host:

```sh
python3 -m unittest discover -s tests
```

## Status and limits

These binaries have not yet been run on a reference Windows 10 installation.
Until that baseline exists they are "WDK-built", not "Windows-verified".

## License

Scripts and workflow in this repo: MIT (`LICENSE`). The driver samples are
Microsoft's, under the MS-PL; their license ships inside each release zip.
