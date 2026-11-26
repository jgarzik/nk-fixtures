# nk-fixtures

Windows kernel-driver test fixtures for the NK kernel, built with the
genuine Microsoft WDK on GitHub's Windows runners and published as
hash-locked release assets: Microsoft's own driver samples, unmodified;
drivers of NK's own that record what Windows does; a table of structure
layouts; and a registry hive.

This repo is deliberately separate from the kernel. The fixtures are external
compatibility targets; they must not evolve in step with the kernel that is
tested against them.

## What gets built

Each driver is built `Release` for `x64` and `arm64`.

### Microsoft's samples

Source: [microsoft/Windows-driver-samples](https://github.com/microsoft/Windows-driver-samples)
at the commit pinned in `fixtures.json`. No source or binary patching, ever.

| Fixture id | Driver | Framework | Upstream path |
| --- | --- | --- | --- |
| `wdm-ioctl` | `sioctl.sys` (+ `ioctlapp.exe`) | WDM | `general/ioctl/wdm` |
| `kmdf-echo-autosync` | `echo.sys` (+ `echoapp.exe`) | KMDF | `general/echo/kmdf` |
| `kmdf-echo-driversync` | `echo_2.sys` | KMDF | `general/echo/kmdf` |
| `wdm-cancel` | `cancel.sys` | WDM | `general/cancel/sys` |
| `wdm-cancel-startio` | `cancel.sys` | WDM | `general/cancel/startio` |
| `wdm-event` | `event.sys` | WDM | `general/event` |

### Conformance drivers

The sources in `nkc/` are NK's, not Microsoft's. A conformance driver
exercises a few kernel routines and writes down what it observed as a
list of 32-bit values; the same binary is loaded on real Windows and on
the kernel under test, and the two lists must be identical. `nkc/nkc.h`
is the part they share and states the rules: facts only, never addresses
or times; documented routines only, with the one exception marked in
`nkc/nkc-undoc.h`; nothing left behind. Each driver creates one device,
`\Device\<name>`, and answers device-control code `0x222000` with its
list; what every value means is written next to the line that logs it.
A driver with more lists than one answers `0x222004` and on with the
others; the table says which.

The fixture id is the driver's name: `nkc-irql` is `nkc-irql.sys`.

| Fixture id | Device | Observes |
| --- | --- | --- |
| `nkc-irql` | `NkcIrql` | IRQL and spin locks |
| `nkc-dpc` | `NkcDpc` | deferred procedure calls |
| `nkc-timer` | `NkcTimer` | kernel timers with a DPC |
| `nkc-time` | `NkcTime` | clocks |
| `nkc-thread` | `NkcThread` | system threads |
| `nkc-wait` | `NkcWait` | waiting on one object |
| `nkc-waitn` | `NkcWaitN` | waiting on several objects at once |
| `nkc-mutex` | `NkcMutex` | mutexes, fast mutexes and critical regions |
| `nkc-work` | `NkcWork` | work items |
| `nkc-se` | `NkcSe` | security descriptors; on a system thread, as the System process's token: the access check case by case, privilege checks, the access state of an open, the descriptor of a new object (`SeAssignSecurity`), reading and changing a descriptor's parts; a second list (`0x222004`) for tokens: what the `Se` and `Zw` routines say of the System token, duplicates, and impersonation on a thread made for it |
| `nkc-reg` | `NkcReg` | the registry, as a driver uses it: keys and values made, read, enumerated and deleted, every information class with room and without, and the query tables of `RtlQueryRegistryValues` and `RtlQueryRegistryValuesEx` |
| `nkc-ex` | `NkcEx` | the executive: push locks, sequenced singly linked lists, lookaside lists, executive resources (`ERESOURCE`), executive timers, `ExUuidCreate`, pool allocation with a priority or a quota charge; second threads where waiting has to be seen |
| `nkc-rtl` | `NkcRtl` | the run-time library: the C string routines the kernel exports, `_vsnwprintf`, counted strings and the ANSI code page, SIDs, access lists and descriptors, app-container SIDs, the Unicode prefix table, `FsRtlIsNameInExpression`, the table of characters legal in file names. Its other device-control codes (listed at the top of the source) return whole tables as raw data: every character's capital (`0x222800` to `0x22283C`), the code page to Unicode (`0x222840`) and back (`0x222880` to `0x2228BC`) |
| `nkc-etw` | `NkcEtw` | trace providers with nobody listening: ETW registration and writes, WMI registration of a device and the `IRP_MJ_SYSTEM_CONTROL` requests it brings, a WMI event, bugcheck-reason callbacks, `ZwQuerySystemInformation`; a second list (`0x222004`) for the routines a WPP-traced driver looks up by name |
| `nkc-ob` | `NkcOb` | objects: what the reference routines return, referencing through a handle (wrong type, no handle, more access than the handle has, a kernel handle for user mode); a second list (`0x222004`) for the kernel's store of security descriptors |
| `nkc-ps` | `NkcPs` | the System process and its threads: ids, sessions, attaching to the current process, waits and alerts through handles, thread priority through a handle, quota; a second list (`0x222004`) for the host silo: slots, contexts and silo monitors on a system with no container |
| `nkc-seh` | `NkcSeh` | structured exception handling: the order of filters, `__finally` blocks and handlers, what a filter is shown, unwinding, the kernel's raising routines, probes, memory faults a `__try` catches |
| `nkc-seh-fatal` | `NkcSehFatal` | nothing by its list, which is empty: each of its other device-control codes (`0x222400` to `0x222410`, listed at the top of the source) does one thing Windows answers with a bugcheck |
| `nkc-cross` | `NkcCross` | an exception that crosses the kernel: raised in another driver's dispatch routine, or in this driver's completion routine, with a `__try` around the `IoCallDriver` that led there; the order of filters, `__finally` blocks and the handler on both sides. Needs `nkc-cross-b` loaded first. Its device-control code `0x222440` has a DPC routine raise over a `__try`, which may stop the system |
| `nkc-cross-b` | `NkcCrossB` | nothing by its own list: it is the far side of `nkc-cross`, and raises or completes in its dispatch routine as that driver's requests ask |
| `nkc-libuser` | `NkcLibUser` | what it imports from `nkc-lib.sys`: functions by name and by ordinal, a variable, and how often the library was initialised |
| `nkc-lib` | none | an export driver (kernel-mode library): nothing loads it but an importer's import table |
| `nkc-libbad` | `NkcLibBad` | nothing: it imports a name `nkc-lib.sys` does not export, so a loader must refuse it |

`nkc-libuser` and `nkc-libbad` do not link against the library's project
output. Before linking, each makes its import library with `lib /def`:
`nkc-libuser` from `nkc-lib.def`, the file the library itself is linked
with, and `nkc-libbad` from `nkc-libbad.def`, which lists one symbol more
and has no library behind it. `fixtures.json` states under `expect` what
each of the three must import or export, and the pipeline refuses a
build that linked otherwise.

### The ABI probe

Fixture `abi-probe`, `abi-probe.sys`. The sources in `abi-probe/` are
NK's, not Microsoft's. Each declares a
table of `sizeof` and `FIELD_OFFSET` values for driver-visible structures,
and of constants a kernel must agree on. The WDK compiles them like any
driver, so the numbers are what Microsoft's compiler and headers produce
for the pinned target, on each architecture.

| File | Includes | Records |
| --- | --- | --- |
| `probe.c` | `<ntifs.h>` | I/O (`DEVICE_OBJECT`, `IRP`, `MDL`, ...), security, the registry's query structures, `EXCEPTION_RECORD`, every field of `CONTEXT`, `ERESOURCE`, lookaside lists, `ACCESS_STATE`, ... |
| `probe-unwind.c` | `<windef.h>` | what the unwinder shares with a driver's language handler: `DISPATCHER_CONTEXT`, `SCOPE_TABLE`, `RUNTIME_FUNCTION`, `UNWIND_HISTORY_TABLE`. The kernel headers do not define these; `<winnt.h>` does, and cannot be included next to `<ntifs.h>` |

The pipeline reads every table back out of the built image and publishes
them as one file, `abi-probe.<arch>.txt`, one fact per line:

```
sizeof DEVICE_OBJECT 336
offsetof IRP Tail.Overlay.CurrentStackLocation 184
```

A kernel can check its own structure definitions against that file. The
driver itself is not meant to be loaded.

### The registry hive

`hive/system.hive.txt` lists registry keys and values, one per line; the
format is documented at the top of the file. A CI job on the Windows
runner turns it into a real hive, `system.hiv`
(`scripts/fixtures.py hive`, `scripts/hive.py`):

1. an empty key under `HKLM\SOFTWARE` is saved to a file, which is an
   empty hive;
2. that hive is loaded at `HKLM\NKHIVE`;
3. every key is created with `RegCreateKeyExW` and every value set with
   `NtSetValueKey`, so the stored bytes are exactly the manifest's;
4. the hive is saved in the latest hive format (`RegSaveKeyExW`,
   `REG_LATEST_FORMAT`) and unloaded.

So the container is written by Microsoft's registry: its cells, lists,
hashes, security records and checksum are what Windows produces. The
content has two parts. What a kernel reads at boot is copied from an
installation of Windows 10: `Select`; under `ControlSet001`,
`Control\ServiceGroupOrder` and `Control\GroupOrderList` in full, an
empty `Control\Class`, and the `Services` keys of `Null`, `Npfs`, `Msfs`
and `msrpc` with the values Windows gives them (none has an
`ImagePath`). `Control\NkTest` is NK's and exercises the format: every
common value type, values of 0 to 5 bytes, values past 16344 bytes that
need big-data cells, names that are and are not Latin-1, a key with a
class, 1200 subkeys of one key. The manifest says for each key where it
comes from and what of Windows' key it leaves out.

`reg.exe` is not used: it cannot set a key's class, and a value larger
than a command line cannot be passed to it.

The job refuses to publish a file that is not a clean hive (signature,
checksum, sequence numbers, length) or whose format version has no
big-data cells. The hive is not reproducible byte for byte (it carries
timestamps); like every fixture, its identity is its SHA-256.

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
  (`nkc-seh.x64.nkc-seh.sys`, `wdm-ioctl.arm64.sioctl.sys`, ...)
- `abi-probe.<arch>.txt` — the ABI probe's table as text
- `system.hiv` — the registry hive, the same for every architecture
- `nk-fixtures-<arch>.zip` — everything for one arch: drivers, PDBs, INF/CAT,
  companion apps, upstream license
- `manifest.json` — upstream commit, toolchain versions, msbuild properties,
  run URL, and per file: size, SHA-256, PE machine/timestamp/image size,
  signature flag, the full import table by DLL and, for a driver that
  exports, its export table; under `hives`, per hive: size, SHA-256, the
  SHA-256 of its manifest, key and value counts and what its base block says
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
the PE reader, the ABI table reader, the hive manifest and its parser,
`fixtures.json` against the sources, collect and finalize.

```sh
python3 -m unittest discover -s tests
```

## Status and limits

These binaries have not yet been run on a reference Windows 10 installation.
Until that baseline exists they are "WDK-built", not "Windows-verified".

## License

Scripts and workflow in this repo: MIT (`LICENSE`). The driver samples are
Microsoft's, under the MS-PL; their license ships inside each release zip.
