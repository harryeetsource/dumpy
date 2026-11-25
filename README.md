# dumpy

Recover valid PE images from Windows memory dumps — user-mode EXEs and DLLs, .NET assemblies, kernel drivers — attribute them to the processes that had them mapped, and point out code that doesn't belong: unlisted images, hidden drivers, and executable memory outside any image.

dumpy works without symbols. It reads the page tables, PEBs, loader lists, EPROCESS objects and VAD trees straight out of physical memory, and learns the structure offsets for the kernel build it finds in the capture. That includes builds with no published layout.

- Language: Rust, edition 2024 (needs Rust 1.85 or newer; developed against 1.97), no external crates
- Version: `dumpy --version` prints the build string. Every log line of a run starts with the same string, so you can always tell which binary produced a result.

---

## Contents

1. [Build](#build)
2. [Quick start](#quick-start)
3. [Commands](#commands)
4. [How it works](#how-it-works)
5. [Output layout](#output-layout)
6. [Output tiers: what each recovered file is](#output-tiers-what-each-recovered-file-is)
7. [Report reference (TSV columns)](#report-reference-tsv-columns)
8. [Environment variables](#environment-variables)
9. [Reading the log](#reading-the-log)
10. [Limits and caveats](#limits-and-caveats)
11. [Troubleshooting](#troubleshooting)
12. [Testing](#testing)

---

## Build

```bash
cargo build --release
# binary: target/release/dumpy (dumpy.exe on Windows)
cargo test --release
```

The release profile uses LTO. Nothing needs to be installed besides a Rust toolchain, Rust 1.85 or newer (`rustup update stable`).

---

## Quick start

### One command: extract everything

```powershell
.\dumpy.exe --extract-all .\complete.dmp .\out
```

This runs every phase in order and writes `out\INDEX.tsv`, one row per extracted artifact:

1. **User mode:** every address space, 20 per batch, until all are covered. The EPROCESS table and VAD resolution are set up automatically.
2. **EPROCESS:** PIDs, parents, names and create/exit times, from every validated process.
3. **Kernel:** the loaded-module list, recovered with the same tiers and naming as user images. Unlisted kernel images whose code is mapped executable. Executable kernel memory outside every image.
4. **Index:** `INDEX.tsv` (see [INDEX.tsv](#indextsv)).

The command is safe to rerun into the same folder: finished user batches are skipped, and the kernel phase and index are rebuilt.

The rest of this section runs the user-mode phase on its own, which is useful when you want different batch sizes.

### 1. Identify the dump

```powershell
.\dumpy.exe --info .\complete.dmp
```

This reports the acquisition format: a Windows crash dump (`PAGEDU64`), or `RawOrPadded` for flat physical images such as WinPmem raw output, padded or unknown formats.

### 2. Recover user-mode images, process by process (recommended)

A large raw dump has hundreds of address spaces, so it's processed in **batches of roots**. Each batch writes its own tables, and they're merged into one view in the same output folder.

```powershell
$v = .\dumpy.exe --version
New-Item -ItemType Directory -Force .\out | Out-Null
foreach ($start in 0..14 | % { $_ * 20 }) {
    .\dumpy.exe --recover-process-aware .\complete.dmp .\out 200000 20 $start 4096 600 2>&1 |
        Tee-Object -Append .\out\recover.log
}
```

- `200000`: pages scanned per address space
- `20`: address spaces (roots) per batch
- `$start`: first root index of the batch. `0..14` × 20 covers 300 roots; widen the range if the log reports more roots discovered.
- `4096`: maximum image recoveries per batch
- `600`: maximum MiB for a single module

In the same folder:

- **The first batch** builds `dumpy_eprocess.tsv` itself (see [EPROCESS scan](#4-eprocess-scan-pids-parents-times)) and turns on VAD resolution. Later batches reuse the file.
- **Finished batches are never rerun.** Running the loop a second time is harmless: completed batches print `already completed; skipping`. Set `DUMPY_RERUN=1` to redo a batch on purpose.

### 3. Optional: refresh PIDs, parents and times in the process table

```powershell
.\dumpy.exe --eprocess-scan .\complete.dmp .\out
```

This rewrites `dumpy_processes.tsv` with PID, parent, name, create/exit time and active-list membership, and writes `dumpy_eprocess.tsv`.

### 4. Look at the results

```powershell
Get-ChildItem .\out\images -File | Group-Object { ($_.Name -split '\.')[-2..-1] -join '.' } | Select-Object Count, Name
```

The images to analyse are `*.recovered.pe` and `*.code-complete.pe`. See [Output tiers](#output-tiers-what-each-recovered-file-is).

---

## Commands

| Command | Purpose |
|---|---|
| `--version` | Print the build string. |
| `--extract-all <dump> <out>` | **Everything in one pass:** user images over all address spaces, EPROCESS table, kernel modules, unlisted kernel images, unbacked kernel code, and `INDEX.tsv`. |
| `--info <dump>` | Identify the acquisition format and size. |
| `--recover-process-aware <dump> <out> [pages=100000] [roots=8] [root_start=0] [max_recoveries=4096] [max_module_mib=600]` | **Main workflow.** Discover address spaces, find PEBs, walk loader lists, recover images, report unlisted images and orphan executable memory. |
| `--process-scan <dump> <out> [pages] [roots] [root_start]` | Same discovery and reports as above, without recovering images. |
| `--eprocess-scan <dump> <out>` | Locate EPROCESS objects and learn their layout. Fills PID, PPID, name, create/exit time and active-list membership. Needs `dumpy_processes.tsv` in `<out>`. |
| `--verify-dir <dir>` | Re-validate every recovered file in a directory (`.recovered.pe`, `.code-complete.pe`, `.inconsistent.bin`, `.partial.bin`, `.merged.bin`). |
| `--dump-range <dump> <dtb_hex> <va_hex> <len_hex> <out.bin>` | Read an arbitrary virtual range of one address space to a file, for manual inspection. |
| `--probe-image <dump> <dtb_hex> <base_hex> <out_dir>` | Recover one image at a known base in a known address space. |
| `--virtual <flat_dump> <dtb_hex> <base_hex> <out.exe> [4\|5]` | Rebuild one image through 4- or 5-level paging. |
| `--recover-user <dump> <out> [max_mapped_pages] [max_roots] [max_images_per_root]` | Older user-mode carve, not driven by PEBs. Prefer `--recover-process-aware`. |
| `--discover <verified_flat_dump>` | List candidate page-table roots. |
| `--modules <crash_dump>` / `--processes <crash_dump>` | List kernel modules or processes from a Windows crash dump. |
| `--recover-kernel <crash_dump> <out>` | Recover kernel modules from a Windows crash dump. |
| `<dump> <out>` | Default: kernel-module recovery for crash dumps; for anything else, a linear MZ carve of physical memory (no address-space attribution). |

The total scan budget per run (`pages × roots`) is capped at 8,000,000 pages. Use more batches rather than larger ones.

---

## How it works

### 1. Address spaces
- **Root discovery.** Page-table roots (PML4s) are found by their self-referencing entries and checked for coherence (user and kernel halves present, entries pointing inside the capture). 4- and 5-level paging are both supported.
- **The kernel root** (System's CR3) is the root with the most kernel mappings. It's used to read kernel structures: EPROCESS, VAD nodes and prototype PTEs.

### 2. Translation
Besides hardware-valid PTEs, dumpy resolves Windows software PTEs, with per-page provenance:

| Mechanism | When it applies | Provenance column |
|---|---|---|
| Transition PTE | Valid=0, Transition=1: the page is on the standby/modified list and still in RAM. | `transition_pages` |
| Prototype PTE | Valid=0, Prototype=1: a pointer to the section's shared prototype PTE, read through the kernel root. | `prototype_pages` |
| VAD walk | No PTE at all (the page table is absent or the entry is zero): look up the process's VAD tree, take `FirstPrototypePte[page]`, and resolve that. | `vad_pages` |
| PFN unswizzle | Software-PTE PFNs that point beyond the capture with SwizzleBit clear. | (silent) |

`DUMPY_STRICT_PTE=1` turns off everything except hardware-valid PTEs.

### 3. Processes and modules
- **PEB discovery** scans only private read-write, non-executable pages. It also follows TEBs (`NT_TIB.Self` at +0x30 and the PEB pointer at +0x60), and requires the `Mutant == -1` gate.
- **Loader lists** are walked in both directions over all three lists (load, memory and initialisation order), tolerating gaps. `ldr_complete` records whether the lists closed.
- **Identity:** each image is keyed by `(base, SizeOfImage, header fingerprint)` across all address spaces, so a shared DLL is recovered once. Identities carry over between batches through `images/dumpy_identities.tsv`.

### 4. EPROCESS scan (PIDs, parents, times)
Physical memory is scanned for the DTB values of known address spaces. A hit counts as an EPROCESS only when a validated PEB sits at a fixed distance from it. From those confirmed objects dumpy learns, without symbols:

- `Peb`, `UniqueProcessId`, `ActiveProcessLinks`, `InheritedFromUniqueProcessId`, `CreateTime`, `ExitTime` and `ImageFileName`;
- the DTB field position, confirmed by a `DISPATCHER_HEADER` with Type 3 at field − 0x28.

Duplicate copies of the same process, caused by acquisition smear, are grouped by DTB plus PEB. Linkage and exit time are judged per group. A second "shape" pass finds exited processes whose address space is gone.

Twenty validated processes are enough to learn the layout.

### 5. VAD resolution
`EPROCESS.VadRoot` and `MMVAD.FirstPrototypePte` are learned from the capture:

- **VadRoot:** the EPROCESS field that roots the largest valid binary search tree covering the process's PEB, agreed across processes.
- **FirstPrototypePte:** the MMVAD field whose prototype PTEs name the same physical frames as the hardware PTEs of pages the process did touch.

The node header (RTL_BALANCED_NODE plus the MMVAD_SHORT VPN fields) is checked by structure, not assumed.

### 6. Recovery
- **Pages** come from the image's own address space first. A missing page is borrowed from another address space that maps the same identity only when it is a shared image page: headers, or a non-writable section. A third address space is read as a second opinion, and any disagreement counts as a conflict.
- **Rebuild:** dumpy chooses mapped or raw layout from evidence, rebuilds the file, and validates the import and export tables.
- **Naming**, in order: loader list, export-directory name, VERSIONINFO (`OriginalFilename` / `InternalName`), .NET Module name, then the CodeView PDB name. Roslyn script submissions are labelled.

### 7. Kernel space (`--extract-all`)
- **Page-table walk:** the kernel half (PML4 slots 256–511) of the kernel root is walked. The kernel root is the System process's DTB from the EPROCESS table, or the discovery heuristic when that's unavailable. Each table is descended into once, and pages whose entries mostly point outside the capture are rejected as non-tables. Transition PTEs (page on the standby list, still in RAM) count as non-executable leaves, so a header page in that state is still found. Every mapped leaf (4 KiB, 2 MiB, 1 GiB) is listed with its effective NX and writable bits.
- **Module list:**
  - Crash dumps: the `PsLoadedModuleList` head comes from the dump header.
  - Raw dumps: dumpy looks for a PE header in kernel space whose export directory names itself `ntoskrnl.exe` (or `ntkrnlmp`, `ntkrnlpa`, `ntkrla57`). `PsLoadedModuleList` is one of its exports. More than one image can carry that name: on a hotpatched system `ntkrnlmp_hotpatch.exe` does, and its export is not the live list. So every candidate's list is walked, and the longest complete one is used.
  - If ntoskrnl's header isn't in the capture, the list is found by structure. Physical memory is scanned for a `KLDR_DATA_TABLE_ENTRY` whose DllBase (+0x30) and SizeOfImage (+0x40) match an image found in kernel space. The list is then followed around the ring, and the one node that isn't an entry is the head.
  - An entry whose own header page is missing stays in the list, marked `header not in capture`. Its mapped bytes are written raw as `.headerless.bin`.

  The list is walked with backlink checks.
- **Listed modules** are recovered like user images. A module that reads better through a user address space than through the kernel root is recovered from that one and noted `session space`; that's how win32k-family drivers are reached.
- **Unlisted kernel images:** PE headers at kernel page starts that aren't inside any listed module.
  - If any page of the image's code is mapped executable, it's recovered and reported. Whether the header page is writable is noted, but on its own that means nothing: plenty of ordinary drivers have writable headers.
  - Otherwise it's a PE held as data (file-cache views, pool copies) and is only counted.
- **Unbacked kernel code:** executable kernel pages outside every listed or unlisted image are merged into regions. Each region is classified by content, the module before it is named, and a `relation` is given: `module tail` (at most 16 KiB, within 64 KiB past a module's end), `gap`, or `before first image`. Module tails show up for most modules on current builds; they're loader-made stubs, not injection. The rest are what to review. Regions are written to `kernel/orphans/` (up to 16 MiB each, 256 MiB in total).

### 8. Review sets
- **Unlisted images:** PE headers mapped in an address space but missing from its loader list.
- **Orphan executable regions:** executable user memory not covered by any known image. Each one is classified by content and by the runtime it belongs to (.NET, V8/Chromium/Electron/CEF, JScript, JVM, CrowdStrike UMPPC).

---

## Output layout

```
out/
├── INDEX.tsv                           every artifact, user and kernel (--extract-all)
├── recover.log                         (from Tee-Object)
├── dumpy_processes.tsv                 address spaces with a validated PEB (merged)
├── dumpy_modules.tsv                   loader-list modules (merged)
├── dumpy_unlisted_images.tsv           PEs not in any loader list (merged)
├── dumpy_orphan_executable.tsv         executable memory outside known images (merged)
├── dumpy_skipped_modules.tsv           modules not recovered, with reason (merged)
├── dumpy_eprocess.tsv                  EPROCESS objects (built by batch 0 or --eprocess-scan)
├── dumpy_eprocess_lookalikes.tsv       DTB-holding objects that are not processes
├── dumpy_<table>.r<start>-<end>.tsv    per-batch tables (merged into the above)
├── .dumpy_batch_r<start>-<end>.done    batch completion markers
├── dtb_<dtb>_orphans/                  bytes of orphan executable regions
├── kernel/                             (--extract-all)
│   ├── <name>_0x<base>.<tier suffix>   listed modules; unlisted ones are kimage_<base>…
│   ├── dumpy_recovery.tsv, dumpy_missing_pages.tsv, …   same reports as images/
│   ├── dumpy_kernel_unlisted.tsv       unlisted kernel images
│   ├── dumpy_kernel_orphans.tsv        executable kernel regions outside images
│   ├── dumpy_kernel_index.tsv          kernel rows of INDEX.tsv
│   └── orphans/kcode_<va>.bin          bytes of those regions
└── images/
    ├── <name>_0x<base>.recovered.pe
    ├── <name>_0x<base>.code-complete.pe
    ├── <name>_0x<base>.inconsistent.bin
    ├── <name>_0x<base>.merged.bin
    ├── <name>_0x<base>.partial.bin
    ├── dumpy_recovery.tsv              one row per recovered identity (merged)
    ├── dumpy_missing_pages.tsv         every page not recovered, with reason
    ├── dumpy_page_sources.tsv          pages borrowed from another address space
    ├── dumpy_sections.tsv              per-section coverage
    ├── dumpy_pe_validation.tsv         import/export table audit
    ├── dumpy_triage.tsv                priority-sorted summary
    ├── dumpy_identities.tsv            identity registry shared by batches
    └── batch_r<start>-<end>/           per-batch copies of the image reports
```

Images without a name are written as `image_<base>_h<fingerprint>…`.

---

## Output tiers: what each recovered file is

| Suffix | `completeness` | Meaning | Use for analysis? |
|---|---|---|---|
| `.recovered.pe` | `exact` | Every page present, and the import/export tables parse (or are absent). | **Yes** |
| `.code-complete.pe` | `code-complete` | Headers, every executable page, and the import/export directories came from memory and validate. Only non-executable data (typically `.rsrc`, `.reloc`, `.data` pages never touched) is zero-filled; the diagnostics column lists what. | **Yes**: loadable and analysable, but not byte-identical to disk |
| `.inconsistent.bin` | `inconsistent` | Every page present, but the pages are not one image: either the tables don't parse, or a kernel driver header (ImageBase in kernel space) sits over a user mapping. Caused by stale PTEs or acquisition smear. | No; look only if you're chasing that address |
| `.headerless.bin` | `headerless` | Kernel module from the module list whose header page is missing: its mapped bytes, written raw (missing pages zero-filled). | For strings, YARA and disassembly at the module's base |
| `.merged.bin` | `merged` | Needed a writable (per-process) page from another address space, or address spaces disagreed on a shared page. | With care |
| `.partial.bin` | `partial` | Pages missing beyond the code-complete bar; missing pages are zero-filled. | For strings and YARA, not execution |
| (no file) | `unavailable` | Nothing recoverable, or section reconstruction failed. | n/a |

A recovered file is a **rebuild from memory**:
- Its hash will not match the on-disk file.
- Authenticode signatures don't survive, because the certificate table is never mapped. `Get-AuthenticodeSignature` will report `NotSigned` even for signed binaries.

Use the `pdb_key` column (GUID plus age) to identify the exact build instead.

---

## Report reference (TSV columns)

### `INDEX.tsv`

One row per artifact, written by `--extract-all`.

| Column | Meaning |
|---|---|
| `category` | `user-image`, `dotnet-assembly`, `dotnet-roslyn-script`, `user-orphan-code`, `kernel-module`, `kernel-unlisted`, `kernel-orphan-code` |
| `name`, `name_source` | Name and where it came from: `loader list`, `kernel module list`, `export name`, `version resource`, `.NET module`, `.NET module, Roslyn script submission`, `pdb name`. Empty when unnamed. |
| `owner` | Processes that map the image, as `name(pid)`: the first three, then `+N more`. `kernel` for kernel artifacts. |
| `base`, `size` | Virtual base and size (span for raw regions). |
| `tier` | `exact`, `code-complete`, `inconsistent`, `merged`, `partial`, `unavailable`, `headerless` (kernel module without a header), or `raw-region` for orphan code. |
| `output` | File written. |
| `notes` | `not in the loader list of …`, PDB key, content class, runtime, `session space`, `header page writable`, relation (`module tail …`, `gap`, `before first image`), `after <module>`, `large page`. |

To pull out the review set:
```powershell
Import-Csv .\out\INDEX.tsv -Delimiter "`t" | Where-Object { $_.category -in 'kernel-unlisted','kernel-orphan-code','user-orphan-code' -or $_.notes -like 'not in the loader list*' }
```

### `images/dumpy_recovery.tsv`

| Column | Meaning |
|---|---|
| `name` | Image name. A source suffix in parentheses shows where it came from: `(export name)`, `(version resource)`, `(.NET module)`, `(.NET module, Roslyn script submission)`, `(pdb name)`. No suffix means the loader list. |
| `base`, `image_bytes` | Virtual base address and SizeOfImage. |
| `available_pages`, `missing_pages` | Page counts. |
| `missing_header`, `missing_import`, `missing_export` | Missing pages that hold the headers, import tables or export tables. |
| `file_backed_pages`, `missing_file_backed_pages` | Pages backed by file content (sections with raw data). |
| `executable_pages`, `missing_executable_pages` | Pages in executable sections. |
| `fallback_pages` | Pages borrowed from another address space; split into `fallback_shared_pages` (headers or read-only sections), `fallback_private_pages` (writable sections) and `fallback_conflicts` (a third mapping disagreed). |
| `transition_pages`, `prototype_pages`, `vad_pages` | Pages resolved through software PTEs (see [Translation](#2-translation)). |
| `completeness` | Output tier (see table above). |
| `priority` | `file-backed-complete`, `executable-complete`, `high-coverage` (≥95% file-backed), `partial-review`, `incoherent-review`. |
| `import_status`, `export_status` | `valid`, `absent`, `invalid` or `incomplete` (plus raw and mapped variants of each). |
| `layout` | Layout the rebuild was based on: `mapped-image` or `raw-file-view`. |
| `executable_utf16_ascii_ratio`, `incoherent_warning` | Flags executable sections that hold text instead of code. |
| `pdb`, `pdb_key` | CodeView PDB path and symbol-server key (GUID with no dashes, then age in hex). |
| `clr_module` | .NET Module name, when present. |
| `output`, `diagnostics` | Written file, and a plain-language summary including zero-filled sections. |

### `images/dumpy_missing_pages.tsv`
`name`, `virtual_address`, `reason`. Reasons name the mechanism that stopped the walk:

| Reason | Meaning |
|---|---|
| `PT/PD/PDPT/PML4 zero: never touched, VAD/section only` | No PTE. Normally resolved through the VAD; seen only when VAD resolution is off. |
| `PT prototype: file-backed, not in RAM` | The page was never read from disk. **Not in the dump.** |
| `PT prototype PTE itself unmapped` | The prototype PTE array lives in paged-out pool. |
| `PT prototype: paged out` / `PD/PT pagefile` | The page is in the pagefile. Not in the dump. |
| `PT demand zero` / `VAD: private memory, never touched` | Never-allocated private memory. |
| `VAD: no VAD covers address` | Address outside any VAD. |
| `physical page absent` | The PFN points beyond the capture. |

Each batch's log ends with a `[missing-census]` summary of these reasons.

### `dumpy_processes.tsv`
`dtb`, `peb`, `bitness`, `image_base`, `pid_hint`, `name_hint`, `ldr`, `modules`, `ldr_entries`, `ldr_complete`, `skipped_headers`, `known_identity_headers`, `pass`, `readable_pages`, `private_rw_pages`, `teb_hits`, `transition_pages`, `truncated`, `wow64_peer`. After `--eprocess-scan`, five more columns are added: `ppid`, `create_time_utc`, `exit_time_utc`, `in_active_list` and `state`.

### `dumpy_modules.tsv`
`dtb`, `peb`, `base`, `size_of_image`, `name`, `ldr_lists` (which of the three lists hold the module), `header_source` (`memory` or `known-identity`), `fingerprint`, `listed_in_roots`, `rx_pages`, `ldr_complete`.

### `dumpy_unlisted_images.tsv`
`attribution` is one of:
- `unlisted`: the process's loader list is complete and doesn't contain this image. **Review these.**
- `unlisted-ldr-incomplete`: the loader list didn't close, so the image may simply have been missed.
- `unattributed`: the address space has no validated PEB.

Other columns: `rx_pages`, `aligned_64k`, `known_elsewhere` / `known_name` (the same identity is listed in another process), `same_header_as`, `pe_summary` (kind, machine, timestamp, sections, imports, exports), `output`.

### `dumpy_orphan_executable.tsv`
Executable user memory outside every known image. Columns:
- `process_runtime`: the runtime the owning process belongs to, from its modules (.NET, V8 and so on).
- `content_class`: `code`, `text`, `binary` or `mostly-zero`.
- `overlaps_known_module`, `content_match` (page-hash match against recovered images), `probable_base`, `probable_base_status`.
- `large_page`, and `first_page_physical` (marked `beyond capture: stale PTE` when the PTE points outside the dump).

### `dumpy_eprocess.tsv`

| Column | Meaning |
|---|---|
| `source` | `dtb-anchored` (found by DTB value) or `shape` (exited process found by structure). |
| `state` | `running`, `exited`, `exited(page tables still in RAM)`, `exited(this copy imaged before exit)`, `no-exit-time,root-missing`, `root-missing`. |
| `pid`, `ppid`, `name`, `create_time_utc`, `exit_time_utc` | From the learned layout. Names are ImageFileName, truncated to 14 characters by Windows. |
| `in_active_list`, `group_linked` | Whether this copy, and whether any copy of the process, is reachable from ActiveProcessLinks. **Use `group_linked`** to judge whether a process is unlinked. |
| `duplicate_of` | Physical address of the first copy of the same process. |
| `eprocess_va`, `eprocess_phys`, `dtb`, `peb`, `peb_confirmed`, `plausible` | Location and validation. |

Objects that hold a DTB value but don't read as a process go to `dumpy_eprocess_lookalikes.tsv`.

---

## Environment variables

| Variable | Effect |
|---|---|
| `DUMPY_RERUN=1` | Redo a batch that already finished in this output folder. Its identities are recovered again and its tables rebuilt. |
| `DUMPY_STRICT_PTE=1` | Hardware-valid PTEs only: no transition, prototype or VAD resolution. |
| `DUMPY_EPROCESS_ALL=1` | Keep look-alike objects in `dumpy_eprocess.tsv` instead of the sidecar file. |

---

## Reading the log

| Line | Meaning |
|---|---|
| `[process-aware] dumpy <version>` | The binary that produced this batch. |
| `[process-aware] N roots discovered; scanning indices a..b` | Total address spaces found, and the range this batch covers. |
| `[vad] building …dumpy_eprocess.tsv from N anchored address spaces` | First batch in a new folder; the EPROCESS file is being built. |
| `[vad] EPROCESS.VadRoot=+0x… … installed for X of Y address spaces` | VAD resolution is on. Expect X close to Y. |
| `[vad] VAD resolution off: …` | VAD resolution is off, with the reason. Coverage will be noticeably lower. |
| `[missing-census] …` | Why the pages still missing in this batch are missing. |
| `[recover] <name> base=… available=… missing=…` | One recovery, with its diagnostics. |
| `already completed; skipping` | Finished batch skipped (see `DUMPY_RERUN`). |
| `[eprocess] absolute EPROCESS offsets: …` | The learned layout for this kernel build. |
| `[kernel] first module (the kernel): … header page found / not present in the capture` | The first list entry is ntoskrnl. If its header is missing, it comes out as `.headerless.bin`. |
| `[kernel] tables: N aliased …, M rejected …` | Shared page tables are walked once, and pages that don't look like page tables are skipped. A large rejected count means the kernel root is suspect. |
| `[kernel] leaves per PML4 slot …` | Where the kernel mappings are, as `slot:leaves/executable`. Driver code lives in the slots with executable leaves. |
| `[kernel] ntoskrnl.exe at 0x…: PsLoadedModuleList=0x… -> N modules` | One line per image that exports the kernel's name, with the size of the list it leads to. |
| `[kernel] using the module list of … (N modules)` | The candidate chosen. |
| `[kernel] unlisted executable images: N; PE headers in data …: M` | N images are recovered as `kernel-unlisted`; M PEs held as data are only counted. |
| `[extract-all] INDEX.tsv: N artifacts` | Run finished. |

---

## Limits and caveats

- **Memory holds only what was read.** Windows maps an entire image but reads only the pages a process touches. On a typical capture most still-missing image pages are `file-backed, not in RAM`; no memory-side technique can recover them, and they come out zero-filled.
- **Acquisition smear.** Live captures are taken over minutes. Objects can appear twice with drifting counters, and a PTE can point at a frame that was reused mid-capture. dumpy groups duplicate EPROCESS copies, checks shared pages against a second address space, and moves images whose pages don't form one image to the `inconsistent` tier.
- **Freed page tables.** A self-referencing PML4 can outlive its process. `dumpy_eprocess.tsv` marks such address spaces `exited(page tables still in RAM)`.
- **Learned, not looked-up, offsets.** EPROCESS and VAD offsets are inferred and printed in the log. If the log shows low support counts, treat PIDs, names and times as provisional.
- **Kernel scan scope:**
  - The kernel walk assumes 4-level paging.
  - Large pages are searched for PE headers only at their first byte.
  - The walk stops at 24 million leaves, with a warning in the log.
  - Unlisted kernel images count only if their code is mapped executable. A driver copy held as data is counted in the log but not recovered.
- **Not handled:** VAD-prototype PTE encoding (`ProtoAddress == 0xFFFFFFFF0000`), pagefile content, and the PFN database. That last one would recover pages whose prototype PTEs are in paged-out pool.
- **KVA shadowing:** detected and reported. On shadowed systems the roots found are user CR3s.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Columns or tiers described here are missing from your output | Stale binary. Check `--version` and the first log line of every batch. |
| `process scan budget … exceeds safe cap` | `pages × roots` is above 8,000,000. Use smaller batches. |
| `[kernel] ntoskrnl not identified … searching for the module list by structure` | ntoskrnl's header or export page isn't in the capture. The structural search normally finds the list anyway (`module list found by structure`). |
| `[kernel] module list not found by structure either` | No list is available, so every executable kernel image is labelled `kernel-unlisted`. Read those rows with that in mind. |
| `[vad] VAD resolution off: … not found` with an old binary | Versions before 0.14 needed `dumpy_eprocess.tsv` copied in. Current versions build it in batch 0. |
| `EPROCESS scan failed: no EPROCESS objects confirmed` | Too few validated PEBs, or an unusual layout. Run more batches into the folder (more anchors), then run `--eprocess-scan` on it. The `tried +0x… scores:` lines show which field failed to learn. |
| Results look truncated after running the loop twice into one folder | Pre-0.14.1 behaviour. Current versions skip finished batches. Start a fresh folder for a clean set. |
| `Tee-Object : … DirectoryNotFound` | Create the output folder before the loop (`New-Item -ItemType Directory -Force`). |
| `Get-AuthenticodeSignature` says `NotSigned` | Expected for any rebuilt image; see [Output tiers](#output-tiers-what-each-recovered-file-is). |

---

## Testing

```bash
cargo test --release
```

Unit tests cover:
- page-table classification, gap merging and coalescing;
- PEB and loader-list walking, including incomplete lists;
- EPROCESS layout learning and image-name rules;
- PDB and .NET naming, including non-ASCII Roslyn names;
- export and version naming;
- PE validation.

`tests_fixture_make_flat.py` builds `flat.bin`, a synthetic flat physical image that exercises the whole pipeline, kernel phase included:
- two address spaces and a System-like kernel root;
- a PEB reached through a TEB, and a loader list;
- a shared DLL that needs a borrowed read-only page;
- a DLL whose `.data` page exists only in another process (expected tier `merged`);
- a DLL whose `.data` was never touched (expected tier `code-complete`);
- an unlisted image and an orphan executable page;
- a prototype-pointer PTE;
- EPROCESS-like objects with `DISPATCHER_HEADER`s;
- a three-node VAD tree with prototype PTE arrays;
- in kernel space:
  - an `ntoskrnl.exe` exporting `PsLoadedModuleList`, and a two-entry module list (`ntoskrnl.exe`, `listed.sys`);
  - an unlisted driver with executable code and a writable header;
  - a PE held as data (NX code), which is counted but not recovered;
  - a hotpatch-style decoy below the kernel that also exports `ntoskrnl.exe`, with an empty `PsLoadedModuleList`; it must be rejected;
  - one executable page outside every image.

```bash
python3 tests_fixture_make_flat.py          # writes flat.bin
dumpy --extract-all flat.bin out_fixture
ls out_fixture/images                       # recovered.pe ×2, code-complete.pe, merged.bin
ls out_fixture/kernel                       # ntoskrnl.exe and listed.sys .recovered.pe, kimage_… .recovered.pe
```

The log should show the decoy tried and rejected (`-> 0 modules`), then `using the module list of ntoskrnl.exe at 0xffff800000100000 (2 modules)`. The kernel summary line should read `2 listed modules, 2 unlisted executable images, 1 PE headers in data, 1 executable regions outside images` (the decoy and `hidden.sys` are the unlisted pair). `INDEX.tsv` has 12 rows.

The first batch builds the EPROCESS file and learns `VadRoot=+0x700` and `FirstPrototypePte=+0x50` from the fixture.
