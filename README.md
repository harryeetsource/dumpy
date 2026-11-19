# Dumpy — Windows memory forensics and PE recovery (work in progress)

## v0.11.0: bounded import/export verification and recovery prioritization

The new `pe_verify.rs` checks rebuilt file-layout images beyond the mere
existence of import/export directory headers. Import checks validate descriptor
terminators, DLL-name strings, thunk termination, imported names, ordinal
encodings and RVA bounds. Export checks validate DLL names, address/name/
ordinal arrays, referenced names, ordinal bounds and forwarder strings.
Malformed or truncated structures are reported with bounded reference-error
counts. Tables are classified as `absent`, `valid`, `invalid`, or `incomplete`
(where their declared directory pages were missing). If an import descriptor
lacks `OriginalFirstThunk`, recovery flags that the first-thunk/IAT path may
contain relocated or resolved runtime pointers; original names are not invented.

New files under each recovery report directory:

- `dumpy_pe_validation.tsv`: per-image import/export statuses, table sizes,
  invalid references and suspected resolved-IAT indicator.
- `dumpy_triage.tsv`: prioritized list of recovered files with file-backed
  and executable coverage, import/export page gaps and table status.

The triage labels are `file-backed-complete`, `executable-complete`,
`high-coverage` (at least 95% file-backed pages), and `partial-review`.
These labels are **forensic prioritization**, not proof that a dumped image
is an exact original on-disk PE or safe to execute. The scanner still bounds
raw-root discovery and all import/export pointer dereferences.

Full-memory test command:

```powershell
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
.\dumpy.exe --recover-user .\complete.dmp .\full-user-v011 100000 301 512
```

For the **already extracted 4,530 images**, run the new offline verifier
instead of repeating the full-memory scan:

```powershell
.\dumpy.exe --verify-dir .\full-user-v010\raw_deduplicated
```

This reads `.recovered.pe`, `.partial.bin`, and `.merged.bin` files in that
directory, validates their PE headers/import/export references and writes
`dumpy_existing_validation.tsv`. The offline report cannot infer which bytes
were originally missing from RAM; the full recovery command additionally
uses page-availability data to classify incomplete directory pages.

## v0.10.0: section-aware image completeness

In addition to total mapped page availability, the recovery pipeline now
calculates **file-backed page coverage** (headers plus section `SizeOfRawData`)
and **executable file-backed page coverage** (sections with
`IMAGE_SCN_MEM_EXECUTE`). The CSV-style TSV columns are:
`file_backed_pages`, `missing_file_backed_pages`, `executable_pages`, and
`missing_executable_pages`. A new `dumpy_sections.tsv` lists each PE section's
name, RVA, raw-data byte count, executable flag, total file-backed pages and
missing file-backed pages. The existing total `available_pages` and
`missing_pages` remain as before, so missing uninitialized image tails are not
mistaken for missing initialized executable bytes.

The scanner **does not relabel incomplete mappings as complete executables**:
page merging can still mix process-private modifications, import names can be
rewritten in memory, and import/export tables can reference memory outside
their declared directory byte ranges. `dumpy_sections.tsv` is forensic
triage metadata, not proof of PE executability or original disk identity.

Run `--recover-user` with your existing dump and a fresh output directory to
generate the updated report schema.

v0.9.6 removes the unused legacy `user_images::scan` wrapper and
`MAX_IMAGES` constant after the new configurable `scan_limited` API was
introduced. The synthetic page-table regression test now calls that API.

## Automatic user-process PE recovery (v0.9.0)

### v0.9.1 diagnostic update

The user-image scanner checks **every present 4 KiB user page boundary**,
including addresses not aligned to 64 KiB, and probes subpages of large
mappings. Console diagnostics distinguish `mapped_pages` (present page-table
entries), `readable_pages` (physical bytes available),
`missing_physical_pages`, `mz_hits`, `rejected_pe` (invalid PE headers),
`unaligned_pe`, missing page tables and unreadable candidate headers.
A synthetic four-level page-table test covers a non-64 KiB-aligned PE and a
present mapping whose physical page is absent from the capture.

### v0.9.2 raw/padded full-memory exploration

### v0.9.3 deduplicated raw recovery

### v0.9.4 multi-DTB missing-page recovery

### v0.9.5 configurable full-dump coverage

The v0.9.4 test found **14,805 additional page recoveries across 88 merged
images**, approximately 57.8 MiB. The most improved image at virtual base
`0x7ff8199f0000` recovered 14,182 fallback pages and had 38,135 available
pages after merging. The log also confirmed the previous cap of 32/301 roots,
with several individual scans truncated at the 128-image ceiling.

Raw-memory recovery now accepts two extra bounded arguments to increase those
limits deliberately. Syntax:

```powershell
.\dumpy.exe --recover-user .\complete.dmp .\full-user-v095 100000 301 512
```

Arguments after the output directory are, in order:
`max_mapped_pages` (default 100,000 for raw captures), `max_roots`
(default 32), and `max_images_per_root` (default 128). Upper limits are
100,000,000 pages, 8,192 roots and 4,096 images respectively. This expanded
scan may take significantly longer and produce more candidates and temporary
RAM usage; start with the defaults when testing a new acquisition. The
page-table/PE safety checks and explicit truncation diagnostics remain intact.

The v0.9.3 full-memory test reduced 1,195 raw PE candidates to **321 distinct
header identities**, removing 874 redundant copies. The results were still
mostly partial even when several address spaces mapped an identical PE header.

Raw recovery now selects up to eight DTBs with the strongest sampled page
coverage for each header identity. It reads each page from the preferred DTB
first, and consults the other matching-header roots **only when that page is
unavailable**. `dumpy_recovery.tsv` has a `fallback_pages` field, while
`dumpy_page_sources.tsv` records the virtual address and supplying fallback
DTB for every substituted page. The header identity is checked before roots
are grouped. This does not establish that their modified private section
pages are equivalent; cross-root compositions are named `*.merged.bin`, not
`*.recovered.pe`, even if every page becomes readable. They are forensic
composites, not guaranteed coherent executables.

With very large images, fallback reads can be expensive; the eight-root bound
prevents unbounded attempts. Existing missing-page and import/export status
reporting remains intact.

An actual full-memory test found 325 structural roots, 301 user-capable roots
in the coherent cohort, and **1,195 PE candidates** across 32 scanned roots.
Many were repeat views of the same DLL mapped at the same virtual base.

Raw recovery now collects candidates before reconstruction, groups them by
virtual base, declared image size, and a 64-bit fingerprint of the entire first
PE header page, and chooses the DTB with the best readable-page coverage across
up to 256 evenly spaced sample pages. It reconstructs only the chosen copy,
instead of creating many similar partial images. A distinct PE header at the
same address is **not** deduplicated. The full list of referring roots and
the selected winner are saved in `raw_deduplicated/dumpy_raw_aliases.tsv`.
Other reports and recovered images are written under `raw_deduplicated/`.

The coverage rank is a sample, not a guarantee of the globally most complete
mapping. The grouping also cannot prove two identical header pages have
identical modified section contents. Use a fresh output directory to avoid
confusing old v0.9.2 files with deduplicated output.

`--recover-user` now handles inputs classified as `RawOrPadded` by attempting
bounded **tentative flat-physical-memory** discovery. It scans for self-referencing
PML4 pages, requires at least two candidate roots to share the same self-ref
slot and matching non-self kernel mapping, then scans up to 32 root candidates
with user mappings (100,000 present pages per root by default). Candidates
are named by DTB rather than PID because a raw image lacks crash-header
process metadata. Readable PE images are reconstructed with existing per-page
missing-data accounting. Both acceptance and rejection of the flat mapping
are printed as diagnostics; a structural candidate is evidence, **not proof**
of the acquisition's physical address layout. Output must be validated.

```powershell
.\dumpy.exe --info .\complete.dmp
.\dumpy.exe --recover-user .\complete.dmp .\full-user-output
# Optional per-root page budget:
.\dumpy.exe --recover-user .\complete.dmp .\full-user-output 500000
```

The full-dump search may take considerable time and can find no roots if
CrowdStrike's acquisition contains non-flat data or physical-address gaps.
No unverified file-header signature is treated as a valid physical page map.

The process-list and DTB heuristics validated against the supplied Windows 11
kernel dump are now connected to user virtual-address scanning:

```powershell
.\dumpy.exe --processes .\fred.dmp
.\dumpy.exe --recover-user .\fred.dmp .\user-output
# Optional: allow up to two million present logical pages per process
.\dumpy.exe --recover-user .\fred.dmp .\user-output 2000000
```

This command requires **neither an image base nor a process DTB**. It discovers
structural PML4 roots, traverses the active process list, and uses only processes
with exactly one matching DTB candidate. It then walks four-level AMD64 paging
tables in the user half of each process's address space, including 2 MiB and
1 GiB large pages, probing 64 KiB-aligned present pages for validated PE
headers (every 4 KiB page as of v0.9.1). Each discovered candidate is reconstructed through the existing
page-aware PE recovery pipeline, with per-process `dumpy_recovery.tsv` and
`dumpy_missing_pages.tsv` reports. A PE with absent pages is explicitly named
`*.partial.bin` rather than misrepresented as a complete image.

The default scan budget is **500,000 present logical pages per process**,
200,000 page tables and 128 candidates per process. The optional final argument
changes the mapped-page budget. A truncated scan is reported explicitly.

**Important limitations:** This is a bounded first-pass scanner; it detects
4 KiB page-aligned PE headers only, and requires header pages and relevant
page tables to be present in the captured memory. Process-list corruption
currently stops traversal and is reported as `PARTIAL`; it does not establish
that later processes are absent. Windows kernel crash dumps commonly exclude
user pages, so zero recovered user images from `fred.dmp` is not proof that
processes had no images. Full-memory acquisition is the appropriate test for
user PE recovery. Process names, PIDs and DTB offsets remain heuristic without
matched Windows type symbols; the user-image names are generic address-based
labels. The recovered PE's import/export descriptors are preserved as present,
but resolved IAT pointers cannot reliably be turned back into original import
names from a single image alone.


Build on Windows with `cargo build --release`, then run:

```
dumpy.exe "D:\path\memory.raw" "D:\recovered-pes"
```

This is an incremental Rust 2021 implementation named **Dumpy**. It uses only the Rust standard library. The original three user files are kept intact in `original_reference/` for comparison. The current `src/` implementation is a rewrite; it does not yet retain all capabilities of those original files.

## Changes

- Checks signed / malformed `e_lfanew`, signatures, header and section lengths, numeric overflow and truncation.
- Scans in 8 MiB windows, including `MZ` signatures crossing window boundaries, with accurate absolute offsets.
- Uses bounded, seek-based reads per candidate (600 MiB maximum PE image).
- Reconstructs section-based, mapped images into disk layout when needed; preserves raw file-layout candidates when preferred.
- Keeps import/export directory values and descriptor references as RVAs. Converting these to raw file offsets corrupts valid PEs.
- Validates the presence and basic structure of import and export directories and reports damaged ones.
- Names output by original byte offset so multiple candidates cannot overwrite one another.

## Recovery limitations

- A process memory image may have an overwritten IAT, missing bound-import data, relocated pointers, and absent overlays. Recovering *original* import tables from a loaded process can require reverse mapping the loaded DLL exports and reconstructing imports, which isn't possible solely from these file bytes.
- The input may contain false-positive `MZ` byte patterns. A reported extracted file is structurally plausible, not guaranteed to be executable or malware-free.
- In ambiguous cases where both raw and mapped layouts look plausible, this version prefers raw layout. Some mapped images without usable directories may need explicit mode selection.
- PE overlays, certificates and appended data may be lost when the reported file size ends at the last section.
- Rust compilation and runtime behavior must be verified on your Windows machine. The development environment used for this revision did not provide `cargo` or `rustc`.

Test with `cargo test`, then `cargo clippy --all-targets -- -D warnings`.

## Memory-aware foundation (v0.3)

The existing two-argument invocation still runs physical signature carving.
New commands:

```
dumpy.exe --info "D:\capture.raw"
dumpy.exe --discover "D:\capture.raw"
dumpy.exe --modules "D:\kernel.dmp"
dumpy.exe --virtual "D:\capture.raw" 0x1aa000 0x7ff700000000 "D:\output\recovered.exe" 4
```

The `--virtual` mode requires a **verified flat physical memory image**, the process's
directory table base (DTB/CR3), and the mapped image virtual base. The example
addresses are placeholders, not values discovered from your dump.

It supports AMD64 4-level and 5-level paging and 4 KiB, 2 MiB, and 1 GiB pages.
It reads each virtual page using its page-table translation and fails explicitly
on absent pages, avoiding silent zero-filling. It then reconstructs section data
into the PE's raw file layout while retaining import and export RVAs.

**Not implemented:** automatic Windows kernel/process discovery, process-specific DTB retrieval,
Microsoft PDB type resolution, minidump streams,
or reconstruction of imports whose names were overwritten by resolved IAT entries.
The `--info` classification `RawOrPadded` means only that known crash/minidump
signatures were not detected; it is not positive proof that file offsets are
physical addresses. Do not use `--virtual` without independently verifying that.

### Experimental candidate discovery

`--discover` now scans for structurally plausible self-referencing AMD64 PML4
pages, without asking the user for a DTB. This is an **initial heuristic**:
Windows configurations without a self-referencing top-level page-table entry
may not appear; a candidate is not yet a validated process root; it is not
automatically fed into PE recovery. Future kernel/PDB validation is necessary
before connecting discovered roots to process enumeration. At most 4096
candidates are retained and the first 100 are printed.

### PAGE/DU64 crash dumps

The program now parses Windows x64 crash dump headers, run-based (`DumpType=1`)
and bitmap-selected (`DumpType=5` full; `DumpType=6` kernel) physical pages. It maps physical addresses
to their stored file offsets for paging and discovery. Other dump types and
unknown bitmap variants fail explicitly. `--info` prints crash metadata and
captured range counts. On a recognized crash dump, the normal two-argument
command now performs kernel module PE recovery **without** incorrect raw PE
carving. User-process recovery is not implemented yet.

Version 0.5.2 parses the modern `SDMP`/`FDMP` bitmap subheader at file offset
`0x2000`, with 64-bit FirstPage metadata (`+0x20`), present-page count (`+0x28`),
bitmap bit count (`+0x30`), and bitset (`+0x38`). The source validates the
captured-page count and the recorded first-page location against the dump file
size before mapping. This layout is different from the older summary header
with 32-bit fields near its start.

### Kernel module enumeration (v0.6.0)

`--modules <PAGE/DU64 dump>` walks the kernel's `PsLoadedModuleList` using the
DTB, list-head address and physical-page mapping from the crash header.
It bounds traversal, checks backlink consistency and cycles, tries several
candidate x64 loader entry layouts, and validates each proposed image base
against a mapped PE signature. A module's Unicode name is printed only if
readable. This is a validated heuristic, not symbol-based identification of
the exact `KLDR_DATA_TABLE_ENTRY` layout. Some modules may be skipped when
their pages are absent or the layout differs. `--modules` lists metadata only;
use `--recover-kernel` or the normal two-argument command to rebuild images.

As of 0.6.2, an invalid later link yields a **PARTIAL** traversal report and
prints every previously validated module. The mismatch remains in diagnostics;
the scanner does not skip or follow the damaged link. This supports kernel
dumps whose capture is missing a list page while distinguishing recovered
entries from an entirely validated list.

### Kernel module PE recovery (v0.7.0)

For Windows crash dumps, the normal two-argument command now enumerates the
validated kernel modules and attempts PE recovery from each module's virtual
memory pages:

```
dumpy.exe "C:\captures\memory.dmp" "C:\output\Dumpy"
```

Equivalent explicit command:

```
dumpy.exe --recover-kernel "C:\captures\memory.dmp" "C:\output\Dumpy"
```

The new `src/recovery.rs` reads the mapped images page by page and reconstructs
raw section layout. Outputs with every page readable receive `.recovered.pe`;
outputs with at least one missing page are written as `.partial.bin`. Those
partial files are **not** guaranteed executable and must not be presented as
faithful complete images. Reports `dumpy_recovery.tsv` and
`dumpy_missing_pages.tsv` describe availability and structural validation.
The recovery report additionally distinguishes missing PE header, import
directory and export directory pages from other missing sections.

Missing pages are zero-filled in the partial buffer solely to preserve virtual
offsets for section reconstruction. The reports identify these missing areas.
Original import-name data overwritten by loader-resolved IAT entries is not
reconstructed. This version covers kernel modules, not automatic user-process
PE recovery. Inspect recovered output with an independent PE parser.

### Process discovery candidates (v0.8.0)

```
dumpy.exe --processes "C:\captures\memory.dmp"
```

The initial `src/processes.rs` walks `PsActiveProcessHead` through the captured
kernel DTB, validates list pointers, reads the adjacent PID field as a **hint**,
and searches nearby process-object memory for candidate page-table roots that
match the separately discovered PML4 pages. Candidate names and roots are
reported without claiming that the EPROCESS layout is verified. Dynamic PDB
layout resolution and user-mode module enumeration are still required for
reliable cross-version process identity and executable recovery.
Version 0.8.1 additionally searches memory following `ActiveProcessLinks` for
plausible `ImageFileName` strings and displays relative locations of candidate
DTB fields. Equal relative offsets across several processes provide evidence
for a shared EPROCESS layout, but are not a substitute for matching symbols.
Version 0.8.2 selects an image-name field offset only when at least two
independent process objects agree, then re-reads each fixed-size name field
from that common offset. This avoids reporting the substring `System` inside
`Secure System` as the complete process name. Relative DTB offsets now display
as signed hexadecimal values instead of wrapped unsigned numbers.

See `ARCHITECTURE.md` for a precise inventory of what's implemented, the
proposed module split, format compatibility boundaries, and validation criteria.
