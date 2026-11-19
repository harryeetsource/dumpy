# Dumpy architecture and implementation status

## Purpose

Dumpy is intended to recover PE images from Windows RAM acquisitions using
automatic process-aware virtual memory reconstruction. The long-term CLI is:

```
dumpy.exe <memory_dump> <output_directory>
```

**This full automated workflow is not yet implemented.** The current two-argument
command performs physical MZ carving, which cannot generally recover complete
loaded PE images from scattered physical RAM pages.

## Actual source inventory

| File | Existing behavior | Limitations |
| --- | --- | --- |
| `src/main.rs` | CLI, physical PE extraction, manual virtual extraction, diagnostic commands | No fully automatic process-aware extraction |
| `src/io.rs` | Bounded chunk-based physical scanning and positional reads | Physical bytes are not virtual image bytes |
| `src/rebuild.rs` | PE32/PE32+ parsing, raw/mapped section recovery, rudimentary import/export structure checks | No full import recovery, relocations, TLS, resource repair, or missing-page map |
| `src/memory.rs` | Flat-physical reads, x64 4/5-level translation, 4K/2M/1G pages, virtual read | Requires a DTB, no sparse-page recovery or non-flat dump address mapping |
| `src/discovery.rs` | Bounded physical scan for self-referencing PML4 candidate pages | Heuristic only; no kernel or EPROCESS validation |
| `src/crashdump.rs` | PAGE/DU64 header parsing; type-1 runs and type-5/type-6 bitmap physical page mapping | Not validated against your CrowdStrike dump; other types unsupported |
| `src/kernel_modules.rs` | Bounded PsLoadedModuleList traversal with PE-backed image-base validation | Heuristic entry offsets; no matched PDB layouts |
| `src/recovery.rs` | Kernel module mapped-image reconstruction and sparse-page reporting | Partial outputs may contain zero-filled missing pages; user process recovery not implemented |
| `src/processes.rs` | Active-process list traversal with PID/name/DTB candidate hints | Symbol-free heuristic only; not yet validated across builds |
| `original_reference/*.rs` | Unmodified original user sources | Reference copies, not included in the current binary |

## Planned module structure (NOT implemented yet)

The following architecture is a roadmap, not a description of shipped files.

```
src/
  acquisition/
    raw.rs           Flat/padded memory with physical range validation
    crashdump.rs     Windows crash dump header and physical run mapping
    minidump.rs      Virtual memory stream index and module list
  memory/
    paging.rs        Page table translation and paging modes
    virtual.rs       Sparse virtual page reader with provenance
  windows/
    kernel.rs        Kernel identification and cross-validation
    symbols.rs       PDB identity resolution, cache, and type layouts
    processes.rs     Process enumeration, DTB discovery, validation
    modules.rs       PEB/LDR/VAD image enumeration and validation
  pe/
    parser.rs        Bounded header and section parsing
    rebuild.rs       Raw layout recovery
    imports.rs       ILT, IAT, forwarders, ordinal/name recovery
    exports.rs       Export name/ordinal/RVA recovery
    validate.rs      Structural and consistency checks
  carving/
    signatures.rs    Physical fallback carving
  reporting/
    mod.rs           Source, process, virtual/physical provenance, errors
```

## Architecture boundaries

1. **Acquisition layer:** Dump format detection must never interpret an unknown
   format as proven raw memory merely because it lacks `MDMP` or `PAGE`.
   Structured dumps need their own virtual/physical range mappings.
2. **Memory layer:** For a given process DTB, virtual reads should report
   present, missing, paged-out, or unsupported pages separately.
3. **Windows layer:** Dynamic process discovery needs verified Windows kernel
   state. PML4 self-reference is neither universal nor a sufficient DTB proof.
   Version-dependent structures should use matching symbols, with an explicit
   unsupported state if symbols are unavailable.
4. **PE layer:** Raw versus mapped image layout must be resolved from source
   provenance and structural validation, not only directory byte availability.
   Import/export structures contain RVAs, not raw offsets.
5. **Reporting layer:** Every recovered image should record process PID, name,
   virtual base, translated physical pages, missing ranges, import/export
   diagnostics, and SHA-256. This structured report is not yet implemented.

## Validation gates before calling Dumpy production-ready

- Cargo build, test, formatting and Clippy on Windows and Linux.
- Synthetic physical-memory fixtures exercising all x64 paging page sizes.
- Real, known-good raw and structured Windows memory acquisitions.
- Cross-check process/module enumeration against independently established
  ground truth for at least several Windows 10 and 11 builds.
- PE parser fuzz tests covering malformed sizes, directory tables and offsets.
- Verify recovered imports/exports with independent PE parsers and original
  module binaries where available.
- Ensure unsupported formats/structures fail explicitly rather than silently
  creating apparently valid outputs.

## Current practical commands

```
cargo test
cargo build --release
target/release/dumpy --info memory.raw
target/release/dumpy --discover memory.raw
target/release/dumpy memory.raw out_dir
```

The `--virtual` option is retained for development tests. It is *not* the
intended user-facing recovery workflow.
# v0.9.0: automatic user mapped-image discovery

v0.11.0 introduces `pe_verify.rs` for independently bounded traversal of PE
import/export references within reconstructed raw-layout bytes. Recovery now
persists a structured table-integrity report and ranks outputs by file-backed
coverage, executable coverage and validated directory structures.
The offline `--verify-dir` mode verifies already recovered images without
re-reading the original dump and explicitly cannot recover missing-page
provenance from standalone PE files.

v0.10.0 reports completeness for the PE file-backed sections independently
from full `SizeOfImage` virtual page coverage. It identifies executable
sections from `IMAGE_SCN_MEM_EXECUTE` and emits per-section coverage rows.

v0.9.5 provides bounded CLI controls for the number of raw DTB roots explored
and PE header candidates retained per root, allowing a full discovered cohort
to be scanned without increasing default resource costs for every acquisition.

v0.9.4 `recovery::recover_from_roots` attempts alternate DTBs for pages absent
from the selected primary process mapping. These DTBs share an identical full
PE header page and are ranked by sampled availability. Every fallback page is
recorded with its source DTB; merged files use `.merged.bin` to warn about
potential differences in process-private, modified image pages.

v0.9.3 deduplicates raw PE candidates across discovered DTBs before expensive
image reconstruction, using (virtual base, image size, first-page fingerprint).
It samples page availability to select a representative DTB and emits alias
records for all other DTBs exposing the same PE header.

v0.9.2 permits tentative flat physical discovery for unknown raw/padded
acquisitions if multiple structurally coherent PML4 roots share matching
kernel mappings. It never claims those roots identify specific processes;
the output records the DTB and missing-data diagnostics.

v0.9.1 expands candidate probes to every mapped 4 KiB user page and separately
accounts for physically unavailable pages, `MZ` hits and rejected PE headers.
The acquisition format remains verified before any crash-dump process recovery.

`user_images.rs` walks USER-accessible present entries from a uniquely
associated process DTB. The four-level scanner bounds logical mapped-page
coverage, page-table visits and discovered image count. It probes 64 KiB
aligned user virtual addresses, validates PE NT and optional headers and
passes images into the page-aware `recovery.rs` rebuild logic. Missing pages
remain visible in per-process diagnostics and partial artifacts. This mode is
explicitly separate from raw-file carving and kernel module recovery.

