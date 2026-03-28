# SortX

<p align="center">
  <strong>Signature-first file classification for DFIR, triage, and parser automation.</strong>
</p>

<p align="center">
  <em>Built for KAPE-style evidence collections, but designed to work against any directory tree.</em>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.12%2B-blue.svg">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg">
  <img alt="Focus" src="https://img.shields.io/badge/focus-DFIR%20%26%20artifact%20routing-0a7ea4.svg">
  <img alt="Classifier" src="https://img.shields.io/badge/engine-signature%20first-success.svg">
</p>

<p align="center">
  <img src="sort.gif" alt="SortX demo" width="900">
</p>

---

## Why SortX

When I collected evidence with KAPE or any broad triage workflow, I often ended up with a large mixed directory containing many unrelated formats:

- EVTX files for event log parsing
- registry hives and transaction logs for registry tooling
- NTFS metadata files for filesystem analysis
- scripts, markdown, captures, logs, and helper files mixed in with actual evidence

`SortX` solves the hand-sorting step.

It walks a directory, classifies files using exact forensic names, binary signatures, and carefully scoped heuristics, then writes them into stable buckets such as:

- `classified/evtx`
- `classified/registry-hive`
- `classified/pcap`
- `classified/powershell`
- `classified/log`

That makes downstream automation much easier, because each parser can target only the formats it supports.

## Highlights

- Signature-first classification instead of relying on human-readable `libmagic` descriptions
- Windows forensic artifact awareness for EVTX, registry hives, NTFS metadata, jump lists, and prefetch
- General file-format coverage for archives, captures, images, scripts, structured text, and plain text
- Machine-friendly outputs for automation: `inventory.json`, summaries, manifest, and per-tag folders
- Optional `python-magic` enrichment for MIME and descriptive metadata
- Designed to be easy to extend with new rule types and artifact families

## What It Produces

Given an input directory, `SortX` creates a classification workspace like this:

```text
output/
├── artifacts/
│   ├── inventory.json
│   ├── inventory-summary.json
│   └── classification-summary.json
├── classified/
│   ├── evtx/
│   ├── registry-hive/
│   ├── pcap/
│   ├── log/
│   ├── markdown/
│   └── ...
├── logs/
│   └── case.log
└── manifest.json
```

Each inventory record includes:

- source paths
- hash
- size and timestamps
- `primary_tag`
- `family`
- structured `classification` metadata

The nested `classification` object includes:

- `tag`
- `family`
- `description`
- `method`
- `confidence`
- `rule_name`
- `header_hex`
- optional `mime_type`
- optional `magic_description`

## How It Classifies

`SortX` currently evaluates rules in this order:

1. strict forensic filename rules
2. binary signature rules
3. advisory forensic filename rules
4. extension fallback rules
5. text and structured-content heuristics
6. `unknown`

This order is deliberate. The most reliable and least ambiguous rules win first.

## Quick Start

### Windows

```powershell
python3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python3 .\sortx classify --dir ../out/ --out extracted
```

### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./sortx classify --dir ../out/ --out extracted
```

Credits to `sbousseaden` for `EVTX-ATTACK-SAMPLES` which could be used for easy testing purposes as example instead of `out/` here above. Link to the original GitHub repository:
- https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
```bash
./sortx classify --dir EVTX-ATTACK-SAMPLES --out extracted
```

If `python-magic` complains about a missing system library:

```bash
sudo apt install libmagic1
```

`python-magic` is optional. The classifier works without it, but you lose `mime_type` and `magic_description` enrichment.

If you want a bare `sortx` command in your shell, create a symlink into a directory already in your `PATH`:

```bash
ln -s "$PWD/sortx" ~/.local/bin/sortx
sortx classify --dir ../out/ --out extracted
```

If you prefer an editable package install instead, install `setuptools` in the virtual environment and then install the project:

```bash
pip install setuptools
pip install -e .
sortx classify --dir ../out/ --out extracted
```

## Example Workflow

Classify a KAPE output folder:

```powershell
./sortx classify --dir ../out/ --out extracted
```

Run `EvtxECmd` only on event logs:

```powershell
./EvtxECmd.exe -d "../../sortx/extracted/classified/evtx" --csv "EvtxEcmd_out"
```

Run registry tooling only on hives:

```powershell
RECmd.exe --bn BatchExamples\Kroll_Batch.reb --d "../../sortx/extracted/classified/registry-hive"
```

Process packet captures separately:

```bash
find extracted/classified/pcap -type f
```

Help commands:
```bash
./sortx --help
./sortx classify --help
```

## Coverage At A Glance

Current high-value buckets include:

- Windows evidence: `evtx`, `etl`, `registry-hive`, `registry-log`, `lnk`, `prefetch`, `jumplist-*`
- NTFS metadata: `ntfs-mft`, `ntfs-mftmirr`, `ntfs-logfile`, `ntfs-bitmap`, `ntfs-secure`, `ntfs-boot`, `ntfs-usnjrnl`
- Network captures: `pcap`, `pcapng`
- Documents and data: `pdf`, `xml`, `json`, `yaml`, `csv`, `markdown`, `html`, `jupyter-notebook`, `config`, `toml`
- Scripts and code: `powershell`, `python`, `python-bytecode`, `shell-script`, `javascript`, `css`
- Archives and binaries: `zip`, `gzip`, `7z`, `rar`, `olecf`, `sqlite`, `pe`, `elf`
- Media and general text: `png`, `jpeg`, `gif`, `log`, `text`

## Windows vs Unix Coverage

Windows coverage is currently deeper and more forensic-aware. It includes:

- EVTX and ETL traces
- registry hives and registry transaction logs
- jump lists
- shortcuts
- prefetch
- NTFS metadata files
- pagefile and hibernation file detection

Unix and Linux coverage is currently format-oriented rather than artifact-name-oriented. It includes:

- `elf`
- `gzip`
- `7z`
- `rar`
- `zip`
- `sqlite`
- `json`
- `xml`
- `csv`
- `text`
- `pdf`
- `png`
- `jpeg`
- `gif`
- `shell-script`

There are not yet Unix-forensics-specific filename rules for artifacts such as shell history, journald files, wtmp/utmp, auth logs, or macOS plists beyond the generic format matches above.

## Exhaustive Current Classification Coverage

<details>
<summary><strong>Open full coverage list</strong></summary>

### Windows forensic artifacts by exact filename

- `$MFT` -> `ntfs-mft`
- `$MFTMirr` -> `ntfs-mftmirr`
- `$LogFile` -> `ntfs-logfile`
- `$Bitmap` -> `ntfs-bitmap`
- `$Secure` -> `ntfs-secure`
- `$Boot` -> `ntfs-boot`
- `$UsnJrnl` -> `ntfs-usnjrnl`
- `$J` -> `ntfs-usnjrnl`
- `pagefile.sys` -> `pagefile`

### Windows forensic artifacts by advisory exact filename

These are classified by name when no stronger signature rule already matched:

- `SAM` -> `registry-hive`
- `SECURITY` -> `registry-hive`
- `SOFTWARE` -> `registry-hive`
- `SYSTEM` -> `registry-hive`
- `DEFAULT` -> `registry-hive`
- `COMPONENTS` -> `registry-hive`
- `Amcache.hve` -> `registry-hive`
- `BCD` -> `registry-hive`
- `NTUSER.DAT` -> `registry-hive`
- `UsrClass.dat` -> `registry-hive`
- `hiberfil.sys` -> `hibernation-file`

### Windows forensic artifacts by filename pattern

- `SAM.LOG`
- `SAM.LOG1`
- `SAM.LOG2`
- `SAM.BLF`
- `SAM.regtrans-ms`
- `SECURITY.LOG`
- `SECURITY.LOG1`
- `SECURITY.LOG2`
- `SECURITY.BLF`
- `SECURITY.regtrans-ms`
- `SOFTWARE.LOG`
- `SOFTWARE.LOG1`
- `SOFTWARE.LOG2`
- `SOFTWARE.BLF`
- `SOFTWARE.regtrans-ms`
- `SYSTEM.LOG`
- `SYSTEM.LOG1`
- `SYSTEM.LOG2`
- `SYSTEM.BLF`
- `SYSTEM.regtrans-ms`
- `DEFAULT.LOG`
- `DEFAULT.LOG1`
- `DEFAULT.LOG2`
- `DEFAULT.BLF`
- `DEFAULT.regtrans-ms`
- `COMPONENTS.LOG`
- `COMPONENTS.LOG1`
- `COMPONENTS.LOG2`
- `COMPONENTS.BLF`
- `COMPONENTS.regtrans-ms`
- `Amcache.hve.LOG`
- `Amcache.hve.LOG1`
- `Amcache.hve.LOG2`
- `Amcache.hve.BLF`
- `Amcache.hve.regtrans-ms`
- `BCD.LOG`
- `BCD.LOG1`
- `BCD.LOG2`
- `BCD.BLF`
- `BCD.regtrans-ms`
- `NTUSER.DAT.LOG`
- `NTUSER.DAT.LOG1`
- `NTUSER.DAT.LOG2`
- `NTUSER.DAT.BLF`
- `NTUSER.DAT.regtrans-ms`
- `UsrClass.dat.LOG`
- `UsrClass.dat.LOG1`
- `UsrClass.dat.LOG2`
- `UsrClass.dat.BLF`
- `UsrClass.dat.regtrans-ms`

All of the above pattern matches are classified as `registry-log`.

### Windows forensic artifacts by filename suffix

- `*.automaticdestinations-ms` -> `jumplist-automaticdestinations`
- `*.customdestinations-ms` -> `jumplist-customdestinations`

### Binary signature coverage

- EVTX header `ElfFile\x00` -> `evtx`
- PCAP little-endian header `d4 c3 b2 a1` -> `pcap`
- PCAP big-endian header `a1 b2 c3 d4` -> `pcap`
- PCAP nanosecond-resolution headers `4d 3c b2 a1` and `a1 b2 3c 4d` -> `pcap`
- PCAPNG section header `0a 0d 0d 0a` -> `pcapng`
- Registry hive header `regf` -> `registry-hive`
- LNK shell link header `4c 00 00 00 01 14 02 00` -> `lnk`
- ZIP local file header `PK\x03\x04` -> `zip`
- ZIP empty archive header `PK\x05\x06` -> `zip`
- ZIP spanned archive header `PK\x07\x08` -> `zip`
- OLE Compound File header `d0 cf 11 e0 a1 b1 1a e1` -> `olecf`
- SQLite header `SQLite format 3\x00` -> `sqlite`
- PDF header `%PDF-` -> `pdf`
- PNG header `89 50 4e 47 0d 0a 1a 0a` -> `png`
- JPEG header `ff d8 ff` -> `jpeg`
- GIF87a header -> `gif`
- GIF89a header -> `gif`
- Gzip header `1f 8b 08` -> `gzip`
- 7-Zip header `37 7a bc af 27 1c` -> `7z`
- RAR v4 header `52 61 72 21 1a 07 00` -> `rar`
- RAR v5 header `52 61 72 21 1a 07 01 00` -> `rar`
- Portable Executable with valid `MZ` and `PE\0\0` layout -> `pe`
- ELF header `7f 45 4c 46` -> `elf`
- Prefetch header with `SCCA` at offset 4 -> `prefetch`
- Hibernation header `HIBR` -> `hibernation-file`

### Text and structured-content heuristics

- XML content starting with an XML declaration -> `xml`
- JSON content starting with `{` or `[` after whitespace -> `json`
- HTML content starting with `<!doctype html` or `<html` -> `html`
- Delimited text with consistent separator counts across most sampled lines -> `csv`
- Printable text content -> `text`

### Extension fallback coverage

These are only used when no stronger filename, signature, or text rule matched:

- `*.evtx` -> `evtx`
- `*.etl` -> `etl`
- `*.pf` -> `prefetch`
- `*.lnk` -> `lnk`
- `*.xml` -> `xml`
- `*.ipynb` -> `jupyter-notebook`
- `*.json` -> `json`
- `*.pcap` -> `pcap`
- `*.pcapng` -> `pcapng`
- `*.yml` and `*.yaml` -> `yaml`
- `*.csv` -> `csv`
- `*.md` and `*.markdown` -> `markdown`
- `*.html` and `*.htm` -> `html`
- `*.ps1`, `*.psm1`, `*.psd1` -> `powershell`
- `*.py` and `*.pyw` -> `python`
- `*.pyc` and `*.pyo` -> `python-bytecode`
- `*.sh`, `*.bash`, `*.zsh` -> `shell-script`
- `*.js`, `*.mjs`, `*.cjs` -> `javascript`
- `*.css` -> `css`
- `*.toml` -> `toml`
- `*.ini`, `*.cfg`, `*.conf`, `*.config` -> `config`
- `*.log` -> `log`
- `*.txt` -> `text`

### Empty and unknown files

- zero-byte files -> `empty`
- everything else not matched above -> `unknown`

</details>

## Adding New Classifications

The main place to extend the engine is [discovery/classifier.py](/home/simonl01/Documents/sortx/discovery/classifier.py).

### Choose The Right Rule Type

Use a strict filename rule when the artifact is identified by an exact forensic name:

- `$MFT`
- `NTUSER.DAT`
- `pagefile.sys`

Use a signature rule when the file has a reliable header or magic number:

- `EVTX`
- `PCAP`
- `SQLite`
- `PDF`

Use an extension rule when the format is mostly identified by filename suffix:

- `.ps1`
- `.md`
- `.yaml`
- `.etl`

Use a text heuristic only when the format is text-based and does not have a strong binary signature.

### Steps To Add A New Type

1. Pick a stable tag name and family.
2. Decide the strongest detection method.
3. Add the rule in `STRICT_FILENAME_RULES`, `ADVISORY_FILENAME_RULES`, `SIGNATURE_RULES`, `EXTENSION_RULES`, or `_classify_text()`.
4. Give it a clear description and reasonable confidence.
5. Update the exhaustive coverage section in this README.
6. Re-run the classifier into a fresh output directory.
7. Check `inventory.json`, `classification-summary.json`, and `classified/<tag>/` for false positives.

### Example Signature Rule

```python
OffsetSignatureRule(
    name="example-header",
    tag="example",
    family="example-family",
    description="Example artifact",
    mime_type="application/x-example",
    confidence=1.0,
    offset=0,
    pattern=b"EXMP",
),
```

### Example Extension Rule

```python
((".example",), "example", "example-family", "Example file", "extension", 0.8),
```

## Maintenance Notes

Remove `__pycache__` folders:

```bash
find . -type d -name '__pycache__'
find . -type d -name '__pycache__' -prune -exec rm -rf {} +
```
