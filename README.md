# m-burner

An interactive Linux tool for writing a directory to a **blank, unformatted BD-R / M-DISC Blu-ray** and verifying every file afterward. A run is successful only when a full readback from the optical disc matches the source manifest: paths, sizes, and SHA-256 hashes.

## Installation

Requires Debian or Ubuntu with Python 3.10 or newer:

```bash
sudo bash install.sh
m-burner
```

The installer installs system dependencies through `apt-get` using temporary official distribution sources and isolated package indexes (so broken third-party PPAs do not block installation), creates `/opt/m-burner/venv`, installs a pinned, hash-verified version of `pycdlib`, and provides `/usr/local/bin/m-burner`. Package signatures remain mandatory. Temporary APT sources and indexes are removed on exit; system repository configuration is unchanged. It does not perform a full OS upgrade, update drive firmware, or change user groups.

**Run the burner without sudo.** Your user must have read/write access to the optical device, usually through the `cdrom` group.

The program prompts for a source directory and a disc label. Labels may contain up to 32 characters: `A–Z`, `0–9`, and `_`. If multiple optical drives are present, specify one explicitly:

```bash
m-burner --source '/path/to/files' --label BACKUP_001 --device /dev/sr0
```

Add `--yes` to skip the final write confirmation when the operation is already authorized. This does **not** bypass safety checks.

## Workflow

1. Confirm that the selected device is an optical drive and contains a blank, unformatted BD-R SRM. `dvd+rw-mediainfo` and `xorriso` must agree on the exact number of available 2048-byte blocks.
2. Calculate the image size using `xorriso -as mkisofs -print-size`. The filesystem is **ISO 9660 level 3 + Rock Ridge + Joliet**, with the source directory's contents at the disc root. The image plus a 2 MiB padding/alignment allowance must fit. Insufficient capacity stops the run before writing.
3. Read all source files and save a SHA-256 manifest. Build the image, verify both filename trees and their data mappings, and check every file's hash. Source changes during preparation stop the run.
4. Recheck drive identity and blank media, then write with `xorriso` and close the disc. A supported 4x speed is preferred; `--speed` selects another supported speed. Live output includes progress, FIFO and drive buffer levels, actual write speed, and estimated time remaining. ETA is approximate; drive messages are shown during finalization.
5. Eject and reload the disc. Slim drives may require manually closing the tray; the program detects reloading automatically.
6. Read every file directly from the optical device and compare paths, sizes, and SHA-256 hashes. Verification also checks empty directories, unexpected files, and agreement between Rock Ridge and Joliet. The original source directory is no longer required at this stage.

### Supported recording mode

The tool writes **without preformatting**, retaining the blank BD-R's available capacity without reserving space for hardware defect replacement. Formatted, partially recorded, closed, or unsupported media are rejected. It does not use overburn or force options, erase media, or automatically retry an interrupted recording.

This intentionally narrow workflow does not implement DVD recording, multisession updates, or recovery of partially written discs. Media support still depends on the drive and its firmware.

## Storage and source protection

Run artifacts are saved by default under:

```text
~/.local/state/m-burner/runs/<timestamp>-<label>-<unique-suffix>/
```

To use another filesystem and protect an entire source tree:

```bash
m-burner --work-dir /mnt/staging/m-burner --protect-root /path/to/protected-data
```

The working directory cannot be inside the source directory or any `--protect-root`, including through symbolic links. Repeat `--protect-root` to protect additional trees. The working filesystem must have room for the complete image plus at least 1 GiB. Existing files are never deleted to free space.

Artifacts include `image.iso`, `image.iso.sha256`, `manifest.json`, `config.json`, `state.json`, executed commands, write logs, media information, verification reports, and per-file hash results. A successful run produces `result.json` with `success: true` and a human-readable `REPORT.txt`. After successful full disc verification, the image, its checksum sidecar, command logs, diagnostic logs, and per-file verification logs are automatically deleted. The manifest, metadata, and final reports remain as a compact record. Cleanup only targets known filenames in the current run directory; it never removes source files or other runs. Cleanup errors are listed in `result.json` and reported without changing the successful disc verification result. On write/read/verification failure, interruption, or reload timeout, artifacts are retained. Preparation-only runs also retain their image.

Source files are only read, including hidden files. Normal reads may update access times through the operating system. Symbolic links and special files are rejected explicitly rather than silently skipped. If Joliet cannot represent names exactly, or the image changes any names, preparation fails **before writing**. Files larger than 4 GiB use ISO level 3 multi-extent records; older readers without that support may not read them.

## Resume verification

If the disc is not reloaded within 300 seconds, the program exits with code **75** and preserves its state. Close the tray and run:

```bash
m-burner --resume /path/to/run
```

Resume performs **verification only**, never another write. For a run already verified and cleaned, it displays the existing report location without rereading or rewriting the disc. If cleanup was interrupted or incomplete, it retries only cleanup. It requires a recorded successful write result. An interruption during recording requires separate diagnosis; automatic continuation is prohibited. Verification failures never trigger rewriting.

Set a different reload timeout with `--reload-timeout 600`.

## Preparation and capacity checks

Create and verify an image without recording:

```bash
m-burner --prepare-only
```

A subsequent normal run creates a new independent set of artifacts. `--resume` is only for verifying an already recorded disc.

Check the media and image capacity without creating an image:

```bash
m-burner --check-only
```

If another recording program is running, m-burner refuses to proceed and does not terminate it. During recording, Ctrl+C is not forwarded to the writer: m-burner waits for the operation to finish. Interrupting preparation or readback does not modify the optical media, and artifacts remain available.

## Development and validation

Run from the repository using an interpreter with `pycdlib` installed:

```bash
/opt/m-burner/venv/bin/python m_burner.py
/opt/m-burner/venv/bin/python -m unittest discover -s tests -v
M_BURNER_LARGE_TEST=1 /opt/m-burner/venv/bin/python -m unittest discover -s tests -v
```

Automated tests do not write optical media. They cover capacity boundaries, padding, unsuitable media and devices, source changes, symlinks, Unicode and special filenames, empty directories, corrupted or truncated images, verification-only resume, and multi-extent files. The optional large-file test temporarily creates an image larger than 4 GiB outside the source tree.

Real-disc validation evidence is published in `validation/` only after full readback. Source data, source filenames, images, and detailed recording logs are not committed. The program's SHA-256 in a run report identifies the exact implementation tested.
