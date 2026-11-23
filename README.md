# BootInspector
A drag-and-drop macOS utility that reads raw .iso, .img, and .toast headers to check whether an image contains a valid Apple Partition Map (APM) and a blessed tbxi System Folder before you mount it in UTM or QEMU.


## Build

Open `BootInspector.xcodeproj` in Xcode 27.2 and build the BootInspector scheme. The project includes the app, unit test, and UI test targets.

## PlayStation disc inspection

Drop an image to select its inspection mode automatically. BootInspector checks signatures and filesystem data to distinguish Mac OS, generic ISO 9660, and PlayStation images, including cooked and raw layouts. Drop several files or a folder to scan the selection recursively and open a disc report directly in the main window. Use the **Disc** selector in the same window to switch between reports.

| Input | Inspection |
|---|---|
| CUE/BIN, BIN, IMG, ISO, raw MDF | Boot data, region evidence, track layout, and optional track hashes. Direct MDF inspection covers readable raw sectors only. |
| CloneCD CCD/IMG/SUB | Unscrambled data, CD audio track boundaries, and companion SUB presence. |
| CHD v5 | Track metadata and native boot inspection when libchdr is bundled. A separately installed chdman provides an extraction fallback. |
| TOC, NRG, GDI | Optional conversion with chdman for layouts supported by the installed tool. |
| M3U/M3U8 | Local disc list. Open individual members for inspection. |
| ECM | Temporary sector reconstruction with an ECM checksum check and PlayStation boot inspection. |
| MDS, PBP and compressed ISO variants | Format-specific conversion guidance. |

Use **Grant Track Folder Access** for companion files and **Calculate Track SHA-1** to hash individual stored tracks, including stored pregaps. Firmware filenames are regional examples. Exact requirements depend on the selected emulator or recompilation. Structural checks do not run the game.

**Scan BIOS Folder** identifies known firmware by SHA-256, including the exact Alundra Recompiled profile for SLES-01135. **Preview CUE Repair** validates a replacement for a missing BIN, then lets you save a new CUE beside the original. **Verify Raw Sector EDC/ECC** checks supported raw data tracks for sector corruption.

**Scan Library** recursively groups descriptors and their companion files, then exports the scan as JSON or CSV. The batch scan uses native CHD boot inspection when available and skips external extraction.

### Bundle the native CHD decoder

Build BootInspector in Xcode, then run `sh bundle-libchdr.sh /path/to/BootInspector.app` with CMake and the Xcode command-line tools available. The script builds a pinned libchdr revision for the app’s architectures, embeds its dylib, and signs the local build ad hoc by default. Pass a signing identity as the second argument if needed. Use a fresh local build as the input to the script. Native inspection decodes requested CD hunks directly from the CHD and leaves the source untouched.

### Optional disc catalogs and LibCrypt

Use **Disc Catalog** to load either or both reference files for the current app session. BootInspector reads the selected files locally.

- **DuckStation GameDB** accepts DuckStation’s generated `gamedb.yaml`. It looks up the disc’s boot serial and known aliases for a title and a LibCrypt flag. A serial match can also identify a patched disc and does not determine its exact revision.
- **Logiqx XML DAT** accepts a PlayStation DAT with complete, ordered per-track sizes and SHA-1 values. Use **Calculate Track SHA-1** to compare an individual disc, or **Scan Library** to compare tracks automatically when their sizes are in the DAT. Exact matching is available for layouts with accessible stored track boundaries. Native CD CHDs can match a DAT directly. Track hashes include stored pregaps, exclude CHD hunk padding and subcode, and convert CD audio to BIN byte order. Mixed-mode stored pregaps and other layouts without comparable track boundaries may still provide a serial match when the GameDB is loaded.

The SBI check reads the same-name companion and validates the header, BCD timestamps, record types, payload lengths, and overlapping records. A structurally valid SBI does not establish that its Q-channel data belongs to the disc. The app reports declared SUB or CHD subchannel data separately without validating its contents. Catalog status, LibCrypt, and SBI results are included in batch CSV and JSON exports.

[DuckStation GameDB](https://github.com/stenzek/duckstation/blob/master/src/core/game_database.cpp) · [Redump LibCrypt notes](https://wiki.redump.info/LibCrypt)

[SBI record format](https://psx-spx.consoledev.net/dev/ps1/cdr/cdromfileformats/diskimages/)

### Run the tests

Run the BootInspector scheme’s Test action in Xcode, or use `xcodebuild -project BootInspector.xcodeproj -scheme BootInspector -destination 'platform=macOS' test`. The app-hosted unit tests generate their own disc fixtures. The native CHD case runs when the app contains bundled libchdr or `BOOTINSPECTOR_TEST_LIBCHDR` points to a compatible dylib in the test process environment.
