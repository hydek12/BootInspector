# BootInspector
A drag-and-drop macOS utility that reads raw .iso, .img, and .toast headers to check whether an image contains a valid Apple Partition Map (APM) and a blessed tbxi System Folder before you mount it in UTM or QEMU.


## PlayStation disc inspection

Use **PlayStation** mode for raw images or cooked ISO. The app detects raw sector layouts by content, including 2,352-byte sectors and 2,448-byte sectors with subchannel data. Opening a CUE, CHD, CCD, ECM, or playlist selects PlayStation mode automatically.

| Input | Inspection |
|---|---|
| CUE/BIN, BIN, IMG, ISO, raw MDF | Boot data, region evidence, track layout, and optional track hashes. Direct MDF inspection covers readable raw sectors only. |
| CloneCD CCD/IMG/SUB | Unscrambled data, CD audio track boundaries, and companion SUB presence. |
| CHD v5 | Track metadata directly. A separately installed chdman can temporarily extract the disc for boot inspection. |
| TOC, NRG, GDI | Optional conversion with chdman for layouts supported by the installed tool. |
| M3U/M3U8 | Local disc list. Open individual members for inspection. |
| ECM | Temporary sector reconstruction with an ECM checksum check and PlayStation boot inspection. |
| MDS, PBP and compressed ISO variants | Format-specific conversion guidance. |

Use **Grant Track Folder Access** for companion files and **Calculate Track SHA-1** to hash individual stored tracks, including stored pregaps. Firmware filenames are regional examples. Exact requirements depend on the selected emulator or recompilation. Structural checks do not run the game.

**Scan BIOS Folder** identifies known firmware by SHA-256, including the exact Alundra Recompiled profile for SLES-01135. **Preview CUE Repair** validates a replacement for a missing BIN, then lets you save a new CUE beside the original. **Verify Raw Sector EDC/ECC** checks supported raw data tracks for sector corruption.

**Scan Library** recursively groups descriptors and their companion files, then exports the scan as JSON or CSV. The batch scan reports CHD track metadata from the container and skips the optional extraction step.
