import SwiftUI
import Combine
import UniformTypeIdentifiers

// MARK: - Binary Data Helpers

extension Data {
    func readUInt16BE(at offset: Int) -> UInt16? {
        guard offset >= 0, offset + 2 <= count else { return nil }
        return (UInt16(self[offset]) << 8) | UInt16(self[offset + 1])
    }

    func readUInt32BE(at offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= count else { return nil }
        return (UInt32(self[offset]) << 24) |
               (UInt32(self[offset + 1]) << 16) |
               (UInt32(self[offset + 2]) << 8) |
               UInt32(self[offset + 3])
    }

    func readASCII(at offset: Int, length: Int) -> String {
        guard offset >= 0, offset + length <= count else { return "" }
        let slice = self[offset..<(offset + length)]
        let trimmed = slice.prefix { $0 != 0 }
        return String(bytes: trimmed, encoding: .ascii)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }
}

// MARK: - Inspection Models

struct PartitionRecord: Identifiable {
    let id: Int              // 1-based partition number (matches OpenBIOS cd:X)
    let name: String
    let type: String
    let startBlock: UInt32
    let blockCount: UInt32
    let byteOffset: UInt64
    let byteSize: UInt64
    let hfsStatus: String?
    let isBlessed: Bool
    let blessedFolderID: UInt32?
}

struct ImageReport {
    let fileName: String
    let fileSize: UInt64
    let hasDriverDescriptorMap: Bool
    let blockSize: UInt16
    let hasApplePartitionMap: Bool
    let apmBlockStride: Int
    let hasISO9660: Bool
    let isoVolumeID: String
    let partitions: [PartitionRecord]
    let verdictTitle: String
    let verdictDetail: String
    let isBootablePPC: Bool
    let suggestedOpenBIOSCommand: String?
}

// MARK: - Binary Image Parser

struct DiskImageInspector {
    static func inspect(url: URL) throws -> ImageReport {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }

        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        let fileSize = (try? handle.seekToEnd()) ?? 0
        try handle.seek(toOffset: 0)

        // Read first 128 KB for header scanning
        let headerData = (try? handle.read(upToCount: 131_072)) ?? Data()

        // 1. Check Block 0 Driver Descriptor Map ("ER" = 0x4552)
        let ddmSig = headerData.readUInt16BE(at: 0)
        let hasDDM = (ddmSig == 0x4552)
        let ddmBlockSize = hasDDM ? (headerData.readUInt16BE(at: 2) ?? 512) : 512

        // 2. Check ISO-9660 Primary Volume Descriptor at offset 0x8000 (32768)
        let isoMagic = headerData.readASCII(at: 0x8001, length: 5)
        let hasISO = (isoMagic == "CD001")
        let isoVolID = hasISO ? headerData.readASCII(at: 0x8028, length: 32) : ""

        // 3. Detect Apple Partition Map ("PM" = 0x504D) at 512-byte or 2048-byte stride
        var apmStride = 0
        if headerData.readUInt16BE(at: 512) == 0x504D {
            apmStride = 512
        } else if headerData.readUInt16BE(at: 2048) == 0x504D {
            apmStride = 2048
        }

        var partitions: [PartitionRecord] = []
        let hasAPM = apmStride > 0

        if hasAPM {
            let totalEntries = Int(headerData.readUInt32BE(at: apmStride + 4) ?? 1)
            let safeMax = min(totalEntries, 64)

            for idx in 1...safeMax {
                let entryOffset = idx * apmStride
                guard entryOffset + 136 <= headerData.count else { break }
                guard headerData.readUInt16BE(at: entryOffset) == 0x504D else { break }

                let pStartBlock = headerData.readUInt32BE(at: entryOffset + 8) ?? 0
                let pBlockCount = headerData.readUInt32BE(at: entryOffset + 12) ?? 0
                let pName = headerData.readASCII(at: entryOffset + 16, length: 32)
                let pType = headerData.readASCII(at: entryOffset + 48, length: 32)

                let byteOffset = UInt64(pStartBlock) * UInt64(apmStride)
                let byteSize = UInt64(pBlockCount) * UInt64(apmStride)

                var hfsStatus: String? = nil
                var isBlessed = false
                var blessedID: UInt32? = nil

                if pType == "Apple_HFS" || pType == "Apple_HFSX" {
                    let result = inspectHFSPartition(handle: handle, partitionOffset: byteOffset, fileSize: fileSize)
                    hfsStatus = result.summary
                    isBlessed = result.isBlessed
                    blessedID = result.blessedDirID
                }

                partitions.append(PartitionRecord(
                    id: idx,
                    name: pName.isEmpty ? "(Unnamed)" : pName,
                    type: pType,
                    startBlock: pStartBlock,
                    blockCount: pBlockCount,
                    byteOffset: byteOffset,
                    byteSize: byteSize,
                    hfsStatus: hfsStatus,
                    isBlessed: isBlessed,
                    blessedFolderID: blessedID
                ))
            }
        }

        // 4. Generate Bootability Verdict
        let blessedPartitions = partitions.filter { $0.isBlessed }
        let hfsPartitions = partitions.filter { $0.type == "Apple_HFS" || $0.type == "Apple_HFSX" }

        let verdictTitle: String
        let verdictDetail: String
        let isBootablePPC: Bool
        var suggestedCmd: String? = nil

        if let firstBlessed = blessedPartitions.first {
            isBootablePPC = true
            verdictTitle = "BOOTABLE MAC PPC IMAGE"
            verdictDetail = "Valid Apple Partition Map found with a blessed System Folder (CNID \(firstBlessed.blessedFolderID ?? 0)) on Partition \(firstBlessed.id) (\(firstBlessed.name)). OpenBIOS should locate \\\\:tbxi automatically."
            suggestedCmd = "boot cd:\(firstBlessed.id),\\\\:tbxi"
        } else if !hfsPartitions.isEmpty {
            isBootablePPC = false
            verdictTitle = "UNBLESSED HFS VOLUME (LIKELY TO HANG)"
            verdictDetail = "Found an Apple_HFS partition, but its Master Directory Block reports Blessed Folder ID = 0. OpenBIOS will fail at cdrom:,\\\\:tbxi unless the System Folder is blessed."
        } else if hasISO && !hasAPM {
            isBootablePPC = false
            verdictTitle = "PC / ISO-9660 ONLY — NOT BOOTABLE ON PPC"
            verdictDetail = "This image contains an ISO-9660 header (\(isoVolID)) with no Apple Partition Map. It was likely dumped on Windows or Linux and stripped of Mac boot metadata."
        } else {
            isBootablePPC = false
            verdictTitle = "UNRECOGNIZED OR RAW UNFORMATTED IMAGE"
            verdictDetail = "No Apple Partition Map (PM) or ISO-9660 volume descriptor was detected. This may be an empty disk container or an unsupported format (e.g., compressed DMG or NDIF)."
        }

        return ImageReport(
            fileName: url.lastPathComponent,
            fileSize: fileSize,
            hasDriverDescriptorMap: hasDDM,
            blockSize: ddmBlockSize,
            hasApplePartitionMap: hasAPM,
            apmBlockStride: apmStride,
            hasISO9660: hasISO,
            isoVolumeID: isoVolID,
            partitions: partitions,
            verdictTitle: verdictTitle,
            verdictDetail: verdictDetail,
            isBootablePPC: isBootablePPC,
            suggestedOpenBIOSCommand: suggestedCmd
        )
    }

    private static func inspectHFSPartition(handle: FileHandle, partitionOffset: UInt64, fileSize: UInt64) -> (summary: String, isBlessed: Bool, blessedDirID: UInt32?) {
        // Volume Header / Master Directory Block sits 1024 bytes into the partition
        let mdbOffset = partitionOffset + 1024
        guard mdbOffset + 512 <= fileSize else {
            return ("Partition truncated past EOF", false, nil)
        }

        do {
            try handle.seek(toOffset: mdbOffset)
            guard let block = try handle.read(upToCount: 512), block.count >= 120 else {
                return ("Unable to read Volume Header", false, nil)
            }

            let sig = block.readUInt16BE(at: 0) ?? 0

            if sig == 0x4244 {
                // Classic HFS ("BD"): drFndrInfo[0] (blessed System Folder DirID) is at offset 86 (0x56)
                let blessedDirID = block.readUInt32BE(at: 86) ?? 0
                let volNameLen = Int(block[36])
                let volName = volNameLen > 0 && volNameLen <= 27
                    ? block.readASCII(at: 37, length: volNameLen)
                    : "HFS Volume"
                if blessedDirID > 0 {
                    return ("HFS Standard (\"\(volName)\") — Blessed System DirID: \(blessedDirID)", true, blessedDirID)
                } else {
                    return ("HFS Standard (\"\(volName)\") — NOT Blessed (DirID: 0)", false, 0)
                }
            } else if sig == 0x482B || sig == 0x4858 {
                // HFS+ ("H+") or HFSX ("HX"): finderInfo[0] (blessed System Folder CNID) is at offset 80 (0x50)
                let formatLabel = (sig == 0x4858) ? "HFSX" : "HFS+"
                let blessedDirID = block.readUInt32BE(at: 80) ?? 0
                if blessedDirID > 0 {
                    return ("\(formatLabel) Extended — Blessed System CNID: \(blessedDirID)", true, blessedDirID)
                } else {
                    return ("\(formatLabel) Extended — NOT Blessed (CNID: 0)", false, 0)
                }
            } else {
                return (String(format: "Unknown HFS signature (0x%04X)", sig), false, nil)
            }
        } catch {
            return ("I/O error reading partition header", false, nil)
        }
    }
}

// MARK: - SwiftUI Interface

struct ContentView: View {
    @State private var report: ImageReport?
    @State private var errorMessage: String?
    @State private var playStationMode = false
    @State private var psReport: PlayStationReport?
    @State private var currentURL: URL?
    @State private var trackFolder: URL?
    @State private var inspection: Task<Void, Never>?
    @State private var hashes: [Int: String] = [:]
    @State private var verifying = false
    @State private var inspecting = false
    @State private var biosMatches: [PlayStationTools.BIOS]?
    @State private var alundraProfile = false
    @State private var cueRepair: PlayStationTools.CueRepair?
    @State private var batch: [PlayStationTools.BatchRecord]?
    @State private var gameDB: PlayStationCatalog?
    @State private var discDAT: PlayStationCatalog?
    @State private var sectorSummary: CDSectorIntegrity.Summary?
    @State private var toolBusy = false
    @State private var toolError: String?
    @State private var isTargeted = false

    private let playStationExtensions: Set<String> = [
        "cue", "chd", "ccd", "m3u", "m3u8", "mds", "mdf", "toc", "nrg",
        "gdi", "pbp", "ecm", "cso", "zso", "isz", "dax", "raw", "2352", "2448"
    ]

    var body: some View {
        VStack(spacing: 16) {
            // Header & File Picker Bar
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(playStationMode ? "PlayStation Disc Inspector" : "HFS / ISO Partition & Blessing Inspector")
                        .font(.headline)
                    Text(playStationMode ? "Inspect boot identity, firmware guidance, and CD tracks" : "Inspect raw .iso, .toast, .img, or .cdr files for QEMU / UTM PowerPC bootability")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
                if playStationMode {
                    Menu("Disc Catalog") {
                        Button("Load DuckStation GameDB…") { loadCatalog(gameDB: true) }
                        Button("Load Logiqx XML DAT…") { loadCatalog(gameDB: false) }
                        if gameDB != nil || discDAT != nil {
                            Button("Clear Catalogs") {
                                gameDB = nil
                                discDAT = nil
                            }
                        }
                    }
                    .disabled(toolBusy)
                    Button(toolBusy ? "Working…" : "Scan Library…") { scanLibrary() }
                        .disabled(toolBusy)
                }
                Button("Open Image...") {
                    pickFile()
                }
                .keyboardShortcut("o", modifiers: .command)
            }

            Picker("Disc type", selection: $playStationMode) {
                Text("Mac OS").tag(false)
                Text("PlayStation").tag(true)
            }
            .pickerStyle(.segmented)
            .onChange(of: playStationMode) {
                if let currentURL { analyze(url: currentURL) }
            }

            if inspecting {
                ProgressView("Reading disc image…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if playStationMode, let psReport {
                playStationReportView(psReport)
            } else if !playStationMode, let report {
                reportView(report)
            } else {
                dropZoneView
            }

            if let toolError {
                Text(toolError).font(.caption).foregroundStyle(.red)
            }
            if let errorMessage = errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundColor(.red)
            }
        }
        .padding(20)
        .frame(minWidth: 680, minHeight: 500)
        .sheet(isPresented: Binding(get: { cueRepair != nil }, set: { if !$0 { cueRepair = nil } })) {
            if let cueRepair { cueRepairSheet(cueRepair) }
        }
        .sheet(isPresented: Binding(get: { batch != nil }, set: { if !$0 { batch = nil } })) {
            if let batch { batchSheet(batch) }
        }
        .onDrop(of: [.fileURL], isTargeted: $isTargeted) { providers in
            handleDrop(providers: providers)
        }
    }

    var dropZoneView: some View {
        VStack(spacing: 12) {
            Image(systemName: "opticaldisc")
                .font(.system(size: 44))
                .foregroundColor(isTargeted ? .accentColor : .secondary)
            Text(playStationMode ? "Drop a PlayStation disc image here" : "Drop a Mac OS .iso, .toast, or .img file here")
                .font(.title3)
                .fontWeight(.medium)
            Text(playStationMode ? "Open CUE/BIN, raw images, ISO, CHD, CloneCD, or a disc playlist." : "Checks Block 0 DDM, Apple Partition Map (APM), ISO-9660 descriptors, and HFS/HFS+ System Folder blessing")
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [8]))
                .foregroundColor(isTargeted ? .accentColor : .gray.opacity(0.4))
        )
    }

    func reportView(_ r: ImageReport) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                // Verdict Banner
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: r.isBootablePPC ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                        .font(.system(size: 28))
                        .foregroundColor(r.isBootablePPC ? .green : .orange)

                    VStack(alignment: .leading, spacing: 4) {
                        Text(r.verdictTitle)
                            .font(.headline)
                            .foregroundColor(r.isBootablePPC ? .green : .orange)
                        Text(r.verdictDetail)
                            .font(.subheadline)
                            .fixedSize(horizontal: false, vertical: true)

                        if let cmd = r.suggestedOpenBIOSCommand {
                            HStack {
                                Text("OpenBIOS Manual Boot:")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                Text(cmd)
                                    .font(.system(.caption, design: .monospaced))
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(Color.black.opacity(0.15))
                                    .cornerRadius(4)
                            }
                            .padding(.top, 4)
                        }
                    }
                    Spacer()
                }
                .padding(14)
                .background(
                    RoundedRectangle(cornerRadius: 10)
                        .fill((r.isBootablePPC ? Color.green : Color.orange).opacity(0.12))
                )

                // Low-Level Header Summary Grid
                GroupBox("Image Structure & Volume Descriptors") {
                    VStack(spacing: 8) {
                        infoRow("File Name", r.fileName)
                        infoRow("Total Size", ByteCountFormatter.string(fromByteCount: Int64(r.fileSize), countStyle: .file))
                        infoRow("Block 0 Driver Map (ER)", r.hasDriverDescriptorMap ? "Present (\(r.blockSize)-byte logical blocks)" : "Missing")
                        infoRow("Apple Partition Map (PM)", r.hasApplePartitionMap ? "Present (\(r.apmBlockStride)-byte sector stride, \(r.partitions.count) entries)" : "Not Found")
                        infoRow("ISO-9660 Descriptor (CD001)", r.hasISO9660 ? "Present (Volume ID: \"\(r.isoVolumeID)\")" : "Not Found")
                    }
                    .padding(6)
                }

                // Partition Map Table
                GroupBox("Apple Partition Map Entries") {
                    if r.partitions.isEmpty {
                        Text("No Apple Partition Map entries exist in this image.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .padding(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } else {
                        VStack(spacing: 8) {
                            ForEach(r.partitions) { part in
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack {
                                        Text("Partition #\(part.id): \(part.name)")
                                            .font(.system(.subheadline, design: .monospaced))
                                            .fontWeight(.bold)
                                        Spacer()
                                        Text(part.type)
                                            .font(.system(.caption, design: .monospaced))
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(part.isBlessed ? Color.green.opacity(0.2) : Color.secondary.opacity(0.15))
                                            .cornerRadius(4)
                                    }

                                    Text("Start Block: \(part.startBlock)  |  Blocks: \(part.blockCount)  |  Size: \(ByteCountFormatter.string(fromByteCount: Int64(part.byteSize), countStyle: .file))")
                                        .font(.caption)
                                        .foregroundColor(.secondary)

                                    if let hfs = part.hfsStatus {
                                        HStack(spacing: 6) {
                                            Image(systemName: part.isBlessed ? "checkmark.circle.fill" : "xmark.circle.fill")
                                                .foregroundColor(part.isBlessed ? .green : .red)
                                            Text(hfs)
                                                .font(.caption)
                                                .fontWeight(.medium)
                                        }
                                        .padding(.top, 2)
                                    }
                                }
                                .padding(8)
                                .background(Color.primary.opacity(0.04))
                                .cornerRadius(6)
                            }
                        }
                        .padding(4)
                    }
                }
            }
        }
    }

    func infoRow(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .fontWeight(.medium)
        }
    }

    private func pickFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.allowedContentTypes = [.item]
        if panel.runModal() == .OK, let url = panel.url {
            open(url: url)
        }
    }

    private func handleDrop(providers: [NSItemProvider]) -> Bool {
        guard let provider = providers.first else { return false }
        _ = provider.loadObject(ofClass: URL.self) { url, _ in
            guard let url else { return }
            DispatchQueue.main.async {
                open(url: url)
            }
        }
        return true
    }

    private func open(url: URL) {
        currentURL = url
        trackFolder = nil
        if playStationExtensions.contains(url.pathExtension.lowercased()), !playStationMode {
            playStationMode = true
        } else {
            analyze(url: url)
        }
    }

    private func analyze(url: URL) {
        inspection?.cancel()
        errorMessage = nil
        toolError = nil
        alundraProfile = false
        psReport = nil
        report = nil
        hashes = [:]
        sectorSummary = nil
        verifying = false
        if playStationMode {
            inspecting = true
            let folder = trackFolder
            inspection = Task {
                do {
                    let result = try await Task.detached(priority: .userInitiated) {
                        let scoped = folder?.startAccessingSecurityScopedResource() ?? false
                        defer { if scoped { folder?.stopAccessingSecurityScopedResource() } }
                        return try PlayStationInspector.inspect(url)
                    }.value
                    guard !Task.isCancelled else { return }
                    psReport = result
                } catch {
                    guard !Task.isCancelled else { return }
                    errorMessage = error.localizedDescription
                }
                inspecting = false
            }
        } else {
            inspecting = false
            do {
                report = try DiskImageInspector.inspect(url: url)
            } catch {
                errorMessage = "Failed to inspect image: \(error.localizedDescription)"
            }
        }
    }

    private func grantTrackFolder(for url: URL) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.directoryURL = url.deletingLastPathComponent()
        panel.prompt = "Grant Access"
        if panel.runModal() == .OK {
            trackFolder = panel.url
            analyze(url: url)
        }
    }

    private func verifyTracks(_ report: PlayStationReport) {
        let folder = trackFolder
        verifying = true
        errorMessage = nil
        inspection = Task {
            let worker = Task.detached(priority: .utility) {
                let scoped = folder?.startAccessingSecurityScopedResource() ?? false
                let imageScope = report.file.startAccessingSecurityScopedResource()
                defer {
                    if scoped { folder?.stopAccessingSecurityScopedResource() }
                    if imageScope { report.file.stopAccessingSecurityScopedResource() }
                }
                var result: [Int: String] = [:]
                for track in report.tracks where track.frames != nil {
                    result[track.id] = try PlayStationInspector.sha1(track)
                }
                return result
            }
            do {
                let result = try await withTaskCancellationHandler {
                    try await worker.value
                } onCancel: { worker.cancel() }
                guard !Task.isCancelled else { return }
                hashes = result
            } catch {
                guard !Task.isCancelled else { return }
                errorMessage = "Could not hash tracks: \(error.localizedDescription)"
            }
            verifying = false
        }
    }

    private func inspectUsingCHDTool(_ report: PlayStationReport) {
        let panel = NSOpenPanel()
        panel.prompt = "Use chdman"
        panel.message = "Choose the chdman executable from your MAME tools installation."
        guard panel.runModal() == .OK, let tool = panel.url else { return }
        let folder = trackFolder
        inspecting = true
        errorMessage = nil
        inspection = Task {
            do {
                let result = try await Task.detached(priority: .utility) {
                    let scoped = folder?.startAccessingSecurityScopedResource() ?? false
                    defer { if scoped { folder?.stopAccessingSecurityScopedResource() } }
                    return try PlayStationInspector.inspectUsingCHDTool(report.file, tool: tool)
                }.value
                guard !Task.isCancelled else { return }
                psReport = result
            } catch {
                guard !Task.isCancelled else { return }
                errorMessage = "Could not inspect the CHD boot data: \(error.localizedDescription)"
            }
            inspecting = false
        }
    }

    private func verifySectors(_ report: PlayStationReport) {
        let folder = trackFolder
        toolBusy = true
        toolError = nil
        sectorSummary = nil
        Task {
            defer { toolBusy = false }
            do {
                let summary = try await Task.detached(priority: .utility) {
                    let folderScope = folder?.startAccessingSecurityScopedResource() ?? false
                    let imageScope = report.file.startAccessingSecurityScopedResource()
                    defer {
                        if folderScope { folder?.stopAccessingSecurityScopedResource() }
                        if imageScope { report.file.stopAccessingSecurityScopedResource() }
                    }
                    return try CDSectorIntegrity.scan(report.tracks)
                }.value
                if psReport?.file == report.file { sectorSummary = summary }
            } catch { toolError = error.localizedDescription }
        }
    }

    private func selectFolder(_ prompt: String, at directory: URL? = nil) -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.directoryURL = directory
        panel.prompt = prompt
        return panel.runModal() == .OK ? panel.url : nil
    }

    private func scanBIOS() {
        guard let folder = selectFolder("Scan BIOS Folder") else { return }
        toolBusy = true
        toolError = nil
        Task {
            defer { toolBusy = false }
            do {
                biosMatches = try await Task.detached(priority: .utility) {
                    try PlayStationTools.scanBIOS(in: folder)
                }.value
            } catch { toolError = error.localizedDescription }
        }
    }

    private func loadCatalog(gameDB isGameDB: Bool) {
        let panel = NSOpenPanel()
        panel.prompt = "Load Catalog"
        panel.allowedContentTypes = (isGameDB ? ["yaml", "yml"] : ["xml", "dat"])
            .compactMap { UTType(filenameExtension: $0) }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        toolBusy = true
        toolError = nil
        Task {
            defer { toolBusy = false }
            do {
                let catalog = try await Task.detached(priority: .utility) { try PlayStationCatalog(url: url) }.value
                guard isGameDB == !catalog.discs.isEmpty else {
                    throw PlayStationInspector.InspectionError("Choose the load command that matches this catalog format.")
                }
                if isGameDB { gameDB = catalog } else { discDAT = catalog }
            } catch { toolError = error.localizedDescription }
        }
    }

    private func scanLibrary() {
        guard let folder = selectFolder("Scan Disc Library") else { return }
        let gameDB = gameDB
        let dat = discDAT
        toolBusy = true
        toolError = nil
        Task {
            defer { toolBusy = false }
            do {
                batch = try await Task.detached(priority: .utility) {
                    try PlayStationTools.scanLibrary(folder, gameDB: gameDB, dat: dat)
                }.value
            } catch { toolError = error.localizedDescription }
        }
    }

    private func previewRepair(for report: PlayStationReport) {
        let panel = NSOpenPanel()
        panel.directoryURL = report.file.deletingLastPathComponent()
        panel.prompt = "Preview Replacement"
        guard panel.runModal() == .OK, let replacement = panel.url else { return }
        toolBusy = true
        toolError = nil
        let folder = trackFolder
        Task {
            defer { toolBusy = false }
            do {
                cueRepair = try await Task.detached(priority: .userInitiated) {
                    try PlayStationTools.previewCueRepair(report.file, with: replacement, folder: folder)
                }.value
            } catch { toolError = error.localizedDescription }
        }
    }

    private func cueRepairSheet(_ repair: PlayStationTools.CueRepair) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Preview CUE Repair").font(.headline)
            infoRow("Missing file", repair.originalName)
            infoRow("Replacement", repair.replacementName)
            if let serial = repair.serial { infoRow("Replacement serial", serial) }
            Text("Save a repaired copy beside its BIN files. The original CUE stays in place.")
                .font(.subheadline).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel") { cueRepair = nil }
                Button("Save Repaired Copy…") {
                    let directory = repair.source.deletingPathExtension().deletingLastPathComponent().standardizedFileURL
                    let defaultName = repair.source.deletingPathExtension().lastPathComponent + " (repaired).cue"
                    if let destination = exportDestination(defaultName, directory: directory) {
                        guard destination.deletingLastPathComponent().standardizedFileURL == directory,
                              destination.pathExtension.lowercased() == "cue",
                              !FileManager.default.fileExists(atPath: destination.path) else {
                            toolError = "Choose a new .cue filename in the original disc folder."
                            cueRepair = nil
                            return
                        }
                        do {
                            try repair.data.write(to: destination, options: .withoutOverwriting)
                            cueRepair = nil
                            currentURL = destination
                            analyze(url: destination)
                        } catch {
                            toolError = error.localizedDescription
                            cueRepair = nil
                        }
                    }
                }
            }
        }
        .padding(20).frame(minWidth: 470)
        .textSelection(.enabled)
    }

    private func exportDestination(_ filename: String, directory: URL? = nil) -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = filename
        panel.directoryURL = directory
        return panel.runModal() == .OK ? panel.url : nil
    }

    private func batchSheet(_ batch: [PlayStationTools.BatchRecord]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("PlayStation Library Scan").font(.headline)
            Text("\(batch.count) entries · \(batch.filter(\.bootVerified).count) verified boot entries")
                .font(.subheadline)
            List(batch, id: \.path) { entry in
                VStack(alignment: .leading, spacing: 3) {
                    Text(entry.path).lineLimit(1)
                    Text([entry.serial ?? entry.format, entry.region, "\(entry.tracks) tracks"].joined(separator: " · "))
                        .font(.caption).foregroundStyle(.secondary)
                    if let title = entry.catalogTitle { Text(title).font(.caption) }
                    ForEach([entry.catalogMatch, entry.libCrypt, entry.sbi].compactMap { $0 }, id: \.self) { detail in
                        Text(detail).font(.caption).foregroundStyle(.secondary)
                    }
                    ForEach(Array(entry.notes.enumerated()), id: \.offset) { note in
                        Text(note.element).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            HStack {
                Spacer()
                Button("Close") { self.batch = nil }
                Button("Export CSV…") {
                    guard let url = exportDestination("PlayStation Library.csv") else { return }
                    do {
                        try PlayStationTools.batchCSV(batch).write(to: url, atomically: true, encoding: .utf8)
                    } catch {
                        toolError = error.localizedDescription
                        self.batch = nil
                    }
                }
                Button("Export JSON…") {
                    guard let url = exportDestination("PlayStation Library.json") else { return }
                    do {
                        let encoder = JSONEncoder()
                        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                        try encoder.encode(batch).write(to: url, options: .atomic)
                    } catch {
                        toolError = error.localizedDescription
                        self.batch = nil
                    }
                }
            }
        }
        .padding(20).frame(minWidth: 620, minHeight: 440)
    }

    private func playStationReportView(_ report: PlayStationReport) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Label(report.bootValid ? "PlayStation boot entry verified" :
                        (report.members.isEmpty ? "Boot entry unverified" : "Disc playlist"),
                      systemImage: report.bootValid ? "checkmark.seal.fill" : "exclamationmark.triangle")
                    .font(.headline)
                    .foregroundStyle(report.bootValid ? .green : .orange)
                GroupBox("Disc identity") {
                    VStack(spacing: 7) {
                        infoRow("Image", report.file.lastPathComponent)
                        infoRow("Format", report.format)
                        infoRow("Size", ByteCountFormatter.string(fromByteCount: Int64(report.size), countStyle: .file))
                        infoRow("Serial", report.serial ?? "Unknown")
                        infoRow("Region", report.region)
                        ForEach(report.regions.keys.sorted(), id: \.self) { key in
                            infoRow(key, report.regions[key] ?? "")
                        }
                        infoRow("Region-matched BIOS", report.bios)
                        if report.serial == "SLES-01135" {
                            Toggle("Use Alundra Recompiled firmware profile", isOn: $alundraProfile)
                            if alundraProfile {
                                infoRow("Required firmware", "SCPH-5552 · exact SHA-256 match")
                            }
                        }
                        Button("Scan BIOS Folder…") { scanBIOS() }.disabled(toolBusy)
                        if let biosMatches {
                            let matches = alundraProfile
                                ? biosMatches.filter { $0.sha256 == PlayStationTools.alundraBIOS }
                                : biosMatches.filter { $0.region == report.region }
                            if matches.isEmpty {
                                Text("No matching known BIOS in the selected folder.").font(.caption)
                            } else {
                                ForEach(matches) { match in
                                    infoRow(match.model, match.file.lastPathComponent)
                                }
                            }
                        }
                        infoRow("ISO 9660 volume", report.volume ?? "Unavailable")
                        infoRow("Boot path", report.bootPath ?? "Unavailable")
                        let catalog = PlayStationTools.assess(report, gameDB: gameDB, dat: discDAT, hashes: hashes)
                        if let gameDB { infoRow("Serial catalog", gameDB.name) }
                        if let discDAT { infoRow("Track catalog", discDAT.name) }
                        if let title = catalog.title {
                            infoRow(catalog.match == "Exact track SHA-1" ? "Catalog release" : "Catalog title by serial", title)
                        }
                        if let match = catalog.match { infoRow("Catalog match", match) }
                        infoRow("LibCrypt", catalog.libCrypt)
                        infoRow("SBI companion", catalog.sbi)
                        if report.sbi == .missing, !["CUE", "CCD", "TOC", "GDI", "M3U", "M3U8"].contains(report.format) {
                            Button("Grant Companion Folder Access…") { grantTrackFolder(for: report.file) }
                        }
                        if report.hasSUB { infoRow("SUB companion", "Present · contents unverified") }
                        if report.embeddedSubchannel { infoRow("CHD subchannel data", "Declared · contents unverified") }
                        if let details = report.bootDetails { infoRow("PS-X EXE", details) }
                    }
                    .textSelection(.enabled)
                    .padding(6)
                }
                if !report.members.isEmpty {
                    GroupBox("Playlist discs") {
                        VStack(alignment: .leading) {
                            ForEach(Array(report.members.enumerated()), id: \.offset) { member in
                                Button("Disc \(member.offset + 1) · \(member.element.lastPathComponent)") {
                                    currentURL = member.element
                                    analyze(url: member.element)
                                }
                            }
                            Button("Grant Playlist Folder Access…") { grantTrackFolder(for: report.file) }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(6)
                    }
                }
                if report.members.isEmpty {
                    GroupBox("Tracks") {
                        VStack(alignment: .leading, spacing: 9) {
                            ForEach(report.tracks) { track in
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("Track \(track.id) · \(track.type)").font(.headline)
                                    Text(track.file.lastPathComponent)
                                    Text(trackSummary(track))
                                    if let hash = hashes[track.id] { Text("SHA-1 \(hash)").monospaced() }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            if report.canUseCHDTool {
                                Button("Inspect With chdman…") { inspectUsingCHDTool(report) }
                            }
                            if report.format == "CUE", report.warnings.contains(where: { $0.hasPrefix("Missing or unreadable track file:") }) {
                                Button("Preview CUE Repair…") { previewRepair(for: report) }.disabled(toolBusy)
                            }
                            if ["CUE", "CCD", "TOC", "GDI"].contains(report.format) {
                                Button("Grant Track Folder Access…") { grantTrackFolder(for: report.file) }
                            }
                            if !["CHD", "TOC", "NRG", "GDI", "ECM"].contains(report.format),
                               report.tracks.contains(where: { $0.frames != nil }) {
                                Button(verifying ? "Hashing…" : "Calculate Track SHA-1") { verifyTracks(report) }
                                    .disabled(verifying)
                            }
                            if report.tracks.contains(where: CDSectorIntegrity.supports) {
                                Button(toolBusy ? "Working…" : "Verify Raw Sector EDC/ECC") { verifySectors(report) }
                                    .disabled(toolBusy)
                            }
                            if let sectorSummary {
                                infoRow("Raw sectors checked", sectorSummary.sectors.formatted())
                                infoRow("EDC mismatches", "\(sectorSummary.edcMismatches) / \(sectorSummary.checkedEDC)")
                                infoRow("ECC mismatches", "\(sectorSummary.eccMismatches) / \(sectorSummary.checkedECC)")
                                infoRow("Malformed headers", sectorSummary.malformedHeaders.formatted())
                                infoRow("Form 2 without EDC", sectorSummary.omittedForm2EDC.formatted())
                                infoRow("Other unchecked sector modes", sectorSummary.uncheckedSectors.formatted())
                                ForEach(sectorSummary.examples, id: \.self) { Text($0) }
                            }
                        }
                        .font(.caption)
                        .textSelection(.enabled)
                        .padding(6)
                    }
                }
                if !report.warnings.isEmpty {
                    GroupBox("Inspection notes") {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(Array(report.warnings.enumerated()), id: \.offset) { entry in
                                Text(entry.element).frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                        .font(.caption)
                        .padding(6)
                    }
                }
                if let config = report.config {
                    DisclosureGroup("SYSTEM.CNF") {
                        Text(config).monospaced().textSelection(.enabled)
                    }
                }
            }
        }
    }

    private func trackSummary(_ track: PlayStationTrack) -> String {
        let size = track.sectorBytes.map { "\($0) bytes/sector" } ?? "Sector size unknown"
        let start = track.start.map { "Start \($0)" } ?? "Start unknown"
        let length = track.frames.map { "Length \($0) sectors (\($0 / 75)s)" } ?? "Length unknown"
        return "\(size) · \(start) · \(length) · Pregap \(track.pregap + track.storedPregap) sectors"
    }
}
