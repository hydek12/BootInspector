import CryptoKit
import Foundation

nonisolated struct PlayStationTrack: Identifiable, Sendable {
    let id: Int
    let type: String
    let file: URL
    let sectorBytes: Int?
    var index00: Int?
    var index01: Int?
    var pregap = 0
    var start: Int?
    var frames: Int?

    var storedPregap: Int { max(0, (index01 ?? 0) - (index00 ?? index01 ?? 0)) }
}

nonisolated struct PlayStationReport: Sendable {
    let file: URL
    var format: String
    var size = 0
    var tracks: [PlayStationTrack] = []
    var volume: String?
    var serial: String?
    var bootPath: String?
    var bootValid = false
    var bootDetails: String?
    var config: String?
    var regions: [String: String] = [:]
    var warnings: [String] = []
    var hasSBI = false
    var hasSUB = false
    var members: [URL] = []

    var canUseCHDTool: Bool {
        ["CHD", "TOC", "NRG", "GDI"].contains(format) && !bootValid
    }

    var region: String {
        let values = Set(regions.values)
        return values.count > 1 ? "Conflicting evidence" : values.first ?? "Unknown"
    }

    var bios: String {
        switch region {
        case "Japan / NTSC-J": return "SCPH-5500 (example)"
        case "North America / NTSC-U/C": return "SCPH-5501 (example)"
        case "Europe / PAL": return "SCPH-5502 (example)"
        default: return "Select using the emulator’s region settings"
        }
    }
}

nonisolated enum PlayStationInspector {
    struct InspectionError: LocalizedError {
        let errorDescription: String?
        init(_ message: String) { errorDescription = message }
    }

    private struct Extent {
        let block: Int
        let size: Int
        let directory: Bool
    }

    private static let sectorSizes = [
        "AUDIO": 2352, "MODE1/2048": 2048, "MODE1/2352": 2352,
        "MODE2/2336": 2336, "MODE2/2352": 2352, "MODE2/2448": 2448, "MODE1/2448": 2448, "CDI/2336": 2336, "CDI/2352": 2352
    ]

    static func inspect(_ url: URL) throws -> PlayStationReport {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let kind = url.pathExtension.lowercased()
        var report = PlayStationReport(file: url, format: kind.uppercased())
        report.hasSBI = companion(url, extension: "sbi") != nil
        report.hasSUB = companion(url, extension: "sub") != nil
        switch kind {
        case "chd":
            try inspectCHD(url, report: &report)
            return report
        case "m3u", "m3u8":
            report.members = try readPlaylist(url)
            for file in report.members where !FileManager.default.fileExists(atPath: file.path) {
                report.warnings.append("Missing or inaccessible playlist entry: \(file.lastPathComponent)")
            }
            return report
        case "toc", "nrg", "gdi":
            report.warnings.append("Use chdman to convert this descriptor temporarily and inspect the resulting CD tracks.")
            return report
        case "ecm":
            return try inspectECM(url, container: report)
        case "pbp", "cso", "zso", "isz", "dax", "mds":
            let guidance = kind == "mds" ? "Open the companion MDF to inspect its data track, or convert MDS/MDF to CUE/BIN to preserve the track layout." :
                "Decode or convert the image to CUE/BIN or CHD before inspection."
            throw InspectionError("\(kind.uppercased()) container. \(guidance)")
        case "ccd":
            try readCloneCD(url, report: &report)
        case "cue":
            try readCue(url, report: &report)
        default:
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            let size = try handle.seekToEnd()
            var detected: String?
            for mode in ["MODE1/2048", "MODE2/2352", "MODE1/2352", "MODE2/2448", "MODE1/2448", "MODE2/2336"] {
                let track = PlayStationTrack(id: 1, type: mode, file: url, sectorBytes: sectorSizes[mode], index01: 0)
                if try volumeDescriptor(handle, track: track, fileSize: size) != nil {
                    detected = mode
                    break
                }
            }
            guard let detected else { throw InspectionError("No supported ISO 9660 data track was found.") }
            report.tracks = [PlayStationTrack(id: 1, type: detected, file: url, sectorBytes: sectorSizes[detected], index01: 0)]
            report.warnings.append("Standalone image. Additional tracks and pregaps require a disc descriptor.")
        }
        try measureTracks(report: &report)
        for track in report.tracks where track.type.hasPrefix("MODE") && (track.frames ?? 0) > 16 {
            let handle = try FileHandle(forReadingFrom: track.file)
            defer { try? handle.close() }
            guard let descriptor = try volumeDescriptor(handle, track: track, fileSize: handle.seekToEnd()) else { continue }
            try inspectFilesystem(handle, track: track, descriptor: descriptor, report: &report)
            if report.bootPath != nil { break }
        }
        if report.volume == nil { report.warnings.append("No readable ISO 9660 data track was found.") }
        if report.bootPath == nil { report.warnings.append("No PlayStation boot entry was found.") }
        if report.region == "Conflicting evidence" { report.warnings.append("The boot serial and license area indicate different regions.") }
        return report
    }

    private static func inspectECM(_ url: URL, container: PlayStationReport) throws -> PlayStationReport {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let image = directory.appendingPathComponent("decoded.bin")
        try PlayStationECM.decode(url, to: image)
        let decoded = try inspect(image)
        var report = container
        report.size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        report.volume = decoded.volume
        report.serial = decoded.serial
        report.bootPath = decoded.bootPath
        report.bootValid = decoded.bootValid
        report.bootDetails = decoded.bootDetails
        report.config = decoded.config
        report.regions = decoded.regions
        report.tracks = decoded.tracks.map {
            PlayStationTrack(id: $0.id, type: $0.type, file: url, sectorBytes: $0.sectorBytes,
                             start: $0.start, frames: $0.frames)
        }
        report.warnings = decoded.warnings
        report.warnings.append("ECM checksum verified. Track sizes are from the decoded data.")
        return report
    }

    private static func companion(_ url: URL, extension suffix: String) -> URL? {
        let base = url.deletingPathExtension().lastPathComponent
        let parent = url.deletingLastPathComponent()
        for ext in [suffix, suffix.uppercased()] {
            let file = parent.appendingPathComponent(base).appendingPathExtension(ext)
            if FileManager.default.fileExists(atPath: file.path) { return file }
        }
        return nil
    }

    private static func readDescriptor(_ url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: 1_048_576) ?? Data()
        guard data.count < 1_048_576,
              let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
            throw InspectionError("The disc descriptor is too large or unreadable.")
        }
        return String(text.drop(while: { $0 == "\u{FEFF}" }))
    }

    private static func readPlaylist(_ url: URL) throws -> [URL] {
        let parent = url.deletingLastPathComponent()
        let lines = try readDescriptor(url).components(separatedBy: .newlines)
        let files = lines.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter {
            !$0.isEmpty && !$0.hasPrefix("#") && !$0.contains("://")
        }.map { URL(fileURLWithPath: $0, relativeTo: parent).standardizedFileURL }
        guard !files.isEmpty else { throw InspectionError("The playlist has no local disc images.") }
        return files
    }

    private static func readCloneCD(_ url: URL, report: inout PlayStationReport) throws {
        let image = companion(url, extension: "img") ?? url.deletingPathExtension().appendingPathExtension("img")
        let text = try readDescriptor(url)
        var sections: [(String, [String: String])] = []
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("["), line.hasSuffix("]") {
                sections.append((String(line.dropFirst().dropLast()).uppercased(), [:]))
            } else if let index = sections.indices.last {
                let pair = line.split(separator: "=", maxSplits: 1)
                if pair.count == 2 {
                    sections[index].1[pair[0].trimmingCharacters(in: .whitespaces).uppercased()] =
                        pair[1].trimmingCharacters(in: .whitespaces)
                }
            }
        }
        if sections.first(where: { $0.0 == "DISC" })?.1["DATATRACKSSCRAMBLED"] == "1" {
            throw InspectionError("This CloneCD image has scrambled data sectors. Convert it to descrambled CUE/BIN or CHD first.")
        }
        for (section, fields) in sections where section.hasPrefix("TRACK ") {
            guard let number = Int(section.dropFirst(6)), (1...99).contains(number),
                  !report.tracks.contains(where: { $0.id == number }) else {
                throw InspectionError("Invalid or duplicate CloneCD track number.")
            }
            let type = switch fields["MODE"] {
            case "0": "AUDIO"
            case "1": "MODE1/2352"
            case "2": "MODE2/2352"
            default: "Unknown"
            }
            report.tracks.append(PlayStationTrack(id: number, type: type, file: image,
                sectorBytes: sectorSizes[type], index00: fields["INDEX 0"].flatMap(Int.init),
                index01: fields["INDEX 1"].flatMap(Int.init)))
        }
        guard !report.tracks.isEmpty else { throw InspectionError("The CloneCD descriptor contains no supported track records.") }
        report.tracks.sort { $0.id < $1.id }
    }

    private static func readCue(_ url: URL, report: inout PlayStationReport) throws {
        let text = try readDescriptor(url)
        var backing: URL?
        var fileType: String?
        for line in text.components(separatedBy: .newlines) {
            let line = line.trimmingCharacters(in: .whitespaces)
            guard let command = line.split(whereSeparator: \.isWhitespace).first else { continue }
            let rest = line.dropFirst(command.count).trimmingCharacters(in: .whitespaces)
            let fields = rest.split(whereSeparator: \.isWhitespace)
            switch command.uppercased() {
            case "FILE":
                let pieces = rest.split(separator: "\"")
                let name = rest.hasPrefix("\"") ? pieces.first.map(String.init) : fields.dropLast().joined(separator: " ")
                backing = name.flatMap { $0.isEmpty ? nil : URL(fileURLWithPath: $0, relativeTo: url.deletingLastPathComponent()).standardizedFileURL }
                fileType = fields.last?.uppercased()
            case "TRACK":
                guard let backing, fields.count == 2, let id = Int(fields[0]), (1...99).contains(id),
                      !report.tracks.contains(where: { $0.id == id }) else {
                    throw InspectionError("Invalid or duplicate TRACK declaration: \(line)")
                }
                let type = fields[1].uppercased()
                report.tracks.append(PlayStationTrack(id: id, type: type, file: backing,
                    sectorBytes: fileType == "BINARY" ? sectorSizes[type] : nil))
            case "INDEX", "PREGAP":
                guard let i = report.tracks.indices.last, let time = fields.last, let frame = cueFrame(time) else {
                    throw InspectionError("Invalid CUE timing: \(line)")
                }
                if command.uppercased() == "PREGAP" { report.tracks[i].pregap = frame }
                else if fields.first == "00" { report.tracks[i].index00 = frame }
                else if fields.first == "01" { report.tracks[i].index01 = frame }
            default: break
            }
        }
        guard !report.tracks.isEmpty else { throw InspectionError("The CUE contains no tracks.") }
    }

    private static func cueFrame(_ value: Substring) -> Int? {
        let parts = value.split(separator: ":").compactMap { Int($0) }
        guard parts.count == 3, (0...999).contains(parts[0]), (0..<60).contains(parts[1]),
              (0..<75).contains(parts[2]) else { return nil }
        return (parts[0] * 60 + parts[1]) * 75 + parts[2]
    }

    private static func measureTracks(report: inout PlayStationReport) throws {
        var fileSizes: [URL: Int] = [:]
        var unreadable = Set<URL>()
        var discFrame: Int? = 0
        for i in report.tracks.indices {
            let track = report.tracks[i]
            if fileSizes[track.file] == nil && !unreadable.contains(track.file) {
                do {
                    let handle = try FileHandle(forReadingFrom: track.file)
                    defer { try? handle.close() }
                    fileSizes[track.file] = Int(try handle.seekToEnd())
                } catch {
                    unreadable.insert(track.file)
                    report.warnings.append("Missing or unreadable track file: \(track.file.lastPathComponent). Grant access to its containing folder if needed.")
                }
            }
            guard let size = fileSizes[track.file], let stride = track.sectorBytes,
                  let begin = track.index01, begin >= 0, (track.index00 ?? begin) >= 0,
                  (track.index00 ?? begin) <= begin else {
                if !unreadable.contains(track.file) { report.warnings.append("Unsupported sector layout or missing INDEX 01 on track \(track.id).") }
                discFrame = nil
                continue
            }
            let sameFile = report.tracks.filter { $0.file == track.file }
            guard sameFile.allSatisfy({ $0.sectorBytes == stride }) else {
                report.warnings.append("Shared files with mixed sector sizes cannot be measured reliably.")
                discFrame = nil
                continue
            }
            let fileFrames = size / stride
            let next = report.tracks.dropFirst(i + 1).first { $0.file == track.file }
            let end = next.flatMap { $0.index00 ?? $0.index01 } ?? fileFrames
            guard begin < end, end <= fileFrames else {
                report.warnings.append("Track \(track.id) has invalid or truncated sector boundaries.")
                discFrame = nil
                continue
            }
            if size % stride != 0 { report.warnings.append("Track \(track.id) backing file ends with a partial sector.") }
            let start = discFrame.map { $0 + track.pregap + track.storedPregap }
            report.tracks[i].start = start
            report.tracks[i].frames = end - begin
            discFrame = start.map { $0 + end - begin }
        }
        report.size = fileSizes.values.reduce(0, +)
    }

    private static func volumeDescriptor(_ handle: FileHandle, track: PlayStationTrack, fileSize: UInt64) throws -> Data? {
        let frames = track.frames ?? Int(fileSize / UInt64(track.sectorBytes ?? 2048))
        for block in 16..<min(frames, 64) {
            let data = try sector(handle, track: track, block: block)
            guard data.count == 2048, String(decoding: data[1..<6], as: UTF8.self) == "CD001" else { break }
            if data[0] == 1 { return data }
            if data[0] == 255 { break }
        }
        return nil
    }

    private static func sector(_ handle: FileHandle, track: PlayStationTrack, block: Int) throws -> Data {
        let offset = switch track.type {
        case "MODE1/2352", "MODE1/2448": 16
        case "MODE2/2352", "MODE2/2448": 24
        case "MODE2/2336": 8
        default: 0
        }
        let seek = ((track.index01 ?? 0) + block) * (track.sectorBytes ?? 2048) + offset
        try handle.seek(toOffset: UInt64(seek))
        return try handle.read(upToCount: 2048) ?? Data()
    }

    private static func inspectFilesystem(_ handle: FileHandle, track: PlayStationTrack, descriptor: Data,
                                          report: inout PlayStationReport) throws {
        report.volume = String(decoding: descriptor[40..<72], as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let root = extent(descriptor, at: 156), let maxFrames = track.frames else { return }
        func read(_ entry: Extent, limit: Int) throws -> Data {
            let count = min(entry.size, limit)
            let blocks = (count + 2047) / 2048
            guard entry.block < maxFrames, blocks <= maxFrames - entry.block else { return Data() }
            var bytes = Data()
            for block in 0..<blocks { bytes.append(try sector(handle, track: track, block: entry.block + block)) }
            return Data(bytes.prefix(count))
        }
        func find(_ path: [String]) throws -> Extent? {
            var current = root
            for component in path {
                guard current.directory else { return nil }
                let bytes = try read(current, limit: 2_097_152)
                var pos = 0
                var match: Extent?
                while pos < bytes.count {
                    let length = Int(bytes[pos])
                    if length == 0 { pos = (pos / 2048 + 1) * 2048; continue }
                    guard length >= 34, pos + length <= bytes.count else { break }
                    let nameSize = Int(bytes[pos + 32])
                    if nameSize <= length - 33 {
                        let name = String(decoding: bytes[(pos + 33)..<(pos + 33 + nameSize)], as: UTF8.self)
                        let normalized = name.split(separator: ";").first.map(String.init) ?? name
                        if normalized.caseInsensitiveCompare(component) == .orderedSame { match = extent(bytes, at: pos); break }
                    }
                    pos += length
                }
                guard let match else { return nil }
                current = match
            }
            return current
        }
        if let config = try find(["SYSTEM.CNF"]) {
            report.config = String(decoding: try read(config, limit: 16_384), as: UTF8.self)
            let lines = report.config?.components(separatedBy: .newlines) ?? []
            for line in lines {
                let pair = line.split(separator: "=", maxSplits: 1)
                guard pair.count == 2, pair[0].trimmingCharacters(in: .whitespaces).uppercased() == "BOOT" else { continue }
                report.bootPath = pair[1].trimmingCharacters(in: .whitespaces)
                break
            }
        } else if try find(["PSX.EXE"]) != nil { report.bootPath = "PSX.EXE" }

        var license = Data()
        for block in 0..<min(maxFrames, 16) { license.append(try sector(handle, track: track, block: block)) }
        let text = String(decoding: license, as: UTF8.self).uppercased()
        for (marker, region) in [
            ("SONY COMPUTER ENTERTAINMENT EUROPE", "Europe / PAL"),
            ("SONY COMPUTER ENTERTAINMENT AMERICA", "North America / NTSC-U/C"),
            ("SONY COMPUTER ENTERTAINMENT INC.", "Japan / NTSC-J")
        ] where text.contains(marker) { report.regions["License area"] = region; break }

        guard let raw = report.bootPath else { return }
        let clean = raw.split(separator: ":").last?.split(separator: ";").first ?? Substring(raw)
        let path = clean.split(whereSeparator: { $0 == "/" || $0 == "\\" }).map(String.init)
        if let filename = path.last, let range = filename.range(of: #"^[A-Za-z]{4}[_-][0-9]{3}\.?[0-9]{2}$"#, options: .regularExpression) {
            let serial = filename[range].uppercased().replacingOccurrences(of: "_", with: "-").replacingOccurrences(of: ".", with: "")
            report.serial = serial
            switch serial.prefix(4) {
            case "SLES", "SCES": report.regions["Boot serial"] = "Europe / PAL"
            case "SLUS", "SCUS": report.regions["Boot serial"] = "North America / NTSC-U/C"
            case "SLPS", "SLPM", "SCPS", "SIPS", "SCPM": report.regions["Boot serial"] = "Japan / NTSC-J"
            default: break
            }
        }
        guard !path.isEmpty, let executable = try find(path), !executable.directory else {
            report.warnings.append("The boot executable specified by SYSTEM.CNF is missing.")
            return
        }
        let header = try read(executable, limit: 2048)
        report.bootValid = header.count == 2048 && header.prefix(8).elementsEqual("PS-X EXE".utf8)
        if report.bootValid {
            report.bootDetails = String(format: "Entry 0x%08X · Load 0x%08X · Payload %u bytes",
                UInt32(le32(header, 16)), UInt32(le32(header, 24)), UInt32(le32(header, 28)))
            if le32(header, 28) > executable.size - 2048 {
                report.bootValid = false
                report.warnings.append("The PS-X EXE payload exceeds the boot file length.")
            }
        } else { report.warnings.append("The boot file lacks a complete PS-X EXE header.") }
    }

    private static func extent(_ data: Data, at offset: Int) -> Extent? {
        guard offset + 34 <= data.count else { return nil }
        return Extent(block: le32(data, offset + 2), size: le32(data, offset + 10), directory: data[offset + 25] & 2 != 0)
    }

    private static func le32(_ data: Data, _ i: Int) -> Int {
        (0..<4).reduce(0) { $0 | (Int(data[i + $1]) << ($1 * 8)) }
    }

    private static func bigEndian(_ data: Data, _ start: Int, _ count: Int) -> UInt64 {
        data[start..<(start + count)].reduce(0) { ($0 << 8) | UInt64($1) }
    }

    private static func inspectCHD(_ url: URL, report: inout PlayStationReport) throws {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let length = try handle.seekToEnd()
        try handle.seek(toOffset: 0)
        let header = try handle.read(upToCount: 124) ?? Data()
        guard header.count == 124, header.prefix(8).elementsEqual("MComprHD".utf8),
              bigEndian(header, 8, 4) == 124, bigEndian(header, 12, 4) == 5 else {
            throw InspectionError("Expected a CHD version 5 container.")
        }
        report.size = Int(length)
        var offset = bigEndian(header, 48, 8)
        var visited = Set<UInt64>()
        var start = 0
        while offset != 0 {
            guard length >= 16, offset <= length - 16, visited.count < 256, visited.insert(offset).inserted else {
                throw InspectionError("Invalid CHD metadata chain.")
            }
            try handle.seek(toOffset: offset)
            let record = try handle.read(upToCount: 16) ?? Data()
            guard record.count == 16 else { throw InspectionError("Truncated CHD metadata.") }
            let tag = String(decoding: record.prefix(4), as: UTF8.self)
            let size = Int(bigEndian(record, 5, 3))
            if tag == "CHT2" || tag == "CHTR" {
                guard size <= 4096, UInt64(size) <= length - offset - 16 else { throw InspectionError("Invalid CHD track metadata length.") }
                let data = try handle.read(upToCount: size) ?? Data()
                let fields = String(decoding: data.prefix { $0 != 0 }, as: UTF8.self)
                    .split(whereSeparator: \.isWhitespace).reduce(into: [String: String]()) { result, field in
                        let pair = field.split(separator: ":", maxSplits: 1)
                        if pair.count == 2 { result[String(pair[0])] = String(pair[1]) }
                    }
                guard let number = fields["TRACK"].flatMap(Int.init), (1...99).contains(number),
                      let type = fields["TYPE"], let frames = fields["FRAMES"].flatMap(Int.init), (1...1_000_000).contains(frames),
                      !report.tracks.contains(where: { $0.id == number }) else { throw InspectionError("Invalid CHD track record.") }
                let gap = fields["PREGAP"].flatMap(Int.init) ?? 0
                let postgap = fields["POSTGAP"].flatMap(Int.init) ?? 0
                guard (0...frames).contains(gap), (0...1_000_000).contains(postgap) else { throw InspectionError("Invalid CHD gap length.") }
                let stored = fields["PGTYPE"]?.hasPrefix("V") == true
                let mode = ["MODE2_RAW":"MODE2/2352", "MODE1_RAW":"MODE1/2352", "MODE1":"MODE1/2048", "MODE2":"MODE2/2336"][type] ?? type
                report.tracks.append(PlayStationTrack(id: number, type: mode, file: url, sectorBytes: sectorSizes[mode],
                    pregap: gap, start: start + gap, frames: frames - (stored ? gap : 0)))
                start += frames + (stored ? 0 : gap) + postgap
            }
            offset = bigEndian(record, 8, 8)
        }
        report.warnings.append("CHD track metadata only. Use chdman or open the equivalent CUE/BIN to inspect the boot executable and region.")
        if report.tracks.isEmpty { report.warnings.append("This CHD has no supported CD track records.") }
    }

    static func inspectUsingCHDTool(_ url: URL, tool: URL) throws -> PlayStationReport {
        let imageScope = url.startAccessingSecurityScopedResource()
        let toolScope = tool.startAccessingSecurityScopedResource()
        defer {
            if imageScope { url.stopAccessingSecurityScopedResource() }
            if toolScope { tool.stopAccessingSecurityScopedResource() }
        }
        var container = try inspect(url)
        guard container.canUseCHDTool, tool.lastPathComponent == "chdman",
              FileManager.default.isExecutableFile(atPath: tool.path) else {
            throw InspectionError("Select an executable chdman for a supported CD image.")
        }
        let work = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: work) }
        var input = url
        if container.format != "CHD" {
            input = work.appendingPathComponent("converted.chd")
            try runCHDTool(tool, arguments: ["createcd", "-i", url.path, "-o", input.path, "-c", "cdzl,cdfl", "-np", "4"], in: work)
            let metadata = try inspect(input)
            container.tracks = metadata.tracks.map { track in
                PlayStationTrack(id: track.id, type: track.type, file: url, sectorBytes: track.sectorBytes,
                                 pregap: track.pregap, start: track.start, frames: track.frames)
            }
            container.size = Int((try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
            container.warnings.removeAll { $0.hasPrefix("Use chdman") }
        }
        let cue = work.appendingPathComponent("disc.cue")
        try runCHDTool(tool, arguments: ["extractcd", "-i", input.path, "-o", cue.path,
                                         "-ob", work.appendingPathComponent("track%t.bin").path, "-sb"], in: work)
        let extracted = try inspect(cue)
        container.volume = extracted.volume
        container.serial = extracted.serial
        container.bootPath = extracted.bootPath
        container.bootValid = extracted.bootValid
        container.bootDetails = extracted.bootDetails
        container.config = extracted.config
        container.regions = extracted.regions
        container.warnings.removeAll { $0.hasPrefix("CHD track metadata only.") }
        container.warnings.append(contentsOf: extracted.warnings)
        return container
    }

    private static func runCHDTool(_ tool: URL, arguments: [String], in directory: URL) throws {
        let command = Process()
        command.executableURL = tool
        command.arguments = arguments
        let logURL = directory.appendingPathComponent("chdman.log")
        try Data().write(to: logURL)
        let log = try FileHandle(forUpdating: logURL)
        defer { try? log.close() }
        command.standardOutput = log
        command.standardError = log
        try command.run()
        let deadline = ProcessInfo.processInfo.systemUptime + 180
        while command.isRunning && ProcessInfo.processInfo.systemUptime < deadline {
            Thread.sleep(forTimeInterval: 0.1)
        }
        if command.isRunning {
            command.terminate()
            throw InspectionError("chdman timed out while reading the disc.")
        }
        command.waitUntilExit()
        guard command.terminationStatus == 0 else {
            let size = try log.seekToEnd()
            try log.seek(toOffset: size > 1024 ? size - 1024 : 0)
            let detail = String(decoding: try log.read(upToCount: 1024) ?? Data(), as: UTF8.self)
            throw InspectionError("chdman could not read this disc. \(detail)")
        }
    }

    static func sha1(_ track: PlayStationTrack) throws -> String {
        guard let index = track.index00 ?? track.index01, let frames = track.frames,
              let stride = track.sectorBytes else { throw InspectionError("Track boundaries are unknown.") }
        let url = track.file
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        try file.seek(toOffset: UInt64(index * stride))
        var remaining = (frames + track.storedPregap) * stride
        var hash = Insecure.SHA1()
        while remaining > 0 {
            let bytes = try file.read(upToCount: min(remaining, 1_048_576)) ?? Data()
            guard !bytes.isEmpty else { throw InspectionError("Track file ended while hashing.") }
            remaining -= bytes.count
            try Task.checkCancellation()
            hash.update(data: bytes)
        }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
