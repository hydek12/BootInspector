import CryptoKit
import Foundation

nonisolated enum PlayStationTools {
    struct BIOS: Identifiable, Sendable {
        let file: URL
        let sha256: String
        let model: String
        let region: String

        var id: URL { file }
    }

    struct CueRepair: Sendable {
        let source: URL
        let originalName: String
        let replacementName: String
        let serial: String?
        let data: Data
    }

    struct BatchRecord: Codable, Sendable {
        let path: String
        let format: String
        let serial: String?
        let region: String
        let bootVerified: Bool
        let tracks: Int
        let notes: [String]
        var catalogTitle: String? = nil
        var catalogMatch: String? = nil
        var libCrypt: String? = nil
        var sbi: String? = nil
    }

    static func batchCSV(_ records: [BatchRecord]) -> String {
        let header = "path,format,serial,region,boot_verified,tracks,notes,catalog_title,catalog_match,libcrypt,sbi"
        let rows = records.map { record in
            [
                record.path, record.format, record.serial ?? "", record.region,
                String(record.bootVerified), String(record.tracks),
                record.notes.joined(separator: "\n"), record.catalogTitle ?? "",
                record.catalogMatch ?? "", record.libCrypt ?? "", record.sbi ?? ""
            ].map { value in
                let first = value.drop(while: \.isWhitespace).first
                let escaped = value.replacingOccurrences(of: "\"", with: "\"\"")
                let prefix = first.map { "=+-@".contains($0) } == true ? "'" : ""
                return "\"\(prefix)\(escaped)\""
            }.joined(separator: ",")
        }
        return ([header] + rows).joined(separator: "\r\n") + "\r\n"
    }

    private static let firmware: [String: (model: String, region: String)] = [
        "9c0421858e217805f4abe18698afea8d5aa36ff0727eb8484944e00eb5e7eadb": ("SCPH-5500", "Japan / NTSC-J"),
        "11052b6499e466bbf0a709b1f9cb6834a9418e66680387912451e971cf8a1fef": ("SCPH-5501", "North America / NTSC-U/C"),
        "1faaa18fa820a0225e488d9f086296b8e6c46df739666093987ff7d8fd352c09": ("SCPH-5502 / SCPH-5552", "Europe / PAL"),
        "42e4124be7623e2e28b1db0d8d426539646faee49d74b71166d8ba5bd7c472ed": ("SCPH-1001", "North America / NTSC-U/C"),
        "aca9cbfa974b933646baad6556a867eca9b81ce65d8af343a7843f7775b9ffc8": ("SCPH-101", "North America / NTSC-U/C")
    ]

    static let alundraBIOS = "1faaa18fa820a0225e488d9f086296b8e6c46df739666093987ff7d8fd352c09"

    static func scanBIOS(in folder: URL) throws -> [BIOS] {
        let scoped = folder.startAccessingSecurityScopedResource()
        defer { if scoped { folder.stopAccessingSecurityScopedResource() } }
        let keys: Set<URLResourceKey> = [.isRegularFileKey, .fileSizeKey]
        let files = try FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: Array(keys), options: .skipsHiddenFiles)
        var matches: [BIOS] = []
        for file in files.sorted(by: { $0.lastPathComponent.localizedStandardCompare($1.lastPathComponent) == .orderedAscending }) {
            try Task.checkCancellation()
            guard let info = try? file.resourceValues(forKeys: keys), info.isRegularFile == true,
                  info.fileSize == 524_288, let handle = try? FileHandle(forReadingFrom: file) else { continue }
            defer { try? handle.close() }
            guard let data = try? handle.read(upToCount: 524_289), data.count == 524_288 else { continue }
            let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            if let bios = firmware[digest] {
                matches.append(BIOS(file: file, sha256: digest, model: bios.model, region: bios.region))
            }
        }
        return matches
    }

    static func previewCueRepair(_ url: URL, with replacement: URL, folder: URL?) throws -> CueRepair {
        let scopes = [url, replacement] + (folder.map { [$0] } ?? [])
        let accessed = scopes.filter { $0.startAccessingSecurityScopedResource() }
        defer { accessed.forEach { $0.stopAccessingSecurityScopedResource() } }
        let directory = url.deletingLastPathComponent().standardizedFileURL
        guard url.pathExtension.lowercased() == "cue",
              replacement.deletingLastPathComponent().standardizedFileURL == directory,
              replacement.pathExtension.lowercased() == "bin" else {
            throw PlayStationInspector.InspectionError("Choose a BIN in the same folder as the CUE.")
        }

        let report = try PlayStationInspector.inspect(url)
        let files = Set(report.tracks.map(\.file))
        let missing = files.filter { !FileManager.default.fileExists(atPath: $0.path) }
        guard missing.count == 1, let original = missing.first,
              original.deletingLastPathComponent().standardizedFileURL == directory,
              !files.contains(replacement.standardizedFileURL) else {
            throw PlayStationInspector.InspectionError("Repair requires exactly one missing local track file and an unused replacement BIN.")
        }
        let affected = report.tracks.filter { $0.file == original }
        let handle = try FileHandle(forReadingFrom: replacement)
        defer { try? handle.close() }
        let size = try handle.seekToEnd()
        guard size > 0, let bytes = Int(exactly: size),
              affected.allSatisfy({ track in
                  guard let stride = track.sectorBytes, let start = track.index01 else { return false }
                  return start >= 0 && bytes.isMultiple(of: stride) && start < bytes / stride
              }) else {
            throw PlayStationInspector.InspectionError("The replacement BIN does not fit the CUE track boundaries.")
        }
        let replacementName = replacement.lastPathComponent
        guard !replacementName.contains("\""), !replacementName.contains(where: \.isNewline) else {
            throw PlayStationInspector.InspectionError("The replacement filename cannot be written safely in a CUE.")
        }
        // Keep the source encoding and line endings in the exported copy.
        let cue = try FileHandle(forReadingFrom: url)
        defer { try? cue.close() }
        guard let originalData = try cue.read(upToCount: 1_048_576), originalData.count < 1_048_576 else {
            throw PlayStationInspector.InspectionError("The CUE could not be read for preview.")
        }
        let encoding: String.Encoding = String(data: originalData, encoding: .utf8) != nil ? .utf8 : .isoLatin1
        guard let text = String(data: originalData, encoding: encoding) else {
            throw PlayStationInspector.InspectionError("The CUE text encoding could not be read.")
        }
        let pattern = #"(?im)^([ \t]*FILE[ \t]+)(?:"([^"]+)"|([^\s"]+))([ \t]+BINARY\b)"#
        let expression = try NSRegularExpression(pattern: pattern)
        let matches = expression.matches(in: text, range: NSRange(text.startIndex..., in: text))
        let originalName = original.lastPathComponent
        let missingStatements = matches.filter { match in
            let field = match.range(at: 2).location != NSNotFound ? match.range(at: 2) : match.range(at: 3)
            guard let range = Range(field, in: text) else { return false }
            return String(text[range]) == originalName
        }
        guard missingStatements.count == 1, let match = missingStatements.first,
              let prefix = Range(match.range(at: 1), in: text),
            let suffix = Range(match.range(at: 4), in: text),
            let range = Range(match.range, in: text) else {
            throw PlayStationInspector.InspectionError("The missing file could not be matched to a FILE statement.")
        }
        var amended = text
        amended.replaceSubrange(range, with: "\(text[prefix])\"\(replacementName)\"\(text[suffix])")
        guard let data = amended.data(using: encoding) else {
            throw PlayStationInspector.InspectionError("The new filename cannot be represented in this CUE encoding.")
        }
        let raw = try? PlayStationInspector.inspect(replacement)
        if affected.contains(where: { $0.type.hasPrefix("MODE") && $0.index01 == 0 }),
           raw?.bootValid != true {
            throw PlayStationInspector.InspectionError("The replacement data track has no verified PlayStation boot entry.")
        }
        return CueRepair(source: url, originalName: originalName, replacementName: replacementName, serial: raw?.serial, data: data)
    }

    struct CatalogAssessment: Sendable {
        let title: String?
        let match: String?
        let libCrypt: String
        let sbi: String
    }

    static func assess(_ report: PlayStationReport, gameDB: PlayStationCatalog?,
                       dat: PlayStationCatalog?, hashes: [Int: String] = [:]) -> CatalogAssessment {
        let disc = report.serial.flatMap { gameDB?.discs[$0] }
        let exact = dat?.match(report.tracks, hashes: hashes) ?? []
        let match: String?
        if !exact.isEmpty {
            match = "Exact track SHA-1"
        } else if let dat {
            if report.tracks.isEmpty || report.tracks.contains(where: { $0.storedByteCount == nil }) {
                match = "Track hashes unavailable for this layout"
            } else if !dat.containsLayout(report.tracks) || hashes.count == report.tracks.count {
                match = "No exact catalog match"
            } else {
                match = "Track SHA-1 comparison pending"
            }
        } else {
            match = disc != nil ? "Serial match" : gameDB != nil ? "Serial absent from catalog" : nil
        }

        let hasSubchannel = report.hasSUB || report.embeddedSubchannel || report.tracks.contains { $0.sectorBytes == 2448 }
        let libCrypt: String
        if disc?.libCrypt == true {
            switch report.sbi {
            case .valid: libCrypt = "Catalog flags LibCrypt · SBI structure valid"
            case .missing where hasSubchannel: libCrypt = "Catalog flags LibCrypt · other subchannel data declared, contents unverified"
            case .missing: libCrypt = "Catalog flags LibCrypt · SBI missing or inaccessible"
            case .invalid, .unreadable: libCrypt = "Catalog flags LibCrypt · SBI unusable"
            }
        } else {
            libCrypt = disc == nil ? "Unknown · no serial match in a LibCrypt catalog" : "Serial match · no LibCrypt flag"
        }
        return CatalogAssessment(title: exact.isEmpty ? disc?.title : exact.joined(separator: " / "),
                                 match: match, libCrypt: libCrypt, sbi: report.sbi.summary)
    }

    static func scanLibrary(_ folder: URL, gameDB: PlayStationCatalog? = nil, dat: PlayStationCatalog? = nil) throws -> [BatchRecord] {
        let scoped = folder.startAccessingSecurityScopedResource()
        defer { if scoped { folder.stopAccessingSecurityScopedResource() } }
        let primary: Set<String> = ["cue", "ccd", "iso", "chd", "m3u", "m3u8", "toc", "gdi", "nrg", "pbp", "ecm", "mds", "cso", "zso", "isz", "dax"]
        let raw: Set<String> = ["img", "bin", "mdf", "raw", "2352", "2448"]
        guard let enumerator = FileManager.default.enumerator(at: folder, includingPropertiesForKeys: [.isRegularFileKey],
                                                              options: [.skipsHiddenFiles, .skipsPackageDescendants]) else {
            throw PlayStationInspector.InspectionError("The disc library folder could not be opened.")
        }
        var descriptors: [URL] = []
        var loose: [URL] = []
        var companions: [String: PlayStationInspector.Companions] = [:]
        for case let file as URL in enumerator {
            try Task.checkCancellation()
            let ext = file.pathExtension.lowercased()
            let sidecar = ext == "sbi" || ext == "sub"
            guard sidecar || primary.contains(ext) || raw.contains(ext),
                  (try? file.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else { continue }
            if sidecar {
                let key = PlayStationInspector.Companions.key(for: file)
                if ext == "sbi" { companions[key, default: .init()].sbi = file }
                else { companions[key, default: .init()].sub = file }
            } else if primary.contains(ext) {
                descriptors.append(file)
            } else {
                loose.append(file)
            }
        }
        let root = folder.standardizedFileURL.path + "/"
        var backing = Set<URL>()
        func inspect(_ file: URL) throws -> BatchRecord {
            try Task.checkCancellation()
            let path = file.path.hasPrefix(root) ? String(file.path.dropFirst(root.count)) : file.lastPathComponent
            do {
                let sidecars = companions[PlayStationInspector.Companions.key(for: file)] ?? .init()
                let report = try PlayStationInspector.inspect(file, companions: sidecars)
                if ["CUE", "CCD"].contains(report.format) {
                    backing.formUnion(report.tracks.map { $0.file.standardizedFileURL })
                }
                var hashes: [Int: String] = [:]
                var notes = report.warnings
                if dat?.containsLayout(report.tracks) == true {
                    do {
                        for track in report.tracks { hashes[track.id] = try PlayStationInspector.sha1(track) }
                    } catch is CancellationError {
                        throw CancellationError()
                    } catch {
                        notes.append("Could not compare track SHA-1: \(error.localizedDescription)")
                    }
                }
                let assessment = assess(report, gameDB: gameDB, dat: dat, hashes: hashes)
                return BatchRecord(path: path, format: report.format, serial: report.serial, region: report.region,
                    bootVerified: report.bootValid, tracks: report.tracks.count, notes: notes,
                    catalogTitle: assessment.title, catalogMatch: assessment.match,
                    libCrypt: assessment.libCrypt, sbi: assessment.sbi)
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                return BatchRecord(path: path, format: file.pathExtension.uppercased(), serial: nil, region: "Unknown",
                    bootVerified: false, tracks: 0, notes: [error.localizedDescription])
            }
        }
        let descriptorReports = try descriptors.map(inspect)
        let rawReports = try loose.filter { !backing.contains($0.standardizedFileURL) }.map(inspect)
        return (descriptorReports + rawReports).sorted { $0.path.localizedStandardCompare($1.path) == .orderedAscending }
    }
}
