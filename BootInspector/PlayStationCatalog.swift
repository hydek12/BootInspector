import Foundation

nonisolated struct PlayStationCatalog: Sendable {
    struct Disc: Sendable {
        let title: String
        let libCrypt: Bool
    }

    struct TrackKey: Hashable, Sendable {
        let size: Int
        let sha1: String
    }

    let name: String
    let discs: [String: Disc]
    let releases: [[TrackKey]: [String]]
    private let trackSizes: Set<[Int]>

    init(url: URL) throws {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        let limit = 32 * 1024 * 1024
        guard try file.seekToEnd() <= limit else {
            throw PlayStationInspector.InspectionError("The disc catalog exceeds 32 MiB.")
        }
        try file.seek(toOffset: 0)
        let data = try file.read(upToCount: limit + 1) ?? Data()
        guard data.count <= limit else {
            throw PlayStationInspector.InspectionError("The disc catalog exceeds 32 MiB.")
        }
        name = url.lastPathComponent
        if ["yaml", "yml"].contains(url.pathExtension.lowercased()) {
            discs = Self.readDuckStation(String(decoding: data, as: UTF8.self))
            releases = [:]
        } else {
            discs = [:]
            releases = try LogiqxReader.read(data)
        }
        trackSizes = Set(releases.keys.map { $0.map(\.size) })
        guard !discs.isEmpty || !releases.isEmpty else {
            throw PlayStationInspector.InspectionError("No supported entries in this DuckStation GameDB or Logiqx XML catalog.")
        }
    }

    private static func serial(_ value: String) -> String? {
        let code = value.trimmingCharacters(in: .whitespaces)
        guard code.utf8.count == 10, code.range(of: #"^[A-Z]{4}-[0-9]{5}$"#, options: .regularExpression) != nil else { return nil }
        return code
    }

    // Read the fields emitted by DuckStation's generated GameDB. Nested
    // metadata and compatibility settings are intentionally ignored.
    private static func readDuckStation(_ text: String) -> [String: Disc] {
        var result: [String: Disc] = [:]
        var aliases: [String: Disc] = [:]
        var primary: String?
        var title: String?
        var libCrypt = false
        var codes: [String] = []
        var readingCodes = false

        func finishEntry() {
            guard let primary, let title else { return }
            let disc = Disc(title: title, libCrypt: libCrypt)
            result[primary] = disc
            for code in codes {
                if let previous = aliases[code] {
                    aliases[code] = Disc(title: previous.title, libCrypt: previous.libCrypt || libCrypt)
                } else {
                    aliases[code] = disc
                }
            }
        }
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = String(rawLine)
            if !line.hasPrefix(" "), line.hasSuffix(":") {
                finishEntry()
                primary = serial(String(line.dropLast()))
                title = nil
                libCrypt = false
                codes.removeAll(keepingCapacity: true)
                readingCodes = false
            } else if line.hasPrefix("    - "), readingCodes {
                if let code = serial(String(line.dropFirst(6))) { codes.append(code) }
            } else if line.hasPrefix("  "), !line.hasPrefix("   ") {
                readingCodes = line == "  codes:"
                if line == "  libcrypt: true" { libCrypt = true }
                if line.hasPrefix("  name: "),
                   let decoded = try? JSONDecoder().decode(String.self, from: Data(line.dropFirst(8).utf8)) {
                    title = decoded
                }
            }
        }
        finishEntry()
        return result.merging(aliases, uniquingKeysWith: { primary, alias in
            Disc(title: primary.title, libCrypt: primary.libCrypt || alias.libCrypt)
        })
    }

    func containsLayout(_ tracks: [PlayStationTrack]) -> Bool {
        guard !tracks.isEmpty else { return false }
        let sizes = tracks.compactMap(\.storedByteCount)
        return sizes.count == tracks.count && trackSizes.contains(sizes)
    }

    func match(_ tracks: [PlayStationTrack], hashes: [Int: String]) -> [String] {
        let keys = tracks.compactMap { track -> TrackKey? in
            guard let size = track.storedByteCount, let sha1 = hashes[track.id] else { return nil }
            return TrackKey(size: size, sha1: sha1)
        }
        guard !keys.isEmpty, keys.count == tracks.count else { return [] }
        return Set(releases[keys] ?? []).sorted()
    }

    private final class LogiqxReader: NSObject, XMLParserDelegate {
        var stack: [String] = []
        var name: String?
        var tracks: [TrackKey] = []
        var incomplete = false
        var releases: [[TrackKey]: [String]] = [:]

        static func read(_ data: Data) throws -> [[TrackKey]: [String]] {
            let reader = LogiqxReader()
            let parser = XMLParser(data: data)
            parser.shouldResolveExternalEntities = false
            parser.externalEntityResolvingPolicy = .never
            parser.delegate = reader
            guard parser.parse() else {
                throw PlayStationInspector.InspectionError("The Logiqx XML catalog could not be parsed.")
            }
            return reader.releases
        }

        func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                    qualifiedName: String?, attributes: [String: String]) {
            stack.append(elementName)
            if stack.count == 2, stack[0] == "datafile", ["game", "machine"].contains(elementName) {
                name = attributes["name"]
                tracks = []
                incomplete = false
            }
            guard stack.count == 3, name != nil else { return }
            if elementName == "disk" { incomplete = true }
            guard elementName == "rom" else { return }
            guard let sha1 = attributes["sha1"]?.lowercased(), sha1.utf8.count == 40,
                  sha1.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                  let size = attributes["size"].flatMap(Int.init), size > 0 else {
                incomplete = true
                return
            }
            tracks.append(TrackKey(size: size, sha1: sha1))
        }

        func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName: String?) {
            if stack.count == 2, let name, !incomplete, !tracks.isEmpty {
                releases[tracks, default: []].append(name)
            }
            if stack.count == 2 { name = nil }
            stack.removeLast()
        }
    }
}
