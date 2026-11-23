import Foundation

nonisolated enum DiscImageType: Equatable, Sendable {
    case folder
    case mac
    case iso9660
    case playStation(String)
    case unknown

    static let descriptors: Set<String> = ["cue", "ccd", "m3u", "m3u8", "toc", "gdi", "nrg",
                                          "pbp", "mds", "cso", "zso", "isz", "dax"]
    static let signatureRequired: Set<String> = ["ecm", "cso", "zso", "pbp"]
    private static let rawExtensions: Set<String> = ["bin", "img", "mdf", "raw", "2352", "2448"]

    static func detect(_ url: URL, requireContainerSignature: Bool = false) throws -> Self {
        let scope = url.startAccessingSecurityScopedResource()
        defer { if scope { url.stopAccessingSecurityScopedResource() } }
        if try url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory == true { return .folder }
        let suffix = url.pathExtension.lowercased()
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        let prefix = try file.read(upToCount: 16) ?? Data()

        if prefix.starts(with: "MComprHD".utf8) { return .playStation("chd") }
        if prefix.starts(with: [0x45, 0x43, 0x4D, 0]) { return .playStation("ecm") }
        if prefix.starts(with: [0, 0x50, 0x42, 0x50]) { return .playStation("pbp") }
        if prefix.starts(with: "CISO".utf8) { return .playStation("cso") }
        if prefix.starts(with: "ZISO".utf8) { return .playStation("zso") }
        if requireContainerSignature && signatureRequired.contains(suffix) { return .unknown }
        let bytes = prefix + (try file.read(upToCount: 42_000 - prefix.count) ?? Data())

        func matches(_ signature: String, at offset: Int) -> Bool {
            let end = offset + signature.utf8.count
            return end <= bytes.count && bytes[offset..<end].elementsEqual(signature.utf8)
        }
        let apm = [512, 2048].contains { matches("PM", at: $0) }
        if apm || (matches("ER", at: 0) && [512, 2048].contains(Int(bytes.readUInt16BE(at: 2) ?? 0))) {
            return .mac
        }
        let cookedISO = matches("CD001", at: 16 * 2048 + 1)
        let rawISO = [(2352, 16), (2352, 24), (2448, 16), (2448, 24), (2336, 8)]
            .contains { matches("CD001", at: 16 * $0.0 + $0.1 + 1) }
        if cookedISO || rawISO,
           let report = try? PlayStationInspector.inspect(url, chdLibrary: nil, companions: .init(), detectedFormat: "iso") {
            if report.bootPath != nil || !report.regions.isEmpty { return .playStation(cookedISO ? "iso" : "bin") }
            return .iso9660
        }
        if matches("[CloneCD]", at: 0) { return .playStation("ccd") }
        if matches("#EXTM3U", at: 0) { return .playStation("m3u") }
        if descriptors.contains(suffix) || rawExtensions.contains(suffix) && suffix != "img" ||
            ["chd", "ecm"].contains(suffix) { return .playStation(suffix) }
        if matches("BD", at: 1024) || matches("H+", at: 1024) || matches("HX", at: 1024) ||
            ["toast", "cdr", "dmg"].contains(suffix) { return .mac }
        return .unknown
    }
}
