import Foundation
import Testing
@testable import BootInspector

struct PlayStationCatalogTests {
    @Test func sbiValidatesRecordBoundaries() {
        let header: [UInt8] = [0x53, 0x42, 0x49, 0]
        let full: [UInt8] = [0x03, 0x04, 0x05, 1] + Array(repeating: 0, count: 10)
        let partial: [UInt8] = [0x03, 0x04, 0x06, 3, 0, 0, 0]
        #expect(PlayStationSBI.validate(Data(header + full + partial)) == .valid(2))
        #expect(PlayStationSBI.validate(Data(header + full.dropLast())) == .invalid("truncated record payload"))
        #expect(PlayStationSBI.validate(Data(header + full + full)) == .invalid("overlapping records at one sector"))
        let relative: [UInt8] = [0x03, 0x04, 0x06, 2, 0, 0, 0]
        #expect(PlayStationSBI.validate(Data(header + relative + partial)) == .valid(2))
        #expect(PlayStationSBI.validate(Data(header + [0x03, 0x04, 0x75, 1])) == .invalid("invalid BCD timestamp"))
    }

    @Test func findsMixedCaseCompanionsForSingleAndBatchInspection() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: folder) }
        let playlist = folder.appendingPathComponent("Disc.m3u")
        try "Member.bin".write(to: playlist, atomically: true, encoding: .utf8)
        let companion = folder.appendingPathComponent("Disc.SbI")
        try Data([0x53, 0x42, 0x49, 0, 3, 4, 5, 2, 0, 0, 0]).write(to: companion)

        let report = try PlayStationInspector.inspect(playlist)
        let batch = try PlayStationTools.scanLibrary(folder)
        #expect(report.sbi == .valid(1))
        #expect(batch.count == 1)
        #expect(batch.first?.sbi == report.sbi.summary)
    }

    @Test func exactMatchRequiresOrderedCompleteTrackSet() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).appendingPathExtension("xml")
        defer { try? FileManager.default.removeItem(at: file) }
        let hash1 = String(repeating: "a", count: 40)
        let hash2 = String(repeating: "b", count: 40)
        let xml = """
        <datafile>
          <game name="Test Release (Disc 1) (Rev 1)">
            <rom name="Track 01.bin" size="2352" sha1="\(hash1.uppercased())"/>
            <rom name="Track 02.bin" size="2352" sha1="\(hash2)"/>
          </game>
          <game name="Incomplete Record">
            <rom name="Track 01.bin" size="2352" sha1="\(hash1)"/>
            <rom name="Track 02.bin" size="2352"/>
          </game>
        </datafile>
        """
        try xml.write(to: file, atomically: true, encoding: .utf8)
        let catalog = try PlayStationCatalog(url: file)
        let tracks = (1...2).map {
            PlayStationTrack(id: $0, type: "MODE2/2352", file: file, sectorBytes: 2352, index01: 0, frames: 1)
        }
        #expect(catalog.match(tracks, hashes: [1: hash1, 2: hash2]) == ["Test Release (Disc 1) (Rev 1)"])
        #expect(catalog.match(tracks, hashes: [1: hash2, 2: hash1]).isEmpty)
        #expect(catalog.match(Array(tracks.prefix(1)), hashes: [1: hash1]).isEmpty)
    }
}
