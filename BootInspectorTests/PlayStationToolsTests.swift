import Foundation
import Testing
@testable import BootInspector

struct PlayStationToolsTests {
    @Test func repairsCueInMemoryAndPreservesOriginal() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let original = DiscFixture.cue(file: "missing.bin").replacingOccurrences(of: "\n", with: "\r\n")
        let cue = try fixture.write("disc.cue", original)
        let replacement = try fixture.write("new track.bin", DiscFixture.raw(DiscFixture.playStationISO()))
        let preview = try PlayStationTools.previewCueRepair(cue, with: replacement, folder: fixture.folder)
        #expect(preview.originalName == "missing.bin")
        #expect(preview.replacementName == "new track.bin")
        #expect(preview.serial == "SLES-12345")
        #expect(try String(contentsOf: cue, encoding: .utf8) == original)
        #expect(preview.data == Data(original.replacingOccurrences(of: "missing.bin", with: "new track.bin").utf8))
        let repaired = try fixture.write("repaired.cue", preview.data)
        #expect(try PlayStationInspector.inspect(repaired).bootValid)
    }

    @Test func rejectsShortReplacementAndCompleteCue() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let cue = try fixture.write("disc.cue", DiscFixture.cue(file: "missing.bin"))
        let short = try fixture.write("replace.bin", Data([0]))
        #expect(throws: PlayStationInspector.InspectionError.self) {
            try PlayStationTools.previewCueRepair(cue, with: short, folder: fixture.folder)
        }
        let raw = DiscFixture.raw(DiscFixture.playStationISO())
        _ = try fixture.write("missing.bin", raw)
        let replacement = try fixture.write("replace.bin", raw)
        #expect(throws: PlayStationInspector.InspectionError.self) {
            try PlayStationTools.previewCueRepair(cue, with: replacement, folder: fixture.folder)
        }
    }

    @Test func groupsBatchTracksAndRetainsPerDiscErrors() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        _ = try fixture.write("game.bin", DiscFixture.raw(DiscFixture.playStationISO()))
        _ = try fixture.write("game.cue", DiscFixture.cue(file: "game.bin"))
        _ = try fixture.write("broken.iso", Data())
        let batch = try PlayStationTools.scanLibrary(fixture.folder)
        #expect(batch.map(\.path) == ["broken.iso", "game.cue"])
        #expect(batch.map(\.bootVerified) == [false, true])
        #expect(batch.last?.serial == "SLES-12345")
        #expect(batch.first?.notes.isEmpty == false)
        let exported = try JSONEncoder().encode(batch)
        let decoded = try JSONDecoder().decode([PlayStationTools.BatchRecord].self, from: exported)
        #expect(decoded.map(\.path) == batch.map(\.path))
    }

    @Test func quotesCSVAndEscapesSpreadsheetFormulas() {
        let record = PlayStationTools.BatchRecord(path: "=1+1.bin", format: "RAW", serial: nil,
                                                 region: "Unknown", bootVerified: false, tracks: 1, notes: ["a,\"b\"", "line two"])
        let csv = PlayStationTools.batchCSV([record])
        #expect(csv.hasPrefix("path,format,serial,region,boot_verified,tracks,notes,"))
        #expect(csv.contains("\"'=1+1.bin\""))
        #expect(csv.contains("\"a,\"\"b\"\"\nline two\""))
        #expect(csv.hasSuffix("\r\n"))
    }

    @Test func biosScanSkipsUnknownAndWrongSizedFiles() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        _ = try fixture.write("unknown.bin", Data(repeating: 0, count: 524_288))
        _ = try fixture.write("short.bin", Data([0]))
        #expect(try PlayStationTools.scanBIOS(in: fixture.folder).isEmpty)
    }
}
