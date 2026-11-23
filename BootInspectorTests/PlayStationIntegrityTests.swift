import Foundation
import Testing
@testable import BootInspector

struct PlayStationIntegrityTests {
    @Test func decodesECMAndInspectsBootData() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let raw = DiscFixture.raw(DiscFixture.playStationISO())
        let source = try fixture.write("game.ecm", DiscFixture.ecm(raw))
        let destination = fixture.folder.appendingPathComponent("decoded.bin")
        try PlayStationECM.decode(source, to: destination)
        #expect(try Data(contentsOf: destination) == raw)
        let report = try PlayStationInspector.inspect(source)
        #expect(report.bootValid)
        #expect(report.serial == "SLES-12345")
        #expect(report.warnings.contains { $0.contains("checksum verified") })
    }

    @Test func decodesAllCompactECMRecordTypes() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        for (type, size) in [(1, 2051), (2, 2052), (3, 2328)] {
            var compact = Data(repeating: 0x35, count: size)
            if type == 2 { compact[2] = 0x08 }
            if type == 3 { compact[2] = 0x28 }
            let expected = CDSectorIntegrity.reconstruct(compact, type: type)
            #expect(expected.count == (type == 1 ? 2352 : 2336))
            let input = try fixture.write("compact-\(type).ecm", DiscFixture.ecm(expected, compact: compact, type: UInt8(type)))
            let output = fixture.folder.appendingPathComponent("compact-\(type).raw")
            try PlayStationECM.decode(input, to: output)
            #expect(try Data(contentsOf: output) == expected)
        }
    }

    @Test func distinguishesXAForm2WithoutEDCFromCheckedForm2() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        var compact = Data(repeating: 0x35, count: 2328)
        compact[2] = 0x28
        let mode1 = CDSectorIntegrity.reconstruct(Data(repeating: 0, count: 2051), type: 1)
        var form2 = Data(mode1.prefix(16))
        form2[15] = 2
        form2.append(CDSectorIntegrity.reconstruct(compact, type: 3))
        var noEDC = form2
        noEDC.replaceSubrange(2348..<2352, with: [0, 0, 0, 0])
        let source = try fixture.write("form2.bin", form2 + noEDC)
        let track = PlayStationTrack(id: 1, type: "MODE2/2352", file: source, sectorBytes: 2352, index01: 0, frames: 2)
        let summary = try CDSectorIntegrity.scan([track])
        #expect(summary.checkedEDC == 1)
        #expect(summary.edcMismatches == 0)
        #expect(summary.omittedForm2EDC == 1)
        #expect(summary.checkedECC == 0)
    }

    @Test func rejectsECMChecksumTrailingBytesAndTruncation() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let good = DiscFixture.ecm(Data([1, 2, 3]))
        var corrupt = good
        corrupt[corrupt.count - 1] ^= 1
        for (index, stream) in [corrupt, good + Data([0]), Data(good.dropLast())].enumerated() {
            let source = try fixture.write("bad-\(index).ecm", stream)
            let destination = fixture.folder.appendingPathComponent("output-\(index)")
            #expect(throws: PlayStationInspector.InspectionError.self) {
                try PlayStationECM.decode(source, to: destination)
            }
        }
    }

    @Test func verifiesRawSectorAndDetectsInjectedCorruption() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let valid = CDSectorIntegrity.reconstruct(Data(repeating: 0, count: 2051), type: 1)
        #expect(valid.count == 2352)
        var damaged = valid
        damaged[24] ^= 1
        var malformed = valid
        malformed[1] = 0
        let source = try fixture.write("raw.bin", valid + damaged + malformed)
        let track = PlayStationTrack(id: 1, type: "MODE1/2352", file: source, sectorBytes: 2352, index01: 0, start: 10, frames: 3)
        let result = try CDSectorIntegrity.scan([track])
        #expect(result.sectors == 3)
        #expect(result.checkedEDC == 2)
        #expect(result.checkedECC == 2)
        #expect(result.edcMismatches == 1)
        #expect(result.eccMismatches == 1)
        #expect(result.malformedHeaders == 1)
        #expect(result.examples.first?.contains("LBA 11") == true)
    }

    @Test func rejectsTruncatedRawTrackAndSkipsAudio() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let file = try fixture.write("short.bin", Data([0]))
        let raw = PlayStationTrack(id: 1, type: "MODE2/2352", file: file, sectorBytes: 2352, index01: 0, frames: 1)
        let audio = PlayStationTrack(id: 2, type: "AUDIO", file: file, sectorBytes: 2352, index01: 0, frames: 1)
        #expect(try CDSectorIntegrity.scan([audio]).sectors == 0)
        #expect(throws: PlayStationInspector.InspectionError.self) { try CDSectorIntegrity.scan([raw]) }
        #expect(throws: PlayStationInspector.InspectionError.self) { try PlayStationInspector.sha1(raw) }
    }
}
