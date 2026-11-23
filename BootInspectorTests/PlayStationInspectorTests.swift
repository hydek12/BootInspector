import CryptoKit
import Foundation
import Testing
@testable import BootInspector

struct PlayStationInspectorTests {
    @Test func readsCookedAndRawSectorLayouts() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let iso = DiscFixture.playStationISO()
        let inputs: [(Data, Int)] = [(iso, 2048), (DiscFixture.raw(iso, offset: 16), 2352),
                                     (DiscFixture.raw(iso), 2352), (DiscFixture.raw(iso, stride: 2448), 2448),
                                     (DiscFixture.raw(iso, stride: 2336, offset: 8), 2336)]
        for (data, stride) in inputs {
            let report = try PlayStationInspector.inspect(fixture.write("game.iso", data))
            #expect(report.bootValid)
            #expect(report.serial == "SLES-12345")
            #expect(report.region == "Europe / PAL")
            #expect(report.bios.contains("SCPH-5502"))
            #expect(report.volume == "BOOTINSPECTOR TEST")
            #expect(report.tracks.first?.sectorBytes == stride)
            #expect(report.bootDetails?.contains("0x80010000") == true)
        }
    }

    @Test func reportsRegionConflictsAndInvalidExecutables() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let mixed = try fixture.write("mixed.iso", DiscFixture.playStationISO(bootName: "SLUS_123.45"))
        let report = try PlayStationInspector.inspect(mixed)
        #expect(report.bootValid)
        #expect(report.region == "Conflicting evidence")
        #expect(report.regions["Boot serial"] == "North America / NTSC-U/C")
        for invalid in [DiscFixture.playStationISO(includeExecutable: false), DiscFixture.playStationISO(declaredPayload: 1)] {
            let broken = try PlayStationInspector.inspect(fixture.write("invalid.iso", invalid))
            #expect(!broken.bootValid)
            #expect(broken.serial == "SLES-12345")
        }
    }

    @Test func findsDefaultExecutableWithoutConfiguration() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let source = try fixture.write("default.iso", DiscFixture.playStationISO(config: false))
        let report = try PlayStationInspector.inspect(source)
        #expect(report.bootValid)
        #expect(report.bootPath == "PSX.EXE")
        #expect(report.serial == nil)
    }

    @Test func measuresSharedCueTracksAndStoredPregap() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        var image = DiscFixture.raw(DiscFixture.playStationISO())
        image.append(Data(repeating: 0, count: 4 * 2352))
        _ = try fixture.write("data and audio.bin", image)
        let text = DiscFixture.cue(file: "data and audio.bin") + """
          TRACK 02 AUDIO
            INDEX 00 00:00:24
            INDEX 01 00:00:25
        """
        let report = try PlayStationInspector.inspect(fixture.write("game.cue", text))
        #expect(report.bootValid)
        #expect(report.tracks.map(\.frames) == [24, 3])
        #expect(report.tracks.map(\.start) == [0, 25])
        #expect(report.tracks.last?.storedPregap == 1)
        let audio = try #require(report.tracks.last)
        #expect(audio.storedByteCount == 4 * 2352)
        #expect(try PlayStationInspector.sha1(audio) == "8dcf92652a0c30f281de21deee83f04078f5758d")
    }

    @Test func rejectsMalformedDescriptorsAndUnsupportedImages() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let invalid = try fixture.write("invalid.cue", DiscFixture.cue(file: "missing.bin").replacingOccurrences(of: "00:00:00", with: "00:00:75"))
        let raw = try fixture.write("empty.iso", Data())
        let mds = try fixture.write("disc.mds", Data())
        for url in [invalid, raw, mds] {
            #expect(throws: PlayStationInspector.InspectionError.self) { try PlayStationInspector.inspect(url) }
        }
        let missing = try PlayStationInspector.inspect(fixture.write("missing.cue", DiscFixture.cue(file: "missing.bin")))
        #expect(!missing.bootValid)
        #expect(missing.warnings.contains { $0.contains("Missing or unreadable track file") })
    }

    @Test func readsCloneCDAndRejectsScrambledData() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        _ = try fixture.write("disc.img", DiscFixture.raw(DiscFixture.playStationISO()))
        _ = try fixture.write("disc.sub", Data([0]))
        let ccd = "[Disc]\nDataTracksScrambled=0\n[TRACK 1]\nMODE=2\nINDEX 1=0\n"
        let report = try PlayStationInspector.inspect(fixture.write("disc.ccd", ccd))
        #expect(report.bootValid)
        #expect(report.hasSUB)
        let scrambled = try fixture.write("disc.ccd", ccd.replacingOccurrences(of: "Scrambled=0", with: "Scrambled=1"))
        #expect(throws: PlayStationInspector.InspectionError.self) { try PlayStationInspector.inspect(scrambled) }
    }

    @Test func opensLocalPlaylistMembersAndIgnoresRemoteURLs() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        _ = try fixture.write("Disc 1.iso", DiscFixture.playStationISO())
        let playlist = try fixture.write("game.m3u8", "#EXTM3U\nDisc 1.iso\nhttps://example.invalid/disc.iso\nMissing.bin\n")
        let report = try PlayStationInspector.inspect(playlist)
        #expect(report.members.map(\.lastPathComponent) == ["Disc 1.iso", "Missing.bin"])
        #expect(report.warnings.count == 1)
        #expect(report.warnings.first?.contains("Missing.bin") == true)
    }

    @Test func readsCHDMetadataAndRejectsCyclicChains() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let iso = DiscFixture.playStationISO()
        let report = try PlayStationInspector.inspect(fixture.write("disc.chd", DiscFixture.chd(iso: iso)), chdLibrary: nil)
        #expect(report.tracks.first?.frames == 24)
        #expect(report.tracks.first?.type == "MODE2/2352")
        #expect(report.embeddedSubchannel)
        #expect(report.canUseCHDTool)
        let cyclic = try fixture.write("cyclic.chd", DiscFixture.chd(iso: iso, cyclic: true))
        #expect(throws: PlayStationInspector.InspectionError.self) { try PlayStationInspector.inspect(cyclic, chdLibrary: nil) }
    }

    @Test(.enabled(if: nativeCHDLibrary != nil, "Requires bundled libchdr or BOOTINSPECTOR_TEST_LIBCHDR"))
    func readsNativeCHDBootData() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let source = try fixture.write("disc.chd", DiscFixture.chd(iso: DiscFixture.playStationISO()))
        let report = try PlayStationInspector.inspect(source, chdLibrary: nativeCHDLibrary)
        #expect(report.bootValid)
        #expect(report.serial == "SLES-12345")
        #expect(report.volume == "BOOTINSPECTOR TEST")
        #expect(!report.canUseCHDTool)
        let raw = DiscFixture.raw(DiscFixture.playStationISO())
        let expected = Insecure.SHA1.hash(data: raw).map { String(format: "%02x", $0) }.joined()
        #expect(report.tracks.first?.storedByteCount == raw.count)
        #expect(try PlayStationInspector.trackHashes(report) == [1: expected])
    }
}

private nonisolated var nativeCHDLibrary: URL? {
    let explicit = ProcessInfo.processInfo.environment["BOOTINSPECTOR_TEST_LIBCHDR"].map { URL(fileURLWithPath: $0) }
    let bundled = Bundle.main.privateFrameworksURL?.appendingPathComponent("libchdr.dylib")
    return [explicit, bundled].compactMap { $0 }.first { FileManager.default.fileExists(atPath: $0.path) }
}
