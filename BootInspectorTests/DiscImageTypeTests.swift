import Foundation
import Testing
@testable import BootInspector

struct DiscImageTypeTests {
    @Test func detectsByContentWhenNamesAreAmbiguous() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let ps = DiscFixture.playStationISO()
        let mac = try fixture.write("mac.bin", DiscFixture.macImage())
        let cooked = try fixture.write("playstation.img", ps)
        let raw = try fixture.write("playstation.raw", DiscFixture.raw(ps, stride: 2448))
        let generic = try fixture.write("install.iso", DiscFixture.playStationISO(license: "", includeExecutable: false, config: false))
        let renamedCHD = try fixture.write("container.iso", DiscFixture.chd(iso: ps))
        let renamedECM = try fixture.write("packed.bin", DiscFixture.ecm(DiscFixture.raw(ps)))
        let invalid = try fixture.write("notes.txt", "test")
        #expect(try DiscImageType.detect(mac) == .mac)
        #expect(try DiscImageType.detect(cooked) == .playStation("iso"))
        #expect(try DiscImageType.detect(raw) == .playStation("bin"))
        #expect(try DiscImageType.detect(generic) == .iso9660)
        #expect(try DiscImageType.detect(renamedCHD) == .playStation("chd"))
        #expect(try DiscImageType.detect(renamedECM) == .playStation("ecm"))
        #expect(try DiscImageType.detect(invalid) == .unknown)
        #expect(try DiscImageType.detect(fixture.folder) == .folder)
    }

    @Test func scansMixedFolderAndMultipleInputsWithoutDuplicatingBackingFiles() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let child = fixture.folder.appendingPathComponent("nested", isDirectory: true)
        try FileManager.default.createDirectory(at: child, withIntermediateDirectories: false)
        let raw = child.appendingPathComponent("disc.bin")
        try DiscFixture.raw(DiscFixture.playStationISO()).write(to: raw)
        let cue = child.appendingPathComponent("disc.cue")
        try DiscFixture.cue(file: "disc.bin").write(to: cue, atomically: true, encoding: .utf8)
        let mac = try fixture.write("installer.toast", DiscFixture.macImage())
        let generic = try fixture.write("data.iso", DiscFixture.playStationISO(license: "", includeExecutable: false, config: false))
        _ = try fixture.write("notes.txt", "ignore")
        _ = try fixture.write("shader.cso", "DXBC")
        _ = try fixture.write("lighting.ecm", "unrelated cache")
        let folderRows = try PlayStationTools.scanSelection([fixture.folder])
        #expect(Set(folderRows.map(\.format)) == ["ISO 9660", "Mac OS", "CUE"])
        #expect(folderRows.first { $0.format == "CUE" }?.path == "nested/disc.cue")
        #expect(folderRows.filter(\.bootVerified).count == 2)
        let selectionRows = try PlayStationTools.scanSelection([raw, cue, mac, raw, generic])
        #expect(selectionRows.count == 3)
        #expect(Set(selectionRows.map(\.format)) == ["ISO 9660", "Mac OS", "CUE"])
    }
    @Test func scanEntriesRetainTheSourceAndFolderGrant() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let child = fixture.folder.appendingPathComponent("nested", isDirectory: true)
        try FileManager.default.createDirectory(at: child, withIntermediateDirectories: false)
        let image = child.appendingPathComponent("disc.iso")
        try DiscFixture.playStationISO().write(to: image)

        let scanned = try PlayStationTools.scanEntries([fixture.folder, image])
        let row = try #require(scanned.first)
        #expect(scanned.count == 1)
        #expect(row.file.resolvingSymlinksInPath() == image.resolvingSymlinksInPath())
        #expect(row.accessFolder == fixture.folder)
        #expect(try PlayStationInspector.inspect(row.file).bootValid)
    }

    @Test func folderAndCueBinDropOpenTheVerifiedCueFirst() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let raw = try fixture.write("Game (Track 01).bin", DiscFixture.raw(DiscFixture.playStationISO()))
        let cue = try fixture.write("Game.cue", DiscFixture.cue(file: raw.lastPathComponent))
        let unverified = try fixture.write("A Unverified.iso", Data())

        for selection in [[raw, cue], [fixture.folder], [unverified, raw, cue]] {
            let entries = try PlayStationTools.scanEntries(selection)
            let initial = try #require(PlayStationTools.initialScanEntry(entries))
            #expect(initial.file.resolvingSymlinksInPath() == cue.resolvingSymlinksInPath())
            #expect(initial.record.serial == "SLES-12345")
            #expect(initial.record.bootVerified)
            #expect(!entries.contains { $0.file.lastPathComponent == raw.lastPathComponent })
        }

        let invalidOnly = try PlayStationTools.scanEntries([unverified])
        #expect(PlayStationTools.initialScanEntry(invalidOnly)?.file == unverified)
        #expect(PlayStationTools.initialScanEntry([]) == nil)
    }

    @Test func openingOneBINFindsItsCueWithoutUsingAnUnrelatedNamesake() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let raw = try fixture.write("Disc.bin", DiscFixture.raw(DiscFixture.playStationISO()))
        _ = try fixture.write("Disc.cue", DiscFixture.cue(file: "Other.bin"))
        let correct = try fixture.write("Multi Track.cue", DiscFixture.cue(file: raw.lastPathComponent))
        #expect(PlayStationInspector.preferredCue(for: raw)?.resolvingSymlinksInPath() == correct.resolvingSymlinksInPath())

        _ = try fixture.write("Also References Disc.cue", DiscFixture.cue(file: raw.lastPathComponent))
        #expect(PlayStationInspector.preferredCue(for: raw) == nil)
    }

}
