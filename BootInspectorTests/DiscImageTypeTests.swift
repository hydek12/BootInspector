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
}
