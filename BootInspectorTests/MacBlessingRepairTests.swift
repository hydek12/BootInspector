import Foundation
import Testing
@testable import BootInspector

struct MacBlessingRepairTests {
    @Test func savesVerifiedCopyAndOnlyChangesTheTwoHeaderFieldsAndWriteCounts() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let original = Self.image()
        let source = try fixture.write("source.toast", original)
        let target = fixture.folder.appendingPathComponent("repaired.toast")
        let plan = try MacBlessingRepair.preview(source, partitionID: 1, folderID: 42)
        #expect(plan.currentID == 0)
        #expect(plan.folder.id == 42)
        try MacBlessingRepair.saveCopy(of: source, to: target, plan: plan)
        #expect(try Data(contentsOf: source) == original)
        var expected = original
        for offset in [Self.primary, Self.alternate] {
            DiscFixture.put(8, in: &expected, at: offset + 68, count: 4)
            DiscFixture.put(42, in: &expected, at: offset + 80, count: 4)
            DiscFixture.put(42, in: &expected, at: offset + 92, count: 4)
        }
        #expect(try Data(contentsOf: target) == expected)
        #expect(try DiskImageInspector.inspect(url: target).isBootablePPC)

        #expect(throws: MacBlessingRepair.RepairError.self) {
            try MacBlessingRepair.saveCopy(of: source, to: target, plan: plan)
        }
        #expect(try Data(contentsOf: target) == expected)
    }

    @Test func rejectsInvalidForksAndDisagreeingHeaders() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let invalidFork = try fixture.write("invalid.toast", Self.image(validBoot: false))
        #expect(throws: MacBlessingRepair.RepairError.self) {
            try MacBlessingRepair.preview(invalidFork, partitionID: 1, folderID: 42)
        }
        var bytes = Self.image()
        bytes[Self.alternate + 95] ^= 1
        let disagreement = try fixture.write("disagreement.toast", bytes)
        #expect(throws: MacBlessingRepair.RepairError.self) {
            try MacBlessingRepair.preview(disagreement, partitionID: 1, folderID: 42)
        }
    }

    @Test func keepsJournaledAndMacOSXVolumesOutsideRepairScope() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        for (name, field, value) in [("journaled", 4, UInt64(0x2100)), ("osx", 100, UInt64(89))] {
            var bytes = Self.image()
            for offset in [Self.primary, Self.alternate] {
                DiscFixture.put(value, in: &bytes, at: offset + field, count: 4)
            }
            let source = try fixture.write(name + ".toast", bytes)
            #expect(throws: MacBlessingRepair.RepairError.self) {
                try MacBlessingRepair.preview(source, partitionID: 1, folderID: 42)
            }
        }
    }

    @Test func skipsPublishingIfSourceChangedAfterPreview() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        var bytes = Self.image()
        let source = try fixture.write("change.toast", bytes)
        let plan = try MacBlessingRepair.preview(source, partitionID: 1, folderID: 42)
        for offset in [Self.primary, Self.alternate] {
            DiscFixture.put(9, in: &bytes, at: offset + 68, count: 4)
        }
        try bytes.write(to: source)
        let target = fixture.folder.appendingPathComponent("repaired.toast")
        #expect(throws: MacBlessingRepair.RepairError.self) {
            try MacBlessingRepair.saveCopy(of: source, to: target, plan: plan)
        }
        #expect(!FileManager.default.fileExists(atPath: target.path))
        #expect(try Data(contentsOf: source) == bytes)
    }

    private static let base = 8 * 512
    private static let primary = base + 1024
    private static let alternate = base + 24 * 512 - 1024

    private static func image(validBoot: Bool = true) -> Data {
        var bytes = DiscFixture.macImage(signature: 0x482B, blessedID: 0)
        DiscFixture.put(24, in: &bytes, at: 512 + 12, count: 4)
        DiscFixture.put(4, in: &bytes, at: primary + 2, count: 2)
        DiscFixture.put(0x100, in: &bytes, at: primary + 4, count: 4)
        DiscFixture.put(24, in: &bytes, at: primary + 44, count: 4)
        DiscFixture.put(7, in: &bytes, at: primary + 68, count: 4)
        let header = Data(bytes[primary..<(primary + 512)])
        bytes.replaceSubrange(alternate..<(alternate + 512), with: header)
        let leaf = primary + 512 + 1024
        for (record, block, forkField) in [(1, 8, 168), (2, 9, 168), (3, 10, 88)] {
            let start = leaf + Int(bytes.readUInt16BE(at: leaf + 1024 - (record + 1) * 2)!)
            let value = start + (Int(bytes.readUInt16BE(at: start)!) + 3) / 2 * 2
            let fork = value + forkField
            DiscFixture.put(512, in: &bytes, at: fork, count: 8)
            DiscFixture.put(1, in: &bytes, at: fork + 12, count: 4)
            DiscFixture.put(UInt64(block), in: &bytes, at: fork + 16, count: 4)
            DiscFixture.put(1, in: &bytes, at: fork + 20, count: 4)
            let payload = base + block * 512
            if record != 3 {
                DiscFixture.put(256, in: &bytes, at: payload, count: 4)
                DiscFixture.put(300, in: &bytes, at: payload + 4, count: 4)
                DiscFixture.put(16, in: &bytes, at: payload + 8, count: 4)
                DiscFixture.put(28, in: &bytes, at: payload + 12, count: 4)
            } else if validBoot {
                DiscFixture.put("<CHRP-BOOT>", in: &bytes, at: payload)
            }
        }
        return bytes
    }
}
