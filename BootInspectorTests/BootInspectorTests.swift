import Foundation
import Testing
@testable import BootInspector

@MainActor
struct BootInspectorTests {
    @Test func binaryReadersRejectInvalidRanges() {
        let bytes = Data([0x12, 0x34, 0x56, 0x78])
        #expect(bytes.readUInt16BE(at: 1) == 0x3456)
        #expect(bytes.readUInt32BE(at: 0) == 0x12345678)
        #expect(bytes.readUInt16BE(at: -1) == nil)
        #expect(bytes.readUInt32BE(at: .max) == nil)
        #expect(bytes.readASCII(at: 0, length: -1) == "")
        #expect(bytes.readASCII(at: 1, length: .max) == "")
        #expect(Data(" TEST\0ignored".utf8).readASCII(at: 0, length: 13) == "TEST")
    }

    @Test func detectsBlessedClassicHFS() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let report = try DiskImageInspector.inspect(url: fixture.write("classic.img", DiscFixture.macImage()))
        #expect(report.hasDriverDescriptorMap)
        #expect(report.blockSize == 512)
        #expect(report.apmBlockStride == 512)
        #expect(report.partitions.first?.blessedFolderID == 42)
        #expect(report.partitions.first?.byteOffset == 4096)
        #expect(report.isBootablePPC)
        #expect(report.suggestedOpenBIOSCommand?.hasPrefix("boot cd:1,") == true)
    }

    @Test func readsHFSPlusAndHFSXOnOpticalMedia() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        for signature in [UInt64(0x482B), UInt64(0x4858)] {
            let bytes = DiscFixture.macImage(stride: 2048, signature: signature, blessedID: 93)
            let report = try DiskImageInspector.inspect(url: fixture.write("optical.toast", bytes))
            #expect(report.apmBlockStride == 2048)
            #expect(report.partitions.first?.blessedFolderID == 93)
            #expect(report.isBootablePPC)
        }
    }

    @Test func rejectsUnblessedAndTruncatedPartitions() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let unblessed = try fixture.write("unblessed.img", DiscFixture.macImage(blessedID: 0))
        let truncated = try fixture.write("truncated.img", DiscFixture.macImage(start: 1000))
        let unknown = try fixture.write("unknown.img", DiscFixture.macImage(signature: 0))
        for source in [unblessed, truncated, unknown] {
            let report = try DiskImageInspector.inspect(url: source)
            #expect(!report.isBootablePPC)
            #expect(report.suggestedOpenBIOSCommand == nil)
        }
        let report = try DiskImageInspector.inspect(url: truncated)
        #expect(report.partitions.first?.hfsStatus == "Partition truncated past EOF")
    }

    @Test func handlesZeroEntryPartitionMap() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let image = try fixture.write("empty-map.img", DiscFixture.macImage(entries: 0))
        let report = try DiskImageInspector.inspect(url: image)
        #expect(report.hasApplePartitionMap)
        #expect(report.partitions.isEmpty)
        #expect(!report.isBootablePPC)
    }

    @Test func distinguishesISOOnlyAndEmptyImages() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let iso = try DiskImageInspector.inspect(url: fixture.write("pc.iso", DiscFixture.playStationISO()))
        #expect(iso.hasISO9660)
        #expect(iso.isoVolumeID == "BOOTINSPECTOR TEST")
        #expect(!iso.hasApplePartitionMap)
        #expect(!iso.isBootablePPC)
        let empty = try DiskImageInspector.inspect(url: fixture.write("empty.img", Data()))
        #expect(empty.fileSize == 0)
        #expect(!empty.hasISO9660)
        #expect(!empty.isBootablePPC)
    }
}
