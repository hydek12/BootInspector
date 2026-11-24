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
    @Test func distinguishesMissingStaleAndIncompleteBootMetadata() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        let candidate = MacBootCatalog.Folder(id: 42, name: "System Folder")
        let cases: [(Data, MacBootCatalog.Finding)] = [
            (DiscFixture.macImage(blessedID: 0), .missingBlessing([candidate])),
            (DiscFixture.macImage(blessedID: 99, systemFolderID: 42), .staleBlessing([candidate])),
            (DiscFixture.macImage(bootFile: false), .noSupportedSystemFolder)
        ]
        for (index, sample) in cases.enumerated() {
            let report = try DiskImageInspector.inspect(url: fixture.write("case-\(index).img", sample.0))
            #expect(report.partitions.first?.bootFinding == sample.1)
            #expect(!report.isBootablePPC)
        }
    }

    @Test func leavesHeaderOnlyAndCyclicCatalogsUnverified() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        for (index, bytes) in [DiscFixture.macImage(catalog: false), DiscFixture.macImage(cyclic: true)].enumerated() {
            let report = try DiskImageInspector.inspect(url: fixture.write("invalid-\(index).img", bytes))
            #expect(report.partitions.first?.blessedFolderID == 42)
            #expect(!report.isBootablePPC)
            guard case .unavailable = report.partitions.first?.bootFinding else {
                Issue.record("Expected catalog validation to be unavailable")
                continue
            }
        }
    }

    @Test func resolvesTheCatalogInsideAnHFSWrapper() throws {
        let fixture = try DiscFixture()
        defer { fixture.remove() }
        var bytes = DiscFixture.macImage(signature: 0x482B, blessedID: 75)
        let start = 8 * 512
        let embeddedStart = start + 4 * 512
        let size = 12 * 512
        let innerVolume = Data(bytes[start..<(start + size)])
        bytes.replaceSubrange(embeddedStart..<(embeddedStart + size), with: innerVolume)
        DiscFixture.put(20, in: &bytes, at: 512 + 12, count: 4)
        let wrapper = start + 1024
        bytes.replaceSubrange(wrapper..<(wrapper + 512), with: Data(repeating: 0, count: 512))
        DiscFixture.put(0x4244, in: &bytes, at: wrapper, count: 2)
        DiscFixture.put(512, in: &bytes, at: wrapper + 20, count: 4)
        DiscFixture.put(0x482B, in: &bytes, at: wrapper + 124, count: 2)
        DiscFixture.put(4, in: &bytes, at: wrapper + 126, count: 2)
        DiscFixture.put(12, in: &bytes, at: wrapper + 128, count: 2)
        let report = try DiskImageInspector.inspect(url: fixture.write("wrapped.toast", bytes))
        #expect(report.partitions.first?.bootFinding == .verified(.init(id: 75, name: "System Folder")))
        #expect(report.partitions.first?.hfsStatus?.contains("HFS wrapper") == true)
    }

}
