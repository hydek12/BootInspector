import Foundation

nonisolated struct DiscFixture {
    let folder: URL

    init() throws {
        folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
    }

    func remove() { try? FileManager.default.removeItem(at: folder) }

    func write(_ name: String, _ data: Data) throws -> URL {
        let file = folder.appendingPathComponent(name)
        try data.write(to: file)
        return file
    }

    func write(_ name: String, _ text: String) throws -> URL {
        try write(name, Data(text.utf8))
    }

    static func put(_ value: UInt64, in data: inout Data, at offset: Int, count: Int, littleEndian: Bool = false) {
        for i in 0..<count {
            let shift = (littleEndian ? i : count - i - 1) * 8
            data[offset + i] = UInt8(truncatingIfNeeded: value >> shift)
        }
    }

    static func put(_ text: String, in data: inout Data, at offset: Int) {
        data.replaceSubrange(offset..<(offset + text.utf8.count), with: text.utf8)
    }

    static func macImage(stride: Int = 512, signature: UInt64 = 0x4244, blessedID: UInt64 = 42,
                         entries: UInt64 = 1, start: UInt64 = 8) -> Data {
        var image = Data(repeating: 0, count: 24_576)
        put(0x4552, in: &image, at: 0, count: 2)
        put(UInt64(stride), in: &image, at: 2, count: 2)
        put(0x504D, in: &image, at: stride, count: 2)
        put(entries, in: &image, at: stride + 4, count: 4)
        put(start, in: &image, at: stride + 8, count: 4)
        put(4, in: &image, at: stride + 12, count: 4)
        put("System", in: &image, at: stride + 16)
        put("Apple_HFS", in: &image, at: stride + 48)
        let header = Int(start) * stride + 1024
        if header + 90 <= image.count {
            put(signature, in: &image, at: header, count: 2)
            put(blessedID, in: &image, at: header + (signature == 0x4244 ? 86 : 80), count: 4)
        }
        return image
    }

    static func playStationISO(bootName: String = "SLES_123.45", license: String = "SONY COMPUTER ENTERTAINMENT EUROPE",
                               includeExecutable: Bool = true, declaredPayload: UInt64 = 0, config: Bool = true) -> Data {
        let sector = 2048
        var image = Data(repeating: 0, count: 24 * sector)
        func directory(_ name: String, block: Int, size: Int, isDirectory: Bool = false) -> Data {
            var entry = Data(repeating: 0, count: 33 + name.utf8.count + (name.utf8.count.isMultiple(of: 2) ? 1 : 0))
            entry[0] = UInt8(entry.count)
            put(UInt64(block), in: &entry, at: 2, count: 4, littleEndian: true)
            put(UInt64(block), in: &entry, at: 6, count: 4)
            put(UInt64(size), in: &entry, at: 10, count: 4, littleEndian: true)
            put(UInt64(size), in: &entry, at: 14, count: 4)
            entry[25] = isDirectory ? 2 : 0
            entry[28] = 1
            entry[31] = 1
            entry[32] = UInt8(name.utf8.count)
            put(name, in: &entry, at: 33)
            return entry
        }
        put(license, in: &image, at: 4 * sector)
        let volume = 16 * sector
        image[volume] = 1
        put("CD001", in: &image, at: volume + 1)
        image[volume + 6] = 1
        put("BOOTINSPECTOR TEST".padding(toLength: 32, withPad: " ", startingAt: 0), in: &image, at: volume + 40)
        let root = directory("\0", block: 20, size: sector, isDirectory: true)
        image.replaceSubrange((volume + 156)..<(volume + 156 + root.count), with: root)
        var entries = Data()
        if config {
            let text = "BOOT = cdrom:\\\(bootName);1\r\n"
            put(text, in: &image, at: 21 * sector)
            entries.append(directory("SYSTEM.CNF;1", block: 21, size: text.utf8.count))
        }
        if includeExecutable {
            entries.append(directory((config ? bootName : "PSX.EXE") + ";1", block: 22, size: sector))
            put("PS-X EXE", in: &image, at: 22 * sector)
            put(0x80010000, in: &image, at: 22 * sector + 16, count: 4, littleEndian: true)
            put(declaredPayload, in: &image, at: 22 * sector + 28, count: 4, littleEndian: true)
        }
        image.replaceSubrange((20 * sector)..<(20 * sector + entries.count), with: entries)
        return image
    }

    static func raw(_ iso: Data, stride: Int = 2352, offset: Int = 24) -> Data {
        let count = iso.count / 2048
        var data = Data(repeating: 0, count: count * stride)
        for i in 0..<count {
            let payload = i * stride + offset
            data.replaceSubrange(payload..<(payload + 2048), with: iso[(i * 2048)..<((i + 1) * 2048)])
        }
        return data
    }

    static func cue(file: String, type: String = "MODE2/2352") -> String {
        "FILE \"\(file)\" BINARY\n  TRACK 01 \(type)\n    INDEX 01 00:00:00\n"
    }

    static func ecm(_ raw: Data, compact: Data? = nil, type: UInt8 = 0) -> Data {
        func runLength(_ length: UInt32, type: UInt8 = 0) -> [UInt8] {
            var bytes = [UInt8((length & 31) << 2) | type]
            var remaining = length >> 5
            while remaining > 0 {
                bytes[bytes.count - 1] |= 0x80
                bytes.append(UInt8(remaining & 127))
                remaining >>= 7
            }
            return bytes
        }
        var data = Data([0x45, 0x43, 0x4D, 0])
        data.append(contentsOf: runLength(compact == nil ? UInt32(raw.count - 1) : 0, type: type))
        data.append(compact ?? raw)
        data.append(contentsOf: runLength(.max))
        var edc: UInt32 = 0
        for byte in raw {
            edc ^= UInt32(byte)
            for _ in 0..<8 {
                edc = (edc >> 1) ^ (edc & 1 == 0 ? 0 : 0xD8018001)
            }
        }
        var trailer = Data(repeating: 0, count: 4)
        put(UInt64(edc), in: &trailer, at: 0, count: 4, littleEndian: true)
        data.append(trailer)
        return data
    }

    static func chd(iso: Data, cyclic: Bool = false) -> Data {
        let frameBytes = 2448
        let hunkBytes = frameBytes * 4
        let frames = iso.count / 2048
        let hunks = frames / 4
        let metadataOffset = 124 + hunks * 4
        var data = Data(repeating: 0, count: (hunks + 1) * hunkBytes)
        put("MComprHD", in: &data, at: 0)
        put(124, in: &data, at: 8, count: 4)
        put(5, in: &data, at: 12, count: 4)
        put(UInt64(frames * frameBytes), in: &data, at: 32, count: 8)
        put(124, in: &data, at: 40, count: 8)
        put(UInt64(metadataOffset), in: &data, at: 48, count: 8)
        put(UInt64(hunkBytes), in: &data, at: 56, count: 4)
        put(UInt64(frameBytes), in: &data, at: 60, count: 4)
        for i in 0..<hunks { put(UInt64(i + 1), in: &data, at: 124 + i * 4, count: 4) }
        let metadata = "TRACK:1 TYPE:MODE2_RAW SUBTYPE:RW_RAW FRAMES:\(frames) PREGAP:0 PGTYPE:MODE2_RAW PGSUB:NONE POSTGAP:0\0"
        put("CHT2", in: &data, at: metadataOffset)
        put(UInt64(metadata.utf8.count), in: &data, at: metadataOffset + 5, count: 3)
        put(cyclic ? UInt64(metadataOffset) : 0, in: &data, at: metadataOffset + 8, count: 8)
        put(metadata, in: &data, at: metadataOffset + 16)
        data.replaceSubrange(hunkBytes..<data.count, with: raw(iso, stride: frameBytes))
        return data
    }
}
