import Foundation

nonisolated enum CDSectorIntegrity {
    struct Summary: Sendable {
        var sectors = 0
        var checkedEDC = 0
        var checkedECC = 0
        var omittedForm2EDC = 0
        var edcMismatches = 0
        var eccMismatches = 0
        var malformedHeaders = 0
        var uncheckedSectors = 0
        var examples: [String] = []
    }

    private static let sync: [UInt8] = [0] + Array(repeating: 255, count: 10) + [0]
    private static let edcTable: [UInt32] = (0..<256).map { value in
        var register = UInt32(value)
        for _ in 0..<8 {
            register = (register >> 1) ^ (register & 1 == 0 ? 0 : 0xD8018001)
        }
        return register
    }

    private static let forward: [UInt8] = (0..<256).map {
        UInt8(truncatingIfNeeded: ($0 << 1) ^ ($0 & 0x80 == 0 ? 0 : 0x11D))
    }

    private static let backward: [UInt8] = {
        var table = Array(repeating: UInt8(0), count: 256)
        for value in 0..<256 { table[value ^ Int(forward[value])] = UInt8(value) }
        return table
    }()

    static func edc(_ bytes: UnsafeBufferPointer<UInt8>, range: Range<Int>, initial: UInt32 = 0) -> UInt32 {
        var value = initial
        for index in range { value = (value >> 8) ^ edcTable[Int((value ^ UInt32(bytes[index])) & 255)] }
        return value
    }

    static func littleEndian32(_ bytes: UnsafeBufferPointer<UInt8>, offset: Int) -> UInt32 {
        UInt32(bytes[offset]) | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16) | (UInt32(bytes[offset + 3]) << 24)
    }

    private static func parity(_ bytes: UnsafeBufferPointer<UInt8>, base: Int, major: Int, majors: Int,
                               minors: Int, multiplier: Int, increment: Int, clearAddress: Bool) -> (UInt8, UInt8) {
        let size = majors * minors
        var index = (major / 2) * multiplier + (major & 1)
        var a: UInt8 = 0
        var b: UInt8 = 0
        for _ in 0..<minors {
            let value = clearAddress && index < 4 ? 0 : bytes[base + 12 + index]
            index += increment
            if index >= size { index -= size }
            a = forward[Int(a ^ value)]
            b ^= value
        }
        a = backward[Int(forward[Int(a)] ^ b)]
        return (a, a ^ b)
    }

    private static func matchesECC(_ bytes: UnsafeBufferPointer<UInt8>, base: Int, mode2: Bool) -> Bool {
        for major in 0..<86 {
            let pair = parity(bytes, base: base, major: major, majors: 86, minors: 24,
                              multiplier: 2, increment: 86, clearAddress: mode2)
            if bytes[base + 2076 + major] != pair.0 || bytes[base + 2162 + major] != pair.1 { return false }
        }
        for major in 0..<52 {
            let pair = parity(bytes, base: base, major: major, majors: 52, minors: 43,
                              multiplier: 86, increment: 88, clearAddress: mode2)
            if bytes[base + 2248 + major] != pair.0 || bytes[base + 2300 + major] != pair.1 { return false }
        }
        return true
    }

    static func reconstruct(_ compact: Data, type: Int) -> Data {
        var sector = Array(repeating: UInt8(0), count: 2352)
        sector.replaceSubrange(0..<12, with: sync)
        let mode2 = type != 1
        sector[15] = mode2 ? 2 : 1
        if mode2 {
            sector.replaceSubrange(20..<(20 + compact.count), with: compact)
            sector.replaceSubrange(16..<20, with: compact.prefix(4))
        } else {
            sector.replaceSubrange(12..<15, with: compact.prefix(3))
            sector.replaceSubrange(16..<2064, with: compact.dropFirst(3))
        }
        let end = type == 1 ? 2064 : (type == 2 ? 2072 : 2348)
        let value = sector.withUnsafeBufferPointer { edc($0, range: (mode2 ? 16 : 0)..<end) }
        for index in 0..<4 { sector[end + index] = UInt8(truncatingIfNeeded: value >> (index * 8)) }
        if type != 3 {
            for major in 0..<86 {
                let pair = sector.withUnsafeBufferPointer {
                    parity($0, base: 0, major: major, majors: 86, minors: 24, multiplier: 2, increment: 86, clearAddress: mode2)
                }
                sector[2076 + major] = pair.0
                sector[2162 + major] = pair.1
            }
            for major in 0..<52 {
                let pair = sector.withUnsafeBufferPointer {
                    parity($0, base: 0, major: major, majors: 52, minors: 43, multiplier: 86, increment: 88, clearAddress: mode2)
                }
                sector[2248 + major] = pair.0
                sector[2300 + major] = pair.1
            }
        }
        return Data(mode2 ? sector.dropFirst(16) : sector[...])
    }

    static func supports(_ track: PlayStationTrack) -> Bool {
        track.type.hasPrefix("MODE") && (track.sectorBytes == 2352 || track.sectorBytes == 2448)
            && track.index01 != nil && track.frames != nil
    }

    static func scan(_ tracks: [PlayStationTrack]) throws -> Summary {
        var result = Summary()
        for track in tracks where supports(track) {
            try Task.checkCancellation()
            guard let stride = track.sectorBytes, let index = track.index01, let frames = track.frames else { continue }
            let scoped = track.file.startAccessingSecurityScopedResource()
            defer { if scoped { track.file.stopAccessingSecurityScopedResource() } }
            let handle = try FileHandle(forReadingFrom: track.file)
            defer { try? handle.close() }
            try handle.seek(toOffset: UInt64(index * stride))
            var position = 0
            while position < frames {
                try Task.checkCancellation()
                let batch = min(frames - position, 256)
                let data = try handle.read(upToCount: batch * stride) ?? Data()
                guard data.count == batch * stride else {
                    throw PlayStationInspector.InspectionError("Track \(track.id) ended during sector verification.")
                }
                data.withUnsafeBytes { raw in
                    let bytes = raw.bindMemory(to: UInt8.self)
                    for i in 0..<batch {
                        let issue = inspect(bytes, base: i * stride, result: &result)
                        if let issue, result.examples.count < 12 {
                            let address = track.start.map { "LBA \($0 + position + i)" } ?? "sector \(position + i)"
                            result.examples.append("Track \(track.id), \(address): \(issue)")
                        }
                    }
                }
                position += batch
            }
        }
        return result
    }

    private static func inspect(_ bytes: UnsafeBufferPointer<UInt8>, base: Int, result: inout Summary) -> String? {
        result.sectors += 1
        guard sync.indices.allSatisfy({ bytes[base + $0] == sync[$0] }) else {
            result.malformedHeaders += 1
            return "missing raw sector sync"
        }
        let mode = bytes[base + 15]
        guard mode == 1 || mode == 2 else {
            result.uncheckedSectors += 1
            return nil
        }
        let mode2 = mode == 2
        if mode2 && !(16..<20).allSatisfy({ bytes[base + $0] == bytes[base + $0 + 4] }) {
            result.malformedHeaders += 1
            return "mismatched XA subheaders"
        }
        let form2 = mode2 && bytes[base + 18] & 0x20 != 0
        let end = !mode2 ? 2064 : (form2 ? 2348 : 2072)
        let stored = littleEndian32(bytes, offset: base + end)
        var errors: [String] = []
        if form2 && stored == 0 {
            result.omittedForm2EDC += 1
        } else {
            result.checkedEDC += 1
            if edc(bytes, range: (base + (mode2 ? 16 : 0))..<(base + end)) != stored {
                result.edcMismatches += 1
                errors.append("EDC mismatch")
            }
        }
        if !form2 {
            result.checkedECC += 1
            if !matchesECC(bytes, base: base, mode2: mode2) {
                result.eccMismatches += 1
                errors.append("ECC mismatch")
            }
        }
        return errors.isEmpty ? nil : errors.joined(separator: ", ")
    }
}
