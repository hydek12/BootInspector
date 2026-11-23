import Foundation

nonisolated enum PlayStationECM {
    private static let maximumDecodedBytes = 1_200_000_000

    private final class Reader {
        private let file: FileHandle
        private var buffer = Data()
        private var offset = 0

        init(_ file: FileHandle) { self.file = file }

        func read(_ count: Int) throws -> Data {
            if offset + count > buffer.count {
                buffer = Data(buffer.dropFirst(offset))
                offset = 0
                while buffer.count < count {
                    let next = try file.read(upToCount: max(1_048_576, count - buffer.count)) ?? Data()
                    guard !next.isEmpty else { throw PlayStationInspector.InspectionError("The ECM stream ended unexpectedly.") }
                    buffer.append(next)
                }
            }
            let result = Data(buffer[offset..<(offset + count)])
            offset += count
            return result
        }

        func byte() throws -> UInt8 { try read(1)[0] }

        var hasTrailingData: Bool {
            get throws {
                if offset < buffer.count { return true }
                return !(try file.read(upToCount: 1) ?? Data()).isEmpty
            }
        }
    }

    static func decode(_ url: URL, to destination: URL) throws {
        let source = try FileHandle(forReadingFrom: url)
        defer { try? source.close() }
        let reader = Reader(source)
        guard try reader.read(4).elementsEqual([0x45, 0x43, 0x4D, 0]) else {
            throw PlayStationInspector.InspectionError("Invalid ECM header.")
        }
        try Data().write(to: destination, options: .withoutOverwriting)
        let output = try FileHandle(forWritingTo: destination)
        defer { try? output.close() }
        var pending = Data()
        var written = 0
        var checksum: UInt32 = 0

        func flush() throws {
            guard !pending.isEmpty else { return }
            try output.write(contentsOf: pending)
            checksum = pending.withUnsafeBytes { raw in
                CDSectorIntegrity.edc(raw.bindMemory(to: UInt8.self), range: 0..<pending.count, initial: checksum)
            }
            pending.removeAll(keepingCapacity: true)
        }
        func append(_ data: Data) throws {
            guard data.count <= maximumDecodedBytes - written else {
                throw PlayStationInspector.InspectionError("The ECM expands beyond the supported single-CD size.")
            }
            written += data.count
            pending.append(data)
            if pending.count >= 1_048_576 { try flush() }
        }
        while true {
            try Task.checkCancellation()
            var byte = try reader.byte()
            let type = Int(byte & 3)
            var value = UInt64((byte >> 2) & 31)
            var shift = 5
            while byte & 0x80 != 0 {
                guard shift < 33 else { throw PlayStationInspector.InspectionError("Invalid ECM run length.") }
                byte = try reader.byte()
                value |= UInt64(byte & 127) << shift
                shift += 7
            }
            if value == UInt64(UInt32.max) { break }
            guard value < UInt64(UInt32.max) else { throw PlayStationInspector.InspectionError("Invalid ECM run length.") }
            var count = Int(value) + 1
            let compact = [1, 2051, 2052, 2328][type]
            let expanded = [1, 2352, 2336, 2336][type]
            guard count <= (maximumDecodedBytes - written) / expanded else {
                throw PlayStationInspector.InspectionError("The ECM contains an oversized run.")
            }
            if type == 0 {
                while count > 0 {
                    try Task.checkCancellation()
                    let chunk = min(count, 1_048_576)
                    try append(reader.read(chunk))
                    count -= chunk
                }
            } else {
                for index in 0..<count {
                    if index.isMultiple(of: 256) { try Task.checkCancellation() }
                    try append(CDSectorIntegrity.reconstruct(reader.read(compact), type: type))
                }
            }
        }
        try flush()
        let stored = try reader.read(4).withUnsafeBytes {
            CDSectorIntegrity.littleEndian32($0.bindMemory(to: UInt8.self), offset: 0)
        }
        guard stored == checksum, try !reader.hasTrailingData else {
            throw PlayStationInspector.InspectionError("The decoded ECM checksum or end marker is invalid.")
        }
    }
}
