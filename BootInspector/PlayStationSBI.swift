import Foundation

nonisolated enum PlayStationSBI: Equatable, Sendable {
    case missing
    case valid(Int)
    case invalid(String)
    case unreadable

    var summary: String {
        switch self {
        case .missing: "No same-name SBI found or directory inaccessible"
        case .valid(let records): "Structure valid · \(records) Q-channel records"
        case .invalid(let reason): "Invalid SBI · \(reason)"
        case .unreadable: "SBI found but unreadable"
        }
    }

    static func inspect(_ file: URL?) -> Self {
        guard let file else { return .missing }
        do {
            let handle = try FileHandle(forReadingFrom: file)
            defer { try? handle.close() }
            let data = try handle.read(upToCount: 1_048_577) ?? Data()
            return validate(data)
        } catch {
            return .unreadable
        }
    }

    static func validate(_ data: Data) -> Self {
        guard data.count <= 1_048_576, data.starts(with: [0x53, 0x42, 0x49, 0]) else {
            return .invalid("bad header or size")
        }
        var offset = data.startIndex + 4
        var fieldsByPosition: [Int: UInt8] = [:]
        var records = 0
        while offset < data.endIndex {
            guard data.endIndex - offset >= 4 else { return .invalid("truncated record header") }
            let msf = data[offset..<(offset + 3)].map { Int($0 >> 4) * 10 + Int($0 & 15) }
            guard data[offset..<(offset + 3)].allSatisfy({ $0 >> 4 < 10 && $0 & 15 < 10 }),
                  msf[1] < 60, msf[2] < 75 else { return .invalid("invalid BCD timestamp") }
            let length: Int
            let fields: UInt8
            switch data[offset + 3] {
            case 1: (length, fields) = (10, 3)
            case 2: (length, fields) = (3, 1)
            case 3: (length, fields) = (3, 2)
            default: return .invalid("unknown record type")
            }
            guard data.endIndex - offset >= 4 + length else { return .invalid("truncated record payload") }
            let position = (msf[0] * 60 + msf[1]) * 75 + msf[2]
            guard fieldsByPosition[position, default: 0] & fields == 0 else {
                return .invalid("overlapping records at one sector")
            }
            fieldsByPosition[position, default: 0] |= fields
            records += 1
            offset += 4 + length
        }
        return records == 0 ? .invalid("no records") : .valid(records)
    }
}
