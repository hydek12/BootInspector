import Foundation

nonisolated enum MacBootCatalog {
    struct Folder: Sendable, Equatable {
        let id: UInt32
        let name: String
    }

    enum Finding: Sendable, Equatable {
        case verified(Folder)
        case missingBlessing([Folder])
        case staleBlessing([Folder])
        case noSupportedSystemFolder
        case unavailable(String)

        var detail: String {
            switch self {
            case .verified(let folder):
                "Blessed folder “\(folder.name)” (CNID \(folder.id)) has catalog records for System, Finder, and a tbxi boot file."
            case .missingBlessing(let folders):
                "Blessing is missing. " + Self.candidates(folders)
            case .staleBlessing(let folders):
                "The recorded blessing does not identify a complete classic PPC System Folder. " + Self.candidates(folders)
            case .noSupportedSystemFolder:
                "No catalog folder has all three files required by this classic PPC tbxi boot profile."
            case .unavailable(let reason):
                "Catalog validation unavailable. " + reason
            }
        }

        private static func candidates(_ folders: [Folder]) -> String {
            "Candidate folders: " + folders.map { "\($0.name) (CNID \($0.id))" }.joined(separator: ", ")
        }
    }

    private enum CatalogError: String, Error {
        case layout = "The volume geometry or catalog extent is invalid."
        case overflow = "The catalog requires extent overflow records."
        case tree = "The catalog B-tree is incomplete or malformed."
    }

    private struct Extent {
        let offset: UInt64
        let length: UInt64
    }

    private struct StartupFiles: OptionSet {
        let rawValue: UInt8
        static let system = Self(rawValue: 1)
        static let finder = Self(rawValue: 2)
        static let boot = Self(rawValue: 4)
        static let required: Self = [.system, .finder, .boot]
    }

    static func inspect(handle: FileHandle, header: Data, offset: UInt64, length: UInt64,
                        blessedID: UInt32) -> Finding {
        do {
            let (folders, startup) = try readCatalog(handle: handle, header: header, offset: offset, length: length)
            let candidates = folders.values.filter { startup[$0.id]?.contains(.required) == true }.sorted { $0.id < $1.id }
            if let match = candidates.first(where: { $0.id == blessedID }) { return .verified(match) }
            if candidates.isEmpty { return .noSupportedSystemFolder }
            return blessedID == 0 ? .missingBlessing(candidates) : .staleBlessing(candidates)
        } catch let error as CatalogError {
            return .unavailable(error.rawValue)
        } catch {
            return .unavailable(error.localizedDescription)
        }
    }

    static func validatedStartupFolders(handle: FileHandle, header: Data, offset: UInt64, length: UInt64) throws -> [Folder] {
        let (folders, startup) = try readCatalog(handle: handle, header: header, offset: offset, length: length, validateForks: true)
        return folders.values.filter { startup[$0.id]?.contains(.required) == true }.sorted { $0.id < $1.id }
    }

    private static func readCatalog(handle: FileHandle, header: Data, offset: UInt64, length: UInt64, validateForks: Bool = false)
        throws -> ([UInt32: Folder], [UInt32: StartupFiles]) {
        guard header.count >= 512 else { throw CatalogError.layout }
        let classic = u16(header, 0) == 0x4244
        let blockSize = UInt64(u32(header, classic ? 20 : 40))
        let blocks = classic ? UInt64(u16(header, 18)) : UInt64(u32(header, 44))
        let base = classic ? UInt64(u16(header, 28)) * 512 : 0
        let fileSize = classic ? UInt64(u32(header, 146)) : u64(header, 272)
        guard blockSize >= 512, blockSize.isMultiple(of: 512), blockSize <= 16 * 1024 * 1024,
              base <= length, blocks > 0, blocks <= (length - base) / blockSize,
              fileSize >= 64, fileSize <= length else { throw CatalogError.layout }

        func forkPrefix(_ node: Data, at field: Int) throws -> (Data, UInt64)? {
            let size = u64(node, field)
            let allocated = UInt64(u32(node, field + 12))
            guard size > 0, allocated > 0, allocated <= blocks, size <= allocated * blockSize else { return nil }
            var ranges: [Range<UInt64>] = []
            var represented: UInt64 = 0
            for index in 0..<8 {
                let first = UInt64(u32(node, field + 16 + index * 8))
                let count = UInt64(u32(node, field + 20 + index * 8))
                if count == 0 { break }
                guard first < blocks, count <= blocks - first, count <= allocated - represented else { return nil }
                let range = first..<(first + count)
                guard !ranges.contains(where: { $0.overlaps(range) }) else { return nil }
                ranges.append(range)
                represented += count
            }
            guard represented == allocated, let first = ranges.first else { return nil }
            let prefixSize = Int(min(size, 512))
            try handle.seek(toOffset: offset + first.lowerBound * blockSize)
            guard let bytes = try handle.read(upToCount: prefixSize), bytes.count == prefixSize else { return nil }
            return (bytes, size)
        }

        func hasResourceMap(_ fork: (Data, UInt64)?) -> Bool {
            guard let (bytes, size) = fork, bytes.count >= 16 else { return false }
            let dataOffset = UInt64(u32(bytes, 0))
            let mapOffset = UInt64(u32(bytes, 4))
            let dataLength = UInt64(u32(bytes, 8))
            let mapLength = UInt64(u32(bytes, 12))
            return dataOffset >= 16 && dataOffset <= size && dataLength > 0 && dataLength <= size - dataOffset &&
                mapOffset >= dataOffset + dataLength && mapOffset <= size && mapLength >= 28 && mapLength <= size - mapOffset
        }

        var extents: [Extent] = []
        for index in 0..<(classic ? 3 : 8) {
            let field = classic ? 150 + index * 4 : 288 + index * 8
            let first = classic ? UInt64(u16(header, field)) : UInt64(u32(header, field))
            let count = classic ? UInt64(u16(header, field + 2)) : UInt64(u32(header, field + 4))
            if count == 0 { break }
            guard first < blocks, count <= blocks - first else { throw CatalogError.layout }
            let extent = Extent(offset: offset + base + first * blockSize, length: count * blockSize)
            guard !extents.contains(where: {
                extent.offset < $0.offset + $0.length && $0.offset < extent.offset + extent.length
            }) else { throw CatalogError.layout }
            extents.append(extent)
        }
        guard extents.reduce(UInt64(0), { $0 + $1.length }) >= fileSize else { throw CatalogError.overflow }

        func read(at position: UInt64, count: Int) throws -> Data {
            guard position <= fileSize, UInt64(count) <= fileSize - position else { throw CatalogError.tree }
            var skip = position
            var bytes = Data()
            for extent in extents {
                if skip >= extent.length { skip -= extent.length; continue }
                let amount = min(count - bytes.count, Int(extent.length - skip))
                try handle.seek(toOffset: extent.offset + skip)
                guard let part = try handle.read(upToCount: amount), part.count == amount else { throw CatalogError.tree }
                bytes.append(part)
                if bytes.count == count { return bytes }
                skip = 0
            }
            throw CatalogError.tree
        }

        let tree = try read(at: 0, count: 64)
        let nodeSize = Int(u16(tree, 32))
        let total = u32(tree, 36)
        let records = u32(tree, 20)
        let last = u32(tree, 28)
        var leaf = u32(tree, 24)
        guard tree[8] == 1, (512...32768).contains(nodeSize), nodeSize.nonzeroBitCount == 1,
              total > 0, UInt64(total) * UInt64(nodeSize) <= fileSize, records <= 1_000_000 else {
            throw CatalogError.tree
        }
        if records == 0 {
            guard leaf == 0, last == 0 else { throw CatalogError.tree }
            return ([:], [:])
        }
        guard leaf > 0, last > 0 else { throw CatalogError.tree }
        var folders: [UInt32: Folder] = [:]
        var startup: [UInt32: StartupFiles] = [:]
        var visited = Set<UInt32>()
        var previous: UInt32 = 0
        var seen: UInt32 = 0
        while leaf != 0 {
            try Task.checkCancellation()
            guard leaf < total, visited.count < 65_536, visited.insert(leaf).inserted else { throw CatalogError.tree }
            let node = try read(at: UInt64(leaf) * UInt64(nodeSize), count: nodeSize)
            let count = Int(u16(node, 10))
            let table = nodeSize - (count + 1) * 2
            guard node[8] == 0xFF, node[9] == 1, u32(node, 4) == previous,
                  count > 0, table >= 14, UInt32(count) <= records - seen else { throw CatalogError.tree }
            for index in 0..<count {
                let from = Int(u16(node, nodeSize - (index + 1) * 2))
                let end = Int(u16(node, nodeSize - (index + 2) * 2))
                guard from >= 14, end <= table, end - from >= (classic ? 8 : 10) else { throw CatalogError.tree }
                let keyBytes = classic ? Int(node[from]) + 1 : Int(u16(node, from)) + 2
                let value = from + (keyBytes + 1) / 2 * 2
                let nameLength = classic ? Int(node[from + 6]) : Int(u16(node, from + 6)) * 2
                let nameStart = from + (classic ? 7 : 8)
                guard nameStart + nameLength <= from + keyBytes, value + 2 <= end else { throw CatalogError.tree }
                let type = classic ? UInt16(node[value]) : u16(node, value)
                if type == 1 {
                    guard value + (classic ? 10 : 12) <= end else { throw CatalogError.tree }
                    let id = u32(node, value + (classic ? 6 : 8))
                    let name = String(data: node[nameStart..<(nameStart + nameLength)],
                                      encoding: classic ? .macOSRoman : .utf16BigEndian) ?? ""
                    guard id >= 2, !name.isEmpty, folders[id] == nil else { throw CatalogError.tree }
                    folders[id] = Folder(id: id, name: name)
                } else if type == 2 {
                    guard value + (classic ? 40 : 176) <= end else { throw CatalogError.tree }
                    let parent = u32(node, from + 2)
                    let finderType = u32(node, value + (classic ? 4 : 48))
                    let dataSize = classic ? UInt64(u32(node, value + 26)) : u64(node, value + 88)
                    let resourceSize = classic ? UInt64(u32(node, value + 36)) : u64(node, value + 168)
                    if validateForks {
                        guard !classic, value + 248 <= end else { throw CatalogError.tree }
                        switch finderType {
                        case 0x7A737973:
                            if try hasResourceMap(forkPrefix(node, at: value + 168)) { startup[parent, default: []].insert(.system) }
                        case 0x464E4452:
                            if try hasResourceMap(forkPrefix(node, at: value + 168)) { startup[parent, default: []].insert(.finder) }
                        case 0x74627869:
                            if let (bytes, _) = try forkPrefix(node, at: value + 88), bytes.starts(with: "<CHRP-BOOT>".utf8) {
                                startup[parent, default: []].insert(.boot)
                            }
                        default: break
                        }
                    } else {
                        switch finderType {
                        case 0x7A737973 where resourceSize > 0: startup[parent, default: []].insert(.system)
                        case 0x464E4452 where dataSize > 0 || resourceSize > 0: startup[parent, default: []].insert(.finder)
                        case 0x74627869 where dataSize > 0: startup[parent, default: []].insert(.boot)
                        default: break
                        }
                    }
                }
            }
            seen += UInt32(count)
            previous = leaf
            leaf = u32(node, 0)
        }
        guard previous == last, seen == records else { throw CatalogError.tree }
        return (folders, startup)
    }

    private static func u16(_ data: Data, _ offset: Int) -> UInt16 {
        UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
    }

    private static func u32(_ data: Data, _ offset: Int) -> UInt32 {
        UInt32(u16(data, offset)) << 16 | UInt32(u16(data, offset + 2))
    }

    private static func u64(_ data: Data, _ offset: Int) -> UInt64 {
        UInt64(u32(data, offset)) << 32 | UInt64(u32(data, offset + 4))
    }
}
