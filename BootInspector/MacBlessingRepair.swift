import Foundation

nonisolated enum MacBlessingRepair {
    struct Plan: Equatable, Sendable {
        let partitionID: Int
        let folder: MacBootCatalog.Folder
        let currentID: UInt32
        let classicID: UInt32
        let headerOffsets: [UInt64]
        let writeCount: UInt32
    }

    struct RepairError: LocalizedError {
        let errorDescription: String?
        init(_ reason: String) { errorDescription = reason }
    }

    static func preview(_ source: URL, partitionID: Int, folderID: UInt32) throws -> Plan {
        let scoped = source.startAccessingSecurityScopedResource()
        defer { if scoped { source.stopAccessingSecurityScopedResource() } }
        let report = try DiskImageInspector.inspect(url: source)
        guard let partition = report.partitions.first(where: { $0.id == partitionID }) else {
            throw RepairError("The selected partition is missing from the Apple Partition Map.")
        }
        switch partition.bootFinding {
        case .missingBlessing, .staleBlessing: break
        default: throw RepairError("The selected partition has no missing or stale blessing to repair.")
        }
        let handle = try FileHandle(forReadingFrom: source)
        defer { try? handle.close() }
        let primaryOffset = partition.byteOffset + 1024
        let header = try volumeHeader(handle, at: primaryOffset)
        guard header.readUInt16BE(at: 0) == 0x482B, header.readUInt16BE(at: 2) == 4 else {
            throw RepairError("This repair supports unwrapped HFS+ volumes.")
        }
        let attrs = header.readUInt32BE(at: 4) ?? 0
        guard attrs & 0x100 != 0, attrs & 0x2800 == 0 else {
            throw RepairError("The volume must be clean and non-journaled.")
        }
        let blockSize = UInt64(header.readUInt32BE(at: 40) ?? 0)
        let blocks = UInt64(header.readUInt32BE(at: 44) ?? 0)
        let length = blockSize * blocks
        guard length >= 4096, length <= partition.byteSize else {
            throw RepairError("The HFS+ volume geometry does not fit the partition.")
        }
        let alternateOffset = partition.byteOffset + length - 1024
        let alternate = try volumeHeader(handle, at: alternateOffset)
        guard header[0..<112] == alternate[0..<112], header[272..<352] == alternate[272..<352],
              let current = header.readUInt32BE(at: 80), let classic = header.readUInt32BE(at: 92),
              header.readUInt32BE(at: 100) == 0, let count = header.readUInt32BE(at: 68), count < .max else {
            throw RepairError("Volume headers disagree or contain a separate Mac OS X blessing.")
        }
        let candidates = try MacBootCatalog.validatedStartupFolders(handle: handle, header: header,
                                                                    offset: partition.byteOffset, length: length)
        guard let folder = candidates.first(where: { $0.id == folderID }) else {
            throw RepairError("The selected folder’s startup file forks could not be validated.")
        }
        return Plan(partitionID: partitionID, folder: folder, currentID: current, classicID: classic,
                    headerOffsets: [primaryOffset, alternateOffset], writeCount: count)
    }

    static func saveCopy(of source: URL, to destination: URL, plan: Plan) throws {
        guard source.standardizedFileURL != destination.standardizedFileURL,
              !FileManager.default.fileExists(atPath: destination.path) else {
            throw RepairError("Choose a new image filename.")
        }
        let scoped = [source, destination].filter { $0.startAccessingSecurityScopedResource() }
        defer { scoped.forEach { $0.stopAccessingSecurityScopedResource() } }
        let work = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: work) }
        let copy = work.appendingPathComponent(source.lastPathComponent)
        try Task.checkCancellation()
        try FileManager.default.copyItem(at: source, to: copy)
        guard try preview(copy, partitionID: plan.partitionID, folderID: plan.folder.id) == plan else {
            throw RepairError("The image changed after the repair preview.")
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: copy.path)
        try patch(copy, plan: plan)
        let check = try FileHandle(forReadingFrom: copy)
        defer { try? check.close() }
        for offset in plan.headerOffsets {
            let header = try volumeHeader(check, at: offset)
            guard header.readUInt32BE(at: 68) == plan.writeCount + 1,
                  header.readUInt32BE(at: 80) == plan.folder.id, header.readUInt32BE(at: 92) == plan.folder.id else {
                throw RepairError("A repaired volume header could not be verified.")
            }
        }
        let report = try DiskImageInspector.inspect(url: copy)
        guard report.partitions.first(where: { $0.id == plan.partitionID })?.bootFinding == .verified(plan.folder) else {
            throw RepairError("The repaired copy did not pass structural verification.")
        }
        try Task.checkCancellation()
        try FileManager.default.copyItem(at: copy, to: destination)
    }

    private static func volumeHeader(_ file: FileHandle, at offset: UInt64) throws -> Data {
        try file.seek(toOffset: offset)
        guard let bytes = try file.read(upToCount: 512), bytes.count == 512 else {
            throw RepairError("An HFS+ volume header is incomplete.")
        }
        return bytes
    }

    private static func patch(_ url: URL, plan: Plan) throws {
        let handle = try FileHandle(forUpdating: url)
        defer { try? handle.close() }
        for offset in plan.headerOffsets {
            for (field, value) in [(68, plan.writeCount + 1), (80, plan.folder.id), (92, plan.folder.id)] {
                try handle.seek(toOffset: offset + UInt64(field))
                var encoded = value.bigEndian
                try withUnsafeBytes(of: &encoded) { try handle.write(contentsOf: Data($0)) }
            }
        }
        try handle.synchronize()
    }
}
