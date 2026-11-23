import CryptoKit
import Darwin
import Foundation

nonisolated final class PlayStationCHD {
    private typealias Open = @convention(c) (UnsafePointer<CChar>, Int32, OpaquePointer?, UnsafeMutablePointer<OpaquePointer?>) -> Int32
    private typealias Close = @convention(c) (OpaquePointer) -> Void
    private typealias Read = @convention(c) (OpaquePointer, UInt32, UnsafeMutableRawPointer) -> Int32
    private typealias Header = @convention(c) (OpaquePointer) -> UnsafeRawPointer?
    private typealias ErrorString = @convention(c) (Int32) -> UnsafePointer<CChar>?

    static let frameSize = 2448
    private let library: UnsafeMutableRawPointer
    private let file: OpaquePointer
    private let close: Close
    private let read: Read
    private let errorString: ErrorString
    private let logicalBytes: UInt64
    private var buffer: [UInt8]
    private var cachedHunk: UInt32?

    init(_ url: URL, libraryURL: URL, logicalBytes: UInt64, hunkBytes: Int) throws {
        guard logicalBytes > 0, logicalBytes <= 2_000_000_000,
              hunkBytes > 0, hunkBytes <= 1024 * 1024, hunkBytes.isMultiple(of: Self.frameSize) else {
            throw PlayStationInspector.InspectionError("Unsupported CHD CD storage dimensions.")
        }
        guard let library = dlopen(libraryURL.path, RTLD_NOW | RTLD_LOCAL) else {
            throw PlayStationInspector.InspectionError("The bundled libchdr could not be loaded.")
        }
        var initialized = false
        defer { if !initialized { dlclose(library) } }
        guard let openSymbol = dlsym(library, "chd_open"),
              let closeSymbol = dlsym(library, "chd_close"),
              let readSymbol = dlsym(library, "chd_read"),
              let headerSymbol = dlsym(library, "chd_get_header"),
              let errorSymbol = dlsym(library, "chd_error_string") else {
            throw PlayStationInspector.InspectionError("The bundled libchdr is missing required functions.")
        }

        let open = unsafeBitCast(openSymbol, to: Open.self)
        let errorString = unsafeBitCast(errorSymbol, to: ErrorString.self)
        var handle: OpaquePointer?
        let result = url.path.withCString { open($0, 1, nil, &handle) }
        guard result == 0, let handle else {
            throw PlayStationInspector.InspectionError("libchdr could not open the disc (\(errorString(result).map { String(cString: $0) } ?? String(result))).")
        }

        let header = unsafeBitCast(headerSymbol, to: Header.self)
        let close = unsafeBitCast(closeSymbol, to: Close.self)
        // In the bundled libchdr ABI, hunkbytes follows seven uint32_t fields.
        guard let openedHeader = header(handle), openedHeader.load(fromByteOffset: 28, as: UInt32.self) == UInt32(hunkBytes) else {
            close(handle)
            throw PlayStationInspector.InspectionError("The CHD hunk size changed while opening the disc.")
        }

        self.library = library
        self.file = handle
        self.close = close
        self.read = unsafeBitCast(readSymbol, to: Read.self)
        self.errorString = errorString
        self.logicalBytes = logicalBytes
        self.buffer = [UInt8](repeating: 0, count: hunkBytes)
        initialized = true
    }

    deinit {
        close(file)
        dlclose(library)
    }

    func sector(frame: Int, payloadOffset: Int) throws -> Data {
        let start = try frameOffset(frame, offset: payloadOffset, count: 2048)
        return Data(buffer[start..<(start + 2048)])
    }

    func sha1(firstFrame: Int, frames: Int, sectorBytes: Int, audio: Bool) throws -> String {
        guard firstFrame >= 0, frames > 0, sectorBytes > 0, sectorBytes <= 2352,
              (!audio || sectorBytes == 2352),
              UInt64(firstFrame) + UInt64(frames) <= logicalBytes / UInt64(Self.frameSize) else {
            throw PlayStationInspector.InspectionError("Invalid or incomplete CHD track storage.")
        }
        var hash = Insecure.SHA1()
        var audioSector = [UInt8](repeating: 0, count: audio ? sectorBytes : 0)
        for frame in firstFrame..<(firstFrame + frames) {
            if frame.isMultiple(of: 256) { try Task.checkCancellation() }
            let start = try frameOffset(frame, offset: 0, count: sectorBytes)
            if audio {
                // CHD CDDA uses big-endian samples. BIN catalogs hash little-endian samples.
                for sample in stride(from: 0, to: sectorBytes, by: 2) {
                    audioSector[sample] = buffer[start + sample + 1]
                    audioSector[sample + 1] = buffer[start + sample]
                }
                audioSector.withUnsafeBytes { hash.update(bufferPointer: $0) }
            } else {
                buffer.withUnsafeBytes { bytes in
                    hash.update(bufferPointer: UnsafeRawBufferPointer(rebasing: bytes[start..<(start + sectorBytes)]))
                }
            }
        }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private func frameOffset(_ frame: Int, offset: Int, count: Int) throws -> Int {
        guard frame >= 0, UInt64(frame) < logicalBytes / UInt64(Self.frameSize),
              offset >= 0, offset <= Self.frameSize - count else {
            throw PlayStationInspector.InspectionError("CHD sector is outside the stored CD frames.")
        }
        let byte = frame * Self.frameSize
        let hunk = UInt32(byte / buffer.count)
        if cachedHunk != hunk {
            cachedHunk = nil
            let result = buffer.withUnsafeMutableBytes { read(file, hunk, $0.baseAddress!) }
            guard result == 0 else {
                throw PlayStationInspector.InspectionError("libchdr could not decode hunk \(hunk) (\(errorString(result).map { String(cString: $0) } ?? String(result))).")
            }
            cachedHunk = hunk
        }
        return byte % buffer.count + offset
    }
}
