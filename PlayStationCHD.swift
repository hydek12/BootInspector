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
        guard frame >= 0, UInt64(frame) < logicalBytes / UInt64(Self.frameSize),
              (0...(Self.frameSize - 2048)).contains(payloadOffset) else {
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
        let start = byte % buffer.count + payloadOffset
        return Data(buffer[start..<(start + 2048)])
    }
}
