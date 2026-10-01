import Darwin
import Foundation
import OSLog

struct WiFiNetwork: Identifiable, Hashable {
    let ssid: Data
    let bssid: String
    let channel: Int
    let rssi: Int
    let security: String

    var id: String { bssid }
    var label: String {
        let decoded = String(data: ssid, encoding: .utf8) ?? ssid.map { String(format: "%02x", $0) }.joined()
        return decoded.unicodeScalars.map {
            CharacterSet.controlCharacters.contains($0) ? String(format: "\\u%04x", $0.value) : String($0)
        }.joined()
    }

    init(json: [String: Any]) throws {
        guard let encoded = json["ssid_b64"] as? String, let data = Data(base64Encoded: encoded),
              (1...32).contains(data.count), let bssid = json["bssid"] as? String,
              Self.macAddress(bssid) != nil, let channel = json["channel"] as? Int,
              (1...11).contains(channel), let rssi = json["rssi"] as? Int,
              (-200...20).contains(rssi), let security = json["security"] as? String,
              ["WPA2", "open", "unsupported"].contains(security) else {
            throw AlfaError.message("The radio returned an invalid network listing.")
        }
        self.ssid = data
        self.bssid = bssid.lowercased()
        self.channel = channel
        self.rssi = rssi
        self.security = security
    }

    static func macAddress(_ text: String) -> Data? {
        let fields = text.split(separator: ":", omittingEmptySubsequences: false)
        guard fields.count == 6, fields.allSatisfy({ $0.count == 2 }) else { return nil }
        let bytes = fields.compactMap { UInt8($0, radix: 16) }
        guard bytes.count == 6, bytes[0] & 1 == 0, bytes.contains(where: { $0 != 0 }) else { return nil }
        return Data(bytes)
    }
}

enum RadioEvent {
    case progress(String)
    case networks([WiFiNetwork])
    case radio(Data)
    case ready(Data)
    case rate(Double)
    case ethernet(Data)
    case failed(String)
    case closed
}

final class RadioProcess {
    static let diagnostics = Logger(subsystem: "io.github.clucas.AlfaWiFi", category: "radio")
    private let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private let errors = Pipe()
    private let writeLock = NSLock()
    private let stateLock = NSLock()
    private var stopping = false
    private var closed = false
    private var receivedClosed = false
    private let callback: (RadioEvent) -> Void

    init(callback: @escaping (RadioEvent) -> Void) { self.callback = callback }

    func start(configuration: [String: Any]) throws {
        let executable: URL
        if let project = ProcessInfo.processInfo.environment["ALFA_PROJECT_DIR"], !project.isEmpty {
            let directory = URL(fileURLWithPath: project, isDirectory: true)
            executable = directory.appendingPathComponent(".venv/bin/python")
            process.currentDirectoryURL = directory
        } else {
            guard let resources = Bundle.main.resourceURL else { throw AlfaError.message("The app resources are unavailable.") }
            executable = resources.appendingPathComponent("Python/bin/python3.13")
        }
        guard FileManager.default.isExecutableFile(atPath: executable.path) else {
            throw AlfaError.message("The bundled radio runtime is missing. Rebuild the ALFA app.")
        }
        let config = try JSONSerialization.data(withJSONObject: configuration)
        guard config.count <= 4096 else { throw AlfaError.message("The radio configuration is too large.") }
        process.executableURL = executable
        process.arguments = ["-I", "-B", "-u", "-m", "alfa_rt3070.bridge_service"]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"]
        process.standardInput = input
        process.standardOutput = output
        process.standardError = errors
        guard fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            throw AlfaError.message("Could not protect the radio communication pipe.")
        }
        try process.run()
        input.fileHandleForReading.closeFile()
        output.fileHandleForWriting.closeFile()
        errors.fileHandleForWriting.closeFile()
        DispatchQueue.global(qos: .utility).async { [self] in drainErrors() }
        DispatchQueue.global(qos: .userInitiated).async { [self] in readEvents() }
        do { try write(type: 1, payload: config) }
        catch { stop(); throw error }
    }

    func transmit(_ frame: Data) throws {
        guard (14...1514).contains(frame.count) else { throw AlfaError.message("Invalid outgoing Ethernet frame size.") }
        try write(type: 2, payload: frame)
    }

    func stop() {
        stateLock.lock()
        let first = !stopping && !closed
        stopping = true
        stateLock.unlock()
        guard first else { return }
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            try? write(type: 4, payload: Data(), allowStopping: true)
            writeLock.lock()
            try? input.fileHandleForWriting.close()
            writeLock.unlock()
        }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 6) { [self] in
            if process.isRunning { process.terminate() }
        }
    }

    func terminate() {
        stop()
        if process.isRunning { process.terminate() }
    }

    private func write(type: UInt8, payload: Data, allowStopping: Bool = false) throws {
        writeLock.lock()
        defer { writeLock.unlock() }
        stateLock.lock()
        let unavailable = closed || (stopping && !allowStopping)
        stateLock.unlock()
        guard !unavailable else { throw AlfaError.message("The radio connection is closed.") }
        var record = Data([type])
        var length = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: &length) { record.append(contentsOf: $0) }
        record.append(payload)
        try input.fileHandleForWriting.write(contentsOf: record)
    }

    private func readEvents() {
        do {
            while let header = try readExactly(5, allowEOF: true) {
                let type = header[0]
                let length = header.dropFirst().reduce(0) { ($0 << 8) | Int($1) }
                guard (type == 2 && (14...1514).contains(length)) || (type == 3 && (1...65536).contains(length)) else {
                    throw AlfaError.message("The radio runtime returned an invalid message.")
                }
                guard let payload = try readExactly(length, allowEOF: false) else { break }
                if type == 2 { callback(.ethernet(payload)) }
                else { try statusEvent(payload) }
            }
        } catch {
            stateLock.lock()
            let expected = stopping
            stateLock.unlock()
            if !expected { callback(.failed(error.localizedDescription)) }
            stop()
        }
        stateLock.lock()
        let requestedStop = stopping
        stateLock.unlock()
        if !receivedClosed && !requestedStop {
            callback(.failed("The radio runtime closed its connection unexpectedly."))
        }
        if process.isRunning { stop() }
        process.waitUntilExit()
        stateLock.lock()
        let expected = stopping
        closed = true
        stateLock.unlock()
        try? output.fileHandleForReading.close()
        if !expected && process.terminationStatus != 0 {
            callback(.failed("The radio runtime stopped (exit \(process.terminationStatus))."))
        }
        callback(.closed)
    }

    private func readExactly(_ count: Int, allowEOF: Bool) throws -> Data? {
        var result = Data()
        while result.count < count {
            guard let data = try output.fileHandleForReading.read(upToCount: count - result.count), !data.isEmpty else {
                if allowEOF && result.isEmpty { return nil }
                throw AlfaError.message("The radio runtime closed an incomplete message.")
            }
            result.append(data)
        }
        return result
    }

    private func statusEvent(_ data: Data) throws {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let event = object["event"] as? String else { throw AlfaError.message("Invalid radio status.") }
        switch event {
        case "networks":
            guard let entries = object["networks"] as? [[String: Any]], entries.count <= 128 else {
                throw AlfaError.message("Invalid radio network list.")
            }
            callback(.networks(try entries.map(WiFiNetwork.init(json:))))
        case "radio", "ready":
            guard let text = object["mac"] as? String, let mac = WiFiNetwork.macAddress(text),
                  object["mtu"] as? Int == 1500 else { throw AlfaError.message("Invalid radio link configuration.") }
            callback(event == "radio" ? .radio(mac) : .ready(mac))
        case "rate":
            guard let rate = object["transmit_mbps"] as? Double,
                  [1, 2, 5.5, 6, 9, 11, 12, 18, 24, 36, 48, 54].contains(rate) else {
                throw AlfaError.message("Invalid radio transmit rate.")
            }
            if let value = object["tx_feedback"] {
                guard let feedback = value as? [String: Any],
                      let success = feedback["success"] as? Int, (0...65535).contains(success),
                      let retried = feedback["retried"] as? Int, (0...65535).contains(retried),
                      let failed = feedback["failed"] as? Int, (0...65535).contains(failed) else {
                    throw AlfaError.message("Invalid radio transmit counters.")
                }
                Self.diagnostics.info("TX rate=\(rate, privacy: .public) Mbps; last sample success=\(success, privacy: .public) retried=\(retried, privacy: .public) failed=\(failed, privacy: .public)")
            }
            callback(.rate(rate))
        case "initializing": callback(.progress("Initializing the ALFA radio…"))
        case "scanning": callback(.progress("Scanning 2.4 GHz Wi-Fi…"))
        case "connecting": callback(.progress("Authenticating with the selected Wi-Fi network…"))
        case "error":
            let message = object["message"] as? String ?? "The radio connection failed."
            callback(.failed(String(message.prefix(512))))
        case "closed": receivedClosed = true
        default: throw AlfaError.message("The radio runtime returned an unknown status event.")
        }
    }

    private func drainErrors() {
        while let data = try? errors.fileHandleForReading.read(upToCount: 4096), !data.isEmpty {}
        try? errors.fileHandleForReading.close()
    }
}
