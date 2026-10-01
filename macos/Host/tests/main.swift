import Darwin
import Foundation

var checks = 0

func check(_ condition: @autoclosure () -> Bool, _ message: String) {
    checks += 1
    guard condition() else { fatalError(message) }
}

func rejects(_ message: String, _ operation: () throws -> Void) {
    do { try operation(); fatalError(message) }
    catch { checks += 1 }
}

func listing(ssid: Data = Data("My Wi-Fi".utf8)) -> [String: Any] {
    ["ssid_b64": ssid.base64EncodedString(), "bssid": "02:01:02:03:04:05",
     "channel": 6, "rssi": -53, "security": "WPA2", "label": "untrusted label"]
}

let network = try WiFiNetwork(json: listing())
let unnamed = DriverStatus(flags: 1, interfaceName: "", transmitDrops: 0, receiveDrops: 0)
let named = DriverStatus(flags: 1, interfaceName: "en9", transmitDrops: 0, receiveDrops: 0)
let immediate = try RadioSession.waitForInterfaceName(isActive: { true }, readStatus: { named })
check(immediate?.interfaceName == "en9", "Named interface must not wait for DHCP or enable flags")
var reads = 0
let canceled = try RadioSession.waitForInterfaceName(isActive: { false }, readStatus: { reads += 1; return named })
check(canceled == nil && reads == 0, "Canceled readiness wait must not read the driver")
let pending = try RadioSession.waitForInterfaceName(timeout: 0, isActive: { true }, readStatus: { unnamed })
check(pending?.interfaceName == "", "Readiness timeout must retain pending interface status")
let delayed = try RadioSession.waitForInterfaceName(isActive: { true }, readStatus: {
    reads += 1
    return reads == 1 ? unnamed : named
})
check(delayed?.interfaceName == "en9" && reads == 2, "Readiness wait must observe asynchronous interface creation")
rejects("Readiness errors must reach the session") {
    _ = try RadioSession.waitForInterfaceName(isActive: { true }, readStatus: { throw AlfaError.message("test") })
}
check(network.label == "My Wi-Fi", "SSID label must come from SSID bytes")
check(network.id == "02:01:02:03:04:05", "BSSID identifies a network")
let controlled = try WiFiNetwork(json: listing(ssid: Data("A\nB\u{202e}".utf8)))
check(controlled.label == "A\\u000aB\\u202e", "Control characters must be escaped")
let binary = try WiFiNetwork(json: listing(ssid: Data([0xff, 0xfe])))
check(binary.label == "fffe", "Binary SSIDs need deterministic labels")
for size in [0, 33] {
    rejects("Invalid SSID size accepted") { _ = try WiFiNetwork(json: listing(ssid: Data(repeating: 65, count: size))) }
}
for (key, value) in [("channel", 0 as Any), ("channel", 12), ("rssi", -201), ("security", "WPA3"),
                     ("ssid_b64", "!bad"), ("bssid", "ff:ff:ff:ff:ff:ff")] {
    var invalid = listing()
    invalid[key] = value
    rejects("Invalid network field accepted: \(key)") { _ = try WiFiNetwork(json: invalid) }
}
for invalid in ["00:00:00:00:00:00", "01:00:00:00:00:01", "02:00:00:00:00", "2:00:00:00:00:01", "02:gg:00:00:00:01"] {
    check(WiFiNetwork.macAddress(invalid) == nil, "Invalid MAC accepted")
}

func record(_ type: UInt8 = 3, _ payload: Data) -> Data {
    var result = Data([type])
    var length = UInt32(payload.count).bigEndian
    withUnsafeBytes(of: &length) { result.append(contentsOf: $0) }
    result.append(payload)
    return result
}

func status(_ value: [String: Any]) throws -> Data {
    record(3, try JSONSerialization.data(withJSONObject: value))
}

final class Capture {
    let closed = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private(set) var events: [String] = []
    private(set) var failures: [String] = []

    func receive(_ event: RadioEvent) {
        lock.lock()
        defer { lock.unlock() }
        switch event {
        case .progress: events.append("progress")
        case .networks: events.append("networks")
        case .radio: events.append("radio")
        case .ready: events.append("ready")
        case .rate(let value): events.append("rate:\(value)")
        case .ethernet: events.append("ethernet")
        case .failed(let message): events.append("failed"); failures.append(message)
        case .closed: events.append("closed"); closed.signal()
        }
    }
}

func runFixture(_ bytes: Data, stopRequested: Bool = false) throws -> Capture {
    let project = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let runtime = project.appendingPathComponent(".venv/bin/python")
    try FileManager.default.createDirectory(at: runtime.deletingLastPathComponent(), withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: project) }
    let escaped = bytes.map { String(format: "\\%03o", $0) }.joined()
    let input = stopRequested ? "/bin/dd bs=1 count=27 of=/dev/null 2>/dev/null\n" : ""
    let script = "#!/bin/sh\n" + input + "/usr/bin/printf '" + escaped + "'\n/bin/sleep 0.05\n"
    try script.write(to: runtime, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: runtime.path)
    setenv("ALFA_PROJECT_DIR", project.path, 1)
    let capture = Capture()
    let process = RadioProcess(callback: capture.receive)
    try process.start(configuration: ["action": "scan"])
    if stopRequested { process.stop() }
    check(capture.closed.wait(timeout: .now() + 10) == .success, "Fixture did not close")
    return capture
}

let closed = try status(["event": "closed"])
let found = try status(["event": "networks", "networks": [listing()], "truncated": false])
let scan = try runFixture(found + closed)
check(scan.events == ["networks", "closed"], "Successful scan sequence")
let prepared = try runFixture(status(["event": "radio", "mac": "02:01:02:03:04:05", "mtu": 1500]) + closed)
check(prepared.events == ["radio", "closed"], "Probe is distinct from association")
let ready = try runFixture(status(["event": "ready", "mac": "02:01:02:03:04:05", "mtu": 1500]) + closed)
check(ready.events == ["ready", "closed"], "Ready event shape")
let rate = try runFixture(status(["event": "rate", "transmit_mbps": 54,
                                 "tx_feedback": ["success": 1000, "retried": 2, "failed": 0]]) + closed)
check(rate.events == ["rate:54.0", "closed"], "Transmit rate must reach the app")
let fractionalRate = try runFixture(status(["event": "rate", "transmit_mbps": 5.5]) + closed)
check(fractionalRate.events == ["rate:5.5", "closed"], "Fractional CCK rate must be preserved")
let stopped = try runFixture(closed, stopRequested: true)
check(stopped.failures.isEmpty, "User stop must close without failure")

for bytes in [Data([3, 0, 1, 0, 1]), record(1, Data()), record(2, Data(repeating: 0, count: 13)),
              Data([3, 0, 0, 0, 3, 123]), Data(),
              try status(["event": "unknown"]),
              try status(["event": "rate", "transmit_mbps": 150]),
              try status(["event": "rate", "transmit_mbps": "54"]),
              try status(["event": "rate", "transmit_mbps": 54,
                          "tx_feedback": ["success": 1, "retried": 0, "failed": -1]]),
              try status(["event": "rate", "transmit_mbps": 54,
                          "tx_feedback": ["success": 65536, "retried": 0, "failed": 0]]),
              try status(["event": "ready", "mac": "02:01:02:03:04:05", "mtu": 1400]),
              try status(["event": "networks", "networks": Array(repeating: listing(), count: 129)])] {
    let invalid = try runFixture(bytes)
    check(!invalid.failures.isEmpty, "Malformed child output must fail")
    check(invalid.events.last == "closed", "Malformed child output must still close")
}

if CommandLine.arguments.count == 2 {
    setenv("ALFA_PROJECT_DIR", CommandLine.arguments[1], 1)
    let capture = Capture()
    let process = RadioProcess(callback: capture.receive)
    try process.start(configuration: ["action": "invalid"])
    check(capture.closed.wait(timeout: .now() + 10) == .success, "Python bridge did not close")
    check(capture.failures.contains("The app sent an invalid bridge message."), "Python bridge status decoding")
}
print("Host validation passed: \(checks) checks.")
