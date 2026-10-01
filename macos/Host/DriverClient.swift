import Foundation
import IOKit

enum AlfaError: LocalizedError {
    case message(String)

    var errorDescription: String? {
        switch self { case .message(let message): return message }
    }
}

struct DriverStatus {
    let flags: UInt32
    let interfaceName: String
    let transmitDrops: UInt64
    let receiveDrops: UInt64
}

final class DriverClient {
    private let lock = NSLock()
    private var connection: io_connect_t = 0

    init() throws {
        guard let matching = IOServiceMatching("IOUserService") else {
            throw AlfaError.message("Could not create the ALFA control driver lookup.")
        }
        (matching as NSMutableDictionary)[kIOPropertyMatchKey] = ["IOUserClass": "AlfaControlService"]
        let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
        guard service != 0 else {
            throw AlfaError.message("The ALFA control driver is not running. Install and approve Network Support first.")
        }
        defer { IOObjectRelease(service) }
        let result = IOServiceOpen(service, mach_task_self_, 0, &connection)
        guard result == KERN_SUCCESS else {
            throw AlfaError.message("macOS could not open the ALFA control driver (\(Self.code(result))). Check the app and driver provisioning.")
        }
    }

    deinit { close() }

    func configure(mac: Data) throws {
        guard mac.count == 6 else { throw AlfaError.message("The radio returned an invalid MAC address.") }
        var configuration = Data([1])
        configuration.append(mac)
        configuration.append(0)
        try call(selector: 0, input: configuration)
    }

    func setLink(up: Bool) throws {
        lock.lock()
        defer { lock.unlock() }
        guard connection != 0 else { throw AlfaError.message("The ALFA driver connection is closed.") }
        var value: UInt64 = up ? 1 : 0
        let result = IOConnectCallScalarMethod(connection, 1, &value, 1, nil, nil)
        guard result == KERN_SUCCESS else { throw AlfaError.message("Could not update the ALFA link (\(Self.code(result))).") }
    }

    func receiveFromRadio(_ frame: Data) throws {
        guard (14...1514).contains(frame.count) else { throw AlfaError.message("Invalid Ethernet frame size.") }
        try call(selector: 2, input: frame, permitDrop: true)
    }

    func nextTransmission() throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        guard connection != 0 else { return nil }
        var buffer = [UInt8](repeating: 0, count: 1514)
        var length = buffer.count
        let result = buffer.withUnsafeMutableBytes {
            IOConnectCallStructMethod(connection, 3, nil, 0, $0.baseAddress, &length)
        }
        if result == kIOReturnNotReady { return nil }
        guard result == KERN_SUCCESS else { throw AlfaError.message("Could not read the ALFA transmit queue (\(Self.code(result))).") }
        guard (14...1514).contains(length) else { throw AlfaError.message("The driver returned an invalid Ethernet frame.") }
        return Data(buffer.prefix(length))
    }

    func status() throws -> DriverStatus {
        lock.lock()
        defer { lock.unlock() }
        guard connection != 0 else { throw AlfaError.message("The ALFA driver connection is closed.") }
        var bytes = [UInt8](repeating: 0, count: 40)
        var length = bytes.count
        let result = bytes.withUnsafeMutableBytes {
            IOConnectCallStructMethod(connection, 4, nil, 0, $0.baseAddress, &length)
        }
        guard result == KERN_SUCCESS, length == 40, Self.integer(bytes, at: 0, size: 4) == 1 else {
            throw AlfaError.message("The ALFA driver returned an unsupported status response.")
        }
        let name = String(bytes: bytes[8..<24].prefix { $0 != 0 }, encoding: .utf8) ?? ""
        guard name.isEmpty || name.range(of: "^en[0-9]+$", options: .regularExpression) != nil else {
            throw AlfaError.message("The ALFA driver returned an invalid network interface name.")
        }
        return DriverStatus(flags: UInt32(Self.integer(bytes, at: 4, size: 4)), interfaceName: name,
                            transmitDrops: Self.integer(bytes, at: 24, size: 8),
                            receiveDrops: Self.integer(bytes, at: 32, size: 8))
    }

    func close() {
        lock.lock()
        defer { lock.unlock() }
        guard connection != 0 else { return }
        var down: UInt64 = 0
        _ = IOConnectCallScalarMethod(connection, 1, &down, 1, nil, nil)
        IOServiceClose(connection)
        connection = 0
    }

    private func call(selector: UInt32, input: Data, permitDrop: Bool = false) throws {
        lock.lock()
        defer { lock.unlock() }
        guard connection != 0 else { throw AlfaError.message("The ALFA driver connection is closed.") }
        let result = input.withUnsafeBytes {
            IOConnectCallStructMethod(connection, selector, $0.baseAddress, input.count, nil, nil)
        }
        if permitDrop && (result == kIOReturnNoResources || result == kIOReturnNotReady) { return }
        guard result == KERN_SUCCESS else { throw AlfaError.message("ALFA driver operation \(selector) failed (\(Self.code(result))).") }
    }

    private static func integer(_ bytes: [UInt8], at offset: Int, size: Int) -> UInt64 {
        (0..<size).reduce(0) { $0 | UInt64(bytes[offset + $1]) << (8 * $1) }
    }

    private static func code(_ value: kern_return_t) -> String {
        String(format: "0x%08x", UInt32(bitPattern: value))
    }
}

enum UsbPresence {
    static func isConnected() -> Bool {
        guard let matching = IOServiceMatching("IOUSBHostDevice") else { return false }
        let properties = matching as NSMutableDictionary
        properties["idVendor"] = 0x148F
        properties["idProduct"] = 0x3070
        let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
        guard service != 0 else { return false }
        IOObjectRelease(service)
        return true
    }
}
