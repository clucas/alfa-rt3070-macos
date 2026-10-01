import Foundation

enum SessionEvent {
    case progress(String)
    case networks([WiFiNetwork])
    case prepared(DriverStatus)
    case associated(DriverStatus)
    case status(DriverStatus)
    case rate(Double)
    case failed(String)
    case closed
}

final class RadioSession {
    private let state = NSLock()
    private var stopped = false
    private var driver: DriverClient?
    private var radio: RadioProcess?
    private let prepareInterface: Bool
    private let callback: (SessionEvent) -> Void

    init(prepareInterface: Bool, callback: @escaping (SessionEvent) -> Void) {
        self.prepareInterface = prepareInterface
        self.callback = callback
    }

    func start(configuration: [String: Any]) throws {
        let process = RadioProcess { [weak self] event in self?.receive(event) }
        radio = process
        try process.start(configuration: configuration)
    }

    @discardableResult
    func stop() -> Bool {
        state.lock()
        let first = !stopped
        stopped = true
        let connectedDriver = driver
        driver = nil
        state.unlock()
        connectedDriver?.close()
        radio?.stop()
        return first
    }

    func terminate() {
        stop()
        radio?.terminate()
    }

    private func receive(_ event: RadioEvent) {
        if case .closed = event {
            stop()
            callback(.closed)
            return
        }
        state.lock()
        let active = !stopped
        state.unlock()
        guard active else { return }
        switch event {
        case .closed: break
        case .failed(let message): fail(message)
        case .progress(let message): callback(.progress(message))
        case .networks(let networks): callback(.networks(networks))
        case .rate(let rate): callback(.rate(rate))
        case .radio(let mac):
            guard prepareInterface else { return }
            do {
                if let connection = try prepareDriver(mac: mac),
                   let status = try waitForInterfaceName(connection) {
                    callback(.prepared(status))
                }
            } catch { fail(error.localizedDescription) }
        case .ready(let mac):
            do {
                guard let connection = try prepareDriver(mac: mac) else { return }
                guard let _ = try waitForInterfaceName(connection) else { return }
                state.lock()
                guard !stopped else { state.unlock(); return }
                do { try connection.setLink(up: true) }
                catch { state.unlock(); throw error }
                state.unlock()
                callback(.associated(try connection.status()))
                DispatchQueue.global(qos: .userInitiated).async { [self] in transmitPackets() }
            } catch { fail(error.localizedDescription) }
        case .ethernet(let frame):
            state.lock()
            let connection = driver
            let active = !stopped
            state.unlock()
            guard active else { return }
            guard let connection else { fail("The radio sent a packet before the network driver was ready."); return }
            do { try connection.receiveFromRadio(frame) }
            catch { fail(error.localizedDescription) }
        }
    }

    private func waitForInterfaceName(_ connection: DriverClient) throws -> DriverStatus? {
        try Self.waitForInterfaceName(isActive: {
            self.state.lock()
            defer { self.state.unlock() }
            return !self.stopped
        }, readStatus: connection.status)
    }

    static func waitForInterfaceName(timeout: TimeInterval = 2, isActive: () -> Bool,
                                     readStatus: () throws -> DriverStatus) throws -> DriverStatus? {
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while isActive() {
            let status = try readStatus()
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            if !status.interfaceName.isEmpty || remaining <= 0 { return status }
            Thread.sleep(forTimeInterval: min(0.1, remaining))
        }
        return nil
    }

    private func prepareDriver(mac: Data) throws -> DriverClient? {
        state.lock()
        let existing = driver
        let active = !stopped
        state.unlock()
        guard active else { return nil }
        if let existing {
            try existing.configure(mac: mac)
            return existing
        }
        let connection = try DriverClient()
        try connection.configure(mac: mac)
        state.lock()
        guard !stopped else { state.unlock(); connection.close(); return nil }
        driver = connection
        state.unlock()
        return connection
    }

    private func transmitPackets() {
        var nextStatus = Date.distantPast
        var lastTransmission = -Double.infinity
        while true {
            state.lock()
            let connection = driver
            let active = !stopped
            state.unlock()
            guard active, let connection else { return }
            do {
                if Date() >= nextStatus {
                    let status = try connection.status()
                    RadioProcess.diagnostics.info("Driver drops tx=\(status.transmitDrops, privacy: .public) rx=\(status.receiveDrops, privacy: .public)")
                    callback(.status(status))
                    nextStatus = Date().addingTimeInterval(1)
                }
                if let packet = try connection.nextTransmission() {
                    try radio?.transmit(packet)
                    lastTransmission = ProcessInfo.processInfo.systemUptime
                } else {
                    let recentlyActive = ProcessInfo.processInfo.systemUptime - lastTransmission < 0.1
                    Thread.sleep(forTimeInterval: recentlyActive ? 0.002 : 0.01)
                }
            } catch {
                state.lock()
                let expected = stopped
                state.unlock()
                if !expected { fail(error.localizedDescription) }
                return
            }
        }
    }

    private func fail(_ message: String) {
        if stop() { callback(.failed(message)) }
    }
}
