import AppKit
import Darwin
import Foundation
import SystemExtensions

@MainActor
final class AlfaViewModel: NSObject, ObservableObject, @preconcurrency OSSystemExtensionRequestDelegate {
    static let driverIdentifier = Bundle.main.object(forInfoDictionaryKey: "ALFADriverIdentifier") as? String ?? "UNCONFIGURED"

    @Published private(set) var usbPresent = false
    @Published private(set) var networks: [WiFiNetwork] = []
    @Published var selectedNetworkID: String?
    @Published var password = ""
    @Published private(set) var busy = false
    @Published private(set) var associated = false
    @Published private(set) var status = "Plug in the ALFA adapter, then scan for a Wi-Fi network."
    @Published private(set) var failure: String?
    @Published private(set) var interfaceName = ""
    @Published private(set) var ipv4Address = ""
    @Published private(set) var droppedPackets: UInt64 = 0
    @Published private(set) var transmitRateMbps: Double?
    @Published private(set) var extensionEnabled = false
    @Published private(set) var extensionPending = false
    @Published private(set) var extensionBusy = false
    @Published private(set) var extensionStatus = "Network Support has not been checked."

    private var request: OSSystemExtensionRequest?
    private var requestPurpose = ""
    private var session: RadioSession?
    private var generation = UUID()
    private var timer: Timer?
    private var probeAttempted = false

    var selectedNetwork: WiFiNetwork? { networks.first { $0.id == selectedNetworkID } }
    var canConnect: Bool {
        guard !busy, usbPresent, extensionEnabled, let network = selectedNetwork else { return false }
        return network.security == "open" || (network.security == "WPA2" && !password.isEmpty)
    }

    override init() {
        super.init()
        refreshUSB()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshUSB() }
        }
        refreshExtension()
    }

    func scan() {
        guard !busy, usbPresent else { return }
        networks = []
        selectedNetworkID = nil
        password = ""
        begin(configuration: ["action": "scan"])
    }

    func connect() {
        guard canConnect, let network = selectedNetwork else { return }
        var configuration: [String: Any] = [
            "action": "connect", "ssid_b64": network.ssid.base64EncodedString(), "bssid": network.bssid,
        ]
        if network.security == "WPA2" { configuration["password"] = password }
        password = ""
        begin(configuration: configuration)
    }

    func disconnect() {
        guard let session else { return }
        status = "Disconnecting the ALFA…"
        session.stop()
        associated = false
        interfaceName = ""
        ipv4Address = ""
    }

    func shutdown() {
        timer?.invalidate()
        session?.terminate()
        session = nil
    }

    func installExtension() {
        guard !extensionBusy, !busy else { return }
        guard Bundle.main.bundleURL.path.hasPrefix("/Applications/") else {
            extensionStatus = "Move ALFA Wi-Fi.app to /Applications before installing Network Support."
            return
        }
        submit(.activationRequest(forExtensionWithIdentifier: Self.driverIdentifier, queue: .main), purpose: "install")
    }

    func removeExtension() {
        guard !extensionBusy, !busy else { return }
        submit(.deactivationRequest(forExtensionWithIdentifier: Self.driverIdentifier, queue: .main), purpose: "remove")
    }

    func refreshExtension() {
        guard !extensionBusy else { return }
        submit(.propertiesRequest(forExtensionWithIdentifier: Self.driverIdentifier, queue: .main), purpose: "inspect")
    }

    func openNetworkSettings() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.Network-Settings.extension") else { return }
        NSWorkspace.shared.open(url)
    }

    func openExtensionSettings() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") else { return }
        NSWorkspace.shared.open(url)
    }

    private func begin(configuration: [String: Any]) {
        failure = nil
        busy = true
        associated = false
        interfaceName = ""
        ipv4Address = ""
        droppedPackets = 0
        transmitRateMbps = nil
        status = "Initializing the ALFA radio…"
        let identifier = UUID()
        generation = identifier
        let newSession = RadioSession(prepareInterface: extensionEnabled) { [weak self] event in
            Task { @MainActor in
                guard let self, self.generation == identifier else { return }
                self.receive(event)
            }
        }
        session = newSession
        do { try newSession.start(configuration: configuration) }
        catch {
            newSession.stop()
            session = nil
            busy = false
            failure = error.localizedDescription
            status = "The ALFA could not start."
        }
    }

    private func receive(_ event: SessionEvent) {
        switch event {
        case .progress(let message): status = message
        case .networks(let found):
            networks = found.sorted { $0.rssi > $1.rssi }
            status = found.isEmpty ? "No 2.4 GHz networks were found. Try scanning again." : "Select your network, then enter its password."
        case .prepared(let driver):
            probeAttempted = true
            update(driver)
            status = driver.interfaceName.isEmpty
                ? "macOS is creating the ALFA network interface. You can scan for Wi-Fi."
                : "The ALFA network interface is prepared. Scan to select a Wi-Fi network."
        case .associated(let driver):
            associated = true
            update(driver)
            status = "Wi-Fi authentication passed. macOS is configuring the network connection."
        case .status(let driver): update(driver)
        case .rate(let rate): transmitRateMbps = rate
        case .failed(let message):
            failure = message
            associated = false
            status = "The ALFA connection stopped."
        case .closed:
            let wasAssociated = associated
            session = nil
            busy = false
            associated = false
            ipv4Address = ""
            transmitRateMbps = nil
            if failure == nil && (wasAssociated || status == "Disconnecting the ALFA…") {
                status = "ALFA disconnected. macOS can use your other network connections."
            }
            prepareIfNeeded()
        }
    }

    private func update(_ driver: DriverStatus) {
        interfaceName = driver.interfaceName
        droppedPackets = driver.transmitDrops &+ driver.receiveDrops
        ipv4Address = Self.address(of: interfaceName)
        if associated && !ipv4Address.isEmpty {
            status = "Connected to Wi-Fi. macOS assigned \(ipv4Address) to \(interfaceName)."
        }
    }

    private func refreshUSB() {
        let present = UsbPresence.isConnected()
        if usbPresent && !present && busy {
            session?.stop()
            failure = "The ALFA USB adapter was unplugged."
            associated = false
            status = "The ALFA adapter is disconnected."
        }
        if !present { probeAttempted = false }
        usbPresent = present
        prepareIfNeeded()
    }

    private func prepareIfNeeded() {
        guard extensionEnabled, usbPresent, !busy, !probeAttempted else { return }
        probeAttempted = true
        begin(configuration: ["action": "probe"])
    }

    private func submit(_ value: OSSystemExtensionRequest, purpose: String) {
        request = value
        requestPurpose = purpose
        extensionBusy = true
        value.delegate = self
        if purpose != "inspect" { extensionStatus = "macOS is processing the Network Support request…" }
        OSSystemExtensionManager.shared.submitRequest(value)
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        extensionPending = true
        extensionStatus = "macOS needs your approval. Open Login Items & Extensions and allow the ALFA driver. Keep this app open."
    }

    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        let purpose = requestPurpose
        self.request = nil
        extensionBusy = false
        extensionPending = false
        switch result {
        case .completed:
            if purpose == "remove" {
                extensionEnabled = false
                probeAttempted = false
                extensionStatus = "Network Support removal completed."
            } else if purpose == "install" {
                probeAttempted = false
                extensionStatus = "Installation completed. Checking the driver…"
                refreshExtension()
            }
        case .willCompleteAfterReboot:
            extensionEnabled = false
            extensionStatus = "Restart your Mac to complete the Network Support request."
        @unknown default:
            extensionStatus = "macOS returned an unknown extension result."
        }
    }

    func request(_ request: OSSystemExtensionRequest, foundProperties properties: [OSSystemExtensionProperties]) {
        self.request = nil
        extensionBusy = false
        extensionEnabled = properties.contains { $0.isEnabled && !$0.isUninstalling }
        extensionPending = properties.contains { $0.isAwaitingUserApproval }
        if extensionEnabled { extensionStatus = "Network Support is enabled." }
        else if extensionPending { extensionStatus = "Network Support is waiting for macOS approval." }
        else { extensionStatus = "Install Network Support to add the ALFA to macOS Network settings." }
        if !extensionEnabled { probeAttempted = false }
        prepareIfNeeded()
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        self.request = nil
        extensionBusy = false
        extensionPending = false
        let details = error as NSError
        extensionStatus = "Network Support: \(details.localizedDescription) (\(details.domain) \(details.code))."
    }

    private static func address(of interface: String) -> String {
        guard !interface.isEmpty else { return "" }
        var addresses: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addresses) == 0 else { return "" }
        defer { freeifaddrs(addresses) }
        var cursor = addresses
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            guard String(cString: entry.pointee.ifa_name) == interface,
                  let address = entry.pointee.ifa_addr, address.pointee.sa_family == AF_INET else { continue }
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(address, socklen_t(address.pointee.sa_len), &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let result = String(cString: buffer)
            if result != "0.0.0.0" && !result.hasPrefix("169.254.") { return result }
        }
        return ""
    }
}
