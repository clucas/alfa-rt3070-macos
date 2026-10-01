import AppKit
import SwiftUI

final class AlfaAppDelegate: NSObject, NSApplicationDelegate {
    weak var model: AlfaViewModel?

    func applicationWillTerminate(_ notification: Notification) { model?.shutdown() }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
struct AlfaApp: App {
    @NSApplicationDelegateAdaptor(AlfaAppDelegate.self) private var delegate
    @StateObject private var model = AlfaViewModel()

    var body: some Scene {
        WindowGroup("ALFA Wi-Fi") {
            AlfaView(model: model)
                .onAppear { delegate.model = model }
        }
        .windowResizability(.contentSize)
    }
}

private struct AlfaView: View {
    @ObservedObject var model: AlfaViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Image(systemName: "antenna.radiowaves.left.and.right").font(.largeTitle)
                VStack(alignment: .leading, spacing: 3) {
                    Text("ALFA Wi-Fi").font(.title2.bold())
                    Text(model.usbPresent ? "AWUS036NEH connected by USB" : "Connect your AWUS036NEH USB adapter")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Circle().fill(model.usbPresent ? Color.green : Color.gray).frame(width: 10, height: 10)
            }

            GroupBox("macOS Network Support") {
                VStack(alignment: .leading, spacing: 10) {
                    Text(model.extensionStatus).frame(maxWidth: .infinity, alignment: .leading)
                    HStack {
                        Button(model.extensionEnabled ? "Reinstall Support" : "Install Support", action: model.installExtension)
                            .disabled(model.extensionBusy || model.busy)
                        if model.extensionPending {
                            Button("Open Approval Settings", action: model.openExtensionSettings)
                        }
                        Button("Check Status", action: model.refreshExtension).disabled(model.extensionBusy)
                        Spacer()
                        Button("Remove", action: model.removeExtension)
                            .disabled(!model.extensionEnabled || model.extensionBusy || model.busy)
                    }
                }.padding(6)
            }

            HStack {
                Text("Nearby Wi-Fi").font(.headline)
                Spacer()
                Button("Scan", action: model.scan).disabled(model.busy || !model.usbPresent)
            }
            List(selection: $model.selectedNetworkID) {
                ForEach(model.networks) { network in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(network.label).lineLimit(1)
                            Text("\(network.bssid) · channel \(network.channel)").font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(network.security == "unsupported" ? "Unsupported security" : network.security).foregroundStyle(.secondary)
                        Text("\(network.rssi) dBm").monospacedDigit().frame(width: 70, alignment: .trailing)
                    }
                    .tag(network.id)
                }
            }.frame(height: 190).disabled(model.busy)

            if model.selectedNetwork?.security == "WPA2" {
                SecureField("Wi-Fi password — used for this connection only", text: $model.password)
                    .textFieldStyle(.roundedBorder).disabled(model.busy)
            } else if model.selectedNetwork?.security == "open" {
                Text("This Wi-Fi network is open and does not encrypt its radio traffic.").font(.caption).foregroundStyle(.secondary)
            }

            HStack {
                Button("Connect", action: model.connect).disabled(!model.canConnect).keyboardShortcut(.defaultAction)
                Button("Disconnect", action: model.disconnect).disabled(!model.busy)
                Spacer()
                Button("Open Network Settings", action: model.openNetworkSettings)
            }
            VStack(alignment: .leading, spacing: 7) {
                HStack(alignment: .top) {
                    if model.busy && !model.associated { ProgressView().controlSize(.small) }
                    Text(model.status).textSelection(.enabled)
                }
                if let failure = model.failure { Text(failure).foregroundStyle(.red).textSelection(.enabled) }
                if model.associated, let rate = model.transmitRateMbps {
                    Text("Transmit link rate: \(rate.formatted()) Mbps · adjusts automatically")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if !model.interfaceName.isEmpty {
                    Text("Interface: \(model.interfaceName) · dropped packets: \(model.droppedPackets)")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Text("ALFA appears as an Ethernet connection in Network settings. Choose its service order there. Select Wi-Fi networks in this app. Keep the app open while connected.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(24)
        .frame(width: 650)
    }
}
