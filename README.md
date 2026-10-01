# ALFA RT3070 for macOS

An experimental macOS app and DriverKit Ethernet driver for the ALFA AWUS036NEH (`148f:3070`) on Apple Silicon. The app manages the wireless connection. The driver presents it to macOS as a separate Ethernet service, so Network settings can manage its IP configuration and service priority.

This repository publishes source code. It does not include a signed app, Apple provisioning profiles, signing certificates, or private keys. Building an app that can activate its network extension requires your own Apple Developer signing setup.

## Use the native app

1. Open **ALFA Wi-Fi.app** from Applications with the USB adapter connected.
2. Click **Install Support** and complete the macOS extension approval. This is required once per installation or when macOS requests it for an update.
3. The app initializes the adapter and registers its network interface with the link disconnected.
4. Click **Scan**, select your Wi-Fi network, enter its password, and click **Connect**. Passwords are sent through a local pipe and are not saved.
5. Open **System Settings → Network**. The ALFA appears as an Ethernet service. Under the action menu, use **Set Service Order** to place it above built-in Wi-Fi if you want macOS to prefer it while connected.

Keep the app open while connected. **Disconnect**, quitting the app, or unplugging the adapter takes its link down, allowing macOS to use the remaining network services. The registered service can remain visible while disconnected. Use **Remove** in the app to uninstall this driver's system extension.

The adapter's lights turn off after a scan finishes or the connection stops. Scanning or connecting starts the radio again. While the radio is active, firmware controls the blue and green blink patterns; the lights do not distinguish scanning from a successful connection or confirm internet access.

The standard macOS Wi-Fi picker controls Apple's Wi-Fi service. Select the ALFA's wireless network in this app. macOS handles DHCP, ARP, IPv4, IPv6, and DNS through the Ethernet interface. A displayed IP address confirms address assignment; it does not by itself prove internet access.

## Limits

- 2.4 GHz channels 1–11.
- Open networks and WPA2-Personal with CCMP for pairwise and group encryption.
- No WPA3-only, enterprise authentication, required protected management frames, or TKIP.
- Adaptive legacy transmit rates from 1 to 54 Mbps, limited to rates supported by the access point. Signal strength and transmission failures control rate selection. Actual transfer speeds also depend on radio conditions and software overhead.
- No 802.11n high-throughput mode or frame aggregation.
- Standard untagged Ethernet frames, with a 1500-byte MTU. No VLAN or Ethernet bridging support.
- Development builds work on Macs authorized by their provisioning profiles. Rebuild before those profiles expire.
- Install only one build of this driver at a time, including builds that use different bundle IDs.

The driver does not require a kernel extension or a change to System Integrity Protection.

## Build and test

Requirements:

- An Apple Silicon Mac with macOS 15 or later.
- Full Xcode with the macOS SDK and DriverKit SDK 24 or later selected as the active developer directory. Command Line Tools alone are insufficient.
- [uv](https://docs.astral.sh/uv/getting-started/installation/), which the setup script uses to install an isolated ARM64 Python 3.13 environment and the pinned dependencies.

Clone the source and run the tests:

```sh
git clone https://github.com/clucas/alfa-rt3070-macos.git
cd alfa-rt3070-macos
scripts/setup.sh
macos/Host/tests/run.sh
macos/Driver/tests/run.sh
```

`scripts/setup.sh` runs the Python tests. To run them again, use `.venv/bin/python -m pytest -q`.

For an inspection build without Apple credentials:

```sh
.venv/bin/python scripts/build_macos.py
```

This creates `build/ALFA Wi-Fi.app` with an ad-hoc signature. It cannot activate the system extension.

### Build with your Apple Developer account

Register a host App ID and a separate DriverKit App ID under your team. Choose a host bundle ID that you control, such as `com.example.AlfaWiFi`; the builder derives the driver ID by adding `.Driver`.

The host requires `com.apple.developer.system-extension.install`. The driver requires the DriverKit, networking-family, and development user-client access entitlements in `macos/Driver/Driver.entitlements`. Your provisioning profiles must authorize those capabilities and the signing certificate you select. Follow Apple's [DriverKit development provisioning instructions](https://developer.apple.com/help/account/provisioning-profiles/create-a-driverkit-development-provisioning-profile/) and register the Mac used for testing. DriverKit family entitlements are [available for development](https://developer.apple.com/videos/play/wwdc2022/110373/?time=145); distribution has separate signing and entitlement requirements.

Keep these settings local:

- `ALFA_TEAM_ID`: your ten-character Apple Developer team ID.
- `ALFA_BUNDLE_ID`: your host bundle ID.
- `ALFA_SIGNING_IDENTITY`: your code-signing certificate's name or SHA-1 fingerprint; its private key must be available in your Keychain.
- `ALFA_HOST_PROFILE` and `ALFA_DRIVER_PROFILE`: paths to your host and driver provisioning profiles.

Then build:

```sh
.venv/bin/python scripts/build_macos.py \
  --team-id "$ALFA_TEAM_ID" \
  --bundle-id "$ALFA_BUNDLE_ID" \
  --identity "$ALFA_SIGNING_IDENTITY" \
  --host-profile "$ALFA_HOST_PROFILE" \
  --driver-profile "$ALFA_DRIVER_PROFILE"
```

The output is `build/ALFA Wi-Fi.app`. The script checks profile entitlements and signing certificates, packages its own Python runtime and libraries, and verifies the resulting code signature. Move the app to `/Applications`, open it, and follow the **Use the native app** steps above.

For an app or radio update that does not change DriverKit code, add `--reuse-driver /path/to/your.bundle.id.Driver.dext` to the signed build command. This preserves the existing signed extension and its version. Its identity must match the selected team and bundle IDs.

The default host bundle ID is `io.github.clucas.AlfaWiFi`. Bundle IDs and entitlement templates are public configuration, not credentials. The driver checks the caller's exact provisioned application identifier and team before allowing a client to communicate. Only one client can own the connection.

The repository ignores provisioning profiles, certificate/key files, local environment files, packet captures, and build output. Keep signing material outside the repository. A signed app embeds provisioning profiles, so do not publish a local development app as a release without preparing it for distribution.

`macos/Host` contains the SwiftUI app and packet relay. `macos/Driver` contains the virtual Ethernet DriverKit extension. `macos/Shared/AlfaProtocol.h` defines their bounded RPC interface. `src/alfa_rt3070/bridge_service.py` manages the radio child process and framed local pipes. Adapter locks live in the user's Library/Caches directory, outside the signed app.

## Standalone diagnostics

**Test ALFA Wi-Fi.command** tests authentication, DHCP, and ping through the ALFA without changing the Mac's network preference. The password is requested in the local terminal and is not saved. Stop the native app's radio session before running this diagnostic.

```sh
.venv/bin/python -m alfa_rt3070.cli scan
.venv/bin/python -m alfa_rt3070.cli connect --check
```

**ALFA Wi-Fi.command** also retains the earlier IPv4 tunnel prototype. That route is separate from the DriverKit Network service: it uses temporary routes and DNS, rejects conflicting VPN/DNS routes, and stops at DHCP renewal. Use the native app for integration with Network settings.

## Sources and license

The RT3070 transport, firmware loader, calibration, and descriptors come from [wifit3](https://github.com/derv82/wifit3), pinned to commit `053645ff19a82b9aa8430c687cc502405e6afc4c`. Only its radio implementation is used. WPA2/CCMP uses the `cryptography` package. DriverKit packet-queue setup follows Apple's [Connecting a network driver](https://developer.apple.com/documentation/pcidriverkit/connecting-a-network-driver) sample; its license is in `macos/Driver/LICENSE.apple.txt`.

The project source is GPL-2.0-only; see `LICENSE`. Dependencies retain their own licenses and are downloaded during setup rather than vendored here. The pinned `libusb-package` dependency declares Apache-2.0, which has a [GPL-2.0 compatibility issue](https://www.apache.org/licenses/GPL-compatibility.html) for combined redistribution. That dependency issue must be resolved before distributing a packaged application; this repository does not provide binary releases.

Apple documents service priority in [Change the order of network services](https://support.apple.com/guide/mac-help/change-order-network-services-mac-mchlp2711/mac).
