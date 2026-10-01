from __future__ import annotations

import argparse
import asyncio
import getpass
from ipaddress import IPv4Address
import json
import os
import signal
import sys

from .link import Link
from .radio import Radio
from .station import Station, scan
from .tunnel import Utun


def local_prompt(radio: Radio, function, message: str) -> str:
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        with radio.pause_receiving():
            return function(message)
    finally:
        signal.signal(signal.SIGINT, previous)


def display_networks(networks) -> None:
    for index, network in enumerate(networks, 1):
        print(f"{index:2}. {json.dumps(network.label, ensure_ascii=True):38} "
              f"{network.rssi:4} dBm  ch {network.channel:2}  {network.security}")


async def run(args) -> None:
    if args.command == "connect" and not args.check and os.geteuid() != 0:
        raise PermissionError("Mac network access needs administrator privileges. Run the ALFA Wi-Fi launcher.")
    radio = Radio.find()
    station = Station(radio)
    tunnel = None
    try:
        print("Initializing the ALFA RT3070…", flush=True)
        await radio.connect()
        if args.command == "probe":
            print(f"Ready: RT{radio._chip.rt:04x}, revision {radio._chip.rev:04x}, native USB driver active.")
            return
        print("Scanning 2.4 GHz channels 1–11…", flush=True)
        networks = await scan(radio)
        if args.command == "scan":
            display_networks(networks)
            print(f"Found {len(networks)} access points. No network was joined.")
            return
        candidates = [n for n in networks if n.security != "unsupported"]
        if args.ssid is not None:
            candidates = [n for n in candidates if n.label == args.ssid]
        if args.bssid is not None:
            candidates = [n for n in candidates if n.bssid.hex() == args.bssid.replace(":", "").lower()]
        if not candidates:
            raise RuntimeError("No matching supported 2.4 GHz network was found")
        if args.ssid is None and args.bssid is None:
            display_networks(candidates)
            choice = local_prompt(radio, input, "Network number: ")
            try:
                index = int(choice) - 1
            except ValueError:
                raise ValueError("Enter a network number") from None
            if not 0 <= index < len(candidates):
                raise ValueError("Network number is outside the list")
            network = candidates[index]
        else:
            network = candidates[0]
        password = None
        if network.security == "WPA2":
            if not sys.stdin.isatty():
                raise RuntimeError("The Wi-Fi password must be entered in a local terminal")
            password = local_prompt(radio, getpass.getpass, "Wi-Fi password (not saved): ")
        print(f"Joining {json.dumps(network.label)} with the ALFA…", flush=True)
        await station.connect(network, password)
        password = None
        print("Wi-Fi authentication passed. Requesting an IP address…", flush=True)
        link = Link(station)
        lease = await link.acquire()
        print(f"DHCP passed: {lease.address}; gateway {lease.router}.", flush=True)
        router_ok = await link.ping(lease.router)
        internet_ok = await link.ping(IPv4Address("1.1.1.1"))
        print(f"Gateway ping: {'passed' if router_ok else 'no reply'}. "
              f"Internet ping: {'passed' if internet_ok else 'no reply'}.", flush=True)
        if args.check:
            print("Connection test complete. Your Mac's network preference was not changed.")
            return
        tunnel = Utun.open(lease.address, lease.router, mtu=1500)
        if args.prefer:
            if not internet_ok:
                raise ConnectionError("Internet check did not pass; network preference was not changed")
            tunnel.prefer(lease.dns)
            print("ALFA selected for IPv4 traffic. IPv6 is not supported by this prototype.")
        else:
            print(f"Test interface {tunnel.name} is ready. The Mac's preferred network is unchanged.")
            print(f"Test with: curl -4 --interface {tunnel.name} https://example.com/")
        print("Press Control-C to disconnect the ALFA and restore the previous network preference.")
        print(f"This prototype stops at DHCP renewal ({lease.renewal_seconds // 60} minutes).")
        await link.bridge(tunnel)
    finally:
        try:
            if tunnel is not None:
                tunnel.close()
        finally:
            try:
                await station.disconnect()
            finally:
                await radio.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Experimental ALFA RT3070 native macOS driver")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("probe", help="Initialize the connected USB radio")
    subcommands.add_parser("scan", help="List nearby Wi-Fi networks without joining")
    connect = subcommands.add_parser("connect", help="Join a network; password is prompted locally")
    connect.add_argument("ssid", nargs="?")
    connect.add_argument("--bssid")
    connect.add_argument("--check", action="store_true", help="Test association/DHCP without administrator privileges")
    connect.add_argument("--prefer", action="store_true", help="Prefer ALFA for IPv4 after connectivity checks")
    args = parser.parse_args()
    if getattr(args, "check", False) and getattr(args, "prefer", False):
        parser.error("--check and --prefer cannot be combined")
    try:
        with asyncio.Runner() as runner:
            task = runner.get_loop().create_task(run(args))
            for signum in (signal.SIGTERM, signal.SIGHUP):
                runner.get_loop().add_signal_handler(signum, task.cancel)
            runner.run(_wait(task))
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\nALFA disconnected.")
    except Exception as error:
        print(f"ALFA: {error}", file=sys.stderr)
        sys.exit(1)


async def _wait(task):
    return await task


if __name__ == "__main__":
    main()
