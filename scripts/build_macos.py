#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import fnmatch
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE_ID = "io.github.clucas.AlfaWiFi"
UNCONFIGURED_TEAM = "UNCONFIGURED"
MACHO_MAGIC = {bytes.fromhex(value) for value in ("cffaedfe", "feedfacf", "cefaedfe", "feedface", "cafebabe", "bebafeca", "cafebabf", "bfbafeca")}


def run(*args, **kwargs):
    subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def profile_for(path: Path, identifier: str, entitlements: dict, team_id: str) -> dict:
    profile = plistlib.loads(subprocess.check_output(["security", "cms", "-D", "-i", str(path)]))
    allowed = profile.get("Entitlements", {})
    if team_id not in profile.get("TeamIdentifier", []):
        raise ValueError("Provisioning profile belongs to a different team")
    if allowed.get("com.apple.developer.team-identifier") != team_id:
        raise ValueError("Provisioning profile does not authorize the selected team identifier")
    expiry = profile.get("ExpirationDate")
    if not isinstance(expiry, datetime.datetime):
        raise ValueError("Provisioning profile has no expiration date")
    if expiry.replace(tzinfo=expiry.tzinfo or datetime.timezone.utc) <= datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("Provisioning profile has expired")
    permitted_id = allowed.get("com.apple.application-identifier", allowed.get("application-identifier", ""))
    if not isinstance(permitted_id, str) or not fnmatch.fnmatchcase(f"{team_id}.{identifier}", permitted_id):
        raise ValueError(f"Provisioning profile does not match {identifier}")
    for key, value in entitlements.items():
        if key.startswith("com.apple.security."):
            continue
        permitted = allowed.get(key)
        if isinstance(value, list):
            valid = isinstance(permitted, list) and all(
                any(isinstance(pattern, str) and fnmatch.fnmatchcase(item, pattern) for pattern in permitted)
                for item in value
            )
        else:
            valid = permitted == value
        if not valid:
            raise ValueError(f"Provisioning profile does not authorize {key}")
    return profile


def package_python(destination: Path):
    base = Path(subprocess.check_output([str(ROOT / ".venv/bin/python"), "-c", "import sys;print(sys.base_prefix)"], text=True).strip())
    shutil.copytree(base, destination, symlinks=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "test", "tests"))
    site = destination / "lib/python3.13/site-packages"
    site.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT / ".venv/lib/python3.13/site-packages", site, dirs_exist_ok=True, symlinks=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "__editable__*", "*.pth", "pytest*", "_pytest", "tests"))
    shutil.copytree(ROOT / "src/alfa_rt3070", site / "alfa_rt3070", dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    run(destination / "bin/python3.13", "-I", "-B", "-c", "import alfa_rt3070.radio, alfa_rt3070.wpa, alfa_rt3070.bridge_service")


def sign(path: Path, identity: str, entitlement: Path | None = None):
    args = ["codesign", "--force", "--sign", identity]
    if identity != "-":
        args += ["--options", "runtime", "--timestamp"]
    if entitlement:
        args += ["--entitlements", str(entitlement)]
    run(*args, path)


def validate_driver_identifier(info: dict, driver_id: str):
    personality = info.get("IOKitPersonalities", {}).get("AlfaEthernetDriver", {})
    if info.get("CFBundleIdentifier") != driver_id or any(
        personality.get(key) != driver_id
        for key in ("CFBundleIdentifier", "IOMatchCategory", "IOUserServerName")
    ):
        raise ValueError("The driver has a different bundle or matching identifier")


def reuse_driver(source: Path, destination: Path, driver_id: str, team_id: str):
    with (source / "Info.plist").open("rb") as stream:
        info = plistlib.load(stream)
    validate_driver_identifier(info, driver_id)
    run("codesign", "--verify", "--strict", source)
    entitlements = plistlib.loads(subprocess.check_output(
        ["codesign", "--display", "--entitlements", ":-", str(source)], stderr=subprocess.DEVNULL))
    if entitlements.get("com.apple.application-identifier") != team_id + "." + driver_id:
        raise ValueError("The existing driver belongs to a different application")
    if entitlements.get("com.apple.developer.team-identifier") != team_id:
        raise ValueError("The existing driver belongs to a different team")
    shutil.copytree(source, destination, symlinks=True)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Build the ALFA app and DriverKit extension")
    parser.add_argument("--identity", default="-", help="Signing identity; '-' builds an ad-hoc inspection app")
    parser.add_argument("--team-id", default=os.environ.get("ALFA_TEAM_ID"),
                        help="Ten-character Apple team ID for signed builds (or ALFA_TEAM_ID)")
    parser.add_argument("--bundle-id", default=DEFAULT_BUNDLE_ID,
                        help="Host bundle ID; the DriverKit ID appends '.Driver'")
    parser.add_argument("--host-profile", type=Path)
    parser.add_argument("--driver-profile", type=Path)
    parser.add_argument("--reuse-driver", type=Path,
                        help="Package an existing signed DEXT unchanged for a radio/app-only update")
    args = parser.parse_args(argv)
    signed = args.identity != "-"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+", args.bundle_id):
        parser.error("--bundle-id must be a reverse-DNS identifier containing letters, digits, hyphens, and dots")
    if signed and not re.fullmatch(r"[A-Z0-9]{10}", args.team_id or ""):
        parser.error("Signed builds require --team-id (or ALFA_TEAM_ID) with ten uppercase letters or digits")
    if not signed:
        args.team_id = UNCONFIGURED_TEAM
    if signed and not (args.host_profile and args.driver_profile):
        parser.error("Signed builds require both the host and DriverKit provisioning profiles")
    if args.reuse_driver and not signed:
        parser.error("Reusing a driver requires a signed host build")
    return args


def main(argv=None):
    args = parse_args(argv)
    signed = args.identity != "-"
    host_id = args.bundle_id
    driver_id = host_id + ".Driver"
    team_id = args.team_id
    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    counter = build / "macos-build-number"
    number = int(counter.read_text()) + 1 if counter.exists() else 1
    profiles = {}
    entitlement_values = {}
    for kind, identifier, source, profile in (
        ("Host", host_id, ROOT / "macos/Packaging/Host.entitlements", args.host_profile),
        ("Driver", driver_id, ROOT / "macos/Driver/Driver.entitlements", args.driver_profile),
    ):
        with source.open("rb") as stream:
            entitlement_values[kind] = plistlib.load(stream)
        if signed:
            profiles[kind] = profile_for(profile, identifier, entitlement_values[kind], team_id)
            entitlement_values[kind].update({"com.apple.application-identifier": team_id + "." + identifier,
                                             "com.apple.developer.team-identifier": team_id})
            if profiles[kind]["Entitlements"].get("get-task-allow"):
                entitlement_values[kind]["get-task-allow"] = True
    with tempfile.TemporaryDirectory(prefix="macos-stage-", dir=build) as staging:
        stage = Path(staging)
        app = stage / "ALFA Wi-Fi.app"
        contents = app / "Contents"
        resources = contents / "Resources"
        (contents / "MacOS").mkdir(parents=True)
        resources.mkdir()
        shutil.copyfile(ROOT / "macos/Packaging/AppIcon.icns", resources / "AppIcon.icns")
        driver = contents / "Library/SystemExtensions" / (driver_id + ".dext")
        if args.reuse_driver:
            reuse_driver(args.reuse_driver, driver, driver_id, team_id)
        else:
            run(ROOT / "macos/Driver/build.sh", driver, env={
                **os.environ, "ALFA_TEAM_ID": team_id, "ALFA_HOST_BUNDLE_ID": host_id,
                "ALFA_BUILD_NUMBER": str(number),
            })
            with (driver / "Info.plist").open("rb") as stream:
                driver_info = plistlib.load(stream)
            validate_driver_identifier(driver_info, driver_id)
            driver_info["CFBundleVersion"] = str(number)
            with (driver / "Info.plist").open("wb") as stream:
                plistlib.dump(driver_info, stream)
        with (ROOT / "macos/Packaging/Info.plist").open("rb") as stream:
            info = plistlib.load(stream)
        info.update({"CFBundleIdentifier": host_id, "ALFADriverIdentifier": driver_id,
                     "CFBundleVersion": str(number), "ALFAHasProvisioning": signed})
        with (contents / "Info.plist").open("wb") as stream:
            plistlib.dump(info, stream)
        swift_sources = sorted((ROOT / "macos/Host").glob("*.swift"))
        if not swift_sources:
            raise ValueError("Host app sources are missing")
        run("xcrun", "swiftc", "-swift-version", "5", "-target", "arm64-apple-macos15.0", "-O",
            "-module-cache-path", build / "swift-cache", *swift_sources,
            "-framework", "SwiftUI", "-framework", "AppKit", "-framework", "IOKit", "-framework", "SystemExtensions",
            "-o", contents / "MacOS/AlfaWiFi")
        package_python(resources / "Python")
        shutil.copyfile(ROOT / "LICENSE", resources / "LICENSE")
        shutil.copytree(ROOT / "LICENSES", resources / "LICENSES")
        shutil.copyfile(ROOT / "macos/Driver/LICENSE.apple.txt", resources / "LICENSE.apple.txt")
        shutil.copyfile(ROOT / "README.md", resources / "README.md")
        for item in sorted((resources / "Python").rglob("*")):
            if item.is_file() and not item.is_symlink():
                with item.open("rb") as stream:
                    if stream.read(4) in MACHO_MAGIC:
                        sign(item, args.identity)
        for kind, bundle, profile in (("Driver", driver, args.driver_profile), ("Host", app, args.host_profile)):
            entitlement = stage / (kind + ".entitlements")
            with entitlement.open("wb") as stream:
                plistlib.dump(entitlement_values[kind], stream)
            if signed and not (kind == "Driver" and args.reuse_driver):
                profile_directory = bundle if kind == "Driver" else bundle / "Contents"
                shutil.copyfile(profile, profile_directory / "embedded.provisionprofile")
            if not (kind == "Driver" and args.reuse_driver):
                sign(bundle, args.identity, entitlement)
            if signed:
                prefix = stage / (kind + "-certificate-")
                run("codesign", "--display", "--extract-certificates=" + str(prefix), bundle, capture_output=True)
                if Path(str(prefix) + "0").read_bytes() not in profiles[kind].get("DeveloperCertificates", []):
                    raise ValueError(f"{kind} profile does not authorize the selected signing certificate")
        run("codesign", "--verify", "--deep", "--strict", app)
        run(resources / "Python/bin/python3.13", "-I", "-B", "-c", "import alfa_rt3070.radio, alfa_rt3070.wpa, alfa_rt3070.bridge_service")
        output = build / "ALFA Wi-Fi.app"
        if output.exists():
            previous = build / f"ALFA Wi-Fi.previous-{number}.app"
            output.rename(previous)
        shutil.move(app, output)
        counter.write_text(str(number))
        print(f"Built {output}")
        if not signed:
            print("Inspection build only: driver client access uses an UNCONFIGURED identity. "
                  "Rebuild with a signing identity, team ID, and provisioning profiles to activate it.")


if __name__ == "__main__":
    main()
