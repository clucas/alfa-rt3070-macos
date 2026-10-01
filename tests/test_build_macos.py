import datetime
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build_macos", ROOT / "scripts/build_macos.py")
build_macos = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_macos)
TEAM = "TESTTEAM01"
HOST = "com.example.AlfaWiFi"
DRIVER = HOST + ".Driver"


@pytest.fixture(autouse=True)
def no_team_environment(monkeypatch):
    monkeypatch.delenv("ALFA_TEAM_ID", raising=False)


def profile(identifier=HOST, entitlements=None):
    return {
        "TeamIdentifier": [TEAM],
        "ExpirationDate": datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None, microsecond=0)
        + datetime.timedelta(days=30),
        "Entitlements": {
            "com.apple.application-identifier": TEAM + "." + identifier,
            "com.apple.developer.team-identifier": TEAM,
            **(entitlements or {}),
        },
        "DeveloperCertificates": [b"test-certificate"],
    }


def driver_info(identifier=DRIVER):
    info = plistlib.loads((ROOT / "macos/Driver/Info.plist").read_bytes())
    info["CFBundleIdentifier"] = identifier
    for key in ("CFBundleIdentifier", "IOMatchCategory", "IOUserServerName"):
        info["IOKitPersonalities"]["AlfaEthernetDriver"][key] = identifier
    return info


def signed_args():
    return ["--identity", "Apple Development: Test", "--host-profile", "host.profile",
            "--driver-profile", "driver.profile"]


def test_signed_build_uses_explicit_team_before_environment(monkeypatch):
    monkeypatch.setenv("ALFA_TEAM_ID", "OTHERTEAM1")
    args = build_macos.parse_args(signed_args() + ["--team-id", TEAM, "--bundle-id", HOST])
    assert args.team_id == TEAM
    assert args.bundle_id == HOST


def test_signed_build_accepts_environment_team(monkeypatch):
    monkeypatch.setenv("ALFA_TEAM_ID", TEAM)
    assert build_macos.parse_args(signed_args()).team_id == TEAM


@pytest.mark.parametrize("team", [None, "", "short", "UNCONFIGURED", "testteam01", "TESTTEAM010"])
def test_signed_build_requires_valid_explicit_team(team):
    args = signed_args() + ([] if team is None else ["--team-id", team])
    with pytest.raises(SystemExit) as error:
        build_macos.parse_args(args)
    assert error.value.code == 2


@pytest.mark.parametrize("bundle", ["", "AlfaWiFi", ".com.example", "com..example", "com.example.",
                                   "com.example/*", 'com.example."Injected', "com.example\nInjected"])
def test_bundle_identifier_cannot_inject_compiler_or_plist_values(bundle):
    with pytest.raises(SystemExit):
        build_macos.parse_args(["--bundle-id", bundle])


def test_inspection_build_does_not_inherit_signing_identity(monkeypatch):
    monkeypatch.setenv("ALFA_TEAM_ID", TEAM)
    args = build_macos.parse_args(["--team-id", "OTHERTEAM1"])
    assert args.identity == "-"
    assert args.team_id == "UNCONFIGURED"
    assert args.bundle_id == "io.github.clucas.AlfaWiFi"


def test_signed_build_requires_both_profiles():
    with pytest.raises(SystemExit):
        build_macos.parse_args(["--identity", "Apple Development: Test", "--team-id", TEAM])


def test_inspection_build_cannot_reuse_signed_driver():
    with pytest.raises(SystemExit):
        build_macos.parse_args(["--reuse-driver", "driver.dext"])


@pytest.mark.parametrize("identifier", [HOST, "com.example.*"])
def test_profile_authorizes_selected_application_and_required_capabilities(monkeypatch, identifier):
    required = {"com.apple.developer.driverkit": True,
                "com.apple.developer.driverkit.userclient-access": [DRIVER],
                "com.apple.security.app-sandbox": True}
    allowed = {"com.apple.developer.driverkit": True,
               "com.apple.developer.driverkit.userclient-access": ["com.example.*"]}
    value = profile(identifier, allowed)
    monkeypatch.setattr(build_macos.subprocess, "check_output", lambda *args, **kwargs: plistlib.dumps(value))
    assert build_macos.profile_for(Path("test.profile"), HOST, required, TEAM) == value


@pytest.mark.parametrize("mutation, message", [
    (lambda value: value.update(TeamIdentifier=["OTHERTEAM1"]), "different team"),
    (lambda value: value["Entitlements"].update({"com.apple.developer.team-identifier": "OTHERTEAM1"}), "team identifier"),
    (lambda value: value["Entitlements"].update({"com.apple.application-identifier": TEAM + ".com.other.App"}), "does not match"),
    (lambda value: value["Entitlements"].update({"com.apple.application-identifier": "OTHERTEAM1." + HOST}), "does not match"),
    (lambda value: value.update(ExpirationDate=datetime.datetime(2000, 1, 1)), "expired"),
    (lambda value: value.pop("ExpirationDate"), "no expiration"),
    (lambda value: value["Entitlements"].update({"com.apple.developer.driverkit": False}), "does not authorize"),
])
def test_profile_rejects_identity_expiry_or_capability_mismatch(monkeypatch, mutation, message):
    value = profile(entitlements={"com.apple.developer.driverkit": True})
    mutation(value)
    monkeypatch.setattr(build_macos.subprocess, "check_output", lambda *args, **kwargs: plistlib.dumps(value))
    with pytest.raises(ValueError, match=message):
        build_macos.profile_for(Path("test.profile"), HOST, {"com.apple.developer.driverkit": True}, TEAM)


def test_profile_rejects_unpermitted_list_member(monkeypatch):
    value = profile(entitlements={"com.apple.developer.driverkit.userclient-access": ["com.other.*"]})
    monkeypatch.setattr(build_macos.subprocess, "check_output", lambda *args, **kwargs: plistlib.dumps(value))
    with pytest.raises(ValueError, match="does not authorize"):
        build_macos.profile_for(Path("test.profile"), HOST,
                               {"com.apple.developer.driverkit.userclient-access": [DRIVER]}, TEAM)


@pytest.fixture
def reusable_driver(tmp_path, monkeypatch):
    source = tmp_path / "source.dext"
    source.mkdir()
    (source / "Info.plist").write_bytes(plistlib.dumps(driver_info()))
    (source / "AlfaEthernetDriver").write_bytes(b"signed-driver-placeholder")
    entitlements = {"com.apple.application-identifier": TEAM + "." + DRIVER,
                    "com.apple.developer.team-identifier": TEAM}
    commands = []
    monkeypatch.setattr(build_macos, "run", lambda *args, **kwargs: commands.append(args))
    monkeypatch.setattr(build_macos.subprocess, "check_output",
                        lambda *args, **kwargs: plistlib.dumps(entitlements))
    return source, tmp_path / "output.dext", entitlements, commands


def test_reuse_accepts_unchanged_signed_driver_without_extra_metadata(reusable_driver):
    source, destination, _, commands = reusable_driver
    build_macos.reuse_driver(source, destination, DRIVER, TEAM)
    assert commands == [("codesign", "--verify", "--strict", source)]
    assert (destination / "AlfaEthernetDriver").read_bytes() == b"signed-driver-placeholder"
    assert (destination / "Info.plist").read_bytes() == (source / "Info.plist").read_bytes()


@pytest.mark.parametrize("key,value", [
    ("com.apple.application-identifier", "OTHERTEAM1." + DRIVER),
    ("com.apple.application-identifier", TEAM + ".com.other.App.Driver"),
    ("com.apple.application-identifier", TEAM + ".*"),
    ("com.apple.developer.team-identifier", "OTHERTEAM1"),
    ("com.apple.developer.team-identifier", ""),
])
def test_reuse_rejects_signed_application_or_team_mismatch(reusable_driver, key, value):
    source, destination, entitlements, _ = reusable_driver
    entitlements[key] = value
    with pytest.raises(ValueError, match="different (application|team)"):
        build_macos.reuse_driver(source, destination, DRIVER, TEAM)
    assert not destination.exists()


@pytest.mark.parametrize("key", ["CFBundleIdentifier", "IOMatchCategory", "IOUserServerName", "root"])
def test_reuse_rejects_bundle_and_matching_identifier_mismatch(reusable_driver, key):
    source, destination, _, commands = reusable_driver
    info = driver_info()
    if key == "root":
        info["CFBundleIdentifier"] = "com.other.Driver"
    else:
        info["IOKitPersonalities"]["AlfaEthernetDriver"][key] = "com.other.Driver"
    (source / "Info.plist").write_bytes(plistlib.dumps(info))
    with pytest.raises(ValueError, match="bundle or matching identifier"):
        build_macos.reuse_driver(source, destination, DRIVER, TEAM)
    assert not commands
    assert not destination.exists()


def test_reuse_requires_valid_signature(reusable_driver, monkeypatch):
    source, destination, _, _ = reusable_driver
    def invalid_signature(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args)
    monkeypatch.setattr(build_macos, "run", invalid_signature)
    with pytest.raises(subprocess.CalledProcessError):
        build_macos.reuse_driver(source, destination, DRIVER, TEAM)
    assert not destination.exists()


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS driver packaging uses plutil")
@pytest.mark.parametrize("team,host", [(None, HOST), (TEAM, HOST), (TEAM, "net.example.Custom-WiFi")])
def test_driver_script_uses_identity_in_compiler_and_all_matching_keys(tmp_path, team, host):
    tools = tmp_path / "tools"
    tools.mkdir()
    xcrun = tools / "xcrun"
    xcrun.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "with open(os.environ['ALFA_TEST_CALLS'], 'a') as stream:\n"
        "    stream.write(json.dumps(args) + '\\n')\n"
        "if '--show-sdk-path' in args: print('/test/DriverKit.sdk')\n"
        "if '-o' in args: pathlib.Path(args[args.index('-o') + 1]).write_bytes(b'unsigned-test-output')\n"
    )
    xcrun.chmod(0o755)
    calls = tmp_path / "calls.jsonl"
    environment = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                   "ALFA_HOST_BUNDLE_ID": host, "ALFA_TEST_CALLS": str(calls)}
    if team is not None:
        environment["ALFA_TEAM_ID"] = team
    output = tmp_path / "test.dext"
    subprocess.run(["bash", str(ROOT / "macos/Driver/build.sh"), str(output)],
                   env=environment, check=True, capture_output=True)
    actual = plistlib.loads((output / "Info.plist").read_bytes())
    expected = driver_info(host + ".Driver")
    assert actual == expected
    compiler_calls = [json.loads(line) for line in calls.read_text().splitlines() if '"clang++"' in line]
    assert len(compiler_calls) == 7
    for command in compiler_calls:
        assert f'-DALFA_TEAM_IDENTIFIER="{team or "UNCONFIGURED"}"' in command
        assert f'-DALFA_HOST_APPLICATION_IDENTIFIER="{team or "UNCONFIGURED"}.{host}"' in command


@pytest.mark.parametrize("variable,value", [("ALFA_TEAM_ID", "bad-team"),
                                            ("ALFA_HOST_BUNDLE_ID", 'com.example."Injected')])
def test_driver_script_rejects_invalid_identity_before_compilation(tmp_path, variable, value):
    output = tmp_path / "test.dext"
    result = subprocess.run(["bash", str(ROOT / "macos/Driver/build.sh"), str(output)],
                            env={**os.environ, variable: value}, capture_output=True)
    assert result.returncode == 2
    assert not output.exists()


@pytest.mark.parametrize("signed", [False, True])
def test_packaging_propagates_custom_identity_without_credentials(tmp_path, monkeypatch, signed):
    for relative in ("macos/Packaging/Info.plist", "macos/Packaging/Host.entitlements", "macos/Driver/Driver.entitlements"):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    (tmp_path / "macos/Host").mkdir()
    (tmp_path / "macos/Host/Placeholder.swift").touch()
    (tmp_path / "LICENSE").write_text("test license")
    (tmp_path / "README.md").write_text("test readme")
    monkeypatch.setattr(build_macos, "ROOT", tmp_path)
    monkeypatch.setenv("ALFA_TEAM_ID", TEAM)
    driver_builds = []
    signed_bundles = {}

    def fake_run(*args, **kwargs):
        if str(args[0]).endswith("/Driver/build.sh"):
            driver_builds.append(kwargs["env"])
            destination = Path(args[1])
            destination.mkdir(parents=True)
            (destination / "Info.plist").write_bytes(plistlib.dumps(driver_info()))
        elif args[0] == "codesign":
            for argument in args:
                if str(argument).startswith("--extract-certificates="):
                    Path(str(argument).split("=", 1)[1] + "0").write_bytes(b"test-certificate")

    def fake_sign(path, identity, entitlement=None):
        if entitlement:
            signed_bundles[path.suffix] = (identity, plistlib.loads(entitlement.read_bytes()))

    monkeypatch.setattr(build_macos, "run", fake_run)
    monkeypatch.setattr(build_macos, "sign", fake_sign)
    monkeypatch.setattr(build_macos, "package_python", lambda destination: destination.mkdir())
    monkeypatch.setattr(build_macos.subprocess, "check_output",
                        lambda args, **kwargs: Path(args[-1]).read_bytes())
    args = ["--bundle-id", HOST]
    if signed:
        args += ["--identity", "Apple Development: Test", "--team-id", TEAM]
        for kind, identifier in (("Host", HOST), ("Driver", DRIVER)):
            relative = "macos/Packaging/Host.entitlements" if kind == "Host" else "macos/Driver/Driver.entitlements"
            entitlements = plistlib.loads((tmp_path / relative).read_bytes())
            path = tmp_path / (kind + ".profile")
            path.write_bytes(plistlib.dumps(profile(identifier, entitlements)))
            args += ["--" + kind.lower() + "-profile", str(path)]
    build_macos.main(args)
    contents = tmp_path / "build/ALFA Wi-Fi.app/Contents"
    info = plistlib.loads((contents / "Info.plist").read_bytes())
    assert info["CFBundleIdentifier"] == HOST
    assert info["ALFADriverIdentifier"] == DRIVER
    assert info["ALFAHasProvisioning"] is signed
    assert (contents / "Library/SystemExtensions" / (DRIVER + ".dext")).is_dir()
    assert len(driver_builds) == 1
    assert driver_builds[0]["ALFA_HOST_BUNDLE_ID"] == HOST
    assert driver_builds[0]["ALFA_TEAM_ID"] == (TEAM if signed else "UNCONFIGURED")
    for suffix, identifier in ((".app", HOST), (".dext", DRIVER)):
        identity, entitlements = signed_bundles[suffix]
        assert identity == ("Apple Development: Test" if signed else "-")
        if signed:
            assert entitlements["com.apple.application-identifier"] == TEAM + "." + identifier
            assert entitlements["com.apple.developer.team-identifier"] == TEAM
        else:
            assert "com.apple.application-identifier" not in entitlements
            assert "com.apple.developer.team-identifier" not in entitlements
