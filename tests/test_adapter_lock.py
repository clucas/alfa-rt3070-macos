import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from alfa_rt3070 import adapter_lock
from alfa_rt3070.adapter_lock import AdapterLock


def test_second_driver_cannot_take_over_active_adapter(tmp_path):
    path = tmp_path / "adapter.lock"
    first = AdapterLock.acquire(path)
    try:
        with pytest.raises(RuntimeError, match="Another ALFA"):
            AdapterLock.acquire(path)
    finally:
        first.close()
    second = AdapterLock.acquire(path)
    second.close()
    second.close()


def test_refuses_symlink_lock(tmp_path):
    target = tmp_path / "target"
    target.write_text("preserved")
    link = tmp_path / "adapter.lock"
    link.symlink_to(target)
    with pytest.raises(OSError):
        AdapterLock.acquire(link)
    assert target.read_text() == "preserved"


def test_refuses_other_user_writable_lock(tmp_path):
    path = tmp_path / "adapter.lock"
    path.touch(mode=0o600)
    path.chmod(0o666)
    with pytest.raises(OSError, match="writable"):
        AdapterLock.acquire(path)


@pytest.fixture
def account_home(tmp_path, monkeypatch):
    home = tmp_path / "account-home"
    home.mkdir(mode=0o700)
    uid, gid = os.geteuid(), os.getegid()
    account = SimpleNamespace(pw_uid=uid, pw_gid=gid, pw_dir=str(home))
    monkeypatch.setattr(adapter_lock.pwd, "getpwuid", lambda requested: account)
    monkeypatch.delenv("SUDO_UID", raising=False)
    return account


def test_default_lock_uses_account_cache_outside_source_or_bundle(account_home, monkeypatch):
    expected = Path(account_home.pw_dir) / "Library/Caches/io.github.clucas.AlfaWiFi/adapter.lock"
    assert adapter_lock.default_lock_path() == expected
    monkeypatch.setattr(adapter_lock, "__file__", "/Applications/ALFA Wi-Fi.app/Contents/Resources/Python/lib/site-packages/alfa_rt3070/adapter_lock.py")
    first = AdapterLock.acquire()
    try:
        assert expected.is_file()
        assert expected.stat().st_mode & 0o777 == 0o600
        assert expected.parent.stat().st_mode & 0o777 == 0o700
        monkeypatch.setattr(adapter_lock, "__file__", "/Users/test/Developer/alfa-rt3070/src/alfa_rt3070/adapter_lock.py")
        assert adapter_lock.default_lock_path() == expected
        with pytest.raises(RuntimeError, match="Another ALFA"):
            AdapterLock.acquire(expected)
    finally:
        first.close()


def test_administrator_cli_and_normal_app_share_one_user_lock(account_home, monkeypatch):
    first = AdapterLock.acquire()
    try:
        expected = adapter_lock.default_lock_path()
        monkeypatch.setattr(adapter_lock.os, "geteuid", lambda: 0)
        monkeypatch.setenv("SUDO_UID", str(account_home.pw_uid))
        assert adapter_lock.default_lock_path() == expected
        with pytest.raises(RuntimeError, match="Another ALFA"):
            AdapterLock.acquire()
    finally:
        first.close()


def test_non_root_cannot_redirect_lock_with_sudo_uid(account_home, monkeypatch):
    monkeypatch.setenv("SUDO_UID", "0")
    assert adapter_lock.default_lock_path().is_relative_to(account_home.pw_dir)


@pytest.mark.parametrize("value", ["", "-1", "1.0", "+501", " 501", "５０１", "4294967295", "9" * 100])
def test_root_rejects_invalid_invoking_uid(value, monkeypatch):
    monkeypatch.setattr(adapter_lock.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", value)
    with pytest.raises(OSError, match="Invalid invoking user"):
        adapter_lock.default_lock_path()


def test_root_requires_existing_account_for_invoking_uid(monkeypatch):
    monkeypatch.setattr(adapter_lock.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "123456")

    def missing(uid):
        raise KeyError(uid)

    monkeypatch.setattr(adapter_lock.pwd, "getpwuid", missing)
    with pytest.raises(OSError, match="local account"):
        adapter_lock.default_lock_path()


@pytest.mark.parametrize("field, value", [("pw_uid", -1), ("pw_dir", "relative/home")])
def test_account_identity_and_absolute_home_are_required(account_home, field, value):
    setattr(account_home, field, value)
    with pytest.raises(OSError, match="Invalid local account"):
        adapter_lock.default_lock_path()


@pytest.mark.parametrize("component", ["Library", "Library/Caches", "Library/Caches/io.github.clucas.AlfaWiFi"])
def test_default_lock_rejects_symlinked_cache_directories(account_home, tmp_path, component):
    link = Path(account_home.pw_dir) / component
    link.parent.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "redirected"
    target.mkdir()
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(OSError):
        AdapterLock.acquire()
    assert list(target.iterdir()) == []


@pytest.mark.parametrize("mode", [0o777, 0o770])
def test_refuses_other_user_writable_parent(tmp_path, mode):
    directory = tmp_path / "unsafe"
    directory.mkdir()
    directory.chmod(mode)
    with pytest.raises(OSError, match="directory is writable"):
        AdapterLock.acquire(directory / "adapter.lock")
    assert not (directory / "adapter.lock").exists()


def test_refuses_symlink_parent(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "parent"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(OSError):
        AdapterLock.acquire(link / "adapter.lock")


def test_refuses_hardlinked_lock(tmp_path):
    path = tmp_path / "adapter.lock"
    path.touch(mode=0o600)
    os.link(path, tmp_path / "alias")
    with pytest.raises(OSError, match="Unsafe adapter lock file"):
        AdapterLock.acquire(path)


@pytest.mark.parametrize("target", ["directory", "file"])
def test_refuses_foreign_owner_before_locking(tmp_path, monkeypatch, target):
    original = os.fstat

    def info(descriptor):
        result = original(descriptor)
        matches = stat.S_ISDIR(result.st_mode) if target == "directory" else stat.S_ISREG(result.st_mode)
        if matches:
            return SimpleNamespace(st_mode=result.st_mode, st_uid=os.geteuid() + 1, st_nlink=result.st_nlink)
        return result

    monkeypatch.setattr(adapter_lock.os, "fstat", info)
    with pytest.raises(OSError, match="Unsafe adapter lock"):
        AdapterLock.acquire(tmp_path / "adapter.lock")


def test_root_assigns_new_cache_directories_to_invoking_user(account_home, monkeypatch):
    monkeypatch.setattr(adapter_lock.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", str(account_home.pw_uid))
    ownership = []
    monkeypatch.setattr(adapter_lock.os, "fchown", lambda fd, uid, gid: ownership.append((uid, gid)))
    lock = AdapterLock.acquire()
    lock.close()
    assert ownership == [(account_home.pw_uid, account_home.pw_gid)] * 3
