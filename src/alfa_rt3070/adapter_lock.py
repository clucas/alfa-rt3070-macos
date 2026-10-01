import fcntl
import os
from pathlib import Path
import pwd
import stat

_CACHE_COMPONENTS = ("Library", "Caches", "io.github.clucas.AlfaWiFi")
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _lock_owner():
    uid = os.geteuid()
    if uid == 0 and "SUDO_UID" in os.environ:
        value = os.environ["SUDO_UID"]
        if not value.isascii() or not value.isdecimal() or len(value) > 10:
            raise OSError("Invalid invoking user for the adapter lock")
        uid = int(value)
        if uid >= 2**32 - 1:
            raise OSError("Invalid invoking user for the adapter lock")
    try:
        owner = pwd.getpwuid(uid)
    except (KeyError, OverflowError):
        raise OSError("Adapter lock user does not have a local account") from None
    if owner.pw_uid != uid or not Path(owner.pw_dir).is_absolute():
        raise OSError("Invalid local account for the adapter lock")
    return owner


def default_lock_path() -> Path:
    return Path(_lock_owner().pw_dir).joinpath(*_CACHE_COMPONENTS, "adapter.lock")


def _open_directory(path, owner, *, parent=None, create=False):
    created = False
    if create:
        try:
            os.mkdir(path, mode=0o700, dir_fd=parent)
            created = True
        except FileExistsError:
            pass
    descriptor = os.open(path, _DIRECTORY_FLAGS, dir_fd=parent)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner.pw_uid):
            raise OSError("Unsafe adapter lock directory owner")
        if info.st_mode & 0o022:
            raise OSError("Adapter lock directory is writable by another user")
        if created and os.geteuid() == 0:
            os.fchown(descriptor, owner.pw_uid, owner.pw_gid)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_lock_directory(owner, path):
    if path is not None:
        return _open_directory(Path(path).parent, owner)
    descriptor = _open_directory(owner.pw_dir, owner)
    try:
        for component in _CACHE_COMPONENTS:
            child = _open_directory(component, owner, parent=descriptor, create=True)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class AdapterLock:
    def __init__(self, descriptor: int):
        self.descriptor = descriptor

    @classmethod
    def acquire(cls, path: Path | None = None):
        owner = _lock_owner()
        parent = _open_lock_directory(owner, path)
        try:
            descriptor = os.open(Path(path).name if path is not None else "adapter.lock",
                                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in (0, owner.pw_uid):
                raise OSError("Unsafe adapter lock file")
            if info.st_mode & 0o022:
                raise OSError("Adapter lock file is writable by another user")
            if os.geteuid() == 0 and info.st_uid != owner.pw_uid:
                os.fchown(descriptor, owner.pw_uid, owner.pw_gid)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("Another ALFA window is using this adapter. Stop it before opening another.") from None
            return cls(descriptor)
        except BaseException:
            os.close(descriptor)
            raise

    def close(self):
        if self.descriptor is not None:
            descriptor, self.descriptor = self.descriptor, None
            os.close(descriptor)
