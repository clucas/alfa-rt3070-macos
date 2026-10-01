"""Temporary macOS DNS configuration, removed with its dynamic-store session."""

from __future__ import annotations

import ctypes
from ipaddress import IPv4Address
import os
import plistlib
import re
import sys
import uuid


def _configuration(interface: str, servers: tuple[IPv4Address, ...]) -> dict:
    if re.fullmatch(r"utun[0-9]+", interface) is None:
        raise ValueError("DNS requires a utun interface name")
    if not 1 <= len(servers) <= 8:
        raise ValueError("DNS requires between one and eight IPv4 servers")
    addresses = tuple(IPv4Address(server) for server in servers)
    if any(
        address.is_unspecified or address.is_multicast or address.is_loopback
        or int(address) >= 0xF0000000 or int(address) < 0x01000000
        for address in addresses
    ):
        raise ValueError("DNS servers must be unicast IPv4 addresses")
    return {
        "ServerAddresses": [str(address) for address in addresses],
        "SupplementalMatchDomains": [""],
        "SupplementalMatchOrders": [0],
        "InterfaceName": interface,
    }


class _NativeDns:
    def __init__(self):
        self.cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.sc = ctypes.CDLL("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration")
        pointer = ctypes.c_void_p
        self.cf.CFDataCreate.argtypes = [pointer, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_long]
        self.cf.CFDataCreate.restype = pointer
        self.cf.CFPropertyListCreateWithData.argtypes = [
            pointer, pointer, ctypes.c_ulong, ctypes.POINTER(ctypes.c_long), ctypes.POINTER(pointer),
        ]
        self.cf.CFPropertyListCreateWithData.restype = pointer
        self.cf.CFStringGetCString.argtypes = [pointer, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32]
        self.cf.CFStringGetCString.restype = ctypes.c_ubyte
        self.cf.CFRelease.argtypes = [pointer]
        self.cf.CFRelease.restype = None
        self.sc.SCDynamicStoreCreateWithOptions.argtypes = [pointer, pointer, pointer, pointer, pointer]
        self.sc.SCDynamicStoreCreateWithOptions.restype = pointer
        self.sc.SCDynamicStoreAddTemporaryValue.argtypes = [pointer, pointer, pointer]
        self.sc.SCDynamicStoreAddTemporaryValue.restype = ctypes.c_ubyte
        self.sc.SCError.argtypes = []
        self.sc.SCError.restype = ctypes.c_int

    def _property_list(self, value):
        serialized = plistlib.dumps(value, fmt=plistlib.FMT_BINARY)
        buffer = (ctypes.c_ubyte * len(serialized)).from_buffer_copy(serialized)
        data = self.cf.CFDataCreate(None, buffer, len(serialized))
        if not data:
            raise OSError("CoreFoundation could not allocate DNS configuration")
        error = ctypes.c_void_p()
        try:
            result = self.cf.CFPropertyListCreateWithData(None, data, 0, None, ctypes.byref(error))
            if not result:
                raise OSError("CoreFoundation could not parse DNS configuration")
            return result
        finally:
            if error.value:
                self.cf.CFRelease(error)
            self.cf.CFRelease(data)

    def _session_option_name(self) -> str:
        constant = ctypes.c_void_p.in_dll(self.sc, "kSCDynamicStoreUseSessionKeys")
        buffer = ctypes.create_string_buffer(128)
        if not self.cf.CFStringGetCString(constant, buffer, len(buffer), 0x08000100):
            raise OSError("SystemConfiguration session-key option is unavailable")
        return buffer.value.decode("utf-8")

    def create_session(self, key: str, configuration: dict) -> int:
        values = []
        store = None
        try:
            for value in ("alfa-rt3070", {self._session_option_name(): True}, key, configuration):
                values.append(self._property_list(value))
            name, options, key_ref, config_ref = values
            store = self.sc.SCDynamicStoreCreateWithOptions(None, name, options, None, None)
            if not store:
                raise OSError(f"Could not open temporary DNS session (SCError {self.sc.SCError()})")
            if not self.sc.SCDynamicStoreAddTemporaryValue(store, key_ref, config_ref):
                raise OSError(f"Could not publish temporary DNS configuration (SCError {self.sc.SCError()})")
            return store
        except BaseException:
            if store:
                self.cf.CFRelease(store)
            raise
        finally:
            for value in reversed(values):
                self.cf.CFRelease(value)

    def close_session(self, store: int) -> None:
        self.cf.CFRelease(store)


class TemporaryDns:
    def __init__(self, native: _NativeDns, store: int, key: str):
        self._native = native
        self._store = store
        self.key = key

    @classmethod
    def open(cls, interface: str, servers: tuple[IPv4Address, ...]) -> TemporaryDns:
        configuration = _configuration(interface, servers)
        if sys.platform != "darwin":
            raise OSError("Temporary DNS configuration is available only on macOS")
        if os.geteuid() != 0:
            raise PermissionError("Temporary DNS configuration requires administrator privileges")
        key = f"State:/Network/Service/alfa-rt3070-{uuid.uuid4()}/DNS"
        native = _NativeDns()
        return cls(native, native.create_session(key, configuration), key)

    def close(self) -> None:
        if self._store is not None:
            store, self._store = self._store, None
            self._native.close_session(store)

    def __enter__(self) -> TemporaryDns:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
