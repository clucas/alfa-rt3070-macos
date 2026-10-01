from contextlib import ExitStack
from ipaddress import IPv4Address
import plistlib
import unittest
from unittest.mock import Mock, call, patch

from alfa_rt3070.dns import TemporaryDns, _NativeDns, _configuration


class TemporaryDnsTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("alfa_rt3070.dns.sys.platform", "darwin"))
        self.uid = self.stack.enter_context(patch("alfa_rt3070.dns.os.geteuid", return_value=0))
        self.native = Mock()
        self.native.create_session.return_value = 123
        self.create_native = self.stack.enter_context(patch("alfa_rt3070.dns._NativeDns", return_value=self.native))
        self.servers = (IPv4Address("1.1.1.1"), IPv4Address("8.8.8.8"))

    def test_unique_temporary_service_and_catchall_configuration(self):
        first = TemporaryDns.open("utun77", self.servers)
        second = TemporaryDns.open("utun77", self.servers)
        self.assertNotEqual(first.key, second.key)
        self.assertTrue(first.key.startswith("State:/Network/Service/alfa-rt3070-"))
        self.assertTrue(first.key.endswith("/DNS"))
        self.assertEqual(self.native.create_session.call_args.args[1], {
            "ServerAddresses": ["1.1.1.1", "8.8.8.8"],
            "SupplementalMatchDomains": [""],
            "SupplementalMatchOrders": [0],
            "InterfaceName": "utun77",
        })

    def test_close_releases_only_its_session_once(self):
        dns = TemporaryDns.open("utun77", self.servers)
        dns.close()
        dns.close()
        self.native.close_session.assert_called_once_with(123)

    def test_context_closes_session_on_error(self):
        with self.assertRaisesRegex(RuntimeError, "connection failed"):
            with TemporaryDns.open("utun77", self.servers):
                raise RuntimeError("connection failed")
        self.native.close_session.assert_called_once_with(123)

    def test_privilege_failure_does_not_load_or_call_native_apis(self):
        self.uid.return_value = 501
        with self.assertRaises(PermissionError):
            TemporaryDns.open("utun77", self.servers)
        self.create_native.assert_not_called()

    def test_invalid_server_or_interface_fails_before_native_calls(self):
        cases = (
            ("en0", self.servers), ("utun1;bad", self.servers), ("utun77", ()),
            ("utun77", (IPv4Address("127.0.0.1"),)),
            ("utun77", (IPv4Address("0.1.2.3"),)),
            ("utun77", (IPv4Address("224.0.0.1"),)),
            ("utun77", (IPv4Address("255.255.255.255"),)),
        )
        for interface, servers in cases:
            with self.assertRaises(ValueError):
                TemporaryDns.open(interface, servers)
        self.create_native.assert_not_called()


class NativeDnsOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.native = _NativeDns.__new__(_NativeDns)
        self.native.cf = Mock()
        self.native.sc = Mock()
        self.native.sc.SCDynamicStoreCreateWithOptions.return_value = 500
        self.native.sc.SCDynamicStoreAddTemporaryValue.return_value = True
        self.native.sc.SCError.return_value = 1003
        self.native._session_option_name = Mock(return_value="UseSessionKeys")
        self.native._property_list = Mock(side_effect=[100, 200, 300, 400])
        self.key = "State:/Network/Service/alfa-rt3070-test/DNS"
        self.config = _configuration("utun77", (IPv4Address("1.1.1.1"),))

    def test_native_store_uses_session_keys_and_add_only_operation(self):
        store = self.native.create_session(self.key, self.config)
        self.assertEqual(store, 500)
        self.native._property_list.assert_has_calls([
            call("alfa-rt3070"), call({"UseSessionKeys": True}), call(self.key), call(self.config),
        ])
        self.native.sc.SCDynamicStoreCreateWithOptions.assert_called_once_with(None, 100, 200, None, None)
        self.native.sc.SCDynamicStoreAddTemporaryValue.assert_called_once_with(500, 300, 400)
        self.assertEqual(self.native.cf.CFRelease.call_args_list, [call(400), call(300), call(200), call(100)])
        self.native.close_session(store)
        self.native.cf.CFRelease.assert_called_with(500)

    def test_duplicate_key_or_publish_failure_releases_session_and_values(self):
        self.native.sc.SCDynamicStoreAddTemporaryValue.return_value = False
        with self.assertRaises(OSError):
            self.native.create_session(self.key, self.config)
        self.assertEqual(self.native.cf.CFRelease.call_args_list, [call(500), call(400), call(300), call(200), call(100)])

    def test_store_creation_failure_releases_allocated_values(self):
        self.native.sc.SCDynamicStoreCreateWithOptions.return_value = None
        with self.assertRaises(OSError):
            self.native.create_session(self.key, self.config)
        self.native.sc.SCDynamicStoreAddTemporaryValue.assert_not_called()
        self.assertEqual(self.native.cf.CFRelease.call_args_list, [call(400), call(300), call(200), call(100)])

    def test_partial_allocation_failure_releases_completed_allocations(self):
        self.native._property_list.side_effect = [100, 200, OSError("allocation failed")]
        with self.assertRaises(OSError):
            self.native.create_session(self.key, self.config)
        self.assertEqual(self.native.cf.CFRelease.call_args_list, [call(200), call(100)])
        self.native.sc.SCDynamicStoreCreateWithOptions.assert_not_called()

    def test_property_list_serialization_releases_temporary_data(self):
        self.native.cf.CFDataCreate.return_value = 100
        self.native.cf.CFPropertyListCreateWithData.return_value = 200
        result = _NativeDns._property_list(self.native, self.config)
        self.assertEqual(result, 200)
        buffer = self.native.cf.CFDataCreate.call_args.args[1]
        self.assertEqual(plistlib.loads(bytes(buffer)), self.config)
        self.native.cf.CFRelease.assert_called_once_with(100)


if __name__ == "__main__":
    unittest.main()
