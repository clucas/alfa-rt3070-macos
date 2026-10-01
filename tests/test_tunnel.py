from contextlib import ExitStack
from ipaddress import IPv4Address
import struct
import subprocess
import unittest
from unittest.mock import Mock, call, patch

from alfa_rt3070.ip import build_udp_ipv4
from alfa_rt3070.tunnel import Utun, _check_preference_routes, _run


def packet(payload=b"hello"):
    return build_udp_ipv4(payload, "192.0.2.1", "192.0.2.2", 1234, 4321)


class TunnelSetupTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("alfa_rt3070.tunnel.sys.platform", "darwin"))
        self.uid = self.stack.enter_context(patch("alfa_rt3070.tunnel.os.geteuid", return_value=0))
        self.socket = Mock()
        self.socket.fileno.return_value = 42
        self.socket.getsockopt.return_value = b"utun77\0"
        self.create_socket = self.stack.enter_context(patch("alfa_rt3070.tunnel.socket.socket", return_value=self.socket))
        self.run = self.stack.enter_context(patch("alfa_rt3070.tunnel._run"))

        def ioctl(fd, command, buffer, mutate):
            self.assertEqual(fd, 42)
            self.assertEqual(command, 0xC0644E03)
            self.assertIn(b"com.apple.net.utun_control", buffer)
            self.assertTrue(mutate)
            struct.pack_into("=I", buffer, 0, 17)

        self.stack.enter_context(patch("alfa_rt3070.tunnel.fcntl.ioctl", side_effect=ioctl))

    def test_scoped_route_only_and_idempotent_cleanup(self):
        tunnel = Utun.open("192.168.42.25", "192.168.42.1")
        self.assertEqual((tunnel.name, tunnel.fileno()), ("utun77", 42))
        self.socket.connect.assert_called_once_with((17, 0))
        self.assertEqual(self.run.call_args_list, [
            call(["/sbin/ifconfig", "utun77", "inet", "192.168.42.25", "192.168.42.25", "netmask", "255.255.255.255", "mtu", "1400", "up"]),
            call(["/sbin/route", "-n", "add", "-ifscope", "utun77", "default", "-interface", "utun77"]),
        ])
        tunnel.close()
        tunnel.close()
        self.assertEqual(self.run.call_count, 2)
        self.socket.close.assert_called_once()

    def test_no_interface_is_created_without_admin_privileges(self):
        self.uid.return_value = 501
        with self.assertRaises(PermissionError):
            Utun.open("192.168.42.25", "192.168.42.1")
        self.create_socket.assert_not_called()
        self.run.assert_not_called()

    def test_interface_closes_when_address_or_route_setup_fails(self):
        failure = subprocess.CalledProcessError(1, ["test"])
        for effects in ([failure], [None, failure]):
            with self.subTest(effects=effects):
                self.socket.reset_mock()
                self.run.reset_mock()
                self.run.side_effect = effects
                with self.assertRaises(subprocess.CalledProcessError):
                    Utun.open("192.168.42.25", "192.168.42.1")
                self.socket.close.assert_called_once()

    def test_dns_cleanup_failure_still_closes_interface(self):
        tunnel = Utun.open("192.168.42.25", "192.168.42.1")
        tunnel._dns = Mock()
        tunnel._dns.close.side_effect = OSError("DNS cleanup failed")
        with self.assertRaises(OSError):
            tunnel.close()
        self.socket.close.assert_called_once()
        tunnel.close()

    def test_invalid_interface_name_never_reaches_commands(self):
        self.socket.getsockopt.return_value = b"utun1;bad\0"
        with self.assertRaises(OSError):
            Utun.open("192.168.42.25", "192.168.42.1")
        self.run.assert_not_called()
        self.socket.close.assert_called_once()

    def test_invalid_address_or_mtu_never_creates_interface(self):
        cases = (
            ("0.0.0.0", "192.168.42.1", 1400),
            ("192.168.42.25", "127.0.0.1", 1400),
            ("192.168.42.25", "192.168.42.25", 1400),
            ("192.168.42.25", "192.168.42.1", 1600),
        )
        for address, peer, mtu in cases:
            with self.assertRaises(ValueError):
                Utun.open(address, peer, mtu=mtu)
        self.create_socket.assert_not_called()


ROUTES = """Routing tables

Internet:
Destination        Gateway         Flags       Netif Expire
default            192.168.42.1    UGScg         en0
default            link#88         UCSIg         utun77
127                127.0.0.1       UCS           lo0
192.168.42         link#14          UCS           en0
"""


class TunnelPreferenceTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("alfa_rt3070.tunnel.os.geteuid", return_value=0))
        self.run = self.stack.enter_context(patch("alfa_rt3070.tunnel._run", return_value=ROUTES))
        self.dns = Mock()
        self.dns_open = self.stack.enter_context(patch("alfa_rt3070.tunnel.TemporaryDns.open", return_value=self.dns))
        self.socket = Mock()
        self.tunnel = Utun(self.socket, "utun77", 1400)
        self.servers = (IPv4Address("1.1.1.1"),)

    def test_preference_adds_split_routes_and_temporary_dns_once(self):
        self.tunnel.prefer(self.servers)
        self.tunnel.prefer(self.servers)
        self.assertEqual(self.run.call_args_list, [
            call(["/usr/sbin/netstat", "-rn", "-f", "inet"]),
            call(["/sbin/route", "-n", "add", "-inet", "0.0.0.0/1", "-interface", "utun77"]),
            call(["/sbin/route", "-n", "add", "-inet", "128.0.0.0/1", "-interface", "utun77"]),
        ])
        self.dns_open.assert_called_once_with("utun77", self.servers)
        self.tunnel.close()
        self.tunnel.close()
        self.dns.close.assert_called_once()
        self.socket.close.assert_called_once()
        self.assertEqual(self.run.call_count, 3)

    def test_existing_split_routes_and_vpn_routes_prevent_mutation(self):
        for row in (
            "0/1 192.168.42.1 UGSc en0",
            "0.0.0.0/1 192.168.42.1 UGSc en0",
            "128.0/1 192.168.42.1 UGSc en0",
            "10/8 link#15 UCS utun4",
            "default link#15 UCS ppp0",
        ):
            self.run.reset_mock()
            self.run.return_value = ROUTES + row + "\n"
            with self.assertRaises(RuntimeError):
                self.tunnel.prefer(self.servers)
            self.assertEqual(self.run.call_count, 1)
        self.dns_open.assert_not_called()
        self.socket.close.assert_not_called()

    def test_partial_route_failure_closes_interface_without_route_deletion(self):
        self.run.side_effect = [ROUTES, "", subprocess.CalledProcessError(1, ["route", "add"])]
        with self.assertRaises(subprocess.CalledProcessError):
            self.tunnel.prefer(self.servers)
        self.socket.close.assert_called_once()
        self.dns_open.assert_not_called()
        self.assertFalse(any("delete" in item.args[0] for item in self.run.call_args_list))

    def test_existing_lan_and_host_routes_to_dns_prevent_preference(self):
        for table, dns in (
            (ROUTES, (IPv4Address("192.168.42.1"),)),
            (ROUTES + "1.1.1.1 192.168.42.1 UGHS en0\n", self.servers),
            (ROUTES + "10/8 192.168.42.1 UGS en0\n", (IPv4Address("10.5.6.7"),)),
        ):
            self.run.reset_mock()
            self.run.return_value = table
            with self.assertRaisesRegex(RuntimeError, "DNS"):
                self.tunnel.prefer(dns)
            self.assertEqual(self.run.call_count, 1)
        self.dns_open.assert_not_called()
        self.socket.close.assert_not_called()

    def test_dns_failure_rolls_back_routes_by_closing_interface(self):
        self.dns_open.side_effect = OSError("DNS unavailable")
        with self.assertRaises(OSError):
            self.tunnel.prefer(self.servers)
        self.socket.close.assert_called_once()
        with self.assertRaises(OSError):
            self.tunnel.prefer(self.servers)

    def test_changed_dns_requires_a_new_connection(self):
        self.tunnel.prefer(self.servers)
        with self.assertRaises(RuntimeError):
            self.tunnel.prefer((IPv4Address("8.8.8.8"),))
        self.dns_open.assert_called_once()

    def test_unknown_route_table_format_fails_closed(self):
        for table in ("", "permission denied", "Destination Gateway Flags\ndefault x y", ROUTES + "truncated\n"):
            with self.assertRaises(OSError):
                _check_preference_routes(table, "utun77")


class TunnelPacketTests(unittest.TestCase):
    def setUp(self):
        self.socket = Mock()
        self.tunnel = Utun(self.socket, "utun77", 1400)

    def test_ipv4_headers_are_network_byte_order(self):
        data = packet()
        self.socket.recv.return_value = b"\0\0\0\x02" + data
        self.assertEqual(self.tunnel.read_packet(), data)
        self.socket.send.return_value = len(data) + 4
        self.tunnel.write_packet(data)
        self.socket.send.assert_called_once_with(b"\0\0\0\x02" + data)

    def test_read_rejects_ipv6_truncated_and_oversize_packets(self):
        for frame in (b"\0\0\0\x1e" + packet(), b"\0\0", b"\0\0\0\x02" + packet()[:-1], b"\0\0\0\x02" + packet(b"x" * 1400)):
            self.socket.recv.return_value = frame
            with self.assertRaises(ValueError):
                self.tunnel.read_packet()

    def test_eof_and_short_write_report_failure(self):
        self.socket.recv.return_value = b""
        with self.assertRaises(ConnectionError):
            self.tunnel.read_packet()
        self.socket.send.return_value = 4
        with self.assertRaises(OSError):
            self.tunnel.write_packet(packet())

    def test_invalid_output_is_never_written(self):
        with self.assertRaises(ValueError):
            self.tunnel.write_packet(b"not IP")
        self.socket.send.assert_not_called()

    def test_commands_use_argument_arrays_without_shell(self):
        with patch("alfa_rt3070.tunnel.subprocess.run") as run:
            _run(["/sbin/route", "-n", "get", "default"])
        args, kwargs = run.call_args
        self.assertEqual(args, (["/sbin/route", "-n", "get", "default"],))
        self.assertNotIn("shell", kwargs)
        self.assertTrue(kwargs["check"])
        self.assertEqual(kwargs["timeout"], 5)


if __name__ == "__main__":
    unittest.main()
