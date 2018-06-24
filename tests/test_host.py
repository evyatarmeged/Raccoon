import unittest
from raccoon.lib.host import Host
from raccoon.utils.exceptions import HostHandlerException


class TestHost(unittest.TestCase):

    def setUp(self):
        self.dns_records = ("A", "MX", "NS", "CNAME", "SOA")
        self.ip_host = Host("127.250.11.3", self.dns_records)
        self.domain_proto_host = Host("https://www.example.com", self.dns_records)
        self.ip_port_host = Host("127.0.0.1:9000", self.dns_records)

    def test_port(self):
        self.assertEqual(self.ip_host.port, 80)
        self.assertEqual(self.domain_proto_host.port, 443)
        self.assertEqual(self.ip_port_host.port, 9000)

    def test_proto(self):
        self.assertEqual(self.ip_host.protocol, "http")
        self.assertEqual(self.domain_proto_host.protocol, "https")
        self.assertEqual(self.ip_port_host.protocol, "http")
        with self.assertRaises(HostHandlerException):
            Host("ftp://throw.error", ())

    def test_is_ip(self):
        self.assertEqual(self.ip_host.is_ip, True)
        self.assertEqual(self.domain_proto_host.is_ip, False)
        self.assertEqual(self.ip_port_host.is_ip, True)

    def test_forward_slash_removal(self):
        domain = "google.com/"
        host = Host(domain, self.dns_records)
        self.assertEqual(host.target, "google.com")


