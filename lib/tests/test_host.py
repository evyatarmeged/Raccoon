import sys
import unittest
from ..racoon.host import Host
from ..racoon.exceptions import HostHandlerException


class TestHost(unittest.TestCase):

    # Why the hell is this camel cased?
    def setUp(self):
        self.ip_host = Host("127.250.11.3")
        self.domain_proto_host = Host("https://www.example.com")
        self.ip_port_host = "127.0.0.1:9000"

    def test_port(self):
        self.assertEquals(self.ip_host.port == 80)
        self.assertEquals(self.domain_proto_host.port == 80)
        self.assertEquals(self.ip_port_host == 9000)

    def test_proto(self):
        self.assertEquals(self.ip_host.proto == "http")
        self.assertEquals(self.domain_proto_host.port == "https")
        self.assertEquals(self.ip_port_host == "http")
        with self.assertRaises(HostHandlerException):
            Host("ftp://throw.error")

    def test_is_ip(self):
        self.assertEquals(self.ip_host.is_ip is True)
        self.assertEquals(self.domain_proto_host.is_ip is False)
        self.assertEquals(self.ip_port_host.is_ip is True)

    def test_forward_slash_removal(self):
        domain = "google.com/"
        host = Host(domain)
        self.assertEquals(host.target == "google.com")


