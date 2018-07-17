import unittest
from raccoon_src.lib.host import Host
from raccoon_src.utils.exceptions import HostHandlerException


class TestHost(unittest.TestCase):

    def setUp(self):
        self.TestHost = Host
        self.TestHost.create_host_dir_and_set_file_logger = lambda _: None

    def test_port_extraction(self):
        host = self.TestHost("www.example.com:35000", ())
        host.parse()
        self.assertEqual(host.port, 35000)

    def test_default_port(self):
        host = self.TestHost("www.example.com", ())
        host.parse()
        self.assertEqual(host.port, 80)

    def test_proto_extraction(self):
        host = self.TestHost("https://www.example.com", ())
        host.parse()
        self.assertEqual(host.protocol, "https")

    def test_default_protocol(self):
        host = self.TestHost("127.0.0.1", ())
        host.parse()
        self.assertEqual(host.protocol, "http")

    def test_invalid_protocol(self):
        with self.assertRaises(HostHandlerException):
            host = self.TestHost("ftp://www.example.com", ())
            host.parse()

    def test_ip_detected(self):
        host = self.TestHost("10.10.10.75", ())
        host.parse()
        self.assertEqual(host.is_ip, True)

    def test_fqdn_detected(self):
        host = self.TestHost("https://www.example.com", ())
        host.parse()
        self.assertEqual(host.fqdn, "www.example.com")

    def test_naked_detected(self):
        host = self.TestHost("https://www.example.com", ())
        host.parse()
        self.assertEqual(host.naked, "example.com")
