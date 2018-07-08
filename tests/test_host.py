import unittest
from raccoon.lib.host import Host
from raccoon.utils.exceptions import HostHandlerException


class TestHst(unittest.TestCase):

    def setUp(self):
        # Dir creation and logger error solve
        # host = Host("noonecares.com", ())
        # host.create_host_dir_and_set_file_logger = lambda: None
        pass

    def test_port_extraction(self):
        pass

    def test_default_port(self):
        pass

    def test_custom_port(self):
        pass

    def test_proto_extraction(self):
        pass

    def test_default_protocol(self):
        pass

    def test_https_protocol(self):
        pass

    def test_invalid_protocol(self):
        pass

    def test_ip_detected(self):
        pass

    def test_fqdn_detected(self):
        pass

    def test_naked_detected(self):
        pass
