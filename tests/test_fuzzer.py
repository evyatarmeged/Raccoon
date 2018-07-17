import unittest
import asyncio
from src.lib.fuzzer import URLFuzzer
from src.lib.host import Host
from src.utils.exceptions import FuzzerException, RequestHandlerException
from src.utils.logger import SystemOutLogger


class TestURLFuzzer(unittest.TestCase):

    def setUp(self):
        self.TestHost = Host
        self.TestHost.create_host_dir_and_set_file_logger = lambda _: None
        self.TestFuzzer = URLFuzzer
        self.TestFuzzer.get_log_file_path = lambda _, __: SystemOutLogger()
        self.loop = asyncio.get_event_loop()

    def test_bad_wordlist(self):
        host = self.TestHost("127.0.0.1", ())
        fuzzer = self.TestFuzzer(host, (), wordlist="no/such/path", num_threads=1)
        with self.assertRaises(FuzzerException):
            self.loop.run_until_complete(fuzzer.fuzz_all())

