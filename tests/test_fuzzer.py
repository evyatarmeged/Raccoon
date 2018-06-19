import unittest
import asyncio
from raccoon.lib.fuzzer import URLFuzzer
from raccoon.utils.exceptions import FuzzerException, RequestHandlerException


class TestURLFuzzer(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.get_event_loop()

    def test_bad_wordlist(self):
        fuzzer = URLFuzzer("127.0.0.1", (), wordlist="no/such/path")
        with self.assertRaises(FuzzerException):
            self.loop.run_until_complete(fuzzer.fuzz_all())

    def test_bad_host(self):
        fuzzer = URLFuzzer("127.0.0.1", (), wordlist="../raccoon/wordlists/mock_wordlist")
        with self.assertRaises(RequestHandlerException):
            self.loop.run_until_complete(fuzzer.fuzz_all())