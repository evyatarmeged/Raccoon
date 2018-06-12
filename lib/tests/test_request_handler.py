import os
import sys
import unittest
from ..raccoon.utils.request_handler import RequestHandler
from ..raccoon.utils.exceptions import RequestHandlerException


class TestRequestHandler(unittest.TestCase):

    def test_tor_proxies(self):
        rh = RequestHandler(tor_routing=True)
        self.assertEqual(rh.proxies, {
            "http": "socks5://127.0.0.1:9050",
            "https": "socks5://127.0.0.1:9050"
        })

    def test_proxy_list(self):
        rh = RequestHandler(proxy_list="lib/wordlists/proxies")
        self.assertEqual(type(rh.proxies), list)

    def test_bad_proxy_list(self):
        with self.assertRaises(RequestHandlerException):
            rh = RequestHandler(proxy_list="no_such_list.txt")

    def test_request_handler_singleton(self):
        rh1 = RequestHandler()
        rh2 = RequestHandler()
        self.assertEqual(id(rh1), id(rh2))


if __name__ == "__main__":
    unittest.main()
