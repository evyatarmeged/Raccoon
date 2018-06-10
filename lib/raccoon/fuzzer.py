import asyncio
import random
import time
from functools import partial
from fake_useragent import UserAgent
from concurrent.futures import ThreadPoolExecutor
from utils.exceptions import FuzzerException
from utils.coloring import COLOR
from utils.request_handler import RequestHandler


# Really wanted to use Aiohttp, doesn't play nice with proxies or TOR, disconnects unexpectedly, etc.
# Going threaded on this one


class URLFuzzer:

    def __init__(self, target, request_handler, threads=100, wordlist="../wordlists/fuzzlist",
                 ignored_response_codes=(404, 504)):
        self.target = target
        self.request_handler = request_handler
        self.threads = threads
        self.wordlist = wordlist
        self.ignored_error_codes = ignored_response_codes
        self.proxies = None

    @staticmethod
    def _print_response(code, url, headers):
        if 300 > code >= 200:
            color = COLOR.GREEN
        elif 400 > code >= 300:
            color = COLOR.BLUE
            url += " redirects to {}".format(headers.get("Location"))
        elif 510 > code >= 400:
            color = COLOR.RED
        else:
            color = COLOR.RESET
        print("{}[{}]{} {} ".format(color, code, COLOR.RESET, url))

    def _fetch(self, uri, proto="https", sub_domain=False):
        """
        Send a HEAD request to URL and print response code if it's not in ignored_error_codes

        :param uri: URI to fuzz
        :param proto: use HTTP/HTTPS
        :param sub_domain: If True, build destination URL with {URL}.{HOST} else {HOST}/{URL}
        """
        if not sub_domain:
            url = "{}://{}/{}".format(proto, self.target, uri)
        else:
            url = "{}://{}.{}".format(proto, uri, self.target)
        res = self.request_handler.send("HEAD", url=url)
        if res.status_code not in self.ignored_error_codes:
            self._print_response(res.status_code, url, res.headers)

    def fuzz_all(self, proto="http", sub_domain=False):
        try:
            with open(self.wordlist, "r") as file:
                fuzzlist = file.readlines()
                fuzzlist = [x.replace("\n", "") for x in fuzzlist]
        except FileNotFoundError:
            raise FuzzerException("Cannot read URL list from {}. Will not perform Fuzzing".format(self.wordlist))

        print("Fuzzing URLs from {}".format(self.wordlist))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(partial(self._fetch, proto=proto, sub_domain=sub_domain), fuzzlist)
