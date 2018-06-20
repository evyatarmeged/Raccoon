import time
from functools import partial
from multiprocessing.pool import ThreadPool
from raccoon.utils.exceptions import FuzzerException, RequestHandlerException
from raccoon.utils.coloring import COLOR
from raccoon.utils.request_handler import RequestHandler


# Really wanted to use Aiohttp, doesn't play nice with proxies or TOR, disconnects unexpectedly, etc.
# Going threaded on this one


class URLFuzzer:

    def __init__(self,
                 host,
                 ignored_response_codes,
                 num_threads,
                 wordlist,
                 summary_file="raccoon/fuzzing/{}"):

        self.target = host.target
        self.ignored_error_codes = ignored_response_codes
        self.proto = host.protocol
        self.num_threads = num_threads
        self.wordlist = wordlist
        self.summary_file = summary_file.format(self.target)
        self.request_handler = RequestHandler()  # Will get the single, already initiated instance

    @staticmethod
    def _print_response(code, url, headers):
        if 300 > code >= 200:
            color = COLOR.GREEN`
        elif 400 > code >= 300:
            color = COLOR.CYAN
            url += " redirects to {}".format(headers.get("Location"))
        elif 510 > code >= 400:
            color = COLOR.RED
        else:
            color = COLOR.RESET
        print("{}[{}]{} {} ".format(color, code, COLOR.RESET, url))

    def _fetch(self, uri, sub_domain=False):
        """
        Send a HEAD request to URL and print response code if it's not in ignored_error_codes
        :param uri: URI to fuzz
        :param sub_domain: If True, build destination URL with {URL}.{HOST} else {HOST}/{URL}
        """
        if not sub_domain:
            url = "{}://{}/{}".format(self.proto, self.target, uri)
        else:
            url = "{}://{}.{}".format(self.proto, uri, self.target)
        res = self.request_handler.send("HEAD", url=url)
        if res.status_code not in self.ignored_error_codes:
            self._print_response(res.status_code, url, res.headers)

    async def fuzz_all(self, sub_domain=False):
        """
        Create a pool of threads, read the wordlist and invoke fuzz_all.
        Should be run in an event loop.
        :param sub_domain: Indicate if this is subdomain enumeration or URL busting
        """
        try:
            with open(self.wordlist, "r") as file:
                fuzzlist = file.readlines()
                fuzzlist = [x.replace("\n", "") for x in fuzzlist]
        except FileNotFoundError:
            raise FuzzerException("Cannot read URL list from {}. Will not perform Fuzzing".format(self.wordlist))

        print("Fuzzing from {}".format(self.wordlist))
        pool = ThreadPool(self.num_threads)
        pool.map(partial(self._fetch, sub_domain=sub_domain), fuzzlist)

    def write_up(self):
        # TODO: Out to file
        pass
