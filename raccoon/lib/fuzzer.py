import time
from functools import partial
from multiprocessing.pool import ThreadPool
from raccoon.utils.exceptions import FuzzerException, RequestHandlerException
from raccoon.utils.coloring import COLOR, COLORED_COMBOS
from raccoon.utils.request_handler import RequestHandler
from raccoon.utils.help_utils import HelpUtilities
from raccoon.utils.logger import Logger, SystemOutLogger


# Really wanted to use Aiohttp, doesn't play nice with proxies or TOR, disconnects unexpectedly, etc.
# Going threaded on this one


class URLFuzzer:

    def __init__(self,
                 host,
                 ignored_response_codes,
                 num_threads,
                 wordlist,
                 follow_redirects=False):

        self.target = host.target
        self.ignored_error_codes = ignored_response_codes
        self.proto = host.protocol
        self.port = host.port
        self.num_threads = num_threads
        self.wordlist = wordlist
        self.follow_redirects = follow_redirects
        self.request_handler = RequestHandler()  # Will get the single, already initiated instance
        self.logger = None

    def _log_response(self, code, url, headers):
        if 300 > code >= 200:
            color = COLOR.GREEN
        elif 400 > code >= 300:
            color = COLOR.BLUE
            url += " redirects to {}".format(headers.get("Location"))
        elif 510 > code >= 400:
            color = COLOR.RED
        else:
            color = COLOR.RESET
        self.logger.info("{}[{}]{} {}".format(
            color, code, COLOR.RESET, url))

    def _fetch(self, uri, sub_domain=False):
        """
        Send a HEAD request to URL and print response code if it's not in ignored_error_codes
        :param uri: URI to fuzz
        :param sub_domain: If True, build destination URL with {URL}.{HOST} else {HOST}/{URL}
        """
        if not sub_domain:
            if self.port != 80 and self.port != 443:
                url = "{}://{}:{}/{}".format(self.proto, self.target, self.port, uri)
            else:
                url = "{}://{}/{}".format(self.proto, self.target, uri)
        else:
            if self.port != 80 and self.port != 443:
                url = "{}://{}.{}:{}".format(self.proto, uri, self.target, self.port)
            else:
                url = "{}://{}.{}".format(self.proto, uri, self.target)

        try:
            res = self.request_handler.send("HEAD", url=url, allow_redirects=self.follow_redirects)
            if res.status_code not in self.ignored_error_codes:
                self._log_response(res.status_code, url, res.headers)
        except (AttributeError, RequestHandlerException):
            # res is None or another error occurred
            pass

    def get_log_file_path(self, path):
        if path:
            log_file = path
        else:
            log_file = "{}/url_fuzz.txt".format(self.target)

        return Logger(HelpUtilities.get_output_path(log_file))

    async def fuzz_all(self, sub_domain=False, log_file_path=None):
        """
        Create a pool of threads, read the wordlist and invoke fuzz_all.
        Should be run in an event loop.
        :param sub_domain: Indicate if this is subdomain enumeration or URL busting
        :param log_file_path: Log subdomain enum results to this path.
        """

        self.logger = self.get_log_file_path(log_file_path)
        try:
            with open(self.wordlist, "r") as file:
                fuzzlist = file.readlines()
                fuzzlist = [x.replace("\n", "") for x in fuzzlist]
        except FileNotFoundError:
            raise FuzzerException("Cannot read URL list from {}. Will not perform Fuzzing".format(self.wordlist))

        self.logger.info("{} Fuzzing from {}".format(COLORED_COMBOS.INFO, self.wordlist))
        pool = ThreadPool(self.num_threads)
        pool.map(partial(self._fetch, sub_domain=sub_domain), fuzzlist)
