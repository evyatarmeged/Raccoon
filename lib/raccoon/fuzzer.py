from functools import partial
from concurrent.futures import ThreadPoolExecutor
from utils.exceptions import FuzzerException, RequestHandlerConnectionReset
from utils.coloring import COLOR
from utils.request_handler import RequestHandler


# Really wanted to use Aiohttp, doesn't play nice with proxies or TOR, disconnects unexpectedly, etc.
# Going threaded on this one


class URLFuzzer:

    def __init__(self, target, threads=100, wordlist="../wordlists/fuzzlist",
                 ignored_response_codes=(404, 504), proto="http"):
        self.target = target
        self.threads = threads
        self.wordlist = wordlist
        self.ignored_error_codes = ignored_response_codes
        self.proto = proto
        self.request_handler = RequestHandler()  # Will get the single, already initiated instance
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

    def _fetch(self, uri, proto, sub_domain=False, refuse_count=0):
        """
        Send a HEAD request to URL and print response code if it's not in ignored_error_codes
        :param uri: URI to fuzz
        :param proto: use HTTP/HTTPS
        :param sub_domain: If True, build destination URL with {URL}.{HOST} else {HOST}/{URL}
        :param refuse_count: Number of times connection was refused (if this is a retry). Should be 0 otherwise
        """
        if not sub_domain:
            url = "{}://{}/{}".format(proto, self.target, uri)
        else:
            url = "{}://{}.{}".format(proto, uri, self.target)
        try:
            res = self.request_handler.send("HEAD", url=url)
            if res.status_code not in self.ignored_error_codes:
                self._print_response(res.status_code, url, res.headers)
        except RequestHandlerConnectionReset:
            if not sub_domain:
                if refuse_count > 25:
                    # TODO: Increase delay
                    raise RequestHandlerException(
                        "Connections are being actively refused by the target.\n"
                        "Maybe add a greater sleep interval ?\nStopping URL fuzzing..."
                    )
                else:
                    self._fetch(uri=uri,
                                proto=proto,
                                refuse_count=refuse_count+1,
                                *args, **kwargs)

    def fuzz_all(self, sub_domain=False):
        try:
            with open(self.wordlist, "r") as file:
                fuzzlist = file.readlines()
                fuzzlist = [x.replace("\n", "") for x in fuzzlist]
        except FileNotFoundError:
            raise FuzzerException("Cannot read URL list from {}. Will not perform Fuzzing".format(self.wordlist))

        print("Fuzzing URLs from {}".format(self.wordlist))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(partial(self._fetch, proto=self.proto, sub_domain=sub_domain), fuzzlist)


a = URLFuzzer("88.198.233.174:35413")
print(len(a.request_handler.proxies))
a.fuzz_all()
print(len(a.request_handler.proxies))
