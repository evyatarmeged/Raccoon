import uuid
from functools import partial
from multiprocessing.pool import ThreadPool
from requests.exceptions import ConnectionError
from raccoon_src.utils.exceptions import FuzzerException, RequestHandlerException
from raccoon_src.utils.coloring import COLOR, COLORED_COMBOS
from raccoon_src.utils.request_handler import RequestHandler
from raccoon_src.utils.help_utils import HelpUtilities
from raccoon_src.utils.logger import Logger


# Really wanted to use Aiohttp, doesn't play nice with proxies or TOR, disconnects unexpectedly, etc.
# Going threaded on this one


class URLFuzzer:

    def __init__(self,
                 host,
                 ignored_response_codes,
                 num_threads,
                 path_to_wordlist,
                 follow_redirects=False):

        self.target = host.target
        self.ignored_error_codes = ignored_response_codes
        self.proto = host.protocol
        self.port = host.port
        self.num_threads = num_threads
        self.path_to_wordlist = path_to_wordlist
        self.wordlist = self._create_set_from_wordlist_file(path_to_wordlist)
        self.follow_redirects = follow_redirects
        self.request_handler = RequestHandler()  # Will get the single, already initiated instance
        self.logger = None

    @staticmethod
    def _create_set_from_wordlist_file(wordlist):
        try:
            with open(wordlist, "r") as file:
                fuzzlist = file.readlines()
                fuzzlist = [x.replace("\n", "") for x in fuzzlist]
                return set(fuzzlist)
        except FileNotFoundError:
            raise FuzzerException("Cannot open file {}. Will not perform Fuzzing".format(wordlist))

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
        self.logger.info("\t{}[{}]{} {}".format(
            color, code, COLOR.RESET, url))

    def _build_request_url(self, uri, sub_domain):
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
        return url

    def _fetch(self, uri, sub_domain=False):
        """
        Send a HEAD request to URL and print response code if it's not in ignored_error_codes
        :param uri: URI to fuzz
        :param sub_domain: If True, build destination URL with {URL}.{HOST} else {HOST}/{URL}
        """
        url = self._build_request_url(uri, sub_domain=sub_domain)

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

    @staticmethod
    def _rule_out_false_positives(response_codes, sub_domain):
        if any(code == 200 for code in response_codes):
            if sub_domain:
                err_msg = "Wildcard subdomain support detected (all subdomains return 200)." \
                          " Will not bruteforce subdomains"
            else:
                err_msg = "Web server seems to redirect requests for all resources " \
                          "to eventually return 200. Will not bruteforce URLs"
            raise FuzzerException(err_msg)

    def _generate_fake_requests(self, sub_domain):
        response_codes = []
        fake_uris = (uuid.uuid4(), uuid.uuid4())
        session = self.request_handler.get_new_session()
        for uri in fake_uris:
            url = self._build_request_url(uri, sub_domain)
            try:
                res = self.request_handler.send("GET", url=url, allow_redirects=True)
                response_codes.append(res.status_code)
                res = session.get(url=url, allow_redirects=self.follow_redirects)
                response_codes.append(res.status_code)
            except RequestHandlerException as e:
                if sub_domain:  # If should-not-work.example.com doesn't resolve, no wildcard subdomain is present
                    return [0]
                else:
                    raise FuzzerException("Could not get a response from {}."
                                          " Maybe target is down ?".format(self.target))
        return response_codes

    async def fuzz_all(self, sub_domain=False, log_file_path=None):
        """
        Create a pool of threads and exhaust self.wordlist on self._fetch
        Should be run in an event loop.
        :param sub_domain: Indicate if this is subdomain enumeration or URL busting
        :param log_file_path: Log subdomain enum results to this path.
        """
        self.logger = self.get_log_file_path(log_file_path)
        try:
            # Rule out wildcard subdomain support/all resources redirect to a 200 page
            response_codes = self._generate_fake_requests(sub_domain)
            self._rule_out_false_positives(response_codes, sub_domain)

            if not sub_domain:
                self.logger.info("{} Fuzzing URLs".format(COLORED_COMBOS.INFO))
            self.logger.info("{} Reading from list: {}".format(COLORED_COMBOS.INFO, self.path_to_wordlist))
            pool = ThreadPool(self.num_threads)
            pool.map(partial(self._fetch, sub_domain=sub_domain), self.wordlist)
            pool.close()
            pool.join()
            if not sub_domain:
                self.logger.info("{} Done fuzzing URLs".format(COLORED_COMBOS.INFO))
        except FuzzerException as e:
            self.logger.info("{} {}".format(COLORED_COMBOS.BAD, e))
        except ConnectionError as e:
            if "Remote end closed connection without response" in str(e):
                self.logger.info("{} {}. Target is actively closing connections - will not "
                                 "bruteforce URLs".format(COLORED_COMBOS.BAD, str(e)))
