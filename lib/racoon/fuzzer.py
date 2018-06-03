import random
import time
import requests
from functools import partial
from multiprocessing.pool import ThreadPool
from requests.exceptions import ProxyError, ConnectionError
from fake_useragent import UserAgent
from urllib3.exceptions import ProxySchemeUnknown
from exceptions import FuzzerException
from coloring import COLOR

USER_AGENT = UserAgent()

# Really wanted to use Aiohttp, doesn't play nice with proxies or TOR, disconnects unexpectedly, etc.
# Going threaded on this one


class URLFuzzer:

    def __init__(self, target, threads=100, proxy_list=None, wordlist="../utils/fuzzlist",
                 tor_routing=False, ignored_error_codes=(404, 504)):
        self.target = target
        self.threads = threads
        self.proxy_list = proxy_list
        self.wordlist = wordlist
        self.ignored_error_codes = ignored_error_codes
        self.tor_routing = tor_routing
        self.user_agents = self._get_user_agents()
        self.proxies = None

    @staticmethod
    def _get_user_agents():
        user_agents = []
        for i in range(10):
            user_agents.append(USER_AGENT.random)
        return user_agents

    @staticmethod
    def print_response(code, url):
        if 300 > code >= 200:
            color = COLOR.GREEN
        elif 400 > code >= 300:
            color = COLOR.BLUE
        elif 510 > code >= 400:
            color = COLOR.RED
        else:
            color = COLOR.RESET
        print("{} [{}] {} {}".format(color, code, url, COLOR.RESET))

    def fetch(self, uri, proto="http", sub_domain=False, prx_dict=None, tries=0, refuse_count=0):
        """
        Send a HEAD request to URL and print response code if it's not in ignored_error_codes

        :param uri: URI to fuzz
        :param proto: use HTTP/HTTPS
        :param sub_domain: If True, build destination URL with {URL}.{HOST} else {HOST}/{URL}
        :param prx_dict: Proxy dict from last request (if this is a retry). Should be None otherwise
        :param tries: Number of tries (if this is a retry). Should be 0 otherwise
        :param refuse_count: Number of times connection was refused (if this is a retry). Should be 0 otherwise
        """
        if prx_dict:
            proxies = prx_dict
        elif self.tor_routing:
            proxies = self.proxies
        elif self.proxies:
            try:
                prx = random.choice(self.proxies)
                proxies = {proto: "http://"+prx for proto in ("http", "https")}
            except IndexError:
                raise FuzzerException("No valid proxies left in proxy list. Stopping URL Fuzzing...")
        else:
            proxies = self.proxies

        try:
            if not sub_domain:
                url = "{}://{}/{}".format(proto, self.target, uri)
            else:
                url = "{}://{}.{}".format(proto, uri, self.target)

            res = requests.head(
                url,
                headers={"User-Agent": random.choice(self.user_agents)},
                proxies=proxies, allow_redirects=True)
            if res.status_code not in self.ignored_error_codes:
                self.print_response(res.status_code, url)

        except ProxyError:
            # Basic fail over and proxy sanity check. If proxy is down after 5 tries, remove it
            if tries > 4:
                if not self.tor_routing:
                    to_drop = list(proxies.values())[0]
                    print("Failed to connect to proxy {} 5 times. Dropping it from list".format(to_drop))
                    try:
                        # Handles race conditions
                        self.proxies.remove(to_drop)
                    except ValueError:
                        pass
                else:
                    raise FuzzerException("Cannot seem to connect to TOR. Stopping URL fuzzing...")
            else:
                # Recursive fail-over attempt
                self.fetch(uri=uri,
                           proto=proto,
                           prx_dict=proxies,
                           tries=tries + 1)
        except ConnectionError:
            if not sub_domain:
                if refuse_count > 25:
                    raise FuzzerException("Connections are being actively refused by the target.\n"
                                          "Maybe add a greater sleep interval ?\nStopping URL fuzzing...")
                else:
                    self.fetch(uri=uri,
                               proto=proto,
                               prx_dict=proxies,
                               tries=tries,
                               refuse_count=refuse_count+1)

    def fuzz_all(self, proto="http", sub_domain=False):
        if self.tor_routing:
            self.proxies = {
                "http": "socks5://127.0.0.1:9050",
                "https": "socks5://127.0.0.1:9050"
            }
        elif self.proxy_list:
            try:
                with open(self.proxy_list, "r") as file:
                    file = file.readlines()
                    self.proxies = [x.replace("\n", "") for x in file]
            except FileNotFoundError:
                raise FuzzerException("Cannot read proxies from {}. Will not perform Fuzzing".format(self.proxy_list))

        print("Fuzzing URLs from {}".format(self.wordlist))
        try:
            with open(self.wordlist, "r") as file:
                fuzzlist = file.readlines()
                fuzzlist = [x.replace("\n", "") for x in fuzzlist]
        except FileNotFoundError:
            raise FuzzerException("Cannot read URL list from {}. Will not perform Fuzzing".format(self.wordlist))

        pool = ThreadPool(self.threads)
        pool.map(partial(self.fetch, proto=proto, sub_domain=sub_domain), fuzzlist)
