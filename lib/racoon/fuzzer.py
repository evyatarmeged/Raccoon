import random, time, requests
from multiprocessing.pool import ThreadPool
from requests.exceptions import ProxyError
from fake_useragent import UserAgent
from urllib3.exceptions import ProxySchemeUnknown

USER_AGENT = UserAgent()

# Really wanted to use Aiohttp, doesn't play nice with proxies or TOR, disconnects unexpectedly, etc.
# Going threaded on this one


class FuzzerException(Exception):
    """Host base exception class"""
    def __init__(self, message='Base Fuzzer Exception'):
        self._message = message

    def __str__(self):
        return self._message


class URLFuzzer:

    def __init__(self, host, tls_data_collector, threads=100,
                 proxy_list=None, wordlist=None, tor_routing=False):
        self.host = host
        self.tls_data = tls_data_collector
        self.threads = threads
        self.proxy_list = proxy_list
        self.wordlist = wordlist
        self.tor_routing = tor_routing
        self.proxies = self._finalize_proxy_list()
        self.user_agents = self._get_user_agents()

    @staticmethod
    def _get_user_agents():
        user_agents = []
        for i in range(10):
            user_agents.append(USER_AGENT.random)
        return user_agents

    @staticmethod
    def print_response(code, url):
        print("[{}] {}".format(code, url))

    def _finalize_proxy_list(self):
        """TOR takes precedence over proxy list, if tor_routing=True and a proxy list is provided"""
        proxies = None
        if self.tor_routing:
            proxies = tuple('socks5://127.0.0.1:9050')
        elif self.proxy_list:
            with open(self.proxy_list, "r") as file:
                proxies = file.readlines()
        return proxies

    def _fetch(self, url, prx_dict=None, tries=0):
        if prx_dict:
            proxies = prx_dict
        else:
            try:
                proxies = {proto: "https://"+random.choice(self.proxies) for proto in ("http", "https")}
            except IndexError:
                raise FuzzerException("No more proxies left in proxy list. Stopping URL Fuzzing...")

        try:
            res = requests.head(
                self.host+"/"+url,
                headers={"User-Agent": random.choice(self.user_agents)},
                proxies=proxies)
            if res.status_code != 404 and res.status_code != 504:
                self.print_response(res.status_code, url)
        except ProxyError:
            # Basic fail over and proxy sanity check. If proxy is down after 3 tries, remove it
            if tries > 2:
                print("Failed to connect to proxy {}. Dropping it from list")
                to_drop = list(proxies.values())[0]
                self.proxies.remove(to_drop)
            else:
                self._fetch(url=url, prx_dict=proxies, tries=tries+1)
        # except ProxySchemeUnknown:
        #     pass

    def fuzz_all(self):
        if not self.wordlist:
            self.wordlist = "../utils/fuzzlist"

        # TODO: try/catch with FileNotFound

        with open(self.wordlist, "r") as file:
            fuzzlist = file.readlines()
            fuzzlist = [x.replace("\n", "") for x in fuzzlist]

        pool = ThreadPool(self.threads)
        pool.map(self._fetch, fuzzlist)


# TODO: Handle errors
# start = time.time()
# fuzzer = URLFuzzer("http://88.198.233.174:57423", "a", proxy_list="../utils/proxies")
# fuzzer.fuzz_all()
# print(time.time() - start)
