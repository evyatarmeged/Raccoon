import random
import requests
from multiprocessing.pool import ThreadPool
from fake_useragent import UserAgent


USER_AGENT = UserAgent()

# Really wanted to use Aiohttp, doesn't play nice with proxies, Tor, disconnects a lot etc.
# Going threaded on this one


class URLFuzzer:

    def __init__(self, host, tls_data_collector, threads=100,
                 proxy_list=None, wordlist=None, tor_routing=False):
        self.host = host
        self.tls_data = tls_data_collector
        self.threads = threads
        self.proxy_list = proxy_list
        self.wordlist = wordlist
        self.tor_routing = tor_routing
        self.proxies = self._resolve_proxy_routing()
        self.user_agents = self.get_user_agents()

    @staticmethod
    def get_user_agents():
        user_agents = []
        for i in range(10):
            user_agents.append(USER_AGENT.random)
        return user_agents

    @staticmethod
    def print_response(code, url):
        print("[{}] {}".format(code, url))

    def _resolve_proxy_routing(self):
        """TOR takes precedence of proxy list, if tor_routing=True and a proxy list is provided"""
        proxies = None
        if self.tor_routing:
            proxies = ('socks5://127.0.0.1:9050', 'socks5://127.0.0.1:9050')
        # elif self.proxy_list:
            # with open(self.proxy_list, "r") as file:
            #     proxies = file.readlines()
        return self.proxy_list

    def _fetch(self, url):
        res = requests.get(
            self.host+"/"+url,
            headers={"User-Agent": random.choice(self.user_agents)},
            proxies={"http": random.choice(self.proxies)}
        )
        print(res.text)
        # if res.status_code != 404 and res.status_code != 504:
        #     self.print_response(res.status_code, url)

    def fuzz_all(self):
        if not self.wordlist:
            self.wordlist = "../utils/fuzzlist"

        # TODO: try/catch with FileNotFound

        # with open(self.wordlist, "r") as file:
        #     fuzzlist = file.readlines()

        fuzzlist = ["/" for i in range(100)]

        pool = ThreadPool(self.threads)
        pool.map(self._fetch, fuzzlist)


def get_proxy_list():
    proxies = []
    response = requests.get('https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list.txt')
    for line in response.text.split('\n')[3:]:
        # Get only HTTP (aiohttp doesn't play nice with HTTPS) and Goggle passing proxies
        if "-S" not in line and "+" in line:
            proxies.append(line.split()[0])
    return proxies


proxies = get_proxy_list()
# print(proxies)
fuzzer = URLFuzzer("https://www.icanhazip.com", "a", proxy_list=proxies)
fuzzer.fuzz_all()