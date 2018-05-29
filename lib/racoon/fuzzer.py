import random
import requests
import aiohttp
import asyncio
from aiohttp.client_exceptions import ClientProxyConnectionError, ClientHttpProxyError, TooManyRedirects
from asyncio import TimeoutError
from fake_useragent import UserAgent


USER_AGENT = UserAgent()


class AsyncURLFuzzer:
    # TODO: Add proto, edit host to a legit one
    # TODO: Add sub-domain grabbing for SANs, sub-domain fuzzing in general(?)

    def __init__(self, host, tls_data_collector):
        self.host = host
        self.tls_data = tls_data_collector
        self.proxies = self.get_proxy_list()
        self.user_agents = self.get_user_agents()
        self.get_proxy_list()

    @staticmethod
    def get_proxy_list():
        #
        proxies = []
        response = requests.get('https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list.txt')
        for line in response.text.split('\n')[3:]:
            # Get only HTTP (aiohttp doesn't play nice with HTTPS) and Goggle passing proxies
            if "-S" not in line and "+" in line:
                proxies.append(line.split()[0])
        return proxies

    @staticmethod
    def get_user_agents():
        user_agents = set()
        for i in range(10):
            user_agents.add(USER_AGENT.random)
        return user_agents

    @staticmethod
    def print_response(code, url):
        print("[{}] {}".format(code, url))

    async def _fetch(self, url):
        asyncio.sleep(random.uniform(0.025, 0.15))
        prx = random.choice(self.proxies)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(url, proxy="http://{}".format(prx)) as response:
                    if response.status != 404:
                        self.print_response(response.status, url)
        except (TooManyRedirects, TimeoutError, ClientHttpProxyError, ClientProxyConnectionError) as e:
            print("Error fuzzing {} through proxy {}".format(url, prx))
            print(e)

    def fuzz_all(self, wordlist):
        tasks = []

        with open(wordlist, 'r') as fuzzlist:
            fuzzlist = fuzzlist.readlines()

        for url in fuzzlist:
            task = asyncio.ensure_future(self._fetch("http://88.198.233.174:56392{}/".format(url)))
            tasks.append(task)

        return tasks

# Random time considered, of course
# 6K Async request fuzzing (no proxies): 133 seconds
# 6K Async request fuzzing (proxies included): 300 seconds with timeout err (should be caught)
