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
        user_agents = []
        for i in range(10):
            user_agents.append(USER_AGENT.random)
        return user_agents

    @staticmethod
    def print_response(code, url):
        print("[{}] {}".format(code, url))

    async def _fetch(self, url, session, tries=0):
        asyncio.sleep(random.uniform(0.025, 0.15))
        prx = random.choice(self.proxies)
        try:
            async with session.head(
                    "{}/{}".format(self.host, url),
                    proxy="http://{}".format(prx),
                    headers={"User-Agent": random.choice(self.user_agents)}
            ) as response:
                if response.status != 404 and response.status != 504:
                    self.print_response(response.status, url)
        except (TooManyRedirects, TimeoutError, ClientHttpProxyError, ClientProxyConnectionError) as e:
            # Some retry mechanism
            if tries > 2:
                print("Error fuzzing {} through proxy {}".format(url, prx))
                print(e)
            else:
                await self._fetch(url, session, tries+1)

    async def fuzz_all(self, wordlist="../utils/fuzzlist"):
        tasks = []

        with open(wordlist, 'r') as fuzzlist:
            fuzzlist = fuzzlist.readlines()

        async with aiohttp.ClientSession() as session:
            for url in fuzzlist:
                asyncio.ensure_future(self._fetch(url, session))

        # return tasks


a = AsyncURLFuzzer("88.198.233.174:56818", "213")
runnable = a.fuzz_all()
loop = asyncio.get_event_loop()
loop.run_until_complete(a.fuzz_all())

# Random time considered, of course
# 6K Async request fuzzing (no proxies): 133 seconds
# 6K Async request fuzzing (proxies included): 300 seconds with timeout err (should be caught)
