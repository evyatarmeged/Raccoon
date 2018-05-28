import random
import requests
from requests.exceptions import ProxyError, ConnectTimeout
from multiprocessing.pool import ThreadPool


# Threaded version. Still considering aiohttp


class URLFuzzer:

    def __init__(self, host, tls_data_collector, threads=50):
        self.host = host
        self.tls_data = tls_data_collector
        self.pool = ThreadPool(threads)
        self.proxies = []
        self.get_proxy_list()

    def get_proxy_list(self):
        response = requests.get('https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list.txt')
        for line in response.text.split('\n')[3:]:
            # Get only HTTPS and Google passing proxies
            if "-S" in line and "+" in line:
                self.proxies.append(line.split()[0])

    def fetch(self, url, proto="http"):
        time.sleep(random.uniform(0.05, 0.25))
        prx = random.choice(self.proxies)
        try:
            response = requests.head(
                "{}://{}/{}".format(proto, self.host, url),
                proxies={"https": prx},
                timeout=10
            )
            if response.status_code != 404:
                print("[{}] {}".format(str(response.status_code), url))
        except (ProxyError, ConnectTimeout):
            # Bad proxy, remove it from list to save future requests the trouble of failing
            bad_prx = self.proxies.index(prx)
            try:
                self.proxies.remove(bad_prx)
            # Prevent race condition
            except ValueError:
                pass
            finally:
                self.fetch(url)

    def fuzz_urls(self, wordlist='/home/mr_evya/PycharmProjects/racoon/lib/utils/fuzzlist'):
        with open(wordlist, "r") as fuzz_list:
            fuzz_list = fuzz_list.readlines()
            self.pool.map(self.fetch, fuzz_list)

    def find_subdomains(self, sans):
        """Extracts all sub-domains from TLSVersionChecker SAN list"""
        pass
