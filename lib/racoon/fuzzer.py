import random
import requests
from multiprocessing.pool import  ThreadPool


# Aiohttp proxy support is iffy at best, currently using ThreadPool until further notice


class URLFuzzer:
    # TODO: Async/Threaded ?

    def __init__(self, host, tls_data_collector):
        self.host = host
        self.tls_data = tls_data_collector
        self.proxies = []

    def get_proxy_list(self):
        with open('../utils/proxy_list', 'w') as proxy_file:
            page = requests.get('https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list.txt')

    def find_subdomains(self, sans):
        """Extracts all sub-domains for TLSVersionChecker SAN list"""
        pass

