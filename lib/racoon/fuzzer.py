import aiohttp
import threading


class FuzzerWorker:
    # TODO: Will use this class for threaded fuzzing

    def __init__(self):
        pass


class URLFuzzer:
    # TODO: Async/Threaded ?

    def __init__(self, host, tls_data_collector):
        self.host = host
        self.tls_data = tls_data_collector

    def get_proxy_list(self):
        pass

    def find_subdomains(self, sans):
        """Extracts all sub-domains for TLSVersionChecker SAN list"""
        pass