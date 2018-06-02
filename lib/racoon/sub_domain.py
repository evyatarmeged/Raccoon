import requests
from bs4 import BeautifulSoup
from .fuzzer import URLFuzzer


class SubDomainEnumerator:

    def __init__(self, host, sans, proxy_list, tor_routing, domain_list):
        self.host = host
        self.sans = sans
        self.proxy_list = proxy_list
        self.tor_routing = tor_routing
        self.domain_list = domain_list
        self.sub_domains = set()

    def run(self):
        pass

    def find_subdomains_in_sans(self):
        print("Trying to find sub-domains in certificate SANs")
        pass

    def google_dork(self):
        print("Looking for sub-domains in Google")
        pass

    def bruteforce(self):
        sub_domain_fuzzer = URLFuzzer(self.host, wordlist=self.domain_list, tor_routing=self.tor_routing)
        print("Trying to detect sub-domains by bruteforce")
        pass

