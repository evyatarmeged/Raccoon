import re
import requests
from bs4 import BeautifulSoup
from fuzzer import URLFuzzer


class SubDomainEnumerator:

    def __init__(self, target, sans, tor_routing, proxy_list=None,
                 domain_list="../utils/subdomains", sans_lookup=True,
                 google_dork_lookup=True, bruteforce_lookup=True):
        self.target = target
        self.sans = sans
        self.proxy_list = proxy_list
        self.tor_routing = tor_routing
        self.domain_list = domain_list
        self.sans_lookup = sans_lookup
        self.google_dork_lookup = google_dork_lookup
        self.bruteforce_lookup = bruteforce_lookup
        self.sub_domains = set()

    def run(self):
        print("Enumerating sub-domains")
        if self.sans_lookup:
            self.find_subdomains_in_sans()
        if self.google_dork_lookup:
            self.google_dork()
        if self.bruteforce_lookup:
            self.bruteforce()
        print("Done enumerating sub-domains")

    def find_subdomains_in_sans(self):
        """Looks for different TLDs as well as different sub-domains in SAN list"""
        print("Trying to find sub-domains in the Subject Alternative Name list")
        domains = self.target.split('.')
        domain, tld_less = domains[0], ".".join(domains[:-1])

        for san in self.sans:
            if (tld_less in san or domain in san) and self.target != san:
                print("Sub-domain detected: {}".format(san))

    def google_dork(self):
        print("Discovering sub-domains suggestions in Google")
        page = requests.get("https://www.google.com/search?q=site:{}&num=100".format(self.target))
        soup = BeautifulSoup(page.text, "lxml")
        results = set(re.findall(r"\w+\.{}".format(self.target), soup.text))
        for subd in results:
            if "www." not in subd:
                print("Detected Sub-domain through Google dorking: {}".format(subd))

    def bruteforce(self):
        print("Trying to detect sub-domains by bruteforce")
        sub_domain_fuzzer = URLFuzzer(self.target, wordlist=self.domain_list, tor_routing=self.tor_routing)
        sub_domain_fuzzer.fuzz_all(sub_domain=True)
