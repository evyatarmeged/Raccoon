import re
from bs4 import BeautifulSoup
from raccoon.utils.request_handler import RequestHandler
from raccoon.lib.fuzzer import URLFuzzer
from raccoon.utils.help_utils import HelpUtilities
from raccoon.utils.logger import Logger
from raccoon.utils.coloring import COLOR, COLORED_COMBOS


class SubDomainEnumerator:

    def __init__(self,
                 host,
                 sans,
                 domain_list,
                 ignored_response_codes,
                 num_threads,
                 follow_redirects):
        self.host = host
        self.target = host.target
        self.sans = sans
        self.domain_list = domain_list
        self.ignored_error_codes = ignored_response_codes
        self.num_threads = num_threads
        self.follow_redirects = follow_redirects
        self.request_handler = RequestHandler()
        self.sub_domains = set()
        log_file = HelpUtilities.get_output_path("{}/subdomains.txt".format(self.target))
        self.logger = Logger(log_file)

    async def run(self):
        self.logger.info("\n{} Enumerating Subdomains".format(COLORED_COMBOS.INFO))
        if self.sans:
            self.find_subdomains_in_sans()
        self.google_dork()
        await self.bruteforce()
        self.logger.info("\n{} Done enumerating Subdomains".format(COLORED_COMBOS.INFO))

    def find_subdomains_in_sans(self):
        """Looks for different TLDs as well as different sub-domains in SAN list"""
        self.logger.info("{} Trying to find Subdomains in SANs list".format(COLORED_COMBOS.INFO))
        if self.host.naked:
            domain = self.host.naked
            tld_less = domain.split(".")[0]
        else:
            domain = self.host.target.split(".")
            tld_less = domain[1]
            domain = ".".join(domain[1:])

        for san in self.sans:
            if (tld_less in san or domain in san) and self.target != san:
                self.logger.info("{} Subdomain detected: {}".format(COLORED_COMBOS.GOOD, san))

    def google_dork(self):
        self.logger.info("{} Trying to discover subdomains in Google".format(COLORED_COMBOS.INFO))
        page = self.request_handler.send(
            "GET",
            url="https://www.google.com/search?q=site:{}&num=100".format(self.target)
        )
        soup = BeautifulSoup(page.text, "lxml")
        results = set(re.findall(r"\w+\.{}".format(self.target), soup.text))
        for subdomain in results:
            if "www." not in subdomain:
                self.logger.info("{} Detected subdomain through Google dorking: {}".format(
                    COLORED_COMBOS.GOOD, subdomain))

    async def bruteforce(self):
        path = "{}/subdomain_fuzz.txt".format(self.host.target)

        # If a naked domain exists, use it
        if self.host.naked:
            self.host.target = self.host.naked

        self.logger.info("{} Bruteforcing subdomains".format(COLORED_COMBOS.INFO))
        sub_domain_fuzzer = URLFuzzer(
            host=self.host,
            wordlist=self.domain_list,
            num_threads=self.num_threads,
            ignored_response_codes=self.ignored_error_codes,
            follow_redirects=self.follow_redirects
            )
        await sub_domain_fuzzer.fuzz_all(sub_domain=True, log_file_path=path)

