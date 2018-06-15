import asyncio
import aiohttp
import requests
from fake_useragent import UserAgent
from bs4 import BeautifulSoup
from coloring import COLOR


class WebAppVulnDetector:

    def __init__(self, target, ua):
        self.target = target
        self.ua = ua
        self.cms_url = "https://whatcms.org/?s={}"
        self.headers = None

    def detect_cms(self):
        page = requests.get(self.cms_url.format(self.target))
        soup = BeautifulSoup(page.text, "lxml")
        found = soup.select(".panel.panel-success")
        if found:
            try:
                cms = [a for a in soup.select("a") if "/c/" in a.get("href")][0]
                print("CMS detected: target seems to use {}".format(cms.get("title")))
            except IndexError:
                pass

    def gather_cookie_info(self, jar):
        for cookie in jar:
            key = cookie.__dict__.get("name")
            value = cookie.__dict__.get("value")
            domain = cookie.__dict__.get("domain")
            secure = cookie.__dict__.get("secure")
            try:
                if domain in self.target or self.target in domain:
                    if not secure:
                        print("Found cookie without secure flag: {%s: %s}" % (key, value))
            except TypeError:
                continue

    def server_info(self):
        if self.headers.get("server"):
            print("Web server used: {}".format(self.headers.get("server")))

    def detect_anti_clickjacking(self):
        if not self.headers.get("X-Frame-Options"):
            print("X-Frame-Options header not detected - target might be vulnerable to clickjacking")

    def detect_xss_protection(self):
        if self.headers.get("X-XSS-PROTECTION") == "1":
            print("Found X-XSS-PROTECTION")

    def cors_wildcard(self):
        if self.headers.get("Access-Control-Allow-Origin") == "*":
            print("CORS wildcard detected")

    def get_robots_txt(self):
        res = requests.get("{}/robots.txt".format(self.target))
        if res.status_code == 200:
            # TODO: Write to file
            robots_txt = res.text
            print("Fetched robots.txt")

    def scan_xss(self):
        # TODO: Scan input fields for XSS
        pass

    def test_sqli(self):
        # TODO: Scan forms/parameterized URLs for SQLi
        pass

    def run(self):
        print("Scanning {} for web vulnerabilities".format(self.target))
        self.detect_cms()
        self.get_robots_txt()

        with requests.Session() as session:
            response = session.get(self.target)
            self.headers = response.headers

        self.server_info()
        self.cors_wildcard()
        self.detect_xss_protection()
        self.detect_anti_clickjacking()
        self.gather_cookie_info(session.cookies)

    def write_up(self):
        # TODO: Out to file
        pass