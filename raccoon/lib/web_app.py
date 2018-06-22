import asyncio
import aiohttp
import requests
from bs4 import BeautifulSoup
from coloring import COLOR
from raccoon.utils.request_handler import RequestHandler


class WebAppDataGrabber:

    def __init__(self, host):
        self.target = host.target
        self.request_handler = RequestHandler()
        self.headers = None
        self.robots = None

    def detect_cms(self):
        page = requests.get("https://whatcms.org/?s={}".format(self.target))
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
        if res.status_code == 200 and res.text:
            self.robots = res.text
            print("Fetched robots.txt")

    def run(self):
        print("Collecting {} web app information".format(self.target))
        self.detect_cms()
        self.get_robots_txt()

        session = self.request_handler.get_new_session()
        with session:
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