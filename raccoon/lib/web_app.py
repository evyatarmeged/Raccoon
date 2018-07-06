import asyncio
import requests
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError, TooManyRedirects
from raccoon.utils.coloring import COLOR
from raccoon.utils.request_handler import RequestHandler
from raccoon.utils.helper_utils import HelperUtilities
from raccoon.utils.exceptions import WebAppScannerException
from raccoon.utils.logger import Logger


class WebApplicationScanner:

    def __init__(self, host):
        self.host = host
        self.request_handler = RequestHandler()
        self.web_scan_results = []
        self.headers = None
        self.robots = None
        log_file = HelperUtilities.get_output_path("{}/web_scan.txt".format(self.host.target))
        self.target_dir = "/".join(log_file.split("/")[:-1])
        self.logger = Logger(log_file)

    def detect_cms(self):
        page = requests.get("https://whatcms.org/?s={}".format(self.host.target))
        soup = BeautifulSoup(page.text, "lxml")
        found = soup.select(".panel.panel-success")
        if found:
            try:
                cms = [a for a in soup.select("a") if "/c/" in a.get("href")][0]
                self.logger.info("CMS detected: target is using {}".format(cms.get("title")))
            except IndexError:
                pass

    def gather_cookie_info(self, jar):
        for cookie in jar:
            key = cookie.__dict__.get("name")
            value = cookie.__dict__.get("value")
            domain = cookie.__dict__.get("domain")
            secure = cookie.__dict__.get("secure")
            try:
                if domain in self.host.target or self.host.target in domain:
                    if not secure:
                        self.logger.info(
                            "Found cookie without secure flag: {%s: %s}" % (key, value)
                        )
            except TypeError:
                continue

    def gather_server_info(self):
        if self.headers.get("server"):
            self.logger.info("Web server detected: {}".format(self.headers.get("server")))

    def detect_anti_clickjacking(self):
        if not self.headers.get("X-Frame-Options"):
            self.logger.info(
                "X-Frame-Options header not detected - target might be vulnerable to clickjacking"
            )

    def detect_xss_protection(self):
        if self.headers.get("X-XSS-PROTECTION") == "1":
            self.logger.info("Found X-XSS-PROTECTION")

    def cors_wildcard(self):
        if self.headers.get("Access-Control-Allow-Origin") == "*":
            self.logger.info("CORS wildcard detected")

    def get_robots_txt(self):
        res = self.request_handler.send(
            "GET",
            url="{}://{}:{}/robots.txt".format(
                self.host.protocol,
                self.host.target,
                self.host.port
            )
        )
        if res.status_code == 200 and res.text:
            self.logger.info("Found robots.txt")
            with open("{}/robots.txt".format(self.target_dir), "w") as file:
                file.write(res.text)

    def get_sitemap(self):
        res = self.request_handler.send(
            "GET",
            url="{}://{}:{}/robots.txt".format(
                self.host.protocol,
                self.host.target,
                self.host.port
            )
        )
        if res.status_code == 200 and res.text:
            self.logger.info("Found sitemap.xml")
            with open("{}/sitemap.xml".format(self.target_dir), "w") as file:
                file.write(res.text)

    async def run_scan(self):
        self.logger.info("Trying to collect {} web application data".format(self.host.target))
        session = self.request_handler.get_new_session()
        try:
            with session:
                # Test if target is serving HTTP requests
                response = session.get(
                    timeout=20,
                    url="{}://{}:{}".format(
                        self.host.protocol,
                        self.host.target,
                        self.host.port
                    )
                )
                self.headers = response.headers
                self.detect_cms()
                self.get_robots_txt()
                self.gather_server_info()
                self.cors_wildcard()
                self.detect_xss_protection()
                self.detect_anti_clickjacking()
                self.gather_cookie_info(session.cookies)

        except (ConnectionError, TooManyRedirects) as e:
            raise WebAppScannerException("Couldn't get response from server.\n"
                                         "Caused due to exception: {}".format(str(e)))