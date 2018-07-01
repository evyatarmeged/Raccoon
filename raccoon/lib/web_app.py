import asyncio
import requests
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError, TooManyRedirects
from raccoon.utils.coloring import COLOR
from raccoon.utils.request_handler import RequestHandler
from raccoon.utils.helper_utils import HelperUtilities
from raccoon.utils.exceptions import WebAppScannerException


class WebApplicationScanner:

    def __init__(self, host):
        self.host = host
        self.request_handler = RequestHandler()
        self.web_scan_results = []
        self.headers = None
        self.robots = None

    def save_and_log_result(self, result):
        self.web_scan_results.append(result)
        print(result)

    def detect_cms(self):
        page = requests.get("https://whatcms.org/?s={}".format(self.host.target))
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
                        self.save_and_log_result(
                            "Found cookie without secure flag: {%s: %s}" % (key, value)
                        )
            except TypeError:
                continue

    def gather_server_info(self):
        if self.headers.get("server"):
            self.save_and_log_result("Web server detected: {}".format(self.headers.get("server")))

    def detect_anti_clickjacking(self):
        if not self.headers.get("X-Frame-Options"):
            self.save_and_log_result(
                "X-Frame-Options header not detected - target might be vulnerable to clickjacking"
            )

    def detect_xss_protection(self):
        if self.headers.get("X-XSS-PROTECTION") == "1":
            self.save_and_log_result("Found X-XSS-PROTECTION")

    def cors_wildcard(self):
        if self.headers.get("Access-Control-Allow-Origin") == "*":
            self.save_and_log_result("CORS wildcard detected")

    def get_robots_txt(self):
        res = requests.get(
            "{}://{}:{}/robots.txt".format(
                self.host.protocol,
                self.host.target,
                self.host.port
            )
        )
        if res.status_code == 200 and res.text:
            self.robots = res.text

    async def run_scan(self):
        print("Trying to collect {} web app information".format(self.host.target))
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
        finally:
            self.write_up()

    def write_up(self):
        path = HelperUtilities.get_output_path("{}/web_scan.txt".format(self.host.target))
        with open(path, "w") as file:
            for line in self.web_scan_results:
                file.write(line+"\n")
            if self.robots:
                print("Found robots.txt. Writing contents to {}".format(path))
                file.write(self.robots+"\n")
