import requests
from bs4 import BeautifulSoup
from coloring import COLOR


class WebAppVulnDetector:

    def __init__(self, target):
        self.target = target
        self.cms_url = "https://whatcms.org/?s={}"

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
        else:
            print("BURRRP")

    def find_login_page(self):
        pass

    def gather_cookie_info(self):
        pass

    def clickjacking_exists(self):
        pass

    def xss_exists(self):
        pass

    def cors_wildcard(self):
        pass

    def get_robots_txt(self):
        pass


vuln_detector = WebAppVulnDetector("www.github.com")
vuln_detector.detect_cms()
