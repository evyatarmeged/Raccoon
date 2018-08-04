import random
import requests
from requests.exceptions import ProxyError, TooManyRedirects, ConnectionError, ConnectTimeout
from urllib3.exceptions import LocationParseError, NewConnectionError
from raccoon_src.utils.exceptions import RequestHandlerException, RequestHandlerConnectionReset
from raccoon_src.utils.singleton import Singleton
from fake_useragent.errors import FakeUserAgentError

try:
    from fake_useragent import UserAgent
except FakeUserAgentError:
    pass


class RequestHandler(metaclass=Singleton):
    """
    A wrapper for request sending and session creating.
    Used to abstract proxy/tor routing to avoid repeating configurations for each module
    """

    def __init__(self,
                 proxy_list=None,
                 tor_routing=False,
                 single_proxy=None,
                 delay=None,
                 cookies=None):
        self.proxy_list = proxy_list
        self.tor_routing = tor_routing
        self.delay = delay
        self.single_proxy = single_proxy
        self.proxies = self.set_instance_proxies()
        self.cookies = cookies
        self.ua = UserAgent(verify_ssl=False)

    def set_instance_proxies(self):
        """
        Set the proxies to any of the following:
        Proxy List - a list of proxies to choose randomly from for each request. Read from file.
        TOR - a dict of socks5 and the TOR service default 9050 that will be used
        Else, No proxies - an empty dict will be used.
        """
        proxies = {}
        if self.tor_routing:
            proxies = {
                "http": "socks5://127.0.0.1:9050",
                "https": "socks5://127.0.0.1:9050"
            }
        elif self.proxy_list:
            try:
                with open(self.proxy_list, "r") as file:
                    file = file.readlines()
                    proxies = [x.replace("\n", "") for x in file]
            except FileNotFoundError:
                raise RequestHandlerException("Cannot read proxies from {}".format(self.proxy_list))
        elif self.single_proxy:
            proxies = {
                "http": self.single_proxy,
                "https": self.single_proxy
            }
        return proxies

    def get_request_proxies(self):
        if self.tor_routing or self.single_proxy:
            proxies = self.proxies
        elif self.proxy_list:
            if not self.proxies:
                raise RequestHandlerException("No valid proxies left in proxy list. Exiting.")
            else:
                try:
                    prx = random.choice(self.proxies)
                    proxies = {proto: "{}://{}".format(proto, prx) for proto in ("http", "https")}
                except IndexError:
                    raise RequestHandlerException("No valid proxies left in proxy list. Exiting.")
        else:
            proxies = self.proxies
        return proxies

    def send(self, method="GET", *args, **kwargs):
        """
        Send a GET/POST/HEAD request using the object's proxies and headers
        :param method: Method to send request in. GET/POST/HEAD
        """
        proxies = self.get_request_proxies()
        headers = {"User-Agent": self.ua.random}

        try:
            if method.lower() == "get":
                return requests.get(proxies=proxies, headers=headers, cookies=self.cookies, *args, **kwargs)
            elif method.lower() == "post":
                return requests.post(proxies=proxies, headers=headers, cookies=self.cookies, *args, **kwargs)
            elif method.lower() == "head":
                return requests.head(proxies=proxies, headers=headers, cookies=self.cookies, *args, **kwargs)
            else:
                raise RequestHandlerException("Unsupported method: {}".format(method))
        except ProxyError:
            # TODO: Apply fail over for bad proxies or drop them
            raise RequestHandlerException("Error connecting to proxy")
        except ConnectTimeout:
            raise RequestHandlerException("Connection with server timed out")
        except NewConnectionError:
            raise RequestHandlerException("Address cannot be resolved")
            # New connection error == Can't resolve address
        except ConnectionError:
            # TODO: Increase delay
            raise RequestHandlerException("Error connecting to host")
        except TooManyRedirects:
            raise RequestHandlerException("Infinite redirects detected - too many redirects error")

    def get_new_session(self):
        """Returns a new session using the object's proxies and headers"""
        session = requests.Session()
        session.headers = {"User-Agent": self.ua.random}
        session.proxies = self.get_request_proxies()
        return session
