import random
import requests
import threading
from fake_useragent import UserAgent
from requests.exceptions import ProxyError, TooManyRedirects, ConnectionError, ConnectTimeout
from urllib3.exceptions import LocationParseError
from raccoon.utils.exceptions import RequestHandlerException, RequestHandlerConnectionReset


class RequestHandler:
    """
    A wrapper for request sending and session creating.
    Used to abstract proxy/tor routing to avoid repeating configurations for each module
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(RequestHandler, cls).__new__(cls)
        return cls._instance

    def __init__(self, proxy_list=None, tor_routing=None, delay=None):
        self.proxy_list = proxy_list
        self.tor_routing = tor_routing
        self.delay = delay
        self.proxies = self.set_instance_proxies()
        self.ua = UserAgent()

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
        return proxies

    def get_request_proxies(self):
        if self.tor_routing:
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
                return requests.get(proxies=proxies, headers=headers, *args, **kwargs)
            elif method.lower() == "post":
                return requests.post(proxies=proxies, headers=headers, *args, **kwargs)
            elif method.lower() == "head":
                return requests.head(proxies=proxies, headers=headers, *args, **kwargs)
            else:
                raise RequestHandlerException("Unsupported method: {}".format(method))
        except ProxyError:
            # TODO: Apply fail over for bad proxies or drop them
            raise RequestHandlerException("Error connecting to proxy")
        except ConnectTimeout:
            pass
        except ConnectionError:
            # TODO: Increase delay
            raise RequestHandlerException("Error connecting to host")
        except TooManyRedirects:
            pass

    def get_new_session(self):
        """Returns a new session using the object's proxies and headers"""
        session = requests.Session()
        session.headers = {"User-Agent": self.ua.random}
        session.proxies = self.get_request_proxies()
        return session
