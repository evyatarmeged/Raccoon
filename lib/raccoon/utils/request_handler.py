import random
import requests
from fake_useragent import UserAgent
from requests.exceptions import ProxyError, TooManyRedirects, ConnectionError
from urllib3.exceptions import LocationParseError
import threading
from .exceptions import RequestHandlerException, RequestHandlerConnectionReset


class RequestHandler:
    """
    Request handling class.
    Used to abstract proxy/tor routing to avoid repeating configurations for each module
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(RequestHandler, cls).__new__(cls)
        return cls._instance

    def __init__(self, proxy_list=None, tor_routing=None):
        # TODO: Add Delay
        self.proxy_list = proxy_list
        self.tor_routing = tor_routing
        self.proxies = self.set_object_proxies()
        self.ua = UserAgent()

    def set_object_proxies(self):
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
            try:
                prx = random.choice(self.proxies)
                proxies = {proto: "{}://{}".format(proto, prx) for proto in ("http", "https")}
            except IndexError:
                raise RequestHandlerException("No valid proxies left in proxy list. Exiting.")
        else:
            proxies = self.proxies
        return proxies

    def proxy_fail_over(self, method, proxies, tries, *args, **kwargs):
        """If the proxy fails/refuses to connect 3 times in a row, it is dropped from proxy list"""
        if tries > 5:
            raise Exception("Connect connect to proxy: {}".format(proxies))
        else:
            # Fail-over attempt for proxy connection issues
            self.send(method=method,
                      proxies=proxies,
                      tries=tries+1,
                      *args, **kwargs)

    def send(self, method="GET", proxies=None, tries=0, *args, **kwargs):
        """
        :param method: Method to send request in. GET/POST/HEAD
        :param proxies: Proxy dict from last request (if this is a retry). Should be None otherwise
        :param tries: Number of proxy reconnection tries
        """
        if not self.proxies:
            raise RequestHandlerException("No valid proxies left in proxy list. Exiting.")
        if not proxies:
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
            print("PRX ERR", e)
            raise RequestHandlerException("Proxy Error for prx: {}".format(tuple(proxies.values())[0]))
        except ConnectionError as e:
            print("CONN ERR", e)
            self.proxy_fail_over(
                method=method,
                proxies=proxies,
                tries=tries,
                *args, **kwargs
            )
        except ConnectionResetError as e:
            print("CONN RST ERR", e, type(e))
            pass
        except Exception as e:
            print("GENERAL EXC", type(e), e)
        except LocationParseError:
            print("Bad proxy format: ".format(proxies.values()[0]))
            # Bad proxy format
            self.drop_proxy(proxies)