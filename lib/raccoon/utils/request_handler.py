import random
import requests
from fake_useragent import UserAgent
from threading import Lock
from requests.exceptions import ProxyError, TooManyRedirects, ConnectionError
from urllib3.exceptions import LocationParseError
from .exceptions import RequestHandlerException, RequestHandlerConnectionReset


lock = Lock()


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
                raise RequestHandler("No valid proxies left in proxy list. Exiting.")
        else:
            proxies = self.proxies
        return proxies

    def drop_proxy(self, proxy_dict):
        to_drop = list(proxy_dict.values())[0]
        to_drop = to_drop.split("://")[1]
        print("3 connection errors received from {}.\nDropping it from proxy list".format(to_drop))
        lock.acquire()
        try:
            # Handles race conditions
            self.proxies.remove(to_drop)
            print(self.proxies)
        except ValueError:
            pass
        finally:
            lock.release()

    def proxy_fail_over(self, method, proxies, tries, *args, **kwargs):
        """If the proxy fails/refuses to connect 3 times in a row, it is dropped from proxy list"""
        if tries > 2:
            if not self.tor_routing:
                self.drop_proxy(proxies)
            else:
                raise RequestHandlerException("Cannot seem to connect to TOR. Exiting")
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
        :return:
        """
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
            self.proxy_fail_over(
                method=method,
                proxies=proxies,
                tries=tries,
                *args, **kwargs
            )
        except ConnectionError as e:
            # Connection Error might also be proxy related, hence the check
            curr_prx = list(proxies.values())[0]
            curr_prx = curr_prx.split("://")[1].split(":")
            if "host='{}', port={}".format(*curr_prx) in e.__str__():
                if ":".join(curr_prx) in self.proxies:
                    self.proxy_fail_over(
                        method=method,
                        proxies=proxies,
                        tries=tries,
                        *args, **kwargs
                    )
            else:
                raise RequestHandlerConnectionReset
        except LocationParseError:
            print("Bad proxy format: ".format(proxies.values()[0]))
            # Bad proxy format
            self.drop_proxy(proxies)