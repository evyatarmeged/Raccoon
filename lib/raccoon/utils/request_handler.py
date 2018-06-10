import random
import requests
from fake_useragent import UserAgent
from requests.exceptions import ConnectionError, ProxyError, TooManyRedirects
from .exceptions import RequestHandlerException


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
                proxies = {proto: "http://" + prx for proto in ("http", "https")}
            except IndexError:
                raise RequestHandler("No valid proxies left in proxy list. Exiting.")
        else:
            proxies = self.proxies
        return proxies

    def send(self, method="GET", proxies=None, tries=0, refuse_count=0, *args, **kwargs):
        """
        :param method: Method to send request in. GET/POST/HEAD
        :param proxies: Proxy dict from last request (if this is a retry). Should be None otherwise
        :param tries: Number of tries (if this is a retry). Should be 0 otherwise
        :param refuse_count: Number of times connection was refused (if this is a retry). Should be 0 otherwise
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
                return requests.head(proxies=proxies, headers=headers,  *args, **kwargs)
            else:
                raise RequestHandlerException("Unsupported method: {}".format(method))

        except ProxyError:
            # Basic fail over and proxy sanity check. If proxy is down after 5 tries, remove it
            if tries > 4:
                if not self.tor_routing:
                    to_drop = list(proxies.values())[0]
                    print("5 connection errors received from {}.\n Dropping it from proxy list".format(to_drop))
                    try:
                        # Handles race conditions
                        self.proxies.remove(to_drop)
                    except ValueError:
                        pass
                else:
                    raise RequestHandlerException("Cannot seem to connect to TOR. Exiting")
            else:
                # Recursive fail-over attempt
                self.send(method=method,
                          proxies=proxies,
                          tries=tries+1,
                          *args, **kwargs)

        except ConnectionError:
            if not sub_domain:
                if refuse_count > 25:
                    # TODO: Increase delay
                    raise RequestHandlerException(
                        "Connections are being actively refused by the target.\n"
                        "Maybe add a greater sleep interval ?\nStopping URL fuzzing..."
                    )
                else:
                    self.send(method=method,
                              proxies=proxies,
                              refuse_count=refuse_count+1,
                              *args, **kwargs)
        except TooManyRedirects:
            pass
