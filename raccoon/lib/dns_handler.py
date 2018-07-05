import time
from dns import resolver
from asyncio.subprocess import PIPE, create_subprocess_exec
from requests.exceptions import ConnectionError
from raccoon.utils.helper_utils import HelperUtilities
from raccoon.utils.logger import Logger
from raccoon.utils.request_handler import RequestHandler


# noinspection PyUnboundLocalVariable
class DNSHandler:
    """Handles DNS queries and lookups"""

    resolver = resolver.Resolver()
    request_handler = RequestHandler()

    @classmethod
    def query_dns(cls, domains, records):
        """
        Query DNS records for host.
        :param domains: Iterable of domains to get DNS Records for
        :param records: Iterable of DNS records to get from domain.
        """
        results = {k: set() for k in records}
        for record in records:
            for domain in domains:
                try:
                    answers = cls.resolver.query(domain, record)
                    for answer in answers:
                        # Add value to record type
                        results.get(record).add(answer)
                except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.NoNameservers):
                    # Type of record doesn't fit domain or no answer from ns
                    continue

        return {k: v for k, v in results.items() if v}

    @classmethod
    async def grab_whois(cls, host):
        if not host.naked:
            return

        script = "whois {}".format(host.naked).split()
        log_file = HelperUtilities.get_output_path("{}/whois.txt".format(host.target))
        logger = Logger(log_file)
        logger.info("Retrieving WHOIS Information for {}".format(host))

        process = await create_subprocess_exec(
            *script,
            stdout=PIPE,
            stderr=PIPE
        )
        result, err = await process.communicate()

        for line in result.decode().strip().split("\n"):
                if ":" in line:
                    logger.debug(line)

    @classmethod
    async def generate_dns_dumpster_mapping(cls, host, sout_logger):
        # Start DNS Dumpster session for the token
        dnsdumpster_session = DNSHandler.request_handler.get_new_session()
        url = "https://dnsdumpster.com"
        if host.naked:
            target = host.naked
        else:
            target = host.target
        payload = {
            "targetip": target,
            "csrfmiddlewaretoken": None
        }
        sout_logger.info("Trying to generate DNS Mapping for {}".format(host.target))
        try:
            dnsdumpster_session.get(url)
            jar = dnsdumpster_session.cookies
            for c in jar:
                if not c.__dict__.get("name") == "csrftoken":
                    continue
                payload["csrfmiddlewaretoken"] = c.__dict__.get("value")
                break

            dnsdumpster_session.post(url, data=payload, headers={"Referer": "https://dnsdumpster.com/"})
            time.sleep(3)
            page = dnsdumpster_session.get("https://dnsdumpster.com/static/map/{}.png".format(target))
            if page.status_code == 200:
                path = HelperUtilities.get_output_path("{}/dns_mapping.png".format(host.target))
                with open(path, "wb") as target_image:
                    target_image.write(page.content)
        except ConnectionError:
            sout_logger.info("Failed to generate DNS mapping. A connection error occurred.")