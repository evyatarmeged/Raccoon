from dns import resolver
from asyncio.subprocess import PIPE, create_subprocess_exec


# noinspection PyUnboundLocalVariable
class DNSHandler:
    """Handles DNS queries and lookups"""

    _resolver = resolver.Resolver()

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
                    answers = cls._resolver.query(domain, record)
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
        path = "{}/whois.txt".format(host.target)
        process = await create_subprocess_exec(
            *script,
            stdout=PIPE,
            stderr=PIPE
        )
        result, err = await process.communicate()
        print("Writing {} WHOIS Information to {}".format(host, path))

        with open(path, "w+") as file:
            for line in result.decode().strip().split("\n"):
                if ":" in line:
                    file.write("{}\n".format(line))
