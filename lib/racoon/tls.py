import re
from asyncio.subprocess import PIPE, create_subprocess_exec


class TLSCipherSuiteChecker:

    def __init__(self, host):
        self.host = host

    async def scan_ciphers(self, port=443):
        print("Started Scanning Ciphers")
        script = "nmap --script ssl-enum-ciphers -p {} {}".format(str(port), self.host).split()
        process = await create_subprocess_exec(
            *script,
            stdout=PIPE,
            stderr=PIPE
        )
        result, err = await process.communicate()
        if process.returncode != 0:
            parsed = err.decode().strip()
        else:
            parsed = self._parse_nmap_outpt(result)
        return parsed

    @staticmethod
    def _parse_nmap_outpt(result):
        result = result.decode().strip().split('\n')
        return '\n'.join([line for line in result if "TLS" in line or "ciphers" in line])


# noinspection PyTypeChecker
class TLSVersionChecker:

    def __init__(self, host):
        self.host = host
        self._versions = ("tls1", "tls1_1", "tls1_2")
        # OpenSSL likes to hang, Linux timeout to the rescue
        self._base_script = "timeout 7 openssl s_client -connect {}:443 ".format(self.host)
        self.begin = "-----BEGIN CERTIFICATE-----"
        self.end = "-----END CERTIFICATE-----"
        self.cert_pattern = re.compile("{}(.*?){}".format(self.begin, self.end, re.MULTILINE))

    async def test_supported_versions(self):
        print("Started Testing Versions")
        return {
            "SNI": await self._extract_ssl_data(True),
            "non-SNI": await self._extract_ssl_data()
        }

    def is_certificate(self, text):
        if self.begin in text and self.end in text:
            return True
        return

    def get_certificate(self, text):
        # TODO: add certificate to extracted data ?
        pass

    async def _extract_ssl_data(self, sni=False):
        """Test for version support (SNI/non-SNI), get all SANs, get certificate"""
        # Do for all responses
        responses = await self._exec_openssl(self._base_script, sni)
        tls_dict = self._parse_sclient_output(responses)
        # Do for one successful SSL response
        for res in responses:
            if self.is_certificate(res):
                tls_dict["SANs"] = await self._parse_san_output(res)
                break
        return tls_dict

    async def _exec_openssl(self, script, sni=False):
        procs = []
        outputs = []
        if sni:
            script += " -servername {}".format(self.host)
        for v in self._versions:
            curr = script + ' -{}'.format(v)
            procs.append(
                await create_subprocess_exec(
                    *curr.split(),
                    stdout=PIPE,
                    stderr=PIPE
                )
            )
        for p in procs:
            result, err = await p.communicate()
            outputs.append(result.decode().strip())
        return outputs

    @staticmethod
    async def _parse_san_output(data):
        process = await create_subprocess_exec(
            "openssl", "x509", "-noout", "-text",
            stdin=PIPE,
            stderr=PIPE,
            stdout=PIPE
        )
        result, err = await process.communicate(input=bytes(data, encoding='ascii'))
        sans = re.findall(r"DNS:\S*\b", str(result, encoding='ascii'))
        return {san.replace("DNS:", '') for san in sans}

    def _parse_sclient_output(self, results):
        is_supported = {"TLSv1": False, "TLSv1.1": False, "TLSv1.2": False}
        for res in results:
            if not self.is_certificate(res):
                continue
            for line in res.split('\n'):
                if "Protocol" in line:
                    ver = line.strip().split(':')[1].strip()
                    is_supported[ver] = True
        return is_supported
