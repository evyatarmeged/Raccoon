import re
# noinspection PyProtectedMember
from asyncio.subprocess import PIPE, create_subprocess_exec
from raccoon.utils.helper_utils import HelperUtilities
from raccoon.utils.logger import Logger


class TLSCipherSuiteChecker:

    def __init__(self, host):
        self.target = host.target

    async def scan_ciphers(self, port):
        script = "nmap --script ssl-enum-ciphers -p {} {}".format(str(port), self.target).split()
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
        result = result.decode().strip().split("\n")
        return '\n'.join([line for line in result if "|" in line]).strip().rstrip()


# noinspection PyTypeChecker
class TLSHandler(TLSCipherSuiteChecker):

    def __init__(self, host, port=443):
        super().__init__(host)
        self.target = host.target
        self.port = port
        self._versions = ("tls1", "tls1_1", "tls1_2")
        # OpenSSL likes to hang, Linux timeout to the rescue
        self._base_script = "timeout 10 openssl s_client -connect {}:{} ".format(self.target, self.port)
        self.begin = "-----BEGIN CERTIFICATE-----"
        self.end = "-----END CERTIFICATE-----"
        self.sni_data = {}
        self.non_sni_data = {}
        self.ciphers = ""
        log_file = HelperUtilities.get_output_path("{}/tls_report.txt".format(self.target))
        self.logger = Logger(log_file)

    async def run(self, sni=True):
        self.logger.info("Started collecting TLS data")
        self.ciphers = await self.scan_ciphers(self.port)
        self.non_sni_data = await self._execute_ssl_data_extraction()
        if sni:
            self.sni_data = await self._execute_ssl_data_extraction(sni=sni)
        await self.is_heartbleed_vulnerable()
        self.logger.info("Done collecting TLS data")

        if self._are_certificates_identical():
            self.non_sni_data["Certificate_details"] = "Same as SNI Certificate"
        self.write_up()

    def _are_certificates_identical(self):
        """
        Validate that both certificates exist.
        :returns: True if they are identical, False otherwise
        """
        sni_cert = self.sni_data["Certificate_details"]
        non_sni_cert = self.non_sni_data["Certificate_details"]
        if all(cert for cert in (sni_cert, non_sni_cert) if cert) and sni_cert == non_sni_cert:
            return True
        return

    def _is_certificate_exists(self, text):
        if self.begin in text and self.end in text:
            return True
        return

    async def _extract_certificate_details(self, data):
        process = await create_subprocess_exec(
            "timeout", "5", "openssl", "x509", "-text",
            stdin=PIPE,
            stderr=PIPE,
            stdout=PIPE
        )
        result, err = await process.communicate(input=bytes(data, encoding='ascii'))
        result = result.decode().strip()
        cert_details = result.split(self.begin)[0].strip()

        result_lines = cert_details.split("\n")
        for i, line in enumerate(result_lines):
            if "DNS:" in line:
                result_lines.pop(i)
                result_lines.pop(i-1)

        cert_details = "\n".join(result_lines)
        return cert_details

    async def is_heartbleed_vulnerable(self):
        script = self._base_script + "-tlsextdebug"
        process = await create_subprocess_exec(
            *script.split(),
            stdout=PIPE,
            stderr=PIPE
        )
        result, err = await process.communicate()
        try:
            if "server extension \"heartbeat\" (id=15)" in result.decode().strip():
                self.logger.info("Target seems to be vulnerable to Heartbleed - CVE-2014-0160")
        except TypeError:  # Type error means no result
            pass

    async def _execute_ssl_data_extraction(self, sni=False):
        """
        Test for version support (SNI/non-SNI), get all SANs, get certificate details
        :param sni: True will call cause _exec_openssl to call openssl with -servername flag
        """
        # Do for all responses
        responses = await self._run_openssl_sclient_cmd(self._base_script, sni)
        tls_dict = self._parse_openssl_sclient_output(responses)
        # Do for one successful SSL response
        for res in responses:
            if self._is_certificate_exists(res):
                tls_dict["SANs"] = await self._get_sans_from_openssl_cmd(res)
                tls_dict["Certificate_details"] = await self._extract_certificate_details(res)
                break

        return tls_dict

    async def _run_openssl_sclient_cmd(self, script, sni=False):
        processes = []
        outputs = []
        if sni:
            script += " -servername {}".format(self.target)
        for v in self._versions:
            curr = (script + ' -{}'.format(v)).split()
            processes.append(
                await create_subprocess_exec(
                    *curr,
                    stdout=PIPE,
                    stderr=PIPE
                )
            )
        for p in processes:
            result, err = await p.communicate()

            outputs.append(result.decode().strip())

        return outputs

    @staticmethod
    async def _get_sans_from_openssl_cmd(data):
        process = await create_subprocess_exec(
            "openssl", "x509", "-noout", "-text",
            stdin=PIPE,
            stderr=PIPE,
            stdout=PIPE
        )
        result, err = await process.communicate(input=bytes(data, encoding='ascii'))
        sans = re.findall(r"DNS:\S*\b", result.decode().strip())
        return {san.replace("DNS:", '') for san in sans}

    def _parse_openssl_sclient_output(self, results):
        is_supported = {"TLSv1": False, "TLSv1.1": False, "TLSv1.2": False}
        for res in results:
            if not self._is_certificate_exists(res):
                continue
            for line in res.split('\n'):
                if "Protocol" in line:
                    ver = line.strip().split(':')[1].strip()
                    is_supported[ver] = True
        return is_supported

    def _dictionary_log_procedure(self, result_dict):
        for k, v in result_dict.items():
            if k == "SANs":
                self.logger.debug("{0}:\n{1}\n {2}\n{1}\n".format(k, "-"*15, "\n".join(v)))
            elif k == "Certificate_details":
                self.logger.debug(v)
            else:
                self.logger.debug("{}: {}\n".format(k, v))

    def write_up(self):
        self.logger.debug("Supporting Ciphers:\n")
        self.logger.debug(self.ciphers+"\n")
        self.logger.debug("-"*80+"\n")
        self.logger.debug("SNI Data:\n")
        self._dictionary_log_procedure(self.sni_data)
        self.logger.debug("-"*80+"\n")
        self.logger.debug("non-SNI Data:\n")
        self._dictionary_log_procedure(self.non_sni_data)
