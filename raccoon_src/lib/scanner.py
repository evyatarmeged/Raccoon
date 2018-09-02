import re
from subprocess import PIPE, Popen
from raccoon_src.utils.help_utils import HelpUtilities
from raccoon_src.utils.logger import Logger
from raccoon_src.utils.coloring import COLOR, COLORED_COMBOS


class NmapScan:
    """
    Nmap scan class
    Will run SYN/TCP scan according to privileges.
    Start Raccoon with sudo for -sS else will run -sT
    """

    def __init__(self, host, port_range, full_scan=None, scripts=None, services=None):
        self.target = host.target
        self.full_scan = full_scan
        self.scripts = scripts
        self.services = services
        self.port_range = port_range
        self.path = HelpUtilities.get_output_path("{}/nmap_scan.txt".format(self.target))
        self.logger = Logger(self.path)

    def build_script(self):
        script = ["nmap", "-Pn", self.target]

        if self.port_range:
            HelpUtilities.validate_port_range(self.port_range)
            script.append("-p")
            script.append(self.port_range)
            self.logger.info("{} Added port range {} to Nmap script".format(COLORED_COMBOS.NOTIFY, self.port_range))
        if self.full_scan:
            script.append("-sV")
            script.append("-sC")
            self.logger.info("{} Added scripts and services to Nmap script".format(COLORED_COMBOS.NOTIFY))
            return script
        else:
            if self.scripts:
                self.logger.info("{} Added safe-scripts scan to Nmap script".format(COLORED_COMBOS.NOTIFY))
                script.append("-sC")
            if self.services:
                self.logger.info("{} Added service scan to Nmap script".format(COLORED_COMBOS.NOTIFY))
                script.append("-sV")
        return script


class NmapVulnersScan(NmapScan):
    """
    NmapVulners scan class (NmapScan subclass)
    """

    def __init__(self, host, port_range, vulners_path):
        super().__init__(host=host, port_range=port_range)
        self.vulners_path = vulners_path
        self.path = HelpUtilities.get_output_path("{}/nmap_vulners_scan.txt".format(self.target))
        self.logger = Logger(self.path)

    def build_script(self):
        script = ["nmap", "-Pn", "-sV", "--script", self.vulners_path, self.target]

        if self.port_range:
            HelpUtilities.validate_port_range(self.port_range)
            script.append("-p")
            script.append(self.port_range)
            self.logger.info("{} Added port range {} to Nmap script".format(COLORED_COMBOS.NOTIFY, self.port_range))

        return script


class Scanner:

    @classmethod
    def run(cls, scan):
        script = scan.build_script()

        scan.logger.info("{} Nmap script to run: {}".format(COLORED_COMBOS.INFO, " ".join(script)))
        scan.logger.info("{} Nmap scan started\n".format(COLORED_COMBOS.GOOD))
        process = Popen(
            script,
            stdout=PIPE,
            stderr=PIPE
        )
        result, err = process.communicate()
        result, err = result.decode().strip(), err.decode().strip()
        if result:
            parsed_result = cls._parse_scan_output(result)
            scan.logger.info(parsed_result)
        Scanner.write_up(scan, result, err)

    @classmethod
    def _parse_scan_output(cls, result):
        parsed_output = ""
        for line in result.split("\n"):
            if "PORT" in line and "STATE" in line:
                parsed_output += "{} Nmap discovered the following ports:\n".format(COLORED_COMBOS.GOOD)
            if "/tcp" in line or "/udp" in line and "open" in line:
                line = line.split()
                parsed_output += "\t{}{}{} {}\n".format(COLOR.GREEN, line[0], COLOR.RESET, " ".join(line[1:]))
        return parsed_output

    @classmethod
    def write_up(cls, scan, result, err):
        open(scan.path, "w").close()
        if result:
            scan.logger.debug(result+"\n")
        if err:
            scan.logger.debug(err)


class VulnersScanner(Scanner):

    @classmethod
    def _parse_scan_output(cls, result):

        parsed_output = ""
        out_versions, out_pure = cls._parse_vulners_output(result)

        out_versions = re.sub(r"(\d+\/(?:tcp|udp))", COLOR.GREEN + r"\1" + COLOR.RESET, out_versions)
        out_versions = re.sub(r"(\sCVE\S*)", COLOR.RED + r"\1" + COLOR.RESET, out_versions)
        out_pure = re.sub(r"(\d+\/(?:tcp|udp))", COLOR.GREEN + r"\1" + COLOR.RESET, out_pure)

        if out_pure:
            parsed_output += "{} NmapVulners discovered the following open ports:\n{}"\
                .format(COLORED_COMBOS.GOOD, out_pure)
        if out_versions:
            parsed_output += "{} NmapVulners discovered some vulnerable software within the following open ports:\n{}"\
                .format(COLORED_COMBOS.GOOD, out_versions)
        return parsed_output

    @classmethod
    def _parse_vulners_output(cls, res):
        ports = re.findall(r"(?:^\d+/(?:tcp|udp).*open.*$\n(?:^\|.*$\n)*)", res, re.MULTILINE)
        out_vers = ""
        out_none = ""
        for port in ports:
            if 'vulners' in port:
                out_vers += '\n' + '\n'.join(
                    re.findall(r"^(\d+/(?:tcp|udp).*open.*$)[\s\S]*?(^\|.*vulners[\s\S]+?^\|_.+?$)", port,
                               re.MULTILINE)[0])
            else:
                out_none += port
        return out_vers, out_none
