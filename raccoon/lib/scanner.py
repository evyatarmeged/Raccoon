from subprocess import PIPE, Popen
from raccoon.utils.helper_utils import HelperUtilities
from raccoon.utils.logger import Logger


class NmapScan:
    """
    Nmap scan class
    Will run SYN/TCP scan according to privileges.
    Start Raccoon with sudo for -sS else will run -sT
    """

    def __init__(self, host, full_scan, scripts, services, port_range):
        self.target = host.target
        self.full_scan = full_scan
        self.scripts = scripts
        self.services = services
        self.port_range = port_range
        path = HelperUtilities.get_output_path("{}/nmap_scan.txt".format(self.target))
        self.logger = Logger(path)
        self.script = self.build_script()

    def build_script(self):
        script = ["nmap", "-Pn", self.target]

        if self.port_range:
            HelperUtilities.validate_port_range(self.port_range)
            script.append("-p")
            script.append(self.port_range)
            self.logger.debug("Added port range {} to Nmap script".format(self.port_range))

        if self.full_scan:
            script.append("-sV")
            script.append("-sC")
            self.logger.debug("Added scripts and services to Nmap script")
            return script
        else:
            if self.scripts:
                self.logger.debug("Added script scan to Nmap script")
                script.append("-sC")
            if self.services:
                self.logger.debug("Added service scan to Nmap script")
                script.append("-sV")
        return script


class Scanner:

    @classmethod
    def run(cls, scan):
        scan.logger.debug("Nmap script to run: {}".format(" ".join(scan.script)))
        scan.logger.info("Starting Nmap scan")
        process = Popen(
            scan.script,
            stdout=PIPE,
            stderr=PIPE
        )
        result, err = process.communicate()
        result, err = result.decode().strip(), err.decode().strip()
        Scanner.write_up(scan, result, err)

    @classmethod
    def write_up(cls, scan, result, err):
        if result:
            scan.logger.debug(result+"\n")
        if err:
            scan.logger.debug(err)
