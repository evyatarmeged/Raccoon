import os
from raccoon.utils.exceptions import ScannerException
import asyncio
from subprocess import PIPE, Popen


class NmapScan:
    """
    Nmap scan class
    Will run SYN/TCP scan according to privileges.
    Start Raccoon with sudo for -sS else will run -sT
    """

    def __init__(self, host, full_scan=False, scripts=False, services=False, port_range=None):
        self.target = host.target
        self.full_scan = full_scan
        self.scripts = scripts
        self.services = services
        self.port_range = port_range
        self.script = self.build_script()

    def build_script(self):
        script = "nmap -Pn {}".format(self.target)

        if self.port_range:
            if "-" not in self.port_range or len(self.port_range.split("-") != 2):
                raise ScannerExceptions("Invalid port range {}".format(self.port_range))
            script += " -p {}".format(self.port_range)
            print("Added port range to nmap script {}".format(self.port_range))

        if self.full_scan:
            script += " -sV -sC"
            print("Added scripts and services to nmap script")
            return script
        else:
            if self.scripts:
                print("Added script scan to nmap script")
                script += " -sC"
            if self.services:
                print("Added service scan to nmap script")
                script += " -sV"
            else:
                print("Running basic nmap scan")
        return script.split()


class Scanner:

    @classmethod
    def run(cls, scan):
        print("Starting nmap scan on {}".format(scan.target))
        process = Popen(
            scan.script,
            stdout=PIPE,
            stderr=PIPE
        )
        result, err = process.communicate()
        result, err = result.decode().strip(), err.decode().strip()
        Scanner.write_up(scan.target, result, err)

    @classmethod
    def write_up(cls, target, result, err):
        path = "nmap_scans/{}".format(target)
        print("Writing nmap scan results to {}".format(path))
        try:
            os.mkdir("nmap_scans")
        except FileExistsError:
            pass

        with open(path, "w") as file:
            if err:
                file.write(err)
            elif result:
                file.write(result)
