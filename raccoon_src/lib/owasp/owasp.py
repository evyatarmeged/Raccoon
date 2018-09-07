from os import mkdir
from raccoon_src.utils.help_utils import HelpUtilities
from raccoon_src.utils.logger import SystemOutLogger
from raccoon_src.utils.coloring import COLORED_COMBOS, COLOR


class OWASPScanner:

    def __init__(self, host):
        self.host = host
        self._subscribers = []
        self.running_threads = []
        self.logger = SystemOutLogger()

        try:
            mkdir(HelpUtilities.PATH+"/owasp")
        except FileExistsError:
            pass

    def discover_dir_traversal(self):
        # if potentially vulnerable, create instance and run scan in a new thread
        pass

    def discover_rfi(self):
        # if potentially vulnerable, create instance and run scan in a new thread
        pass

    def run(self):
        # Perform all checks, create relevant threads
        pass
