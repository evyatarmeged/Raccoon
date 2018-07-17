import logging
from os import path
from sys import stdout
from raccoon_src.utils.singleton import Singleton


class SystemOutLogger(metaclass=Singleton):
    """
    Single instance stdout logger to be shared among modules
    Logging level is set by verbosity/quiet arguments from user
    Logs to stdout - other loggers call its functions to log to stdout
    in addition to their own file-writing logging
    """
    def __init__(self, level="INFO"):
        self.level = level
        self.logger = self.get_logger()

    def get_logger(self):
        logger = logging.getLogger("Raccoon")
        logger.setLevel(self.level)

        out_handler = logging.StreamHandler(stdout)
        formatter = logging.Formatter('%(message)s')
        out_handler.setFormatter(formatter)
        logger.addHandler(out_handler)
        return logger

    def debug(self, *args, **kwargs):
        self.logger.debug(*args, **kwargs)

    def info(self, *args, **kwargs):
        self.logger.info(*args, **kwargs)

    def warning(self, *args, **kwargs):
        self.logger.warning(*args, **kwargs)

    def error(self, *args, **kwargs):
        self.logger.error(*args, **kwargs)

    def critical(self, *args, **kwargs):
        self.logger.critical(*args, **kwargs)


class Logger:
    """
    Logger that should instantiated for each module
    Will write all logs (DEBUG) to self.outfile argument.
    In addition calls SystemOutLogger functions to write to stdout in correspondence with
    verbosity levels
    """

    def __init__(self, outfile):
        self.outfile = outfile
        self.stout_logger = SystemOutLogger()
        self.logger = self.get_logger()

    def get_logger(self):
        logger = logging.getLogger(self.__str__())
        logger.setLevel("DEBUG")

        out_handler = logging.FileHandler(self.outfile)
        formatter = logging.Formatter('%(message)s')
        out_handler.setFormatter(formatter)
        logger.addHandler(out_handler)
        return logger

    def debug(self, *args, **kwargs):
        self.stout_logger.debug(*args, **kwargs)
        self.logger.debug(*args, **kwargs)

    def info(self, *args, **kwargs):
        self.stout_logger.info(*args, **kwargs)
        self.logger.info(*args, **kwargs)

    def warning(self, *args, **kwargs):
        self.stout_logger.warning(*args, **kwargs)
        self.logger.warning(*args, **kwargs)

    def error(self, *args, **kwargs):
        self.stout_logger.error(*args, **kwargs)
        self.logger.error(*args, **kwargs)

    def critical(self, *args, **kwargs):
        self.stout_logger.critical(*args, **kwargs)
        self.logger.critical(*args, **kwargs)
