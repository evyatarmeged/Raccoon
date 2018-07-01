import logging
from sys import stdout
from raccoon.utils.singleton import Singleton
from raccoon.utils.exceptions import RaccoonException


class Logger(metaclass=Singleton):

    def __init__(self, level):
        self.level = level
        self.logger = self.get_logger()

    def get_logger(self):
        logger = logging.getLogger("Raccoon")
        try:
            if type(self.level) == str:
                level = logging.getLevelName(self.level.upper())
            elif type(self.level) == int:
                level = logging.getLevelName(self.level)
            logger.setLevel(level)
        except ValueError:
            raise RaccoonException("\nInvalid logging level: {}\nValue should be one of the following:"
                                   " DEBUG,INFO,WARNING,ERROR,CRITICAL\n"
                                   "or numeric: 10,20,30,40,50".format(self.level))

        out_handler = logging.StreamHandler(stdout)
        out_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(message)s'))
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
