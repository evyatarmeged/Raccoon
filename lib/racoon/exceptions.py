# TODO: Put all exceptions here with a general Racoon exception class


class RaccoonException(Exception):
    """Host base exception class"""
    def __init__(self, message='Host Handler Exception'):
        self._message = message

    def __str__(self):
        return self._message


class FuzzerException(RaccoonException):
    """Host base exception class"""
    def __init__(self, message='Base Fuzzer Exception'):
        super().__init__(message)

    def __str__(self):
        return self._message


class HostHandlerException(Exception):
    """Host base exception class"""
    def __init__(self, message='Host Handler Exception'):
        self._message = message

    def __str__(self):
        return self._message

