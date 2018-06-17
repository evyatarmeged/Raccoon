class RaccoonBaseException(Exception):
    """Raccoon base exception class"""
    def __init__(self, message='Raccoon Base Exception'):
        self._message = message

    def __str__(self):
        return self._message


class FuzzerException(RaccoonBaseException):
    def __init__(self, message='Fuzzer Exception'):
        super().__init__(message)

    def __str__(self):
        return self._message


class HostHandlerException(RaccoonBaseException):
    def __init__(self, message='Host Handler Exception'):
        super().__init__(message)

    def __str__(self):
        return self._message


class ScannerException(RaccoonBaseException):
    def __init__(self, message='Scanner Exception'):
        super().__init__(message)

    def __str__(self):
        return self._message


class WAFException(RaccoonBaseException):
    def __init__(self, message='WAF Exception'):
        super().__init__(message)

    def __str__(self):
        return self._message


class RequestHandlerException(RaccoonBaseException):

    def __init__(self, message='RequestHandler Exception'):
        super().__init__(message)

    def __str__(self):
        return self._message


class RequestHandlerConnectionReset(RequestHandlerException):

    def __init__(self, message='Connection Reset'):
        super().__init__(message)

    def __str__(self):
        return self._message

