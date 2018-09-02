class Singleton(type):

    def __init__(cls, *args, **kwargs):
        super().__init__(*args, **kwargs)
        cls.instance = None

    def __call__(cls, *args, **kwargs):
        if not cls.instance:
            cls.instance = super().__call__(*args, **kwargs)

        return cls.instance
