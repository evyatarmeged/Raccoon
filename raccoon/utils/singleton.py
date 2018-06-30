class Singleton(type):
    def __init__(cls, *args, **kwargs):
        super(Singleton, cls).__init__(*args, **kwargs)
        cls.instance = None

    def __call__(cls, *args, **kwargs):
        if not cls.instance:
            cls.instance = super(Singleton, cls).__call__(*args, **kwargs)

        return cls.instance
