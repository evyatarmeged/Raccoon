from collections import namedtuple

Color = namedtuple("Color", ["RED", "BLUE", "CYAN", "GREEN", "YELLOW", "BOLD", "RESET"])
COLOR = Color("\033[91m", "\033[94m", "\033[1;36m", "\033[92m", "\033[93m", "\033[;1m", "\033[0;0m")
