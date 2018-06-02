from collections import namedtuple

Color = namedtuple("Color", ["RED", "BLUE", "CYAN", "GREEN", "YELLOW", "BOLD", "RESET"])
COLOR = Color("\033[1;31m", "\033[1;34m", "\033[1;36m", "\033[0;32m", "\033[0;33m", "\033[;1m", "\033[0;0m")
