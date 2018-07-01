from collections import namedtuple

Color = namedtuple("Color", ["RED", "BLUE", "CYAN", "GREEN", "YELLOW", "GRAY", "BOLD", "RESET"])
COLOR = Color("\033[1;31m", "\033[1;34m", "\033[1;36m", "\033[1;32m", "\033[93m", "\033[1;30m", "\033[;1m", "\033[0;0m")
