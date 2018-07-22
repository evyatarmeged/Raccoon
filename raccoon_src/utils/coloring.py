from collections import namedtuple

Color = namedtuple("Color", ["RED", "BLUE", "CYAN", "GREEN", "YELLOW", "GRAY", "BOLD", "RESET"])
COLOR = Color(
    "\033[1;31m",  # red
    "\033[1;34m",  # blue
    "\033[1;36m",  # cyan
    "\033[1;32m",  # green
    "\033[93m",    # yellow
    "\033[1;30m",  # gray
    "\033[;1m",    # bold
    "\033[0;0m"    # reset
)

ColoredCombos = namedtuple("ColoredCombos", ["INFO", "GOOD", "BAD", "NOTIFY"])
COLORED_COMBOS = ColoredCombos(
    "{}[#]{}".format(COLOR.BLUE, COLOR.RESET),
    "{}[v]{}".format(COLOR.GREEN, COLOR.RESET),
    "{}[x]{}".format(COLOR.RED, COLOR.RESET),
    "{}[!]{}".format(COLOR.YELLOW, COLOR.RESET))
