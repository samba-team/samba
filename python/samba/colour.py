# ANSI codes for 4 bit and xterm-256color
#
# Copyright (C) Andrew Bartlett 2018
#
# Originally written by Douglas Bagnall
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# The 4 bit colours are available as global variables with names like
# RED, DARK_RED, REV_RED (for red background), and REV_DARK_RED.
#
# The 256-colour codes are obtained using xterm_256_color(n), where n
# is the number of the desired colour.

# C_NORMAL resets to normal, whatever that is
C_NORMAL = "\033[0m"

UNDERLINE = "\033[4m"

def _gen_ansi_colours():
    g = globals()
    for i, name in enumerate(('BLACK', 'RED', 'GREEN', 'YELLOW', 'BLUE',
                              'MAGENTA', 'CYAN', 'WHITE')):
        g[name] = "\033[1;3%dm" % i
        g['DARK_' + name] = "\033[3%dm" % i
        g['REV_' + name] = "\033[1;4%dm" % i
        g['REV_DARK_' + name] = "\033[4%dm" % i

_gen_ansi_colours()

# kcc.debug uses these aliases (which make visual sense)
PURPLE = DARK_MAGENTA
GREY = DARK_WHITE

def xterm_256_colour(n, bg=False, bold=False):
    weight = '01;' if bold else ''
    target = '48' if bg else '38'

    return "\033[%s%s;5;%dm" % (weight, target, int(n))
