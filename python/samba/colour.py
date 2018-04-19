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
# RED, DARK_RED, REV_RED (for red background), and REV_DARK_RED. If
# switch_colour_off() is called, these names will all point to the
# empty string. switch_colour_on() restores the default values.
#
# The 256-colour codes are obtained using xterm_256_color(n), where n
# is the number of the desired colour.


def _gen_ansi_colours():
    g = globals()
    for i, name in enumerate(('BLACK', 'RED', 'GREEN', 'YELLOW', 'BLUE',
                              'MAGENTA', 'CYAN', 'WHITE')):
        g[name] = "\033[1;3%dm" % i
        g['DARK_' + name] = "\033[3%dm" % i
        g['REV_' + name] = "\033[1;4%dm" % i
        g['REV_DARK_' + name] = "\033[4%dm" % i

    # kcc.debug uses these aliases (which make visual sense)
    g['PURPLE'] = DARK_MAGENTA
    g['GREY'] = DARK_WHITE

    # C_NORMAL resets to normal, whatever that is
    g['C_NORMAL'] = "\033[0m"

    # Non-colour ANSI codes.
    g['UNDERLINE'] = "\033[4m"


_gen_ansi_colours()

# Generate functions that colour a string. The functions look like
# this:
#
#    c_BLUE("hello")  # "\033[1;34mhello\033[0m" -> blue text
#    c_DARK_RED(3)    # 3 will be stringified and coloured
#
# but if colour is switched off, no colour codes are added.
#
#    c_BLUE("hello")  # "hello"
#
# The definition of the functions looks a little odd, because we want
# to bake in the name of the colour but not its actual value.

for _k in list(globals().keys()):
    if _k.isupper():
        def _f(s, name=_k):
            return "%s%s%s" % (globals()[name], s, C_NORMAL)
        globals()['c_%s' % _k] = _f

del _k, _f


def switch_colour_off():
    """Convert all the ANSI colour codes into empty strings."""
    g = globals()
    for k, v in list(g.items()):
        if k.isupper() and isinstance(v, str) and v.startswith('\033'):
            g[k] = ''


def switch_colour_on():
    """Regenerate all the ANSI colour codes."""
    _gen_ansi_colours()


def xterm_256_colour(n, bg=False, bold=False):
    weight = '01;' if bold else ''
    target = '48' if bg else '38'

    return "\033[%s%s;5;%dm" % (weight, target, int(n))
