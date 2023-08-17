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


def is_colour_wanted(*streams, hint='auto'):
    """The hint is presumably a --color argument.

    The streams to be considered can be file objects or file names,
    with '-' being a special filename indicating stdout.

    We follow the behaviour of GNU `ls` in what we accept.
    * `git` is stricter, accepting only {always,never,auto}.
    * `grep` is looser, accepting mixed case variants.
    * historically we have used {yes,no,auto}.
    * {always,never,auto} appears the commonest convention.
    * if the caller tries to opt out of choosing and sets hint to None
      or '', we assume 'auto'.
    """
    if hint in ('no', 'never', 'none'):
        return False

    if hint in ('yes', 'always', 'force'):
        return True

    if hint not in ('auto', 'tty', 'if-tty', None, ''):
        raise ValueError("unexpected colour hint: {hint}; "
                         "try always|never|auto")

    from os import environ
    if environ.get('NO_COLOR'):
        # Note: per spec, we treat the empty string as if unset.
        return False

    for stream in streams:
        if isinstance(stream, str):
            # This function can be passed filenames instead of file
            # objects, in which case we treat '-' as stdout, and test
            # that. Any other string is not regarded as a tty.
            if stream != '-':
                return False
            import sys
            stream = sys.stdout

        if not stream.isatty():
            return False
    return True


def colour_if_wanted(*streams, hint='auto'):
    wanted = is_colour_wanted(*streams, hint=hint)
    if wanted:
        switch_colour_on()
    else:
        switch_colour_off()
    return wanted


def colourdiff(a, b):
    """Generate a string comparing two strings or byte sequences, with
    differences coloured to indicate what changed.

    Byte sequences are printed as hex pairs separated by colons.
    """
    from difflib import SequenceMatcher
    out = []
    if isinstance(a, bytes):
        a = a.hex(':')
    if isinstance(b, bytes):
        b = b.hex(':')
    a = a.replace(' ', '␠')
    b = b.replace(' ', '␠')

    s = SequenceMatcher(None, a, b)
    for op, al, ar, bl, br in s.get_opcodes():
        if op == 'equal':
            out.append(a[al: ar])
        elif op == 'delete':
            out.append(c_RED(a[al: ar]))
        elif op == 'insert':
            out.append(c_GREEN(b[bl: br]))
        elif op == 'replace':
            out.append(c_RED(a[al: ar]))
            out.append(c_GREEN(b[bl: br]))
        else:
            out.append(f' --unknown diff op {op}!-- ')

    return ''.join(out)
