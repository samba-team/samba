# Debug utilities for samba_kcc
#
# Copyright (C) Andrew Bartlett 2015
#
# Although Andrew Bartlett owns the copyright, the actual work was
# performed by Douglas Bagnall and Garming Sam.
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

import sys
import logging
from functools import partial
import traceback

logger = logging.getLogger("samba_kcc")
logger.addHandler(logging.StreamHandler(sys.stdout))
DEBUG = logger.debug
WARN = logger.warning


# colours for prettier logs
from samba.colour import C_NORMAL, REV_RED
from samba.colour import DARK_RED, RED
from samba.colour import DARK_GREEN, GREEN
from samba.colour import DARK_YELLOW, YELLOW
from samba.colour import DARK_BLUE, BLUE
from samba.colour import PURPLE, MAGENTA
from samba.colour import DARK_CYAN, CYAN
from samba.colour import GREY, WHITE


def _color_debug(*args, **kwargs):
    DEBUG('%s%s%s' % (kwargs['color'], args[0], C_NORMAL), *args[1:])


_globals = globals()
for _color in ('DARK_RED', 'RED', 'DARK_GREEN', 'GREEN', 'YELLOW',
               'DARK_YELLOW', 'DARK_BLUE', 'BLUE', 'PURPLE', 'MAGENTA',
               'DARK_CYAN', 'CYAN', 'GREY', 'WHITE', 'REV_RED'):
    _globals['DEBUG_' + _color] = partial(_color_debug, color=_globals[_color])


def DEBUG_FN(msg=''):
    filename, lineno, function, text = traceback.extract_stack(None, 2)[0]
    DEBUG("%s%s:%s%s %s%s()%s '%s'" % (CYAN, filename, BLUE, lineno,
                                       CYAN, function, C_NORMAL, msg))


def null_debug(*args, **kwargs):
    pass
