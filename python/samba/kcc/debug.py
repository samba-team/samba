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


#colours for prettier logs
C_NORMAL = "\033[00m"
DARK_RED = "\033[00;31m"
RED = "\033[01;31m"
DARK_GREEN = "\033[00;32m"
GREEN = "\033[01;32m"
YELLOW = "\033[01;33m"
DARK_YELLOW = "\033[00;33m"
DARK_BLUE = "\033[00;34m"
BLUE = "\033[01;34m"
PURPLE = "\033[00;35m"
MAGENTA = "\033[01;35m"
DARK_CYAN = "\033[00;36m"
CYAN = "\033[01;36m"
GREY = "\033[00;37m"
WHITE = "\033[01;37m"
REV_RED = "\033[01;41m"


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
