# Samba common functions
#
# Copyright (C) Joe Guo <joeg@catalyst.net.nz>
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

import sys
import logging
from samba.colour import GREY, YELLOW, GREEN, RED, DARK_RED, C_NORMAL

LEVEL_COLORS = {
    logging.CRITICAL: DARK_RED,
    logging.ERROR: RED,
    logging.WARNING: YELLOW,
    logging.INFO: GREEN,
    logging.DEBUG: GREY,
}


class ColoredFormatter(logging.Formatter):
    """Add color to log according to level"""

    def format(self, record):
        log = super(ColoredFormatter, self).format(record)
        color = LEVEL_COLORS.get(record.levelno, GREY)
        return color + log + C_NORMAL


def get_samba_logger(
        name='samba', stream=sys.stderr,
        level=None, verbose=False, quiet=False,
        fmt=('%(levelname)s %(asctime)s pid:%(process)d '
             '%(pathname)s #%(lineno)d: %(message)s'),
        datefmt=None):
    """
    Get a logger instance and config it.
    """
    logger = logging.getLogger(name)

    if not level:
        # if level not specified, map options to level
        level = ((verbose and logging.DEBUG) or
                 (quiet and logging.WARNING) or logging.INFO)

    logger.setLevel(level)

    if (hasattr(stream, 'isatty') and stream.isatty()):
        Formatter = ColoredFormatter
    else:
        Formatter = logging.Formatter
    formatter = Formatter(fmt=fmt, datefmt=datefmt)

    handler = logging.StreamHandler(stream=stream)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
