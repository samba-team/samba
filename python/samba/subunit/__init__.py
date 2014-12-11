# Subunit handling
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2014
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

"""Subunit test protocol."""

import datetime


PROGRESS_SET = 0
PROGRESS_CUR = 1
PROGRESS_PUSH = 2
PROGRESS_POP = 3


# From http://docs.python.org/library/datetime.html
_ZERO = datetime.timedelta(0)

# A UTC class.

class UTC(datetime.tzinfo):
    """UTC"""

    def utcoffset(self, dt):
        return _ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return _ZERO

utc = UTC()
