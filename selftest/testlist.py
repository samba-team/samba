# testlist.py -- Test list
# Copyright (C) 2012 Jelmer Vernooij <jelmer@samba.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 3
# of the License or (at your option) any later version of
# the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.

"""Selftest test list management."""

__all__ = ['find_in_list', 'read_test_regexes']

import re

def find_in_list(list, fullname):
    """Find test in list.

    :param list: List with 2-tuples with regex and reason
    """
    for (regex, reason) in list:
        if re.match(regex, fullname):
            if reason is not None:
                return reason
            else:
                return ""
    return None


def read_test_regexes(f):
    """Read tuples with regular expression and optional string from a file.

    :param f: File-like object to read from
    :return: Iterator over tuples with regular expression and test name
    """
    for l in f.readlines():
        l = l.strip()
        if l[0] == "#":
            continue
        try:
            (test, reason) = l.split("#", 1)
        except ValueError:
            yield l, None
        else:
            yield test.strip(), reason.strip()
