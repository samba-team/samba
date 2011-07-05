#!/usr/bin/env python
#
# Samba common functions
#
# Copyright (C) Matthieu Patou <mat@matws.net>
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

def confirm(msg, forced = False, allow_all=False):
    """confirm an action with the user
        :param msg: A string to print to the user
        :param forced: Are the answer forced
    """
    if forced:
        print("%s [YES]" % msg)
        return True

    mapping = {
        'Y': True,
        'YES': True,
        '': False,
        'N': False,
        'NO': False,
        }

    prompt = '[y/N]'

    if allow_all:
        mapping['ALL'] = 'ALL'
        mapping['NONE'] = 'NONE'
        prompt = '[y/N/all/none]'

    while True:
        v = raw_input(msg + ' %s ' % prompt)
        v = v.upper()
        if v in mapping:
            return mapping[v]
        print("Unknown response '%s'" % v)


