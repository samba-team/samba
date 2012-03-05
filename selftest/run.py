#!/usr/bin/python -u
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2012 Jelmer Vernooij <jelmer@samba.org>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import subprocess
import warnings

# expand strings from %ENV
def expand_environment_strings(s, vars):
    # we use a reverse sort so we do the longer ones first
    for k in sorted(vars.keys(), reverse=True):
        v = vars[k]
        s = s.replace("$%s" % k, v)
    return s


def expand_command_list(cmd):
    if not "$LISTOPT" in cmd:
        return None
    return cmd.replace("$LISTOPT", "--list")
