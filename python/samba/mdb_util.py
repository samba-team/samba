# Unix SMB/CIFS implementation.
# mdb util helpers
#
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018
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

import samba
import subprocess
import os
from samba.netcmd import CommandError


def mdb_copy(file1, file2):
    """Copy mdb file using mdb_copy utility and rename it
    """
    # Find the location of the mdb_copy tool
    dirs = os.getenv('PATH').split(os.pathsep)
    found = False
    for d in dirs:
        toolpath = os.path.join(d, "mdb_copy")
        if os.path.exists(toolpath):
            found = True
            break

    if not found:
        raise CommandError("mdb_copy not found. "
                           "You may need to install the lmdb-utils package")

    mdb_copy_cmd = [toolpath, "-n", file1, "%s.copy.mdb" % file1]
    status = subprocess.check_call(mdb_copy_cmd, close_fds=True, shell=False)

    os.rename("%s.copy.mdb" % file1, file2)
