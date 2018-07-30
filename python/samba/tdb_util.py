# Unix SMB/CIFS implementation.
# tdb util helpers
#
# Copyright (C) Kai Blin <kai@samba.org> 2011
# Copyright (C) Amitay Isaacs <amitay@gmail.com> 2011
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2013
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


def tdb_copy(file1, file2, readonly=False):
    """Copy tdb file using tdbbackup utility and rename it
    """
    # Find the location of tdbbackup tool
    dirs = ["bin", samba.param.bin_dir()] + os.getenv('PATH').split(os.pathsep)
    for d in dirs:
        toolpath = os.path.join(d, "tdbbackup")
        if os.path.exists(toolpath):
            break

    tdbbackup_cmd = [toolpath, "-s", ".copy.tdb", file1]
    if readonly:
        tdbbackup_cmd.append("-r")

    status = subprocess.check_call(tdbbackup_cmd, close_fds=True, shell=False)

    os.rename("%s.copy.tdb" % file1, file2)
