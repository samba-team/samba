# Unix SMB/CIFS implementation.
# Copyright Volker Lendecke <vl@samba.org> 2012
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

"""Tests for samba.samba3.libsmb."""

from samba.samba3 import libsmb_samba_internal as libsmb
from samba.dcerpc import security
from samba.samba3 import param as s3param
from samba import credentials
from samba import (ntstatus,NTSTATUSError)
import samba.tests
import os
import stat

class LibsmbTests(samba.tests.TestCase):

    def setUp(self):
        self.lp = s3param.get_context()
        self.lp.load(samba.tests.env_get_var_value("SMB_CONF_PATH"))

        self.creds = credentials.Credentials()
        self.creds.guess(self.lp)
        self.creds.set_domain(samba.tests.env_get_var_value("DOMAIN"))
        self.creds.set_username(samba.tests.env_get_var_value("USERNAME"))
        self.creds.set_password(samba.tests.env_get_var_value("PASSWORD"))

        # Build the global inject file path
        server_conf = samba.tests.env_get_var_value("SERVERCONFFILE")
        server_conf_dir = os.path.dirname(server_conf)
        self.global_inject = os.path.join(server_conf_dir, "global_inject.conf")

        self.server_ip = samba.tests.env_get_var_value("SERVER_IP")

    def clean_file(self, conn, filename):
        try:
            conn.unlink(filename)
        except NTSTATUSError as e:
            if e.args[0] == ntstatus.NT_STATUS_FILE_IS_A_DIRECTORY:
                conn.rmdir(filename)
            elif not (e.args[0] == ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND or
                      e.args[0] == ntstatus.NT_STATUS_OBJECT_PATH_NOT_FOUND):
                raise

    def wire_mode_to_unix(self, wire):
        mode = libsmb.wire_mode_to_unix(wire)
        type = stat.S_IFMT(mode)
        perms = mode & (stat.S_IRWXU|stat.S_IRWXG|stat.S_IRWXO|
                        stat.S_ISUID|stat.S_ISGID|stat.S_ISVTX)
        return (type, perms)
