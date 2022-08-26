# Unix SMB/CIFS implementation.
# Copyright Volker Lendecke <vl@samba.org> 2022
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

from samba.samba3 import libsmb_samba_internal as libsmb
from samba.samba3 import param as s3param
from samba import (credentials,NTSTATUSError)
import samba.tests
import os

class Smb3UnixTests(samba.tests.TestCase):

    def setUp(self):
        self.lp = s3param.get_context()
        self.lp.load(os.getenv("SMB_CONF_PATH"))

        self.creds = credentials.Credentials()
        self.creds.guess(self.lp)
        self.creds.set_username(os.getenv("USERNAME"))
        self.creds.set_password(os.getenv("PASSWORD"))

        # Build the global inject file path
        server_conf = os.getenv("SERVERCONFFILE")
        server_conf_dir = os.path.dirname(server_conf)
        self.global_inject = os.path.join(server_conf_dir, "global_inject.conf")

    def enable_smb3unix(self):
        with open(self.global_inject, 'w') as f:
            f.write("smb3 unix extensions = yes\n")

    def disable_smb3unix(self):
        with open(self.global_inject, 'w') as f:
            f.truncate()

    def test_negotiate_context_posix(self):
        try:
            self.enable_smb3unix()

            c = libsmb.Conn(
                os.getenv("SERVER_IP"),
                "tmp",
                self.lp,
                self.creds,
                posix=True)
            self.assertTrue(c.have_posix())

        finally:
            self.disable_smb3unix()

    def test_negotiate_context_noposix(self):
        c = libsmb.Conn(
                os.getenv("SERVER_IP"),
                "tmp",
                self.lp,
                self.creds,
                posix=True)
        self.assertFalse(c.have_posix())
