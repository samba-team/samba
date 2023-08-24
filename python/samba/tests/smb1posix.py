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
from samba import (ntstatus,NTSTATUSError)
import samba.tests.libsmb
import stat

class Smb1PosixTests(samba.tests.libsmb.LibsmbTests):

    def test_directory_case_sensivity(self):
        """Test that in smb1 posix dirs are case sensitive"""
        conn = libsmb.Conn(
            self.server_ip,
            "posix_share",
            self.lp,
            self.creds,
            force_smb1=True)
        conn.smb1_posix()

        try:
            conn.mkdir("lower")
        except NTSTATUSError as e:
            if e.args[0] != ntstatus.NT_STATUS_OBJECT_NAME_COLLISION:
                raise
        try:
            conn.mkdir("lower/second")
        except NTSTATUSError as e:
            if e.args[0] != ntstatus.NT_STATUS_OBJECT_NAME_COLLISION:
                raise

        self.assertFalse(conn.chkpath("Lower/second"))
        conn.rmdir("lower/second")
        conn.rmdir("lower")

    def test_mknod(self):
        """Test SMB1 posix mknod"""
        conn = libsmb.Conn(
            self.server_ip,
            "posix_share",
            self.lp,
            self.creds,
            force_smb1=True)
        conn.smb1_posix()

        def do_test(name, filetype):
            conn.mknod(name, filetype | 0o755)
            st = conn.smb1_stat(name)
            self.assertEqual(st["mode"], filetype | 0o755)
            conn.unlink(name)

        do_test("fifo", stat.S_IFIFO)
        do_test("sock", stat.S_IFSOCK)

if __name__ == '__main__':
    import unittest
    unittest.main()
