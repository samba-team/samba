# Unix SMB/CIFS implementation.
# Copyright Volker Lendecke <vl@samba.org> 2026
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

"""Tests for oplock breaks via samba.samba3.libsmb."""

import threading

from samba.samba3 import libsmb_samba_internal as libsmb
from samba.dcerpc import security
import samba.tests.libsmb


class OplockTests(samba.tests.libsmb.LibsmbTests):
    """Conn.get_oplock_break(), which only sees SMB1 breaks"""

    def test_get_oplock_break(self):
        holder = libsmb.Conn(self.server_ip,
                             "tmp",
                             self.lp,
                             self.creds,
                             multi_threaded=True,
                             force_smb1=True)
        other = libsmb.Conn(self.server_ip,
                            "tmp",
                            self.lp,
                            self.creds,
                            multi_threaded=True,
                            force_smb1=True)
        fname = "test_get_oplock_break"
        self.addCleanup(self.clean_file, other, fname)

        fnum = holder.create(fname,
                             CreateFlags=(libsmb.REQUEST_OPLOCK |
                                          libsmb.REQUEST_BATCH_OPLOCK),
                             DesiredAccess=security.SEC_FILE_READ_DATA,
                             ShareAccess=(libsmb.FILE_SHARE_READ |
                                          libsmb.FILE_SHARE_WRITE |
                                          libsmb.FILE_SHARE_DELETE),
                             CreateDisposition=libsmb.FILE_OPEN_IF)

        # The second open waits for the break to be acknowledged,
        # which the holder's close does. Only a multi_threaded Conn
        # drops the GIL while it waits.
        error = None

        def open_other():
            nonlocal error
            try:
                ofnum = other.create(
                    fname,
                    DesiredAccess=security.SEC_FILE_READ_DATA,
                    ShareAccess=(libsmb.FILE_SHARE_READ |
                                 libsmb.FILE_SHARE_WRITE |
                                 libsmb.FILE_SHARE_DELETE),
                    CreateDisposition=libsmb.FILE_OPEN)
                other.close(ofnum)
            except Exception as e:
                error = e

        t = threading.Thread(target=open_other, daemon=True)
        t.start()

        try:
            brk = holder.get_oplock_break()
            self.assertEqual(brk["fnum"], fnum)
            # Conn does not announce CAP_LEVEL_II_OPLOCKS, so smbd
            # breaks to none
            self.assertEqual(brk["level"], 0)
        finally:
            try:
                holder.close(fnum)
            finally:
                t.join(timeout=20)
        self.assertFalse(t.is_alive())
        if error is not None:
            raise error


if __name__ == "__main__":
    import unittest
    unittest.main()
