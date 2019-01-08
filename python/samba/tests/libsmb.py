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
import samba.tests
import threading
import sys
import os


class LibsmbTestCase(samba.tests.TestCase):

    class OpenClose(threading.Thread):

        def __init__(self, conn, filename, num_ops):
            threading.Thread.__init__(self)
            self.conn = conn
            self.filename = filename
            self.num_ops = num_ops
            self.exc = False

        def run(self):
            c = self.conn
            try:
                for i in range(self.num_ops):
                    f = c.create(self.filename, CreateDisposition=3,
                                 DesiredAccess=security.SEC_STD_DELETE)
                    c.delete_on_close(f, True)
                    c.close(f)
            except Exception:
                self.exc = sys.exc_info()

    def test_OpenClose(self):

        lp = s3param.get_context()
        lp.load(os.getenv("SMB_CONF_PATH"))

        creds = credentials.Credentials()
        creds.guess(lp)
        creds.set_username(os.getenv("USERNAME"))
        creds.set_password(os.getenv("PASSWORD"))

        c = libsmb.Conn(os.getenv("SERVER_IP"), "tmp",
                        lp, creds, multi_threaded=True,
                        force_smb1=True)

        mythreads = []

        for i in range(3):
            t = LibsmbTestCase.OpenClose(c, "test" + str(i), 10)
            mythreads.append(t)

        for t in mythreads:
            t.start()

        for t in mythreads:
            t.join()
            if t.exc:
                raise t.exc[0](t.exc[1])


if __name__ == "__main__":
    import unittest
    unittest.main()
