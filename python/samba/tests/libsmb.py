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
from samba import (credentials,NTSTATUSError)
from samba.ntstatus import NT_STATUS_DELETE_PENDING
from samba.credentials import SMB_ENCRYPTION_REQUIRED
import samba.tests
import threading
import sys
import os
import random


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

    def prep_creds(self):
        lp = s3param.get_context()
        lp.load(os.getenv("SMB_CONF_PATH"))

        creds = credentials.Credentials()
        creds.guess(lp)
        creds.set_username(os.getenv("USERNAME"))
        creds.set_password(os.getenv("PASSWORD"))

        return (lp,creds)

    def test_OpenClose(self):
        (lp,creds) = self.prep_creds()

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

    def test_SMB3EncryptionRequired(self):
        test_dir = 'testing_%d' % random.randint(0, 0xFFFF)

        (lp,creds) = self.prep_creds()
        creds.set_smb_encryption(SMB_ENCRYPTION_REQUIRED)

        c = libsmb.Conn(os.getenv("SERVER_IP"), "tmp",
                        lp, creds)

        c.mkdir(test_dir)
        c.rmdir(test_dir)

    def test_SMB1EncryptionRequired(self):
        test_dir = 'testing_%d' % random.randint(0, 0xFFFF)

        (lp,creds) = self.prep_creds()
        creds.set_smb_encryption(SMB_ENCRYPTION_REQUIRED)

        c = libsmb.Conn(os.getenv("SERVER_IP"), "tmp",
                        lp, creds, force_smb1=True)

        c.mkdir(test_dir)
        c.rmdir(test_dir)

    def test_RenameDstDelOnClose(self):
        (lp,creds) = self.prep_creds()

        dstdir = "\\dst-subdir"

        c1 = libsmb.Conn(os.getenv("SERVER_IP"), "tmp", lp, creds)
        c2 = libsmb.Conn(os.getenv("SERVER_IP"), "tmp", lp, creds)

        try:
            c1.deltree(dstdir)
        except:
            pass

        c1.mkdir(dstdir)
        dnum = c1.create(dstdir, DesiredAccess=security.SEC_STD_DELETE)
        c1.delete_on_close(dnum,1)
        c2.savefile("\\src.txt", b"Content")

        with self.assertRaises(NTSTATUSError) as cm:
            c2.rename("\\src.txt", dstdir + "\\dst.txt")
        if (cm.exception.args[0] != NT_STATUS_DELETE_PENDING):
            raise AssertionError("Rename must fail with DELETE_PENDING")

        c1.delete_on_close(dnum,0)
        c1.close(dnum)

        try:
            c1.deltree(dstdir)
            c1.unlink("\\src.txt")
        except:
            pass

    def test_libsmb_CreateContexts(self):
        (lp,creds) = self.prep_creds()
        c = libsmb.Conn(os.getenv("SERVER_IP"), "tmp", lp, creds)
        cc_in = [(libsmb.SMB2_CREATE_TAG_MXAC, b'')]
        fnum,cr,cc = c.create_ex("",CreateContexts=cc_in)
        self.assertEqual(
            cr['file_attributes'] & libsmb.FILE_ATTRIBUTE_DIRECTORY,
            libsmb.FILE_ATTRIBUTE_DIRECTORY)
        self.assertEqual(cc[0][0],libsmb.SMB2_CREATE_TAG_MXAC)
        self.assertEqual(len(cc[0][1]),8)
        c.close(fnum)

if __name__ == "__main__":
    import unittest
    unittest.main()
