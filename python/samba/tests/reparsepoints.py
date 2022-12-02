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
from samba.dcerpc import security as sec
from samba import reparse_symlink
import samba.tests.libsmb

class ReparsePoints(samba.tests.libsmb.LibsmbTests):

    def connection(self):
        share = samba.tests.env_get_var_value("SHARENAME")
        smb1 = samba.tests.env_get_var_value("SMB1", allow_missing=True)
        conn = libsmb.Conn(
            self.server_ip,
            share,
            self.lp,
            self.creds,
            force_smb1=smb1)
        return conn

    def clean_file(self, conn, filename):
        try:
            conn.unlink(filename)
        except NTSTATUSError as e:
            err = e.args[0]
            ok = (err == ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND)
            ok |= (err == ntstatus.NT_STATUS_OBJECT_PATH_NOT_FOUND)
            ok |= (err == ntstatus.NT_STATUS_IO_REPARSE_TAG_NOT_HANDLED)
            if not ok:
                raise

    def test_error_not_a_reparse_point(self):
        conn = self.connection()
        filename = 'reparse'
        self.clean_file(conn, filename)

        fd = conn.create(
            filename,
            DesiredAccess=sec.SEC_FILE_WRITE_ATTRIBUTE,
            CreateDisposition=libsmb.FILE_CREATE)

        with self.assertRaises(NTSTATUSError) as e:
            conn.fsctl(fd, libsmb.FSCTL_GET_REPARSE_POINT, b'', 1024)

        self.assertEqual(e.exception.args[0],
                         ntstatus.NT_STATUS_NOT_A_REPARSE_POINT)

        conn.close(fd)

        self.clean_file(conn, filename)

    def test_create_reparse(self):
        conn = self.connection()
        filename = 'reparse'
        self.clean_file(conn, filename)

        fd = conn.create(
            filename,
            DesiredAccess=sec.SEC_FILE_WRITE_ATTRIBUTE,
            CreateDisposition=libsmb.FILE_CREATE)
        b = reparse_symlink.put(0x80000025, 0, b'asdfasdfasdfasdfasdfasdf')
        conn.fsctl(fd, libsmb.FSCTL_SET_REPARSE_POINT, b, 0)
        b = reparse_symlink.put(0x80000026, 0, b'asdfasdfasdfasdfasdfasdf')
        conn.fsctl(fd, libsmb.FSCTL_SET_REPARSE_POINT, b, 0)

    # Show that we can write to a reparse point when opened properly
    def test_write_reparse(self):
        conn = self.connection()
        filename = 'reparse'
        self.clean_file(conn, filename)

        fd = conn.create(
            filename,
            DesiredAccess=sec.SEC_FILE_WRITE_ATTRIBUTE,
            CreateDisposition=libsmb.FILE_CREATE)
        b = reparse_symlink.put(0x80000025, 0, b'asdfasdfasdfasdfasdfasdf')
        conn.fsctl(fd, libsmb.FSCTL_SET_REPARSE_POINT, b, 0)
        conn.close(fd);

        fd,cr,_ = conn.create_ex(
            filename,
            DesiredAccess=sec.SEC_FILE_WRITE_DATA|sec.SEC_STD_DELETE,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT,
            CreateDisposition=libsmb.FILE_OPEN)
        self.assertEqual(
            cr['file_attributes'] & libsmb.FILE_ATTRIBUTE_REPARSE_POINT,
            libsmb.FILE_ATTRIBUTE_REPARSE_POINT)

        conn.write(fd, b'x', 1)

        conn.delete_on_close(fd, 1)
        conn.close(fd);

    # Show that directories can carry reparse points

    def test_create_reparse_directory(self):
        conn = self.connection()
        dirname = "reparse_dir"
        filename = f'{dirname}\\file.txt'

        self.clean_file(conn, filename)
        self.clean_file(conn, dirname)

        dir_fd = conn.create(
            dirname,
            DesiredAccess=sec.SEC_FILE_WRITE_ATTRIBUTE|
            sec.SEC_STD_DELETE,
            CreateDisposition=libsmb.FILE_CREATE,
            CreateOptions=libsmb.FILE_DIRECTORY_FILE)
        b = reparse_symlink.put(0x80000025, 0, b'asdfasdfasdfasdfasdfasdf')
        conn.fsctl(dir_fd, libsmb.FSCTL_SET_REPARSE_POINT, b, 0)

        with self.assertRaises(NTSTATUSError) as e:
            fd = conn.create(
                filename,
                DesiredAccess=sec.SEC_STD_DELETE,
                CreateDisposition=libsmb.FILE_CREATE)

        self.assertEqual(e.exception.args[0],
                         ntstatus.NT_STATUS_IO_REPARSE_TAG_NOT_HANDLED)

        conn.delete_on_close(dir_fd, 1)
        conn.close(dir_fd);

    # Only empty directories can carry reparse points

    def test_create_reparse_nonempty_directory(self):
        conn = self.connection()
        dirname = "reparse_dir"
        filename = f'{dirname}\\file.txt'

        self.clean_file(conn, filename)
        self.clean_file(conn, dirname)

        dir_fd = conn.create(
            dirname,
            DesiredAccess=sec.SEC_FILE_WRITE_ATTRIBUTE|
            sec.SEC_STD_DELETE,
            CreateDisposition=libsmb.FILE_CREATE,
            CreateOptions=libsmb.FILE_DIRECTORY_FILE)
        fd = conn.create(
            filename,
            DesiredAccess=sec.SEC_FILE_WRITE_ATTRIBUTE|
            sec.SEC_STD_DELETE,
            CreateDisposition=libsmb.FILE_CREATE)

        b = reparse_symlink.put(0x80000025, 0, b'asdf')
        try:
            conn.fsctl(dir_fd, libsmb.FSCTL_SET_REPARSE_POINT, b, 0)
        except NTSTATUSError as e:
            err = e.args[0]
            ok = (err == ntstatus.NT_STATUS_DIRECTORY_NOT_EMPTY)
            if not ok:
                raise

        conn.delete_on_close(fd, 1)
        conn.close(fd)
        conn.delete_on_close(dir_fd, 1)
        conn.close(dir_fd)

    # Show that reparse point opens respect share modes

    def test_reparse_share_modes(self):
        conn = self.connection()
        filename = 'reparse'
        self.clean_file(conn, filename)

        fd = conn.create(
            filename,
            DesiredAccess=sec.SEC_FILE_WRITE_ATTRIBUTE,
            CreateDisposition=libsmb.FILE_CREATE)
        b = reparse_symlink.put(0x80000025, 0, b'asdfasdfasdfasdfasdfasdf')
        conn.fsctl(fd, libsmb.FSCTL_SET_REPARSE_POINT, b, 0)
        conn.close(fd);

        fd1 = conn.create(
            filename,
            DesiredAccess=sec.SEC_FILE_READ_DATA|sec.SEC_STD_DELETE,
            CreateDisposition=libsmb.FILE_OPEN,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)

        with self.assertRaises(NTSTATUSError) as e:
            fd2 = conn.create(
                filename,
                DesiredAccess=sec.SEC_FILE_READ_DATA,
                CreateDisposition=libsmb.FILE_OPEN,
                CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)

        self.assertEqual(e.exception.args[0],
                         ntstatus.NT_STATUS_SHARING_VIOLATION)

        conn.delete_on_close(fd1, 1);
        conn.close(fd1)

if __name__ == '__main__':
    import unittest
    unittest.main()
