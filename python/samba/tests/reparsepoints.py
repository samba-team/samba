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
import stat

def posix_context(mode):
    return (libsmb.SMB2_CREATE_TAG_POSIX, mode.to_bytes(4, 'little'))

class ReparsePoints(samba.tests.libsmb.LibsmbTests):

    def connection(self, posix=False):
        share = samba.tests.env_get_var_value("SHARENAME", allow_missing=True)
        if not share:
            share = "tmp"
        smb1 = samba.tests.env_get_var_value("SMB1", allow_missing=True)
        conn = libsmb.Conn(
            self.server_ip,
            share,
            self.lp,
            self.creds,
            posix=posix,
            force_smb1=smb1)
        return conn

    def connection_posix(self):
        share = samba.tests.env_get_var_value("SHARENAME", allow_missing=True)
        if not share:
            share = "posix_share"
        conn = libsmb.Conn(
            self.server_ip,
            share,
            self.lp,
            self.creds,
            force_smb1=True)
        conn.smb1_posix()
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
            DesiredAccess=sec.SEC_FILE_WRITE_ATTRIBUTE | sec.SEC_STD_DELETE,
            CreateDisposition=libsmb.FILE_CREATE)

        conn.delete_on_close(fd, 1)

        with self.assertRaises(NTSTATUSError) as e:
            conn.fsctl(fd, libsmb.FSCTL_SET_REPARSE_POINT, b'', 0)

        self.assertEqual(e.exception.args[0],
                         ntstatus.NT_STATUS_INVALID_BUFFER_SIZE)

        for i in range(1,15):
            with self.assertRaises(NTSTATUSError) as e:
                conn.fsctl(fd, libsmb.FSCTL_SET_REPARSE_POINT, i * b'0', 0)

            self.assertEqual(e.exception.args[0],
                             ntstatus.NT_STATUS_IO_REPARSE_DATA_INVALID)

        # Create a syntactically valid [MS-FSCC] 2.1.2.2 REPARSE_DATA_BUFFER
        b = reparse_symlink.put(0x80000025, 0, b'asdfasdfasdfasdfasdfasdf')

        # Show that SET_REPARSE_POINT does exact length checks

        with self.assertRaises(NTSTATUSError) as e:
            conn.fsctl(fd, libsmb.FSCTL_SET_REPARSE_POINT, b + b'0', 0)
        self.assertEqual(e.exception.args[0],
                         ntstatus.NT_STATUS_IO_REPARSE_DATA_INVALID)

        with self.assertRaises(NTSTATUSError) as e:
            conn.fsctl(fd, libsmb.FSCTL_SET_REPARSE_POINT, b[:-1], 0)
        self.assertEqual(e.exception.args[0],
                         ntstatus.NT_STATUS_IO_REPARSE_DATA_INVALID)

        # Exact length works
        conn.fsctl(fd, libsmb.FSCTL_SET_REPARSE_POINT, b, 0)

        b = reparse_symlink.put(0x80000026, 0, b'asdf')

        # We can't overwrite an existing reparse point with a different tag
        with self.assertRaises(NTSTATUSError) as e:
            conn.fsctl(fd, libsmb.FSCTL_SET_REPARSE_POINT, b, 0)
        self.assertEqual(e.exception.args[0],
                         ntstatus.NT_STATUS_IO_REPARSE_TAG_MISMATCH)

    def test_query_reparse_tag(self):
        conn = self.connection()
        filename = 'reparse'
        self.clean_file(conn, filename)

        fd = conn.create(
            filename,
            DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE |
                sec.SEC_FILE_WRITE_ATTRIBUTE |
                sec.SEC_STD_DELETE,
            CreateDisposition=libsmb.FILE_CREATE)

        conn.delete_on_close(fd, 1)

        info = conn.qfileinfo(fd, libsmb.FSCC_FILE_ATTRIBUTE_TAG_INFORMATION);
        self.assertEqual(info['tag'], 0)

        b = reparse_symlink.put(0x80000026, 0, b'asdf')
        conn.fsctl(fd, libsmb.FSCTL_SET_REPARSE_POINT, b, 0)

        info = conn.qfileinfo(fd, libsmb.FSCC_FILE_ATTRIBUTE_TAG_INFORMATION);
        self.assertEqual(info['tag'], 0x80000026)


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
        conn.close(fd)

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
        conn.close(fd)

    def test_query_dir_reparse(self):
        conn = self.connection()
        filename = 'reparse'
        self.clean_file(conn, filename)

        fd = conn.create(
            filename,
            DesiredAccess=sec.SEC_FILE_WRITE_ATTRIBUTE,
            CreateDisposition=libsmb.FILE_CREATE)
        b = reparse_symlink.symlink_put("y", "y", 0, 0)
        conn.fsctl(fd, libsmb.FSCTL_SET_REPARSE_POINT, b, 0)
        conn.close(fd)

        dirents = conn.list("", filename)
        self.assertEqual(
            dirents[0]["attrib"],
            libsmb.FILE_ATTRIBUTE_REPARSE_POINT|
            libsmb.FILE_ATTRIBUTE_ARCHIVE)
        self.assertEqual(
            dirents[0]["reparse_tag"],
            libsmb.IO_REPARSE_TAG_SYMLINK)

        self.clean_file(conn, filename)

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

        try:
            conn.fsctl(dir_fd, libsmb.FSCTL_SET_REPARSE_POINT, b, 0)
        except NTSTATUSError as e:
            err = e.args[0]
            if (err != ntstatus.NT_STATUS_ACCESS_DENIED):
                raise
        finally:
            conn.close(dir_fd)
            self.clean_file(conn, dirname)

        if (err == ntstatus.NT_STATUS_ACCESS_DENIED):
            self.fail("Could not set reparse point on directory")
            conn.close(dir_fd)
            self.clean_file(conn, dirname)
            return

        with self.assertRaises(NTSTATUSError) as e:
            fd = conn.create(
                filename,
                DesiredAccess=sec.SEC_STD_DELETE,
                CreateDisposition=libsmb.FILE_CREATE)

        self.assertEqual(e.exception.args[0],
                         ntstatus.NT_STATUS_IO_REPARSE_TAG_NOT_HANDLED)

        conn.delete_on_close(dir_fd, 1)
        conn.close(dir_fd)

        dirents = conn.list("", dirname)
        self.assertEqual(
            dirents[0]["attrib"],
            libsmb.FILE_ATTRIBUTE_REPARSE_POINT|
            libsmb.FILE_ATTRIBUTE_DIRECTORY)
        self.assertEqual(dirents[0]["reparse_tag"], 0x80000025)

        self.clean_file(conn, dirname)

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

        conn.delete_on_close(fd, 1)
        conn.close(fd)
        conn.delete_on_close(dir_fd, 1)
        conn.close(dir_fd)

        ok = (err == ntstatus.NT_STATUS_DIRECTORY_NOT_EMPTY)
        if not ok:
            self.fail(f'set_reparse on nonempty directory returned {err}')

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
        conn.close(fd)

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

        conn.delete_on_close(fd1, 1)
        conn.close(fd1)

    def test_delete_reparse_point(self):
        conn = self.connection()
        filename = 'reparse'
        self.clean_file(conn, filename)

        fd = conn.create(
            filename,
            DesiredAccess=sec.SEC_FILE_WRITE_ATTRIBUTE,
            CreateDisposition=libsmb.FILE_CREATE)
        b = reparse_symlink.put(0x80000025, 0, b'asdfasdfasdfasdfasdfasdf')
        conn.fsctl(fd, libsmb.FSCTL_SET_REPARSE_POINT, b, 0)
        conn.close(fd)

        (fd,cr,_) = conn.create_ex(
            filename,
            DesiredAccess=sec.SEC_FILE_WRITE_ATTRIBUTE|sec.SEC_STD_DELETE,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT,
            CreateDisposition=libsmb.FILE_OPEN)

        self.assertEqual(cr['file_attributes'] &
                         libsmb.FILE_ATTRIBUTE_REPARSE_POINT,
                         libsmb.FILE_ATTRIBUTE_REPARSE_POINT)

        b = reparse_symlink.put(0x80000026, 0, b'')
        with self.assertRaises(NTSTATUSError) as e:
            conn.fsctl(fd, libsmb.FSCTL_DELETE_REPARSE_POINT, b, 0)
        self.assertEqual(e.exception.args[0],
                         ntstatus.NT_STATUS_IO_REPARSE_TAG_MISMATCH)

        b = reparse_symlink.put(0x80000026, 0, b' ')
        with self.assertRaises(NTSTATUSError) as e:
            conn.fsctl(fd, libsmb.FSCTL_DELETE_REPARSE_POINT, b, 0)
        self.assertEqual(e.exception.args[0],
                         ntstatus.NT_STATUS_IO_REPARSE_DATA_INVALID)

        b = reparse_symlink.put(0x80000025, 0, b' ')
        with self.assertRaises(NTSTATUSError) as e:
            conn.fsctl(fd, libsmb.FSCTL_DELETE_REPARSE_POINT, b, 0)
        self.assertEqual(e.exception.args[0],
                         ntstatus.NT_STATUS_IO_REPARSE_DATA_INVALID)

        b = reparse_symlink.put(0x80000025, 0, b'')
        conn.fsctl(fd, libsmb.FSCTL_DELETE_REPARSE_POINT, b, 0)

        with self.assertRaises(NTSTATUSError) as e:
            conn.fsctl(fd, libsmb.FSCTL_DELETE_REPARSE_POINT, b, 0)
        self.assertEqual(e.exception.args[0],
                         ntstatus.NT_STATUS_NOT_A_REPARSE_POINT)

        conn.close(fd)

        (fd,cr,_) = conn.create_ex(
            filename,
            DesiredAccess=sec.SEC_FILE_WRITE_ATTRIBUTE|sec.SEC_STD_DELETE,
            CreateDisposition=libsmb.FILE_OPEN)

        self.assertEqual(cr['file_attributes'] &
                         libsmb.FILE_ATTRIBUTE_REPARSE_POINT,
                         0)

        conn.delete_on_close(fd, 1)
        conn.close(fd)

    def do_test_nfs_reparse(self, filename, filetype, nfstype):
        """Test special file reparse tag"""
        smb2 = self.connection(posix=True)
        smb1 = self.connection_posix()

        self.clean_file(smb2, filename)
        smb1.mknod(filename, filetype | 0o755)

        fd,_,_ = smb2.create_ex(
            filename,
            DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE|sec.SEC_STD_DELETE,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT,
            CreateDisposition=libsmb.FILE_OPEN,
            ShareAccess=(libsmb.FILE_SHARE_READ|libsmb.FILE_SHARE_WRITE|libsmb.FILE_SHARE_DELETE),
            CreateContexts=[posix_context(0o600)])
        smb2.delete_on_close(fd, 1)

        info = smb2.qfileinfo(fd, libsmb.FSCC_FILE_ATTRIBUTE_TAG_INFORMATION);
        self.assertEqual(info['tag'], libsmb.IO_REPARSE_TAG_NFS)

        info = smb2.qfileinfo(fd, libsmb.FSCC_FILE_POSIX_INFORMATION);
        self.assertEqual(info['reparse_tag'], libsmb.IO_REPARSE_TAG_NFS)

        type, perms = self.wire_mode_to_unix(info['perms'])
        self.assertEqual(type, filetype)

        reparse = smb2.fsctl(fd, libsmb.FSCTL_GET_REPARSE_POINT, b'', 1024)
        (tag, ) = reparse_symlink.get(reparse)
        self.assertEqual(tag, nfstype)

    def test_fifo_reparse(self):
        """Test FIFO reparse tag"""
        self.do_test_nfs_reparse('fifo', stat.S_IFIFO, 'NFS_SPECFILE_FIFO')

    def test_sock_reparse(self):
        """Test SOCK reparse tag"""
        self.do_test_nfs_reparse('sock', stat.S_IFSOCK, 'NFS_SPECFILE_SOCK')

    def test_reparsepoint_posix_type(self):
        conn = self.connection(posix=True)
        filename = 'reparse'
        self.clean_file(conn, filename)

        fd,_,_ = conn.create_ex(
            filename,
            DesiredAccess=sec.SEC_FILE_WRITE_ATTRIBUTE,
            CreateDisposition=libsmb.FILE_CREATE,
            CreateContexts=[posix_context(0o600)])
        b = reparse_symlink.symlink_put("y", "y", 0, 0)
        conn.fsctl(fd, libsmb.FSCTL_SET_REPARSE_POINT, b, 0)
        conn.close(fd)

        dirents = conn.list("", filename,info_level=libsmb.SMB2_FIND_POSIX_INFORMATION)
        self.assertEqual(
            dirents[0]["attrib"],
            libsmb.FILE_ATTRIBUTE_REPARSE_POINT|
            libsmb.FILE_ATTRIBUTE_ARCHIVE)
        self.assertEqual(
            dirents[0]["reparse_tag"],
            libsmb.IO_REPARSE_TAG_SYMLINK)

        type, perms = self.wire_mode_to_unix(dirents[0]['perms'])
        self.assertEqual(type, stat.S_IFLNK)

        self.clean_file(conn, filename)

if __name__ == '__main__':
    import unittest
    unittest.main()
