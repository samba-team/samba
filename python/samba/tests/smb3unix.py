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
from samba import NTSTATUSError,ntstatus
import samba.tests.libsmb
from samba.dcerpc import security
from samba.common import get_string
from samba.dcerpc import smb3posix
from samba.ndr import ndr_unpack
from samba.dcerpc.security import dom_sid
from samba import reparse_symlink
import os
import subprocess
import stat

def posix_context(mode):
    return (libsmb.SMB2_CREATE_TAG_POSIX, mode.to_bytes(4, 'little'))

class Smb3UnixTests(samba.tests.libsmb.LibsmbTests):

    def setUp(self):
        super().setUp()

        self.samsid = os.environ["SAMSID"]
        prefix_abs = os.environ["PREFIX_ABS"]
        p = subprocess.run(['stat', '-f', '-c', '%T', prefix_abs], capture_output=True, text=True)
        self.fstype = p.stdout.strip().lower()

    def connections(self, share1=None, posix1=False, share2=None, posix2=True):
        if not share1:
            share1 = samba.tests.env_get_var_value(
                "SHARE1", allow_missing=True)
            if not share1:
                share1 = "tmp"

        if not share2:
            share2 = samba.tests.env_get_var_value(
                "SHARE2", allow_missing=True)
            if not share2:
                share2 = "tmp"

        conn1 = libsmb.Conn(
            self.server_ip,
            share1,
            self.lp,
            self.creds,
            posix=posix1)

        conn2 = libsmb.Conn(
            self.server_ip,
            share2,
            self.lp,
            self.creds,
            posix=posix2)

        return (conn1, conn2)

    def wire_mode_to_unix(self, wire):
        mode = libsmb.wire_mode_to_unix(wire)
        type = stat.S_IFMT(mode)
        perms = mode & (stat.S_IRWXU|stat.S_IRWXG|stat.S_IRWXO|
                        stat.S_ISUID|stat.S_ISGID|stat.S_ISVTX)
        return (type, perms)

    def test_negotiate_context_posix(self):
        c = libsmb.Conn(
            self.server_ip,
            "tmp",
            self.lp,
            self.creds,
            posix=True)
        self.assertTrue(c.have_posix())

    def test_negotiate_context_posix_invalid_length(self):
        with self.assertRaises(NTSTATUSError) as cm:
            c = libsmb.Conn(
                self.server_ip,
                "tmp",
                self.lp,
                self.creds,
                negotiate_contexts=[(0x100, b'01234')])

        e = cm.exception
        self.assertEqual(e.args[0], ntstatus.NT_STATUS_INVALID_PARAMETER)

    def test_negotiate_context_posix_invalid_blob(self):
        c = libsmb.Conn(
            self.server_ip,
            "tmp",
            self.lp,
            self.creds,
            negotiate_contexts=[(0x100, b'0123456789012345')])
        self.assertFalse(c.have_posix())

    def test_posix_create_context(self):
        c = libsmb.Conn(
            self.server_ip,
            "tmp",
            self.lp,
            self.creds,
            posix=True)
        self.assertTrue(c.have_posix())

        cc_in=[(libsmb.SMB2_CREATE_TAG_POSIX,b'0000')]
        fnum,_,cc_out = c.create_ex("",CreateContexts=cc_in)
        self.assertEqual(cc_in[0][0],cc_out[0][0])

        c.close(fnum)

    def test_posix_create_invalid_context_length(self):
        c = libsmb.Conn(
            self.server_ip,
            "tmp",
            self.lp,
            self.creds,
            posix=True)
        self.assertTrue(c.have_posix())

        cc_in=[(libsmb.SMB2_CREATE_TAG_POSIX,b'00000')]

        with self.assertRaises(NTSTATUSError) as cm:
            fnum,_,cc_out = c.create_ex("",CreateContexts=cc_in)

        e = cm.exception
        self.assertEqual(e.args[0], ntstatus.NT_STATUS_INVALID_PARAMETER)

    def delete_test_file(self, c, fname, mode=0):
        f,_,cc_out = c.create_ex(fname,
                        DesiredAccess=security.SEC_STD_ALL,
                        CreateDisposition=libsmb.FILE_OPEN,
                        CreateContexts=[posix_context(mode)])
        c.delete_on_close(f, True)
        c.close(f)

    def test_posix_query_dir(self):
        test_files = []
        try:
            c = libsmb.Conn(
                self.server_ip,
                "smb3_posix_share",
                self.lp,
                self.creds,
                posix=True)
            self.assertTrue(c.have_posix())

            for i in range(10):
                fname = '\\test%d' % i
                f,_,cc_out = c.create_ex(fname,
                                CreateDisposition=libsmb.FILE_OPEN_IF,
                                CreateContexts=[posix_context(0o744)])
                c.close(f)
                test_files.append(fname)

            expected_count = len(c.list(''))
            self.assertNotEqual(expected_count, 0, 'No files were found')

            actual_count = len(c.list('',
                                info_level=libsmb.SMB2_FIND_POSIX_INFORMATION))
            self.assertEqual(actual_count-2, expected_count,
                             'SMB2_FIND_POSIX_INFORMATION failed to list contents')

        finally:
            if len(test_files) > 0:
                for fname in test_files:
                    self.delete_test_file(c, fname)

    def test_posix_reserved_char(self):
        c = libsmb.Conn(
            self.server_ip,
            "smb3_posix_share",
            self.lp,
            self.creds,
            posix=True)
        self.assertTrue(c.have_posix())

        test_files = ['a ', 'a  ', '. ', '.  ', 'a.',
                      '.a', ' \\ ', '>', '<' '?']

        for fname in test_files:
            try:
                f,_,cc_out = c.create_ex('\\%s' % fname,
                                CreateDisposition=libsmb.FILE_CREATE,
                                DesiredAccess=security.SEC_STD_DELETE,
                                CreateContexts=[posix_context(0o744)])
            except NTSTATUSError as e:
                self.fail(e)
            c.delete_on_close(f, True)
            c.close(f)

    def test_posix_delete_on_close(self):
        c = libsmb.Conn(
            self.server_ip,
            "smb3_posix_share",
            self.lp,
            self.creds,
            posix=True)
        self.assertTrue(c.have_posix())

        f,_,cc_out = c.create_ex('\\TESTING999',
                        DesiredAccess=security.SEC_STD_ALL,
                        CreateDisposition=libsmb.FILE_CREATE,
                        CreateContexts=[posix_context(0o744)])
        c.delete_on_close(f, True)
        c.close(f)

    def test_posix_case_sensitive(self):
        try:
            c = libsmb.Conn(
                self.server_ip,
                "smb3_posix_share",
                self.lp,
                self.creds,
                posix=True)
            self.assertTrue(c.have_posix())

            f,_,cc_out = c.create_ex('\\xx',
                            DesiredAccess=security.SEC_STD_ALL,
                            CreateDisposition=libsmb.FILE_CREATE,
                            CreateContexts=[posix_context(0o644)])
            c.close(f)

            fail = False
            try:
                f,_,cc_out = c.create_ex('\\XX',
                                DesiredAccess=security.SEC_STD_ALL,
                                CreateDisposition=libsmb.FILE_OPEN,
                                CreateContexts=[posix_context(0)])
            except NTSTATUSError:
                pass
            else:
                fail = True
                c.close(f)

            self.assertFalse(fail, "Opening uppercase file didn't fail")

        finally:
            self.delete_test_file(c, '\\xx')

    def test_posix_perm_files(self):
        test_files = {}
        try:
            c = libsmb.Conn(
                self.server_ip,
                "smb3_posix_share",
                self.lp,
                self.creds,
                posix=True)
            self.assertTrue(c.have_posix())

            for perm in range(0o600, 0o7777+1):
                # Owner write permission is required or cleanup will fail, and
                # owner read is required to list the file if O_PATH is disabled
                if perm & 0o600 != 0o600:
                    continue

                # Don't create with setuid or setgid.
                if perm & 0o6000 != 0:
                    continue

                fname = 'testfile%04o' % perm
                test_files[fname] = perm
                f,_,cc_out = c.create_ex('\\%s' % fname,
                                DesiredAccess=security.SEC_FILE_ALL,
                                CreateDisposition=libsmb.FILE_CREATE,
                                CreateContexts=[posix_context(perm)])
                if perm & 0o200 == 0o200:
                    c.write(f, buffer=b"data", offset=0)
                c.close(f)

                dname = 'testdir%04o' % perm
                test_files[dname] = perm
                f,_,cc_out = c.create_ex('\\%s' % dname,
                                DesiredAccess=security.SEC_STD_ALL,
                                CreateDisposition=libsmb.FILE_CREATE,
                                CreateOptions=libsmb.FILE_DIRECTORY_FILE,
                                CreateContexts=[posix_context(perm)])
                c.close(f)

            res = c.list("", info_level=libsmb.SMB2_FIND_POSIX_INFORMATION)

            found_files = {get_string(i['name']): i for i in res}
            for fname,perm in test_files.items():
                self.assertIn(get_string(fname), found_files.keys(),
                              'Test file not found')

                found_unixmode = found_files[fname]['perms']
                found_perms = found_unixmode & (stat.S_IRWXU|
                                                stat.S_IRWXG|
                                                stat.S_IRWXO|
                                                stat.S_ISUID|
                                                stat.S_ISGID|
                                                stat.S_ISVTX)

                self.assertEqual(test_files[fname], found_perms,
                                 'Requested %04o, Received %04o' % \
                                 (test_files[fname], found_perms))

                self.assertEqual(found_files[fname]['reparse_tag'],
                                 libsmb.IO_REPARSE_TAG_RESERVED_ZERO)
                self.assertEqual(found_perms, perm)
                self.assertEqual(found_files[fname]['owner_sid'],
                                 self.samsid + "-1000")
                self.assertTrue(found_files[fname]['group_sid'].startswith("S-1-22-2-"))

                if fname.startswith("testfile"):
                    self.assertTrue(stat.S_ISREG(found_unixmode))
                    self.assertEqual(found_files[fname]['nlink'], 1)
                    self.assertEqual(found_files[fname]['size'], 4)
                    self.assertEqual(found_files[fname]['allocation_size'],
                                     4096)
                    self.assertEqual(found_files[fname]['attrib'],
                                     libsmb.FILE_ATTRIBUTE_ARCHIVE)
                else:
                    self.assertTrue(stat.S_ISDIR(found_unixmode))
                    # Note: btrfs always reports the link count of directories as one.
                    if self.fstype == "btrfs":
                        self.assertEqual(found_files[fname]['nlink'], 1)
                    else:
                        self.assertEqual(found_files[fname]['nlink'], 2)
                    self.assertEqual(found_files[fname]['attrib'],
                                     libsmb.FILE_ATTRIBUTE_DIRECTORY)

        finally:
            if len(test_files) > 0:
                for fname in test_files.keys():
                    self.delete_test_file(c, '\\%s' % fname)

    def test_share_root_null_sids_fid(self):
        c = libsmb.Conn(
            self.server_ip,
            "smb3_posix_share",
            self.lp,
            self.creds,
            posix=True)
        self.assertTrue(c.have_posix())

        res = c.list("", info_level=libsmb.SMB2_FIND_POSIX_INFORMATION)
        found_files = {get_string(i['name']): i for i in res}
        dotdot = found_files['..']
        self.assertEqual('S-1-0-0', dotdot['owner_sid'],
                         'The owner sid for .. was not NULL')
        self.assertEqual('S-1-0-0', dotdot['group_sid'],
                         'The group sid for .. was not NULL')
        self.assertEqual(0, dotdot['ino'], 'The ino for .. was not 0')
        self.assertEqual(0, dotdot['dev'], 'The dev for .. was not 0')

    def test_create_context_basic1(self):
        """
        Check basic CreateContexts response
        """
        try:
            c = libsmb.Conn(
                self.server_ip,
                "smb3_posix_share",
                self.lp,
                self.creds,
                posix=True)
            self.assertTrue(c.have_posix())

            wire_mode = libsmb.unix_mode_to_wire(
                stat.S_IFREG|stat.S_IWUSR|stat.S_IRUSR)

            f,_,cc_out = c.create_ex('\\test_create_context_basic1_file',
                                     DesiredAccess=security.SEC_STD_ALL,
                                     CreateDisposition=libsmb.FILE_CREATE,
                                     CreateContexts=[posix_context(wire_mode)])
            c.close(f)

            cc = ndr_unpack(smb3posix.smb3_posix_cc_info, cc_out[0][1])

            self.assertEqual(cc.nlinks, 1)
            self.assertEqual(cc.reparse_tag, libsmb.IO_REPARSE_TAG_RESERVED_ZERO)
            self.assertEqual(cc.posix_mode, 0o600)
            self.assertEqual(cc.owner, dom_sid(self.samsid + "-1000"))
            self.assertTrue(str(cc.group).startswith("S-1-22-2-"))

            wire_mode = libsmb.unix_mode_to_wire(
                stat.S_IFREG|stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)

            f,_,cc_out = c.create_ex('\\test_create_context_basic1_dir',
                                     DesiredAccess=security.SEC_STD_ALL,
                                     CreateDisposition=libsmb.FILE_CREATE,
                                     CreateOptions=libsmb.FILE_DIRECTORY_FILE,
                                     CreateContexts=[posix_context(wire_mode)])

            c.close(f)

            cc = ndr_unpack(smb3posix.smb3_posix_cc_info, cc_out[0][1])

            # Note: btrfs always reports the link count of directories as one.
            if self.fstype == "btrfs":
                self.assertEqual(cc.nlinks, 1)
            else:
                self.assertEqual(cc.nlinks, 2)

            self.assertEqual(cc.reparse_tag, libsmb.IO_REPARSE_TAG_RESERVED_ZERO)

            (type, perms) = self.wire_mode_to_unix(cc.posix_mode);
            self.assertEqual(type, stat.S_IFDIR)
            self.assertEqual(perms, 0o700)

            self.assertEqual(cc.owner, dom_sid(self.samsid + "-1000"))
            self.assertTrue(str(cc.group).startswith("S-1-22-2-"))

        finally:
            self.delete_test_file(c, '\\test_create_context_basic1_file')
            self.delete_test_file(c, '\\test_create_context_basic1_dir')

    def test_create_context_reparse(self):
        """
        Check reparse tag in posix create context response
        """
        try:
            c = libsmb.Conn(
                self.server_ip,
                "smb3_posix_share",
                self.lp,
                self.creds,
                posix=True)
            self.assertTrue(c.have_posix())

            tag = 0x80000025

            f,_,cc_out = c.create_ex('\\reparse',
                                     DesiredAccess=security.SEC_STD_ALL,
                                     CreateDisposition=libsmb.FILE_CREATE,
                                     CreateContexts=[posix_context(0o600)])

            cc = ndr_unpack(smb3posix.smb3_posix_cc_info, cc_out[0][1])
            self.assertEqual(cc.reparse_tag, libsmb.IO_REPARSE_TAG_RESERVED_ZERO)

            b = reparse_symlink.put(tag, 0, b'asdf')
            c.fsctl(f, libsmb.FSCTL_SET_REPARSE_POINT, b, 0)

            c.close(f)

            f,_,cc_out = c.create_ex('\\reparse',
                                     DesiredAccess=security.SEC_STD_ALL,
                                     CreateDisposition=libsmb.FILE_OPEN,
                                     CreateContexts=[posix_context(0o600)])
            c.close(f)

            cc = ndr_unpack(smb3posix.smb3_posix_cc_info, cc_out[0][1])
            self.assertEqual(cc.reparse_tag, tag)

        finally:
            self.delete_test_file(c, '\\reparse')

    def test_delete_on_close(self):
        """
        Test two opens with delete-on-close:
        1. Windows open
        2. POSIX open
        Closing handle 1 should unlink the file, a subsequent directory
        listing shouldn't list the deleted file.
        """
        (winconn,posixconn) = self.connections()

        self.clean_file(winconn, 'test_delete_on_close')

        fdw = winconn.create(
            'test_delete_on_close',
            DesiredAccess=security.SEC_FILE_WRITE_ATTRIBUTE | security.SEC_STD_DELETE,
            ShareAccess=0x07,
            CreateDisposition=libsmb.FILE_CREATE)
        self.addCleanup(self.clean_file, winconn, 'test_delete_on_close')

        fdp,_,_ = posixconn.create_ex(
            'test_delete_on_close',
            DesiredAccess=security.SEC_FILE_WRITE_ATTRIBUTE | security.SEC_STD_DELETE,
            ShareAccess=0x07,
            CreateDisposition=libsmb.FILE_OPEN,
            CreateContexts=[posix_context(0o600)])

        winconn.delete_on_close(fdw, 1)
        posixconn.delete_on_close(fdp, 1)

        winconn.close(fdw)

        # The file should now already be deleted
        l = winconn.list('', mask='test_delete_on_close')
        found_files = {get_string(f['name']): f for f in l}
        self.assertFalse('test_delete_on_close' in found_files)

    def test_posix_fs_info(self):
        """
        Test the posix filesystem attributes list given by cli_get_posix_fs_info.
        With a non-posix connection, a NT_STATUS_INVALID_INFO_CLASS error
        is expected.
        """
        (winconn, posixconn) = self.connections()

        try:
            posix_info = posixconn.get_posix_fs_info()
        except Exception as e:
            self.fail(str(e))
        self.assertTrue(isinstance(posix_info, dict))
        self.assertTrue('optimal_transfer_size' in posix_info)

        with self.assertRaises(NTSTATUSError) as cm:
            winconn.get_posix_fs_info()
        e = cm.exception
        self.assertEqual(e.args[0], ntstatus.NT_STATUS_INVALID_INFO_CLASS)
