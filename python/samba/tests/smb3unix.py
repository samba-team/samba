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

def posix_context(mode):
    return (libsmb.SMB2_CREATE_TAG_POSIX, mode.to_bytes(4, 'little'))

class Smb3UnixTests(samba.tests.libsmb.LibsmbTests):

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
                self.server_ip,
                "tmp",
                self.lp,
                self.creds,
                posix=True)
            self.assertTrue(c.have_posix())

        finally:
            self.disable_smb3unix()

    def test_negotiate_context_noposix(self):
        c = libsmb.Conn(
                self.server_ip,
                "tmp",
                self.lp,
                self.creds,
                posix=True)
        self.assertFalse(c.have_posix())

    def test_negotiate_context_posix_invalid_length(self):
        try:
            self.enable_smb3unix()

            with self.assertRaises(NTSTATUSError) as cm:
                c = libsmb.Conn(
                    self.server_ip,
                    "tmp",
                    self.lp,
                    self.creds,
                    negotiate_contexts=[(0x100, b'01234')])

            e = cm.exception
            self.assertEqual(e.args[0], ntstatus.NT_STATUS_INVALID_PARAMETER)

        finally:
            self.disable_smb3unix()

    def test_negotiate_context_posix_invalid_blob(self):
        try:
            self.enable_smb3unix()

            c = libsmb.Conn(
                self.server_ip,
                "tmp",
                self.lp,
                self.creds,
                negotiate_contexts=[(0x100, b'0123456789012345')])
            self.assertFalse(c.have_posix())

        finally:
            self.disable_smb3unix()

    def test_posix_create_context(self):
        try:
            self.enable_smb3unix()

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

        finally:
            self.disable_smb3unix()

    def test_posix_create_context_noposix(self):
        c = libsmb.Conn(
            self.server_ip,
            "tmp",
            self.lp,
            self.creds,
            posix=True)
        self.assertFalse(c.have_posix())

        cc_in=[(libsmb.SMB2_CREATE_TAG_POSIX,b'0000')]
        fnum,_,cc_out = c.create_ex("",CreateContexts=cc_in)
        self.assertEqual(len(cc_out), 0)

        c.close(fnum)

    def test_posix_create_invalid_context_length(self):
        try:
            self.enable_smb3unix()

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

        finally:
            self.disable_smb3unix()

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
            self.enable_smb3unix()

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
                                info_level=libsmb.SMB2_FIND_POSIX_INFORMATION,
                                posix=True))
            self.assertEqual(actual_count-2, expected_count,
                             'SMB2_FIND_POSIX_INFORMATION failed to list contents')

        finally:
            for fname in test_files:
                self.delete_test_file(c, fname)

            self.disable_smb3unix()

    def test_posix_reserved_char(self):
        try:
            self.enable_smb3unix()

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

        finally:
            self.disable_smb3unix()

    def test_posix_delete_on_close(self):
        try:
            self.enable_smb3unix()

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

        finally:
            self.disable_smb3unix()

    def test_posix_case_sensitive(self):
        try:
            self.enable_smb3unix()

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

            self.disable_smb3unix()

    def test_posix_perm_files(self):
        try:
            self.enable_smb3unix()

            c = libsmb.Conn(
                self.server_ip,
                "smb3_posix_share",
                self.lp,
                self.creds,
                posix=True)
            self.assertTrue(c.have_posix())

            test_files = {}
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
                                DesiredAccess=security.SEC_STD_ALL,
                                CreateDisposition=libsmb.FILE_CREATE,
                                CreateContexts=[posix_context(perm)])
                c.close(f)

                dname = 'testdir%04o' % perm
                test_files[dname] = perm
                f,_,cc_out = c.create_ex('\\%s' % dname,
                                DesiredAccess=security.SEC_STD_ALL,
                                CreateDisposition=libsmb.FILE_CREATE,
                                CreateOptions=libsmb.FILE_DIRECTORY_FILE,
                                CreateContexts=[posix_context(perm)])
                c.close(f)

            res = c.list("", info_level=100, posix=True)
            found_files = {get_string(i['name']): i['perms'] for i in res}
            for fname, perm in test_files.items():
                self.assertIn(get_string(fname), found_files.keys(),
                              'Test file not found')
                self.assertEqual(test_files[fname], found_files[fname],
                                 'Requested %04o, Received %04o' % \
                                         (test_files[fname], found_files[fname]))

        finally:
            for fname in test_files.keys():
                self.delete_test_file(c, '\\%s' % fname)

            self.disable_smb3unix()

    def test_share_root_null_sids_fid(self):
        try:
            self.enable_smb3unix()

            c = libsmb.Conn(
                self.server_ip,
                "smb3_posix_share",
                self.lp,
                self.creds,
                posix=True)
            self.assertTrue(c.have_posix())

            res = c.list("", info_level=100, posix=True)
            found_files = {get_string(i['name']): i for i in res}
            dotdot = found_files['..']
            self.assertEqual('S-1-0-0', dotdot['owner_sid'],
                             'The owner sid for .. was not NULL')
            self.assertEqual('S-1-0-0', dotdot['group_sid'],
                             'The group sid for .. was not NULL')
            self.assertEqual(0, dotdot['ino'], 'The ino for .. was not 0')
            self.assertEqual(0, dotdot['dev'], 'The dev for .. was not 0')
        finally:
            self.disable_smb3unix()
