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
