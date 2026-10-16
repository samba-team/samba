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

"""Tests for byte range locks via samba.samba3.libsmb."""

from samba.samba3 import libsmb_samba_internal as libsmb
from samba.samba3.libsmb_samba_internal import (
    FILE_CREATE,
    FILE_DELETE_ON_CLOSE,
    FILE_OPEN,
    FILE_OPEN_IF,
    FILE_SHARE_DELETE,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    SMB2_LOCK_FLAG_EXCLUSIVE,
    SMB2_LOCK_FLAG_FAIL_IMMEDIATELY,
    SMB2_LOCK_FLAG_SHARED,
    SMB2_LOCK_FLAG_UNLOCK,
)
from samba.dcerpc.security import (
    SEC_FILE_READ_ATTRIBUTE,
    SEC_FILE_READ_DATA,
    SEC_FILE_WRITE_DATA,
    SEC_STD_DELETE,
)
from samba import ntstatus, NTSTATUSError
import samba.tests.libsmb

FILE_SHARE_ALL = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE

SHARED = SMB2_LOCK_FLAG_SHARED | SMB2_LOCK_FLAG_FAIL_IMMEDIATELY
EXCLUSIVE = SMB2_LOCK_FLAG_EXCLUSIVE | SMB2_LOCK_FLAG_FAIL_IMMEDIATELY
UNLOCK = SMB2_LOCK_FLAG_UNLOCK


class LockTests:
    """Tests for Conn.lock(), run over SMB2 and SMB1"""

    force_smb1 = False

    def setUp(self):
        super().setUp()
        self.conn = libsmb.Conn(self.server_ip,
                                "tmp",
                                self.lp,
                                self.creds,
                                force_smb1=self.force_smb1)

    def lock(self, fnum, offset, length, flags):
        """NTSTATUS of a single element lock request"""
        try:
            self.conn.lock(fnum, [(offset, length, flags)])
        except NTSTATUSError as e:
            return e.args[0]
        return ntstatus.NT_STATUS_OK

    def create(self, fname, access, disposition, options=0):
        # The SMB1 and SMB2 tests must not see each other's files
        fname = "%s_%s" % (type(self).__name__, fname)
        return self.conn.create(fname,
                                DesiredAccess=access,
                                ShareAccess=FILE_SHARE_ALL,
                                CreateDisposition=disposition,
                                CreateOptions=options)

    def test_lock_unlock(self):
        fname = "lock_unlock"
        fnum1 = self.create(fname,
                            SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA |
                            SEC_STD_DELETE,
                            FILE_OPEN_IF,
                            FILE_DELETE_ON_CLOSE)
        fnum2 = self.create(fname,
                            SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA,
                            FILE_OPEN)

        status = self.lock(fnum1, 0, 10, EXCLUSIVE)
        self.assertEqual(status, ntstatus.NT_STATUS_OK)
        status = self.lock(fnum2, 0, 10, SHARED)
        self.assertEqual(status, ntstatus.NT_STATUS_LOCK_NOT_GRANTED)
        status = self.lock(fnum1, 0, 10, UNLOCK)
        self.assertEqual(status, ntstatus.NT_STATUS_OK)
        status = self.lock(fnum1, 0, 10, UNLOCK)
        self.assertEqual(status, ntstatus.NT_STATUS_RANGE_NOT_LOCKED)
        status = self.lock(fnum2, 0, 10, SHARED)
        self.assertEqual(status, ntstatus.NT_STATUS_OK)

        self.conn.close(fnum2)
        self.conn.close(fnum1)

    def test_lock_multiple(self):
        fnum = self.create("lock_multiple",
                           SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA |
                           SEC_STD_DELETE,
                           FILE_OPEN_IF,
                           FILE_DELETE_ON_CLOSE)
        self.conn.lock(fnum, [(0, 10, EXCLUSIVE), (20, 10, EXCLUSIVE)])
        self.conn.lock(fnum, [(0, 10, UNLOCK), (20, 10, UNLOCK)])
        self.conn.close(fnum)

    def check_lock_no_data_access(self, fnum):
        # Byte range locks and unlocks need FILE_READ_DATA or
        # FILE_WRITE_DATA on the handle
        for flags in [SHARED, EXCLUSIVE, UNLOCK]:
            status = self.lock(fnum, 0, 10, flags)
            self.assertEqual(status,
                             ntstatus.NT_STATUS_ACCESS_DENIED,
                             "flags 0x%x" % flags)

    def test_lock_stat_open(self):
        fname = "lock_stat_open"
        fnum1 = self.create(fname,
                            SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA |
                            SEC_STD_DELETE,
                            FILE_OPEN_IF,
                            FILE_DELETE_ON_CLOSE)
        fnum2 = self.create(fname, SEC_FILE_READ_ATTRIBUTE, FILE_OPEN)
        self.check_lock_no_data_access(fnum2)
        self.conn.close(fnum2)
        self.conn.close(fnum1)

    def test_lock_created_without_data_access(self):
        # Creating the file needs an fd open for writing, this must
        # not be what grants the lock
        self.clean_file(self.conn,
                        "%s_lock_created_delete_only" % type(self).__name__)
        fnum = self.create("lock_created_delete_only",
                           SEC_STD_DELETE,
                           FILE_CREATE,
                           FILE_DELETE_ON_CLOSE)
        self.check_lock_no_data_access(fnum)
        self.conn.close(fnum)


class Smb2LockTests(LockTests, samba.tests.libsmb.LibsmbTests):
    pass


class Smb1LockTests(LockTests, samba.tests.libsmb.LibsmbTests):
    force_smb1 = True



class CrossProtocolLockTests(samba.tests.libsmb.LibsmbTests):
    """Locks beyond 4GB set over one protocol must conflict with the
    other protocol: This checks the 64-bit offset encoding of both
    clients against each other, a mis-encoded offset would not
    overlap."""

    def setUp(self):
        super().setUp()
        self.smb1 = libsmb.Conn(self.server_ip,
                                "tmp",
                                self.lp,
                                self.creds,
                                force_smb1=True)
        self.smb2 = libsmb.Conn(self.server_ip, "tmp", self.lp, self.creds)

    def check_high_offset(self, fname, holder, other, deny_status):
        offset = 0x100000000
        fnum1 = holder.create(fname,
                              DesiredAccess=SEC_FILE_READ_DATA |
                              SEC_FILE_WRITE_DATA | SEC_STD_DELETE,
                              ShareAccess=FILE_SHARE_ALL,
                              CreateDisposition=FILE_OPEN_IF,
                              CreateOptions=FILE_DELETE_ON_CLOSE)
        fnum2 = other.create(fname,
                             DesiredAccess=SEC_FILE_READ_DATA |
                             SEC_FILE_WRITE_DATA,
                             ShareAccess=FILE_SHARE_ALL,
                             CreateDisposition=FILE_OPEN)

        holder.lock(fnum1, [(offset, 10, EXCLUSIVE)])
        with self.assertRaises(NTSTATUSError) as e:
            other.lock(fnum2, [(offset, 10, EXCLUSIVE)])
        self.assertEqual(e.exception.args[0], deny_status)

        other.close(fnum2)
        holder.close(fnum1)

    def test_smb1_lock_denies_smb2(self):
        self.check_high_offset("lock_high_smb1",
                               self.smb1,
                               self.smb2,
                               ntstatus.NT_STATUS_LOCK_NOT_GRANTED)

    def test_smb2_lock_denies_smb1(self):
        # smbd delays failed SMB1 locks at offsets >= 0xEF000000 and
        # then returns NT_STATUS_FILE_LOCK_CONFLICT
        self.check_high_offset("lock_high_smb2",
                               self.smb2,
                               self.smb1,
                               ntstatus.NT_STATUS_FILE_LOCK_CONFLICT)


class Smb1PosixLockTests(samba.tests.libsmb.LibsmbTests):
    """libsmb's SMB_SET_POSIX_LOCK sends the client pid as lock
    context, so all files locked over one connection share the same
    smblctx LCTX. smbd must keep its per-file POSIX lock accounting right
    for that.

    The comments describe what happens with the "LCTX has POSIX locks"
    marker in posix_pending_close_db keyed by smblctx alone.

    """

    def setUp(self):
        super().setUp()
        self.conn = libsmb.Conn(self.server_ip,
                                "posix_share",
                                self.lp,
                                self.creds,
                                force_smb1=True)
        self.conn.smb1_posix()

    def create(self, fname):
        fname = "posix_lock_%s" % fname
        self.clean_file(self.conn, fname)
        return self.conn.create(fname,
                                DesiredAccess=SEC_FILE_READ_DATA |
                                SEC_FILE_WRITE_DATA | SEC_STD_DELETE,
                                ShareAccess=FILE_SHARE_ALL,
                                CreateDisposition=FILE_CREATE,
                                CreateOptions=FILE_DELETE_ON_CLOSE)

    def test_two_files_close_second(self):
        fnum1 = self.create("close_second_1")
        fnum2 = self.create("close_second_2")
        # No marker for LCTX yet: store it, lock_ref_count(fnum1) = 1
        self.conn.smb1_posix_lock(fnum1, 0, 10, write=True)
        # Marker for LCTX exists: lock_ref_count(fnum2) stays 0
        self.conn.smb1_posix_lock(fnum2, 0, 10, write=True)
        # brl_close_fnum() unlocks, LCTX has no locks left on fnum2:
        # decrement_lock_ref_count(fnum2) finds 0, SMB_ASSERT panics
        self.assertNoNTSTATUSError(self.conn.close, fnum2)
        self.conn.smb1_posix_unlock(fnum1, 0, 10)
        self.conn.close(fnum1)

    def test_two_files_unlock_second(self):
        fnum1 = self.create("unlock_second_1")
        fnum2 = self.create("unlock_second_2")
        # Marker for LCTX stored, lock_ref_count(fnum1) = 1
        self.conn.smb1_posix_lock(fnum1, 0, 10, write=True)
        # Marker for LCTX exists: lock_ref_count(fnum2) stays 0
        self.conn.smb1_posix_lock(fnum2, 0, 10, write=True)
        # LCTX has no locks left on fnum2:
        # decrement_lock_ref_count(fnum2) finds 0, SMB_ASSERT panics
        self.assertNoNTSTATUSError(self.conn.smb1_posix_unlock,
                                   fnum2, 0, 10)
        self.conn.smb1_posix_unlock(fnum1, 0, 10)
        self.conn.close(fnum2)
        self.conn.close(fnum1)

    def test_two_files_unlock_first(self):
        fnum1 = self.create("unlock_first_1")
        fnum2 = self.create("unlock_first_2")
        # Marker for LCTX stored, lock_ref_count(fnum1) = 1
        self.conn.smb1_posix_lock(fnum1, 0, 10, write=True)
        # Marker for LCTX exists: lock_ref_count(fnum2) stays 0
        self.conn.smb1_posix_lock(fnum2, 0, 10, write=True)
        # Marker for LCTX deleted, lock_ref_count(fnum1) = 0, fine
        self.conn.smb1_posix_unlock(fnum1, 0, 10)
        # Deleting the missing marker succeeds (rbt), then
        # decrement_lock_ref_count(fnum2) finds 0, SMB_ASSERT panics
        self.assertNoNTSTATUSError(self.conn.smb1_posix_unlock,
                                   fnum2, 0, 10)
        self.conn.close(fnum2)
        self.conn.close(fnum1)

    def test_two_files_out_of_range(self):
        # Locks beyond the POSIX range are not mapped to fcntl, but
        # set/release_posix_lock_posix_flavour() still do the
        # accounting, same sequence as test_two_files_unlock_first
        offset = 0xFFFFFFFFFFFFFFF0
        fnum1 = self.create("out_of_range_1")
        fnum2 = self.create("out_of_range_2")
        self.conn.smb1_posix_lock(fnum1, offset, 10, write=True)
        self.conn.smb1_posix_lock(fnum2, offset, 10, write=True)
        self.conn.smb1_posix_unlock(fnum1, offset, 10)
        # decrement_lock_ref_count(fnum2) finds 0, SMB_ASSERT panics
        self.assertNoNTSTATUSError(self.conn.smb1_posix_unlock,
                                   fnum2, offset, 10)
        self.conn.close(fnum2)
        self.conn.close(fnum1)

if __name__ == "__main__":
    import unittest
    unittest.main()
