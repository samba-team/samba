# Unix SMB/CIFS implementation. Tests for ntacls manipulation
# Copyright (C) Andrew Bartlett 2018
# Copyright (C) Joe Guo <joeg@catalyst.net.nz> 2018
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

"""Tests for samba ntacls backup"""
import os

from samba.samba3 import libsmb_samba_internal as libsmb
from samba.samba3 import smbd
from samba import samdb
from samba import ntacls

from samba.auth import system_session
from samba.auth_util import system_session_unix
from samba.dcerpc import security
from samba.tests import env_loadparm
from samba.tests.smbd_base import SmbdBaseTests


class NtaclsBackupRestoreTests(SmbdBaseTests):
    """
    Tests for NTACLs backup and restore.
    """

    def setUp(self):
        super(NtaclsBackupRestoreTests, self).setUp()

        self.server = os.environ["SERVER"]  # addc
        samdb_url = 'ldap://' + self.server

        self.service = 'test1'  # service/share to test
        # root path for service
        self.service_root = os.path.join(
            os.environ["LOCAL_PATH"], self.service)

        self.smb_conf_path = os.environ['SMB_CONF_PATH']
        self.creds = self.insta_creds(template=self.get_credentials())

        self.samdb_conn = samdb.SamDB(
            url=samdb_url, session_info=system_session(),
            credentials=self.creds, lp=env_loadparm())

        self.dom_sid = security.dom_sid(self.samdb_conn.get_domain_sid())

        # helper will load conf into lp, that's how smbd can find services.
        self.ntacls_helper = ntacls.NtaclsHelper(self.service,
                                                 self.smb_conf_path,
                                                 self.dom_sid)
        self.lp = self.ntacls_helper.lp

        self.smb_conn = libsmb.Conn(
            self.server, self.service, lp=self.lp, creds=self.creds)

        self.smb_helper = ntacls.SMBHelper(self.smb_conn, self.dom_sid)

        self.tarfile_path = os.path.join(self.tempdir,
                                         'ntacls-backup.tar.gz')

        # an example file tree
        self.tree = {
            'file0.txt': b'test file0',
            'dir1': {
                'file1.txt': b'test file1',
                'dir2': {}  # an empty dir in dir
            },
        }

        self._delete_tarfile()
        self.smb_helper.delete_tree()

        self.smb_helper.create_tree(self.tree)
        self._check_tree()
        # keep a copy of ntacls after tree just created
        self.original_ntacls = self.smb_helper.get_ntacls()

    def tearDown(self):
        self._delete_tarfile()
        self.smb_helper.delete_tree()
        super(NtaclsBackupRestoreTests, self).tearDown()

    def _delete_tarfile(self):
        try:
            os.remove(self.tarfile_path)
        except OSError:
            pass

    def _check_tarfile(self):
        self.assertTrue(os.path.isfile(self.tarfile_path))

    def _check_tree(self):
        actual_tree = self.smb_helper.get_tree()
        self.assertDictEqual(self.tree, actual_tree)

    def test_smbd_mkdir(self):
        """
        A smoke test for smbd.mkdir API
        """

        dirpath = os.path.join(self.service_root, 'a-dir')
        smbd.mkdir(dirpath, system_session_unix(), self.service)
        mode = os.stat(dirpath).st_mode

        # This works in conjunction with the TEST_UMASK in smbd_base
        # to ensure that permissions are not related to the umask
        # but instead the smb.conf settings
        self.assertEqual(mode & 0o777, 0o755)
        self.assertTrue(os.path.isdir(dirpath))

    def test_smbd_create_file(self):
        """
        A smoke test for smbd.create_file and smbd.unlink API
        """

        filepath = os.path.join(self.service_root, 'a-file')
        smbd.create_file(filepath, system_session_unix(), self.service)
        self.assertTrue(os.path.isfile(filepath))

        mode = os.stat(filepath).st_mode

        # This works in conjunction with the TEST_UMASK in smbd_base
        # to ensure that permissions are not related to the umask
        # but instead the smb.conf settings
        self.assertEqual(mode & 0o777, 0o644)

        # As well as checking that unlink works, this removes the
        # fake xattrs from the dev/inode based DB
        smbd.unlink(filepath, system_session_unix(), self.service)
        self.assertFalse(os.path.isfile(filepath))

    def test_compare_getntacl(self):
        """
        Ntacls get from different ways should be the same
        """

        file_name = 'file0.txt'
        file_path = os.path.join(self.service_root, file_name)

        sd0 = self.smb_helper.get_acl(file_name, as_sddl=True)

        sd1 = self.ntacls_helper.getntacl(
            file_path, system_session_unix(), as_sddl=True, direct_db_access=False)

        sd2 = self.ntacls_helper.getntacl(
            file_path, system_session_unix(), as_sddl=True, direct_db_access=True)

        self.assertEqual(sd0, sd1)
        self.assertEqual(sd1, sd2)

    def test_backup_online(self):
        """
        Backup service online, delete files, restore and check.
        """
        ntacls.backup_online(
            self.smb_conn, self.tarfile_path, self.dom_sid)
        self._check_tarfile()

        self.smb_helper.delete_tree()
        ntacls.backup_restore(
            self.tarfile_path, self.service_root,
            self.samdb_conn, self.smb_conf_path)
        self._check_tree()

        # compare ntacls after restored
        self.assertDictEqual(
            self.original_ntacls, self.smb_helper.get_ntacls())

    def test_backup_offline(self):
        """
        Backup service offline, delete files, restore and check.
        """
        ntacls.backup_offline(
            self.service_root, self.tarfile_path,
            self.samdb_conn, self.smb_conf_path)
        self._check_tarfile()

        self.smb_helper.delete_tree()
        ntacls.backup_restore(
            self.tarfile_path, self.service_root,
            self.samdb_conn, self.smb_conf_path)
        self._check_tree()

        # compare ntacls after restored
        self.assertDictEqual(
            self.original_ntacls, self.smb_helper.get_ntacls())
