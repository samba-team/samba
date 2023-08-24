#!/usr/bin/env python3
# Unix SMB/CIFS implementation. Tests for smb notify
# Copyright (C) Björn Baumbach <bb@samba.org> 2020
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

import sys
import os

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

import samba
import random
from samba.tests import TestCase
from samba import credentials
from samba.ntstatus import NT_STATUS_NOTIFY_CLEANUP
from samba.samba3 import libsmb_samba_internal as libsmb
from samba.samba3 import param as s3param
from samba.dcerpc import security

from samba import ntacls

test_dir = os.path.join('notify_test_%d' % random.randint(0, 0xFFFF))

class SMBNotifyTests(TestCase):
    def setUp(self):
        super(SMBNotifyTests, self).setUp()
        self.server = samba.tests.env_get_var_value("SERVER")

        # create an SMB connection to the server
        self.lp = s3param.get_context()
        self.lp.load(samba.tests.env_get_var_value("SMB_CONF_PATH"))

        self.share = samba.tests.env_get_var_value("NOTIFY_SHARE")

        creds = credentials.Credentials()
        creds.guess(self.lp)
        creds.set_username(samba.tests.env_get_var_value("USERNAME"))
        creds.set_password(samba.tests.env_get_var_value("PASSWORD"))

        strict_checking = samba.tests.env_get_var_value('STRICT_CHECKING', allow_missing=True)
        if strict_checking is None:
            strict_checking = '1'
        self.strict_checking = bool(int(strict_checking))

        self.smb_conn = libsmb.Conn(self.server, self.share, self.lp, creds)
        self.smb_conn_unpriv = None

        try:
            self.smb_conn.deltree(test_dir)
        except:
            pass
        self.smb_conn.mkdir(test_dir)

    def connect_unpriv(self):
        creds_unpriv = credentials.Credentials()
        creds_unpriv.guess(self.lp)
        creds_unpriv.set_username(samba.tests.env_get_var_value("USERNAME_UNPRIV"))
        creds_unpriv.set_password(samba.tests.env_get_var_value("PASSWORD_UNPRIV"))

        self.smb_conn_unpriv = libsmb.Conn(self.server, self.share, self.lp, creds_unpriv)

    def tearDown(self):
        super(SMBNotifyTests, self).tearDown()
        try:
            self.smb_conn.deltree(test_dir)
        except:
            pass

    def make_path(self, dirpath, filename):
        return os.path.join(dirpath, filename).replace('/', '\\')

    def test_notify(self):
        # setup notification request on the share root
        root_fnum = self.smb_conn.create(Name="", ShareAccess=1)
        root_notify = self.smb_conn.notify(fnum=root_fnum,
                                           buffer_size=0xffff,
                                           completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                           recursive=True)
        # setup notification request on the test_dir
        test_dir_fnum = self.smb_conn.create(Name=test_dir, ShareAccess=1)
        test_dir_notify = self.smb_conn.notify(fnum=test_dir_fnum,
                                               buffer_size=0xffff,
                                               completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                               recursive=True)

        # make sure we didn't receive any changes yet.
        self.smb_conn.echo()
        changes = root_notify.get_changes(wait=False)
        self.assertIsNone(changes)
        changes = test_dir_notify.get_changes(wait=False)
        self.assertIsNone(changes)

        # create a test directory
        dir_name = "dir"
        dir_path = self.make_path(test_dir, dir_name)
        self.smb_conn.mkdir(dir_path)

        # check for 'added' notifications
        changes = root_notify.get_changes(wait=True)
        self.assertIsNotNone(changes)
        self.assertEqual(changes[0]['name'], dir_path)
        self.assertEqual(changes[0]['action'], libsmb.NOTIFY_ACTION_ADDED)
        self.assertEqual(len(changes), 1)
        changes = test_dir_notify.get_changes(wait=True)
        self.assertIsNotNone(changes)
        self.assertEqual(changes[0]['name'], dir_name)
        self.assertEqual(changes[0]['action'], libsmb.NOTIFY_ACTION_ADDED)
        self.assertEqual(len(changes), 1)

        # readd notification requests
        root_notify = self.smb_conn.notify(fnum=root_fnum,
                                           buffer_size=0xffff,
                                           completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                           recursive=True)
        test_dir_notify = self.smb_conn.notify(fnum=test_dir_fnum,
                                               buffer_size=0xffff,
                                               completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                               recursive=True)

        # make sure we didn't receive any changes yet.
        self.smb_conn.echo()
        changes = root_notify.get_changes(wait=False)
        self.assertIsNone(changes)
        changes = test_dir_notify.get_changes(wait=False)
        self.assertIsNone(changes)

        # create subdir and trigger notifications
        sub_name = "subdir"
        sub_path_rel = self.make_path(dir_name, sub_name)
        sub_path_full = self.make_path(dir_path, sub_name)
        self.smb_conn.mkdir(sub_path_full)

        # check for 'added' notifications
        changes = root_notify.get_changes(wait=True)
        self.assertIsNotNone(changes)
        self.assertEqual(changes[0]['name'], sub_path_full)
        self.assertEqual(changes[0]['action'], libsmb.NOTIFY_ACTION_ADDED)
        self.assertEqual(len(changes), 1)
        changes = test_dir_notify.get_changes(wait=True)
        self.assertIsNotNone(changes)
        self.assertEqual(changes[0]['name'], sub_path_rel)
        self.assertEqual(changes[0]['action'], libsmb.NOTIFY_ACTION_ADDED)
        self.assertEqual(len(changes), 1)

        # readd notification requests
        root_notify = self.smb_conn.notify(fnum=root_fnum,
                                           buffer_size=0xffff,
                                           completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                           recursive=True)
        test_dir_notify = self.smb_conn.notify(fnum=test_dir_fnum,
                                               buffer_size=0xffff,
                                               completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                               recursive=True)

        # make sure we didn't receive any changes yet.
        self.smb_conn.echo()
        changes = root_notify.get_changes(wait=False)
        self.assertIsNone(changes)
        changes = test_dir_notify.get_changes(wait=False)
        self.assertIsNone(changes)

        # remove test dir and trigger notifications
        self.smb_conn.rmdir(sub_path_full)

        # check for 'removed' notifications
        changes = root_notify.get_changes(wait=True)
        self.assertIsNotNone(changes)
        self.assertEqual(changes[0]['name'], sub_path_full)
        self.assertEqual(changes[0]['action'], libsmb.NOTIFY_ACTION_REMOVED)
        self.assertEqual(len(changes), 1)
        changes = test_dir_notify.get_changes(wait=True)
        self.assertIsNotNone(changes)
        self.assertEqual(changes[0]['name'], sub_path_rel)
        self.assertEqual(changes[0]['action'], libsmb.NOTIFY_ACTION_REMOVED)
        self.assertEqual(len(changes), 1)

        # readd notification requests
        root_notify = self.smb_conn.notify(fnum=root_fnum,
                                           buffer_size=0xffff,
                                           completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                           recursive=True)
        test_dir_notify = self.smb_conn.notify(fnum=test_dir_fnum,
                                               buffer_size=0xffff,
                                               completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                               recursive=True)

        # make sure we didn't receive any changes yet.
        self.smb_conn.echo()
        changes = root_notify.get_changes(wait=False)
        self.assertIsNone(changes)
        changes = test_dir_notify.get_changes(wait=False)
        self.assertIsNone(changes)

        # closing the handle on test_dir will trigger
        # a NOTIFY_CLEANUP on test_dir_notify and
        # it also seems to update something on test_dir it self
        # and post a MODIFIED on root_notify
        #
        # TODO: find out why windows generates ACTION_MODIFIED
        #       and why Samba doesn't
        self.smb_conn.close(test_dir_fnum)
        try:
            changes = test_dir_notify.get_changes(wait=True)
            self.fail()
        except samba.NTSTATUSError as err:
            self.assertEqual(err.args[0], NT_STATUS_NOTIFY_CLEANUP)
        self.smb_conn.echo()
        changes = root_notify.get_changes(wait=False)
        if self.strict_checking:
            self.assertIsNotNone(changes)
        if changes is not None:
            self.assertEqual(changes[0]['name'], test_dir)
            self.assertEqual(changes[0]['action'], libsmb.NOTIFY_ACTION_MODIFIED)
            self.assertEqual(len(changes), 1)

            # readd notification request
            root_notify = self.smb_conn.notify(fnum=root_fnum,
                                               buffer_size=0xffff,
                                               completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                               recursive=True)

        # make sure we didn't receive any changes yet.
        self.smb_conn.echo()
        changes = root_notify.get_changes(wait=False)
        self.assertIsNone(changes)

        # remove test_dir
        self.smb_conn.rmdir(dir_path)

        # check for 'removed' notifications
        changes = root_notify.get_changes(wait=True)
        self.assertIsNotNone(changes)
        self.assertEqual(changes[0]['name'], dir_path)
        self.assertEqual(changes[0]['action'], libsmb.NOTIFY_ACTION_REMOVED)
        self.assertEqual(len(changes), 1)

        # readd notification request
        root_notify = self.smb_conn.notify(fnum=root_fnum,
                                           buffer_size=0xffff,
                                           completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                           recursive=True)
        # closing the handle on test_dir will trigger
        # a NOTIFY_CLEANUP on root_notify
        self.smb_conn.close(root_fnum)
        try:
            changes = root_notify.get_changes(wait=True)
            self.fail()
        except samba.NTSTATUSError as err:
            self.assertEqual(err.args[0], NT_STATUS_NOTIFY_CLEANUP)


    def _test_notify_privileged_path(self,
                                     monitor_path=None,
                                     rel_prefix=None):
        self.connect_unpriv()

        domain_sid = security.dom_sid() # we just use S-0-0
        smb_helper = ntacls.SMBHelper(self.smb_conn, domain_sid)

        private_name = "private"
        private_rel = self.make_path(rel_prefix, private_name)
        private_path = self.make_path(test_dir, private_name)
        # create a private test directory
        self.smb_conn.mkdir(private_path)

        # Get the security descriptor and replace it
        # with a one that only grants access to SYSTEM and the
        # owner.
        private_path_sd_old = smb_helper.get_acl(private_path)
        private_path_sd_new = security.descriptor()
        private_path_sd_new.type = private_path_sd_old.type
        private_path_sd_new.revision = private_path_sd_old.revision
        private_path_sd_new = security.descriptor.from_sddl("G:BAD:(A;;0x%x;;;%s)(A;;0x%x;;;%s)" % (
                security.SEC_RIGHTS_DIR_ALL,
                security.SID_NT_SYSTEM,
                security.SEC_RIGHTS_DIR_ALL,
                str(private_path_sd_old.owner_sid)),
                domain_sid)
        private_path_sd_new.type |= security.SEC_DESC_SELF_RELATIVE
        private_path_sd_new.type |= security.SEC_DESC_DACL_PROTECTED
        set_secinfo = security.SECINFO_GROUP | security.SECINFO_DACL | security.SECINFO_PROTECTED_DACL
        smb_helper.set_acl(private_path, private_path_sd_new, sinfo=set_secinfo)

        # setup notification request as privileged user
        monitor_priv_fnum = self.smb_conn.create(Name=monitor_path, ShareAccess=1)
        notify_priv = self.smb_conn.notify(fnum=monitor_priv_fnum,
                                           buffer_size=0xffff,
                                           completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                           recursive=True)

        # setup notification request as unprivileged user
        monitor_unpriv_fnum = self.smb_conn_unpriv.create(Name=monitor_path, ShareAccess=1)
        notify_unpriv = self.smb_conn_unpriv.notify(fnum=monitor_unpriv_fnum,
                                                    buffer_size=0xffff,
                                                    completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                                    recursive=True)

        # make sure we didn't receive any changes yet.
        self.smb_conn.echo()
        changes = notify_priv.get_changes(wait=False)
        self.assertIsNone(changes)
        self.smb_conn_unpriv.echo()
        changes = notify_unpriv.get_changes(wait=False)
        self.assertIsNone(changes)

        # trigger notification in the private dir
        new_name = 'test-new'
        new_rel = self.make_path(private_rel, new_name)
        new_path = self.make_path(private_path, new_name)
        self.smb_conn.mkdir(new_path)

        # check that only the privileged user received the changes
        changes = notify_priv.get_changes(wait=True)
        self.assertIsNotNone(changes)
        self.assertEqual(changes[0]['name'], new_rel)
        self.assertEqual(changes[0]['action'], libsmb.NOTIFY_ACTION_ADDED)
        self.assertEqual(len(changes), 1)
        notify_priv = self.smb_conn.notify(fnum=monitor_priv_fnum,
                                           buffer_size=0xffff,
                                           completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                           recursive=True)

        # check that the unprivileged user does not receives the changes
        self.smb_conn_unpriv.echo()
        changes = notify_unpriv.get_changes(wait=False)
        self.assertIsNone(changes)
        # and there's no additional change for the privileged user
        self.smb_conn.echo()
        changes = notify_priv.get_changes(wait=False)
        self.assertIsNone(changes)

        # trigger notification in the private dir
        self.smb_conn.rmdir(new_path)

        # check that only the privileged user received the changes
        changes = notify_priv.get_changes(wait=True)
        self.assertIsNotNone(changes)
        self.assertEqual(changes[0]['name'], new_rel)
        self.assertEqual(changes[0]['action'], libsmb.NOTIFY_ACTION_REMOVED)
        self.assertEqual(len(changes), 1)
        notify_priv = self.smb_conn.notify(fnum=monitor_priv_fnum,
                                           buffer_size=0xffff,
                                           completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                           recursive=True)

        # check that the unprivileged user does not receives the changes
        self.smb_conn_unpriv.echo()
        changes = notify_unpriv.get_changes(wait=False)
        self.assertIsNone(changes)
        # and there's no additional change for the privileged user
        self.smb_conn.echo()
        changes = notify_priv.get_changes(wait=False)
        self.assertIsNone(changes)

        # trigger notification for both
        self.smb_conn.rmdir(private_path)

        # check that both get the notification
        changes = notify_unpriv.get_changes(wait=True)
        self.assertIsNotNone(changes)
        self.assertEqual(changes[0]['name'], private_rel)
        self.assertEqual(changes[0]['action'], libsmb.NOTIFY_ACTION_REMOVED)
        self.assertEqual(len(changes), 1)
        notify_unpriv = self.smb_conn_unpriv.notify(fnum=monitor_unpriv_fnum,
                                                    buffer_size=0xffff,
                                                    completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                                    recursive=True)
        changes = notify_priv.get_changes(wait=True)
        self.assertIsNotNone(changes)
        self.assertEqual(changes[0]['name'], private_rel)
        self.assertEqual(changes[0]['action'], libsmb.NOTIFY_ACTION_REMOVED)
        self.assertEqual(len(changes), 1)
        notify_priv = self.smb_conn.notify(fnum=monitor_priv_fnum,
                                           buffer_size=0xffff,
                                           completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
                                           recursive=True)

        # check that the unprivileged user does not receives the changes
        self.smb_conn_unpriv.echo()
        changes = notify_unpriv.get_changes(wait=False)
        self.assertIsNone(changes)
        # and there's no additional change for the privileged user
        self.smb_conn.echo()
        changes = notify_priv.get_changes(wait=False)
        self.assertIsNone(changes)

        # closing the handle on will trigger a NOTIFY_CLEANUP
        self.smb_conn_unpriv.close(monitor_unpriv_fnum)
        try:
            changes = notify_unpriv.get_changes(wait=True)
            self.fail()
        except samba.NTSTATUSError as err:
            self.assertEqual(err.args[0], NT_STATUS_NOTIFY_CLEANUP)

        # there's no additional change for the privileged user
        self.smb_conn.echo()
        changes = notify_priv.get_changes(wait=False)
        self.assertIsNone(changes)

        # closing the handle on will trigger a NOTIFY_CLEANUP
        self.smb_conn.close(monitor_priv_fnum)
        try:
            changes = notify_priv.get_changes(wait=True)
            self.fail()
        except samba.NTSTATUSError as err:
            self.assertEqual(err.args[0], NT_STATUS_NOTIFY_CLEANUP)

    def test_notify_privileged_test(self):
        return self._test_notify_privileged_path(monitor_path=test_dir, rel_prefix="")

    def test_notify_privileged_root(self):
        return self._test_notify_privileged_path(monitor_path="", rel_prefix=test_dir)

if __name__ == "__main__":
    import unittest
    unittest.main()
