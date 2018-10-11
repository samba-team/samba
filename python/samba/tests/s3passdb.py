# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
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

"""Tests for samba.s3passdb"""

from samba.samba3 import passdb
from samba.samba3 import param as s3param
from samba.tests import TestCaseInTempDir
from samba.dcerpc.security import dom_sid
import os


for p in ["../../../../../testdata/samba3", "../../../../testdata/samba3"]:
    DATADIR = os.path.join(os.path.dirname(__file__), p)
    if os.path.exists(DATADIR):
        break


class PassdbTestCase(TestCaseInTempDir):

    def setUp(self):
        super(PassdbTestCase, self).setUp()
        os.system("cp -r %s %s" % (DATADIR, self.tempdir))
        datadir = os.path.join(self.tempdir, "samba3")

        self.lp = s3param.get_context()
        self.lp.load(os.path.join(datadir, "smb.conf"))
        self.lp.set("private dir", datadir)
        self.lp.set("state directory", datadir)
        self.lp.set("lock directory", datadir)
        self.lp.set("cache directory", datadir)
        passdb.set_secrets_dir(datadir)
        self.pdb = passdb.PDB("tdbsam")

    def tearDown(self):
        self.lp = []
        self.pdb = []
        os.system("rm -rf %s" % os.path.join(self.tempdir, "samba3"))
        super(PassdbTestCase, self).tearDown()

    def test_policy(self):
        policy = self.pdb.get_account_policy()
        self.assertEquals(0, policy['bad lockout attempt'])
        self.assertEquals(-1, policy['disconnect time'])
        self.assertEquals(0, policy['lockout duration'])
        self.assertEquals(999999999, policy['maximum password age'])
        self.assertEquals(0, policy['minimum password age'])
        self.assertEquals(5, policy['min password length'])
        self.assertEquals(0, policy['password history'])
        self.assertEquals(0, policy['refuse machine password change'])
        self.assertEquals(0, policy['reset count minutes'])
        self.assertEquals(0, policy['user must logon to change password'])

    def test_get_sid(self):
        domain_sid = passdb.get_global_sam_sid()
        self.assertEquals(dom_sid("S-1-5-21-2470180966-3899876309-2637894779"), domain_sid)

    def test_usernames(self):
        userlist = self.pdb.search_users(0)
        self.assertEquals(3, len(userlist))

    def test_getuser(self):
        user = self.pdb.getsampwnam("root")

        self.assertEquals(16, user.acct_ctrl)
        self.assertEquals("", user.acct_desc)
        self.assertEquals(0, user.bad_password_count)
        self.assertEquals(0, user.bad_password_time)
        self.assertEquals(0, user.code_page)
        self.assertEquals(0, user.country_code)
        self.assertEquals("", user.dir_drive)
        self.assertEquals("BEDWYR", user.domain)
        self.assertEquals("root", user.full_name)
        self.assertEquals(dom_sid('S-1-5-21-2470180966-3899876309-2637894779-513'), user.group_sid)
        self.assertEquals("\\\\BEDWYR\\root", user.home_dir)
        self.assertEquals([-1 for i in range(21)], user.hours)
        self.assertEquals(21, user.hours_len)
        self.assertEquals(9223372036854775807, user.kickoff_time)
        self.assertEquals(None, user.lanman_passwd)
        self.assertEquals(9223372036854775807, user.logoff_time)
        self.assertEquals(0, user.logon_count)
        self.assertEquals(168, user.logon_divs)
        self.assertEquals("", user.logon_script)
        self.assertEquals(0, user.logon_time)
        self.assertEquals("", user.munged_dial)
        self.assertEquals(b'\x87\x8d\x80\x14`l\xda)gzD\xef\xa15?\xc7', user.nt_passwd)
        self.assertEquals("", user.nt_username)
        self.assertEquals(1125418267, user.pass_can_change_time)
        self.assertEquals(1125418267, user.pass_last_set_time)
        self.assertEquals(2125418266, user.pass_must_change_time)
        self.assertEquals(None, user.plaintext_passwd)
        self.assertEquals("\\\\BEDWYR\\root\\profile", user.profile_path)
        self.assertEquals(None, user.pw_history)
        self.assertEquals(dom_sid("S-1-5-21-2470180966-3899876309-2637894779-1000"), user.user_sid)
        self.assertEquals("root", user.username)
        self.assertEquals("", user.workstations)

    def test_group_length(self):
        grouplist = self.pdb.enum_group_mapping()
        self.assertEquals(13, len(grouplist))

    def test_get_group(self):
        group = self.pdb.getgrsid(dom_sid("S-1-5-32-544"))
        self.assertEquals("Administrators", group.nt_name)
        self.assertEquals(-1, group.gid)
        self.assertEquals(5, group.sid_name_use)

    def test_groupsids(self):
        grouplist = self.pdb.enum_group_mapping()
        sids = []
        for g in grouplist:
            sids.append(str(g.sid))
        self.assertTrue("S-1-5-32-544" in sids)
        self.assertTrue("S-1-5-32-545" in sids)
        self.assertTrue("S-1-5-32-546" in sids)
        self.assertTrue("S-1-5-32-548" in sids)
        self.assertTrue("S-1-5-32-549" in sids)
        self.assertTrue("S-1-5-32-550" in sids)
        self.assertTrue("S-1-5-32-551" in sids)

    def test_alias_length(self):
        aliaslist = self.pdb.search_aliases()
        self.assertEquals(1, len(aliaslist))
        self.assertEquals("Jelmers NT Group", aliaslist[0]['account_name'])
