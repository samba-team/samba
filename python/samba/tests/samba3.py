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

"""Tests for samba.samba3."""

from samba.samba3 import (
    Registry,
    WinsDatabase,
    IdmapDatabase,
    )
from samba.samba3 import passdb
from samba.samba3 import param as s3param
from samba.tests import TestCase, TestCaseInTempDir
from samba.dcerpc.security import dom_sid
import os


for p in [ "../../../../../testdata/samba3", "../../../../testdata/samba3" ]:
    DATADIR = os.path.join(os.path.dirname(__file__), p)
    if os.path.exists(DATADIR):
        break


class RegistryTestCase(TestCase):

    def setUp(self):
        super(RegistryTestCase, self).setUp()
        self.registry = Registry(os.path.join(DATADIR, "registry"))

    def tearDown(self):
        self.registry.close()
        super(RegistryTestCase, self).tearDown()

    def test_length(self):
        self.assertEquals(28, len(self.registry))

    def test_keys(self):
        self.assertTrue("HKLM" in self.registry.keys())

    def test_subkeys(self):
        self.assertEquals(["SOFTWARE", "SYSTEM"], self.registry.subkeys("HKLM"))

    def test_values(self):
        self.assertEquals({'DisplayName': (1L, 'E\x00v\x00e\x00n\x00t\x00 \x00L\x00o\x00g\x00\x00\x00'),
                           'ErrorControl': (4L, '\x01\x00\x00\x00')},
                           self.registry.values("HKLM/SYSTEM/CURRENTCONTROLSET/SERVICES/EVENTLOG"))


class PassdbTestCase(TestCaseInTempDir):

    def setUp(self):
        super (PassdbTestCase, self).setUp()
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

    def test_param(self):
        self.assertEquals("BEDWYR", self.lp.get("netbios name"))
        self.assertEquals("SAMBA", self.lp.get("workgroup"))
        self.assertEquals("USER", self.lp.get("security"))

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
        self.assertEquals('\x87\x8d\x80\x14`l\xda)gzD\xef\xa15?\xc7', user.nt_passwd)
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


class WinsDatabaseTestCase(TestCase):

    def setUp(self):
        super(WinsDatabaseTestCase, self).setUp()
        self.winsdb = WinsDatabase(os.path.join(DATADIR, "wins.dat"))

    def test_length(self):
        self.assertEquals(22, len(self.winsdb))

    def test_first_entry(self):
        self.assertEqual((1124185120, ["192.168.1.5"], 0x64), self.winsdb["ADMINISTRATOR#03"])

    def tearDown(self):
        self.winsdb.close()
        super(WinsDatabaseTestCase, self).tearDown()


class IdmapDbTestCase(TestCase):

    def setUp(self):
        super(IdmapDbTestCase, self).setUp()
        self.idmapdb = IdmapDatabase(os.path.join(DATADIR,
            "winbindd_idmap"))

    def test_user_hwm(self):
        self.assertEquals(10000, self.idmapdb.get_user_hwm())

    def test_group_hwm(self):
        self.assertEquals(10002, self.idmapdb.get_group_hwm())

    def test_uids(self):
        self.assertEquals(1, len(list(self.idmapdb.uids())))

    def test_gids(self):
        self.assertEquals(3, len(list(self.idmapdb.gids())))

    def test_get_user_sid(self):
        self.assertEquals("S-1-5-21-58189338-3053988021-627566699-501", self.idmapdb.get_user_sid(65534))

    def test_get_group_sid(self):
        self.assertEquals("S-1-5-21-2447931902-1787058256-3961074038-3007", self.idmapdb.get_group_sid(10001))

    def tearDown(self):
        self.idmapdb.close()
        super(IdmapDbTestCase, self).tearDown()
