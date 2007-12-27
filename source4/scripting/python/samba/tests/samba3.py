#!/usr/bin/python

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

import unittest
from samba.samba3 import (GroupMappingDatabase, Registry, PolicyDatabase, SecretsDatabase, TdbSam,
                          WinsDatabase, SmbpasswdFile, ACB_NORMAL, IdmapDatabase, SAMUser)
import os

DATADIR=os.path.join(os.path.dirname(__file__), "../../../../../testdata/samba3")
print "Samba 3 data dir: %s" % DATADIR

class RegistryTestCase(unittest.TestCase):
    def setUp(self):
        self.registry = Registry(os.path.join(DATADIR, "registry.tdb"))

    def tearDown(self):
        self.registry.close()

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


class PolicyTestCase(unittest.TestCase):
    def setUp(self):
        self.policy = PolicyDatabase(os.path.join(DATADIR, "account_policy.tdb"))

    def test_policy(self):
        self.assertEquals(self.policy.min_password_length, 5)
        self.assertEquals(self.policy.minimum_password_age, 0)
        self.assertEquals(self.policy.maximum_password_age, 999999999)
        self.assertEquals(self.policy.refuse_machine_password_change, 0)
        self.assertEquals(self.policy.reset_count_minutes, 0)
        self.assertEquals(self.policy.disconnect_time, -1)
        self.assertEquals(self.policy.user_must_logon_to_change_password, None)
        self.assertEquals(self.policy.password_history, 0)
        self.assertEquals(self.policy.lockout_duration, 0)
        self.assertEquals(self.policy.bad_lockout_minutes, None)


class GroupsTestCase(unittest.TestCase):
    def setUp(self):
        self.groupdb = GroupMappingDatabase(os.path.join(DATADIR, "group_mapping.tdb"))

    def tearDown(self):
        self.groupdb.close()

    def test_group_length(self):
        self.assertEquals(13, len(list(self.groupdb.groupsids())))

    def test_get_group(self):
        self.assertEquals((-1, 5L, 'Administrators', ''), self.groupdb.get_group("S-1-5-32-544"))

    def test_groupsids(self):
        sids = list(self.groupdb.groupsids())
        self.assertTrue("S-1-5-32-544" in sids)

    def test_alias_length(self):
        self.assertEquals(0, len(list(self.groupdb.aliases())))


class SecretsDbTestCase(unittest.TestCase):
    def setUp(self):
        self.secretsdb = SecretsDatabase(os.path.join(DATADIR, "secrets.tdb"))

    def tearDown(self):
        self.secretsdb.close()

    def test_get_sid(self):
        self.assertTrue(self.secretsdb.get_sid("BEDWYR") is not None)


class TdbSamTestCase(unittest.TestCase):
    def setUp(self):
        self.samdb = TdbSam(os.path.join(DATADIR, "passdb.tdb"))

    def tearDown(self):
        self.samdb.close()

    def test_usernames(self):
        self.assertEquals(3, len(list(self.samdb.usernames())))

    def test_getuser(self):
        return
        user = SAMUser("root")
        self.assertEquals(user, self.samdb["root"])


class WinsDatabaseTestCase(unittest.TestCase):
    def setUp(self):
        self.winsdb = WinsDatabase(os.path.join(DATADIR, "wins.dat"))

    def test_length(self):
        self.assertEquals(22, len(self.winsdb))

    def test_first_entry(self):
        self.assertEqual((1124185120, ["192.168.1.5"], 0x64), self.winsdb["ADMINISTRATOR#03"])

    def tearDown(self):
        self.winsdb.close()

class SmbpasswdTestCase(unittest.TestCase):
    def setUp(self):
        self.samdb = SmbpasswdFile(os.path.join(DATADIR, "smbpasswd"))

    def test_length(self):
        self.assertEquals(3, len(self.samdb))

    def test_get_user(self):
        user = SAMUser("rootpw")
        user.lm_password = "552902031BEDE9EFAAD3B435B51404EE"
        user.nt_password = "878D8014606CDA29677A44EFA1353FC7"
        user.acct_ctrl = ACB_NORMAL
        user.pass_last_set_time = int(1125418267)
        user.uid = 0
        self.assertEquals(user, self.samdb["rootpw"])

    def tearDown(self):
        self.samdb.close()


class IdmapDbTestCase(unittest.TestCase):
    def setUp(self):
        self.idmapdb = IdmapDatabase(os.path.join(DATADIR, "winbindd_idmap.tdb"))

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


class ShareInfoTestCase(unittest.TestCase):
    def setUp(self):
        self.shareinfodb = ShareInfoDatabase(os.path.join(DATADIR, "share_info.tdb"))

    # FIXME: needs proper data so it can be tested

    def tearDown(self):
        self.shareinfodb.close()
