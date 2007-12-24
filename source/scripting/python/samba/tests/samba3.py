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
from samba.samba3 import GroupMappingDatabase, Registry, PolicyDatabase
import os

DATADIR=os.path.join(os.path.dirname(__file__), "../../../../../testdata/samba3")

class RegistryTestCase(unittest.TestCase):
    def setUp(self):
        self.registry = Registry(os.path.join(DATADIR, "registry.tdb"))

    def test_length(self):
        self.assertEquals(28, len(self.registry))

    def test_keys(self):
        self.assertEquals([], self.registry.keys())


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
        self.assertEquals(self.policy.user_must_logon_to_change_password, 0)
        self.assertEquals(self.policy.password_history, 0)
        self.assertEquals(self.policy.lockout_duration, 0)
        self.assertEquals(self.policy.bad_lockout_minutes, 0)


class GroupsTestCase(unittest.TestCase):
    def setUp(self):
        self.groupdb = GroupMappingDatabase(os.path.join(DATADIR, "group_mapping.tdb"))

