# Unix SMB/CIFS implementation. Tests for dsdb
# Copyright (C) Matthieu Patou <mat@matws.net> 2010
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

"""These tests want to be run on a freshly provisioned domain that has
not been greatly modified by other tests (which at the time of writing
probably means 'chgdcpass').

Tests here should only read the database.

This is to avoid flapping tests.
"""

from samba.credentials import Credentials
from samba.samdb import SamDB
from samba.auth import system_session
from samba.tests import TestCase
from samba.gkdi import (
    KEY_CYCLE_DURATION,
    MAX_CLOCK_SKEW
)
from samba.nt_time import nt_now
import ldb
import samba


class DsdbQuietProvisionTests(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.lp = samba.tests.env_loadparm()
        cls.creds = Credentials()
        cls.creds.guess(cls.lp)
        cls.session = system_session()
        cls.samdb = SamDB(session_info=cls.session,
                          credentials=cls.creds,
                          lp=cls.lp)

    def test_dsdb_dn_gkdi_gmsa_root_keys_exist(self):
        """In provision we set up a GKDI root key.

        There should always be at least one that is already valid
        """
        current_time = nt_now()
        # We need the GKDI key to be already available for use
        min_use_start_time = current_time \
            - KEY_CYCLE_DURATION - MAX_CLOCK_SKEW

        dn = self.samdb.get_config_basedn()
        dn.add_child("CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services")
        res = self.samdb.search(dn,
                                scope=ldb.SCOPE_SUBTREE,
                                expression=f"(&(objectClass = msKds-ProvRootKey)(msKds-UseStartTime<={min_use_start_time}))")

        self.assertGreater(len(res), 0)

    def test_dsdb_smartcard_expire_set(self):
        """In provision we set msDS-ExpirePasswordsOnSmartCardOnlyAccounts: TRUE for a new 2016 provision
        """
        dn = self.samdb.get_default_basedn()
        res = self.samdb.search(dn,
                                scope=ldb.SCOPE_BASE,
                                expression="(msDS-ExpirePasswordsOnSmartCardOnlyAccounts=TRUE)")

        self.assertEqual(len(res), 1)
