# Unix SMB/CIFS implementation. Tests for samba.kcc core.
# Copyright (C) Andrew Bartlett 2015
#
# Written by Douglas Bagnall <douglas.bagnall@catalyst.net.nz>
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

"""Tests for samba.kcc"""

import samba
import os
import time
from tempfile import mkdtemp

import samba.tests
from samba import kcc
from samba import ldb
from samba.dcerpc import misc


from samba.param import LoadParm
from samba.credentials import Credentials
from samba.samdb import SamDB

unix_now = int(time.time())
unix_once_upon_a_time = 1000000000  # 2001-09-09

ENV_DSAS = {
    'ad_dc_ntvfs': ['CN=LOCALDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com'],
    'fl2000dc': ['CN=DC5,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba2000,DC=example,DC=com'],
    'fl2003dc': ['CN=DC6,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba2003,DC=example,DC=com'],
    'fl2008r2dc': ['CN=DC7,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba2008r2,DC=example,DC=com'],
    'promoted_dc': ['CN=PROMOTEDVDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com',
                    'CN=LOCALDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com'],
    'vampire_dc': ['CN=LOCALDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com',
                   'CN=LOCALVAMPIREDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com'],
}


class KCCTests(samba.tests.TestCase):
    def setUp(self):
        super(KCCTests, self).setUp()
        self.lp = LoadParm()
        self.creds = Credentials()
        self.creds.guess(self.lp)
        self.creds.set_username(os.environ["USERNAME"])
        self.creds.set_password(os.environ["PASSWORD"])

    def test_list_dsas(self):
        my_kcc = kcc.KCC(unix_now, False, False, False, False)
        my_kcc.load_samdb("ldap://%s" % os.environ["SERVER"],
                          self.lp, self.creds)
        try:
            dsas = my_kcc.list_dsas()
        except kcc.KCCError as e:
            self.fail("kcc.list_dsas failed with %s" % e)
        env = os.environ['TEST_ENV']
        for expected_dsa in ENV_DSAS[env]:
            self.assertIn(expected_dsa, dsas)

    def test_verify(self):
        """check that the KCC generates graphs that pass its own verify
        option. This is not a spectacular achievement when there are
        only a couple of nodes to connect, but it shows something.
        """
        my_kcc = kcc.KCC(unix_now, readonly=True, verify=True,
                         debug=False, dot_file_dir=None)

        # As this is flapping with errors under python3, we catch
        # exceptions and turn them into failures..
        try:
            my_kcc.run("ldap://%s" % os.environ["SERVER"],
                       self.lp, self.creds,
                       attempt_live_connections=False)
        except (samba.kcc.graph_utils.GraphError, kcc.KCCError):
            import traceback
            traceback.print_exc()
            self.fail()
