# Unix SMB/CIFS implementation. Tests for graph_utils.py routines
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

"""Tests for samba.ldif_utils"""

import samba
import os
from tempfile import mkdtemp

import samba.tests
from samba import ldif_utils
from samba import ldb
from samba.dcerpc import misc


from samba.param import LoadParm
from samba.credentials import Credentials
from samba.samdb import SamDB

MULTISITE_LDIF = os.path.join(os.environ['SRCDIR_ABS'],
                              "testdata/ldif-utils-test-multisite.ldif")

MULTISITE_LDIF_DSAS = (
    ("CN=WIN08,CN=Servers,CN=Site-4,CN=Sites,CN=Configuration,DC=ad,DC=samba,DC=example,DC=com",
     "Site-4"),
    ("CN=WIN07,CN=Servers,CN=Site-4,CN=Sites,CN=Configuration,DC=ad,DC=samba,DC=example,DC=com",
     "Site-4"),
    ("CN=WIN06,CN=Servers,CN=Site-3,CN=Sites,CN=Configuration,DC=ad,DC=samba,DC=example,DC=com",
     "Site-3"),
    ("CN=WIN09,CN=Servers,CN=Site-5,CN=Sites,CN=Configuration,DC=ad,DC=samba,DC=example,DC=com",
     "Site-5"),
    ("CN=WIN10,CN=Servers,CN=Site-5,CN=Sites,CN=Configuration,DC=ad,DC=samba,DC=example,DC=com",
     "Site-5"),
    ("CN=WIN02,CN=Servers,CN=Site-2,CN=Sites,CN=Configuration,DC=ad,DC=samba,DC=example,DC=com",
     "Site-2"),
    ("CN=WIN04,CN=Servers,CN=Site-2,CN=Sites,CN=Configuration,DC=ad,DC=samba,DC=example,DC=com",
     "Site-2"),
    ("CN=WIN03,CN=Servers,CN=Site-2,CN=Sites,CN=Configuration,DC=ad,DC=samba,DC=example,DC=com",
     "Site-2"),
    ("CN=WIN05,CN=Servers,CN=Site-2,CN=Sites,CN=Configuration,DC=ad,DC=samba,DC=example,DC=com",
     "Site-2"),
    ("CN=WIN01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ad,DC=samba,DC=example,DC=com",
     "Default-First-Site-Name"),
)


class LdifUtilTests(samba.tests.TestCase):
    def setUp(self):
        super(LdifUtilTests, self).setUp()
        self.lp = LoadParm()
        self.creds = Credentials()
        self.creds.guess(self.lp)
        #self.creds.set_machine_account(self.lp)
        self.tmpdir = mkdtemp()

    def tearDown(self):
        #shutil.rmtree(self.tmpdir)
        pass

    def test_write_search_url(self):
        pass
        #write_search_result(samdb, f, res)

    def test_ldif_to_samdb(self):
        dburl = os.path.join(self.tmpdir, "ldap")
        samdb = ldif_utils.ldif_to_samdb(dburl, self.lp, MULTISITE_LDIF)
        self.assertIsInstance(samdb, SamDB)

        dsa = ("CN=WIN01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,"
               "CN=Configuration,DC=ad,DC=samba,DC=example,DC=com")
        res = samdb.search(ldb.Dn(samdb, "CN=NTDS Settings," + dsa),
                           scope=ldb.SCOPE_BASE, attrs=["objectGUID"])

        ntds_guid = misc.GUID(samdb.get_ntds_GUID())
        self.assertEqual(misc.GUID(res[0]["objectGUID"][0]), ntds_guid)

        service_name_res = samdb.search(base="",
                                        scope=ldb.SCOPE_BASE,
                                        attrs=["dsServiceName"])
        dn = ldb.Dn(samdb,
                    service_name_res[0]["dsServiceName"][0])
        self.assertEqual(dn, ldb.Dn(samdb, "CN=NTDS Settings," + dsa))

    def test_ldif_to_samdb_forced_local_dsa(self):
        for dsa, site in MULTISITE_LDIF_DSAS:
            dburl = os.path.join(self.tmpdir, "ldif-to-samba-forced-local-dsa"
                                 "-%s" % dsa)
            samdb = ldif_utils.ldif_to_samdb(dburl, self.lp, MULTISITE_LDIF,
                                             forced_local_dsa=dsa)
            self.assertIsInstance(samdb, SamDB)
            self.assertEqual(samdb.server_site_name(), site)

            res = samdb.search(ldb.Dn(samdb, "CN=NTDS Settings," + dsa),
                               scope=ldb.SCOPE_BASE, attrs=["objectGUID"])

            ntds_guid = misc.GUID(samdb.get_ntds_GUID())
            self.assertEqual(misc.GUID(res[0]["objectGUID"][0]), ntds_guid)

            service_name_res = samdb.search(base="",
                                            scope=ldb.SCOPE_BASE,
                                            attrs=["dsServiceName"])
            dn = ldb.Dn(samdb,
                        service_name_res[0]["dsServiceName"][0])
            self.assertEqual(dn, ldb.Dn(samdb, "CN=NTDS Settings," + dsa))

    def samdb_to_ldif_file(self):
        #samdb_to_ldif_file(samdb, dburl, lp, creds, ldif_file):
        pass
