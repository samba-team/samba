# Unix SMB/CIFS implementation. Tests for samba.kcc.ldif_import_export.
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

"""Tests for samba.kcc.ldif_import_export"""

import samba
import os
import time
import subprocess
import logging
import samba.tests
from samba.kcc import ldif_import_export, KCC
from samba import ldb
from samba.dcerpc import misc


from samba.param import LoadParm
from samba.credentials import Credentials
from samba.samdb import SamDB

unix_now = int(time.time())

MULTISITE_LDIF = os.path.join(os.environ['SRCDIR_ABS'],
                              "testdata/ldif-utils-test-multisite.ldif")


# UNCONNECTED_LDIF is a single site, unconnected 5DC database that was
# created using samba-tool domain join in testenv.
UNCONNECTED_LDIF = os.path.join(os.environ['SRCDIR_ABS'],
                                "testdata/unconnected-intrasite.ldif")

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


class LdifImportExportTests(samba.tests.TestCaseInTempDir):
    def setUp(self):
        super(LdifImportExportTests, self).setUp()
        self.lp = LoadParm()
        self.creds = Credentials()
        self.creds.guess(self.lp)

    def remove_files(self, *files):
        for f in files:
            assert(f.startswith(self.tempdir))
            os.unlink(f)

    def test_write_search_url(self):
        pass

    def test_ldif_to_samdb(self):
        dburl = os.path.join(self.tempdir, "ldap")
        samdb = ldif_import_export.ldif_to_samdb(dburl, self.lp,
                                                 MULTISITE_LDIF)
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
                    service_name_res[0]["dsServiceName"][0].decode('utf8'))
        self.assertEqual(dn, ldb.Dn(samdb, "CN=NTDS Settings," + dsa))
        self.remove_files(dburl)

    def test_ldif_to_samdb_forced_local_dsa(self):
        for dsa, site in MULTISITE_LDIF_DSAS:
            dburl = os.path.join(self.tempdir, "ldif-to-samba-forced-local-dsa"
                                 "-%s" % dsa)
            samdb = ldif_import_export.ldif_to_samdb(dburl, self.lp,
                                                     MULTISITE_LDIF,
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
                        service_name_res[0]["dsServiceName"][0].decode('utf8'))
            self.assertEqual(dn, ldb.Dn(samdb, "CN=NTDS Settings," + dsa))
            self.remove_files(dburl)

    def test_samdb_to_ldif_file(self):
        dburl = os.path.join(self.tempdir, "ldap")
        dburl2 = os.path.join(self.tempdir, "ldap_roundtrip")
        ldif_file = os.path.join(self.tempdir, "ldif")
        samdb = ldif_import_export.ldif_to_samdb(dburl, self.lp,
                                                 MULTISITE_LDIF)
        self.assertIsInstance(samdb, SamDB)
        ldif_import_export.samdb_to_ldif_file(samdb, dburl,
                                              lp=self.lp, creds=None,
                                              ldif_file=ldif_file)
        self.assertGreater(os.path.getsize(ldif_file), 1000,
                           "LDIF should be larger than 1000 bytes")
        samdb = ldif_import_export.ldif_to_samdb(dburl2, self.lp,
                                                 ldif_file)
        self.assertIsInstance(samdb, SamDB)
        dsa = ("CN=WIN01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,"
               "CN=Configuration,DC=ad,DC=samba,DC=example,DC=com")
        res = samdb.search(ldb.Dn(samdb, "CN=NTDS Settings," + dsa),
                           scope=ldb.SCOPE_BASE, attrs=["objectGUID"])
        self.remove_files(dburl)
        self.remove_files(dburl2)
        self.remove_files(ldif_file)


class KCCMultisiteLdifTests(samba.tests.TestCaseInTempDir):
    def setUp(self):
        super(KCCMultisiteLdifTests, self).setUp()
        self.lp = LoadParm()
        self.creds = Credentials()
        self.creds.guess(self.lp)

    def remove_files(self, *files):
        for f in files:
            assert(f.startswith(self.tempdir))
            os.unlink(f)

    def _get_kcc(self, name, readonly=False, verify=False, dot_file_dir=None):
        # Note that setting read-only to False won't affect the ldif,
        # only the temporary database that is created from it.
        my_kcc = KCC(unix_now, readonly=readonly, verify=verify,
                     dot_file_dir=dot_file_dir)
        tmpdb = os.path.join(self.tempdir, 'tmpdb')
        my_kcc.import_ldif(tmpdb, self.lp, MULTISITE_LDIF)
        self.remove_files(tmpdb)
        return my_kcc

    def test_list_dsas(self):
        my_kcc = self._get_kcc('test-list')
        dsas = set(my_kcc.list_dsas())
        expected_dsas = set(x[0] for x in MULTISITE_LDIF_DSAS)
        self.assertEqual(dsas, expected_dsas)

    def test_verify(self):
        """Check that the KCC generates graphs that pass its own verify
        option.
        """
        my_kcc = self._get_kcc('test-verify', verify=True)
        tmpdb = os.path.join(self.tempdir, 'verify-tmpdb')
        my_kcc.import_ldif(tmpdb, self.lp, MULTISITE_LDIF)

        my_kcc.run(None,
                   self.lp, self.creds,
                   attempt_live_connections=False)
        self.remove_files(tmpdb)

    def test_unconnected_db(self):
        """Check that the KCC generates errors on a unconnected db
        """
        my_kcc = self._get_kcc('test-verify', verify=True)
        tmpdb = os.path.join(self.tempdir, 'verify-tmpdb')
        my_kcc.import_ldif(tmpdb, self.lp, UNCONNECTED_LDIF)

        try:
            my_kcc.run(None,
                       self.lp, self.creds,
                       attempt_live_connections=False)
        except samba.kcc.graph_utils.GraphError:
            pass
        except Exception:
            self.fail("Did not expect this error.")
        finally:
            self.remove_files(tmpdb)

    def test_dotfiles(self):
        """Check that KCC writes dot_files when asked.
        """
        my_kcc = self._get_kcc('test-dotfiles', dot_file_dir=self.tempdir)
        tmpdb = os.path.join(self.tempdir, 'dotfile-tmpdb')
        files = [tmpdb]
        my_kcc.import_ldif(tmpdb, self.lp, MULTISITE_LDIF)
        my_kcc.run(None,
                   self.lp, self.creds,
                   attempt_live_connections=False)

        dot = '/usr/bin/dot'
        for fn in os.listdir(self.tempdir):
            if fn.endswith('.dot'):
                ffn = os.path.join(self.tempdir, fn)
                if os.path.exists(dot) and subprocess.call([dot, '-?']) == 0:
                    r = subprocess.call([dot, '-Tcanon', ffn])
                    self.assertEqual(r, 0)

                # even if dot is not there, at least check the file is non-empty
                size = os.stat(ffn).st_size
                self.assertNotEqual(size, 0)
                files.append(ffn)

        self.remove_files(*files)
