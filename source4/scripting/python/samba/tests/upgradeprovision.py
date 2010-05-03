#!/usr/bin/python

# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
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

import os
from samba.credentials import Credentials
from samba.auth import system_session
from samba.upgradehelpers import get_paths, usn_in_range, get_ldbs,\
                                 find_provision_key_parameters, dn_sort,\
                                 identic_rename, get_diff_sddls
from samba import param
from samba.tests import env_loadparm, TestCaseInTempDir
import ldb

lp = env_loadparm()


class UpgradeProvisionTestCase(TestCaseInTempDir):
    """Some simple tests for individual functions in the provisioning code.
    """
    def test_get_paths(self):
        smbConfPath = "%s/%s/%s" % (os.environ["SELFTEST_PREFIX"], "dc", "etc/smb.conf")
        targetdir = os.path.join(os.environ["SELFTEST_PREFIX"], "dc")
        privatePath = os.path.join(targetdir, "private")

        paths = get_paths(param, None, smbConfPath)
        self.assertEquals(paths.private_dir, privatePath)

        paths2 = get_paths(param, targetdir)
        self.assertEquals(paths2.private_dir, privatePath)

    def test_usn_in_range(self):

        range = []
        range.append(5)
        range.append(25)
        range.append(35)
        range.append(55)

        vals = []
        vals.append(3)
        vals.append(26)
        vals.append(56)

        for v in vals:
            self.assertFalse(usn_in_range(v, range))

        vals = []
        vals.append(5)
        vals.append(20)
        vals.append(25)
        vals.append(35)
        vals.append(36)

        for v in vals:
            self.assertTrue(usn_in_range(v, range))


    def test_get_ldbs(self):
        smbConfPath = "%s/%s/%s" % (os.environ["SELFTEST_PREFIX"], "dc", "etc/smb.conf")
        paths = get_paths(param, None, smbConfPath)
        creds = Credentials()
        creds.guess(lp)
        try:
            get_ldbs(paths, creds, system_session(), lp)
        except:
            self.assertTrue(0)

    def test_find_key_param(self):
        smbConfPath = "%s/%s/%s" % (os.environ["SELFTEST_PREFIX"], "dc", "etc/smb.conf")
        paths = get_paths(param, None, smbConfPath)
        creds = Credentials()
        creds.guess(lp)
        rootdn = "dc=samba,dc=example,dc=com"
        ldbs = get_ldbs(paths, creds, system_session(), lp)
        find_provision_key_parameters(ldbs.sam, ldbs.secrets, paths,
                                                     smbConfPath, lp)
        try:
            names = find_provision_key_parameters(ldbs.sam, ldbs.secrets, paths,
                                                     smbConfPath, lp)
        except:
            self.assertTrue(0)

        self.assertTrue(names.realm == "SAMBA.EXAMPLE.COM")
        self.assertTrue(str(names.rootdn).lower() == rootdn.lower())
        self.assertTrue(names.ntdsguid != "")



    def test_dn_sort(self):
        # higher level comes after lower even if lexicographicaly closer
        # ie dc=tata,dc=toto (2 levels), comes after dc=toto
        # even if dc=toto is lexicographicaly after dc=tata, dc=toto
        self.assertEquals(dn_sort("dc=tata,dc=toto", "dc=toto"), 1)
        self.assertEquals(dn_sort("dc=zata", "dc=tata"), 1)
        self.assertEquals(dn_sort("dc=toto,dc=tata",
                                    "cn=foo,dc=toto,dc=tata"), -1)
        self.assertEquals(dn_sort("cn=bar, dc=toto,dc=tata",
                                    "cn=foo, dc=toto,dc=tata"), -1)

    def test_identic_rename(self):
        smbConfPath = "%s/%s/%s" % (os.environ["SELFTEST_PREFIX"], "dc", "etc/smb.conf")
        paths = get_paths(param, None, smbConfPath)
        creds = Credentials()
        creds.guess(lp)
        rootdn = "DC=samba,DC=example,DC=com"
        ldbs = get_ldbs(paths, creds, system_session(), lp)

        guestDN = ldb.Dn(ldbs.sam, "CN=Guest,CN=Users,%s" % rootdn)
        try:
            identic_rename(ldbs.sam, guestDN)
            res = ldbs.sam.search(expression="(name=Guest)", base=rootdn,
                                    scope=ldb.SCOPE_SUBTREE, attrs=["dn"])
        except:
            self.assertTrue(0)

        self.assertEquals(len(res), 1)
        self.assertEquals(str(res[0]["dn"]), "CN=Guest,CN=Users,%s" % rootdn)

    def test_get_diff_sddl(self):
        sddl = "O:SAG:DUD:AI(A;CIID;RPWPCRCCLCLORCWOWDSW;;;SA)\
(A;CIID;RP LCLORC;;;AU)(A;CIID;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)S:AI(AU;CIIDSA;WP;;;WD)"
        sddl1 = "O:SAG:DUD:AI(A;CIID;RPWPCRCCLCLORCWOWDSW;;;SA)\
(A;CIID;RP LCLORC;;;AU)(A;CIID;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)S:AI(AU;CIIDSA;WP;;;WD)"
        sddl2 = "O:BAG:DUD:AI(A;CIID;RPWPCRCCLCLORCWOWDSW;;;SA)\
(A;CIID;RP LCLORC;;;AU)(A;CIID;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)S:AI(AU;CIIDSA;WP;;;WD)"
        sddl3 = "O:SAG:BAD:AI(A;CIID;RPWPCRCCLCLORCWOWDSW;;;SA)\
(A;CIID;RP LCLORC;;;AU)(A;CIID;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)S:AI(AU;CIIDSA;WP;;;WD)"
        sddl4 = "O:SAG:DUD:AI(A;CIID;RPWPCRCCLCLORCWOWDSW;;;BA)\
(A;CIID;RP LCLORC;;;AU)(A;CIID;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)S:AI(AU;CIIDSA;WP;;;WD)"
        sddl5 = "O:SAG:DUD:AI(A;CIID;RPWPCRCCLCLORCWOWDSW;;;SA)\
(A;CIID;RP LCLORC;;;AU)(A;CIID;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"

        self.assertEquals(get_diff_sddls(sddl, sddl1) ,"")
        txt = get_diff_sddls(sddl, sddl2)
        self.assertEquals(txt ,"\tOwner mismatch: SA (in ref) BA (in current)\n")
        txt = get_diff_sddls(sddl, sddl3)
        self.assertEquals(txt ,"\tGroup mismatch: DU (in ref) BA (in current)\n")
        txt = get_diff_sddls(sddl, sddl4)
        txtmsg = "\tPart dacl is different between reference and current here\
 is the detail:\n\t\t(A;CIID;RPWPCRCCLCLORCWOWDSW;;;BA) ACE is not present in\
 the reference\n\t\t(A;CIID;RPWPCRCCLCLORCWOWDSW;;;SA) ACE is not present in\
 the current\n"
        self.assertEquals(txt , txtmsg)
        txt = get_diff_sddls(sddl, sddl5)
        self.assertEquals(txt ,"\tCurrent ACL hasn't a sacl part\n")
