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

"""Tests for samba.upgradeprovision."""

import os
from samba.upgradehelpers import (usn_in_range, dn_sort,
                                  update_secrets,
                                  construct_existor_expr)
from samba.descriptor import get_diff_sds
from samba.tests.provision import create_dummy_secretsdb
from samba.tests import TestCaseInTempDir
from samba import Ldb
from ldb import SCOPE_BASE
import samba.tests
from samba.dcerpc import security


def dummymessage(a=None, b=None):
    pass


class UpgradeProvisionTestCase(TestCaseInTempDir):
    """Some simple tests for individual functions in the provisioning code.
    """
    def test_usn_in_range(self):
        range = [5, 25, 35, 55]

        vals = [3, 26, 56]

        for v in vals:
            self.assertFalse(usn_in_range(v, range))

        vals = [5, 20, 25, 35, 36]

        for v in vals:
            self.assertTrue(usn_in_range(v, range))

    def test_dn_sort(self):
        # higher level comes after lower even if lexicographicaly closer
        # ie dc=tata,dc=toto (2 levels), comes after dc=toto
        # even if dc=toto is lexicographicaly after dc=tata, dc=toto
        self.assertEqual(dn_sort("dc=tata,dc=toto", "dc=toto"), 1)
        self.assertEqual(dn_sort("dc=zata", "dc=tata"), 1)
        self.assertEqual(dn_sort("dc=toto,dc=tata",
                                  "cn=foo,dc=toto,dc=tata"), -1)
        self.assertEqual(dn_sort("cn=bar, dc=toto,dc=tata",
                                  "cn=foo, dc=toto,dc=tata"), -1)

    def test_get_diff_sds(self):
        domsid = security.dom_sid('S-1-5-21')

        sddl = "O:SAG:DUD:AI(A;CI;RPWPCRCCLCLORCWOWDSW;;;SA)\
(A;CI;RP LCLORC;;;AU)(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)S:AI(AU;CISA;WP;;;WD)"
        sddl1 = "O:SAG:DUD:AI(A;CI;RPWPCRCCLCLORCWOWDSW;;;SA)\
(A;CI;RP LCLORC;;;AU)(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)S:AI(AU;CISA;WP;;;WD)"
        sddl2 = "O:BAG:DUD:AI(A;CI;RPWPCRCCLCLORCWOWDSW;;;SA)\
(A;CI;RP LCLORC;;;AU)(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)S:AI(AU;CISA;WP;;;WD)"
        sddl3 = "O:SAG:BAD:AI(A;CI;RPWPCRCCLCLORCWOWDSW;;;SA)\
(A;CI;RP LCLORC;;;AU)(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)S:AI(AU;CISA;WP;;;WD)"
        sddl4 = "O:SAG:DUD:AI(A;CI;RPWPCRCCLCLORCWOWDSW;;;BA)\
(A;CI;RP LCLORC;;;AU)(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)S:AI(AU;CISA;WP;;;WD)"
        sddl5 = "O:SAG:DUD:AI(A;CI;RPWPCRCCLCLORCWOWDSW;;;SA)\
(A;CI;RP LCLORC;;;AU)(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        sddl6 = "O:SAG:DUD:AI(A;CIID;RPWPCRCCLCLORCWOWDSW;;;SA)\
(A;CIID;RP LCLORC;;;AU)(A;CIID;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)\
(A;CI;RPWPCRCCLCLORCWOWDSW;;;SA)\
(A;CI;RP LCLORC;;;AU)(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)S:AI(AU;CISA;WP;;;WD)(AU;CIIDSA;WP;;;WD)"

        self.assertEqual(get_diff_sds(security.descriptor.from_sddl(sddl, domsid),
                                       security.descriptor.from_sddl(sddl1, domsid),
                                       domsid), "")
        txt = get_diff_sds(security.descriptor.from_sddl(sddl, domsid),
                           security.descriptor.from_sddl(sddl2, domsid),
                           domsid)
        self.assertEqual(txt, "\tOwner mismatch: SA (in ref) BA(in current)\n")
        txt = get_diff_sds(security.descriptor.from_sddl(sddl, domsid),
                           security.descriptor.from_sddl(sddl3, domsid),
                           domsid)
        self.assertEqual(txt, "\tGroup mismatch: DU (in ref) BA(in current)\n")
        txt = get_diff_sds(security.descriptor.from_sddl(sddl, domsid),
                           security.descriptor.from_sddl(sddl4, domsid),
                           domsid)
        txtmsg = "\tPart dacl is different between reference and current here\
 is the detail:\n\t\t(A;CI;RPWPCRCCLCLORCWOWDSW;;;BA) ACE is not present in\
 the reference\n\t\t(A;CI;RPWPCRCCLCLORCWOWDSW;;;SA) ACE is not present in\
 the current\n"
        self.assertEqual(txt, txtmsg)

        txt = get_diff_sds(security.descriptor.from_sddl(sddl, domsid),
                           security.descriptor.from_sddl(sddl5, domsid),
                           domsid)
        self.assertEqual(txt, "\tCurrent ACL hasn't a sacl part\n")
        self.assertEqual(get_diff_sds(security.descriptor.from_sddl(sddl, domsid),
                                       security.descriptor.from_sddl(sddl6, domsid),
                                       domsid), "")

    def test_construct_existor_expr(self):
        res = construct_existor_expr([])
        self.assertEqual(res, "")

        res = construct_existor_expr(["foo"])
        self.assertEqual(res, "(|(foo=*))")

        res = construct_existor_expr(["foo", "bar"])
        self.assertEqual(res, "(|(foo=*)(bar=*))")


class UpdateSecretsTests(samba.tests.TestCaseInTempDir):

    def setUp(self):
        super(UpdateSecretsTests, self).setUp()
        self.referencedb = create_dummy_secretsdb(
            os.path.join(self.tempdir, "ref.ldb"))

    def _getEmptyDb(self):
        return Ldb(os.path.join(self.tempdir, "secrets.ldb"))

    def _getCurrentFormatDb(self):
        return create_dummy_secretsdb(
            os.path.join(self.tempdir, "secrets.ldb"))

    def test_trivial(self):
        # Test that updating an already up-to-date secretsdb works fine
        self.secretsdb = self._getCurrentFormatDb()
        self.assertEqual(None,
                          update_secrets(self.referencedb, self.secretsdb, dummymessage))

    def test_update_modules(self):
        empty_db = self._getEmptyDb()
        update_secrets(self.referencedb, empty_db, dummymessage)
        newmodules = empty_db.search(base="@MODULES", scope=SCOPE_BASE)
        refmodules = self.referencedb.search(base="@MODULES", scope=SCOPE_BASE)
        self.assertEqual(newmodules.msgs, refmodules.msgs)

    def tearDown(self):
        for name in ["ref.ldb", "secrets.ldb", "secrets.tdb", "secrets.tdb.bak", "secrets.ntdb"]:
            path = os.path.join(self.tempdir, name)
            if os.path.exists(path):
                os.unlink(path)
        super(UpdateSecretsTests, self).tearDown()
