#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst.Net Ltd. 2017
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2019
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
import drs_base
import ldb
import samba
from samba import sd_utils
from ldb import LdbError

class ReplAclTestCase(drs_base.DrsBaseTestCase):

    def setUp(self):
        super(ReplAclTestCase, self).setUp()
        self.mod = "(A;CIOI;GA;;;SY)"
        self.mod_becomes = "(A;OICIIO;GA;;;SY)"
        self.mod_inherits_as = "(A;OICIIOID;GA;;;SY)"

        self.sd_utils_dc1 = sd_utils.SDUtils(self.ldb_dc1)
        self.sd_utils_dc2 = sd_utils.SDUtils(self.ldb_dc2)

        self.ou = samba.tests.create_test_ou(self.ldb_dc1,
                                             "test_acl_inherit")

        # disable replication for the tests so we can control at what point
        # the DCs try to replicate
        self._disable_all_repl(self.dnsname_dc1)
        self._disable_all_repl(self.dnsname_dc2)

        # make sure DCs are synchronized before the test
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)

    def tearDown(self):
        self.ldb_dc1.delete(self.ou, ["tree_delete:1"])

        # re-enable replication
        self._enable_all_repl(self.dnsname_dc1)
        self._enable_all_repl(self.dnsname_dc2)

        super(ReplAclTestCase, self).tearDown()

    def test_acl_inheirt_new_object_1_pass(self):
        # Set the inherited ACL on the parent OU
        self.sd_utils_dc1.dacl_add_ace(self.ou, self.mod)

        # Assert ACL set stuck as expected
        self.assertIn(self.mod_becomes,
                      self.sd_utils_dc1.get_sd_as_sddl(self.ou))

        # Make a new object
        dn = ldb.Dn(self.ldb_dc1, "OU=l2,%s" % self.ou)
        self.ldb_dc1.add({"dn": dn, "objectclass": "organizationalUnit"})

        self._net_drs_replicate(DC=self.dnsname_dc2,
                                fromDC=self.dnsname_dc1,
                                forced=True)

        # Assert ACL replicated as expected
        self.assertIn(self.mod_becomes,
                      self.sd_utils_dc2.get_sd_as_sddl(self.ou))

        # Confirm inherited ACLs are identical and were inherited

        self.assertIn(self.mod_inherits_as,
                      self.sd_utils_dc1.get_sd_as_sddl(dn))
        self.assertEqual(self.sd_utils_dc1.get_sd_as_sddl(dn),
                          self.sd_utils_dc2.get_sd_as_sddl(dn))

    def test_acl_inheirt_new_object(self):
        # Set the inherited ACL on the parent OU
        self.sd_utils_dc1.dacl_add_ace(self.ou, self.mod)

        # Assert ACL set stuck as expected
        self.assertIn(self.mod_becomes,
                      self.sd_utils_dc1.get_sd_as_sddl(self.ou))

        # Replicate to DC2

        self._net_drs_replicate(DC=self.dnsname_dc2,
                                fromDC=self.dnsname_dc1,
                                forced=True)

        # Make a new object
        dn = ldb.Dn(self.ldb_dc1, "OU=l2,%s" % self.ou)
        self.ldb_dc1.add({"dn": dn, "objectclass": "organizationalUnit"})

        self._net_drs_replicate(DC=self.dnsname_dc2,
                                fromDC=self.dnsname_dc1,
                                forced=True)

        # Assert ACL replicated as expected
        self.assertIn(self.mod_becomes,
                      self.sd_utils_dc2.get_sd_as_sddl(self.ou))

        # Confirm inherited ACLs are identical and were inheritied

        self.assertIn(self.mod_inherits_as,
                      self.sd_utils_dc1.get_sd_as_sddl(dn))
        self.assertEqual(self.sd_utils_dc1.get_sd_as_sddl(dn),
                          self.sd_utils_dc2.get_sd_as_sddl(dn))

    def test_acl_inherit_existing_object(self):
        # Make a new object
        dn = ldb.Dn(self.ldb_dc1, "OU=l2,%s" % self.ou)
        self.ldb_dc1.add({"dn": dn, "objectclass": "organizationalUnit"})

        try:
            self.ldb_dc2.search(scope=ldb.SCOPE_BASE,
                                base=dn,
                                attrs=[])
            self.fail()
        except LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_NO_SUCH_OBJECT)

        self._net_drs_replicate(DC=self.dnsname_dc2,
                                fromDC=self.dnsname_dc1,
                                forced=True)

        # Confirm it is now replicated
        self.ldb_dc2.search(scope=ldb.SCOPE_BASE,
                            base=dn,
                            attrs=[])

        # Set the inherited ACL on the parent OU
        self.sd_utils_dc1.dacl_add_ace(self.ou, self.mod)

        # Assert ACL set stuck as expected
        self.assertIn(self.mod_becomes,
                      self.sd_utils_dc1.get_sd_as_sddl(self.ou))

        # Replicate to DC2

        self._net_drs_replicate(DC=self.dnsname_dc2,
                                fromDC=self.dnsname_dc1,
                                forced=True)

        # Confirm inherited ACLs are identical and were inherited

        # Assert ACL replicated as expected
        self.assertIn(self.mod_becomes,
                      self.sd_utils_dc2.get_sd_as_sddl(self.ou))

        self.assertIn(self.mod_inherits_as,
                      self.sd_utils_dc1.get_sd_as_sddl(dn))
        self.assertEqual(self.sd_utils_dc1.get_sd_as_sddl(dn),
                          self.sd_utils_dc2.get_sd_as_sddl(dn))

    def test_acl_inheirt_existing_object_1_pass(self):
        # Make a new object
        dn = ldb.Dn(self.ldb_dc1, "OU=l2,%s" % self.ou)
        self.ldb_dc1.add({"dn": dn, "objectclass": "organizationalUnit"})

        try:
            self.ldb_dc2.search(scope=ldb.SCOPE_BASE,
                                base=dn,
                                attrs=[])
            self.fail()
        except LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_NO_SUCH_OBJECT)

        # Set the inherited ACL on the parent OU
        self.sd_utils_dc1.dacl_add_ace(self.ou, self.mod)

        # Assert ACL set as expected
        self.assertIn(self.mod_becomes,
                      self.sd_utils_dc1.get_sd_as_sddl(self.ou))

        # Replicate to DC2

        self._net_drs_replicate(DC=self.dnsname_dc2,
                                fromDC=self.dnsname_dc1,
                                forced=True)

        # Assert ACL replicated as expected
        self.assertIn(self.mod_becomes,
                      self.sd_utils_dc2.get_sd_as_sddl(self.ou))

        # Confirm inherited ACLs are identical and were inherited

        self.assertIn(self.mod_inherits_as,
                      self.sd_utils_dc1.get_sd_as_sddl(dn))
        self.assertEqual(self.sd_utils_dc1.get_sd_as_sddl(dn),
                          self.sd_utils_dc2.get_sd_as_sddl(dn))

    def test_acl_inheirt_renamed_object(self):
        # Make a new object
        new_ou = samba.tests.create_test_ou(self.ldb_dc1,
                                            "acl_test_l2")

        sub_ou_dn = ldb.Dn(self.ldb_dc1, "OU=l2,%s" % self.ou)

        try:
            self.ldb_dc2.search(scope=ldb.SCOPE_BASE,
                                base=new_ou,
                                attrs=[])
            self.fail()
        except LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_NO_SUCH_OBJECT)

        self._net_drs_replicate(DC=self.dnsname_dc2,
                                fromDC=self.dnsname_dc1,
                                forced=True)

        # Confirm it is now replicated
        self.ldb_dc2.search(scope=ldb.SCOPE_BASE,
                            base=new_ou,
                            attrs=[])

        # Set the inherited ACL on the parent OU on DC1
        self.sd_utils_dc1.dacl_add_ace(self.ou, self.mod)

        # Assert ACL set as expected
        self.assertIn(self.mod_becomes,
                      self.sd_utils_dc1.get_sd_as_sddl(self.ou))

        # Replicate to DC2

        self._net_drs_replicate(DC=self.dnsname_dc2,
                                fromDC=self.dnsname_dc1,
                                forced=True)

        # Assert ACL replicated as expected
        self.assertIn(self.mod_becomes,
                      self.sd_utils_dc2.get_sd_as_sddl(self.ou))

        # Rename to under self.ou

        self.ldb_dc1.rename(new_ou, sub_ou_dn)

        # Replicate to DC2

        self._net_drs_replicate(DC=self.dnsname_dc2,
                                fromDC=self.dnsname_dc1,
                                forced=True)

        # Confirm inherited ACLs are identical and were inherited
        self.assertIn(self.mod_inherits_as,
                      self.sd_utils_dc1.get_sd_as_sddl(sub_ou_dn))
        self.assertEqual(self.sd_utils_dc1.get_sd_as_sddl(sub_ou_dn),
                          self.sd_utils_dc2.get_sd_as_sddl(sub_ou_dn))


    def test_acl_inheirt_renamed_child_object(self):
        # Make a new OU
        new_ou = samba.tests.create_test_ou(self.ldb_dc1,
                                            "acl_test_l2")

        # Here is where the new OU will end up at the end.
        sub2_ou_dn_final = ldb.Dn(self.ldb_dc1, "OU=l2,%s" % self.ou)

        sub3_ou_dn = ldb.Dn(self.ldb_dc1, "OU=l3,%s" % new_ou)
        sub3_ou_dn_final = ldb.Dn(self.ldb_dc1, "OU=l3,%s" % sub2_ou_dn_final)

        self.ldb_dc1.add({"dn": sub3_ou_dn,
                          "objectclass": "organizationalUnit"})

        sub4_ou_dn = ldb.Dn(self.ldb_dc1, "OU=l4,%s" % sub3_ou_dn)
        sub4_ou_dn_final = ldb.Dn(self.ldb_dc1, "OU=l4,%s" % sub3_ou_dn_final)

        self.ldb_dc1.add({"dn": sub4_ou_dn,
                          "objectclass": "organizationalUnit"})

        try:
            self.ldb_dc2.search(scope=ldb.SCOPE_BASE,
                                base=new_ou,
                                attrs=[])
            self.fail()
        except LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_NO_SUCH_OBJECT)

        self._net_drs_replicate(DC=self.dnsname_dc2,
                                fromDC=self.dnsname_dc1,
                                forced=True)

        # Confirm it is now replicated
        self.ldb_dc2.search(scope=ldb.SCOPE_BASE,
                            base=new_ou,
                            attrs=[])

        #
        # Given a tree new_ou -> l3 -> l4
        #

        # Set the inherited ACL on the grandchild OU (l3) on DC1
        self.sd_utils_dc1.dacl_add_ace(sub3_ou_dn, self.mod)

        # Assert ACL set stuck as expected
        self.assertIn(self.mod_becomes,
                      self.sd_utils_dc1.get_sd_as_sddl(sub3_ou_dn))

        # Rename new_ou (l2) to under self.ou (this must happen second).  If the
        # inheritence between l3 and l4 is name-based, this could
        # break.

        # The tree is now self.ou -> l2 -> l3 -> l4

        self.ldb_dc1.rename(new_ou, sub2_ou_dn_final)

        # Assert ACL set remained as expected
        self.assertIn(self.mod_becomes,
                      self.sd_utils_dc1.get_sd_as_sddl(sub3_ou_dn_final))

        # Replicate to DC2

        self._net_drs_replicate(DC=self.dnsname_dc2,
                                fromDC=self.dnsname_dc1,
                                forced=True)

        # Confirm set ACLs (on l3 ) are identical and were inherited
        self.assertIn(self.mod_becomes,
                      self.sd_utils_dc2.get_sd_as_sddl(sub3_ou_dn_final))
        self.assertEqual(self.sd_utils_dc1.get_sd_as_sddl(sub3_ou_dn_final),
                          self.sd_utils_dc2.get_sd_as_sddl(sub3_ou_dn_final))

        # Confirm inherited ACLs (from l3 to l4) are identical
        # and where inherited
        self.assertIn(self.mod_inherits_as,
                      self.sd_utils_dc1.get_sd_as_sddl(sub4_ou_dn_final))
        self.assertEqual(self.sd_utils_dc1.get_sd_as_sddl(sub4_ou_dn_final),
                          self.sd_utils_dc2.get_sd_as_sddl(sub4_ou_dn_final))


    def test_acl_inheirt_renamed_object_in_conflict(self):
        # Make a new object to be renamed under self.ou
        new_ou = samba.tests.create_test_ou(self.ldb_dc1,
                                            "acl_test_l2")

        # Make a new OU under self.ou (on DC2)
        sub_ou_dn = ldb.Dn(self.ldb_dc2, "OU=l2,%s" % self.ou)
        self.ldb_dc2.add({"dn": sub_ou_dn,
                          "objectclass": "organizationalUnit"})

        # Set the inherited ACL on the parent OU
        self.sd_utils_dc1.dacl_add_ace(self.ou, self.mod)

        # Assert ACL set stuck as expected
        self.assertIn(self.mod_becomes,
                      self.sd_utils_dc1.get_sd_as_sddl(self.ou))

        # Replicate to DC2

        self._net_drs_replicate(DC=self.dnsname_dc2,
                                fromDC=self.dnsname_dc1,
                                forced=True)

        # Rename to under self.ou
        self.ldb_dc1.rename(new_ou, sub_ou_dn)
        self.assertIn(self.mod_inherits_as,
                      self.sd_utils_dc1.get_sd_as_sddl(sub_ou_dn))

        # Replicate to DC2 (will cause a conflict, DC1 to win, version
        # is higher since named twice)

        self._net_drs_replicate(DC=self.dnsname_dc2,
                                fromDC=self.dnsname_dc1,
                                forced=True)

        children = self.ldb_dc2.search(scope=ldb.SCOPE_ONELEVEL,
                                       base=self.ou,
                                       attrs=[])
        for child in children:
            self.assertIn(self.mod_inherits_as,
                          self.sd_utils_dc2.get_sd_as_sddl(child.dn))
            self.assertEqual(self.sd_utils_dc1.get_sd_as_sddl(sub_ou_dn),
                              self.sd_utils_dc2.get_sd_as_sddl(child.dn))

        # Replicate back
        self._net_drs_replicate(DC=self.dnsname_dc1,
                                fromDC=self.dnsname_dc2,
                                forced=True)

        self.assertIn(self.mod_inherits_as,
                      self.sd_utils_dc1.get_sd_as_sddl(sub_ou_dn))

        for child in children:
            self.assertIn(self.mod_inherits_as,
                          self.sd_utils_dc1.get_sd_as_sddl(child.dn))
            self.assertEqual(self.sd_utils_dc1.get_sd_as_sddl(child.dn),
                              self.sd_utils_dc2.get_sd_as_sddl(child.dn))
