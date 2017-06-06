#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Tests various schema replication scenarios
#
# Copyright (C) Catalyst.Net Ltd. 2017
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

#
# Usage:
#  export DC1=dc1_dns_name
#  export DC2=dc2_dns_name
#  export SUBUNITRUN=$samba4srcdir/scripting/bin/subunitrun
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" $SUBUNITRUN getncchanges -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

import drs_base
import samba.tests
import ldb
from ldb import SCOPE_BASE

from samba.dcerpc import drsuapi

class DrsReplicaSyncIntegrityTestCase(drs_base.DrsBaseTestCase):
    def setUp(self):
        super(DrsReplicaSyncIntegrityTestCase, self).setUp()
        self.base_dn = self.ldb_dc1.get_default_basedn()
        self.ou = "OU=uptodateness_test,%s" % self.base_dn
        self.ldb_dc1.add({
            "dn": self.ou,
            "objectclass": "organizationalUnit"})
        (self.drs, self.drs_handle) = self._ds_bind(self.dnsname_dc1)
        (self.default_hwm, self.default_utdv) = self._get_highest_hwm_utdv(self.ldb_dc1)
        self._debug = True

    def tearDown(self):
        super(DrsReplicaSyncIntegrityTestCase, self).tearDown()
        # tidyup groups and users
        try:
            self.ldb_dc1.delete(self.ou, ["tree_delete:1"])
        except ldb.LdbError as (enum, string):
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                pass

    def add_object(self, dn):
        """Adds an OU object"""
        self.ldb_dc1.add({"dn": dn, "objectclass": "organizationalunit"})
        res = self.ldb_dc1.search(base=dn, scope=SCOPE_BASE)
        self.assertEquals(len(res), 1)

    def modify_object(self, dn, attr, value):
        """Modifies an object's USN by adding an attribute value to it"""
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb_dc1, dn)
        m[attr] = ldb.MessageElement(value, ldb.FLAG_MOD_ADD, attr)
        self.ldb_dc1.modify(m)

    def create_object_range(self, start, end, prefix=""):
        """
        Creates a block of objects. Object names are numbered sequentially,
        using the optional prefix supplied.
        """
        dn_list = []

        # Create the parents first, then the children.
        # This makes it easier to see in debug when GET_ANC takes effect
        # because the parent/children become interleaved (by default,
        # this approach means the objects are organized into blocks of
        # parents and blocks of children together)
        for x in range(start, end):
            ou = "OU=test_ou_%s%d,%s" % (prefix, x, self.ou)
            self.add_object(ou)
            dn_list.append(ou)

        return dn_list

    def assert_expected_data(self, received_list, expected_list):
        """
        Asserts that we received all the DNs that we expected and
        none are missing.
        """

        # Note that with GET_ANC Windows can end up sending the same parent
        # object multiple times, so this might be noteworthy but doesn't
        # warrant failing the test
        if (len(received_list) != len(expected_list)):
            print("Note: received %d objects but expected %d" %(len(received_list),
                                                                len(expected_list)))

        # Check that we received every object that we were expecting
        for dn in expected_list:
            self.assertTrue(dn in received_list, "DN '%s' missing from replication." % dn)

    def test_repl_integrity(self):
        """
        Modify the objects being replicated while the replication is still
        in progress and check that no object loss occurs.
        """

        # The server behaviour differs between samba and Windows. Samba returns
        # the objects in the original order (up to the pre-modify HWM). Windows
        # incorporates the modified objects and returns them in the new order
        # (i.e. modified objects last), up to the post-modify HWM. The Microsoft
        # docs state the Windows behaviour is optional.

        # Create a range of objects to replicate.
        expected_dn_list = self.create_object_range(0, 400)
        (orig_hwm, unused) = self._get_highest_hwm_utdv(self.ldb_dc1)

        # We ask for the first page of 100 objects.
        # For this test, we don't care what order we receive the objects in,
        # so long as by the end we've received everything
        rxd_dn_list = []
        ctr6 = self._get_replication(drsuapi.DRSUAPI_DRS_WRIT_REP, max_objects=100)
        rxd_dn_list = self._get_ctr6_dn_list(ctr6)

        # Modify some of the second page of objects. This should bump the highwatermark
        for x in range(100, 200):
            self.modify_object(expected_dn_list[x], "displayName", "OU%d" % x)

        (post_modify_hwm, unused) = self._get_highest_hwm_utdv(self.ldb_dc1)
        self.assertTrue(post_modify_hwm.highest_usn > orig_hwm.highest_usn)

        # Get the remaining blocks of data
        while ctr6.more_data:
            ctr6 = self._get_replication(drsuapi.DRSUAPI_DRS_WRIT_REP, max_objects=100,
                                         highwatermark=ctr6.new_highwatermark,
                                         uptodateness_vector=ctr6.uptodateness_vector)
            rxd_dn_list += self._get_ctr6_dn_list(ctr6)

        # Check we still receive all the objects we're expecting
        self.assert_expected_data(rxd_dn_list, expected_dn_list)


