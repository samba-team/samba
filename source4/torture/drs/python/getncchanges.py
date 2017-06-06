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

        # 100 is the minimum max_objects that Microsoft seems to honour
        # (the max honoured is 400ish), so we use that in these tests
        self.max_objects = 100
        self.last_ctr = None

        # store whether we used GET_ANC flags in the requests
        self.used_get_anc = False

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

    def create_object_range(self, start, end, prefix="",
                            children=None, parent_list=None):
        """
        Creates a block of objects. Object names are numbered sequentially,
        using the optional prefix supplied. If the children parameter is
        supplied it will create a parent-child hierarchy and return the
        top-level parents separately.
        """
        dn_list = []

        # Use dummy/empty lists if we're not creating a parent/child hierarchy
        if children is None:
            children = []

        if parent_list is None:
            parent_list = []

        # Create the parents first, then the children.
        # This makes it easier to see in debug when GET_ANC takes effect
        # because the parent/children become interleaved (by default,
        # this approach means the objects are organized into blocks of
        # parents and blocks of children together)
        for x in range(start, end):
            ou = "OU=test_ou_%s%d,%s" % (prefix, x, self.ou)
            self.add_object(ou)
            dn_list.append(ou)

            # keep track of the top-level parents (if needed)
            parent_list.append(ou)

        # create the block of children (if needed)
        for x in range(start, end):
            for child in children:
                ou = "OU=test_ou_child%s%d,%s" % (child, x, parent_list[x])
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
        ctr6 = self.repl_get_next(rxd_dn_list)
        rxd_dn_list = self._get_ctr6_dn_list(ctr6)

        # Modify some of the second page of objects. This should bump the highwatermark
        for x in range(100, 200):
            self.modify_object(expected_dn_list[x], "displayName", "OU%d" % x)

        (post_modify_hwm, unused) = self._get_highest_hwm_utdv(self.ldb_dc1)
        self.assertTrue(post_modify_hwm.highest_usn > orig_hwm.highest_usn)

        # Get the remaining blocks of data
        while not self.replication_complete():
            ctr6 = self.repl_get_next(rxd_dn_list)
            rxd_dn_list += self._get_ctr6_dn_list(ctr6)

        # Check we still receive all the objects we're expecting
        self.assert_expected_data(rxd_dn_list, expected_dn_list)

    def is_parent_known(self, dn, known_dn_list):
        """
        Returns True if the parent of the dn specified is in known_dn_list
        """

        # we can sometimes get system objects like the RID Manager returned.
        # Ignore anything that is not under the test OU we created
        if self.ou not in dn:
            return True

        # Remove the child portion from the name to get the parent's DN
        name_substrings = dn.split(",")
        del name_substrings[0]

        parent_dn = ",".join(name_substrings)

        # check either this object is a parent (it's parent is the top-level
        # test object), or its parent has been seen previously
        return parent_dn == self.ou or parent_dn in known_dn_list

    def repl_get_next(self, initial_objects, get_anc=False):
        """
        Requests the next block of replication data. This tries to simulate
        client behaviour - if we receive a replicated object that we don't know
        the parent of, then re-request the block with the GET_ANC flag set.
        """

        # we're just trying to mimic regular client behaviour here, so just
        # use the highwatermark in the last response we received
        if self.last_ctr:
            highwatermark = self.last_ctr.new_highwatermark
            uptodateness_vector = self.last_ctr.uptodateness_vector
        else:
            # this is the initial replication, so we're starting from the start
            highwatermark = None
            uptodateness_vector = None

        # we'll add new objects as we discover them, so take a copy to modify
        known_objects = initial_objects[:]

        # Ask for the next block of replication data
        replica_flags = drsuapi.DRSUAPI_DRS_WRIT_REP

        if get_anc:
            replica_flags = drsuapi.DRSUAPI_DRS_WRIT_REP | drsuapi.DRSUAPI_DRS_GET_ANC
            self.used_get_anc = True

        ctr6 = self._get_replication(replica_flags,
                                     max_objects=self.max_objects,
                                     highwatermark=highwatermark,
                                     uptodateness_vector=uptodateness_vector)

        # check that we know the parent for every object received
        rxd_dn_list = self._get_ctr6_dn_list(ctr6)

        for i in range(0, len(rxd_dn_list)):

            dn = rxd_dn_list[i]

            if self.is_parent_known(dn, known_objects):

                # the new DN is now known so add it to the list.
                # It may be the parent of another child in this block
                known_objects.append(dn)
            else:
                # If we've already set the GET_ANC flag then it should mean
                # we receive the parents before the child
                self.assertFalse(get_anc, "Unknown parent for object %s" % dn)

                print("Unknown parent for %s - try GET_ANC" % dn)

                # try the same thing again with the GET_ANC flag set this time
                return self.repl_get_next(get_anc=True)

        # store the last successful result so we know what HWM to request next
        self.last_ctr = ctr6

        return ctr6

    def replication_complete(self):
        """Returns True if the current/last replication cycle is complete"""

        if self.last_ctr is None or self.last_ctr.more_data:
            return False
        else:
            return True

    def test_repl_integrity_get_anc(self):
        """
        Modify the parent objects being replicated while the replication is still
        in progress (using GET_ANC) and check that no object loss occurs.
        """

        # Note that GET_ANC behaviour varies between Windows and Samba.
        # On Samba GET_ANC results in the replication restarting from the very
        # beginning. After that, Samba remembers GET_ANC and also sends the
        # parents in subsequent requests (regardless of whether GET_ANC is
        # specified in the later request).
        # Windows only sends the parents if GET_ANC was specified in the last
        # request. It will also resend a parent, even if it's already sent the
        # parent in a previous response (whereas Samba doesn't).

        # Create a small block of 50 parents, each with 2 children (A and B)
        # This is so that we receive some children in the first block, so we
        # can resend with GET_ANC before we learn too many parents
        parent_dn_list = []
        expected_dn_list = self.create_object_range(0, 50, prefix="parent",
                                                    children=("A", "B"),
                                                    parent_list=parent_dn_list)

        # create the remaining parents and children
        expected_dn_list += self.create_object_range(50, 150, prefix="parent",
                                                     children=("A", "B"),
                                                     parent_list=parent_dn_list)

        # We've now got objects in the following order:
        # [50 parents][100 children][100 parents][200 children]

        # Modify the first parent so that it's now ordered last by USN
        # This means we set the GET_ANC flag pretty much straight away
        # because we receive the first child before the first parent
        self.modify_object(parent_dn_list[0], "displayName", "OU0")

        # modify a later block of parents so they also get reordered
        for x in range(50, 100):
            self.modify_object(parent_dn_list[x], "displayName", "OU%d" % x)

        # Get the first block of objects - this should resend the request with
        # GET_ANC set because we won't know about the first child's parent.
        # On samba GET_ANC essentially starts the sync from scratch again, so
        # we get this over with early before we learn too many parents
        rxd_dn_list = []
        ctr6 = self.repl_get_next(rxd_dn_list)
        rxd_dn_list = self._get_ctr6_dn_list(ctr6)

        # modify the last chunk of parents. They should now have a USN higher
        # than the highwater-mark for the replication cycle
        for x in range(100, 150):
            self.modify_object(parent_dn_list[x], "displayName", "OU%d" % x)

        # Get the remaining blocks of data - this will resend the request with
        # GET_ANC if it encounters an object it doesn't have the parent for.
        while not self.replication_complete():
            ctr6 = self.repl_get_next(rxd_dn_list)
            rxd_dn_list += self._get_ctr6_dn_list(ctr6)

        # The way the test objects have been created should force
        # self.repl_get_next() to use the GET_ANC flag. If this doesn't
        # actually happen, then the test isn't doing its job properly
        self.assertTrue(self.used_get_anc,
                        "Test didn't use the GET_ANC flag as expected")

        # Check we get all the objects we're expecting
        self.assert_expected_data(rxd_dn_list, expected_dn_list)

