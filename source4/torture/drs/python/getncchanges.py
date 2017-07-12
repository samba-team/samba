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
import random

from samba.dcerpc import drsuapi

class DrsReplicaSyncIntegrityTestCase(drs_base.DrsBaseTestCase):
    def setUp(self):
        super(DrsReplicaSyncIntegrityTestCase, self).setUp()

        # Note that DC2 is the DC with the testenv-specific quirks (e.g. it's
        # the vampire_dc), so we point this test directly at that DC
        self.set_test_ldb_dc(self.ldb_dc2)
        (self.drs, self.drs_handle) = self._ds_bind(self.dnsname_dc2)

        # add some randomness to the test OU. (Deletion of the last test's
        # objects can be slow to replicate out. So the OU created by a previous
        # testenv may still exist at this point).
        rand = random.randint(1, 10000000)
        self.base_dn = self.test_ldb_dc.get_default_basedn()
        self.ou = "OU=getncchanges%d_test,%s" %(rand, self.base_dn)
        self.test_ldb_dc.add({
            "dn": self.ou,
            "objectclass": "organizationalUnit"})
        (self.default_hwm, self.default_utdv) = self._get_highest_hwm_utdv(self.test_ldb_dc)

        self.rxd_dn_list = []
        self.rxd_links = []
        self.rxd_guids = []

        # 100 is the minimum max_objects that Microsoft seems to honour
        # (the max honoured is 400ish), so we use that in these tests
        self.max_objects = 100
        self.last_ctr = None

        # store whether we used GET_TGT/GET_ANC flags in the requests
        self.used_get_tgt = False
        self.used_get_anc = False

    def tearDown(self):
        super(DrsReplicaSyncIntegrityTestCase, self).tearDown()
        # tidyup groups and users
        try:
            self.ldb_dc2.delete(self.ou, ["tree_delete:1"])
        except ldb.LdbError as (enum, string):
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                pass

    def add_object(self, dn):
        """Adds an OU object"""
        self.test_ldb_dc.add({"dn": dn, "objectclass": "organizationalunit"})
        res = self.test_ldb_dc.search(base=dn, scope=SCOPE_BASE)
        self.assertEquals(len(res), 1)

    def modify_object(self, dn, attr, value):
        """Modifies an object's USN by adding an attribute value to it"""
        m = ldb.Message()
        m.dn = ldb.Dn(self.test_ldb_dc, dn)
        m[attr] = ldb.MessageElement(value, ldb.FLAG_MOD_ADD, attr)
        self.test_ldb_dc.modify(m)

    def delete_attribute(self, dn, attr, value):
        """Deletes an attribute from an object"""
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb_dc2, dn)
        m[attr] = ldb.MessageElement(value, ldb.FLAG_MOD_DELETE, attr)
        self.ldb_dc2.modify(m)

    def start_new_repl_cycle(self):
        """Resets enough state info to start a new replication cycle"""
        # reset rxd_links, but leave rxd_guids and rxd_dn_list alone so we know
        # whether a parent/target is unknown and needs GET_ANC/GET_TGT to resolve
        self.rxd_links = []

        self.used_get_tgt = False
        self.used_get_anc = False
        # mostly preserve self.last_ctr, so that we use the last HWM
        if self.last_ctr is not None:
            self.last_ctr.more_data = True

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

    def assert_expected_data(self, expected_list):
        """
        Asserts that we received all the DNs that we expected and
        none are missing.
        """
        received_list = self.rxd_dn_list

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
        (orig_hwm, unused) = self._get_highest_hwm_utdv(self.test_ldb_dc)

        # We ask for the first page of 100 objects.
        # For this test, we don't care what order we receive the objects in,
        # so long as by the end we've received everything
        self.repl_get_next()

        # Modify some of the second page of objects. This should bump the highwatermark
        for x in range(100, 200):
            self.modify_object(expected_dn_list[x], "displayName", "OU%d" % x)

        (post_modify_hwm, unused) = self._get_highest_hwm_utdv(self.test_ldb_dc)
        self.assertTrue(post_modify_hwm.highest_usn > orig_hwm.highest_usn)

        # Get the remaining blocks of data
        while not self.replication_complete():
            self.repl_get_next()

        # Check we still receive all the objects we're expecting
        self.assert_expected_data(expected_dn_list)

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

    def _repl_send_request(self, get_anc=False, get_tgt=False):
        """Sends a GetNCChanges request for the next block of replication data."""

        # we're just trying to mimic regular client behaviour here, so just
        # use the highwatermark in the last response we received
        if self.last_ctr:
            highwatermark = self.last_ctr.new_highwatermark
            uptodateness_vector = self.last_ctr.uptodateness_vector
        else:
            # this is the first replication chunk
            highwatermark = None
            uptodateness_vector = None

        # Ask for the next block of replication data
        replica_flags = drsuapi.DRSUAPI_DRS_WRIT_REP
        more_flags = 0

        if get_anc:
            replica_flags = drsuapi.DRSUAPI_DRS_WRIT_REP | drsuapi.DRSUAPI_DRS_GET_ANC
            self.used_get_anc = True

        if get_tgt:
            more_flags = drsuapi.DRSUAPI_DRS_GET_TGT
            self.used_get_tgt = True

        # return the response from the DC
        return self._get_replication(replica_flags,
                                     max_objects=self.max_objects,
                                     highwatermark=highwatermark,
                                     uptodateness_vector=uptodateness_vector,
                                     more_flags=more_flags)

    def repl_get_next(self, get_anc=False, get_tgt=False, assert_links=False):
        """
        Requests the next block of replication data. This tries to simulate
        client behaviour - if we receive a replicated object that we don't know
        the parent of, then re-request the block with the GET_ANC flag set.
        If we don't know the target object for a linked attribute, then
        re-request with GET_TGT.
        """

        # send a request to the DC and get the response
        ctr6 = self._repl_send_request(get_anc=get_anc, get_tgt=get_tgt)

        # extract the object DNs and their GUIDs from the response
        rxd_dn_list = self._get_ctr6_dn_list(ctr6)
        rxd_guid_list = self._get_ctr6_object_guids(ctr6)

        # we'll add new objects as we discover them, so take a copy of the
        # ones we already know about, so we can modify these lists safely
        known_objects = self.rxd_dn_list[:]
        known_guids = self.rxd_guids[:]

        # check that we know the parent for every object received
        for i in range(0, len(rxd_dn_list)):

            dn = rxd_dn_list[i]
            guid = rxd_guid_list[i]

            if self.is_parent_known(dn, known_objects):

                # the new DN is now known so add it to the list.
                # It may be the parent of another child in this block
                known_objects.append(dn)
                known_guids.append(guid)
            else:
                # If we've already set the GET_ANC flag then it should mean
                # we receive the parents before the child
                self.assertFalse(get_anc, "Unknown parent for object %s" % dn)

                print("Unknown parent for %s - try GET_ANC" % dn)

                # try the same thing again with the GET_ANC flag set this time
                return self.repl_get_next(get_anc=True, get_tgt=get_tgt,
                                          assert_links=assert_links)

        # check we know about references to any objects in the linked attritbutes
        received_links = self._get_ctr6_links(ctr6)

        # This is so that older versions of Samba fail - we want the links to be
        # sent roughly with the objects, rather than getting all links at the end
        if assert_links:
            self.assertTrue(len(received_links) > 0,
                            "Links were expected in the GetNCChanges response")

        for link in received_links:

            # check the source object is known (Windows can actually send links
            # where we don't know the source object yet). Samba shouldn't ever
            # hit this case because it gets the links based on the source
            if link.identifier not in known_guids:

                # If we've already set the GET_ANC flag then it should mean
                # this case doesn't happen
                self.assertFalse(get_anc, "Unknown source object for GUID %s"
                                 % link.identifier)

                print("Unknown source GUID %s - try GET_ANC" % link.identifier)

                # try the same thing again with the GET_ANC flag set this time
                return self.repl_get_next(get_anc=True, get_tgt=get_tgt,
                                          assert_links=assert_links)

            # check we know the target object
            if link.targetGUID not in known_guids:

                # If we've already set the GET_TGT flag then we should have
                # already received any objects we need to know about
                self.assertFalse(get_tgt, "Unknown linked target for object %s"
                                 % link.targetDN)

                print("Unknown target for %s - try GET_TGT" % link.targetDN)

                # try the same thing again with the GET_TGT flag set this time
                return self.repl_get_next(get_anc=get_anc, get_tgt=True,
                                          assert_links=assert_links)

        # store the last successful result so we know what HWM to request next
        self.last_ctr = ctr6

        # store the objects, GUIDs, and links we received
        self.rxd_dn_list += self._get_ctr6_dn_list(ctr6)
        self.rxd_links += self._get_ctr6_links(ctr6)
        self.rxd_guids += self._get_ctr6_object_guids(ctr6)

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
        self.repl_get_next()

        # modify the last chunk of parents. They should now have a USN higher
        # than the highwater-mark for the replication cycle
        for x in range(100, 150):
            self.modify_object(parent_dn_list[x], "displayName", "OU%d" % x)

        # Get the remaining blocks of data - this will resend the request with
        # GET_ANC if it encounters an object it doesn't have the parent for.
        while not self.replication_complete():
            self.repl_get_next()

        # The way the test objects have been created should force
        # self.repl_get_next() to use the GET_ANC flag. If this doesn't
        # actually happen, then the test isn't doing its job properly
        self.assertTrue(self.used_get_anc,
                        "Test didn't use the GET_ANC flag as expected")

        # Check we get all the objects we're expecting
        self.assert_expected_data(expected_dn_list)

    def assert_expected_links(self, objects_with_links, link_attr="managedBy",
                              num_expected=None):
        """
        Asserts that a GetNCChanges response contains any expected links
        for the objects it contains.
        """
        received_links = self.rxd_links

        if num_expected is None:
            num_expected = len(objects_with_links)

        self.assertTrue(len(received_links) == num_expected,
                        "Received %d links but expected %d"
                        %(len(received_links), num_expected))

        for dn in objects_with_links:
            self.assert_object_has_link(dn, link_attr, received_links)

    def assert_object_has_link(self, dn, link_attr, received_links):
        """
        Queries the object in the DB and asserts there is a link in the
        GetNCChanges response that matches.
        """

        # Look up the link attribute in the DB
        # The extended_dn option will dump the GUID info for the link
        # attribute (as a hex blob)
        res = self.test_ldb_dc.search(ldb.Dn(self.test_ldb_dc, dn), attrs=[link_attr],
                                      controls=['extended_dn:1:0'], scope=ldb.SCOPE_BASE)

        # We didn't find the expected link attribute in the DB for the object.
        # Something has gone wrong somewhere...
        self.assertTrue(link_attr in res[0], "%s in DB doesn't have attribute %s"
                        %(dn, link_attr))

        # find the received link in the list and assert that the target and
        # source GUIDs match what's in the DB
        for val in res[0][link_attr]:
            # Work out the expected source and target GUIDs for the DB link
            target_dn = ldb.Dn(self.test_ldb_dc, val)
            targetGUID_blob = target_dn.get_extended_component("GUID")
            sourceGUID_blob = res[0].dn.get_extended_component("GUID")

            found = False

            for link in received_links:
                if link.selfGUID_blob == sourceGUID_blob and \
                   link.targetGUID_blob == targetGUID_blob:

                    found = True

                    if self._debug:
                        print("Link %s --> %s" %(dn[:25], link.targetDN[:25]))
                    break

            self.assertTrue(found, "Did not receive expected link for DN %s" % dn)

    def test_repl_get_tgt(self):
        """
        Creates a scenario where we should receive the linked attribute before
        we know about the target object, and therefore need to use GET_TGT.
        Note: Samba currently avoids this problem by sending all its links last
        """

        # create the test objects
        reportees = self.create_object_range(0, 100, prefix="reportee")
        managers = self.create_object_range(0, 100, prefix="manager")
        all_objects = managers + reportees
        expected_links = reportees

        # add a link attribute to each reportee object that points to the
        # corresponding manager object as the target
        for i in range(0, 100):
            self.modify_object(reportees[i], "managedBy", managers[i])

        # touch the managers (the link-target objects) again to make sure the
        # reportees (link source objects) get returned first by the replication
        for i in range(0, 100):
            self.modify_object(managers[i], "displayName", "OU%d" % i)

        links_expected = True

        # Get all the replication data - this code should resend the requests
        # with GET_TGT
        while not self.replication_complete():

            # get the next block of replication data (this sets GET_TGT if needed)
            self.repl_get_next(assert_links=links_expected)
            links_expected = len(self.rxd_links) < len(expected_links)

        # The way the test objects have been created should force
        # self.repl_get_next() to use the GET_TGT flag. If this doesn't
        # actually happen, then the test isn't doing its job properly
        self.assertTrue(self.used_get_tgt,
                        "Test didn't use the GET_TGT flag as expected")

        # Check we get all the objects we're expecting
        self.assert_expected_data(all_objects)

        # Check we received links for all the reportees
        self.assert_expected_links(expected_links)

    def test_repl_get_tgt_chain(self):
        """
        Tests the behaviour of GET_TGT with a more complicated scenario.
        Here we create a chain of objects linked together, so if we follow
        the link target, then we'd traverse ~200 objects each time.
        """

        # create the test objects
        objectsA = self.create_object_range(0, 100, prefix="AAA")
        objectsB = self.create_object_range(0, 100, prefix="BBB")
        objectsC = self.create_object_range(0, 100, prefix="CCC")

        # create a complex set of object links:
        #   A0-->B0-->C1-->B2-->C3-->B4-->and so on...
        # Basically each object-A should link to a circular chain of 200 B/C
        # objects. We create the links in separate chunks here, as it makes it
        # clearer what happens with the USN (links on Windows have their own
        # USN, so this approach means the A->B/B->C links aren't interleaved)
        for i in range(0, 100):
            self.modify_object(objectsA[i], "managedBy", objectsB[i])

        for i in range(0, 100):
            self.modify_object(objectsB[i], "managedBy", objectsC[(i + 1) % 100])

        for i in range(0, 100):
            self.modify_object(objectsC[i], "managedBy", objectsB[(i + 1) % 100])

        all_objects = objectsA + objectsB + objectsC
        expected_links = all_objects

        # the default order the objects now get returned in should be:
        # [A0-A99][B0-B99][C0-C99]

        links_expected = True

        # Get all the replication data - this code should resend the requests
        # with GET_TGT
        while not self.replication_complete():

            # get the next block of replication data (this sets GET_TGT if needed)
            self.repl_get_next(assert_links=links_expected)
            links_expected = len(self.rxd_links) < len(expected_links)

        # The way the test objects have been created should force
        # self.repl_get_next() to use the GET_TGT flag. If this doesn't
        # actually happen, then the test isn't doing its job properly
        self.assertTrue(self.used_get_tgt,
                        "Test didn't use the GET_TGT flag as expected")

        # Check we get all the objects we're expecting
        self.assert_expected_data(all_objects)

        # Check we received links for all the reportees
        self.assert_expected_links(expected_links)

    def test_repl_integrity_link_attr(self):
        """
        Tests adding links to new objects while a replication is in progress.
        """

        # create some source objects for the linked attributes, sandwiched
        # between 2 blocks of filler objects
        filler = self.create_object_range(0, 100, prefix="filler")
        reportees = self.create_object_range(0, 100, prefix="reportee")
        filler += self.create_object_range(100, 200, prefix="filler")

        # Start the replication and get the first block of filler objects
        # (We're being mean here and setting the GET_TGT flag right from the
        # start. On earlier Samba versions, if the client encountered an
        # unknown target object and retried with GET_TGT, it would restart the
        # replication cycle from scratch, which avoids the problem).
        self.repl_get_next(get_tgt=True)

        # create the target objects and add the links. These objects should be
        # outside the scope of the Samba replication cycle, but the links should
        # still get sent with the source object
        managers = self.create_object_range(0, 100, prefix="manager")

        for i in range(0, 100):
            self.modify_object(reportees[i], "managedBy", managers[i])

        expected_objects = managers + reportees + filler
        expected_links = reportees

        # complete the replication
        while not self.replication_complete():
            self.repl_get_next(get_tgt=True)

        # If we didn't receive the most recently created objects in the last
        # replication cycle, then kick off another replication to get them
        if len(self.rxd_dn_list) < len(expected_objects):
            self.repl_get_next()

            while not self.replication_complete():
                self.repl_get_next()

        # Check we get all the objects we're expecting
        self.assert_expected_data(expected_objects)

        # Check we received links for all the parents
        self.assert_expected_links(expected_links)

    def test_repl_get_anc_link_attr(self):
        """
        A basic GET_ANC test where the parents have linked attributes
        """

        # Create a block of 100 parents and 100 children
        parent_dn_list = []
        expected_dn_list = self.create_object_range(0, 100, prefix="parent",
                                                    children=("A"),
                                                    parent_list=parent_dn_list)

        # Add links from the parents to the children
        for x in range(0, 100):
            self.modify_object(parent_dn_list[x], "managedBy", expected_dn_list[x + 100])

        # add some filler objects at the end. This allows us to easily see
        # which chunk the links get sent in
        expected_dn_list += self.create_object_range(0, 100, prefix="filler")

        # We've now got objects in the following order:
        # [100 x children][100 x parents][100 x filler]

        # Get the replication data - because the block of children come first,
        # this should retry the request with GET_ANC
        while not self.replication_complete():
            self.repl_get_next()

        self.assertTrue(self.used_get_anc,
                        "Test didn't use the GET_ANC flag as expected")

        # Check we get all the objects we're expecting
        self.assert_expected_data(expected_dn_list)

        # Check we received links for all the parents
        self.assert_expected_links(parent_dn_list)

    def test_repl_get_tgt_and_anc(self):
        """
        Check we can resolve an unknown ancestor when fetching the link target,
        i.e. tests using GET_TGT and GET_ANC in combination
        """

        # Create some parent/child objects (the child will be the link target)
        parents = []
        all_objects = self.create_object_range(0, 100, prefix="parent",
                                               children=["la_tgt"],
                                               parent_list=parents)

        children = [item for item in all_objects if item not in parents]

        # create the link source objects and link them to the child/target
        la_sources = self.create_object_range(0, 100, prefix="la_src")
        all_objects += la_sources

        for i in range(0, 100):
            self.modify_object(la_sources[i], "managedBy", children[i])

        expected_links = la_sources

        # modify the children/targets so they come after the link source
        for x in range(0, 100):
            self.modify_object(children[x], "displayName", "OU%d" % x)

        # modify the parents, so they now come last in the replication
        for x in range(0, 100):
            self.modify_object(parents[x], "displayName", "OU%d" % x)

        # We've now got objects in the following order:
        # [100 la_source][100 la_target][100 parents (of la_target)]

        links_expected = True

        # Get all the replication data - this code should resend the requests
        # with GET_TGT and GET_ANC
        while not self.replication_complete():

            # get the next block of replication data (this sets GET_TGT/GET_ANC)
            self.repl_get_next(assert_links=links_expected)
            links_expected = len(self.rxd_links) < len(expected_links)

        # The way the test objects have been created should force
        # self.repl_get_next() to use the GET_TGT/GET_ANC flags. If this
        # doesn't actually happen, then the test isn't doing its job properly
        self.assertTrue(self.used_get_tgt,
                        "Test didn't use the GET_TGT flag as expected")
        self.assertTrue(self.used_get_anc,
                        "Test didn't use the GET_ANC flag as expected")

        # Check we get all the objects we're expecting
        self.assert_expected_data(all_objects)

        # Check we received links for all the link sources
        self.assert_expected_links(expected_links)

        # Second part of test. Add some extra objects and kick off another
        # replication. The test code will use the HWM from the last replication
        # so we'll only receive the objects we modify below
        self.start_new_repl_cycle()

        # add an extra level of grandchildren that hang off a child
        # that got created last time
        new_parent = "OU=test_new_parent,%s" % children[0]
        self.add_object(new_parent)
        new_children = []

        for x in range(0, 50):
            dn = "OU=test_new_la_tgt%d,%s" % (x, new_parent)
            self.add_object(dn)
            new_children.append(dn)

        # replace half of the links to point to the new children
        for x in range(0, 50):
            self.delete_attribute(la_sources[x], "managedBy", children[x])
            self.modify_object(la_sources[x], "managedBy", new_children[x])

        # add some filler objects to fill up the 1st chunk
        filler = self.create_object_range(0, 100, prefix="filler")

        # modify the new children/targets so they come after the link source
        for x in range(0, 50):
            self.modify_object(new_children[x], "displayName", "OU-%d" % x)

        # modify the parent, so it now comes last in the replication
        self.modify_object(new_parent, "displayName", "OU%d" % x)

        # We should now get the modified objects in the following order:
        # [50 links (x 2)][100 filler][50 new children][new parent]
        # Note that the link sources aren't actually sent (their new linked
        # attributes are sent, but apart from that, nothing has changed)
        all_objects = filler + new_children + [new_parent]
        expected_links = la_sources[:50]

        links_expected = True

        while not self.replication_complete():
            self.repl_get_next(assert_links=links_expected)
            links_expected = len(self.rxd_links) < len(expected_links)

        self.assertTrue(self.used_get_tgt,
                        "Test didn't use the GET_TGT flag as expected")
        self.assertTrue(self.used_get_anc,
                        "Test didn't use the GET_ANC flag as expected")

        # Check we get all the objects we're expecting
        self.assert_expected_data(all_objects)

        # Check we received links (50 deleted links and 50 new)
        self.assert_expected_links(expected_links, num_expected=100)

