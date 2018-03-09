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

from __future__ import print_function
import drs_base
import samba.tests
import ldb
from ldb import SCOPE_BASE
import random

from samba.dcerpc import drsuapi

class DrsReplicaSyncIntegrityTestCase(drs_base.DrsBaseTestCase):
    def setUp(self):
        super(DrsReplicaSyncIntegrityTestCase, self).setUp()

        self.init_test_state()

        # Note that DC2 is the DC with the testenv-specific quirks (e.g. it's
        # the vampire_dc), so we point this test directly at that DC
        self.set_test_ldb_dc(self.ldb_dc2)

        # add some randomness to the test OU. (Deletion of the last test's
        # objects can be slow to replicate out. So the OU created by a previous
        # testenv may still exist at this point).
        rand = random.randint(1, 10000000)
        self.base_dn = self.test_ldb_dc.get_default_basedn()
        self.ou = "OU=getncchanges%d_test,%s" %(rand, self.base_dn)
        self.test_ldb_dc.add({
            "dn": self.ou,
            "objectclass": "organizationalUnit"})

        self.default_conn = DcConnection(self, self.ldb_dc2, self.dnsname_dc2)
        self.set_dc_connection(self.default_conn)

    def tearDown(self):
        super(DrsReplicaSyncIntegrityTestCase, self).tearDown()
        # tidyup groups and users
        try:
            self.ldb_dc2.delete(self.ou, ["tree_delete:1"])
        except ldb.LdbError as e:
            (enum, string) = e.args
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                pass

    def init_test_state(self):
        self.rxd_dn_list = []
        self.rxd_links = []
        self.rxd_guids = []
        self.last_ctr = None

        # 100 is the minimum max_objects that Microsoft seems to honour
        # (the max honoured is 400ish), so we use that in these tests
        self.max_objects = 100

        # store whether we used GET_TGT/GET_ANC flags in the requests
        self.used_get_tgt = False
        self.used_get_anc = False

    def add_object(self, dn, objectclass="organizationalunit"):
        """Adds an OU object"""
        self.test_ldb_dc.add({"dn": dn, "objectclass": objectclass})
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
        m.dn = ldb.Dn(self.test_ldb_dc, dn)
        m[attr] = ldb.MessageElement(value, ldb.FLAG_MOD_DELETE, attr)
        self.test_ldb_dc.modify(m)

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

            # skip any links that aren't part of the test
            if self.ou not in link.targetDN:
                continue

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

    def _repl_integrity_obj_deletion(self, delete_link_source=True):
        """
        Tests deleting link objects while a replication is in progress.
        """

        # create some objects and link them together, with some filler
        # object in between the link sources
        la_sources = self.create_object_range(0, 100, prefix="la_source")
        la_targets = self.create_object_range(0, 100, prefix="la_targets")

        for i in range(0, 50):
            self.modify_object(la_sources[i], "managedBy", la_targets[i])

        filler = self.create_object_range(0, 100, prefix="filler")

        for i in range(50, 100):
            self.modify_object(la_sources[i], "managedBy", la_targets[i])

        # touch the targets so that the sources get replicated first
        for i in range(0, 100):
            self.modify_object(la_targets[i], "displayName", "OU%d" % i)

        # objects should now be in the following USN order:
        # [50 la_source][100 filler][50 la_source][100 la_target]

        # Get the first block containing 50 link sources
        self.repl_get_next()

        # delete either the link targets or link source objects
        if delete_link_source:
            objects_to_delete = la_sources
            # in GET_TGT testenvs we only receive the first 50 source objects
            expected_objects = la_sources[:50] + la_targets + filler
        else:
            objects_to_delete = la_targets
            expected_objects = la_sources + filler

        for obj in objects_to_delete:
            self.ldb_dc2.delete(obj)

        # complete the replication
        while not self.replication_complete():
            self.repl_get_next()

        # Check we get all the objects we're expecting
        self.assert_expected_data(expected_objects)

        # we can't use assert_expected_links() here because it tries to check
        # against the deleted objects on the DC. (Although we receive some
        # links from the first block processed, the Samba client should end up
        # deleting these, as the source/target object involved is deleted)
        self.assertTrue(len(self.rxd_links) == 50,
                        "Expected 50 links, not %d" % len(self.rxd_links))

    def test_repl_integrity_src_obj_deletion(self):
        self._repl_integrity_obj_deletion(delete_link_source=True)

    def test_repl_integrity_tgt_obj_deletion(self):
        self._repl_integrity_obj_deletion(delete_link_source=False)

    def restore_deleted_object(self, guid, new_dn):
        """Re-animates a deleted object"""

        res = self.test_ldb_dc.search(base="<GUID=%s>" % self._GUID_string(guid), attrs=["isDeleted"],
                                  controls=['show_deleted:1'], scope=ldb.SCOPE_BASE)
        if len(res) != 1:
            return

        msg = ldb.Message()
        msg.dn = res[0].dn
        msg["isDeleted"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, "isDeleted")
        msg["distinguishedName"] = ldb.MessageElement([new_dn], ldb.FLAG_MOD_REPLACE, "distinguishedName")
        self.test_ldb_dc.modify(msg, ["show_deleted:1"])

    def sync_DCs(self, nc_dn=None):
        # make sure DC1 has all the changes we've made to DC2
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, nc_dn=nc_dn)

    def get_object_guid(self, dn):
        res = self.test_ldb_dc.search(base=dn, attrs=["objectGUID"], scope=ldb.SCOPE_BASE)
        return res[0]['objectGUID'][0]


    def set_dc_connection(self, conn):
        """
        Switches over the connection state info that the underlying drs_base
        class uses so that we replicate with a different DC.
        """
        self.default_hwm = conn.default_hwm
        self.default_utdv = conn.default_utdv
        self.drs = conn.drs
        self.drs_handle = conn.drs_handle
        self.set_test_ldb_dc(conn.ldb_dc)

    def assert_DCs_replication_is_consistent(self, peer_conn, all_objects,
                                             expected_links):
        """
        Replicates against both the primary and secondary DCs in the testenv
        and checks that both return the expected results.
        """
        print("Checking replication against primary test DC...")

        # get the replication data from the test DC first
        while not self.replication_complete():
            self.repl_get_next()

        # Check we get all the objects and links we're expecting
        self.assert_expected_data(all_objects)
        self.assert_expected_links(expected_links)

        # switch over the DC state info so we now talk to the peer DC
        self.set_dc_connection(peer_conn)
        self.init_test_state()

        print("Checking replication against secondary test DC...")

        # check that we get the same information from the 2nd DC
        while not self.replication_complete():
            self.repl_get_next()

        self.assert_expected_data(all_objects)
        self.assert_expected_links(expected_links)

        # switch back to using the default connection
        self.set_dc_connection(self.default_conn)

    def test_repl_integrity_obj_reanimation(self):
        """
        Checks receiving links for a re-animated object doesn't lose links.
        We test this against the peer DC to make sure it doesn't drop links.
        """

        # This test is a little different in that we're particularly interested
        # in exercising the replmd client code on the second DC.
        # First, make sure the peer DC has the base OU, then connect to it (so
        # we store its inital HWM)
        self.sync_DCs()
        peer_conn = DcConnection(self, self.ldb_dc1, self.dnsname_dc1)

        # create the link source/target objects
        la_sources = self.create_object_range(0, 100, prefix="la_src")
        la_targets = self.create_object_range(0, 100, prefix="la_tgt")

        # store the target object's GUIDs (we need to know these to reanimate them)
        target_guids = []

        for dn in la_targets:
            target_guids.append(self.get_object_guid(dn))

        # delete the link target
        for x in range(0, 100):
            self.ldb_dc2.delete(la_targets[x])

        # sync the DCs, then disable replication. We want the peer DC to get
        # all the following changes in a single replication cycle
        self.sync_DCs()
        self._disable_all_repl(self.dnsname_dc2)

        # restore the target objects for the linked attributes again
        for x in range(0, 100):
            self.restore_deleted_object(target_guids[x], la_targets[x])

        # add the links
        for x in range(0, 100):
            self.modify_object(la_sources[x], "managedBy", la_targets[x])

        # create some additional filler objects
        filler = self.create_object_range(0, 100, prefix="filler")

        # modify the targets so they now come last
        for x in range(0, 100):
            self.modify_object(la_targets[x], "displayName", "OU-%d" % x)

        # the objects should now be sent in the following order:
        # [la sources + links][filler][la targets]
        all_objects = la_sources + la_targets + filler
        expected_links = la_sources

        # Enable replication again make sure the 2 DCs are back in sync
        self._enable_all_repl(self.dnsname_dc2)
        self.sync_DCs()

        # Get the replication data from each DC in turn.
        # Check that both give us all the objects and links we're expecting,
        # i.e. no links were lost
        self.assert_DCs_replication_is_consistent(peer_conn, all_objects,
                                                  expected_links)

    def test_repl_integrity_cross_partition_links(self):
        """
        Checks that a cross-partition link to an unknown target object does
        not result in missing links.
        """

        # check the peer DC is up-to-date, then connect (storing its HWM)
        self.sync_DCs()
        peer_conn = DcConnection(self, self.ldb_dc1, self.dnsname_dc1)

        # stop replication so the peer gets the following objects in one go
        self._disable_all_repl(self.dnsname_dc2)

        # create a link source object in the main NC
        la_source = "OU=cross_nc_src,%s" % self.ou
        self.add_object(la_source)

        # create the link target (a server object) in the config NC
        rand = random.randint(1, 10000000)
        la_target = "CN=getncchanges-%d,CN=Servers,CN=Default-First-Site-Name," \
                    "CN=Sites,%s" %(rand, self.config_dn)
        self.add_object(la_target, objectclass="server")

        # add a cross-partition link between the two
        self.modify_object(la_source, "managedBy", la_target)

        # First, sync across to the peer the NC containing the link source object
        self.sync_DCs()

        # Now, before the peer has received the partition containing the target
        # object, try replicating from the peer. It will only know about half
        # of the link at this point, but it should be a valid scenario
        self.set_dc_connection(peer_conn)

        while not self.replication_complete():
            # pretend we've received other link targets out of order and that's
            # forced us to use GET_TGT. This checks the peer doesn't fail trying
            # to fetch a cross-partition target object that doesn't exist
            self.repl_get_next(get_tgt=True)

        self.set_dc_connection(self.default_conn)
        self.init_test_state()

        # Now sync across the partition containing the link target object
        self.sync_DCs(nc_dn=self.config_dn)
        self._enable_all_repl(self.dnsname_dc2)

        # Get the replication data from each DC in turn.
        # Check that both return the cross-partition link (note we're not
        # checking the config domain NC here for simplicity)
        self.assert_DCs_replication_is_consistent(peer_conn,
                                                  all_objects=[la_source],
                                                  expected_links=[la_source])

        # the cross-partition linked attribute has a missing backlink. Check
        # that we can still delete it successfully
        self.delete_attribute(la_source, "managedBy", la_target)
        self.sync_DCs()

        res = self.test_ldb_dc.search(ldb.Dn(self.ldb_dc1, la_source),
                                      attrs=["managedBy"],
                                      controls=['extended_dn:1:0'],
                                      scope=ldb.SCOPE_BASE)
        self.assertFalse("managedBy" in res[0], "%s in DB still has managedBy attribute"
                         % la_source)
        res = self.test_ldb_dc.search(ldb.Dn(self.ldb_dc2, la_source),
                                      attrs=["managedBy"],
                                      controls=['extended_dn:1:0'],
                                      scope=ldb.SCOPE_BASE)
        self.assertFalse("managedBy" in res[0], "%s in DB still has managedBy attribute"
                         % la_source)

        # Check receiving a cross-partition link to a deleted target.
        # Delete the target and make sure the deletion is sync'd between DCs
        target_guid = self.get_object_guid(la_target)
        self.test_ldb_dc.delete(la_target)
        self.sync_DCs(nc_dn=self.config_dn)        
        self._disable_all_repl(self.dnsname_dc2)

        # re-animate the target
        self.restore_deleted_object(target_guid, la_target)
        self.modify_object(la_source, "managedBy", la_target)

        # now sync the link - because the target is in another partition, the
        # peer DC receives a link for a deleted target, which it should accept
        self.sync_DCs()
        res = self.test_ldb_dc.search(ldb.Dn(self.ldb_dc1, la_source),
                                      attrs=["managedBy"],
                                      controls=['extended_dn:1:0'],
                                      scope=ldb.SCOPE_BASE)
        self.assertTrue("managedBy" in res[0], "%s in DB missing managedBy attribute"
                        % la_source)

        # cleanup the server object we created in the Configuration partition
        self.test_ldb_dc.delete(la_target)
        self._enable_all_repl(self.dnsname_dc2)

    def test_repl_get_tgt_multivalued_links(self):
        """Tests replication with multi-valued link attributes."""

        # create the target/source objects and link them together
        la_targets = self.create_object_range(0, 500, prefix="la_tgt")
        la_source = "CN=la_src,%s" % self.ou
        self.add_object(la_source, objectclass="msExchConfigurationContainer")

        for tgt in la_targets:
            self.modify_object(la_source, "addressBookRoots2", tgt)

        filler = self.create_object_range(0, 100, prefix="filler")

        # We should receive the objects/links in the following order:
        # [500 targets + 1 source][500 links][100 filler]
        expected_objects = la_targets + [la_source] + filler
        link_only_chunk = False

        # First do the replication without needing GET_TGT
        while not self.replication_complete():
            ctr6 = self.repl_get_next()

            if ctr6.object_count == 0 and ctr6.linked_attributes_count != 0:
                link_only_chunk = True

        # we should receive one chunk that contains only links
        self.assertTrue(link_only_chunk,
                        "Expected to receive a chunk containing only links")

        # check we received all the expected objects/links
        self.assert_expected_data(expected_objects)
        self.assert_expected_links([la_source], link_attr="addressBookRoots2", num_expected=500)

        # Do the replication again, forcing the use of GET_TGT this time
        self.init_test_state()

        for x in range(0, 500):
            self.modify_object(la_targets[x], "displayName", "OU-%d" % x)

        # The objects/links should get sent in the following order:
        # [1 source][500 targets][500 links][100 filler]

        while not self.replication_complete():
            ctr6 = self.repl_get_next()

        self.assertTrue(self.used_get_tgt,
                        "Test didn't use the GET_TGT flag as expected")

        # check we received all the expected objects/links
        self.assert_expected_data(expected_objects)
        self.assert_expected_links([la_source], link_attr="addressBookRoots2", num_expected=500)


class DcConnection:
    """Helper class to track a connection to another DC"""

    def __init__(self, drs_base, ldb_dc, dnsname_dc):
        self.ldb_dc = ldb_dc
        (self.drs, self.drs_handle) = drs_base._ds_bind(dnsname_dc)
        (self.default_hwm, self.default_utdv) = drs_base._get_highest_hwm_utdv(ldb_dc)


