#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Tests replication scenarios that involve conflicting linked attribute
# information between the 2 DCs.
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
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" $SUBUNITRUN \
#       link_conflicts -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

import drs_base
import samba.tests
import ldb
from ldb import SCOPE_BASE
import random
import time

from drs_base import AbstractLink
from samba.dcerpc import drsuapi, misc
from samba.dcerpc.drsuapi import DRSUAPI_EXOP_ERR_SUCCESS

# specifies the order to sync DCs in
DC1_TO_DC2 = 1
DC2_TO_DC1 = 2


class DrsReplicaLinkConflictTestCase(drs_base.DrsBaseTestCase):
    def setUp(self):
        super(DrsReplicaLinkConflictTestCase, self).setUp()

        self.ou = samba.tests.create_test_ou(self.ldb_dc1,
                                             "test_link_conflict")
        self.base_dn = self.ldb_dc1.get_default_basedn()

        (self.drs, self.drs_handle) = self._ds_bind(self.dnsname_dc1)
        (self.drs2, self.drs2_handle) = self._ds_bind(self.dnsname_dc2)

        # disable replication for the tests so we can control at what point
        # the DCs try to replicate
        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

    def tearDown(self):
        # re-enable replication
        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self.ldb_dc1.delete(self.ou, ["tree_delete:1"])
        super(DrsReplicaLinkConflictTestCase, self).tearDown()

    def get_guid(self, samdb, dn):
        """Returns an object's GUID (in string format)"""
        res = samdb.search(base=dn, attrs=["objectGUID"], scope=ldb.SCOPE_BASE)
        return self._GUID_string(res[0]['objectGUID'][0])

    def add_object(self, samdb, dn, objectclass="organizationalunit"):
        """Adds an object"""
        samdb.add({"dn": dn, "objectclass": objectclass})
        return self.get_guid(samdb, dn)

    def modify_object(self, samdb, dn, attr, value):
        """Modifies an attribute for an object"""
        m = ldb.Message()
        m.dn = ldb.Dn(samdb, dn)
        m[attr] = ldb.MessageElement(value, ldb.FLAG_MOD_ADD, attr)
        samdb.modify(m)

    def add_link_attr(self, samdb, source_dn, attr, target_dn):
        """Adds a linked attribute between 2 objects"""
        # add the specified attribute to the source object
        self.modify_object(samdb, source_dn, attr, target_dn)

    def del_link_attr(self, samdb, src, attr, target):
        m = ldb.Message()
        m.dn = ldb.Dn(samdb, src)
        m[attr] = ldb.MessageElement(target, ldb.FLAG_MOD_DELETE, attr)
        samdb.modify(m)

    def sync_DCs(self, sync_order=DC1_TO_DC2):
        """Manually syncs the 2 DCs to ensure they're in sync"""
        if sync_order == DC1_TO_DC2:
            # sync DC1-->DC2, then DC2-->DC1
            self._net_drs_replicate(DC=self.dnsname_dc2,
                                    fromDC=self.dnsname_dc1)
            self._net_drs_replicate(DC=self.dnsname_dc1,
                                    fromDC=self.dnsname_dc2)
        else:
            # sync DC2-->DC1, then DC1-->DC2
            self._net_drs_replicate(DC=self.dnsname_dc1,
                                    fromDC=self.dnsname_dc2)
            self._net_drs_replicate(DC=self.dnsname_dc2,
                                    fromDC=self.dnsname_dc1)

    def ensure_unique_timestamp(self):
        """Waits a second to ensure a unique timestamp between 2 objects"""
        time.sleep(1)

    def unique_dn(self, obj_name):
        """Returns a unique object DN"""
        # Because we run each test case twice, we need to create a unique DN so
        # that the 2nd run doesn't hit objects that already exist. Add some
        # randomness to the object DN to make it unique
        rand = random.randint(1, 10000000)
        return "%s-%d,%s" % (obj_name, rand, self.ou)

    def assert_attrs_match(self, res1, res2, attr, expected_count):
        """
        Asserts that the search results contain the expected number of
        attributes and the results match on both DCs
        """
        actual_len = len(res1[0][attr])
        self.assertTrue(actual_len == expected_count,
                        "Expected %u %s attributes, got %u" % (expected_count,
                                                               attr,
                                                               actual_len))
        actual_len = len(res2[0][attr])
        self.assertTrue(actual_len == expected_count,
                        "Expected %u %s attributes, got %u" % (expected_count,
                                                               attr,
                                                               actual_len))

        # check DCs both agree on the same linked attributes
        for val in res1[0][attr]:
            self.assertTrue(val in res2[0][attr],
                            "%s '%s' not found on DC2" % (attr, val))

    def zero_highwatermark(self):
        """Returns a zeroed highwatermark so that all DRS data gets returned"""
        hwm = drsuapi.DsReplicaHighWaterMark()
        hwm.tmp_highest_usn = 0
        hwm.reserved_usn = 0
        hwm.highest_usn = 0
        return hwm

    def _check_replicated_links(self, src_obj_dn, expected_links):
        """Checks that replication sends back the expected linked attributes"""
        self._check_replication([src_obj_dn],
                                drsuapi.DRSUAPI_DRS_WRIT_REP,
                                dest_dsa=None,
                                drs_error=drsuapi.DRSUAPI_EXOP_ERR_SUCCESS,
                                nc_dn_str=src_obj_dn,
                                exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                                expected_links=expected_links,
                                highwatermark=self.zero_highwatermark())

        # Check DC2 as well
        self.set_test_ldb_dc(self.ldb_dc2)

        self._check_replication([src_obj_dn],
                                drsuapi.DRSUAPI_DRS_WRIT_REP,
                                dest_dsa=None,
                                drs_error=drsuapi.DRSUAPI_EXOP_ERR_SUCCESS,
                                nc_dn_str=src_obj_dn,
                                exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                                expected_links=expected_links,
                                highwatermark=self.zero_highwatermark(),
                                drs=self.drs2, drs_handle=self.drs2_handle)
        self.set_test_ldb_dc(self.ldb_dc1)

    def _test_conflict_single_valued_link(self, sync_order):
        """
        Tests a simple single-value link conflict, i.e. each DC adds a link to
        the same source object but linking to different targets.
        """
        src_ou = self.unique_dn("OU=src")
        src_guid = self.add_object(self.ldb_dc1, src_ou)
        self.sync_DCs()

        # create a unique target on each DC
        target1_ou = self.unique_dn("OU=target1")
        target2_ou = self.unique_dn("OU=target2")

        target1_guid = self.add_object(self.ldb_dc1, target1_ou)
        target2_guid = self.add_object(self.ldb_dc2, target2_ou)

        # link the test OU to the respective targets created
        self.add_link_attr(self.ldb_dc1, src_ou, "managedBy", target1_ou)
        self.ensure_unique_timestamp()
        self.add_link_attr(self.ldb_dc2, src_ou, "managedBy", target2_ou)

        # sync the 2 DCs
        self.sync_DCs(sync_order=sync_order)

        res1 = self.ldb_dc1.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["managedBy"])
        res2 = self.ldb_dc2.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["managedBy"])

        # check the object has only have one occurence of the single-valued
        # attribute and it matches on both DCs
        self.assert_attrs_match(res1, res2, "managedBy", 1)

        self.assertTrue(str(res1[0]["managedBy"][0]) == target2_ou,
                        "Expected most recent update to win conflict")

        # we can't query the deleted links over LDAP, but we can check DRS
        # to make sure the DC kept a copy of the conflicting link
        link1 = AbstractLink(drsuapi.DRSUAPI_ATTID_managedBy, 0,
                             misc.GUID(src_guid), misc.GUID(target1_guid))
        link2 = AbstractLink(drsuapi.DRSUAPI_ATTID_managedBy,
                             drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE,
                             misc.GUID(src_guid), misc.GUID(target2_guid))
        self._check_replicated_links(src_ou, [link1, link2])

    def test_conflict_single_valued_link(self):
        # repeat the test twice, to give each DC a chance to resolve
        # the conflict
        self._test_conflict_single_valued_link(sync_order=DC1_TO_DC2)
        self._test_conflict_single_valued_link(sync_order=DC2_TO_DC1)

    def _test_duplicate_single_valued_link(self, sync_order):
        """
        Adds the same single-valued link on 2 DCs and checks we don't end up
        with 2 copies of the link.
        """
        # create unique objects for the link
        target_ou = self.unique_dn("OU=target")
        self.add_object(self.ldb_dc1, target_ou)
        src_ou = self.unique_dn("OU=src")
        src_guid = self.add_object(self.ldb_dc1, src_ou)
        self.sync_DCs()

        # link the same test OU to the same target on both DCs
        self.add_link_attr(self.ldb_dc1, src_ou, "managedBy", target_ou)
        self.ensure_unique_timestamp()
        self.add_link_attr(self.ldb_dc2, src_ou, "managedBy", target_ou)

        # sync the 2 DCs
        self.sync_DCs(sync_order=sync_order)

        res1 = self.ldb_dc1.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["managedBy"])
        res2 = self.ldb_dc2.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["managedBy"])

        # check the object has only have one occurence of the single-valued
        # attribute and it matches on both DCs
        self.assert_attrs_match(res1, res2, "managedBy", 1)

    def test_duplicate_single_valued_link(self):
        # repeat the test twice, to give each DC a chance to resolve
        # the conflict
        self._test_duplicate_single_valued_link(sync_order=DC1_TO_DC2)
        self._test_duplicate_single_valued_link(sync_order=DC2_TO_DC1)

    def _test_conflict_multi_valued_link(self, sync_order):
        """
        Tests a simple multi-valued link conflict. This adds 2 objects with the
        same username on 2 different DCs and checks their group membership is
        preserved after the conflict is resolved.
        """

        # create a common link source
        src_dn = self.unique_dn("CN=src")
        src_guid = self.add_object(self.ldb_dc1, src_dn, objectclass="group")
        self.sync_DCs()

        # create the same user (link target) on each DC.
        # Note that the GUIDs will differ between the DCs
        target_dn = self.unique_dn("CN=target")
        target1_guid = self.add_object(self.ldb_dc1, target_dn,
                                       objectclass="user")
        self.ensure_unique_timestamp()
        target2_guid = self.add_object(self.ldb_dc2, target_dn,
                                       objectclass="user")

        # link the src group to the respective target created
        self.add_link_attr(self.ldb_dc1, src_dn, "member", target_dn)
        self.ensure_unique_timestamp()
        self.add_link_attr(self.ldb_dc2, src_dn, "member", target_dn)

        # sync the 2 DCs. We expect the more recent target2 object to win
        self.sync_DCs(sync_order=sync_order)

        res1 = self.ldb_dc1.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["member"])
        res2 = self.ldb_dc2.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["member"])
        target1_conflict = False

        # we expect exactly 2 members in our test group (both DCs should agree)
        self.assert_attrs_match(res1, res2, "member", 2)

        for val in [str(val) for val in res1[0]["member"]]:
            # check the expected conflicting object was renamed
            self.assertFalse("CNF:%s" % target2_guid in val)
            if "CNF:%s" % target1_guid in val:
                target1_conflict = True

        self.assertTrue(target1_conflict,
                        "Expected link to conflicting target object not found")

    def test_conflict_multi_valued_link(self):
        # repeat the test twice, to give each DC a chance to resolve
        # the conflict
        self._test_conflict_multi_valued_link(sync_order=DC1_TO_DC2)
        self._test_conflict_multi_valued_link(sync_order=DC2_TO_DC1)

    def _test_duplicate_multi_valued_link(self, sync_order):
        """
        Adds the same multivalued link on 2 DCs and checks we don't end up
        with 2 copies of the link.
        """

        # create the link source/target objects
        src_dn = self.unique_dn("CN=src")
        src_guid = self.add_object(self.ldb_dc1, src_dn, objectclass="group")
        target_dn = self.unique_dn("CN=target")
        self.add_object(self.ldb_dc1, target_dn, objectclass="user")
        self.sync_DCs()

        # link the src group to the same target user separately on each DC
        self.add_link_attr(self.ldb_dc1, src_dn, "member", target_dn)
        self.ensure_unique_timestamp()
        self.add_link_attr(self.ldb_dc2, src_dn, "member", target_dn)

        self.sync_DCs(sync_order=sync_order)

        res1 = self.ldb_dc1.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["member"])
        res2 = self.ldb_dc2.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["member"])

        # we expect to still have only 1 member in our test group
        self.assert_attrs_match(res1, res2, "member", 1)

    def test_duplicate_multi_valued_link(self):
        # repeat the test twice, to give each DC a chance to resolve
        # the conflict
        self._test_duplicate_multi_valued_link(sync_order=DC1_TO_DC2)
        self._test_duplicate_multi_valued_link(sync_order=DC2_TO_DC1)

    def _test_conflict_backlinks(self, sync_order):
        """
        Tests that resolving a source object conflict fixes up any backlinks,
        e.g. the same user is added to a conflicting group.
        """

        # create a common link target
        target_dn = self.unique_dn("CN=target")
        target_guid = self.add_object(self.ldb_dc1, target_dn,
                                      objectclass="user")
        self.sync_DCs()

        # create the same group (link source) on each DC.
        # Note that the GUIDs will differ between the DCs
        src_dn = self.unique_dn("CN=src")
        src1_guid = self.add_object(self.ldb_dc1, src_dn, objectclass="group")
        self.ensure_unique_timestamp()
        src2_guid = self.add_object(self.ldb_dc2, src_dn, objectclass="group")

        # link the src group to the respective target created
        self.add_link_attr(self.ldb_dc1, src_dn, "member", target_dn)
        self.ensure_unique_timestamp()
        self.add_link_attr(self.ldb_dc2, src_dn, "member", target_dn)

        # sync the 2 DCs. We expect the more recent src2 object to win
        self.sync_DCs(sync_order=sync_order)

        res1 = self.ldb_dc1.search(base="<GUID=%s>" % target_guid,
                                   scope=SCOPE_BASE, attrs=["memberOf"])
        res2 = self.ldb_dc2.search(base="<GUID=%s>" % target_guid,
                                   scope=SCOPE_BASE, attrs=["memberOf"])
        src1_backlink = False

        # our test user should still be a member of 2 groups (check both
        # DCs agree)
        self.assert_attrs_match(res1, res2, "memberOf", 2)

        for val in [str(val) for val in res1[0]["memberOf"]]:
            # check the conflicting object was renamed
            self.assertFalse("CNF:%s" % src2_guid in val)
            if "CNF:%s" % src1_guid in val:
                src1_backlink = True

        self.assertTrue(src1_backlink,
                        "Backlink to conflicting source object not found")

    def test_conflict_backlinks(self):
        # repeat the test twice, to give each DC a chance to resolve
        # the conflict
        self._test_conflict_backlinks(sync_order=DC1_TO_DC2)
        self._test_conflict_backlinks(sync_order=DC2_TO_DC1)

    def _test_link_deletion_conflict(self, sync_order):
        """
        Checks that a deleted link conflicting with an active link is
        resolved correctly.
        """

        # Add the link objects
        target_dn = self.unique_dn("CN=target")
        self.add_object(self.ldb_dc1, target_dn, objectclass="user")
        src_dn = self.unique_dn("CN=src")
        src_guid = self.add_object(self.ldb_dc1, src_dn, objectclass="group")
        self.sync_DCs()

        # add the same link on both DCs, and resolve any conflict
        self.add_link_attr(self.ldb_dc2, src_dn, "member", target_dn)
        self.ensure_unique_timestamp()
        self.add_link_attr(self.ldb_dc1, src_dn, "member", target_dn)
        self.sync_DCs(sync_order=sync_order)

        # delete and re-add the link on one DC
        self.del_link_attr(self.ldb_dc1, src_dn, "member", target_dn)
        self.add_link_attr(self.ldb_dc1, src_dn, "member", target_dn)

        # just delete it on the other DC
        self.ensure_unique_timestamp()
        self.del_link_attr(self.ldb_dc2, src_dn, "member", target_dn)
        # sanity-check the link is gone on this DC
        res1 = self.ldb_dc2.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["member"])
        self.assertFalse("member" in res1[0], "Couldn't delete member attr")

        # sync the 2 DCs. We expect the more older DC1 attribute to win
        # because it has a higher version number (even though it's older)
        self.sync_DCs(sync_order=sync_order)

        res1 = self.ldb_dc1.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["member"])
        res2 = self.ldb_dc2.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["member"])

        # our test user should still be a member of the group (check both
        # DCs agree)
        self.assertTrue("member" in res1[0],
                        "Expected member attribute missing")
        self.assert_attrs_match(res1, res2, "member", 1)

    def test_link_deletion_conflict(self):
        # repeat the test twice, to give each DC a chance to resolve
        # the conflict
        self._test_link_deletion_conflict(sync_order=DC1_TO_DC2)
        self._test_link_deletion_conflict(sync_order=DC2_TO_DC1)

    def _test_obj_deletion_conflict(self, sync_order, del_target):
        """
        Checks that a receiving a new link for a deleted object gets
        resolved correctly.
        """

        target_dn = self.unique_dn("CN=target")
        target_guid = self.add_object(self.ldb_dc1, target_dn,
                                      objectclass="user")
        src_dn = self.unique_dn("CN=src")
        src_guid = self.add_object(self.ldb_dc1, src_dn, objectclass="group")

        self.sync_DCs()

        # delete the object on one DC
        if del_target:
            search_guid = src_guid
            self.ldb_dc2.delete(target_dn)
        else:
            search_guid = target_guid
            self.ldb_dc2.delete(src_dn)

        # add a link on the other DC
        self.ensure_unique_timestamp()
        self.add_link_attr(self.ldb_dc1, src_dn, "member", target_dn)

        self.sync_DCs(sync_order=sync_order)

        # the object deletion should trump the link addition.
        # Check the link no longer exists on the remaining object
        res1 = self.ldb_dc1.search(base="<GUID=%s>" % search_guid,
                                   scope=SCOPE_BASE,
                                   attrs=["member", "memberOf"])
        res2 = self.ldb_dc2.search(base="<GUID=%s>" % search_guid,
                                   scope=SCOPE_BASE,
                                   attrs=["member", "memberOf"])

        self.assertFalse("member" in res1[0], "member attr shouldn't exist")
        self.assertFalse("member" in res2[0], "member attr shouldn't exist")
        self.assertFalse("memberOf" in res1[0], "member attr shouldn't exist")
        self.assertFalse("memberOf" in res2[0], "member attr shouldn't exist")

    def test_obj_deletion_conflict(self):
        # repeat the test twice, to give each DC a chance to resolve
        # the conflict
        self._test_obj_deletion_conflict(sync_order=DC1_TO_DC2,
                                         del_target=True)
        self._test_obj_deletion_conflict(sync_order=DC2_TO_DC1,
                                         del_target=True)

        # and also try deleting the source object instead of the link target
        self._test_obj_deletion_conflict(sync_order=DC1_TO_DC2,
                                         del_target=False)
        self._test_obj_deletion_conflict(sync_order=DC2_TO_DC1,
                                         del_target=False)

    def _test_full_sync_link_conflict(self, sync_order):
        """
        Checks that doing a full sync doesn't affect how conflicts get resolved
        """

        # create the objects for the linked attribute
        src_dn = self.unique_dn("CN=src")
        src_guid = self.add_object(self.ldb_dc1, src_dn, objectclass="group")
        target_dn = self.unique_dn("CN=target")
        self.add_object(self.ldb_dc1, target_dn, objectclass="user")
        self.sync_DCs()

        # add the same link on both DCs
        self.add_link_attr(self.ldb_dc2, src_dn, "member", target_dn)
        self.ensure_unique_timestamp()
        self.add_link_attr(self.ldb_dc1, src_dn, "member", target_dn)

        # Do a couple of full syncs which should resolve the conflict
        # (but only for one DC)
        if sync_order == DC1_TO_DC2:
            self._net_drs_replicate(DC=self.dnsname_dc2,
                                    fromDC=self.dnsname_dc1,
                                    full_sync=True)
            self._net_drs_replicate(DC=self.dnsname_dc2,
                                    fromDC=self.dnsname_dc1,
                                    full_sync=True)
        else:
            self._net_drs_replicate(DC=self.dnsname_dc1,
                                    fromDC=self.dnsname_dc2,
                                    full_sync=True)
            self._net_drs_replicate(DC=self.dnsname_dc1,
                                    fromDC=self.dnsname_dc2,
                                    full_sync=True)

        # delete and re-add the link on one DC
        self.del_link_attr(self.ldb_dc1, src_dn, "member", target_dn)
        self.ensure_unique_timestamp()
        self.add_link_attr(self.ldb_dc1, src_dn, "member", target_dn)

        # just delete the link on the 2nd DC
        self.ensure_unique_timestamp()
        self.del_link_attr(self.ldb_dc2, src_dn, "member", target_dn)

        # sync the 2 DCs. We expect DC1 to win based on version number
        self.sync_DCs(sync_order=sync_order)

        res1 = self.ldb_dc1.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["member"])
        res2 = self.ldb_dc2.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["member"])

        # check the membership still exits (and both DCs agree)
        self.assertTrue("member" in res1[0],
                        "Expected member attribute missing")
        self.assert_attrs_match(res1, res2, "member", 1)

    def test_full_sync_link_conflict(self):
        # repeat the test twice, to give each DC a chance to resolve
        # the conflict
        self._test_full_sync_link_conflict(sync_order=DC1_TO_DC2)
        self._test_full_sync_link_conflict(sync_order=DC2_TO_DC1)

    def _singleval_link_conflict_deleted_winner(self, sync_order):
        """
        Tests a single-value link conflict where the more-up-to-date link value
        is deleted.
        """
        src_ou = self.unique_dn("OU=src")
        src_guid = self.add_object(self.ldb_dc1, src_ou)
        self.sync_DCs()

        # create a unique target on each DC
        target1_ou = self.unique_dn("OU=target1")
        target2_ou = self.unique_dn("OU=target2")

        target1_guid = self.add_object(self.ldb_dc1, target1_ou)
        target2_guid = self.add_object(self.ldb_dc2, target2_ou)

        # add the links for the respective targets, and delete one of the links
        self.add_link_attr(self.ldb_dc1, src_ou, "managedBy", target1_ou)
        self.add_link_attr(self.ldb_dc2, src_ou, "managedBy", target2_ou)
        self.ensure_unique_timestamp()
        self.del_link_attr(self.ldb_dc1, src_ou, "managedBy", target1_ou)

        # sync the 2 DCs
        self.sync_DCs(sync_order=sync_order)

        res1 = self.ldb_dc1.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["managedBy"])
        res2 = self.ldb_dc2.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["managedBy"])

        # Although the more up-to-date link value is deleted, this shouldn't
        # trump DC1's active link
        self.assert_attrs_match(res1, res2, "managedBy", 1)

        self.assertTrue(str(res1[0]["managedBy"][0]) == target2_ou,
                        "Expected active link win conflict")

        # we can't query the deleted links over LDAP, but we can check that
        # the deleted links exist using DRS
        link1 = AbstractLink(drsuapi.DRSUAPI_ATTID_managedBy, 0,
                             misc.GUID(src_guid), misc.GUID(target1_guid))
        link2 = AbstractLink(drsuapi.DRSUAPI_ATTID_managedBy,
                             drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE,
                             misc.GUID(src_guid), misc.GUID(target2_guid))
        self._check_replicated_links(src_ou, [link1, link2])

    def test_conflict_single_valued_link_deleted_winner(self):
        # repeat the test twice, to give each DC a chance to resolve
        # the conflict
        self._singleval_link_conflict_deleted_winner(sync_order=DC1_TO_DC2)
        self._singleval_link_conflict_deleted_winner(sync_order=DC2_TO_DC1)

    def _singleval_link_conflict_deleted_loser(self, sync_order):
        """
        Tests a single-valued link conflict, where the losing link value is
        deleted.
        """
        src_ou = self.unique_dn("OU=src")
        src_guid = self.add_object(self.ldb_dc1, src_ou)
        self.sync_DCs()

        # create a unique target on each DC
        target1_ou = self.unique_dn("OU=target1")
        target2_ou = self.unique_dn("OU=target2")

        target1_guid = self.add_object(self.ldb_dc1, target1_ou)
        target2_guid = self.add_object(self.ldb_dc2, target2_ou)

        # add the links - we want the link to end up deleted on DC2, but active
        # on DC1. DC1 has the better version and DC2 has the better timestamp -
        # the better version should win
        self.add_link_attr(self.ldb_dc1, src_ou, "managedBy", target1_ou)
        self.del_link_attr(self.ldb_dc1, src_ou, "managedBy", target1_ou)
        self.add_link_attr(self.ldb_dc1, src_ou, "managedBy", target1_ou)
        self.ensure_unique_timestamp()
        self.add_link_attr(self.ldb_dc2, src_ou, "managedBy", target2_ou)
        self.del_link_attr(self.ldb_dc2, src_ou, "managedBy", target2_ou)

        self.sync_DCs(sync_order=sync_order)

        res1 = self.ldb_dc1.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["managedBy"])
        res2 = self.ldb_dc2.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["managedBy"])

        # check the object has only have one occurence of the single-valued
        # attribute and it matches on both DCs
        self.assert_attrs_match(res1, res2, "managedBy", 1)

        self.assertTrue(str(res1[0]["managedBy"][0]) == target1_ou,
                        "Expected most recent update to win conflict")

        # we can't query the deleted links over LDAP, but we can check DRS
        # to make sure the DC kept a copy of the conflicting link
        link1 = AbstractLink(drsuapi.DRSUAPI_ATTID_managedBy,
                             drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE,
                             misc.GUID(src_guid), misc.GUID(target1_guid))
        link2 = AbstractLink(drsuapi.DRSUAPI_ATTID_managedBy, 0,
                             misc.GUID(src_guid), misc.GUID(target2_guid))
        self._check_replicated_links(src_ou, [link1, link2])

    def test_conflict_single_valued_link_deleted_loser(self):
        # repeat the test twice, to give each DC a chance to resolve
        # the conflict
        self._singleval_link_conflict_deleted_loser(sync_order=DC1_TO_DC2)
        self._singleval_link_conflict_deleted_loser(sync_order=DC2_TO_DC1)

    def _test_conflict_existing_single_valued_link(self, sync_order):
        """
        Tests a single-valued link conflict, where the conflicting link value
        already exists (as inactive) on both DCs.
        """
        # create the link objects
        src_ou = self.unique_dn("OU=src")
        src_guid = self.add_object(self.ldb_dc1, src_ou)

        target1_ou = self.unique_dn("OU=target1")
        target2_ou = self.unique_dn("OU=target2")
        target1_guid = self.add_object(self.ldb_dc1, target1_ou)
        target2_guid = self.add_object(self.ldb_dc1, target2_ou)

        # add the links, but then delete them
        self.add_link_attr(self.ldb_dc1, src_ou, "managedBy", target1_ou)
        self.del_link_attr(self.ldb_dc1, src_ou, "managedBy", target1_ou)
        self.add_link_attr(self.ldb_dc1, src_ou, "managedBy", target2_ou)
        self.del_link_attr(self.ldb_dc1, src_ou, "managedBy", target2_ou)
        self.sync_DCs()

        # re-add the links independently on each DC
        self.add_link_attr(self.ldb_dc1, src_ou, "managedBy", target1_ou)
        self.ensure_unique_timestamp()
        self.add_link_attr(self.ldb_dc2, src_ou, "managedBy", target2_ou)

        # try to sync the 2 DCs
        self.sync_DCs(sync_order=sync_order)

        res1 = self.ldb_dc1.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["managedBy"])
        res2 = self.ldb_dc2.search(base="<GUID=%s>" % src_guid,
                                   scope=SCOPE_BASE, attrs=["managedBy"])

        # check the object has only have one occurence of the single-valued
        # attribute and it matches on both DCs
        self.assert_attrs_match(res1, res2, "managedBy", 1)

        # here we expect DC2 to win because it has the more recent link
        self.assertTrue(str(res1[0]["managedBy"][0]) == target2_ou,
                        "Expected most recent update to win conflict")

        # we can't query the deleted links over LDAP, but we can check DRS
        # to make sure the DC kept a copy of the conflicting link
        link1 = AbstractLink(drsuapi.DRSUAPI_ATTID_managedBy, 0,
                             misc.GUID(src_guid), misc.GUID(target1_guid))
        link2 = AbstractLink(drsuapi.DRSUAPI_ATTID_managedBy,
                             drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE,
                             misc.GUID(src_guid), misc.GUID(target2_guid))
        self._check_replicated_links(src_ou, [link1, link2])

    def test_conflict_existing_single_valued_link(self):
        # repeat the test twice, to give each DC a chance to resolve
        # the conflict
        self._test_conflict_existing_single_valued_link(sync_order=DC1_TO_DC2)
        self._test_conflict_existing_single_valued_link(sync_order=DC2_TO_DC1)

    def test_link_attr_version(self):
        """
        Checks the link attribute version starts from the correct value
        """
        # create some objects and add a link
        src_ou = self.unique_dn("OU=src")
        self.add_object(self.ldb_dc1, src_ou)
        target1_ou = self.unique_dn("OU=target1")
        self.add_object(self.ldb_dc1, target1_ou)
        self.add_link_attr(self.ldb_dc1, src_ou, "managedBy", target1_ou)

        # get the link info via replication
        ctr6 = self._get_replication(drsuapi.DRSUAPI_DRS_WRIT_REP,
                                     dest_dsa=None,
                                     drs_error=DRSUAPI_EXOP_ERR_SUCCESS,
                                     exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                                     highwatermark=self.zero_highwatermark(),
                                     nc_dn_str=src_ou)

        self.assertTrue(ctr6.linked_attributes_count == 1,
                        "DRS didn't return a link")
        link = ctr6.linked_attributes[0]
        rcvd_version = link.meta_data.version
        self.assertTrue(rcvd_version == 1,
                        "Link version started from %u, not 1" % rcvd_version)
