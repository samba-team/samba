#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Tests various schema replication scenarios
#
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2011
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
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" $SUBUNITRUN replica_sync -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

import drs_base
import samba.tests

from ldb import (
    SCOPE_BASE)

class DrsReplicaSyncTestCase(drs_base.DrsBaseTestCase):
    """Intended as a black box test case for DsReplicaSync
       implementation. It should test the behavior of this
       case in cases when inbound replication is disabled"""

    def setUp(self):
        super(DrsReplicaSyncTestCase, self).setUp()

    def tearDown(self):
        # re-enable replication
        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        super(DrsReplicaSyncTestCase, self).tearDown()

    def test_ReplEnabled(self):
        """Tests we can replicate when replication is enabled"""
        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=False)

    def test_ReplDisabled(self):
        """Tests we cann't replicate when replication is disabled"""
        self._disable_inbound_repl(self.dnsname_dc1)
        try:
            self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=False)
        except samba.tests.BlackboxProcessError, e:
            self.assertTrue('WERR_DS_DRA_SINK_DISABLED' in e.stderr)
        else:
            self.fail("'drs replicate' command should have failed!")

    def test_ReplDisabledForced(self):
        """Tests we cann't replicate when replication is disabled"""
        self._disable_inbound_repl(self.dnsname_dc1)
        out = self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)

    def test_ReplLocal(self):
        """Tests we can replicate direct to the local db"""
        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=False, local=True, full_sync=True)

    def _create_ou(self, samdb, name):
        ldif = """
dn: %s,%s
objectClass: organizationalUnit
""" % (name, self.domain_dn)
        samdb.add_ldif(ldif)
        res = samdb.search(base="%s,%s" % (name, self.domain_dn),
                           scope=SCOPE_BASE, attrs=["objectGUID"])
        return self._GUID_string(res[0]["objectGUID"][0])

    def _check_deleted(self, sam_ldb, guid):
        # search the user by guid as it may be deleted
        expression = "(objectGUID=%s)" % guid
        res = sam_ldb.search(base=self.domain_dn,
                             expression=expression,
                             controls=["show_deleted:1"],
                             attrs=["isDeleted", "objectCategory", "ou"])
        self.assertEquals(len(res), 1)
        ou_cur = res[0]
        # Deleted Object base DN
        dodn = self._deleted_objects_dn(sam_ldb)
        # now check properties of the user
        name_cur  = ou_cur["ou"][0]
        self.assertEquals(ou_cur["isDeleted"][0],"TRUE")
        self.assertTrue(not("objectCategory" in ou_cur))
        self.assertTrue(dodn in str(ou_cur["dn"]),
                        "OU %s is deleted but it is not located under %s!" % (name_cur, dodn))

    def test_ReplConflictsFullSync(self):
        """Tests that objects created in conflict become conflict DNs (honour full sync override)"""
        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Create conflicting objects on DC1 and DC2, with DC1 object created first
        ou1 = self._create_ou(self.ldb_dc1, "OU=Test Full Sync")
        ou2 = self._create_ou(self.ldb_dc2, "OU=Test Full Sync")

        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, local=True, forced=True, full_sync=True)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Check that DC2 got the DC1 object, and one or other object was make into conflict
        res1 = self.ldb_dc2.search(base="<GUID=%s>" % ou1,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc2.search(base="<GUID=%s>" % ou2,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0]["name"][0]
        print res2[0]["name"][0]
        self.assertTrue('CNF:%s' % ou1 in str(res1[0]["name"][0]) or 'CNF:%s' % ou2 in str(res2[0]["name"][0]))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc2, self.domain_dn) not in str(res1[0].dn))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc2, self.domain_dn) not in str(res2[0].dn))

        # Delete both objects by GUID on DC1

        self.ldb_dc2.delete('<GUID=%s>' % ou1)
        self.ldb_dc2.delete('<GUID=%s>' % ou2)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=True)

        self._check_deleted(self.ldb_dc1, ou1)
        self._check_deleted(self.ldb_dc1, ou2)
        # Check deleted on DC2
        self._check_deleted(self.ldb_dc2, ou1)
        self._check_deleted(self.ldb_dc2, ou2)

    def test_ReplConflictsRemoteWin(self):
        """Tests that objects created in conflict become conflict DNs"""
        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Create conflicting objects on DC1 and DC2, with DC1 object created first
        ou1 = self._create_ou(self.ldb_dc1, "OU=Test Remote Conflict")
        ou2 = self._create_ou(self.ldb_dc2, "OU=Test Remote Conflict")

        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Check that DC2 got the DC1 object, and one or other object was make into conflict
        res1 = self.ldb_dc1.search(base="<GUID=%s>" % ou1,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc1.search(base="<GUID=%s>" % ou2,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0]["name"][0]
        print res2[0]["name"][0]
        self.assertTrue('CNF:%s' % ou1 in str(res1[0]["name"][0]) or 'CNF:%s' % ou2 in str(res2[0]["name"][0]))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res1[0].dn))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res2[0].dn))

        # Delete both objects by GUID on DC1

        self.ldb_dc1.delete('<GUID=%s>' % ou1)
        self.ldb_dc1.delete('<GUID=%s>' % ou2)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True, full_sync=False)

        self._check_deleted(self.ldb_dc1, ou1)
        self._check_deleted(self.ldb_dc1, ou2)
        # Check deleted on DC2
        self._check_deleted(self.ldb_dc2, ou1)
        self._check_deleted(self.ldb_dc2, ou2)

    def test_ReplConflictsLocalWin(self):
        """Tests that objects created in conflict become conflict DNs"""
        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Create conflicting objects on DC1 and DC2, with DC2 object created first
        ou2 = self._create_ou(self.ldb_dc2, "OU=Test Local Conflict")
        ou1 = self._create_ou(self.ldb_dc1, "OU=Test Local Conflict")

        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Check that DC2 got the DC1 object, and one or other object was make into conflict
        res1 = self.ldb_dc1.search(base="<GUID=%s>" % ou1,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc1.search(base="<GUID=%s>" % ou2,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0]["name"][0]
        print res2[0]["name"][0]
        self.assertTrue('CNF:%s' % ou1 in str(res1[0]["name"][0]) or 'CNF:%s' % ou2 in str(res2[0]["name"][0]))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res1[0].dn))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res2[0].dn))

        # Delete both objects by GUID on DC1

        self.ldb_dc1.delete('<GUID=%s>' % ou1)
        self.ldb_dc1.delete('<GUID=%s>' % ou2)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True, full_sync=False)

        self._check_deleted(self.ldb_dc1, ou1)
        self._check_deleted(self.ldb_dc1, ou2)
        # Check deleted on DC2
        self._check_deleted(self.ldb_dc2, ou1)
        self._check_deleted(self.ldb_dc2, ou2)

    def test_ReplConflictsRenameRemoteWin(self):
        """Tests that objects created in conflict become conflict DNs"""
        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Create conflicting objects on DC1 and DC2, with DC1 object created first
        ou1 = self._create_ou(self.ldb_dc1, "OU=Test Remote Rename Conflict")
        ou2 = self._create_ou(self.ldb_dc2, "OU=Test Remote Rename Conflict 2")

        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        self.ldb_dc1.rename("<GUID=%s>" % ou1, "OU=Test Remote Rename Conflict 3,%s" % self.domain_dn)
        self.ldb_dc2.rename("<GUID=%s>" % ou2, "OU=Test Remote Rename Conflict 3,%s" % self.domain_dn)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Check that DC2 got the DC1 object, and one or other object was make into conflict
        res1 = self.ldb_dc1.search(base="<GUID=%s>" % ou1,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc1.search(base="<GUID=%s>" % ou2,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0]["name"][0]
        print res2[0]["name"][0]
        self.assertTrue('CNF:%s' % ou1 in str(res1[0]["name"][0]) or 'CNF:%s' % ou2 in str(res2[0]["name"][0]))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res1[0].dn))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res2[0].dn))

        # Delete both objects by GUID on DC1

        self.ldb_dc1.delete('<GUID=%s>' % ou1)
        self.ldb_dc1.delete('<GUID=%s>' % ou2)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True, full_sync=False)

        self._check_deleted(self.ldb_dc1, ou1)
        self._check_deleted(self.ldb_dc1, ou2)
        # Check deleted on DC2
        self._check_deleted(self.ldb_dc2, ou1)
        self._check_deleted(self.ldb_dc2, ou2)

    def test_ReplConflictsRenameLocalWin(self):
        """Tests that objects created in conflict become conflict DNs"""
        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Create conflicting objects on DC1 and DC2, with DC1 object created first
        ou1 = self._create_ou(self.ldb_dc1, "OU=Test Rename Local Conflict")
        ou2 = self._create_ou(self.ldb_dc2, "OU=Test Rename Local Conflict 2")

        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        self.ldb_dc2.rename("<GUID=%s>" % ou2, "OU=Test Rename Local Conflict 3,%s" % self.domain_dn)
        self.ldb_dc1.rename("<GUID=%s>" % ou1, "OU=Test Rename Local Conflict 3,%s" % self.domain_dn)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Check that DC2 got the DC1 object, and one or other object was make into conflict
        res1 = self.ldb_dc1.search(base="<GUID=%s>" % ou1,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc1.search(base="<GUID=%s>" % ou2,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0]["name"][0]
        print res2[0]["name"][0]
        self.assertTrue('CNF:%s' % ou1 in str(res1[0]["name"][0]) or 'CNF:%s' % ou2 in str(res2[0]["name"][0]))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res1[0].dn))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res2[0].dn))

        # Delete both objects by GUID on DC1

        self.ldb_dc1.delete('<GUID=%s>' % ou1)
        self.ldb_dc1.delete('<GUID=%s>' % ou2)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True, full_sync=False)

        self._check_deleted(self.ldb_dc1, ou1)
        self._check_deleted(self.ldb_dc1, ou2)
        # Check deleted on DC2
        self._check_deleted(self.ldb_dc2, ou1)
        self._check_deleted(self.ldb_dc2, ou2)

    def test_ReplLostAndFound(self):
        """Tests that objects created under a OU deleted eleswhere end up in lostAndFound"""
        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Create two OUs on DC2
        ou1 = self._create_ou(self.ldb_dc2, "OU=Deleted parent")
        ou2 = self._create_ou(self.ldb_dc2, "OU=Deleted parent 2")

        # replicate them from DC2 to DC1
        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Delete both objects by GUID on DC1

        self.ldb_dc1.delete('<GUID=%s>' % ou1)
        self.ldb_dc1.delete('<GUID=%s>' % ou2)

        # Create children on DC2
        ou1_child = self._create_ou(self.ldb_dc2, "OU=Test Child,OU=Deleted parent")
        ou2_child = self._create_ou(self.ldb_dc2, "OU=Test Child,OU=Deleted parent 2")

        # Replicate from DC2
        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Check the sub-OUs are now in lostAndFound and the first one is a conflict DN

        # Check that DC2 got the DC1 object, and one or other object was make into conflict
        res1 = self.ldb_dc1.search(base="<GUID=%s>" % ou1_child,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc1.search(base="<GUID=%s>" % ou2_child,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0]["name"][0]
        print res2[0]["name"][0]
        self.assertTrue('CNF:%s' % ou1_child in str(res1[0]["name"][0]) or 'CNF:%s' % ou2_child in str(res2[0]["name"][0]))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) in str(res1[0].dn))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) in str(res2[0].dn))

        # Delete all objects by GUID on DC1

        self.ldb_dc1.delete('<GUID=%s>' % ou1_child)
        self.ldb_dc1.delete('<GUID=%s>' % ou2_child)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True, full_sync=False)


        # Check all deleted on DC1
        self._check_deleted(self.ldb_dc1, ou1)
        self._check_deleted(self.ldb_dc1, ou2)
        self._check_deleted(self.ldb_dc1, ou1_child)
        self._check_deleted(self.ldb_dc1, ou2_child)
        # Check all deleted on DC2
        self._check_deleted(self.ldb_dc2, ou1)
        self._check_deleted(self.ldb_dc2, ou2)
        self._check_deleted(self.ldb_dc2, ou1_child)
        self._check_deleted(self.ldb_dc2, ou2_child)
