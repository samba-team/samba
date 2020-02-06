#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Test conflict scenarios on the RODC
#
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2011
# Copyright (C) Catalyst.NET Ltd 2018
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
#  export DC2=dc2_dns_name (RODC)
#  export SUBUNITRUN=$samba4srcdir/scripting/bin/subunitrun
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" $SUBUNITRUN replica_sync_rodc -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

import drs_base
import samba.tests
import time
import ldb
from samba.compat import get_string

from ldb import (
    SCOPE_BASE, LdbError, ERR_NO_SUCH_OBJECT)


class DrsReplicaSyncTestCase(drs_base.DrsBaseTestCase):
    """Intended as a black box test case for DsReplicaSync
       implementation. It should test the behavior of this
       case in cases when inbound replication is disabled"""

    def setUp(self):
        super(DrsReplicaSyncTestCase, self).setUp()
        self._disable_all_repl(self.dnsname_dc1)
        self.ou1 = None
        self.ou2 = None

    def tearDown(self):
        # re-enable replication
        self._enable_all_repl(self.dnsname_dc1)

        super(DrsReplicaSyncTestCase, self).tearDown()

    def _create_ou(self, samdb, name):
        ldif = """
dn: %s,%s
objectClass: organizationalUnit
""" % (name, self.domain_dn)
        samdb.add_ldif(ldif)
        res = samdb.search(base="%s,%s" % (name, self.domain_dn),
                           scope=SCOPE_BASE, attrs=["objectGUID"])
        return get_string(self._GUID_string(res[0]["objectGUID"][0]))

    def _check_deleted(self, sam_ldb, guid):
        # search the user by guid as it may be deleted
        res = sam_ldb.search(base='<GUID=%s>' % guid,
                             controls=["show_deleted:1"],
                             attrs=["isDeleted", "objectCategory", "ou"])
        self.assertEqual(len(res), 1)
        ou_cur = res[0]
        # Deleted Object base DN
        dodn = self._deleted_objects_dn(sam_ldb)
        # now check properties of the user
        name_cur = ou_cur["ou"][0]
        self.assertEqual(ou_cur["isDeleted"][0], "TRUE")
        self.assertTrue(not("objectCategory" in ou_cur))
        self.assertTrue(dodn in str(ou_cur["dn"]),
                        "OU %s is deleted but it is not located under %s!" % (name_cur, dodn))

    def test_ReplConflictsRODC(self):
        """Tests that objects created in conflict become conflict DNs"""
        # Replicate all objects to RODC beforehand
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        # Create conflicting objects on DC1 and DC2, with DC1 object created first
        name = "OU=Test RODC Conflict"
        self.ou1 = self._create_ou(self.ldb_dc1, name)

        # Replicate single object
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1,
                                nc_dn="%s,%s" % (name, self.domain_dn),
                                local=True, single=True, forced=True)

        # Delete the object, so another can be added
        self.ldb_dc1.delete('<GUID=%s>' % self.ou1)

        # Create a conflicting DN as it would appear to the RODC
        self.ou2 = self._create_ou(self.ldb_dc1, name)

        try:
            self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1,
                                    nc_dn="%s,%s" % (name, self.domain_dn),
                                    local=True, single=True, forced=True)
        except:
            # Cleanup the object
            self.ldb_dc1.delete('<GUID=%s>' % self.ou2)
            return

        # Replicate cannot succeed, HWM would be updated incorrectly.
        self.fail("DRS replicate should have failed.")

    def test_ReplConflictsRODCRename(self):
        """Tests that objects created in conflict become conflict DNs"""
        # Replicate all objects to RODC beforehand
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        # Create conflicting objects on DC1 and DC2, with DC1 object created first
        name = "OU=Test RODC Rename Conflict"
        self.ou1 = self._create_ou(self.ldb_dc1, name)

        # Replicate single object
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1,
                                nc_dn="%s,%s" % (name, self.domain_dn),
                                local=True, single=True, forced=True)

        # Create a non-conflicting DN to rename as conflicting
        free_name = "OU=Test RODC Rename No Conflict"
        self.ou2 = self._create_ou(self.ldb_dc1, free_name)

        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1,
                                nc_dn="%s,%s" % (free_name, self.domain_dn),
                                local=True, single=True, forced=True)

        # Delete the object, so we can rename freely
        # DO NOT REPLICATE TO THE RODC
        self.ldb_dc1.delete('<GUID=%s>' % self.ou1)

        # Collide the name from the RODC perspective
        self.ldb_dc1.rename("<GUID=%s>" % self.ou2, "%s,%s" % (name, self.domain_dn))

        try:
            self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1,
                                    nc_dn="%s,%s" % (name, self.domain_dn),
                                    local=True, single=True, forced=True)
        except:
            # Cleanup the object
            self.ldb_dc1.delete('<GUID=%s>' % self.ou2)
            return

        # Replicate cannot succeed, HWM would be updated incorrectly.
        self.fail("DRS replicate should have failed.")
