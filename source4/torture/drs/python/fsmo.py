#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Unix SMB/CIFS implementation.
# Copyright (C) Anatoliy Atanasov <anatoliy.atanasov@postpath.com> 2010
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
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" $SUBUNITRUN fsmo -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

from __future__ import print_function
import sys
import time
import os

sys.path.insert(0, "bin/python")

from ldb import SCOPE_BASE

import drs_base


class DrsFsmoTestCase(drs_base.DrsBaseTestCase):

    def setUp(self):
        super(DrsFsmoTestCase, self).setUp()

        # we have to wait for the replication before we make the check
        self.fsmo_wait_max_time = 20
        self.fsmo_wait_sleep_time = 0.2

        # cache some of RootDSE props
        self.dsServiceName_dc1 = self.info_dc1["dsServiceName"][0]
        self.dsServiceName_dc2 = self.info_dc2["dsServiceName"][0]
        self.infrastructure_dn = "CN=Infrastructure," + self.domain_dn
        self.naming_dn = "CN=Partitions," + self.config_dn
        self.rid_dn = "CN=RID Manager$,CN=System," + self.domain_dn
        self.domain_dns_dn = (
            "CN=Infrastructure,DC=DomainDnsZones, %s" % self.domain_dn )
        self.forest_dns_dn = (
            "CN=Infrastructure,DC=ForestDnsZones, %s" % self.domain_dn )

    def tearDown(self):
        super(DrsFsmoTestCase, self).tearDown()

    def _net_fsmo_role_transfer(self, DC, role, noop=False):
        # make command line credentials string
        ccache_name = self.get_creds_ccache_name()
        cmd_line_auth = "--krb5-ccache=%s" % ccache_name
        (result, out, err) = self.runsubcmd("fsmo", "transfer",
                                            "--role=%s" % role,
                                            "-H", "ldap://%s:389" % DC,
                                            cmd_line_auth)

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        if not noop:
            self.assertTrue("FSMO transfer of '%s' role successful" % role in out)
        else:
            self.assertTrue("This DC already has the '%s' FSMO role" % role in out)

    def _wait_for_role_transfer(self, ldb_dc, role_dn, master):
        """Wait for role transfer for certain amount of time

        :return: (Result=True|False, CurrentMasterDnsName) tuple
        """
        cur_master = ''
        retries = int(self.fsmo_wait_max_time / self.fsmo_wait_sleep_time) + 1
        for i in range(0, retries):
            # check if master has been transfered
            res = ldb_dc.search(role_dn,
                                scope=SCOPE_BASE, attrs=["fSMORoleOwner"])
            assert len(res) == 1, "Only one fSMORoleOwner value expected!"
            cur_master = res[0]["fSMORoleOwner"][0]
            if master == cur_master:
                return (True, cur_master)
            # skip last sleep, if no need to wait anymore
            if i != (retries - 1):
                # wait a little bit before next retry
                time.sleep(self.fsmo_wait_sleep_time)
        return (False, cur_master)

    def _role_transfer(self, role, role_dn):
        """Triggers transfer of role from DC1 to DC2
           and vice versa so the role goes back to the original dc"""
        # dc2 gets the role from dc1
        print("Testing for %s role transfer from %s to %s" % (role, self.dnsname_dc1, self.dnsname_dc2))

        self._net_fsmo_role_transfer(DC=self.dnsname_dc2, role=role)
        # check if the role is transfered
        (res, master) = self._wait_for_role_transfer(ldb_dc=self.ldb_dc2,
                                                     role_dn=role_dn,
                                                     master=self.dsServiceName_dc2)
        self.assertTrue(res,
                        "Transferring %s role to %s has failed, master is: %s!" % (role, self.dsServiceName_dc2, master))

        # dc1 gets back the role from dc2
        print("Testing for %s role transfer from %s to %s" % (role, self.dnsname_dc2, self.dnsname_dc1))
        self._net_fsmo_role_transfer(DC=self.dnsname_dc1, role=role)
        # check if the role is transfered
        (res, master) = self._wait_for_role_transfer(ldb_dc=self.ldb_dc1,
                                                     role_dn=role_dn,
                                                     master=self.dsServiceName_dc1)
        self.assertTrue(res,
                        "Transferring %s role to %s has failed, master is: %s!" % (role, self.dsServiceName_dc1, master))

        # dc1 keeps the role
        print("Testing for no-op %s role transfer from %s to %s" % (role, self.dnsname_dc2, self.dnsname_dc1))
        self._net_fsmo_role_transfer(DC=self.dnsname_dc1, role=role, noop=True)
        # check if the role is transfered
        (res, master) = self._wait_for_role_transfer(ldb_dc=self.ldb_dc1,
                                                     role_dn=role_dn,
                                                     master=self.dsServiceName_dc1)
        self.assertTrue(res,
                        "Transferring %s role to %s has failed, master is: %s!" % (role, self.dsServiceName_dc1, master))

    def test_SchemaMasterTransfer(self):
        self._role_transfer(role="schema", role_dn=self.schema_dn)

    def test_InfrastructureMasterTransfer(self):
        self._role_transfer(role="infrastructure", role_dn=self.infrastructure_dn)

    def test_PDCMasterTransfer(self):
        self._role_transfer(role="pdc", role_dn=self.domain_dn)

    def test_RIDMasterTransfer(self):
        self._role_transfer(role="rid", role_dn=self.rid_dn)

    def test_NamingMasterTransfer(self):
        self._role_transfer(role="naming", role_dn=self.naming_dn)

    def test_DomainDnsZonesMasterTransfer(self):
        self._role_transfer(role="domaindns", role_dn=self.domain_dns_dn)

    def test_ForestDnsZonesMasterTransfer(self):
        self._role_transfer(role="forestdns", role_dn=self.forest_dns_dn)
