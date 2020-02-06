# Blackbox tests for "samba-tool drs" command
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2011
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017
# Copyright (C) Catalyst.Net Ltd 2019
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

"""
Blackbox tests for samba-tool drs with no DNS partitions

Adapted from samba_tool_drs.py
"""

import samba.tests
import shutil
import os
import ldb
import drs_base

from samba.tests import BlackboxProcessError
from samba.compat import get_string


class SambaToolDrsNoDnsTests(drs_base.DrsBaseTestCase):
    """Blackbox test case for samba-tool drs."""

    def setUp(self):
        super(SambaToolDrsNoDnsTests, self).setUp()

        self.dc1 = samba.tests.env_get_var_value("DC1")

        creds = self.get_credentials()
        self.cmdline_creds = "-U%s/%s%%%s" % (creds.get_domain(),
                                              creds.get_username(), creds.get_password())

    def tearDown(self):
        self._enable_inbound_repl(self.dnsname_dc1)

        try:
            shutil.rmtree(os.path.join(self.tempdir, "private"))
            shutil.rmtree(os.path.join(self.tempdir, "etc"))
            shutil.rmtree(os.path.join(self.tempdir, "msg.lock"))
            os.remove(os.path.join(self.tempdir, "names.tdb"))
            shutil.rmtree(os.path.join(self.tempdir, "state"))
            shutil.rmtree(os.path.join(self.tempdir, "bind-dns"))
        except Exception:
            pass

        super(SambaToolDrsNoDnsTests, self).tearDown()

    def _get_rootDSE(self, dc, ldap_only=True):
        samdb = samba.tests.connect_samdb(dc, lp=self.get_loadparm(),
                                          credentials=self.get_credentials(),
                                          ldap_only=ldap_only)
        return samdb.search(base="", scope=samba.tests.ldb.SCOPE_BASE)[0], samdb

    def test_samba_tool_replicate_local_no_dns_tdb(self):
        self.backend = 'tdb'
        self._test_samba_tool_replicate_local_no_dns()

    def test_samba_tool_replicate_local_no_dns_mdb(self):
        self.backend = 'mdb'
        self._test_samba_tool_replicate_local_no_dns()

    def _test_samba_tool_replicate_local_no_dns(self):
        """Check we can provision a database without DNS partitions
        (and then add them afterwards)."""

        server_rootdse, _ = self._get_rootDSE(self.dc1)
        nc_name = server_rootdse["defaultNamingContext"]
        server_ldap_service_name = str(server_rootdse["ldapServiceName"][0])
        server_realm = server_ldap_service_name.split(":")[0]
        creds = self.get_credentials()

        # We have to give it a different netbiosname every time
        # it runs, otherwise the collision causes strange issues
        # to happen. This should be different on different environments.
        netbiosname = "dns" + self.backend + self.dc1
        if len(netbiosname) > 15:
            netbiosname = netbiosname[:15]

        out = self.check_output("samba-tool domain join %s dc --server=%s %s --targetdir=%s --option=netbiosname=%s %s --backend-store=%s"
                                % (server_realm, self.dc1, self.cmdline_creds,
                                   self.tempdir, netbiosname,
                                   "--dns-backend=NONE",
                                   self.backend))

        new_dc_config_file = os.path.join(self.tempdir, "etc", "smb.conf")
        new_dc_sam = os.path.join(self.tempdir, "private", "sam.ldb")

        forestdns_dn = ldb.binary_encode('DC=ForestDNSZones,' + str(nc_name))
        domaindns_dn = ldb.binary_encode('DC=DomainDNSZones,' + str(nc_name))

        self.check_output("samba-tool drs replicate --local %s %s %s %s -s %s --full-sync"
                          % ("invalid", self.dc1, forestdns_dn,
                             self.cmdline_creds, new_dc_config_file))

        self.check_output("samba-tool drs replicate --local %s %s %s %s -s %s --full-sync"
                          % ("invalid", self.dc1, domaindns_dn,
                             self.cmdline_creds, new_dc_config_file))

        server_rootdse, samdb = self._get_rootDSE("ldb://" + new_dc_sam, ldap_only=False)
        server_ds_name = ldb.binary_encode(server_rootdse["dsServiceName"][0].decode('utf-8'))

        # Show that Has-Master-NCs is fixed by samba_upgradedns
        res = samdb.search(base=server_ds_name,
                           expression="(msds-hasmasterncs=%s)" % forestdns_dn)
        self.assertEqual(len(res), 0)
        res = samdb.search(base=server_ds_name,
                           expression="(msds-hasmasterncs=%s)" % domaindns_dn)
        self.assertEqual(len(res), 0)

        self.check_output("samba_upgradedns -s %s" % (new_dc_config_file))

        res = samdb.search(base=server_ds_name,
                           expression="(msds-hasmasterncs=%s)" % forestdns_dn)
        self.assertEqual(len(res), 1)
        res = samdb.search(base=server_ds_name,
                           expression="(msds-hasmasterncs=%s)" % domaindns_dn)
        self.assertEqual(len(res), 1)

        # Show that replica locations is fixed by dbcheck
        res = samdb.search(controls=["search_options:1:2"],
                           expression="(&(msds-nc-replica-locations=%s)(ncname=%s))"
                           % (server_ds_name, forestdns_dn))
        self.assertEqual(len(res), 0)
        res = samdb.search(controls=["search_options:1:2"],
                           expression="(&(msds-nc-replica-locations=%s)(ncname=%s))"
                           % (server_ds_name, domaindns_dn))
        self.assertEqual(len(res), 0)

        try:
            # This fixes any forward-link-backward-link issues with the tools
            self.check_output("samba-tool dbcheck -s %s --cross-ncs --fix --yes" % (new_dc_config_file))
        except BlackboxProcessError as e:
            self.assertTrue("Checked " in get_string(e.stdout))

        self.check_output("samba-tool dbcheck -s %s --cross-ncs" % (new_dc_config_file))

        # Compare the two directories
        self.check_output("samba-tool ldapcmp ldap://%s ldb://%s %s --filter=%s" %
                          (self.dc1, new_dc_sam, self.cmdline_creds,
                           "msDs-masteredBy,msDS-NC-Replica-Locations,msDS-hasMasterNCs"))

        # Check all ForestDNS connections and backlinks
        res = samdb.search(base=server_ds_name,
                           expression="(msds-hasmasterncs=%s)" % forestdns_dn)
        self.assertEqual(len(res), 1)
        res = samdb.search(base=forestdns_dn,
                           expression="(msds-masteredby=%s)" % server_ds_name)
        self.assertEqual(len(res), 1)
        res = samdb.search(controls=["search_options:1:2"],
                           expression="(&(msds-nc-replica-locations=%s)(ncname=%s))"
                           % (server_ds_name, forestdns_dn))
        self.assertEqual(len(res), 1)

        # Check all DomainDNS connections and backlinks
        res = samdb.search(base=server_ds_name,
                           expression="(msds-hasmasterncs=%s)" % domaindns_dn)
        self.assertEqual(len(res), 1)
        res = samdb.search(base=domaindns_dn,
                           expression="(msds-masteredby=%s)" % server_ds_name)
        self.assertEqual(len(res), 1)
        res = samdb.search(controls=["search_options:1:2"],
                           expression="(&(msds-nc-replica-locations=%s)(ncname=%s))"
                           % (server_ds_name, domaindns_dn))
        self.assertEqual(len(res), 1)

        # Demote the DC we created in the test
        self.check_output("samba-tool domain demote --remove-other-dead-server=%s -H ldap://%s %s -s %s"
                          % (netbiosname, self.dc1, self.cmdline_creds, new_dc_config_file))
