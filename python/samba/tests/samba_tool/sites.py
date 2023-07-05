# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst.Net LTD 2015
# Copyright (C) Sean Dague <sdague@linux.vnet.ibm.com> 2011
#
# Catalyst.Net's contribution was written by Douglas Bagnall
# <douglas.bagnall@catalyst.net.nz>.
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

import json
import os
import ldb
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba import sites, subnets


class BaseSitesCmdTestCase(SambaToolCmdTest):
    """Tests for samba-tool sites subnets"""
    def setUp(self):
        super(BaseSitesCmdTestCase, self).setUp()
        self.dburl = "ldap://%s" % os.environ["DC_SERVER"]
        self.creds_string = "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                          os.environ["DC_PASSWORD"])

        self.samdb = self.getSamDB("-H", self.dburl, self.creds_string)
        self.config_dn = str(self.samdb.get_config_basedn())


class SitesCmdTestCase(BaseSitesCmdTestCase):

    def test_site_create(self):
        sitename = 'new_site'

        result, out, err = self.runsubcmd("sites", "create", sitename,
                                          "-H", self.dburl, self.creds_string)
        self.assertCmdSuccess(result, out, err)

        dnsites = ldb.Dn(self.samdb, "CN=Sites,%s" % self.config_dn)
        dnsite = ldb.Dn(self.samdb, "CN=%s,%s" % (sitename, dnsites))

        ret = self.samdb.search(base=dnsites, scope=ldb.SCOPE_ONELEVEL,
                                expression='(cn=%s)' % sitename)
        self.assertEqual(len(ret), 1)

        # now delete it
        self.samdb.delete(dnsite, ["tree_delete:0"])

    def test_site_list(self):
        result, out, err = self.runsubcmd("sites", "list",
                                          "-H", self.dburl, self.creds_string)
        self.assertCmdSuccess(result, out, err)
        self.assertIn("Default-First-Site-Name", out)

        # The same but with --json
        result, out, err = self.runsubcmd("sites", "list", "--json",
                                          "-H", self.dburl, self.creds_string)
        self.assertCmdSuccess(result, out, err)
        json_data = json.loads(out)
        self.assertIn("Default-First-Site-Name", json_data)

    def test_site_view(self):
        result, out, err = self.runsubcmd("sites", "view",
                                          "Default-First-Site-Name",
                                          "-H", self.dburl, self.creds_string)
        self.assertCmdSuccess(result, out, err)
        json_data = json.loads(out)
        self.assertEqual(json_data["cn"], "Default-First-Site-Name")

        # Now try one that doesn't exist
        result, out, err = self.runsubcmd("sites", "view",
                                          "Does-Not-Exist",
                                          "-H", self.dburl, self.creds_string)
        self.assertCmdFail(result, err)


class SitesSubnetCmdTestCase(BaseSitesCmdTestCase):
    def setUp(self):
        super(SitesSubnetCmdTestCase, self).setUp()
        self.sitename = "testsite"
        self.sitename2 = "testsite2"
        self.samdb.transaction_start()
        sites.create_site(self.samdb, self.config_dn, self.sitename)
        sites.create_site(self.samdb, self.config_dn, self.sitename2)
        self.samdb.transaction_commit()

    def tearDown(self):
        self.samdb.transaction_start()
        sites.delete_site(self.samdb, self.config_dn, self.sitename)
        sites.delete_site(self.samdb, self.config_dn, self.sitename2)
        self.samdb.transaction_commit()
        super(SitesSubnetCmdTestCase, self).tearDown()

    def test_site_subnet_create(self):
        cidrs = (("10.9.8.0/24", self.sitename),
                 ("50.60.0.0/16", self.sitename2),
                 ("50.61.0.0/16", self.sitename2),  # second subnet on the site
                 ("50.0.0.0/8", self.sitename),  # overlapping subnet, other site
                 ("50.62.1.2/32", self.sitename),  # single IP
                 ("aaaa:bbbb:cccc:dddd:eeee:ffff:2222:1100/120",
                  self.sitename2),
                 )

        for cidr, sitename in cidrs:
            result, out, err = self.runsubcmd("sites", "subnet", "create",
                                              cidr, sitename,
                                              "-H", self.dburl,
                                              self.creds_string)
            self.assertCmdSuccess(result, out, err)

            ret = self.samdb.search(base=self.config_dn,
                                    scope=ldb.SCOPE_SUBTREE,
                                    expression=('(&(objectclass=subnet)(cn=%s))'
                                                % cidr))
            self.assertIsNotNone(ret)
            self.assertEqual(len(ret), 1)

        dnsubnets = ldb.Dn(self.samdb,
                           "CN=Subnets,CN=Sites,%s" % self.config_dn)

        for cidr, sitename in cidrs:
            dnsubnet = ldb.Dn(self.samdb, ("Cn=%s,CN=Subnets,CN=Sites,%s" %
                                           (cidr, self.config_dn)))

            ret = self.samdb.search(base=dnsubnets, scope=ldb.SCOPE_ONELEVEL,
                                    expression='(CN=%s)' % cidr)
            self.assertIsNotNone(ret)
            self.assertEqual(len(ret), 1)
            self.samdb.delete(dnsubnet, ["tree_delete:0"])

    def test_site_subnet_create_should_fail(self):
        cidrs = (("10.9.8.0/33", self.sitename),    # mask too big
                 ("50.60.0.0/8", self.sitename2),   # insufficient zeros
                 ("50.261.0.0/16", self.sitename2),  # bad octet
                 ("7.0.0.0.0/0", self.sitename),    # insufficient zeros
                 ("aaaa:bbbb:cccc:dddd:eeee:ffff:2222:1100/119",
                  self.sitename),                   # insufficient zeros
                 )

        for cidr, sitename in cidrs:
            result, out, err = self.runsubcmd("sites", "subnet", "create",
                                              cidr, sitename,
                                              "-H", self.dburl,
                                              self.creds_string)
            self.assertCmdFail(result)

            ret = self.samdb.search(base=self.config_dn,
                                    scope=ldb.SCOPE_SUBTREE,
                                    expression=('(&(objectclass=subnet)(cn=%s))'
                                                % cidr))

            self.assertIsNotNone(ret)
            self.assertEqual(len(ret), 0)

    def test_site_subnet_list(self):
        subnet = "10.9.8.0/24"
        subnets.create_subnet(self.samdb, self.samdb.get_config_basedn(),
                              subnet, self.sitename)

        # cleanup after test
        dnsubnet = ldb.Dn(self.samdb, ("CN=%s,CN=Subnets,CN=Sites,%s" %
                                       (subnet, self.config_dn)))
        self.addCleanup(self.samdb.delete, dnsubnet, ["tree_delete:1"])

        result, out, err = self.runsubcmd("sites", "subnet", "list",
                                          self.sitename,
                                          "-H", self.dburl, self.creds_string)

        self.assertCmdSuccess(result, out, err)
        self.assertIn(subnet, out)

    def test_site_subnet_view(self):
        subnet = "50.60.0.0/16"
        subnets.create_subnet(self.samdb, self.samdb.get_config_basedn(),
                              subnet, self.sitename2)

        # cleanup after test
        dnsubnet = ldb.Dn(self.samdb, ("CN=%s,CN=Subnets,CN=Sites,%s" %
                                       (subnet, self.config_dn)))
        self.addCleanup(self.samdb.delete, dnsubnet, ["tree_delete:1"])

        result, out, err = self.runsubcmd("sites", "subnet",
                                          "view", subnet,
                                          "-H", self.dburl, self.creds_string)

        self.assertCmdSuccess(result, out, err)
        json_data = json.loads(out)
        self.assertEqual(json_data["cn"], subnet)

        # Now try one that doesn't exist
        result, out, err = self.runsubcmd("sites", "subnet",
                                          "view", "50.0.0.0/8",
                                          "-H", self.dburl, self.creds_string)
        self.assertCmdFail(result, err)
