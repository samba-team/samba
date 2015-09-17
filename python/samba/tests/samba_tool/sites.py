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

import os
import ldb
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba import sites


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
        self.assertCmdSuccess(result)

        dnsites = ldb.Dn(self.samdb, "CN=Sites,%s" % self.config_dn)
        dnsite = ldb.Dn(self.samdb, "CN=%s,%s" % (sitename, dnsites))

        ret = self.samdb.search(base=dnsites, scope=ldb.SCOPE_ONELEVEL,
                                expression='(dn=%s)' % str(dnsite))
        self.assertEquals(len(ret), 1)

        # now delete it
        self.samdb.delete(dnsite, ["tree_delete:0"])
