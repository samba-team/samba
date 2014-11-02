#!/usr/bin/env python
#
# Unit tests for sites manipulation in samba
# Copyright (C) Matthieu Patou <mat@matws.net> 2011
#
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


import optparse
import sys
sys.path.insert(0, "bin/python")
import samba

from samba.tests.subunitrun import TestProgram, SubunitOptions

import samba.getopt as options
from samba import sites
from samba.auth import system_session
from samba.samdb import SamDB
import samba.tests
from samba.dcerpc import security

parser = optparse.OptionParser("dirsync.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]
if not "://" in host:
    ldaphost = "ldap://%s" % host
    ldapshost = "ldaps://%s" % host
else:
    ldaphost = host
    start = host.rindex("://")
    host = host.lstrip(start+3)

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

#
# Tests start here
#

class SitesBaseTests(samba.tests.TestCase):

    def setUp(self):
        super(SitesBaseTests, self).setUp()
        self.ldb_admin = ldb
        self.base_dn = ldb.domain_dn()
        self.domain_sid = security.dom_sid(ldb.get_domain_sid())
        self.configuration_dn = self.ldb_admin.get_config_basedn().get_linearized()

    def get_user_dn(self, name):
        return "CN=%s,CN=Users,%s" % (name, self.base_dn)


#tests on sites
class SimpleSitesTests(SitesBaseTests):

    def test_create(self):
        """test creation of 1 site"""

        self.ldb_admin.transaction_start()
        ok = sites.create_site(self.ldb_admin, self.ldb_admin.get_config_basedn(),
                            "testsamba")
        self.ldb_admin.transaction_commit()

        self.assertRaises(sites.SiteAlreadyExistsException,
                            sites.create_site, self.ldb_admin, self.ldb_admin.get_config_basedn(),
                            "testsamba")

    def test_delete(self):
        """test removal of 1 site"""

        self.ldb_admin.transaction_start()
        ok = sites.delete_site(self.ldb_admin, self.ldb_admin.get_config_basedn(),
                            "testsamba")

        self.ldb_admin.transaction_commit()

        self.assertRaises(sites.SiteNotFoundException,
                            sites.delete_site, self.ldb_admin, self.ldb_admin.get_config_basedn(),
                            "testsamba")


    def test_delete_not_empty(self):
        """test removal of 1 site with servers"""

        self.assertRaises(sites.SiteServerNotEmptyException,
                            sites.delete_site, self.ldb_admin, self.ldb_admin.get_config_basedn(),
                            "Default-First-Site-Name")


ldb = SamDB(ldapshost, credentials=creds, session_info=system_session(lp), lp=lp)

TestProgram(module=__name__, opts=subunitopts)
