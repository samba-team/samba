# Test that ldap referral entiries are created and formatted correctly
#
# Copyright (C) Andrew Bartlett 2019
#
# Based on Unit tests for the notification control
# Copyright (C) Stefan Metzmacher 2016
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

from __future__ import print_function
import optparse
import os
import sys

import samba
from samba.auth import system_session
import samba.getopt as options
from samba import ldb
from samba.samdb import SamDB
import samba.tests
from samba.tests.subunitrun import SubunitOptions

sys.path.insert(0, "bin/python")
parser = optparse.OptionParser("ldap_referrals.py [options]")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)
opts, args = parser.parse_args()

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)


class LdapReferralTest(samba.tests.TestCase):

    def setUp(self):
        super(LdapReferralTest, self).setUp()

    # The referral entries for an ldap request should have the ldap scheme
    # i.e. then should all start with "ldap://"
    def test_ldap_search(self):
        server = os.environ["SERVER"]
        url = "ldap://{0}".format(server)
        db = SamDB(
            url, credentials=creds, session_info=system_session(lp), lp=lp)
        res = db.search(
            base=db.domain_dn(),
            expression="(objectClass=nonexistent)",
            scope=ldb.SCOPE_SUBTREE,
            attrs=["objectGUID", "samAccountName"])

        referals = res.referals
        for referal in referals:
            self.assertTrue(
                referal.startswith("ldap://"),
                "{0} does not start with ldap://".format(referal))

    # The referral entries for an ldaps request should have the ldaps scheme
    # i.e. then should all start with "ldaps://"
    def test_ldaps_search(self):
        server = os.environ["SERVER"]
        url = "ldaps://{0}".format(server)
        db = SamDB(
            url, credentials=creds, session_info=system_session(lp), lp=lp)
        res = db.search(
            base=db.domain_dn(),
            expression="(objectClass=nonexistent)",
            scope=ldb.SCOPE_SUBTREE,
            attrs=["objectGUID", "samAccountName"])

        referals = res.referals
        for referal in referals:
            self.assertTrue(
                referal.startswith("ldaps://"),
                "{0} does not start with ldaps://".format(referal))
