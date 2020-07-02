#!/usr/bin/env python3
#
# Test ASQ LDAP control behaviour in Samba
# Copyright (C) Andrew Bartlett 2019-2020
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

import optparse
import sys
import os
import random

sys.path.insert(0, "bin/python")
import samba
from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

from samba.auth import system_session
from samba import ldb
from samba.samdb import SamDB
from samba.ndr import ndr_unpack
from samba import gensec
from samba.credentials import Credentials
import samba.tests

from ldb import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE, LdbError
from ldb import ERR_TIME_LIMIT_EXCEEDED, ERR_ADMIN_LIMIT_EXCEEDED, ERR_UNWILLING_TO_PERFORM
from ldb import Message

parser = optparse.OptionParser("large_ldap.py [options] <host>")
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

url = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)


class ASQLDAPTest(samba.tests.TestCase):

    def setUp(self):
        super(ASQLDAPTest, self).setUp()
        self.ldb = samba.Ldb(url, credentials=creds, session_info=system_session(lp), lp=lp)
        self.base_dn = self.ldb.get_default_basedn()
        self.NAME_ASQ="asq_" + format(random.randint(0, 99999), "05")
        self.OU_NAME_ASQ= self.NAME_ASQ + "_ou"
        self.ou_dn = ldb.Dn(self.ldb, "ou=" + self.OU_NAME_ASQ + "," + str(self.base_dn))

        samba.tests.delete_force(self.ldb, self.ou_dn,
                                 controls=['tree_delete:1'])

        self.ldb.add({
            "dn": self.ou_dn,
            "objectclass": "organizationalUnit",
            "ou": self.OU_NAME_ASQ})

        self.members = []
        self.members2 = []

        for x in range(20):
            name = self.NAME_ASQ + "_" + str(x)
            dn = ldb.Dn(self.ldb,
                        "cn=" + name + "," + str(self.ou_dn))
            self.members.append(dn)
            self.ldb.add({
                "dn": dn,
                "objectclass": "group"})

        for x in range(20):
            name = self.NAME_ASQ + "_" + str(x + 20)
            dn = ldb.Dn(self.ldb,
                        "cn=" + name + "," + str(self.ou_dn))
            self.members2.append(dn)
            self.ldb.add({
                "dn": dn,
                "objectclass": "group",
                "member": [str(x) for x in self.members]})

        name = self.NAME_ASQ + "_" + str(x + 40)
        self.top_dn = ldb.Dn(self.ldb,
                             "cn=" + name + "," + str(self.ou_dn))
        self.ldb.add({
            "dn": self.top_dn,
            "objectclass": "group",
            "member": [str(x) for x in self.members2]})

    def tearDown(self):
        samba.tests.delete_force(self.ldb, self.ou_dn,
                                 controls=['tree_delete:1'])

    def test_asq(self):
        """Testing ASQ behaviour.

        ASQ is very strange, it turns a BASE search into a search for
        all the objects pointed to by the specified attribute,
        returning multiple entries!

        """

        msgs = self.ldb.search(base=self.top_dn,
                               scope=ldb.SCOPE_BASE,
                               attrs=["objectGUID", "cn", "member"],
                               controls=["asq:1:member"])

        self.assertEqual(len(msgs), 20)

        for msg in msgs:
            self.assertNotEqual(msg.dn, self.top_dn)
            self.assertIn(msg.dn, self.members2)
            for group in msg["member"]:
                self.assertIn(ldb.Dn(self.ldb, str(group)),
                              self.members)

    def test_asq_paged(self):
        """Testing ASQ behaviour with paged_results set.

        ASQ is very strange, it turns a BASE search into a search for
        all the objects pointed to by the specified attribute,
        returning multiple entries!

        """

        msgs = self.ldb.search(base=self.top_dn,
                               scope=ldb.SCOPE_BASE,
                               attrs=["objectGUID", "cn", "member"],
                               controls=["asq:1:member",
                                         "paged_results:1:1024"])

        self.assertEqual(len(msgs), 20)

        for msg in msgs:
            self.assertNotEqual(msg.dn, self.top_dn)
            self.assertIn(msg.dn, self.members2)
            for group in msg["member"]:
                self.assertIn(ldb.Dn(self.ldb, str(group)),
                              self.members)

    def test_asq_vlv(self):
        """Testing ASQ behaviour with VLV set.

        ASQ is very strange, it turns a BASE search into a search for
        all the objects pointed to by the specified attribute,
        returning multiple entries!

        """

        sort_control = "server_sort:1:0:cn"

        msgs = self.ldb.search(base=self.top_dn,
                               scope=ldb.SCOPE_BASE,
                               attrs=["objectGUID", "cn", "member"],
                               controls=["asq:1:member",
                                         sort_control,
                                         "vlv:1:20:20:11:0"])

        self.assertEqual(len(msgs), 20)

        for msg in msgs:
            self.assertNotEqual(msg.dn, self.top_dn)
            self.assertIn(msg.dn, self.members2)
            for group in msg["member"]:
                self.assertIn(ldb.Dn(self.ldb, str(group)),
                              self.members)

    def test_asq_vlv_paged(self):
        """Testing ASQ behaviour with VLV and paged_results set.

        ASQ is very strange, it turns a BASE search into a search for
        all the objects pointed to by the specified attribute,
        returning multiple entries!

        Thankfully combining both of these gives
        unavailable-critical-extension against Windows 1709

        """

        sort_control = "server_sort:1:0:cn"

        try:
            msgs = self.ldb.search(base=self.top_dn,
                                   scope=ldb.SCOPE_BASE,
                                   attrs=["objectGUID", "cn", "member"],
                                   controls=["asq:1:member",
                                             sort_control,
                                             "vlv:1:20:20:11:0",
                                             "paged_results:1:1024"])
            self.fail("should have failed with LDAP_UNAVAILABLE_CRITICAL_EXTENSION")
        except ldb.LdbError as e:
            (enum, estr) = e.args
            self.assertEqual(enum, ldb.ERR_UNSUPPORTED_CRITICAL_EXTENSION)

if "://" not in url:
    if os.path.isfile(url):
        url = "tdb://%s" % url
    else:
        url = "ldap://%s" % url

TestProgram(module=__name__, opts=subunitopts)
