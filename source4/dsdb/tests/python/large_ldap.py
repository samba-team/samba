#!/usr/bin/env python3
#
# Test large LDAP response behaviour in Samba
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


class ManyLDAPTest(samba.tests.TestCase):

    def setUp(self):
        super(ManyLDAPTest, self).setUp()
        self.ldb = SamDB(url, credentials=creds, session_info=system_session(lp), lp=lp)
        self.base_dn = self.ldb.domain_dn()
        self.OU_NAME_MANY="many_ou" + format(random.randint(0, 99999), "05")
        self.ou_dn = ldb.Dn(self.ldb, "ou=" + self.OU_NAME_MANY + "," + str(self.base_dn))

        samba.tests.delete_force(self.ldb, self.ou_dn,
                                 controls=['tree_delete:1'])

        self.ldb.add({
            "dn": self.ou_dn,
            "objectclass": "organizationalUnit",
            "ou": self.OU_NAME_MANY})

        for x in range(2000):
            ou_name = self.OU_NAME_MANY + str(x)
            self.ldb.add({
                "dn": "ou=" + ou_name + "," + str(self.ou_dn),
                "objectclass": "organizationalUnit",
                "ou": ou_name})

    def tearDown(self):
        samba.tests.delete_force(self.ldb, self.ou_dn,
                                 controls=['tree_delete:1'])

    def test_unindexed_iterator_search(self):
        """Testing a search for all the OUs.

        Needed to test that more that IOV_MAX responses can be returned
        """
        if not url.startswith("ldap"):
            self.fail(msg="This test is only valid on ldap")

        count = 0
        msg1 = None
        search1 = self.ldb.search_iterator(base=self.ou_dn,
                                           expression="(ou=" + self.OU_NAME_MANY + "*)",
                                           scope=ldb.SCOPE_SUBTREE,
                                           attrs=["objectGUID", "samAccountName"])

        for reply in search1:
            self.assertIsInstance(reply, ldb.Message)
            count += 1
        res1 = search1.result()

        # Check we got everything
        self.assertEqual(count, 2001)

class LargeLDAPTest(samba.tests.TestCase):

    def setUp(self):
        super(LargeLDAPTest, self).setUp()
        self.ldb = SamDB(url, credentials=creds, session_info=system_session(lp), lp=lp)
        self.base_dn = self.ldb.domain_dn()
        self.USER_NAME = "large_user" + format(random.randint(0, 99999), "05") + "-"
        self.OU_NAME="large_user_ou" + format(random.randint(0, 99999), "05")
        self.ou_dn = ldb.Dn(self.ldb, "ou=" + self.OU_NAME + "," + str(self.base_dn))

        samba.tests.delete_force(self.ldb, self.ou_dn,
                                 controls=['tree_delete:1'])

        self.ldb.add({
            "dn": self.ou_dn,
            "objectclass": "organizationalUnit",
            "ou": self.OU_NAME})

        for x in range(200):
            user_name = self.USER_NAME + format(x, "03")
            self.ldb.add({
                "dn": "cn=" + user_name + "," + str(self.ou_dn),
                "objectclass": "user",
                "sAMAccountName": user_name,
                "jpegPhoto": b'a' * (2 * 1024 * 1024)})

    def tearDown(self):
        # Remake the connection for tear-down (old Samba drops the socket)
        self.ldb = SamDB(url, credentials=creds, session_info=system_session(lp), lp=lp)
        samba.tests.delete_force(self.ldb, self.ou_dn,
                                 controls=['tree_delete:1'])

    def test_unindexed_iterator_search(self):
        """Testing an unindexed search that will break the result size limit"""
        if not url.startswith("ldap"):
            self.fail(msg="This test is only valid on ldap")

        count = 0
        msg1 = None
        search1 = self.ldb.search_iterator(base=self.ou_dn,
                                           expression="(sAMAccountName=" + self.USER_NAME + "*)",
                                           scope=ldb.SCOPE_SUBTREE,
                                           attrs=["objectGUID", "samAccountName"])

        for reply in search1:
            self.assertIsInstance(reply, ldb.Message)
            count += 1

        res1 = search1.result()

        self.assertEqual(count, 200)

        # Now try breaking the 256MB limit

        count_jpeg = 0
        msg1 = None
        search1 = self.ldb.search_iterator(base=self.ou_dn,
                                           expression="(sAMAccountName=" + self.USER_NAME + "*)",
                                           scope=ldb.SCOPE_SUBTREE,
                                           attrs=["objectGUID", "samAccountName", "jpegPhoto"])
        try:
            for reply in search1:
                self.assertIsInstance(reply, ldb.Message)
                msg1 = reply
                count_jpeg += 1
        except LdbError as e:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_SIZE_LIMIT_EXCEEDED)

        # Assert we don't get all the entries but still the error
        self.assertGreater(count, count_jpeg)

        # Now try for just 100MB (server will do some chunking for this)

        count_jpeg2 = 0
        msg1 = None
        try:
            search1 = self.ldb.search_iterator(base=self.ou_dn,
                                               expression="(sAMAccountName=" + self.USER_NAME + "1*)",
                                               scope=ldb.SCOPE_SUBTREE,
                                               attrs=["objectGUID", "samAccountName", "jpegPhoto"])
        except LdbError as e:
            enum = e.args[0]
            estr = e.args[1]
            self.fail(estr)

        for reply in search1:
            self.assertIsInstance(reply, ldb.Message)
            msg1 = reply
            count_jpeg2 += 1

        # Assert we got some entries
        self.assertEqual(count_jpeg2, 100)

    def test_iterator_search(self):
        """Testing an indexed search that will break the result size limit"""
        if not url.startswith("ldap"):
            self.fail(msg="This test is only valid on ldap")

        count = 0
        msg1 = None
        search1 = self.ldb.search_iterator(base=self.ou_dn,
                                           expression="(&(objectClass=user)(sAMAccountName=" + self.USER_NAME + "*))",
                                           scope=ldb.SCOPE_SUBTREE,
                                           attrs=["objectGUID", "samAccountName"])

        for reply in search1:
            self.assertIsInstance(reply, ldb.Message)
            count += 1
        res1 = search1.result()

        # Now try breaking the 256MB limit

        count_jpeg = 0
        msg1 = None
        search1 = self.ldb.search_iterator(base=self.ou_dn,
                                           expression="(&(objectClass=user)(sAMAccountName=" + self.USER_NAME + "*))",
                                           scope=ldb.SCOPE_SUBTREE,
                                           attrs=["objectGUID", "samAccountName", "jpegPhoto"])
        try:
            for reply in search1:
                self.assertIsInstance(reply, ldb.Message)
                count_jpeg =+ 1
        except LdbError as e:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_SIZE_LIMIT_EXCEEDED)

        # Assert we don't get all the entries but still the error
        self.assertGreater(count, count_jpeg)



if "://" not in url:
    if os.path.isfile(url):
        url = "tdb://%s" % url
    else:
        url = "ldap://%s" % url

TestProgram(module=__name__, opts=subunitopts)
