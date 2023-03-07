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

import optparse
import sys
import os
import random
import time

sys.path.insert(0, "bin/python")
import samba
from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

from samba.auth import system_session
from samba import ldb, sd_utils
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

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.ldb = SamDB(url, credentials=creds, session_info=system_session(lp), lp=lp)
        cls.base_dn = cls.ldb.domain_dn()
        cls.OU_NAME_MANY="many_ou" + format(random.randint(0, 99999), "05")
        cls.ou_dn = ldb.Dn(cls.ldb, "ou=" + cls.OU_NAME_MANY + "," + str(cls.base_dn))

        samba.tests.delete_force(cls.ldb, cls.ou_dn,
                                 controls=['tree_delete:1'])

        cls.ldb.add({
            "dn": cls.ou_dn,
            "objectclass": "organizationalUnit",
            "ou": cls.OU_NAME_MANY})

        for x in range(2000):
            ou_name = cls.OU_NAME_MANY + str(x)
            cls.ldb.add({
                "dn": "ou=" + ou_name + "," + str(cls.ou_dn),
                "objectclass": "organizationalUnit",
                "ou": ou_name})

    @classmethod
    def tearDownClass(cls):
        samba.tests.delete_force(cls.ldb, cls.ou_dn,
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

    @classmethod
    def setUpClass(cls):
        cls.ldb = SamDB(url, credentials=creds, session_info=system_session(lp), lp=lp)
        cls.base_dn = cls.ldb.domain_dn()

        cls.sd_utils = sd_utils.SDUtils(cls.ldb)
        cls.USER_NAME = "large_user" + format(random.randint(0, 99999), "05") + "-"
        cls.OU_NAME="large_user_ou" + format(random.randint(0, 99999), "05")
        cls.ou_dn = ldb.Dn(cls.ldb, "ou=" + cls.OU_NAME + "," + str(cls.base_dn))

        samba.tests.delete_force(cls.ldb, cls.ou_dn,
                                 controls=['tree_delete:1'])

        cls.ldb.add({
            "dn": cls.ou_dn,
            "objectclass": "organizationalUnit",
            "ou": cls.OU_NAME})

        for x in range(200):
            user_name = cls.USER_NAME + format(x, "03")
            cls.ldb.add({
                "dn": "cn=" + user_name + "," + str(cls.ou_dn),
                "objectclass": "user",
                "sAMAccountName": user_name,
                "jpegPhoto": b'a' * (2 * 1024 * 1024)})

            ace = "(OD;;RP;{6bc69afa-7bd9-4184-88f5-28762137eb6a};;S-1-%d)" % x
            dn = ldb.Dn(cls.ldb, "cn=" + user_name + "," + str(cls.ou_dn))

            # add an ACE that denies access to the above random attr
            # for a not-existing user.  This makes each SD distinct
            # and so will slow SD parsing.
            cls.sd_utils.dacl_add_ace(dn, ace)

    @classmethod
    def tearDownClass(cls):
        # Remake the connection for tear-down (old Samba drops the socket)
        cls.ldb = SamDB(url, credentials=creds, session_info=system_session(lp), lp=lp)
        samba.tests.delete_force(cls.ldb, cls.ou_dn,
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
        except LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_SIZE_LIMIT_EXCEEDED)
        else:
            # FIXME: Due to a bug in the client, the second exception to
            # transmit the iteration error isn't raised. We must still check
            # that the number of results is fewer than the total count.

            # self.fail('expected to fail with ERR_SIZE_LIMIT_EXCEEDED')

            pass

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

        self.assertEqual(count, 200)

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
                count_jpeg += 1
        except LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_SIZE_LIMIT_EXCEEDED)
        else:
            # FIXME: Due to a bug in the client, the second exception to
            # transmit the iteration error isn't raised. We must still check
            # that the number of results is fewer than the total count.

            # self.fail('expected to fail with ERR_SIZE_LIMIT_EXCEEDED')

            pass

        # Assert we don't get all the entries but still the error
        self.assertGreater(count, count_jpeg)

    def test_timeout(self):

        policy_dn = ldb.Dn(self.ldb,
                           'CN=Default Query Policy,CN=Query-Policies,'
                           'CN=Directory Service,CN=Windows NT,CN=Services,'
                           f'{self.ldb.get_config_basedn().get_linearized()}')

        # Get the current value of lDAPAdminLimits.
        res = self.ldb.search(base=policy_dn,
                              scope=ldb.SCOPE_BASE,
                              attrs=['lDAPAdminLimits'])
        msg = res[0]
        admin_limits = msg['lDAPAdminLimits']

        # Ensure we restore the previous value of the attribute.
        admin_limits.set_flags(ldb.FLAG_MOD_REPLACE)
        self.addCleanup(self.ldb.modify, msg)

        # Temporarily lower the value of MaxQueryDuration so we can test
        # timeout behaviour.
        timeout = 5
        query_duration = f'MaxQueryDuration={timeout}'.encode()

        admin_limits = [limit for limit in admin_limits
                        if not limit.lower().startswith(b'maxqueryduration=')]
        admin_limits.append(query_duration)

        # Set the new attribute value.
        msg = ldb.Message(policy_dn)
        msg['lDAPAdminLimits'] = ldb.MessageElement(admin_limits,
                                                    ldb.FLAG_MOD_REPLACE,
                                                    'lDAPAdminLimits')
        self.ldb.modify(msg)

        # Use a new connection so that the limits are reloaded.
        samdb = SamDB(url, credentials=creds,
                      session_info=system_session(lp),
                      lp=lp)

        # Create a large search expression that will take a long time to
        # evaluate.
        expression = '(jpegPhoto=*X*)' * 2000
        expression = f'(|{expression})'

        # Perform the LDAP search.
        prev = time.time()
        with self.assertRaises(ldb.LdbError) as err:
            samdb.search(base=self.ou_dn,
                         scope=ldb.SCOPE_SUBTREE,
                         expression=expression,
                         attrs=['objectGUID'])
        now = time.time()
        duration = now - prev

        # Ensure that we timed out.
        enum, _ = err.exception.args
        self.assertEqual(ldb.ERR_TIME_LIMIT_EXCEEDED, enum)

        # Ensure that the time spent searching is within the limit we
        # set.  We allow a marginal amount over as the Samba timeout
        # handling is not very accurate (and does not need to be)
        self.assertLess(timeout - 1, duration)
        self.assertLess(duration, timeout * 4)


if "://" not in url:
    if os.path.isfile(url):
        url = "tdb://%s" % url
    else:
        url = "ldap://%s" % url

TestProgram(module=__name__, opts=subunitopts)
