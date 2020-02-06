#!/usr/bin/env python3
#
# Unit tests for the notification control
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

from samba.auth import AUTH_SESSION_INFO_DEFAULT_GROUPS, AUTH_SESSION_INFO_AUTHENTICATED, AUTH_SESSION_INFO_SIMPLE_PRIVILEGES

from ldb import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE, LdbError
from ldb import ERR_TIME_LIMIT_EXCEEDED, ERR_ADMIN_LIMIT_EXCEEDED, ERR_UNWILLING_TO_PERFORM
from ldb import Message

parser = optparse.OptionParser("notification.py [options] <host>")
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


class LDAPNotificationTest(samba.tests.TestCase):

    def setUp(self):
        super(LDAPNotificationTest, self).setUp()
        self.ldb = SamDB(url, credentials=creds, session_info=system_session(lp), lp=lp)
        self.base_dn = self.ldb.domain_dn()

        res = self.ldb.search("", scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
        self.assertEqual(len(res), 1)

        self.user_sid_dn = "<SID=%s>" % str(ndr_unpack(samba.dcerpc.security.dom_sid, res[0]["tokenGroups"][0]))

    def test_simple_search(self):
        """Testing a notification with an modify and a timeout"""
        if not url.startswith("ldap"):
            self.fail(msg="This test is only valid on ldap")

        msg1 = None
        search1 = self.ldb.search_iterator(base=self.user_sid_dn,
                                           expression="(objectClass=*)",
                                           scope=ldb.SCOPE_SUBTREE,
                                           attrs=["name", "objectGUID", "displayName"])
        for reply in search1:
            self.assertIsInstance(reply, ldb.Message)
            self.assertIsNone(msg1)
            msg1 = reply
        res1 = search1.result()

        search2 = self.ldb.search_iterator(base=self.base_dn,
                                           expression="(objectClass=*)",
                                           scope=ldb.SCOPE_SUBTREE,
                                           attrs=["name", "objectGUID", "displayName"])
        refs2 = 0
        msg2 = None
        for reply in search2:
            if isinstance(reply, str):
                refs2 += 1
                continue
            self.assertIsInstance(reply, ldb.Message)
            if reply["objectGUID"][0] == msg1["objectGUID"][0]:
                self.assertIsNone(msg2)
                msg2 = reply
                self.assertEqual(msg1.dn, msg2.dn)
                self.assertEqual(len(msg1), len(msg2))
                self.assertEqual(msg1["name"], msg2["name"])
                #self.assertEqual(msg1["displayName"], msg2["displayName"])
        res2 = search2.result()

        self.ldb.modify_ldif("""
dn: """ + self.user_sid_dn + """
changetype: modify
replace: otherLoginWorkstations
otherLoginWorkstations: BEFORE"
""")
        notify1 = self.ldb.search_iterator(base=self.base_dn,
                                           expression="(objectClass=*)",
                                           scope=ldb.SCOPE_SUBTREE,
                                           attrs=["name", "objectGUID", "displayName"],
                                           controls=["notification:1"],
                                           timeout=1)

        self.ldb.modify_ldif("""
dn: """ + self.user_sid_dn + """
changetype: modify
replace: otherLoginWorkstations
otherLoginWorkstations: AFTER"
""")

        msg3 = None
        for reply in notify1:
            self.assertIsInstance(reply, ldb.Message)
            if reply["objectGUID"][0] == msg1["objectGUID"][0]:
                self.assertIsNone(msg3)
                msg3 = reply
                self.assertEqual(msg1.dn, msg3.dn)
                self.assertEqual(len(msg1), len(msg3))
                self.assertEqual(msg1["name"], msg3["name"])
                #self.assertEqual(msg1["displayName"], msg3["displayName"])
        try:
            res = notify1.result()
            self.fail()
        except LdbError as e10:
            (num, _) = e10.args
            self.assertEqual(num, ERR_TIME_LIMIT_EXCEEDED)
        self.assertIsNotNone(msg3)

        self.ldb.modify_ldif("""
dn: """ + self.user_sid_dn + """
changetype: delete
delete: otherLoginWorkstations
""")

    def test_max_search(self):
        """Testing the max allowed notifications"""
        if not url.startswith("ldap"):
            self.fail(msg="This test is only valid on ldap")

        max_notifications = 5

        notifies = [None] * (max_notifications + 1)
        for i in range(0, max_notifications + 1):
            notifies[i] = self.ldb.search_iterator(base=self.base_dn,
                                                   expression="(objectClass=*)",
                                                   scope=ldb.SCOPE_SUBTREE,
                                                   attrs=["name"],
                                                   controls=["notification:1"],
                                                   timeout=1)
        num_admin_limit = 0
        num_time_limit = 0
        for i in range(0, max_notifications + 1):
            try:
                for msg in notifies[i]:
                    continue
                res = notifies[i].result()
                self.fail()
            except LdbError as e:
                (num, _) = e.args
                if num == ERR_ADMIN_LIMIT_EXCEEDED:
                    num_admin_limit += 1
                    continue
                if num == ERR_TIME_LIMIT_EXCEEDED:
                    num_time_limit += 1
                    continue
                raise
        self.assertEqual(num_admin_limit, 1)
        self.assertEqual(num_time_limit, max_notifications)

    def test_invalid_filter(self):
        """Testing invalid filters for notifications"""
        if not url.startswith("ldap"):
            self.fail(msg="This test is only valid on ldap")

        valid_attrs = ["objectClass", "objectGUID", "distinguishedName", "name"]

        for va in valid_attrs:
            try:
                hnd = self.ldb.search_iterator(base=self.base_dn,
                                               expression="(%s=*)" % va,
                                               scope=ldb.SCOPE_SUBTREE,
                                               attrs=["name"],
                                               controls=["notification:1"],
                                               timeout=1)
                for reply in hnd:
                    self.fail()
                res = hnd.result()
                self.fail()
            except LdbError as e1:
                (num, _) = e1.args
                self.assertEqual(num, ERR_TIME_LIMIT_EXCEEDED)

            try:
                hnd = self.ldb.search_iterator(base=self.base_dn,
                                               expression="(|(%s=*)(%s=value))" % (va, va),
                                               scope=ldb.SCOPE_SUBTREE,
                                               attrs=["name"],
                                               controls=["notification:1"],
                                               timeout=1)
                for reply in hnd:
                    self.fail()
                res = hnd.result()
                self.fail()
            except LdbError as e2:
                (num, _) = e2.args
                self.assertEqual(num, ERR_TIME_LIMIT_EXCEEDED)

            try:
                hnd = self.ldb.search_iterator(base=self.base_dn,
                                               expression="(&(%s=*)(%s=value))" % (va, va),
                                               scope=ldb.SCOPE_SUBTREE,
                                               attrs=["name"],
                                               controls=["notification:1"],
                                               timeout=0)
                for reply in hnd:
                    self.fail()
                res = hnd.result()
                self.fail()
            except LdbError as e3:
                (num, _) = e3.args
                self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

            try:
                hnd = self.ldb.search_iterator(base=self.base_dn,
                                               expression="(%s=value)" % va,
                                               scope=ldb.SCOPE_SUBTREE,
                                               attrs=["name"],
                                               controls=["notification:1"],
                                               timeout=0)
                for reply in hnd:
                    self.fail()
                res = hnd.result()
                self.fail()
            except LdbError as e4:
                (num, _) = e4.args
                self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

            try:
                hnd = self.ldb.search_iterator(base=self.base_dn,
                                               expression="(%s>=value)" % va,
                                               scope=ldb.SCOPE_SUBTREE,
                                               attrs=["name"],
                                               controls=["notification:1"],
                                               timeout=0)
                for reply in hnd:
                    self.fail()
                res = hnd.result()
                self.fail()
            except LdbError as e5:
                (num, _) = e5.args
                self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

            try:
                hnd = self.ldb.search_iterator(base=self.base_dn,
                                               expression="(%s<=value)" % va,
                                               scope=ldb.SCOPE_SUBTREE,
                                               attrs=["name"],
                                               controls=["notification:1"],
                                               timeout=0)
                for reply in hnd:
                    self.fail()
                res = hnd.result()
                self.fail()
            except LdbError as e6:
                (num, _) = e6.args
                self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

            try:
                hnd = self.ldb.search_iterator(base=self.base_dn,
                                               expression="(%s=*value*)" % va,
                                               scope=ldb.SCOPE_SUBTREE,
                                               attrs=["name"],
                                               controls=["notification:1"],
                                               timeout=0)
                for reply in hnd:
                    self.fail()
                res = hnd.result()
                self.fail()
            except LdbError as e7:
                (num, _) = e7.args
                self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

            try:
                hnd = self.ldb.search_iterator(base=self.base_dn,
                                               expression="(!(%s=*))" % va,
                                               scope=ldb.SCOPE_SUBTREE,
                                               attrs=["name"],
                                               controls=["notification:1"],
                                               timeout=0)
                for reply in hnd:
                    self.fail()
                res = hnd.result()
                self.fail()
            except LdbError as e8:
                (num, _) = e8.args
                self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        res = self.ldb.search(base=self.ldb.get_schema_basedn(),
                              expression="(objectClass=attributeSchema)",
                              scope=ldb.SCOPE_ONELEVEL,
                              attrs=["lDAPDisplayName"],
                              controls=["paged_results:1:2500"])
        for msg in res:
            va = str(msg["lDAPDisplayName"][0])
            if va in valid_attrs:
                continue

            try:
                hnd = self.ldb.search_iterator(base=self.base_dn,
                                               expression="(%s=*)" % va,
                                               scope=ldb.SCOPE_SUBTREE,
                                               attrs=["name"],
                                               controls=["notification:1"],
                                               timeout=0)
                for reply in hnd:
                    self.fail()
                res = hnd.result()
                self.fail()
            except LdbError as e9:
                (num, _) = e9.args
                if num != ERR_UNWILLING_TO_PERFORM:
                    print("va[%s]" % va)
                self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        try:
            va = "noneAttributeName"
            hnd = self.ldb.search_iterator(base=self.base_dn,
                                           expression="(%s=*)" % va,
                                           scope=ldb.SCOPE_SUBTREE,
                                           attrs=["name"],
                                           controls=["notification:1"],
                                           timeout=0)
            for reply in hnd:
                self.fail()
            res = hnd.result()
            self.fail()
        except LdbError as e11:
            (num, _) = e11.args
            if num != ERR_UNWILLING_TO_PERFORM:
                print("va[%s]" % va)
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)


if "://" not in url:
    if os.path.isfile(url):
        url = "tdb://%s" % url
    else:
        url = "ldap://%s" % url

TestProgram(module=__name__, opts=subunitopts)
