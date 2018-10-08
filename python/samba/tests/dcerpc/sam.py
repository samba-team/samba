# -*- coding: utf-8 -*-
#
# Unix SMB/CIFS implementation.
# Copyright © Jelmer Vernooij <jelmer@samba.org> 2008
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

"""Tests for samba.dcerpc.sam."""

from samba.dcerpc import samr, security, lsa
from samba.tests import RpcInterfaceTestCase
from samba.tests import env_loadparm, delete_force

from samba.credentials import Credentials
from samba.auth import system_session
from samba.samdb import SamDB
from samba.dsdb import (
    ATYPE_NORMAL_ACCOUNT,
    ATYPE_WORKSTATION_TRUST,
    GTYPE_SECURITY_UNIVERSAL_GROUP,
    GTYPE_SECURITY_GLOBAL_GROUP)
from samba import generate_random_password
import os


# FIXME: Pidl should be doing this for us
def toArray(handle, array, num_entries):
    return [(entry.idx, entry.name) for entry in array.entries[:num_entries]]


class SamrTests(RpcInterfaceTestCase):

    def setUp(self):
        super(SamrTests, self).setUp()
        self.conn = samr.samr("ncalrpc:", self.get_loadparm())
        self.open_samdb()
        self.open_domain_handle()

    #
    # Open the samba database
    #
    def open_samdb(self):
        self.lp = env_loadparm()
        self.domain = os.environ["DOMAIN"]
        self.creds = Credentials()
        self.creds.guess(self.lp)
        self.session = system_session()
        self.samdb = SamDB(
            session_info=self.session, credentials=self.creds, lp=self.lp)

    #
    # Open a SAMR Domain handle
    def open_domain_handle(self):
        self.handle = self.conn.Connect2(
            None, security.SEC_FLAG_MAXIMUM_ALLOWED)

        self.domain_sid = self.conn.LookupDomain(
            self.handle, lsa.String(self.domain))

        self.domain_handle = self.conn.OpenDomain(
            self.handle, security.SEC_FLAG_MAXIMUM_ALLOWED, self.domain_sid)

    def test_connect5(self):
        (level, info, handle) =\
            self.conn.Connect5(None, 0, 1, samr.ConnectInfo1())

    def test_connect2(self):
        handle = self.conn.Connect2(None, security.SEC_FLAG_MAXIMUM_ALLOWED)
        self.assertTrue(handle is not None)

    def test_EnumDomains(self):
        handle = self.conn.Connect2(None, security.SEC_FLAG_MAXIMUM_ALLOWED)
        toArray(*self.conn.EnumDomains(handle, 0, 4294967295))
        self.conn.Close(handle)

    # Create groups based on the id list supplied, the id is used to
    # form a unique name and description.
    #
    # returns a list of the created dn's, which can be passed to delete_dns
    # to clean up after the test has run.
    def create_groups(self, ids):
        dns = []
        for i in ids:
            name = "SAMR_GRP%d" % i
            dn = "cn=%s,cn=Users,%s" % (name, self.samdb.domain_dn())
            delete_force(self.samdb, dn)

            self.samdb.newgroup(name)
            dns.append(dn)
        return dns

    # Create user accounts based on the id list supplied, the id is used to
    # form a unique name and description.
    #
    # returns a list of the created dn's, which can be passed to delete_dns
    # to clean up after the test has run.
    def create_users(self, ids):
        dns = []
        for i in ids:
            name = "SAMR_USER%d" % i
            dn = "cn=%s,CN=USERS,%s" % (name, self.samdb.domain_dn())
            delete_force(self.samdb, dn)

            # We only need the user to exist, we don't need a password
            self.samdb.newuser(
                name,
                password=None,
                setpassword=False,
                description="Description for " + name,
                givenname="given%dname" % i,
                surname="surname%d" % i)
            dns.append(dn)
        return dns

    # Create computer accounts based on the id list supplied, the id is used to
    # form a unique name and description.
    #
    # returns a list of the created dn's, which can be passed to delete_dns
    # to clean up after the test has run.
    def create_computers(self, ids):
        dns = []
        for i in ids:
            name = "SAMR_CMP%d" % i
            dn = "cn=%s,cn=COMPUTERS,%s" % (name, self.samdb.domain_dn())
            delete_force(self.samdb, dn)

            self.samdb.newcomputer(name, description="Description of " + name)
            dns.append(dn)
        return dns

    # Delete the specified dn's.
    #
    # Used to clean up entries created by individual tests.
    #
    def delete_dns(self, dns):
        for dn in dns:
            delete_force(self.samdb, dn)

    # Common tests for QueryDisplayInfo
    #
    def _test_QueryDisplayInfo(
            self, level, check_results, select, attributes, add_elements):
        #
        # Get the expected results by querying the samdb database directly.
        # We do this rather than use a list of expected results as this runs
        # with other tests so we do not have a known fixed list of elements
        expected = self.samdb.search(expression=select, attrs=attributes)
        self.assertTrue(len(expected) > 0)

        #
        # Perform QueryDisplayInfo with max results greater than the expected
        # number of results.
        (ts, rs, actual) = self.conn.QueryDisplayInfo(
            self.domain_handle, level, 0, 1024, 4294967295)

        self.assertEquals(len(expected), ts)
        self.assertEquals(len(expected), rs)
        check_results(expected, actual.entries)

        #
        # Perform QueryDisplayInfo with max results set to the number of
        # results returned from the first query, should return the same results
        (ts1, rs1, actual1) = self.conn.QueryDisplayInfo(
            self.domain_handle, level, 0, rs, 4294967295)
        self.assertEquals(ts, ts1)
        self.assertEquals(rs, rs1)
        check_results(expected, actual1.entries)

        #
        # Perform QueryDisplayInfo and get the last two results.
        # Note: We are assuming there are at least three entries
        self.assertTrue(ts > 2)
        (ts2, rs2, actual2) = self.conn.QueryDisplayInfo(
            self.domain_handle, level, (ts - 2), 2, 4294967295)
        self.assertEquals(ts, ts2)
        self.assertEquals(2, rs2)
        check_results(list(expected)[-2:], actual2.entries)

        #
        # Perform QueryDisplayInfo and get the first two results.
        # Note: We are assuming there are at least three entries
        self.assertTrue(ts > 2)
        (ts2, rs2, actual2) = self.conn.QueryDisplayInfo(
            self.domain_handle, level, 0, 2, 4294967295)
        self.assertEquals(ts, ts2)
        self.assertEquals(2, rs2)
        check_results(list(expected)[:2], actual2.entries)

        #
        # Perform QueryDisplayInfo and get two results in the middle of the
        # list i.e. not the first or the last entry.
        # Note: We are assuming there are at least four entries
        self.assertTrue(ts > 3)
        (ts2, rs2, actual2) = self.conn.QueryDisplayInfo(
            self.domain_handle, level, 1, 2, 4294967295)
        self.assertEquals(ts, ts2)
        self.assertEquals(2, rs2)
        check_results(list(expected)[1:2], actual2.entries)

        #
        # To check that cached values are being returned rather than the
        # results being re-read from disk we add elements, and request all
        # but the first result.
        #
        dns = add_elements([1000, 1002, 1003, 1004])

        #
        # Perform QueryDisplayInfo and get all but the first result.
        # We should be using the cached results so the entries we just added
        # should not be present
        (ts3, rs3, actual3) = self.conn.QueryDisplayInfo(
            self.domain_handle, level, 1, 1024, 4294967295)
        self.assertEquals(ts, ts3)
        self.assertEquals(len(expected) - 1, rs3)
        check_results(list(expected)[1:], actual3.entries)

        #
        # Perform QueryDisplayInfo and get all the results.
        # As the start index is zero we should reread the data from disk and
        # the added entries should be there
        new = self.samdb.search(expression=select, attrs=attributes)
        (ts4, rs4, actual4) = self.conn.QueryDisplayInfo(
            self.domain_handle, level, 0, 1024, 4294967295)
        self.assertEquals(len(expected) + len(dns), ts4)
        self.assertEquals(len(expected) + len(dns), rs4)
        check_results(new, actual4.entries)

        # Delete the added DN's and query all but the first entry.
        # This should ensure the cached results are used and that the
        # missing entry code is triggered.
        self.delete_dns(dns)
        (ts5, rs5, actual5) = self.conn.QueryDisplayInfo(
            self.domain_handle, level, 1, 1024, 4294967295)
        self.assertEquals(len(expected) + len(dns), ts5)
        # The deleted results will be filtered from the result set so should
        # be missing from the returned results.
        # Note: depending on the GUID order, the first result in the cache may
        #       be a deleted entry, in which case the results will contain all
        #       the expected elements, otherwise the first expected result will
        #       be missing.
        if rs5 == len(expected):
            check_results(expected, actual5.entries)
        elif rs5 == (len(expected) - 1):
            check_results(list(expected)[1:], actual5.entries)
        else:
            self.fail("Incorrect number of entries {0}".format(rs5))

        #
        # Perform QueryDisplayInfo specifying an index past the end of the
        # available data.
        # Should return no data.
        (ts6, rs6, actual6) = self.conn.QueryDisplayInfo(
            self.domain_handle, level, ts5, 1, 4294967295)
        self.assertEquals(ts5, ts6)
        self.assertEquals(0, rs6)

        self.conn.Close(self.handle)

    # Test for QueryDisplayInfo, Level 1
    # Returns the sAMAccountName, displayName and description for all
    # the user accounts.
    #
    def test_QueryDisplayInfo_level_1(self):
        def check_results(expected, actual):
            # Assume the QueryDisplayInfo and ldb.search return their results
            # in the same order
            for (e, a) in zip(expected, actual):
                self.assertTrue(isinstance(a, samr.DispEntryGeneral))
                self.assertEquals(str(e["sAMAccountName"]),
                                  str(a.account_name))

                # The displayName and description are optional.
                # In the expected results they will be missing, in
                # samr.DispEntryGeneral the corresponding attribute will have a
                # length of zero.
                #
                if a.full_name.length == 0:
                    self.assertFalse("displayName" in e)
                else:
                    self.assertEquals(str(e["displayName"]), str(a.full_name))

                if a.description.length == 0:
                    self.assertFalse("description" in e)
                else:
                    self.assertEquals(str(e["description"]),
                                      str(a.description))
        # Create four user accounts
        # to ensure that we have the minimum needed for the tests.
        dns = self.create_users([1, 2, 3, 4])

        select = "(&(objectclass=user)(sAMAccountType={0}))".format(
            ATYPE_NORMAL_ACCOUNT)
        attributes = ["sAMAccountName", "displayName", "description"]
        self._test_QueryDisplayInfo(
            1, check_results, select, attributes, self.create_users)

        self.delete_dns(dns)

    # Test for QueryDisplayInfo, Level 2
    # Returns the sAMAccountName and description for all
    # the computer accounts.
    #
    def test_QueryDisplayInfo_level_2(self):
        def check_results(expected, actual):
            # Assume the QueryDisplayInfo and ldb.search return their results
            # in the same order
            for (e, a) in zip(expected, actual):
                self.assertTrue(isinstance(a, samr.DispEntryFull))
                self.assertEquals(str(e["sAMAccountName"]),
                                  str(a.account_name))

                # The description is optional.
                # In the expected results they will be missing, in
                # samr.DispEntryGeneral the corresponding attribute will have a
                # length of zero.
                #
                if a.description.length == 0:
                    self.assertFalse("description" in e)
                else:
                    self.assertEquals(str(e["description"]),
                                      str(a.description))

        # Create four computer accounts
        # to ensure that we have the minimum needed for the tests.
        dns = self.create_computers([1, 2, 3, 4])

        select = "(&(objectclass=user)(sAMAccountType={0}))".format(
            ATYPE_WORKSTATION_TRUST)
        attributes = ["sAMAccountName", "description"]
        self._test_QueryDisplayInfo(
            2, check_results, select, attributes, self.create_computers)

        self.delete_dns(dns)

    # Test for QueryDisplayInfo, Level 3
    # Returns the sAMAccountName and description for all
    # the groups.
    #
    def test_QueryDisplayInfo_level_3(self):
        def check_results(expected, actual):
            # Assume the QueryDisplayInfo and ldb.search return their results
            # in the same order
            for (e, a) in zip(expected, actual):
                self.assertTrue(isinstance(a, samr.DispEntryFullGroup))
                self.assertEquals(str(e["sAMAccountName"]),
                                  str(a.account_name))

                # The description is optional.
                # In the expected results they will be missing, in
                # samr.DispEntryGeneral the corresponding attribute will have a
                # length of zero.
                #
                if a.description.length == 0:
                    self.assertFalse("description" in e)
                else:
                    self.assertEquals(str(e["description"]),
                                      str(a.description))

        # Create four groups
        # to ensure that we have the minimum needed for the tests.
        dns = self.create_groups([1, 2, 3, 4])

        select = "(&(|(groupType=%d)(groupType=%d))(objectClass=group))" % (
            GTYPE_SECURITY_UNIVERSAL_GROUP,
            GTYPE_SECURITY_GLOBAL_GROUP)
        attributes = ["sAMAccountName", "description"]
        self._test_QueryDisplayInfo(
            3, check_results, select, attributes, self.create_groups)

        self.delete_dns(dns)

    # Test for QueryDisplayInfo, Level 4
    # Returns the sAMAccountName (as an ASCII string)
    # for all the user accounts.
    #
    def test_QueryDisplayInfo_level_4(self):
        def check_results(expected, actual):
            # Assume the QueryDisplayInfo and ldb.search return their results
            # in the same order
            for (e, a) in zip(expected, actual):
                self.assertTrue(isinstance(a, samr.DispEntryAscii))
                self.assertTrue(
                    isinstance(a.account_name, lsa.AsciiStringLarge))
                self.assertEquals(
                    str(e["sAMAccountName"]), str(a.account_name.string))

        # Create four user accounts
        # to ensure that we have the minimum needed for the tests.
        dns = self.create_users([1, 2, 3, 4])

        select = "(&(objectclass=user)(sAMAccountType={0}))".format(
            ATYPE_NORMAL_ACCOUNT)
        attributes = ["sAMAccountName", "displayName", "description"]
        self._test_QueryDisplayInfo(
            4, check_results, select, attributes, self.create_users)

        self.delete_dns(dns)

    # Test for QueryDisplayInfo, Level 5
    # Returns the sAMAccountName (as an ASCII string)
    # for all the groups.
    #
    def test_QueryDisplayInfo_level_5(self):
        def check_results(expected, actual):
            # Assume the QueryDisplayInfo and ldb.search return their results
            # in the same order
            for (e, a) in zip(expected, actual):
                self.assertTrue(isinstance(a, samr.DispEntryAscii))
                self.assertTrue(
                    isinstance(a.account_name, lsa.AsciiStringLarge))
                self.assertEquals(
                    str(e["sAMAccountName"]), str(a.account_name.string))

        # Create four groups
        # to ensure that we have the minimum needed for the tests.
        dns = self.create_groups([1, 2, 3, 4])

        select = "(&(|(groupType=%d)(groupType=%d))(objectClass=group))" % (
            GTYPE_SECURITY_UNIVERSAL_GROUP,
            GTYPE_SECURITY_GLOBAL_GROUP)
        attributes = ["sAMAccountName", "description"]
        self._test_QueryDisplayInfo(
            5, check_results, select, attributes, self.create_groups)

        self.delete_dns(dns)
