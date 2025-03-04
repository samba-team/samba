# -*- coding: utf-8 -*-
#
# Unix SMB/CIFS implementation.
# Copyright © Andrew Bartlett <abartlet@samba.org> 2021
# Copyright (C) Catalyst IT Ltd. 2017
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

"""Tests for samba.dcerpc.lsa."""

from samba.dcerpc import lsa, security
from samba.credentials import Credentials
from samba.tests import TestCase
from samba.dcerpc.security import dom_sid
from samba import NTSTATUSError
from samba.ntstatus import (
    NT_STATUS_OK,
    NT_STATUS_ACCESS_DENIED,
    NT_STATUS_NONE_MAPPED,
    NT_STATUS_SOME_NOT_MAPPED,
    NT_STATUS_INVALID_SID,
)
import samba.tests

class LsaTests(TestCase):

    def setUp(self):
        self.lp = self.get_loadparm()
        self.server = samba.tests.env_get_var_value('SERVER')

    def test_lsa_LookupSids3_multiple(self):
        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        c = lsa.lsarpc(
            "ncacn_ip_tcp:%s[schannel,seal]" % self.server,
            self.lp,
            machine_creds)

        sids = lsa.SidArray()
        sid = lsa.SidPtr()
        # Need a set
        x = dom_sid("S-1-5-7")
        sid.sid = x
        sids.sids = [sid]
        sids.num_sids = 1
        names = lsa.TransNameArray2()
        level = lsa.LSA_LOOKUP_NAMES_ALL
        count = 0
        lookup_options = lsa.LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES
        client_revision = lsa.LSA_CLIENT_REVISION_2

        # We want to run LookupSids3 multiple times on the same
        # connection as we have code to re-use the sam.ldb and we need
        # to check things work for the second request.
        (domains, names, count) = c.LookupSids3(sids, names, level, count, lookup_options, client_revision)
        self.assertEqual(count, 1)
        self.assertEqual(names.count, 1)
        self.assertEqual(names.names[0].name.string,
                         "ANONYMOUS LOGON")
        (domains2, names2, count2) = c.LookupSids3(sids, names, level, count, lookup_options, client_revision)
        self.assertEqual(count2, 1)
        self.assertEqual(names2.count, 1)
        self.assertEqual(names2.names[0].name.string,
                         "ANONYMOUS LOGON")

        # Just looking for any exceptions in the last couple of loops
        c.LookupSids3(sids, names, level, count, lookup_options, client_revision)
        c.LookupSids3(sids, names, level, count, lookup_options, client_revision)

    def test_lsa_LookupSids3_multiple_conns(self):
        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        c = lsa.lsarpc(
            "ncacn_ip_tcp:%s[schannel,seal]" % self.server,
            self.lp,
            machine_creds)

        sids = lsa.SidArray()
        sid = lsa.SidPtr()
        # Need a set
        x = dom_sid("S-1-5-7")
        sid.sid = x
        sids.sids = [sid]
        sids.num_sids = 1
        names = lsa.TransNameArray2()
        level = lsa.LSA_LOOKUP_NAMES_ALL
        count = 0
        lookup_options = lsa.LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES
        client_revision = lsa.LSA_CLIENT_REVISION_2

        # We want to run LookupSids3, and then again on a new
        # connection to show that we don't have an issue with the DB
        # being tied to the wrong connection.
        (domains, names, count) = c.LookupSids3(sids,
                                                names,
                                                level,
                                                count,
                                                lookup_options,
                                                client_revision)
        self.assertEqual(count, 1)
        self.assertEqual(names.count, 1)
        self.assertEqual(names.names[0].name.string,
                         "ANONYMOUS LOGON")

        c = lsa.lsarpc(
            "ncacn_ip_tcp:%s[schannel,seal]" % self.server,
            self.lp,
            machine_creds)

        (domains, names, count) = c.LookupSids3(sids,
                                                names,
                                                level,
                                                count,
                                                lookup_options,
                                                client_revision)
        self.assertEqual(count, 1)
        self.assertEqual(names.count, 1)
        self.assertEqual(names.names[0].name.string,
                         "ANONYMOUS LOGON")


    def test_lsa_LookupNames4_LookupSids3_multiple(self):
        """
        Test by going back and forward between real DB lookups
        name->sid->name to ensure the sam.ldb handle is fine once
        shared
        """

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        c_normal = lsa.lsarpc(
            "ncacn_np:%s[seal]" % self.server,
            self.lp,
            machine_creds)

        username, domain = c_normal.GetUserName(None, None, None)

        c = lsa.lsarpc(
            "ncacn_ip_tcp:%s[schannel,seal]" % self.server,
            self.lp,
            machine_creds)

        sids  = lsa.TransSidArray3()
        names = [username]
        level = lsa.LSA_LOOKUP_NAMES_ALL
        count = 0
        lookup_options = lsa.LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES
        client_revision = lsa.LSA_CLIENT_REVISION_2
        (domains, sids, count) = c.LookupNames4(names,
                                                sids,
                                                level,
                                                count,
                                                lookup_options,
                                                client_revision)

        # Another lookup on the same connection, will re-used the
        # server-side implicit state handle on the connection
        (domains, sids, count) = c.LookupNames4(names,
                                                sids,
                                                level,
                                                count,
                                                lookup_options,
                                                client_revision)

        self.assertEqual(count, 1)
        self.assertEqual(sids.count, 1)

        # Now look the SIDs back up
        names = lsa.TransNameArray2()
        sid = lsa.SidPtr()
        sid.sid = sids.sids[0].sid
        lookup_sids = lsa.SidArray()
        lookup_sids.sids = [sid]
        lookup_sids.num_sids = 1
        level = lsa.LSA_LOOKUP_NAMES_ALL
        count = 1
        lookup_options = 0
        client_revision = lsa.LSA_CLIENT_REVISION_2

        (domains, names, count) = c.LookupSids3(lookup_sids,
                                                names,
                                                level,
                                                count,
                                                lookup_options,
                                                client_revision)
        self.assertEqual(count, 1)
        self.assertEqual(names.count, 1)
        self.assertEqual(names.names[0].name.string,
                         username.string)

        # And once more just to be sure, just checking for a fault
        sids  = lsa.TransSidArray3()
        names = [username]
        level = lsa.LSA_LOOKUP_NAMES_ALL
        count = 0
        lookup_options = lsa.LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES
        client_revision = lsa.LSA_CLIENT_REVISION_2
        (domains, sids, count) = c.LookupNames4(names,
                                                sids,
                                                level,
                                                count,
                                                lookup_options,
                                                client_revision)


    def test_lsa_LookupNames4_multiple_conns(self):
        """
        Test by going back and forward between real DB lookups
        name->sid->name to ensure the sam.ldb handle is fine once
        shared
        """

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        c_normal = lsa.lsarpc(
            "ncacn_np:%s[seal]" % self.server,
            self.lp,
            machine_creds)

        username, domain = c_normal.GetUserName(None, None, None)

        c = lsa.lsarpc(
            "ncacn_ip_tcp:%s[schannel,seal]" % self.server,
            self.lp,
            machine_creds)

        sids  = lsa.TransSidArray3()
        names = [username]
        level = lsa.LSA_LOOKUP_NAMES_ALL
        count = 0
        lookup_options = lsa.LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES
        client_revision = lsa.LSA_CLIENT_REVISION_2
        (domains, sids, count) = c.LookupNames4(names,
                                                sids,
                                                level,
                                                count,
                                                lookup_options,
                                                client_revision)

        c = lsa.lsarpc(
            "ncacn_ip_tcp:%s[schannel,seal]" % self.server,
            self.lp,
            machine_creds)

        sids  = lsa.TransSidArray3()
        names = [username]
        level = lsa.LSA_LOOKUP_NAMES_ALL
        count = 0
        lookup_options = lsa.LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES
        client_revision = lsa.LSA_CLIENT_REVISION_2
        (domains, sids, count) = c.LookupNames4(names,
                                                sids,
                                                level,
                                                count,
                                                lookup_options,
                                                client_revision)

    def test_lsa_LookupNames4_without_schannel(self):

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        c_normal = lsa.lsarpc(
            "ncacn_np:%s[seal]" % self.server,
            self.lp,
            machine_creds)

        username, domain = c_normal.GetUserName(None, None, None)

        sids  = lsa.TransSidArray3()
        names = [username]
        level = lsa.LSA_LOOKUP_NAMES_ALL
        count = 0
        lookup_options = lsa.LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES
        client_revision = lsa.LSA_CLIENT_REVISION_2

        with self.assertRaises(NTSTATUSError) as e:
            c_normal.LookupNames4(names,
                                  sids,
                                  level,
                                  count,
                                  lookup_options,
                                  client_revision)
        if (e.exception.args[0] != NT_STATUS_ACCESS_DENIED):
            raise AssertionError("LookupNames4 without schannel must fail with ACCESS_DENIED")

    def test_lsa_LookupSids3_without_schannel(self):
        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        c = lsa.lsarpc(
            "ncacn_ip_tcp:%s[seal]" % self.server,
            self.lp,
            machine_creds)

        sids = lsa.SidArray()
        sid = lsa.SidPtr()
        # Need a set
        x = dom_sid("S-1-5-7")
        sid.sid = x
        sids.sids = [sid]
        sids.num_sids = 1
        names = lsa.TransNameArray2()
        level = lsa.LSA_LOOKUP_NAMES_ALL
        count = 0
        lookup_options = lsa.LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES
        client_revision = lsa.LSA_CLIENT_REVISION_2

        with self.assertRaises(NTSTATUSError) as e:
            c.LookupSids3(sids,
                          names,
                          level,
                          count,
                          lookup_options,
                          client_revision)
        if (e.exception.args[0] != NT_STATUS_ACCESS_DENIED):
            raise AssertionError("LookupSids3 without schannel must fail with ACCESS_DENIED")

    def test_lsa_LookupSids2_none_mapped(self):
        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        c = lsa.lsarpc(
            "ncacn_np:%s[print]" % self.server,
            self.lp,
            machine_creds,
            raise_result_exceptions=False)

        objectAttr = lsa.ObjectAttribute()
        objectAttr.sec_qos = lsa.QosInfo()

        (pol_handle, status) = c.OpenPolicy2('',
                                             objectAttr,
                                             security.SEC_FLAG_MAXIMUM_ALLOWED)
        self.assertEqual(status[0], NT_STATUS_OK)
        self.assertIsNotNone(pol_handle)

        x0 = dom_sid("S-1-3-66")
        sid0 = lsa.SidPtr()
        sid0.sid = x0
        x1 = dom_sid("S-1-3-77")
        sid1 = lsa.SidPtr()
        sid1.sid = x1
        x2 = dom_sid("S-1-3-88")
        sid2 = lsa.SidPtr()
        sid2.sid = x2
        x3 = dom_sid("S-1-3-99")
        sid3 = lsa.SidPtr()
        sid3.sid = x3
        sids = lsa.SidArray()
        sids.sids = [sid0,sid1,sid2,sid3]
        sids.num_sids = 4

        names = lsa.TransNameArray2()
        level = lsa.LSA_LOOKUP_NAMES_ALL
        count = 0
        lookup_options = lsa.LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES
        client_revision = lsa.LSA_CLIENT_REVISION_2

        (domains, names, count, status) = c.LookupSids2(pol_handle,
                                                        sids,
                                                        names,
                                                        level,
                                                        count,
                                                        lookup_options,
                                                        client_revision)
        self.assertEqual(status[0], NT_STATUS_NONE_MAPPED)
        self.assertEqual(count, 0)
        self.assertIsNotNone(domains)
        self.assertEqual(domains.count, 0)
        self.assertIsNotNone(names)
        self.assertEqual(names.count, 4)
        self.assertEqual(names.names[0].sid_type, lsa.SID_NAME_UNKNOWN)
        self.assertEqual(names.names[0].name.string, str(x0))
        self.assertEqual(names.names[0].sid_index, 0xffffffff)
        self.assertEqual(names.names[1].sid_type, lsa.SID_NAME_UNKNOWN)
        self.assertEqual(names.names[1].name.string, str(x1))
        self.assertEqual(names.names[1].sid_index, 0xffffffff)
        self.assertEqual(names.names[2].sid_type, lsa.SID_NAME_UNKNOWN)
        self.assertEqual(names.names[2].name.string, str(x2))
        self.assertEqual(names.names[2].sid_index, 0xffffffff)
        self.assertEqual(names.names[3].sid_type, lsa.SID_NAME_UNKNOWN)
        self.assertEqual(names.names[3].name.string, str(x3))
        self.assertEqual(names.names[3].sid_index, 0xffffffff)

        return

    def test_lsa_LookupSids2_some_not_mapped(self):
        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        c = lsa.lsarpc(
            "ncacn_np:%s[print]" % self.server,
            self.lp,
            machine_creds,
            raise_result_exceptions=False)

        objectAttr = lsa.ObjectAttribute()
        objectAttr.sec_qos = lsa.QosInfo()

        (pol_handle, status) = c.OpenPolicy2('',
                                             objectAttr,
                                             security.SEC_FLAG_MAXIMUM_ALLOWED)
        self.assertEqual(status[0], NT_STATUS_OK)
        self.assertIsNotNone(pol_handle)

        dx0 = dom_sid("S-1-3")

        x0 = dom_sid("S-1-3-66")
        sid0 = lsa.SidPtr()
        sid0.sid = x0
        x1 = dom_sid("S-1-3-0")
        sid1 = lsa.SidPtr()
        sid1.sid = x1
        x2 = dom_sid("S-1-3")
        sid2 = lsa.SidPtr()
        sid2.sid = x2
        x3 = dom_sid("S-1-3-99")
        sid3 = lsa.SidPtr()
        sid3.sid = x3
        sids = lsa.SidArray()
        sids.sids = [sid0,sid1,sid2,sid3]
        sids.num_sids = 4

        names = lsa.TransNameArray2()
        level = lsa.LSA_LOOKUP_NAMES_ALL
        count = 0
        lookup_options = lsa.LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES
        client_revision = lsa.LSA_CLIENT_REVISION_2

        (domains, names, count, status) = c.LookupSids2(pol_handle,
                                                        sids,
                                                        names,
                                                        level,
                                                        count,
                                                        lookup_options,
                                                        client_revision)
        self.assertEqual(status[0], NT_STATUS_SOME_NOT_MAPPED)
        self.assertEqual(count, 1)
        self.assertIsNotNone(domains)
        self.assertEqual(domains.count, 1)
        self.assertEqual(domains.domains[0].name.string, "")
        self.assertEqual(domains.domains[0].sid, dx0)
        self.assertIsNotNone(names)
        self.assertEqual(names.count, 4)
        self.assertEqual(names.names[0].sid_type, lsa.SID_NAME_UNKNOWN)
        self.assertEqual(names.names[0].name.string, str(x0))
        self.assertEqual(names.names[0].sid_index, 0xffffffff)
        self.assertEqual(names.names[1].sid_type, lsa.SID_NAME_WKN_GRP)
        self.assertEqual(names.names[1].name.string, "CREATOR OWNER")
        self.assertEqual(names.names[1].sid_index, 0)
        self.assertEqual(names.names[2].sid_type, lsa.SID_NAME_UNKNOWN)
        self.assertEqual(names.names[2].name.string, str(x2))
        self.assertEqual(names.names[2].sid_index, 0xffffffff)
        self.assertEqual(names.names[3].sid_type, lsa.SID_NAME_UNKNOWN)
        self.assertEqual(names.names[3].name.string, str(x3))
        self.assertEqual(names.names[3].sid_index, 0xffffffff)

        return

    def test_lsa_LookupSids2_invalid_sid(self):
        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        c = lsa.lsarpc(
            "ncacn_np:%s[print]" % self.server,
            self.lp,
            machine_creds,
            raise_result_exceptions=False)

        objectAttr = lsa.ObjectAttribute()
        objectAttr.sec_qos = lsa.QosInfo()

        (pol_handle, status) = c.OpenPolicy2('',
                                             objectAttr,
                                             security.SEC_FLAG_MAXIMUM_ALLOWED)
        self.assertEqual(status[0], NT_STATUS_OK)
        self.assertIsNotNone(pol_handle)

        dx0 = dom_sid("S-1-3")

        x0 = dom_sid("S-1-3-66")
        sid0 = lsa.SidPtr()
        sid0.sid = x0
        x1 = dom_sid("S-1-3-77")
        sid1 = lsa.SidPtr()
        sid1.sid = x1
        x2 = dom_sid("S-1-3")
        sid2 = lsa.SidPtr()
        sid2.sid = x2
        x3 = dom_sid("S-1-3-99")
        sid3 = lsa.SidPtr()
        sid3.sid = x3
        sids = lsa.SidArray()
        sids.sids = [sid0,sid1,sid2,sid3]
        sids.num_sids = 4

        names = lsa.TransNameArray2()
        level = lsa.LSA_LOOKUP_NAMES_ALL
        count = 0
        lookup_options = lsa.LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES
        client_revision = lsa.LSA_CLIENT_REVISION_2

        (domains, names, count, status) = c.LookupSids2(pol_handle,
                                                        sids,
                                                        names,
                                                        level,
                                                        count,
                                                        lookup_options,
                                                        client_revision)
        self.assertEqual(status[0], NT_STATUS_INVALID_SID)
        self.assertEqual(count, 0)
        self.assertIsNotNone(domains)
        self.assertEqual(domains.count, 0)
        self.assertIsNotNone(names)
        self.assertEqual(names.count, 4)
        self.assertEqual(names.names[0].sid_type, lsa.SID_NAME_UNKNOWN)
        self.assertIsNone(names.names[0].name.string)
        self.assertEqual(names.names[0].sid_index, 0xffffffff)
        self.assertEqual(names.names[1].sid_type, lsa.SID_NAME_UNKNOWN)
        self.assertIsNone(names.names[1].name.string)
        self.assertEqual(names.names[1].sid_index, 0xffffffff)
        self.assertEqual(names.names[2].sid_type, lsa.SID_NAME_UNKNOWN)
        self.assertIsNone(names.names[2].name.string)
        self.assertEqual(names.names[2].sid_index, 0xffffffff)
        self.assertEqual(names.names[3].sid_type, lsa.SID_NAME_UNKNOWN)
        self.assertIsNone(names.names[3].name.string)
        self.assertEqual(names.names[3].sid_index, 0xffffffff)

        return
