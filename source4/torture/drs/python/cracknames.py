#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) Catalyst .Net Ltd 2017
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

import samba.tests
import ldb
import drs_base

from samba.dcerpc import drsuapi


class DrsCracknamesTestCase(drs_base.DrsBaseTestCase):
    def setUp(self):
        super(DrsCracknamesTestCase, self).setUp()
        (self.drs, self.drs_handle) = self._ds_bind(self.dnsname_dc1)

        self.ou = "ou=Cracknames_ou,%s" % self.ldb_dc1.get_default_basedn()
        self.username = "Cracknames_user"
        self.user = "cn=%s,%s" % (self.username, self.ou)

        self.ldb_dc1.add({
            "dn": self.ou,
            "objectclass": "organizationalUnit"})

        self.user_record = {
            "dn": self.user,
            "objectclass": "user",
            "sAMAccountName": self.username,
            "userPrincipalName": "test@test.com",
            "servicePrincipalName": "test/%s" % self.ldb_dc1.get_default_basedn(),
            "displayName": "test"}

        self.ldb_dc1.add(self.user_record)
        self.ldb_dc1.delete(self.user_record["dn"])
        self.ldb_dc1.add(self.user_record)

        # The formats specified in MS-DRSR 4.1.4.13; DS_NAME_FORMAT
        # We don't support any of the ones specified in 4.1.4.1.2.
        self.formats = {
            drsuapi.DRSUAPI_DS_NAME_FORMAT_FQDN_1779,
            drsuapi.DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT,
            drsuapi.DRSUAPI_DS_NAME_FORMAT_DISPLAY,
            drsuapi.DRSUAPI_DS_NAME_FORMAT_GUID,
            drsuapi.DRSUAPI_DS_NAME_FORMAT_CANONICAL,
            drsuapi.DRSUAPI_DS_NAME_FORMAT_USER_PRINCIPAL,
            drsuapi.DRSUAPI_DS_NAME_FORMAT_CANONICAL_EX,
            drsuapi.DRSUAPI_DS_NAME_FORMAT_SERVICE_PRINCIPAL,
            # We currently don't support this
            # drsuapi.DRSUAPI_DS_NAME_FORMAT_SID_OR_SID_HISTORY,
            # This format is not supported by Windows (or us)
            # drsuapi.DRSUAPI_DS_NAME_FORMAT_DNS_DOMAIN,
        }

    def tearDown(self):
        self.ldb_dc1.delete(self.user)
        self.ldb_dc1.delete(self.ou)
        super(DrsCracknamesTestCase, self).tearDown()

    def test_Cracknames(self):
        """
        Verifies that we can cracknames any of the standard formats
        (DS_NAME_FORMAT) to a GUID, and that we can cracknames a
        GUID to any of the standard formats.

        GUID was chosen just so that we don't have to do an n^2 loop.
        """
        (result, ctr) = self._do_cracknames(self.user,
                                            drsuapi.DRSUAPI_DS_NAME_FORMAT_FQDN_1779,
                                            drsuapi.DRSUAPI_DS_NAME_FORMAT_GUID)

        self.assertEqual(ctr.count, 1)
        self.assertEqual(ctr.array[0].status,
                          drsuapi.DRSUAPI_DS_NAME_STATUS_OK)

        user_guid = ctr.array[0].result_name

        for name_format in self.formats:
            (result, ctr) = self._do_cracknames(user_guid,
                                                drsuapi.DRSUAPI_DS_NAME_FORMAT_GUID,
                                                name_format)

            self.assertEqual(ctr.count, 1)
            self.assertEqual(ctr.array[0].status,
                              drsuapi.DRSUAPI_DS_NAME_STATUS_OK,
                              "Expected 0, got %s, desired format is %s"
                              % (ctr.array[0].status, name_format))

            (result, ctr) = self._do_cracknames(ctr.array[0].result_name,
                                                name_format,
                                                drsuapi.DRSUAPI_DS_NAME_FORMAT_GUID)

            self.assertEqual(ctr.count, 1)
            self.assertEqual(ctr.array[0].status,
                              drsuapi.DRSUAPI_DS_NAME_STATUS_OK,
                              "Expected 0, got %s, offered format is %s"
                              % (ctr.array[0].status, name_format))

    def test_MultiValuedAttribute(self):
        """
        Verifies that, if we try and cracknames with the desired output
        being a multi-valued attribute, it returns
        DRSUAPI_DS_NAME_STATUS_NOT_UNIQUE.
        """
        username = "Cracknames_user_MVA"
        user = "cn=%s,%s" % (username, self.ou)

        user_record = {
            "dn": user,
            "objectclass": "user",
            "sAMAccountName": username,
            "userPrincipalName": "test2@test.com",
            "servicePrincipalName": ["test2/%s" % self.ldb_dc1.get_default_basedn(),
                                     "test3/%s" % self.ldb_dc1.get_default_basedn()],
            "displayName": "test2"}

        self.ldb_dc1.add(user_record)

        (result, ctr) = self._do_cracknames(user,
                                            drsuapi.DRSUAPI_DS_NAME_FORMAT_FQDN_1779,
                                            drsuapi.DRSUAPI_DS_NAME_FORMAT_GUID)

        self.assertEqual(ctr.count, 1)
        self.assertEqual(ctr.array[0].status,
                          drsuapi.DRSUAPI_DS_NAME_STATUS_OK)

        user_guid = ctr.array[0].result_name

        (result, ctr) = self._do_cracknames(user_guid,
                                            drsuapi.DRSUAPI_DS_NAME_FORMAT_GUID,
                                            drsuapi.DRSUAPI_DS_NAME_FORMAT_SERVICE_PRINCIPAL)

        self.assertEqual(ctr.count, 1)
        self.assertEqual(ctr.array[0].status,
                          drsuapi.DRSUAPI_DS_NAME_STATUS_NOT_UNIQUE)

        self.ldb_dc1.delete(user)

    def test_NoSPNAttribute(self):
        """
        Verifies that, if we try and cracknames with the desired output
        being an SPN, it returns
        DRSUAPI_DS_NAME_STATUS_NOT_UNIQUE.
        """
        username = "Cracknames_no_SPN"
        user = "cn=%s,%s" % (username, self.ou)

        user_record = {
            "dn": user,
            "objectclass": "user",
            "sAMAccountName" : username,
            "userPrincipalName" : "test4@test.com",
            "displayName" : "test4"}

        self.ldb_dc1.add(user_record)

        (result, ctr) = self._do_cracknames(user,
                                            drsuapi.DRSUAPI_DS_NAME_FORMAT_FQDN_1779,
                                            drsuapi.DRSUAPI_DS_NAME_FORMAT_GUID)

        self.assertEqual(ctr.count, 1)
        self.assertEqual(ctr.array[0].status,
                          drsuapi.DRSUAPI_DS_NAME_STATUS_OK)

        user_guid = ctr.array[0].result_name

        (result, ctr) = self._do_cracknames(user_guid,
                                            drsuapi.DRSUAPI_DS_NAME_FORMAT_GUID,
                                            drsuapi.DRSUAPI_DS_NAME_FORMAT_SERVICE_PRINCIPAL)

        self.assertEqual(ctr.count, 1)
        self.assertEqual(ctr.array[0].status,
                          drsuapi.DRSUAPI_DS_NAME_STATUS_NOT_FOUND)

        self.ldb_dc1.delete(user)

    def _do_cracknames(self, name, format_offered, format_desired):
        req = drsuapi.DsNameRequest1()
        names = drsuapi.DsNameString()
        names.str = name

        req.codepage = 1252  # German, but it doesn't really matter here
        req.language = 1033
        req.format_flags = 0
        req.format_offered = format_offered
        req.format_desired = format_desired
        req.count = 1
        req.names = [names]

        (result, ctr) = self.drs.DsCrackNames(self.drs_handle, 1, req)
        return (result, ctr)
