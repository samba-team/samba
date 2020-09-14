#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Test replication scenarios involving an RODC
#
# Copyright (C) Catalyst.Net Ltd. 2017
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

#
# Usage:
#  export DC1=dc1_dns_name
#  export DC2=dc1_dns_name [this is unused for the test, but it'll still try to connect]
#  export SUBUNITRUN=$samba4srcdir/scripting/bin/subunitrun
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" $SUBUNITRUN repl_rodc -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

import drs_base
import samba.tests
import ldb
from ldb import SCOPE_BASE

from samba import WERRORError
from samba.join import DCJoinContext
from samba.dcerpc import drsuapi, misc, drsblobs, security
from samba.drs_utils import drs_DsBind, drs_Replicate
from samba.ndr import ndr_unpack, ndr_pack
from samba.samdb import dsdb_Dn
from samba.credentials import Credentials

import random
import time


def drs_get_rodc_partial_attribute_set(samdb, samdb1, exceptions=[]):
    '''get a list of attributes for RODC replication'''
    partial_attribute_set = drsuapi.DsPartialAttributeSet()
    partial_attribute_set.version = 1

    attids = []

    # the exact list of attids we send is quite critical. Note that
    # we do ask for the secret attributes, but set SPECIAL_SECRET_PROCESSING
    # to zero them out
    schema_dn = samdb.get_schema_basedn()
    res = samdb.search(base=schema_dn, scope=ldb.SCOPE_SUBTREE,
                       expression="objectClass=attributeSchema",
                       attrs=["lDAPDisplayName", "systemFlags",
                              "searchFlags"])

    for r in res:
        ldap_display_name = str(r["lDAPDisplayName"][0])
        if "systemFlags" in r:
            system_flags      = str(r["systemFlags"][0])
            if (int(system_flags) & (samba.dsdb.DS_FLAG_ATTR_NOT_REPLICATED |
                                     samba.dsdb.DS_FLAG_ATTR_IS_CONSTRUCTED)):
                continue
        if "searchFlags" in r:
            search_flags = str(r["searchFlags"][0])
            if (int(search_flags) & samba.dsdb.SEARCH_FLAG_RODC_ATTRIBUTE):
                continue
        try:
            attid = samdb1.get_attid_from_lDAPDisplayName(ldap_display_name)
            if attid not in exceptions:
                attids.append(int(attid))
        except:
            pass

    # the attids do need to be sorted, or windows doesn't return
    # all the attributes we need
    attids.sort()
    partial_attribute_set.attids         = attids
    partial_attribute_set.num_attids = len(attids)
    return partial_attribute_set


class DrsRodcTestCase(drs_base.DrsBaseTestCase):
    """Intended as a semi-black box test case for replication involving
       an RODC."""

    def setUp(self):
        super(DrsRodcTestCase, self).setUp()
        self.base_dn = self.ldb_dc1.get_default_basedn()

        self.ou = samba.tests.create_test_ou(self.ldb_dc1, "test_drs_rodc")
        self.allowed_group = "CN=Allowed RODC Password Replication Group,CN=Users,%s" % self.base_dn

        self.site = self.ldb_dc1.server_site_name()
        self.rodc_name = "TESTRODCDRS%s" % random.randint(1, 10000000)
        self.rodc_pass = "password12#"
        self.computer_dn = "CN=%s,OU=Domain Controllers,%s" % (self.rodc_name, self.base_dn)

        self.rodc_ctx = DCJoinContext(server=self.ldb_dc1.host_dns_name(),
                                      creds=self.get_credentials(),
                                      lp=self.get_loadparm(), site=self.site,
                                      netbios_name=self.rodc_name,
                                      targetdir=None, domain=None,
                                      machinepass=self.rodc_pass)
        self._create_rodc(self.rodc_ctx)
        self.rodc_ctx.create_tmp_samdb()
        self.tmp_samdb = self.rodc_ctx.tmp_samdb

        rodc_creds = Credentials()
        rodc_creds.guess(self.rodc_ctx.lp)
        rodc_creds.set_username(self.rodc_name + '$')
        rodc_creds.set_password(self.rodc_pass)
        self.rodc_creds = rodc_creds

        (self.drs, self.drs_handle) = self._ds_bind(self.dnsname_dc1)
        (self.rodc_drs, self.rodc_drs_handle) = self._ds_bind(self.dnsname_dc1, rodc_creds)

    def tearDown(self):
        self.rodc_ctx.cleanup_old_join()
        super(DrsRodcTestCase, self).tearDown()

    def test_admin_repl_secrets(self):
        """
        When a secret attribute is set to be replicated to an RODC with the
        admin credentials, it should always replicate regardless of whether
        or not it's in the Allowed RODC Password Replication Group.
        """
        rand = random.randint(1, 10000000)
        expected_user_attributes = [drsuapi.DRSUAPI_ATTID_lmPwdHistory,
                                    drsuapi.DRSUAPI_ATTID_supplementalCredentials,
                                    drsuapi.DRSUAPI_ATTID_ntPwdHistory,
                                    drsuapi.DRSUAPI_ATTID_unicodePwd,
                                    drsuapi.DRSUAPI_ATTID_dBCSPwd]

        user_name = "test_rodcA_%s" % rand
        user_dn = "CN=%s,%s" % (user_name, self.ou)
        self.ldb_dc1.add({
            "dn": user_dn,
            "objectclass": "user",
            "sAMAccountName": user_name
        })

        # Store some secret on this user
        self.ldb_dc1.setpassword("(sAMAccountName=%s)" % user_name, 'penguin12#', False, user_name)

        req10 = self._getnc_req10(dest_dsa=str(self.rodc_ctx.ntds_guid),
                                  invocation_id=self.ldb_dc1.get_invocation_id(),
                                  nc_dn_str=user_dn,
                                  exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET,
                                  partial_attribute_set=drs_get_rodc_partial_attribute_set(self.ldb_dc1, self.tmp_samdb),
                                  max_objects=133,
                                  replica_flags=0)
        (level, ctr) = self.drs.DsGetNCChanges(self.drs_handle, 10, req10)

        # Check that the user has been added to msDSRevealedUsers
        self._assert_in_revealed_users(user_dn, expected_user_attributes)

    def test_rodc_repl_secrets(self):
        """
        When a secret attribute is set to be replicated to an RODC with
        the RODC account credentials, it should not replicate if it's in
        the Allowed RODC Password Replication Group. Once it is added to
        the group, it should replicate.
        """
        rand = random.randint(1, 10000000)
        expected_user_attributes = [drsuapi.DRSUAPI_ATTID_lmPwdHistory,
                                    drsuapi.DRSUAPI_ATTID_supplementalCredentials,
                                    drsuapi.DRSUAPI_ATTID_ntPwdHistory,
                                    drsuapi.DRSUAPI_ATTID_unicodePwd,
                                    drsuapi.DRSUAPI_ATTID_dBCSPwd]

        user_name = "test_rodcB_%s" % rand
        user_dn = "CN=%s,%s" % (user_name, self.ou)
        self.ldb_dc1.add({
            "dn": user_dn,
            "objectclass": "user",
            "sAMAccountName": user_name
        })

        # Store some secret on this user
        self.ldb_dc1.setpassword("(sAMAccountName=%s)" % user_name, 'penguin12#', False, user_name)

        req10 = self._getnc_req10(dest_dsa=str(self.rodc_ctx.ntds_guid),
                                  invocation_id=self.ldb_dc1.get_invocation_id(),
                                  nc_dn_str=user_dn,
                                  exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET,
                                  partial_attribute_set=drs_get_rodc_partial_attribute_set(self.ldb_dc1, self.tmp_samdb),
                                  max_objects=133,
                                  replica_flags=0)

        try:
            (level, ctr) = self.rodc_drs.DsGetNCChanges(self.rodc_drs_handle, 10, req10)
            self.fail("Successfully replicated secrets to an RODC that shouldn't have been replicated.")
        except WERRORError as e:
            (enum, estr) = e.args
            self.assertEqual(enum, 8630)  # ERROR_DS_DRA_SECRETS_DENIED

        # send the same request again and we should get the same response
        try:
            (level, ctr) = self.rodc_drs.DsGetNCChanges(self.rodc_drs_handle, 10, req10)
            self.fail("Successfully replicated secrets to an RODC that shouldn't have been replicated.")
        except WERRORError as e1:
            (enum, estr) = e1.args
            self.assertEqual(enum, 8630)  # ERROR_DS_DRA_SECRETS_DENIED

        # Retry with Administrator credentials, ignores password replication groups
        (level, ctr) = self.drs.DsGetNCChanges(self.drs_handle, 10, req10)

        # Check that the user has been added to msDSRevealedUsers
        self._assert_in_revealed_users(user_dn, expected_user_attributes)

    def test_rodc_repl_secrets_follow_on_req(self):
        """
        Checks that an RODC can't subvert an existing (valid) GetNCChanges
        request to reveal secrets it shouldn't have access to.
        """

        # send an acceptable request that will match as many GUIDs as possible.
        # Here we set the SPECIAL_SECRET_PROCESSING flag so that the request gets accepted.
        # (On the server, this builds up the getnc_state->guids array)
        req8 = self._exop_req8(dest_dsa=str(self.rodc_ctx.ntds_guid),
                               invocation_id=self.ldb_dc1.get_invocation_id(),
                               nc_dn_str=self.ldb_dc1.domain_dn(),
                               exop=drsuapi.DRSUAPI_EXOP_NONE,
                               max_objects=1,
                               replica_flags=drsuapi.DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING)
        (level, ctr) = self.rodc_drs.DsGetNCChanges(self.rodc_drs_handle, 8, req8)

        # Get the next replication chunk, but set REPL_SECRET this time. This
        # is following on the the previous accepted request, but we've changed
        # exop to now request secrets. This request should fail
        try:
            req8 = self._exop_req8(dest_dsa=str(self.rodc_ctx.ntds_guid),
                                   invocation_id=self.ldb_dc1.get_invocation_id(),
                                   nc_dn_str=self.ldb_dc1.domain_dn(),
                                   exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET)
            req8.highwatermark = ctr.new_highwatermark

            (level, ctr) = self.rodc_drs.DsGetNCChanges(self.rodc_drs_handle, 8, req8)

            self.fail("Successfully replicated secrets to an RODC that shouldn't have been replicated.")
        except RuntimeError as e2:
            (enum, estr) = e2.args
            pass

    def test_msDSRevealedUsers_admin(self):
        """
        When a secret attribute is to be replicated to an RODC, the contents
        of the attribute should be added to the msDSRevealedUsers attribute
        of the computer object corresponding to the RODC.
        """

        rand = random.randint(1, 10000000)
        expected_user_attributes = [drsuapi.DRSUAPI_ATTID_lmPwdHistory,
                                    drsuapi.DRSUAPI_ATTID_supplementalCredentials,
                                    drsuapi.DRSUAPI_ATTID_ntPwdHistory,
                                    drsuapi.DRSUAPI_ATTID_unicodePwd,
                                    drsuapi.DRSUAPI_ATTID_dBCSPwd]

        # Add a user on DC1, add it to allowed password replication
        # group, and replicate to RODC with EXOP_REPL_SECRETS
        user_name = "test_rodcC_%s" % rand
        password = "password12#"
        user_dn = "CN=%s,%s" % (user_name, self.ou)
        self.ldb_dc1.add({
            "dn": user_dn,
            "objectclass": "user",
            "sAMAccountName": user_name
        })

        # Store some secret on this user
        self.ldb_dc1.setpassword("(sAMAccountName=%s)" % user_name, password, False, user_name)

        self.ldb_dc1.add_remove_group_members("Allowed RODC Password Replication Group",
                                              [user_name],
                                              add_members_operation=True)

        req10 = self._getnc_req10(dest_dsa=str(self.rodc_ctx.ntds_guid),
                                  invocation_id=self.ldb_dc1.get_invocation_id(),
                                  nc_dn_str=user_dn,
                                  exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET,
                                  partial_attribute_set=drs_get_rodc_partial_attribute_set(self.ldb_dc1, self.tmp_samdb),
                                  max_objects=133,
                                  replica_flags=0)
        (level, ctr) = self.drs.DsGetNCChanges(self.drs_handle, 10, req10)

        # Check that the user has been added to msDSRevealedUsers
        (packed_attrs_1, unpacked_attrs_1) = self._assert_in_revealed_users(user_dn, expected_user_attributes)

        # Change the user's password on DC1
        self.ldb_dc1.setpassword("(sAMAccountName=%s)" % user_name, password + "1", False, user_name)

        (packed_attrs_2, unpacked_attrs_2) = self._assert_in_revealed_users(user_dn, expected_user_attributes)
        self._assert_attrlist_equals(unpacked_attrs_1, unpacked_attrs_2)

        # Replicate to RODC again with EXOP_REPL_SECRETS
        req10 = self._getnc_req10(dest_dsa=str(self.rodc_ctx.ntds_guid),
                                  invocation_id=self.ldb_dc1.get_invocation_id(),
                                  nc_dn_str=user_dn,
                                  exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET,
                                  partial_attribute_set=drs_get_rodc_partial_attribute_set(self.ldb_dc1, self.tmp_samdb),
                                  max_objects=133,
                                  replica_flags=0)
        (level, ctr) = self.drs.DsGetNCChanges(self.drs_handle, 10, req10)

        # This is important for Windows, because the entry won't have been
        # updated in time if we don't have it. Even with this sleep, it only
        # passes some of the time...
        time.sleep(5)

        # Check that the entry in msDSRevealedUsers has been updated
        (packed_attrs_3, unpacked_attrs_3) = self._assert_in_revealed_users(user_dn, expected_user_attributes)
        self._assert_attrlist_changed(unpacked_attrs_2, unpacked_attrs_3, expected_user_attributes)

        # We should be able to delete the user
        self.ldb_dc1.deleteuser(user_name)

        res = self.ldb_dc1.search(scope=ldb.SCOPE_BASE, base=self.computer_dn,
                                  attrs=["msDS-RevealedUsers"])
        self.assertFalse("msDS-RevealedUsers" in res[0])

    def test_msDSRevealedUsers(self):
        """
        When a secret attribute is to be replicated to an RODC, the contents
        of the attribute should be added to the msDSRevealedUsers attribute
        of the computer object corresponding to the RODC.
        """

        rand = random.randint(1, 10000000)
        expected_user_attributes = [drsuapi.DRSUAPI_ATTID_lmPwdHistory,
                                    drsuapi.DRSUAPI_ATTID_supplementalCredentials,
                                    drsuapi.DRSUAPI_ATTID_ntPwdHistory,
                                    drsuapi.DRSUAPI_ATTID_unicodePwd,
                                    drsuapi.DRSUAPI_ATTID_dBCSPwd]

        # Add a user on DC1, add it to allowed password replication
        # group, and replicate to RODC with EXOP_REPL_SECRETS
        user_name = "test_rodcD_%s" % rand
        password = "password12#"
        user_dn = "CN=%s,%s" % (user_name, self.ou)
        self.ldb_dc1.add({
            "dn": user_dn,
            "objectclass": "user",
            "sAMAccountName": user_name
        })

        # Store some secret on this user
        self.ldb_dc1.setpassword("(sAMAccountName=%s)" % user_name, password, False, user_name)

        self.ldb_dc1.add_remove_group_members("Allowed RODC Password Replication Group",
                                              [user_name],
                                              add_members_operation=True)

        req10 = self._getnc_req10(dest_dsa=str(self.rodc_ctx.ntds_guid),
                                  invocation_id=self.ldb_dc1.get_invocation_id(),
                                  nc_dn_str=user_dn,
                                  exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET,
                                  partial_attribute_set=drs_get_rodc_partial_attribute_set(self.ldb_dc1, self.tmp_samdb),
                                  max_objects=133,
                                  replica_flags=0)
        (level, ctr) = self.drs.DsGetNCChanges(self.drs_handle, 10, req10)

        # Check that the user has been added to msDSRevealedUsers
        (packed_attrs_1, unpacked_attrs_1) = self._assert_in_revealed_users(user_dn, expected_user_attributes)

        # Change the user's password on DC1
        self.ldb_dc1.setpassword("(sAMAccountName=%s)" % user_name, password + "1", False, user_name)

        (packed_attrs_2, unpacked_attrs_2) = self._assert_in_revealed_users(user_dn, expected_user_attributes)
        self._assert_attrlist_equals(unpacked_attrs_1, unpacked_attrs_2)

        # Replicate to RODC again with EXOP_REPL_SECRETS
        req10 = self._getnc_req10(dest_dsa=str(self.rodc_ctx.ntds_guid),
                                  invocation_id=self.ldb_dc1.get_invocation_id(),
                                  nc_dn_str=user_dn,
                                  exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET,
                                  partial_attribute_set=drs_get_rodc_partial_attribute_set(self.ldb_dc1, self.tmp_samdb),
                                  max_objects=133,
                                  replica_flags=0)
        (level, ctr) = self.rodc_drs.DsGetNCChanges(self.rodc_drs_handle, 10, req10)

        # This is important for Windows, because the entry won't have been
        # updated in time if we don't have it. Even with this sleep, it only
        # passes some of the time...
        time.sleep(5)

        # Check that the entry in msDSRevealedUsers has been updated
        (packed_attrs_3, unpacked_attrs_3) = self._assert_in_revealed_users(user_dn, expected_user_attributes)
        self._assert_attrlist_changed(unpacked_attrs_2, unpacked_attrs_3, expected_user_attributes)

        # We should be able to delete the user
        self.ldb_dc1.deleteuser(user_name)

        res = self.ldb_dc1.search(scope=ldb.SCOPE_BASE, base=self.computer_dn,
                                  attrs=["msDS-RevealedUsers"])
        self.assertFalse("msDS-RevealedUsers" in res[0])

    def test_msDSRevealedUsers_pas(self):
        """
        If we provide a Partial Attribute Set when replicating to an RODC,
        we should ignore it and replicate all of the secret attributes anyway
        msDSRevealedUsers attribute.
        """
        rand = random.randint(1, 10000000)
        expected_user_attributes = [drsuapi.DRSUAPI_ATTID_lmPwdHistory,
                                    drsuapi.DRSUAPI_ATTID_supplementalCredentials,
                                    drsuapi.DRSUAPI_ATTID_ntPwdHistory,
                                    drsuapi.DRSUAPI_ATTID_unicodePwd,
                                    drsuapi.DRSUAPI_ATTID_dBCSPwd]
        pas_exceptions = [drsuapi.DRSUAPI_ATTID_lmPwdHistory,
                          drsuapi.DRSUAPI_ATTID_supplementalCredentials,
                          drsuapi.DRSUAPI_ATTID_ntPwdHistory,
                          drsuapi.DRSUAPI_ATTID_dBCSPwd]

        # Add a user on DC1, add it to allowed password replication
        # group, and replicate to RODC with EXOP_REPL_SECRETS
        user_name = "test_rodcE_%s" % rand
        password = "password12#"
        user_dn = "CN=%s,%s" % (user_name, self.ou)
        self.ldb_dc1.add({
            "dn": user_dn,
            "objectclass": "user",
            "sAMAccountName": user_name
        })

        # Store some secret on this user
        self.ldb_dc1.setpassword("(sAMAccountName=%s)" % user_name, password, False, user_name)

        self.ldb_dc1.add_remove_group_members("Allowed RODC Password Replication Group",
                                              [user_name],
                                              add_members_operation=True)

        pas = drs_get_rodc_partial_attribute_set(self.ldb_dc1, self.tmp_samdb, exceptions=pas_exceptions)
        req10 = self._getnc_req10(dest_dsa=str(self.rodc_ctx.ntds_guid),
                                  invocation_id=self.ldb_dc1.get_invocation_id(),
                                  nc_dn_str=user_dn,
                                  exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET,
                                  partial_attribute_set=pas,
                                  max_objects=133,
                                  replica_flags=0)
        (level, ctr) = self.drs.DsGetNCChanges(self.drs_handle, 10, req10)

        # Make sure that we still replicate the secrets
        for attribute in ctr.first_object.object.attribute_ctr.attributes:
            if attribute.attid in pas_exceptions:
                pas_exceptions.remove(attribute.attid)
        for attribute in pas_exceptions:
            self.fail("%d was not replicated even though the partial attribute set should be ignored."
                      % attribute)

        # Check that the user has been added to msDSRevealedUsers
        (packed_attrs_1, unpacked_attrs_1) = self._assert_in_revealed_users(user_dn, expected_user_attributes)

    def test_msDSRevealedUsers_using_other_RODC(self):
        """
        Ensure that the machine account is tied to the destination DSA.
        """
        # Create a new identical RODC with just the first letter missing
        other_rodc_name = self.rodc_name[1:]
        other_rodc_ctx = DCJoinContext(server=self.ldb_dc1.host_dns_name(),
                                       creds=self.get_credentials(),
                                       lp=self.get_loadparm(), site=self.site,
                                       netbios_name=other_rodc_name,
                                       targetdir=None, domain=None,
                                       machinepass=self.rodc_pass)
        self._create_rodc(other_rodc_ctx)

        other_rodc_creds = Credentials()
        other_rodc_creds.guess(other_rodc_ctx.lp)
        other_rodc_creds.set_username(other_rodc_name + '$')
        other_rodc_creds.set_password(self.rodc_pass)

        (other_rodc_drs, other_rodc_drs_handle) = self._ds_bind(self.dnsname_dc1, other_rodc_creds)

        rand = random.randint(1, 10000000)
        expected_user_attributes = [drsuapi.DRSUAPI_ATTID_lmPwdHistory,
                                    drsuapi.DRSUAPI_ATTID_supplementalCredentials,
                                    drsuapi.DRSUAPI_ATTID_ntPwdHistory,
                                    drsuapi.DRSUAPI_ATTID_unicodePwd,
                                    drsuapi.DRSUAPI_ATTID_dBCSPwd]

        user_name = "test_rodcF_%s" % rand
        user_dn = "CN=%s,%s" % (user_name, self.ou)
        self.ldb_dc1.add({
            "dn": user_dn,
            "objectclass": "user",
            "sAMAccountName": user_name
        })

        # Store some secret on this user
        self.ldb_dc1.setpassword("(sAMAccountName=%s)" % user_name, 'penguin12#', False, user_name)
        self.ldb_dc1.add_remove_group_members("Allowed RODC Password Replication Group",
                                              [user_name],
                                              add_members_operation=True)

        req10 = self._getnc_req10(dest_dsa=str(other_rodc_ctx.ntds_guid),
                                  invocation_id=self.ldb_dc1.get_invocation_id(),
                                  nc_dn_str=user_dn,
                                  exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET,
                                  partial_attribute_set=drs_get_rodc_partial_attribute_set(self.ldb_dc1, self.tmp_samdb),
                                  max_objects=133,
                                  replica_flags=0)

        try:
            (level, ctr) = self.rodc_drs.DsGetNCChanges(self.rodc_drs_handle, 10, req10)
            self.fail("Successfully replicated secrets to an RODC that shouldn't have been replicated.")
        except WERRORError as e3:
            (enum, estr) = e3.args
            self.assertEqual(enum, 8630)  # ERROR_DS_DRA_SECRETS_DENIED

        req10 = self._getnc_req10(dest_dsa=str(self.rodc_ctx.ntds_guid),
                                  invocation_id=self.ldb_dc1.get_invocation_id(),
                                  nc_dn_str=user_dn,
                                  exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET,
                                  partial_attribute_set=drs_get_rodc_partial_attribute_set(self.ldb_dc1, self.tmp_samdb),
                                  max_objects=133,
                                  replica_flags=0)

        try:
            (level, ctr) = other_rodc_drs.DsGetNCChanges(other_rodc_drs_handle, 10, req10)
            self.fail("Successfully replicated secrets to an RODC that shouldn't have been replicated.")
        except WERRORError as e4:
            (enum, estr) = e4.args
            self.assertEqual(enum, 8630)  # ERROR_DS_DRA_SECRETS_DENIED

    def test_msDSRevealedUsers_local_deny_allow(self):
        """
        Ensure that the deny trumps allow, and we can modify these
        attributes directly instead of the global groups.

        This may fail on Windows due to tokenGroup calculation caching.
        """
        rand = random.randint(1, 10000000)
        expected_user_attributes = [drsuapi.DRSUAPI_ATTID_lmPwdHistory,
                                    drsuapi.DRSUAPI_ATTID_supplementalCredentials,
                                    drsuapi.DRSUAPI_ATTID_ntPwdHistory,
                                    drsuapi.DRSUAPI_ATTID_unicodePwd,
                                    drsuapi.DRSUAPI_ATTID_dBCSPwd]

        # Add a user on DC1, add it to allowed password replication
        # group, and replicate to RODC with EXOP_REPL_SECRETS
        user_name = "test_rodcF_%s" % rand
        password = "password12#"
        user_dn = "CN=%s,%s" % (user_name, self.ou)
        self.ldb_dc1.add({
            "dn": user_dn,
            "objectclass": "user",
            "sAMAccountName": user_name
        })

        # Store some secret on this user
        self.ldb_dc1.setpassword("(sAMAccountName=%s)" % user_name, password, False, user_name)

        req10 = self._getnc_req10(dest_dsa=str(self.rodc_ctx.ntds_guid),
                                  invocation_id=self.ldb_dc1.get_invocation_id(),
                                  nc_dn_str=user_dn,
                                  exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET,
                                  partial_attribute_set=drs_get_rodc_partial_attribute_set(self.ldb_dc1, self.tmp_samdb),
                                  max_objects=133,
                                  replica_flags=0)

        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb_dc1, self.computer_dn)

        m["msDS-RevealOnDemandGroup"] = \
            ldb.MessageElement(user_dn, ldb.FLAG_MOD_ADD,
                               "msDS-RevealOnDemandGroup")
        self.ldb_dc1.modify(m)

        # In local allow, should be success
        try:
            (level, ctr) = self.rodc_drs.DsGetNCChanges(self.rodc_drs_handle, 10, req10)
        except:
            self.fail("Should have succeeded when in local allow group")

        self._assert_in_revealed_users(user_dn, expected_user_attributes)

        (self.rodc_drs, self.rodc_drs_handle) = self._ds_bind(self.dnsname_dc1, self.rodc_creds)

        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb_dc1, self.computer_dn)

        m["msDS-NeverRevealGroup"] = \
            ldb.MessageElement(user_dn, ldb.FLAG_MOD_ADD,
                               "msDS-NeverRevealGroup")
        self.ldb_dc1.modify(m)

        # In local allow and deny, should be failure
        try:
            (level, ctr) = self.rodc_drs.DsGetNCChanges(self.rodc_drs_handle, 10, req10)
            self.fail("Successfully replicated secrets to an RODC that shouldn't have been replicated.")
        except WERRORError as e5:
            (enum, estr) = e5.args
            self.assertEqual(enum, 8630)  # ERROR_DS_DRA_SECRETS_DENIED

        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb_dc1, self.computer_dn)

        m["msDS-RevealOnDemandGroup"] = \
            ldb.MessageElement(user_dn, ldb.FLAG_MOD_DELETE,
                               "msDS-RevealOnDemandGroup")
        self.ldb_dc1.modify(m)

        # In local deny, should be failure
        (self.rodc_drs, self.rodc_drs_handle) = self._ds_bind(self.dnsname_dc1, self.rodc_creds)
        try:
            (level, ctr) = self.rodc_drs.DsGetNCChanges(self.rodc_drs_handle, 10, req10)
            self.fail("Successfully replicated secrets to an RODC that shouldn't have been replicated.")
        except WERRORError as e6:
            (enum, estr) = e6.args
            self.assertEqual(enum, 8630)  # ERROR_DS_DRA_SECRETS_DENIED

    def _assert_in_revealed_users(self, user_dn, attrlist):
        res = self.ldb_dc1.search(scope=ldb.SCOPE_BASE, base=self.computer_dn,
                                  attrs=["msDS-RevealedUsers"])
        revealed_users = res[0]["msDS-RevealedUsers"]
        actual_attrids = []
        packed_attrs = []
        unpacked_attrs = []
        for attribute in revealed_users:
            attribute = attribute.decode('utf8')
            dsdb_dn = dsdb_Dn(self.ldb_dc1, attribute)
            metadata = ndr_unpack(drsblobs.replPropertyMetaData1, dsdb_dn.get_bytes())
            if user_dn in attribute:
                unpacked_attrs.append(metadata)
                packed_attrs.append(dsdb_dn.get_bytes())
                actual_attrids.append(metadata.attid)

        self.assertEqual(sorted(actual_attrids), sorted(attrlist))

        return (packed_attrs, unpacked_attrs)

    def _assert_attrlist_equals(self, list_1, list_2):
        return self._assert_attrlist_changed(list_1, list_2, [], num_changes=0, expected_new_usn=False)

    def _assert_attrlist_changed(self, list_1, list_2, changed_attributes, num_changes=1, expected_new_usn=True):
        for i in range(len(list_2)):
            self.assertEqual(list_1[i].attid, list_2[i].attid)
            self.assertEqual(list_1[i].originating_invocation_id, list_2[i].originating_invocation_id)
            self.assertEqual(list_1[i].version + num_changes, list_2[i].version)

            if expected_new_usn:
                self.assertTrue(list_1[i].originating_usn < list_2[i].originating_usn)
                self.assertTrue(list_1[i].local_usn < list_2[i].local_usn)
            else:
                self.assertEqual(list_1[i].originating_usn, list_2[i].originating_usn)
                self.assertEqual(list_1[i].local_usn, list_2[i].local_usn)

            if list_1[i].attid in changed_attributes:
                # We do the changes too quickly, so unless we put sleeps
                # inbetween calls, these remain the same. Checking the USNs
                # is enough.
                pass
                #self.assertTrue(list_1[i].originating_change_time < list_2[i].originating_change_time)
            else:
                self.assertEqual(list_1[i].originating_change_time, list_2[i].originating_change_time)

    def _create_rodc(self, ctx):
        ctx.nc_list = [ctx.base_dn, ctx.config_dn, ctx.schema_dn]
        ctx.full_nc_list = [ctx.base_dn, ctx.config_dn, ctx.schema_dn]
        ctx.krbtgt_dn = "CN=krbtgt_%s,CN=Users,%s" % (ctx.myname, ctx.base_dn)

        ctx.never_reveal_sid = ["<SID=%s-%s>" % (ctx.domsid, security.DOMAIN_RID_RODC_DENY),
                                "<SID=%s>" % security.SID_BUILTIN_ADMINISTRATORS,
                                "<SID=%s>" % security.SID_BUILTIN_SERVER_OPERATORS,
                                "<SID=%s>" % security.SID_BUILTIN_BACKUP_OPERATORS,
                                "<SID=%s>" % security.SID_BUILTIN_ACCOUNT_OPERATORS]
        ctx.reveal_sid = "<SID=%s-%s>" % (ctx.domsid, security.DOMAIN_RID_RODC_ALLOW)

        mysid = ctx.get_mysid()
        admin_dn = "<SID=%s>" % mysid
        ctx.managedby = admin_dn

        ctx.userAccountControl = (samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT |
                                  samba.dsdb.UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION |
                                  samba.dsdb.UF_PARTIAL_SECRETS_ACCOUNT)

        ctx.connection_dn = "CN=RODC Connection (FRS),%s" % ctx.ntds_dn
        ctx.secure_channel_type = misc.SEC_CHAN_RODC
        ctx.RODC = True
        ctx.replica_flags = (drsuapi.DRSUAPI_DRS_INIT_SYNC |
                             drsuapi.DRSUAPI_DRS_PER_SYNC |
                             drsuapi.DRSUAPI_DRS_GET_ANC |
                             drsuapi.DRSUAPI_DRS_NEVER_SYNCED |
                             drsuapi.DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING)

        ctx.join_add_objects()
