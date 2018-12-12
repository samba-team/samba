#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Tests replication scenarios with different user privileges.
# We want to test every replication scenario we can think of against:
# - users with only GET_CHANGES privileges
# - users with only GET_ALL_CHANGES privileges
# - users with both GET_CHANGES and GET_ALL_CHANGES privileges
# - users with no privileges
#
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2011
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017
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
#  export DC2=dc2_dns_name
#  export SUBUNITRUN=$samba4srcdir/scripting/bin/subunitrun
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" $SUBUNITRUN getnc_unpriv -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

import drs_base
import samba.tests
from samba import werror, WERRORError

from samba import sd_utils
import ldb
from ldb import SCOPE_BASE
import random

from samba.dcerpc import drsuapi, security
from samba.credentials import DONT_USE_KERBEROS


class DrsReplicaSyncUnprivTestCase(drs_base.DrsBaseTestCase):
    """Confirm the behaviour of DsGetNCChanges for unprivileged users"""

    def setUp(self):
        super(DrsReplicaSyncUnprivTestCase, self).setUp()
        self.get_changes_user = "get-changes-user"
        self.base_dn = self.ldb_dc1.get_default_basedn()
        self.user_pass = samba.generate_random_password(12, 16)

        # add some randomness to the test OU. (Deletion of the last test's
        # objects can be slow to replicate out. So the OU created by a previous
        # testenv may still exist at this point).
        rand = random.randint(1, 10000000)
        test_ou = "OU=test_getnc_unpriv%d" % rand
        self.ou = "%s,%s" % (test_ou, self.base_dn)
        self.ldb_dc1.add({
            "dn": self.ou,
            "objectclass": "organizationalUnit"})
        self.ldb_dc1.newuser(self.get_changes_user, self.user_pass,
                             userou=test_ou)
        (self.drs, self.drs_handle) = self._ds_bind(self.dnsname_dc1)

        self.sd_utils = sd_utils.SDUtils(self.ldb_dc1)
        self.user_dn = "cn=%s,%s" % (self.get_changes_user, self.ou)
        user_sid = self.sd_utils.get_object_sid(self.user_dn)
        self.acl_mod_get_changes = "(OA;;CR;%s;;%s)" % (security.GUID_DRS_GET_CHANGES,
                                                        str(user_sid))
        self.acl_mod_get_all_changes = "(OA;;CR;%s;;%s)" % (security.GUID_DRS_GET_ALL_CHANGES,
                                                            str(user_sid))
        self.desc_sddl = self.sd_utils.get_sd_as_sddl(self.base_dn)

        # We set DONT_USE_KERBEROS to avoid a race with getting the
        # user replicated to our selected KDC
        self.user_creds = self.insta_creds(template=self.get_credentials(),
                                           username=self.get_changes_user,
                                           userpass=self.user_pass,
                                           kerberos_state=DONT_USE_KERBEROS)
        (self.user_drs, self.user_drs_handle) = self._ds_bind(self.dnsname_dc1,
                                                              self.user_creds)

    def tearDown(self):
        self.sd_utils.modify_sd_on_dn(self.base_dn, self.desc_sddl)
        try:
            self.ldb_dc1.delete(self.ou, ["tree_delete:1"])
        except ldb.LdbError as e1:
            (enum, string) = e1.args
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                pass
        super(DrsReplicaSyncUnprivTestCase, self).tearDown()

    def _test_repl_exop(self, exop, repl_obj, expected_error, dest_dsa=None,
                        partial_attribute_set=None):
        """
        Common function to send a replication request and check the result
        matches what's expected.
        """
        req8 = self._exop_req8(dest_dsa=dest_dsa,
                               invocation_id=self.ldb_dc1.get_invocation_id(),
                               nc_dn_str=repl_obj,
                               exop=exop,
                               replica_flags=drsuapi.DRSUAPI_DRS_WRIT_REP,
                               partial_attribute_set=partial_attribute_set)

        if expected_error is None:
            # user is OK, request should be accepted without throwing an error
            (level, ctr) = self.user_drs.DsGetNCChanges(self.user_drs_handle,
                                                        8, req8)
        else:
            # check the request is rejected (with the error we're expecting)
            try:
                (level, ctr) = self.user_drs.DsGetNCChanges(self.user_drs_handle,
                                                            8, req8)
                self.fail("Should have failed with user denied access")
            except WERRORError as e:
                (enum, estr) = e.args
                self.assertTrue(enum in expected_error,
                                "Got unexpected error: %s" % estr)

    def _test_repl_single_obj(self, repl_obj, expected_error,
                              partial_attribute_set=None):
        """
        Checks that replication on a single object either succeeds or fails as
        expected (based on the user's access rights)
        """
        self._test_repl_exop(exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                             repl_obj=repl_obj,
                             expected_error=expected_error,
                             partial_attribute_set=partial_attribute_set)

    def _test_repl_secret(self, repl_obj, expected_error, dest_dsa=None):
        """
        Checks that REPL_SECRET on an object either succeeds or fails as
        expected (based on the user's access rights)
        """
        self._test_repl_exop(exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET,
                             repl_obj=repl_obj,
                             expected_error=expected_error,
                             dest_dsa=dest_dsa)

    def _test_repl_full(self, expected_error, partial_attribute_set=None):
        """
        Checks that a full replication either succeeds or fails as expected
        (based on the user's access rights)
        """
        self._test_repl_exop(exop=drsuapi.DRSUAPI_EXOP_NONE,
                             repl_obj=self.ldb_dc1.get_default_basedn(),
                             expected_error=expected_error,
                             partial_attribute_set=partial_attribute_set)

    def _test_repl_full_on_ou(self, repl_obj, expected_error):
        """
        Full replication on a specific OU should always fail (it should be done
        against a base NC). The error may vary based on the user's access rights
        """
        # Just try against the OU created in the test setup
        self._test_repl_exop(exop=drsuapi.DRSUAPI_EXOP_NONE,
                             repl_obj=repl_obj,
                             expected_error=expected_error)

    def test_repl_getchanges_userpriv(self):
        """
        Tests various replication requests made by a user with only GET_CHANGES
        rights. Some requests will be accepted, but most will be rejected.
        """

        # Assign the user GET_CHANGES rights
        self.sd_utils.dacl_add_ace(self.base_dn, self.acl_mod_get_changes)

        self._test_repl_single_obj(repl_obj=self.ou,
                                   expected_error=[werror.WERR_DS_DRA_ACCESS_DENIED])
        bad_ou = "OU=bad_obj,%s" % self.ou
        self._test_repl_single_obj(repl_obj=bad_ou,
                                   expected_error=[werror.WERR_DS_DRA_BAD_DN,
                                                   werror.WERR_DS_DRA_ACCESS_DENIED])

        self._test_repl_secret(repl_obj=self.ou,
                               expected_error=[werror.WERR_DS_DRA_ACCESS_DENIED])
        self._test_repl_secret(repl_obj=self.user_dn,
                               expected_error=[werror.WERR_DS_DRA_ACCESS_DENIED])
        self._test_repl_secret(repl_obj=self.user_dn,
                               dest_dsa=self.ldb_dc1.get_ntds_GUID(),
                               expected_error=[werror.WERR_DS_DRA_ACCESS_DENIED])
        self._test_repl_secret(repl_obj=bad_ou,
                               expected_error=[werror.WERR_DS_DRA_BAD_DN])

        self._test_repl_full(expected_error=[werror.WERR_DS_DRA_ACCESS_DENIED])
        self._test_repl_full_on_ou(repl_obj=self.ou,
                                   expected_error=[werror.WERR_DS_CANT_FIND_EXPECTED_NC,
                                                   werror.WERR_DS_DRA_ACCESS_DENIED])
        self._test_repl_full_on_ou(repl_obj=bad_ou,
                                   expected_error=[werror.WERR_DS_DRA_BAD_NC,
                                                   werror.WERR_DS_DRA_ACCESS_DENIED])

        # Partial Attribute Sets don't require GET_ALL_CHANGES rights, so we
        # expect the following to succeed
        self._test_repl_single_obj(repl_obj=self.ou,
                                   expected_error=None,
                                   partial_attribute_set=self.get_partial_attribute_set())
        self._test_repl_full(expected_error=None,
                             partial_attribute_set=self.get_partial_attribute_set())

    def test_repl_getallchanges_userpriv(self):
        """
        Tests various replication requests made by a user with only
        GET_ALL_CHANGES rights. Note that assigning these rights is possible,
        but doesn't make a lot of sense. We test it anyway for consistency.
        """

        # Assign the user GET_ALL_CHANGES rights
        self.sd_utils.dacl_add_ace(self.base_dn, self.acl_mod_get_all_changes)

        # We can expect to get the same responses as an unprivileged user,
        # i.e. we have permission to see the results, but don't have permission
        # to ask
        self.test_repl_no_userpriv()

    def test_repl_both_userpriv(self):
        """
        Tests various replication requests made by a privileged user (i.e. has
        both GET_CHANGES and GET_ALL_CHANGES). We expect any valid requests
        to be accepted.
        """

        # Assign the user both GET_CHANGES and GET_ALL_CHANGES rights
        both_rights = self.acl_mod_get_changes + self.acl_mod_get_all_changes
        self.sd_utils.dacl_add_ace(self.base_dn, both_rights)

        self._test_repl_single_obj(repl_obj=self.ou,
                                   expected_error=None)
        bad_ou = "OU=bad_obj,%s" % self.ou
        self._test_repl_single_obj(repl_obj=bad_ou,
                                   expected_error=[werror.WERR_DS_DRA_BAD_DN])

        # Microsoft returns DB_ERROR, Samba returns ACCESS_DENIED
        self._test_repl_secret(repl_obj=self.ou,
                               expected_error=[werror.WERR_DS_DRA_DB_ERROR,
                                               werror.WERR_DS_DRA_ACCESS_DENIED])
        self._test_repl_secret(repl_obj=self.user_dn,
                               expected_error=[werror.WERR_DS_DRA_DB_ERROR,
                                               werror.WERR_DS_DRA_ACCESS_DENIED])
        # Note that Windows accepts this but Samba rejects it
        self._test_repl_secret(repl_obj=self.user_dn,
                               dest_dsa=self.ldb_dc1.get_ntds_GUID(),
                               expected_error=[werror.WERR_DS_DRA_ACCESS_DENIED])

        self._test_repl_secret(repl_obj=bad_ou,
                               expected_error=[werror.WERR_DS_DRA_BAD_DN])

        self._test_repl_full(expected_error=None)
        self._test_repl_full_on_ou(repl_obj=self.ou,
                                   expected_error=[werror.WERR_DS_CANT_FIND_EXPECTED_NC])
        self._test_repl_full_on_ou(repl_obj=bad_ou,
                                   expected_error=[werror.WERR_DS_DRA_BAD_NC,
                                                   werror.WERR_DS_DRA_BAD_DN])

        self._test_repl_single_obj(repl_obj=self.ou,
                                   expected_error=None,
                                   partial_attribute_set=self.get_partial_attribute_set())
        self._test_repl_full(expected_error=None,
                             partial_attribute_set=self.get_partial_attribute_set())

    def test_repl_no_userpriv(self):
        """
        Tests various replication requests made by a unprivileged user.
        We expect all these requests to be rejected.
        """

        # Microsoft usually returns BAD_DN, Samba returns ACCESS_DENIED
        usual_error = [werror.WERR_DS_DRA_BAD_DN, werror.WERR_DS_DRA_ACCESS_DENIED]

        self._test_repl_single_obj(repl_obj=self.ou,
                                   expected_error=usual_error)
        bad_ou = "OU=bad_obj,%s" % self.ou
        self._test_repl_single_obj(repl_obj=bad_ou,
                                   expected_error=usual_error)

        self._test_repl_secret(repl_obj=self.ou,
                               expected_error=usual_error)
        self._test_repl_secret(repl_obj=self.user_dn,
                               expected_error=usual_error)
        self._test_repl_secret(repl_obj=self.user_dn,
                               dest_dsa=self.ldb_dc1.get_ntds_GUID(),
                               expected_error=usual_error)
        self._test_repl_secret(repl_obj=bad_ou,
                               expected_error=usual_error)

        self._test_repl_full(expected_error=[werror.WERR_DS_DRA_ACCESS_DENIED])
        self._test_repl_full_on_ou(repl_obj=self.ou,
                                   expected_error=usual_error)
        self._test_repl_full_on_ou(repl_obj=bad_ou,
                                   expected_error=[werror.WERR_DS_DRA_BAD_NC,
                                                   werror.WERR_DS_DRA_ACCESS_DENIED])

        self._test_repl_single_obj(repl_obj=self.ou,
                                   expected_error=usual_error,
                                   partial_attribute_set=self.get_partial_attribute_set())
        self._test_repl_full(expected_error=[werror.WERR_DS_DRA_ACCESS_DENIED],
                             partial_attribute_set=self.get_partial_attribute_set())
