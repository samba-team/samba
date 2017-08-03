#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Tests replication scenarios with different user privileges
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

from samba import sd_utils
import ldb
from ldb import SCOPE_BASE

from samba.dcerpc import drsuapi
from samba.credentials import DONT_USE_KERBEROS

class DrsReplicaSyncUnprivTestCase(drs_base.DrsBaseTestCase):
    """Confirm the behaviour of DsGetNCChanges for unprivileged users"""

    def setUp(self):
        super(DrsReplicaSyncUnprivTestCase, self).setUp()
        self.get_changes_user = "get-changes-user"
        self.base_dn = self.ldb_dc1.get_default_basedn()
        self.ou = "OU=test_getncchanges,%s" % self.base_dn
        self.user_pass = samba.generate_random_password(12, 16)
        self.ldb_dc1.add({
            "dn": self.ou,
            "objectclass": "organizationalUnit"})
        self.ldb_dc1.newuser(self.get_changes_user, self.user_pass,
                             userou="OU=test_getncchanges")
        (self.drs, self.drs_handle) = self._ds_bind(self.dnsname_dc1)

        self.sd_utils = sd_utils.SDUtils(self.ldb_dc1)
        user_dn = "cn=%s,%s" % (self.get_changes_user, self.ou)
        user_sid = self.sd_utils.get_object_sid(user_dn)
        mod = "(A;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace(self.base_dn, mod)

        # We set DONT_USE_KERBEROS to avoid a race with getting the
        # user replicated to our selected KDC
        self.user_creds = self.insta_creds(template=self.get_credentials(),
                                           username=self.get_changes_user,
                                           userpass=self.user_pass,
                                           kerberos_state=DONT_USE_KERBEROS)
        (self.user_drs, self.user_drs_handle) = self._ds_bind(self.dnsname_dc1,
                                                              self.user_creds)

    def tearDown(self):
        try:
            self.ldb_dc1.delete(self.ou, ["tree_delete:1"])
        except ldb.LdbError as (enum, string):
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                pass
        super(DrsReplicaSyncUnprivTestCase, self).tearDown()

    def test_do_single_repl(self):
        """
        Make sure that DRSU_EXOP_REPL_OBJ works as a less-privileged
        user with the correct GET_CHANGES rights
        """

        ou1 = "OU=single_obj,%s" % self.ou
        self.ldb_dc1.add({
            "dn": ou1,
            "objectclass": "organizationalUnit"
            })
        req8 = self._exop_req8(dest_dsa=None,
                               invocation_id=self.ldb_dc1.get_invocation_id(),
                               nc_dn_str=ou1,
                               exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                               replica_flags=drsuapi.DRSUAPI_DRS_WRIT_REP)
        (level, ctr) = self.user_drs.DsGetNCChanges(self.user_drs_handle, 8, req8)
        self._check_ctr6(ctr, [ou1])

    def test_do_full_repl(self):
        """
        Make sure that full replication works as a less-privileged
        user with the correct GET_CHANGES rights
        """

        ou1 = "OU=single_obj,%s" % self.ou
        self.ldb_dc1.add({
            "dn": ou1,
            "objectclass": "organizationalUnit"
            })
        req8 = self._exop_req8(dest_dsa=None,
                               invocation_id=self.ldb_dc1.get_invocation_id(),
                               nc_dn_str=ou1,
                               exop=drsuapi.DRSUAPI_EXOP_NONE,
                               replica_flags=drsuapi.DRSUAPI_DRS_WRIT_REP)
        (level, ctr) = self.user_drs.DsGetNCChanges(self.user_drs_handle, 8, req8)
        self.assertEqual(ctr.extended_ret, drsuapi.DRSUAPI_EXOP_ERR_NONE)
