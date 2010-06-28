#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Unix SMB/CIFS implementation.
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2010
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
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" $SUBUNITRUN delete_object -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

import sys
import time
import os

sys.path.append("bin/python")

from samba.auth import system_session
from ldb import SCOPE_BASE, SCOPE_SUBTREE
from samba.samdb import SamDB

import samba.tests


class DrsDeleteObjectTestCase(samba.tests.TestCase):

    # RootDSE msg for DC1
    info_dc1 = None
    ldb_dc1 = None
    # RootDSE msg for DC1
    info_dc2 = None
    ldb_dc2 = None

    def setUp(self):
        super(DrsDeleteObjectTestCase, self).setUp()

        # connect to DCs singleton
        if self.ldb_dc1 is None:
            DrsDeleteObjectTestCase.dc1 = get_env_var("DC1")
            DrsDeleteObjectTestCase.ldb_dc1 = connect_samdb(self.dc1)
        if self.ldb_dc2 is None:
            DrsDeleteObjectTestCase.dc2 = get_env_var("DC2")
            DrsDeleteObjectTestCase.ldb_dc2 = connect_samdb(self.dc2)

        # fetch rootDSEs
        if self.info_dc1 is None:
            ldb = self.ldb_dc1
            res = ldb.search(base="", expression="", scope=SCOPE_BASE, attrs=["*"])
            self.assertEquals(len(res), 1)
            DrsDeleteObjectTestCase.info_dc1 = res[0]
        if self.info_dc2 is None:
            ldb = self.ldb_dc2
            res = ldb.search(base="", expression="", scope=SCOPE_BASE, attrs=["*"])
            self.assertEquals(len(res), 1)
            DrsDeleteObjectTestCase.info_dc2 = res[0]

        # cache some of RootDSE props
        self.schema_dn = self.info_dc1["schemaNamingContext"][0]
        self.domain_dn = self.info_dc1["defaultNamingContext"][0]
        self.config_dn = self.info_dc1["configurationNamingContext"][0]
        self.forest_level = int(self.info_dc1["forestFunctionality"][0])

        # we will need DCs DNS names for 'net drs' command
        self.dnsname_dc1 = self.info_dc1["dnsHostName"][0]
        self.dnsname_dc2 = self.info_dc2["dnsHostName"][0]
        pass

    def tearDown(self):
        super(DrsDeleteObjectTestCase, self).tearDown()

    def _GUID_string(self, guid):
        return self.ldb_dc1.schema_format_value("objectGUID", guid)

    def _deleted_objects_dn(self, sam_ldb):
        wkdn = "<WKGUID=18E2EA80684F11D2B9AA00C04F79F805,%s>" % self.domain_dn
        res = sam_ldb.search(base=wkdn,
                             scope=SCOPE_BASE,
                             controls=["show_deleted:1"])
        self.assertEquals(len(res), 1)
        return str(res[0]["dn"])

    def _make_username(self):
        return "DrsDelObjUser_" + time.strftime("%s", time.gmtime())

    def _check_user(self, sam_ldb, user_orig, is_deleted):
        # search the user by guid as it may be deleted
        guid_str = self._GUID_string(user_orig["objectGUID"][0])
        expression = "(objectGUID=%s)" % guid_str
        res = sam_ldb.search(base=self.domain_dn,
                             expression=expression,
                             controls=["show_deleted:1"])
        self.assertEquals(len(res), 1)
        user_cur = res[0]
        # Deleted Object base DN
        dodn = self._deleted_objects_dn(sam_ldb)
        # now check properties of the user
        name_orig = user_orig["cn"][0]
        name_cur  = user_cur["cn"][0]
        if is_deleted:
            self.assertEquals(user_cur["isDeleted"][0],"TRUE")
            self.assertTrue(not("objectCategory" in user_cur))
            self.assertTrue(not("sAMAccountType" in user_cur))
            self.assertTrue(dodn in str(user_cur["dn"]),
                            "User %s is deleted but it is not located under %s!" % (name_orig, dodn))
            self.assertEquals(name_cur, name_orig + "\nDEL:" + guid_str)
        else:
            self.assertTrue(not("isDeleted" in user_cur))
            self.assertEquals(name_cur, name_orig)
            self.assertEquals(user_orig["dn"], user_cur["dn"])
            self.assertTrue(dodn not in str(user_cur["dn"]))
        pass

    def _net_drs_replicate(self, DC, fromDC):
        # find out where is net command
        net_cmd = os.path.abspath("./bin/net")
        # make command line credentials string
        creds = samba.tests.cmdline_credentials
        cmd_line_auth = "-U%s/%s%%%s" % (creds.get_domain(),
                                         creds.get_username(), creds.get_password())
        # bin/net drs replicate <Dest_DC_NAME> <Src_DC_NAME> <Naming Context>
        cmd_line = "%s drs replicate %s %s %s %s" % (net_cmd, DC, fromDC,
                                                     self.domain_dn, cmd_line_auth)
        ret = os.system(cmd_line)
        self.assertEquals(ret, 0, "Replicating %s from %s has failed!" % (DC, fromDC))
        pass


    def test_NetReplicateCmd(self):
        """Triggers replication from DC1 to DC2
           and vice versa so both DCs are synchronized
           before test_ReplicateDeteleteObject test"""
        # replicate Domain NC on DC2 from DC1
        self._net_drs_replicate(DC=self.dc2, fromDC=self.dc1)
        # replicate Domain NC on DC1 from DC2
        self._net_drs_replicate(DC=self.dc1, fromDC=self.dc2)
        pass

    def test_ReplicateDeteleteObject(self):
        """Verifies how a deleted-object is replicated between two DCs.
           This test should verify that:
            - deleted-object is replicated properly
           TODO: We should verify that after replication,
                 object's state to conform to a deleted-object state
                 or tombstone -object, depending on DC's features
                 It will also be great if check replPropertyMetaData."""
        # work-out unique username to test with
        username = self._make_username()

        # create user on DC1
        self.ldb_dc1.newuser(username=username, password="P@sswOrd!")
        ldb_res = self.ldb_dc1.search(base=self.domain_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username)
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print "Testing for %s with GUID %s" % (username, self._GUID_string(user_orig["objectGUID"][0]))
        self._check_user(sam_ldb=self.ldb_dc1, user_orig=user_orig, is_deleted=False)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dc2, fromDC=self.dc1)

        # delete user on DC1
        self.ldb_dc1.delete(user_dn)
        # check user info on DC1 - should be deleted
        self._check_user(sam_ldb=self.ldb_dc1, user_orig=user_orig, is_deleted=True)
        # check user info on DC2 - should be valid user
        self._check_user(sam_ldb=self.ldb_dc2, user_orig=user_orig, is_deleted=False)

        # trigger replication from DC2 to DC1
        # to check if deleted object gets restored
        self._net_drs_replicate(DC=self.dc1, fromDC=self.dc2)
        # check user info on DC1 - should be deleted
        self._check_user(sam_ldb=self.ldb_dc1, user_orig=user_orig, is_deleted=True)
        # check user info on DC2 - should be valid user
        self._check_user(sam_ldb=self.ldb_dc2, user_orig=user_orig, is_deleted=False)

        # trigger replication from DC1 to DC2
        # to check if deleted object is replicated
        self._net_drs_replicate(DC=self.dc2, fromDC=self.dc1)
        # check user info on DC1 - should be deleted
        self._check_user(sam_ldb=self.ldb_dc1, user_orig=user_orig, is_deleted=True)
        # check user info on DC2 - should be deleted
        self._check_user(sam_ldb=self.ldb_dc2, user_orig=user_orig, is_deleted=True)
        pass



########################################################################################
def get_env_var(var_name):
    if not var_name in os.environ.keys():
        raise AssertionError("Please supply %s in environment" % var_name)
    return os.environ[var_name]

def connect_samdb(samdb_url):
    ldb_options = []
    if not "://" in samdb_url:
        if os.path.isfile(samdb_url):
            samdb_url = "tdb://%s" % samdb_url
        else:
            samdb_url = "ldap://%s" % samdb_url
            # user 'paged_search' module when connecting remotely
            ldb_options = ["modules:paged_searches"]

    return SamDB(url=samdb_url,
                 lp=samba.tests.env_loadparm(),
                 session_info=system_session(),
                 credentials=samba.tests.cmdline_credentials,
                 options=ldb_options)

