#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Tests various schema replication scenarios
#
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
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" $SUBUNITRUN repl_schema -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

import sys
import time
import random
import os

sys.path.append("bin/python")

from samba.auth import system_session
from ldb import SCOPE_BASE, SCOPE_SUBTREE
from samba.samdb import SamDB

import samba.tests


class DrsReplSchemaTestCase(samba.tests.TestCase):

    # RootDSE msg for DC1
    info_dc1 = None
    ldb_dc1 = None
    # RootDSE msg for DC1
    info_dc2 = None
    ldb_dc2 = None
    # prefix for all objects created
    obj_prefix = None

    def setUp(self):
        super(DrsReplSchemaTestCase, self).setUp()

        # connect to DCs singleton
        self._dc_connect("dc1", "DC1", ldap_only=True)
        self._dc_connect("dc2", "DC2", ldap_only=True)

        # initialize objects prefix if not done yet
        if self.obj_prefix is None:
            t = time.strftime("%s", time.gmtime())
            DrsReplSchemaTestCase.obj_prefix = "DrsReplSchema-%s-" % t

        # cache some of RootDSE props
        self.schema_dn = self.info_dc1["schemaNamingContext"][0]
        self.domain_dn = self.info_dc1["defaultNamingContext"][0]
        self.config_dn = self.info_dc1["configurationNamingContext"][0]
        self.forest_level = int(self.info_dc1["forestFunctionality"][0])

        # we will need DCs DNS names for 'samba-tool drs' command
        self.dnsname_dc1 = self.info_dc1["dnsHostName"][0]
        self.dnsname_dc2 = self.info_dc2["dnsHostName"][0]

    def tearDown(self):
        super(DrsReplSchemaTestCase, self).tearDown()

    @classmethod
    def _dc_connect(cls, attr_name, env_var, ldap_only=True):
        ldb_dc = None
        attr_name_ldb = "ldb_" + attr_name
        if hasattr(cls, attr_name_ldb):
            ldb_dc = getattr(cls, attr_name_ldb)
        if ldb_dc is None:
            url_dc = samba.tests.env_get_var_value(env_var)
            ldb_dc = samba.tests.connect_samdb(url_dc, ldap_only=ldap_only)
            res = ldb_dc.search(base="", expression="", scope=SCOPE_BASE, attrs=["*"])
            info_dc = res[0]
            setattr(cls, "ldb_" + attr_name, ldb_dc)
            setattr(cls, "url_" + attr_name, url_dc)
            setattr(cls, "info_" + attr_name, info_dc)
        return ldb_dc

    def _net_drs_replicate(self, DC, fromDC, nc_dn):
        """Triggers replication cycle on 'DC' to
           replicate from 'fromDC'. Naming context to
           be replicated is 'nc_dn' dn"""
        # find out where is net command
        samba_tool_cmd = os.path.abspath("./bin/samba-tool")
        # make command line credentials string
        creds = samba.tests.cmdline_credentials
        cmd_line_auth = "-U%s/%s%%%s" % (creds.get_domain(),
                                         creds.get_username(), creds.get_password())
        # bin/samba-tool drs replicate <Dest_DC_NAME> <Src_DC_NAME> <Naming Context>
        cmd_line = "%s drs replicate %s %s %s %s" % (samba_tool_cmd, DC, fromDC,
                                                     nc_dn, cmd_line_auth)
        ret = os.system(cmd_line)
        self.assertEquals(ret, 0, "Replicating %s from %s has failed!" % (DC, fromDC))

    def _GUID_string(self, guid):
        return self.ldb_dc1.schema_format_value("objectGUID", guid)

    def _ldap_schemaUpdateNow(self, sam_db):
        ldif = """
dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
"""
        sam_db.modify_ldif(ldif)

    def _make_obj_names(self, base_name):
        '''Try to create a unique name for an object
           that is to be added to schema'''
        obj_name = self.obj_prefix + base_name
        obj_dn = "CN=%s,%s" % (obj_name, self.schema_dn)
        return (obj_name, obj_dn)

    def _make_class_ldif(self, class_name, class_dn, attrs=None):
        ldif = """
dn: """ + class_dn + """
objectClass: top
objectClass: classSchema
cn: """ + class_name + """
governsId: 1.2.840.""" + str(random.randint(1,100000)) + """.1.5.13
instanceType: 4
objectClassCategory: 1
subClassOf: organizationalPerson
systemOnly: FALSE
"""
        return ldif

    def _check_object(self, obj_dn):
        '''Check if object obj_dn exists on both DCs'''
        res_dc1 = self.ldb_dc1.search(base=obj_dn,
                                      scope=SCOPE_BASE,
                                      attrs=["*"])
        self.assertEquals(len(res_dc1), 1,
                          "%s doesn't exists on %s" % (obj_dn, self.dnsname_dc1))
        try:
            res_dc2 = self.ldb_dc2.search(base=obj_dn,
                                          scope=SCOPE_BASE,
                                          attrs=["*"])
        except LdbError, (ERR_NO_SUCH_OBJECT, _):
            self.fail("%s doesn't exists on %s" % (obj_dn, self.dnsname_dc2))
        self.assertEquals(len(res_dc2), 1,
                          "%s doesn't exists on %s" % (obj_dn, self.dnsname_dc2))

    def test_all(self):
        """Basic plan is to create bunch of classSchema
           and attributeSchema objects, replicate Schema NC
           and then check all objects are replicated correctly"""

        # add new classSchema object
        (class_name, class_dn) = self._make_obj_names("cls-A")
        ldif = self._make_class_ldif(class_name, class_dn)
        self.ldb_dc1.add_ldif(ldif)
        self._ldap_schemaUpdateNow(self.ldb_dc1)
        # force replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, nc_dn=self.schema_dn)
        # check object is replicated
        self._check_object(class_dn)
