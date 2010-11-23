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
import samba
samba.ensure_external_module("testtools", "testtools")
samba.ensure_external_module("subunit", "subunit/python")

from ldb import LdbError, ERR_NO_SUCH_OBJECT
from ldb import SCOPE_BASE
from ldb import Message
from ldb import FLAG_MOD_REPLACE

import samba.tests


class DrsReplSchemaTestCase(samba.tests.TestCase):

    # prefix for all objects created
    obj_prefix = None

    def setUp(self):
        super(DrsReplSchemaTestCase, self).setUp()

        # connect to DCs
        url_dc = samba.tests.env_get_var_value("DC1")
        (self.ldb_dc1, self.info_dc1) = samba.tests.connect_samdb_ex(url_dc, 
                                                                     ldap_only=True)
        url_dc = samba.tests.env_get_var_value("DC2")
        (self.ldb_dc2, self.info_dc2) = samba.tests.connect_samdb_ex(url_dc, 
                                                                     ldap_only=True)

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
        rec = {"dn": "",
               "schemaUpdateNow": "1"}
        m = Message.from_dict(sam_db, rec, FLAG_MOD_REPLACE)
        sam_db.modify(m)

    def _make_obj_names(self, base_name):
        '''Try to create a unique name for an object
           that is to be added to schema'''
        obj_name = self.obj_prefix + base_name
        obj_ldn = obj_name.replace("-", "")
        obj_dn = "CN=%s,%s" % (obj_name, self.schema_dn)
        return (obj_dn, obj_name, obj_ldn)

    def _schema_new_class(self, ldb_ctx, base_name, attrs=None):
        (class_dn, class_name, class_ldn) = self._make_obj_names(base_name)
        rec = {"dn": class_dn,
               "objectClass": ["top", "classSchema"],
               "cn": class_name,
               "lDAPDisplayName": class_ldn,
               "governsId": "1.2.840." + str(random.randint(1,100000)) + ".1.5.13",
               "instanceType": "4",
               "objectClassCategory": "1",
               "subClassOf": "organizationalPerson",
               "systemOnly": "FALSE"}
        # allow overriding/adding attributes
        if not attrs is None:
            rec.update(attrs)
        # add it to the Schema
        ldb_ctx.add(rec)
        self._ldap_schemaUpdateNow(ldb_ctx)
        return (rec["lDAPDisplayName"], rec["dn"])

    def _schema_new_attr(self, ldb_ctx, base_name, attrs=None):
        (attr_dn, attr_name, attr_ldn) = self._make_obj_names(base_name)
        rec = {"dn": attr_dn,
               "objectClass": ["top", "attributeSchema"],
               "cn": attr_name,
               "lDAPDisplayName": attr_ldn,
               "attributeId": "1.2.841." + str(random.randint(1,100000)) + ".1.5.13",
               "attributeSyntax": "2.5.5.12",
               "omSyntax": "64",
               "instanceType": "4",
               "isSingleValued": "TRUE",
               "systemOnly": "FALSE"}
        # allow overriding/adding attributes
        if not attrs is None:
            rec.update(attrs)
        # add it to the Schema
        ldb_ctx.add(rec)
        self._ldap_schemaUpdateNow(ldb_ctx)
        return (rec["lDAPDisplayName"], rec["dn"])

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

        # add new attributeSchema object
        (a_ldn, a_dn) = self._schema_new_attr(self.ldb_dc1, "attr-A")
        # add new classSchema object
        (c_ldn, c_dn) = self._schema_new_class(self.ldb_dc1, "cls-A")

        # force replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, nc_dn=self.schema_dn)
        
        # check objects are replicated
        self._check_object(c_dn)
        self._check_object(a_dn)
