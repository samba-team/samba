#!/usr/bin/env python3
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

import time
import random
import ldb
import drs_base

from ldb import (
    ERR_NO_SUCH_OBJECT,
    LdbError,
    SCOPE_BASE,
    Message,
    FLAG_MOD_ADD,
    FLAG_MOD_REPLACE
)
from samba.dcerpc import drsuapi, misc
from samba.drs_utils import drs_DsBind
from samba import dsdb


class DrsReplSchemaTestCase(drs_base.DrsBaseTestCase):

    # prefix for all objects created
    obj_prefix = None
    # current Class or Attribute object id
    obj_id = 0

    def _ds_bind(self, server_name):
        binding_str = "ncacn_ip_tcp:%s[seal]" % server_name

        drs = drsuapi.drsuapi(binding_str, self.get_loadparm(), self.get_credentials())
        (drs_handle, supported_extensions) = drs_DsBind(drs)
        return (drs, drs_handle)

    def _exop_req8(self, dest_dsa, invocation_id, nc_dn_str, exop,
                   replica_flags=0, max_objects=0):
        req8 = drsuapi.DsGetNCChangesRequest8()

        req8.destination_dsa_guid = misc.GUID(dest_dsa) if dest_dsa else misc.GUID()
        req8.source_dsa_invocation_id = misc.GUID(invocation_id)
        req8.naming_context = drsuapi.DsReplicaObjectIdentifier()
        req8.naming_context.dn = str(nc_dn_str)
        req8.highwatermark = drsuapi.DsReplicaHighWaterMark()
        req8.highwatermark.tmp_highest_usn = 0
        req8.highwatermark.reserved_usn = 0
        req8.highwatermark.highest_usn = 0
        req8.uptodateness_vector = None
        req8.replica_flags = replica_flags
        req8.max_object_count = max_objects
        req8.max_ndr_size = 402116
        req8.extended_op = exop
        req8.fsmo_info = 0
        req8.partial_attribute_set = None
        req8.partial_attribute_set_ex = None
        req8.mapping_ctr.num_mappings = 0
        req8.mapping_ctr.mappings = None

        return req8

    def setUp(self):
        super(DrsReplSchemaTestCase, self).setUp()

        # disable automatic replication temporary
        self._disable_all_repl(self.dnsname_dc1)
        self._disable_all_repl(self.dnsname_dc2)

        # make sure DCs are synchronized before the test
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)
        # initialize objects prefix if not done yet
        if self.obj_prefix is None:
            t = time.strftime("%s", time.gmtime())
            DrsReplSchemaTestCase.obj_prefix = "DrsReplSchema-%s" % t

    def tearDown(self):
        self._enable_all_repl(self.dnsname_dc1)
        self._enable_all_repl(self.dnsname_dc2)
        super(DrsReplSchemaTestCase, self).tearDown()

    def _make_obj_names(self, base_name):
        '''Try to create a unique name for an object
           that is to be added to schema'''
        self.obj_id += 1
        obj_name = "%s-%d-%s" % (self.obj_prefix, self.obj_id, base_name)
        obj_ldn = obj_name.replace("-", "")
        obj_dn = ldb.Dn(self.ldb_dc1, "CN=X")
        obj_dn.add_base(ldb.Dn(self.ldb_dc1, self.schema_dn))
        obj_dn.set_component(0, "CN", obj_name)
        return (obj_dn, obj_name, obj_ldn)

    def _schema_new_class(self, ldb_ctx, base_name, base_int, oc_cat=1, attrs=None):
        (class_dn, class_name, class_ldn) = self._make_obj_names(base_name)
        rec = {"dn": class_dn,
               "objectClass": ["top", "classSchema"],
               "cn": class_name,
               "lDAPDisplayName": class_ldn,
               "governsId": "1.3.6.1.4.1.7165.4.6.2.5."
               + str((100000 * base_int) + random.randint(1, 100000)) + ".1.5.13",
               "instanceType": "4",
               "objectClassCategory": "%d" % oc_cat,
               "subClassOf": "top",
               "systemOnly": "FALSE"}
        # allow overriding/adding attributes
        if attrs is not None:
            rec.update(attrs)
        # add it to the Schema
        try:
            ldb_ctx.add(rec)
        except LdbError as e:
            (enum, estr) = e.args
            self.fail("Adding record failed with %d/%s" % (enum, estr))

        self._ldap_schemaUpdateNow(ldb_ctx)
        return (rec["lDAPDisplayName"], rec["dn"])

    def _schema_new_attr(self, ldb_ctx, base_name, base_int, attrs=None):
        (attr_dn, attr_name, attr_ldn) = self._make_obj_names(base_name)
        rec = {"dn": attr_dn,
               "objectClass": ["top", "attributeSchema"],
               "cn": attr_name,
               "lDAPDisplayName": attr_ldn,
               "attributeId": "1.3.6.1.4.1.7165.4.6.1.5."
               + str((100000 * base_int) + random.randint(1, 100000)) + ".1.5.13",
               "attributeSyntax": "2.5.5.12",
               "omSyntax": "64",
               "instanceType": "4",
               "isSingleValued": "TRUE",
               "systemOnly": "FALSE"}
        # allow overriding/adding attributes
        if attrs is not None:
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
        self.assertEqual(len(res_dc1), 1,
                          "%s doesn't exists on %s" % (obj_dn, self.dnsname_dc1))
        try:
            res_dc2 = self.ldb_dc2.search(base=obj_dn,
                                          scope=SCOPE_BASE,
                                          attrs=["*"])
        except LdbError as e1:
            (enum, estr) = e1.args
            if enum == ERR_NO_SUCH_OBJECT:
                self.fail("%s doesn't exists on %s" % (obj_dn, self.dnsname_dc2))
            raise
        self.assertEqual(len(res_dc2), 1,
                          "%s doesn't exists on %s" % (obj_dn, self.dnsname_dc2))

    def test_class(self):
        """Simple test for classSchema replication"""
        # add new classSchema object
        (c_ldn, c_dn) = self._schema_new_class(self.ldb_dc1, "cls-S", 0)
        # force replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, nc_dn=self.schema_dn, forced=True)
        # check object is replicated
        self._check_object(c_dn)

    def test_classInheritance(self):
        """Test inheritance through subClassOf
           I think 5 levels of inheritance is pretty decent for now."""
        # add 5 levels deep hierarchy
        c_dn_list = []
        c_ldn_last = None
        for i in range(1, 6):
            base_name = "cls-I-%02d" % i
            (c_ldn, c_dn) = self._schema_new_class(self.ldb_dc1, base_name, i)
            c_dn_list.append(c_dn)
            if c_ldn_last:
                # inherit from last class added
                m = Message.from_dict(self.ldb_dc1,
                                      {"dn": c_dn,
                                       "subClassOf": c_ldn_last},
                                      FLAG_MOD_REPLACE)
                self.ldb_dc1.modify(m)
            # store last class ldapDisplayName
            c_ldn_last = c_ldn
        # force replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, nc_dn=self.schema_dn, forced=True)
        # check objects are replicated
        for c_dn in c_dn_list:
            self._check_object(c_dn)

    def test_classWithCustomAttribute(self):
        """Create new Attribute and a Class,
           that has value for newly created attribute.
           This should check code path that searches for
           AttributeID_id in Schema cache"""
        # add new attributeSchema object
        (a_ldn, a_dn) = self._schema_new_attr(self.ldb_dc1, "attr-A", 7)
        # add a base classSchema class so we can use our new
        # attribute in class definition in a sibling class
        (c_ldn, c_dn) = self._schema_new_class(self.ldb_dc1, "cls-A", 8,
                                               1,
                                               {"systemMayContain": a_ldn,
                                                "subClassOf": "classSchema"})
        # add new classSchema object with value for a_ldb attribute
        (c_ldn, c_dn) = self._schema_new_class(self.ldb_dc1, "cls-B", 9,
                                               1,
                                               {"objectClass": ["top", "classSchema", c_ldn],
                                                a_ldn: "test_classWithCustomAttribute"})
        # force replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, nc_dn=self.schema_dn, forced=True)
        # check objects are replicated
        self._check_object(c_dn)
        self._check_object(a_dn)

    def test_classWithCustomLinkAttribute(self):
        """Create new Attribute and a Class,
           that has value for newly created attribute.
           This should check code path that searches for
           AttributeID_id in Schema cache"""
        # add new attributeSchema object
        (a_ldn, a_dn) = self._schema_new_attr(self.ldb_dc1, "attr-Link-X", 10,
                                              attrs={'linkID': "1.2.840.113556.1.2.50",
                                                     "attributeSyntax": "2.5.5.1",
                                                     "omSyntax": "127"})
        # add a base classSchema class so we can use our new
        # attribute in class definition in a sibling class
        (c_ldn, c_dn) = self._schema_new_class(self.ldb_dc1, "cls-Link-Y", 11,
                                               1,
                                               {"systemMayContain": a_ldn,
                                                "subClassOf": "classSchema"})
        # add new classSchema object with value for a_ldb attribute
        (c_ldn, c_dn) = self._schema_new_class(self.ldb_dc1, "cls-Link-Z", 12,
                                               1,
                                               {"objectClass": ["top", "classSchema", c_ldn],
                                                a_ldn: self.schema_dn})
        # force replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, nc_dn=self.schema_dn, forced=True)
        # check objects are replicated
        self._check_object(c_dn)
        self._check_object(a_dn)

        res = self.ldb_dc1.search(base="",
                                  scope=SCOPE_BASE,
                                  attrs=["domainFunctionality"])

        if int(res[0]["domainFunctionality"][0]) > dsdb.DS_DOMAIN_FUNCTION_2000:
            res = self.ldb_dc1.search(base=a_dn,
                                      scope=SCOPE_BASE,
                                      attrs=["msDS-IntId"])
            self.assertEqual(1, len(res))
            self.assertTrue("msDS-IntId" in res[0])
            int_id = int(res[0]["msDS-IntId"][0])
            if int_id < 0:
                int_id += (1 << 32)

        dc_guid_1 = self.ldb_dc1.get_invocation_id()

        drs, drs_handle = self._ds_bind(self.dnsname_dc1)

        req8 = self._exop_req8(dest_dsa=None,
                               invocation_id=dc_guid_1,
                               nc_dn_str=c_dn,
                               exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                               replica_flags=drsuapi.DRSUAPI_DRS_SYNC_FORCED)

        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)

        for link in ctr.linked_attributes:
            self.assertTrue(link.attid != int_id,
                            'Got %d for both' % link.attid)

    def test_attribute(self):
        """Simple test for attributeSchema replication"""
        # add new attributeSchema object
        (a_ldn, a_dn) = self._schema_new_attr(self.ldb_dc1, "attr-S", 13)
        # force replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, nc_dn=self.schema_dn, forced=True)
        # check object is replicated
        self._check_object(a_dn)

    def test_attribute_on_ou(self):
        """Simple test having an OU with a custome attribute replicated correctly

        This ensures that the server
        """

       # add new attributeSchema object
        (a_ldn, a_dn) = self._schema_new_attr(self.ldb_dc1, "attr-OU-S", 14)
        (c_ldn, c_dn) = self._schema_new_class(self.ldb_dc1, "cls-OU-A", 15,
                                               3,
                                               {"mayContain": a_ldn})
        ou_dn = ldb.Dn(self.ldb_dc1, "ou=X")
        ou_dn.add_base(self.ldb_dc1.get_default_basedn())
        ou_dn.set_component(0, "OU", a_dn.get_component_value(0))
        rec = {"dn": ou_dn,
               "objectClass": ["top", "organizationalUnit", c_ldn],
               "ou": ou_dn.get_component_value(0),
               a_ldn: "test OU"}
        self.ldb_dc1.add(rec)

        # force replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, nc_dn=self.domain_dn, forced=True)
        # check objects are replicated
        self._check_object(c_dn)
        self._check_object(a_dn)
        self._check_object(ou_dn)
        self.ldb_dc1.delete(ou_dn)

    def test_all(self):
        """Basic plan is to create bunch of classSchema
           and attributeSchema objects, replicate Schema NC
           and then check all objects are replicated correctly"""

        # add new classSchema object
        (c_ldn, c_dn) = self._schema_new_class(self.ldb_dc1, "cls-A", 16)
        # add new attributeSchema object
        (a_ldn, a_dn) = self._schema_new_attr(self.ldb_dc1, "attr-A", 17)

        # add attribute to the class we have
        m = Message.from_dict(self.ldb_dc1,
                              {"dn": c_dn,
                               "mayContain": a_ldn},
                              FLAG_MOD_ADD)
        self.ldb_dc1.modify(m)

        # force replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, nc_dn=self.schema_dn, forced=True)

        # check objects are replicated
        self._check_object(c_dn)
        self._check_object(a_dn)

    def test_classWithCustomBinaryDNLinkAttribute(self):
        # Add a new attribute to the schema, which has binary DN syntax (2.5.5.7)
        (bin_ldn, bin_dn) = self._schema_new_attr(self.ldb_dc1, "attr-Link-Bin", 18,
                                                  attrs={"linkID": "1.2.840.113556.1.2.50",
                                                         "attributeSyntax": "2.5.5.7",
                                                         "omSyntax": "127"})

        (bin_ldn_b, bin_dn_b) = self._schema_new_attr(self.ldb_dc1, "attr-Link-Bin-Back", 19,
                                                      attrs={"linkID": bin_ldn,
                                                             "attributeSyntax": "2.5.5.1",
                                                             "omSyntax": "127"})

        # Add a new class to the schema which can have the binary DN attribute
        (c_ldn, c_dn) = self._schema_new_class(self.ldb_dc1, "cls-Link-Bin", 20,
                                               3,
                                               {"mayContain": bin_ldn})
        (c_ldn_b, c_dn_b) = self._schema_new_class(self.ldb_dc1, "cls-Link-Bin-Back", 21,
                                                   3,
                                                   {"mayContain": bin_ldn_b})

        link_end_dn = ldb.Dn(self.ldb_dc1, "ou=X")
        link_end_dn.add_base(self.ldb_dc1.get_default_basedn())
        link_end_dn.set_component(0, "OU", bin_dn_b.get_component_value(0))

        ou_dn = ldb.Dn(self.ldb_dc1, "ou=X")
        ou_dn.add_base(self.ldb_dc1.get_default_basedn())
        ou_dn.set_component(0, "OU", bin_dn.get_component_value(0))

        # Add an instance of the class to be pointed at
        rec = {"dn": link_end_dn,
               "objectClass": ["top", "organizationalUnit", c_ldn_b],
               "ou": link_end_dn.get_component_value(0)}
        self.ldb_dc1.add(rec)

        # .. and one that does, and points to the first one
        rec = {"dn": ou_dn,
               "objectClass": ["top", "organizationalUnit", c_ldn],
               "ou": ou_dn.get_component_value(0)}
        self.ldb_dc1.add(rec)

        m = Message.from_dict(self.ldb_dc1,
                              {"dn": ou_dn,
                               bin_ldn: "B:8:1234ABCD:%s" % str(link_end_dn)},
                              FLAG_MOD_ADD)
        self.ldb_dc1.modify(m)

        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1,
                                nc_dn=self.schema_dn, forced=True)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1,
                                nc_dn=self.domain_dn, forced=True)

        self._check_object(c_dn)
        self._check_object(bin_dn)

        # Make sure we can delete the backlink
        self.ldb_dc1.delete(link_end_dn)

        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1,
                                nc_dn=self.schema_dn, forced=True)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1,
                                nc_dn=self.domain_dn, forced=True)

    def test_rename(self):
        """Basic plan is to create a classSchema
           and attributeSchema objects, replicate Schema NC
           and then check all objects are replicated correctly"""

        # add new classSchema object
        (c_ldn, c_dn) = self._schema_new_class(self.ldb_dc1, "cls-B", 20)

        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1,
                                nc_dn=self.schema_dn, forced=True)

        # check objects are replicated
        self._check_object(c_dn)

        # rename the Class CN
        c_dn_new = ldb.Dn(self.ldb_dc1, str(c_dn))
        c_dn_new.set_component(0,
                               "CN",
                               c_dn.get_component_value(0) + "-NEW")
        try:
            self.ldb_dc1.rename(c_dn, c_dn_new)
        except LdbError as e2:
            (num, _) = e2.args
            self.fail("failed to change CN for %s: %s" % (c_dn, _))

        # force replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1,
                                nc_dn=self.schema_dn, forced=True)

        # check objects are replicated
        self._check_object(c_dn_new)
