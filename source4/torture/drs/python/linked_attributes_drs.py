#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Originally based on ./sam.py
import sys
import os
import base64
import random
import re

sys.path.insert(0, "bin/python")
import samba
from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

from samba.auth import system_session
import ldb
from samba.samdb import SamDB

from samba.dcerpc import drsuapi, misc, drsblobs
from samba.drs_utils import drs_DsBind
from samba.ndr import ndr_unpack, ndr_pack

import drs_base

import time


class LATestException(Exception):
    pass


class LATests(drs_base.DrsBaseTestCase):

    def setUp(self):
        super(LATests, self).setUp()
        # DrsBaseTestCase sets up self.ldb_dc1, self.ldb_dc2
        # we're only using one
        self.samdb = self.ldb_dc1

        self.base_dn = self.samdb.domain_dn()
        self.ou = "OU=la,%s" % self.base_dn
        if True:
            try:
                self.samdb.delete(self.ou, ['tree_delete:1'])
            except ldb.LdbError as e:
                pass
        self.samdb.add({'objectclass': 'organizationalUnit',
                        'dn': self.ou})

        self.dc_guid = self.samdb.get_invocation_id()
        self.drs, self.drs_handle = self._ds_bind(self.dnsname_dc1)

    def tearDown(self):
        super(LATests, self).tearDown()
        try:
            self.samdb.delete(self.ou, ['tree_delete:1'])
        except ldb.LdbError as e:
            pass

    def delete_user(self, user):
        self.samdb.delete(user['dn'])
        del self.users[self.users.index(user)]

    def add_object(self, cn, objectclass):
        dn = "CN=%s,%s" % (cn, self.ou)
        self.samdb.add({'cn': cn,
                        'objectclass': objectclass,
                        'dn': dn})

        return dn

    def add_objects(self, n, objectclass, prefix=None):
        if prefix is None:
            prefix = objectclass
        dns = []
        for i in range(n):
            dns.append(self.add_object("%s%d" % (prefix, i + 1),
                                       objectclass))
        return dns

    def add_linked_attribute(self, src, dest, attr='member'):
        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, src)
        m[attr] = ldb.MessageElement(dest, ldb.FLAG_MOD_ADD, attr)
        self.samdb.modify(m)

    def remove_linked_attribute(self, src, dest, attr='member'):
        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, src)
        m[attr] = ldb.MessageElement(dest, ldb.FLAG_MOD_DELETE, attr)
        self.samdb.modify(m)

    def attr_search(self, obj, expected, attr, scope=ldb.SCOPE_BASE):

        req8 = self._exop_req8(dest_dsa=None,
                               invocation_id=self.dc_guid,
                               nc_dn_str=obj,
                               exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ)

        level, ctr = self.drs.DsGetNCChanges(self.drs_handle, 8, req8)
        expected_attid = getattr(drsuapi, 'DRSUAPI_ATTID_' + attr)

        links = []
        for link in ctr.linked_attributes:
            if link.attid == expected_attid:
                unpacked = ndr_unpack(drsuapi.DsReplicaObjectIdentifier3,
                                      link.value.blob)
                active = link.flags & drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE
                links.append((str(unpacked.dn), bool(active)))

        return links

    def assert_forward_links(self, obj, expected, attr='member'):
        results = self.attr_search(obj, expected, attr)
        self.assertEqual(len(results), len(expected))

        for k, v in results:
            self.assertTrue(k in expected)
            self.assertEqual(expected[k], v, "%s active flag should be %d, not %d" %
                             (k, expected[k], v))

    def get_object_guid(self, dn):
        res = self.samdb.search(dn,
                                scope=ldb.SCOPE_BASE,
                                attrs=['objectGUID'])
        return str(misc.GUID(res[0]['objectGUID'][0]))

    def test_links_all_delete_group(self):
        u1, u2 = self.add_objects(2, 'user', 'u_all_del_group')
        g1, g2 = self.add_objects(2, 'group', 'g_all_del_group')
        g2guid = self.get_object_guid(g2)

        self.add_linked_attribute(g1, u1)
        self.add_linked_attribute(g2, u1)
        self.add_linked_attribute(g2, u2)

        self.samdb.delete(g2)
        self.assert_forward_links(g1, {u1: True})
        res = self.samdb.search('<GUID=%s>' % g2guid,
                                scope=ldb.SCOPE_BASE,
                                controls=['show_deleted:1'])
        new_dn = res[0].dn
        self.assert_forward_links(new_dn, {})

    def test_la_links_delete_link(self):
        u1, u2 = self.add_objects(2, 'user', 'u_del_link')
        g1, g2 = self.add_objects(2, 'group', 'g_del_link')

        self.add_linked_attribute(g1, u1)
        self.add_linked_attribute(g2, u1)
        self.add_linked_attribute(g2, u2)

        self.remove_linked_attribute(g2, u1)

        self.assert_forward_links(g1, {u1: True})
        self.assert_forward_links(g2, {u1: False, u2: True})

        self.add_linked_attribute(g2, u1)
        self.remove_linked_attribute(g2, u2)
        self.assert_forward_links(g2, {u1: True, u2: False})
        self.remove_linked_attribute(g2, u1)
        self.assert_forward_links(g2, {u1: False, u2: False})

    def test_la_links_delete_user(self):
        u1, u2 = self.add_objects(2, 'user', 'u_del_user')
        g1, g2 = self.add_objects(2, 'group', 'g_del_user')

        self.add_linked_attribute(g1, u1)
        self.add_linked_attribute(g2, u1)
        self.add_linked_attribute(g2, u2)

        self.samdb.delete(u1)

        self.assert_forward_links(g1, {})
        self.assert_forward_links(g2, {u2: True})
