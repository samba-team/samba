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
#  export SUBUNITRUN=$samba4srcdir/scripting/bin/subunitrun
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/dsdb/tests/python" $SUBUNITRUN dsdb_schema_attributes
#

import time
import random

import samba.tests
import ldb
from ldb import SCOPE_BASE, LdbError


class SchemaAttributesTestCase(samba.tests.TestCase):

    def setUp(self):
        super(SchemaAttributesTestCase, self).setUp()

        self.lp = samba.tests.env_loadparm()
        self.samdb = samba.tests.connect_samdb(self.lp.samdb_url())

        # fetch rootDSE
        res = self.samdb.search(base="", expression="", scope=SCOPE_BASE, attrs=["*"])
        self.assertEqual(len(res), 1)
        self.schema_dn = res[0]["schemaNamingContext"][0]
        self.base_dn = res[0]["defaultNamingContext"][0]
        self.forest_level = int(res[0]["forestFunctionality"][0])

    def tearDown(self):
        super(SchemaAttributesTestCase, self).tearDown()

    def _ldap_schemaUpdateNow(self):
        ldif = """
dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
"""
        self.samdb.modify_ldif(ldif)

    def _make_obj_names(self, prefix):
        obj_name = prefix + time.strftime("%s", time.gmtime())
        obj_ldap_name = obj_name.replace("-", "")
        obj_dn = "CN=%s,%s" % (obj_name, self.schema_dn)
        return (obj_name, obj_ldap_name, obj_dn)

    def _make_attr_ldif(self, attr_name, attr_dn, sub_oid, extra=None):
        ldif = """
dn: """ + attr_dn + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: 1.3.6.1.4.1.7165.4.6.1.8.%d.""" % sub_oid + str(random.randint(1, 100000)) + """
attributeSyntax: 2.5.5.12
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""

        if extra is not None:
            ldif += extra + "\n"

        return ldif

    def test_AddIndexedAttribute(self):
        # create names for an attribute to add
        (attr_name, attr_ldap_name, attr_dn) = self._make_obj_names("schemaAttributes-IdxAttr-")
        ldif = self._make_attr_ldif(attr_name, attr_dn, 1,
                                    "searchFlags: %d" % samba.dsdb.SEARCH_FLAG_ATTINDEX)

        # add the new attribute
        self.samdb.add_ldif(ldif)
        self._ldap_schemaUpdateNow()

        # Check @ATTRIBUTES

        attr_res = self.samdb.search(base="@ATTRIBUTES", scope=ldb.SCOPE_BASE)

        self.assertIn(attr_ldap_name, attr_res[0])
        self.assertEqual(len(attr_res[0][attr_ldap_name]), 1)
        self.assertEqual(str(attr_res[0][attr_ldap_name][0]), "CASE_INSENSITIVE")

        # Check @INDEXLIST

        idx_res = self.samdb.search(base="@INDEXLIST", scope=ldb.SCOPE_BASE)

        self.assertIn(attr_ldap_name, [str(x) for x in idx_res[0]["@IDXATTR"]])

    def test_AddUnIndexedAttribute(self):
        # create names for an attribute to add
        (attr_name, attr_ldap_name, attr_dn) = self._make_obj_names("schemaAttributes-UnIdxAttr-")
        ldif = self._make_attr_ldif(attr_name, attr_dn, 2)

        # add the new attribute
        self.samdb.add_ldif(ldif)
        self._ldap_schemaUpdateNow()

        # Check @ATTRIBUTES

        attr_res = self.samdb.search(base="@ATTRIBUTES", scope=ldb.SCOPE_BASE)

        self.assertIn(attr_ldap_name, attr_res[0])
        self.assertEqual(len(attr_res[0][attr_ldap_name]), 1)
        self.assertEqual(str(attr_res[0][attr_ldap_name][0]), "CASE_INSENSITIVE")

        # Check @INDEXLIST

        idx_res = self.samdb.search(base="@INDEXLIST", scope=ldb.SCOPE_BASE)

        self.assertNotIn(attr_ldap_name, [str(x) for x in idx_res[0]["@IDXATTR"]])

    def test_AddTwoIndexedAttributes(self):
        # create names for an attribute to add
        (attr_name, attr_ldap_name, attr_dn) = self._make_obj_names("schemaAttributes-2IdxAttr-")
        ldif = self._make_attr_ldif(attr_name, attr_dn, 3,
                                    "searchFlags: %d" % samba.dsdb.SEARCH_FLAG_ATTINDEX)

        # add the new attribute
        self.samdb.add_ldif(ldif)
        self._ldap_schemaUpdateNow()

        # create names for an attribute to add
        (attr_name2, attr_ldap_name2, attr_dn2) = self._make_obj_names("schemaAttributes-Attr-")
        ldif = self._make_attr_ldif(attr_name2, attr_dn2, 4,
                                    "searchFlags: %d" % samba.dsdb.SEARCH_FLAG_ATTINDEX)

        # add the new attribute
        self.samdb.add_ldif(ldif)
        self._ldap_schemaUpdateNow()

        # Check @ATTRIBUTES

        attr_res = self.samdb.search(base="@ATTRIBUTES", scope=ldb.SCOPE_BASE)

        self.assertIn(attr_ldap_name, attr_res[0])
        self.assertEqual(len(attr_res[0][attr_ldap_name]), 1)
        self.assertEqual(str(attr_res[0][attr_ldap_name][0]), "CASE_INSENSITIVE")

        self.assertIn(attr_ldap_name2, attr_res[0])
        self.assertEqual(len(attr_res[0][attr_ldap_name2]), 1)
        self.assertEqual(str(attr_res[0][attr_ldap_name2][0]), "CASE_INSENSITIVE")

        # Check @INDEXLIST

        idx_res = self.samdb.search(base="@INDEXLIST", scope=ldb.SCOPE_BASE)

        self.assertIn(attr_ldap_name, [str(x) for x in idx_res[0]["@IDXATTR"]])
        self.assertIn(attr_ldap_name2, [str(x) for x in idx_res[0]["@IDXATTR"]])

    def test_modify_at_attributes(self):
        m = {"dn": "@ATTRIBUTES",
             "@TEST_EXTRA": ["HIDDEN"]
             }

        msg = ldb.Message.from_dict(self.samdb, m, ldb.FLAG_MOD_ADD)
        self.samdb.modify(msg)

        res = self.samdb.search(base="@ATTRIBUTES", scope=ldb.SCOPE_BASE,
                                attrs=["@TEST_EXTRA"])
        self.assertEqual(len(res), 1)
        self.assertEqual(str(res[0].dn), "@ATTRIBUTES")
        self.assertEqual(len(res[0]), 1)
        self.assertTrue("@TEST_EXTRA" in res[0])
        self.assertEqual(len(res[0]["@TEST_EXTRA"]), 1)
        self.assertEqual(str(res[0]["@TEST_EXTRA"][0]), "HIDDEN")

        samdb2 = samba.tests.connect_samdb(self.lp.samdb_url())

        # We now only update the @ATTRIBUTES when a transaction happens
        # rather than making a read of the DB do writes.
        #
        # This avoids locking issues and is more expected

        samdb2.transaction_start()
        samdb2.transaction_commit()

        res = self.samdb.search(base="@ATTRIBUTES", scope=ldb.SCOPE_BASE,
                                attrs=["@TEST_EXTRA"])
        self.assertEqual(len(res), 1)
        self.assertEqual(str(res[0].dn), "@ATTRIBUTES")
        self.assertEqual(len(res[0]), 0)
        self.assertFalse("@TEST_EXTRA" in res[0])

    def test_modify_at_indexlist(self):
        m = {"dn": "@INDEXLIST",
             "@TEST_EXTRA": ["1"]
             }

        msg = ldb.Message.from_dict(self.samdb, m, ldb.FLAG_MOD_ADD)
        self.samdb.modify(msg)

        res = self.samdb.search(base="@INDEXLIST", scope=ldb.SCOPE_BASE,
                                attrs=["@TEST_EXTRA"])
        self.assertEqual(len(res), 1)
        self.assertEqual(str(res[0].dn), "@INDEXLIST")
        self.assertEqual(len(res[0]), 1)
        self.assertTrue("@TEST_EXTRA" in res[0])
        self.assertEqual(len(res[0]["@TEST_EXTRA"]), 1)
        self.assertEqual(str(res[0]["@TEST_EXTRA"][0]), "1")

        samdb2 = samba.tests.connect_samdb(self.lp.samdb_url())

        # We now only update the @INDEXLIST when a transaction happens
        # rather than making a read of the DB do writes.
        #
        # This avoids locking issues and is more expected

        samdb2.transaction_start()
        samdb2.transaction_commit()

        res = self.samdb.search(base="@INDEXLIST", scope=ldb.SCOPE_BASE,
                                attrs=["@TEST_EXTRA"])
        self.assertEqual(len(res), 1)
        self.assertEqual(str(res[0].dn), "@INDEXLIST")
        self.assertEqual(len(res[0]), 0)
        self.assertFalse("@TEST_EXTRA" in res[0])

    def test_modify_fail_of_at_indexlist(self):
        m = {"dn": "@INDEXLIST",
             "@TEST_NOT_EXTRA": ["1"]
             }

        msg = ldb.Message.from_dict(self.samdb, m, ldb.FLAG_MOD_DELETE)
        try:
            self.samdb.modify(msg)
            self.fail("modify of @INDEXLIST with a failed constraint should fail")
        except LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_NO_SUCH_ATTRIBUTE)
