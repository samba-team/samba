#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This is a port of the original in testprogs/ejs/ldap.js

# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008-2011
# Copyright (C) Catalyst.Net Ltd 2017
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



from __future__ import print_function
import optparse
import sys
import time
import random
import os

sys.path.insert(0, "bin/python")
import samba
from samba.tests.subunitrun import TestProgram, SubunitOptions

import samba.getopt as options

from samba.auth import system_session
from ldb import SCOPE_ONELEVEL, SCOPE_BASE, LdbError
from ldb import ERR_NO_SUCH_OBJECT
from ldb import ERR_UNWILLING_TO_PERFORM
from ldb import ERR_ENTRY_ALREADY_EXISTS
from ldb import ERR_CONSTRAINT_VIOLATION
from ldb import ERR_OBJECT_CLASS_VIOLATION
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_REPLACE
from samba.samdb import SamDB
from samba.dsdb import DS_DOMAIN_FUNCTION_2003
from samba.tests import delete_force
from samba.ndr import ndr_unpack
from samba.dcerpc import drsblobs

parser = optparse.OptionParser("ldap_schema.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)


class SchemaTests(samba.tests.TestCase):

    def setUp(self):
        super(SchemaTests, self).setUp()
        self.ldb = SamDB(host, credentials=creds,
            session_info=system_session(lp), lp=lp, options=ldb_options)
        self.base_dn = self.ldb.domain_dn()
        self.schema_dn = self.ldb.get_schema_basedn().get_linearized()

    def test_generated_schema(self):
        """Testing we can read the generated schema via LDAP"""
        res = self.ldb.search("cn=aggregate,"+self.schema_dn, scope=SCOPE_BASE,
                attrs=["objectClasses", "attributeTypes", "dITContentRules"])
        self.assertEquals(len(res), 1)
        self.assertTrue("dITContentRules" in res[0])
        self.assertTrue("objectClasses" in res[0])
        self.assertTrue("attributeTypes" in res[0])

    def test_generated_schema_is_operational(self):
        """Testing we don't get the generated schema via LDAP by default"""
        # Must keep the "*" form
        res = self.ldb.search("cn=aggregate,"+self.schema_dn, scope=SCOPE_BASE,
                              attrs=["*"])
        self.assertEquals(len(res), 1)
        self.assertFalse("dITContentRules" in res[0])
        self.assertFalse("objectClasses" in res[0])
        self.assertFalse("attributeTypes" in res[0])

    def test_schemaUpdateNow(self):
        """Testing schemaUpdateNow"""
        rand = str(random.randint(1,100000))
        attr_name = "test-Attr" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")

        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: 1.3.6.1.4.1.7165.4.6.1.6.1.""" + rand + """
attributeSyntax: 2.5.5.12
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)
        # We must do a schemaUpdateNow otherwise it's not 100% sure that the schema
        # will contain the new attribute
        ldif = """
dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
"""
        self.ldb.modify_ldif(ldif)

        # Search for created attribute
        res = []
        res = self.ldb.search("cn=%s,%s" % (attr_name, self.schema_dn), scope=SCOPE_BASE,
                              attrs=["lDAPDisplayName","schemaIDGUID", "msDS-IntID"])
        self.assertEquals(len(res), 1)
        self.assertEquals(res[0]["lDAPDisplayName"][0], attr_ldap_display_name)
        self.assertTrue("schemaIDGUID" in res[0])
        if "msDS-IntId" in res[0]:
            msDS_IntId = int(res[0]["msDS-IntId"][0])
            if msDS_IntId < 0:
                msDS_IntId += (1 << 32)
        else:
            msDS_IntId = None

        class_name = "test-Class" + time.strftime("%s", time.gmtime())
        class_ldap_display_name = class_name.replace("-", "")

        # First try to create a class with a wrong "defaultObjectCategory"
        ldif = """
dn: CN=%s,%s""" % (class_name, self.schema_dn) + """
objectClass: top
objectClass: classSchema
defaultObjectCategory: CN=_
adminDescription: """ + class_name + """
adminDisplayName: """ + class_name + """
cn: """ + class_name + """
governsId: 1.3.6.1.4.1.7165.4.6.2.6.1.""" + str(random.randint(1,100000)) + """
instanceType: 4
objectClassCategory: 1
subClassOf: organizationalPerson
systemFlags: 16
rDNAttID: cn
systemMustContain: cn
systemMustContain: """ + attr_ldap_display_name + """
systemOnly: FALSE
"""
        try:
                 self.ldb.add_ldif(ldif)
                 self.fail()
        except LdbError as e1:
                 (num, _) = e1.args
                 self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        ldif = """
dn: CN=%s,%s""" % (class_name, self.schema_dn) + """
objectClass: top
objectClass: classSchema
adminDescription: """ + class_name + """
adminDisplayName: """ + class_name + """
cn: """ + class_name + """
governsId: 1.3.6.1.4.1.7165.4.6.2.6.2.""" + str(random.randint(1,100000)) + """
instanceType: 4
objectClassCategory: 1
subClassOf: organizationalPerson
systemFlags: 16
rDNAttID: cn
systemMustContain: cn
systemMustContain: """ + attr_ldap_display_name + """
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        # Search for created objectclass
        res = []
        res = self.ldb.search("cn=%s,%s" % (class_name, self.schema_dn), scope=SCOPE_BASE,
                              attrs=["lDAPDisplayName", "defaultObjectCategory", "schemaIDGUID", "distinguishedName"])
        self.assertEquals(len(res), 1)
        self.assertEquals(res[0]["lDAPDisplayName"][0], class_ldap_display_name)
        self.assertEquals(res[0]["defaultObjectCategory"][0], res[0]["distinguishedName"][0])
        self.assertTrue("schemaIDGUID" in res[0])

        ldif = """
dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
"""
        self.ldb.modify_ldif(ldif)

        object_name = "obj" + time.strftime("%s", time.gmtime())

        ldif = """
dn: CN=%s,CN=Users,%s"""% (object_name, self.base_dn) + """
objectClass: organizationalPerson
objectClass: person
objectClass: """ + class_ldap_display_name + """
objectClass: top
cn: """ + object_name + """
instanceType: 4
objectCategory: CN=%s,%s"""% (class_name, self.schema_dn) + """
distinguishedName: CN=%s,CN=Users,%s"""% (object_name, self.base_dn) + """
name: """ + object_name + """
""" + attr_ldap_display_name + """: test
"""
        self.ldb.add_ldif(ldif)

        # Search for created object
        obj_res = self.ldb.search("cn=%s,cn=Users,%s" % (object_name, self.base_dn), scope=SCOPE_BASE, attrs=["replPropertyMetaData"])

        self.assertEquals(len(obj_res), 1)
        self.assertTrue("replPropertyMetaData" in obj_res[0])
        val = obj_res[0]["replPropertyMetaData"][0]
        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob, str(val))
        obj = repl.ctr

        # Windows 2000 functional level won't have this.  It is too
        # hard to work it out from the prefixmap however, so we skip
        # this test in that case.
        if msDS_IntId is not None:
            found = False
            for o in repl.ctr.array:
                if o.attid == msDS_IntId:
                    found = True
                    break
            self.assertTrue(found, "Did not find 0x%08x in replPropertyMetaData" % msDS_IntId)
        # Delete the object
        delete_force(self.ldb, "cn=%s,cn=Users,%s" % (object_name, self.base_dn))

    def test_subClassOf(self):
        """ Testing usage of custom child schamaClass
        """

        class_name = "my-Class" + time.strftime("%s", time.gmtime())
        class_ldap_display_name = class_name.replace("-", "")

        ldif = """
dn: CN=%s,%s""" % (class_name, self.schema_dn) + """
objectClass: top
objectClass: classSchema
adminDescription: """ + class_name + """
adminDisplayName: """ + class_name + """
cn: """ + class_name + """
governsId: 1.3.6.1.4.1.7165.4.6.2.6.3.""" + str(random.randint(1,100000)) + """
instanceType: 4
objectClassCategory: 1
subClassOf: organizationalUnit
systemFlags: 16
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        # Search for created objectclass
        res = []
        res = self.ldb.search("cn=%s,%s" % (class_name, self.schema_dn), scope=SCOPE_BASE,
                              attrs=["lDAPDisplayName", "defaultObjectCategory",
                                     "schemaIDGUID", "distinguishedName"])
        self.assertEquals(len(res), 1)
        self.assertEquals(res[0]["lDAPDisplayName"][0], class_ldap_display_name)
        self.assertEquals(res[0]["defaultObjectCategory"][0], res[0]["distinguishedName"][0])
        self.assertTrue("schemaIDGUID" in res[0])

        ldif = """
dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
"""
        self.ldb.modify_ldif(ldif)

        object_name = "org" + time.strftime("%s", time.gmtime())

        ldif = """
dn: OU=%s,%s""" % (object_name, self.base_dn) + """
objectClass: """ + class_ldap_display_name + """
ou: """ + object_name + """
instanceType: 4
"""
        self.ldb.add_ldif(ldif)

        # Search for created object
        res = []
        res = self.ldb.search("ou=%s,%s" % (object_name, self.base_dn), scope=SCOPE_BASE, attrs=["dn"])
        self.assertEquals(len(res), 1)
        # Delete the object
        delete_force(self.ldb, "ou=%s,%s" % (object_name, self.base_dn))


    def test_duplicate_attributeID(self):
        """Testing creating a duplicate attribute"""
        rand = str(random.randint(1,100000))
        attr_name = "test-Attr" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.2." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
attributeSyntax: 2.5.5.12
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s-dup,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """dup
adminDisplayName: """ + attr_name + """dup
cn: """ + attr_name + """-dup
attributeId: """ + attributeID + """
attributeSyntax: 2.5.5.12
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        try:
            self.ldb.add_ldif(ldif)
            self.fail("Should have failed to add duplicate attributeID value")
        except LdbError as e2:
            (enum, estr) = e2.args
            self.assertEquals(enum, ERR_UNWILLING_TO_PERFORM)


    def test_duplicate_attributeID_governsID(self):
        """Testing creating a duplicate attribute and class"""
        rand = str(random.randint(1,100000))
        attr_name = "test-Attr" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.3." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
attributeSyntax: 2.5.5.12
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s-dup,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: classSchema
adminDescription: """ + attr_name + """dup
adminDisplayName: """ + attr_name + """dup
cn: """ + attr_name + """-dup
governsId: """ + attributeID + """
instanceType: 4
objectClassCategory: 1
subClassOf: organizationalPerson
rDNAttID: cn
systemMustContain: cn
systemOnly: FALSE
"""
        try:
            self.ldb.add_ldif(ldif)
            self.fail("Should have failed to add duplicate governsID conflicting with attributeID value")
        except LdbError as e3:
            (enum, estr) = e3.args
            self.assertEquals(enum, ERR_UNWILLING_TO_PERFORM)


    def test_duplicate_cn(self):
        """Testing creating a duplicate attribute"""
        rand = str(random.randint(1,100000))
        attr_name = "test-Attr" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.4." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
attributeSyntax: 2.5.5.12
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """dup
adminDisplayName: """ + attr_name + """dup
cn: """ + attr_name + """
attributeId: """ + attributeID + """.1
attributeSyntax: 2.5.5.12
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        try:
            self.ldb.add_ldif(ldif)
            self.fail("Should have failed to add attribute with duplicate CN")
        except LdbError as e4:
            (enum, estr) = e4.args
            self.assertEquals(enum, ERR_ENTRY_ALREADY_EXISTS)

    def test_duplicate_implicit_ldapdisplayname(self):
        """Testing creating a duplicate attribute ldapdisplayname"""
        rand = str(random.randint(1,100000))
        attr_name = "test-Attr" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.5." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
attributeSyntax: 2.5.5.12
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s-dup,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """dup
adminDisplayName: """ + attr_name + """dup
cn: """ + attr_name + """-dup
ldapDisplayName: """ + attr_ldap_display_name + """
attributeId: """ + attributeID + """.1
attributeSyntax: 2.5.5.12
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        try:
            self.ldb.add_ldif(ldif)
            self.fail("Should have failed to add attribute with duplicate of the implicit ldapDisplayName")
        except LdbError as e5:
            (enum, estr) = e5.args
            self.assertEquals(enum, ERR_UNWILLING_TO_PERFORM)


    def test_duplicate_explicit_ldapdisplayname(self):
        """Testing creating a duplicate attribute ldapdisplayname"""
        rand = str(random.randint(1,100000))
        attr_name = "test-Attr" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.6." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
attributeSyntax: 2.5.5.12
ldapDisplayName: """ + attr_ldap_display_name + """
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s-dup,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """dup
adminDisplayName: """ + attr_name + """dup
cn: """ + attr_name + """-dup
ldapDisplayName: """ + attr_ldap_display_name + """
attributeId: """ + attributeID + """.1
attributeSyntax: 2.5.5.12
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        try:
            self.ldb.add_ldif(ldif)
            self.fail("Should have failed to add attribute with duplicate ldapDisplayName")
        except LdbError as e6:
            (enum, estr) = e6.args
            self.assertEquals(enum, ERR_UNWILLING_TO_PERFORM)


    def test_duplicate_explicit_ldapdisplayname_with_class(self):
        """Testing creating a duplicate attribute ldapdisplayname between
        and attribute and a class"""
        rand = str(random.randint(1,100000))
        attr_name = "test-Attr" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.7." + rand
        governsID   = "1.3.6.1.4.1.7165.4.6.2.6.4." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
attributeSyntax: 2.5.5.12
ldapDisplayName: """ + attr_ldap_display_name + """
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s-dup,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: classSchema
adminDescription: """ + attr_name + """dup
adminDisplayName: """ + attr_name + """dup
cn: """ + attr_name + """-dup
ldapDisplayName: """ + attr_ldap_display_name + """
governsID: """ + governsID + """
instanceType: 4
objectClassCategory: 1
subClassOf: organizationalPerson
rDNAttID: cn
systemMustContain: cn
systemOnly: FALSE
"""
        try:
            self.ldb.add_ldif(ldif)
            self.fail("Should have failed to add class with duplicate ldapDisplayName")
        except LdbError as e7:
            (enum, estr) = e7.args
            self.assertEquals(enum, ERR_UNWILLING_TO_PERFORM)


    def test_duplicate_via_rename_ldapdisplayname(self):
        """Testing creating a duplicate attribute ldapdisplayname"""
        rand = str(random.randint(1,100000))
        attr_name = "test-Attr" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.8." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
attributeSyntax: 2.5.5.12
ldapDisplayName: """ + attr_ldap_display_name + """
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s-dup,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """dup
adminDisplayName: """ + attr_name + """dup
cn: """ + attr_name + """-dup
ldapDisplayName: """ + attr_ldap_display_name + """dup
attributeId: """ + attributeID + """.1
attributeSyntax: 2.5.5.12
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s-dup,%s""" % (attr_name, self.schema_dn) + """
changetype: modify
replace: ldapDisplayName
ldapDisplayName: """ + attr_ldap_display_name + """
-
"""
        try:
            self.ldb.modify_ldif(ldif)
            self.fail("Should have failed to modify schema to have attribute with duplicate ldapDisplayName")
        except LdbError as e8:
            (enum, estr) = e8.args
            self.assertEquals(enum, ERR_UNWILLING_TO_PERFORM)


    def test_duplicate_via_rename_attributeID(self):
        """Testing creating a duplicate attributeID"""
        rand = str(random.randint(1,100000))
        attr_name = "test-Attr" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.9." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
attributeSyntax: 2.5.5.12
ldapDisplayName: """ + attr_ldap_display_name + """
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s-dup,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """dup
adminDisplayName: """ + attr_name + """dup
cn: """ + attr_name + """-dup
ldapDisplayName: """ + attr_ldap_display_name + """dup
attributeId: """ + attributeID + """.1
attributeSyntax: 2.5.5.12
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s-dup,%s""" % (attr_name, self.schema_dn) + """
changetype: modify
replace: attributeId
attributeId: """ + attributeID + """
-
"""
        try:
            self.ldb.modify_ldif(ldif)
            self.fail("Should have failed to modify schema to have attribute with duplicate attributeID")
        except LdbError as e9:
            (enum, estr) = e9.args
            self.assertEquals(enum, ERR_CONSTRAINT_VIOLATION)

    def test_remove_ldapdisplayname(self):
        """Testing removing the ldapdisplayname"""
        rand = str(random.randint(1,100000))
        attr_name = "test-Attr" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.10." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
attributeSyntax: 2.5.5.12
ldapDisplayName: """ + attr_ldap_display_name + """
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
changetype: modify
replace: ldapDisplayName
-
"""
        try:
            self.ldb.modify_ldif(ldif)
            self.fail("Should have failed to remove the ldapdisplayname")
        except LdbError as e10:
            (enum, estr) = e10.args
            self.assertEquals(enum, ERR_OBJECT_CLASS_VIOLATION)

    def test_rename_ldapdisplayname(self):
        """Testing renaming ldapdisplayname"""
        rand = str(random.randint(1,100000))
        attr_name = "test-Attr" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.11." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
attributeSyntax: 2.5.5.12
ldapDisplayName: """ + attr_ldap_display_name + """
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
changetype: modify
replace: ldapDisplayName
ldapDisplayName: """ + attr_ldap_display_name + """2
-
"""
        self.ldb.modify_ldif(ldif)


    def test_change_attributeID(self):
        """Testing change the attributeID"""
        rand = str(random.randint(1,100000))
        attr_name = "test-Attr" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.12." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
attributeSyntax: 2.5.5.12
ldapDisplayName: """ + attr_ldap_display_name + """
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
changetype: modify
replace: attributeID
attributeId: """ + attributeID + """.1

"""
        try:
            self.ldb.modify_ldif(ldif)
            self.fail("Should have failed to modify schema to have different attributeID")
        except LdbError as e11:
            (enum, estr) = e11.args
            self.assertEquals(enum, ERR_CONSTRAINT_VIOLATION)


    def test_change_attributeID_same(self):
        """Testing change the attributeID to the same value"""
        rand = str(random.randint(1,100000))
        attr_name = "test-Attr" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.13." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
attributeSyntax: 2.5.5.12
ldapDisplayName: """ + attr_ldap_display_name + """
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
changetype: modify
replace: attributeID
attributeId: """ + attributeID + """

"""
        try:
            self.ldb.modify_ldif(ldif)
            self.fail("Should have failed to modify schema to have the same attributeID")
        except LdbError as e12:
            (enum, estr) = e12.args
            self.assertEquals(enum, ERR_CONSTRAINT_VIOLATION)


    def test_generated_linkID(self):
        """
        Test that we automatically generate a linkID if the
        OID "1.2.840.113556.1.2.50" is given as the linkID
        of a new attribute, and that we don't get/can't add
        duplicate linkIDs. Also test that we can add a backlink
        by providing the attributeID or ldapDisplayName of
        a forwards link in the linkID attribute.
        """

        # linkID generation isn't available before 2003
        res = self.ldb.search(base="", expression="", scope=SCOPE_BASE,
                         attrs=["domainControllerFunctionality"])
        self.assertEquals(len(res), 1)
        dc_level = int(res[0]["domainControllerFunctionality"][0])
        if dc_level < DS_DOMAIN_FUNCTION_2003:
            return

        rand = str(random.randint(1,100000))

        attr_name_1 = "test-generated-linkID" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name_1 = attr_name_1.replace("-", "")
        attributeID_1 = "1.3.6.1.4.1.7165.4.6.1.6.16." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name_1, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name_1 + """
adminDisplayName: """ + attr_name_1 + """
cn: """ + attr_name_1 + """
attributeId: """ + attributeID_1 + """
linkID: 1.2.840.113556.1.2.50
attributeSyntax: 2.5.5.1
ldapDisplayName: """ + attr_ldap_display_name_1 + """
omSyntax: 127
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""

        try:
            self.ldb.add_ldif(ldif)
        except LdbError as e13:
            (enum, estr) = e13.args
            self.fail(estr)

        attr_name_2 = "test-generated-linkID-2" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name_2 = attr_name_2.replace("-", "")
        attributeID_2 = "1.3.6.1.4.1.7165.4.6.1.6.17." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name_2, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name_2 + """
adminDisplayName: """ + attr_name_2 + """
cn: """ + attr_name_2 + """
attributeId: """ + attributeID_2 + """
linkID: 1.2.840.113556.1.2.50
attributeSyntax: 2.5.5.1
ldapDisplayName: """ + attr_ldap_display_name_2 + """
omSyntax: 127
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""

        try:
            self.ldb.add_ldif(ldif)
        except LdbError as e14:
            (enum, estr) = e14.args
            self.fail(estr)

        res = self.ldb.search("CN=%s,%s" % (attr_name_1, self.schema_dn),
                              scope=SCOPE_BASE,
                              attrs=["linkID"])
        self.assertEquals(len(res), 1)
        linkID_1 = int(res[0]["linkID"][0])

        res = self.ldb.search("CN=%s,%s" % (attr_name_2, self.schema_dn),
                              scope=SCOPE_BASE,
                              attrs=["linkID"])
        self.assertEquals(len(res), 1)
        linkID_2 = int(res[0]["linkID"][0])

        # 0 should never be generated as a linkID
        self.assertFalse(linkID_1 == 0)
        self.assertFalse(linkID_2 == 0)

        # The generated linkID should always be even, because
        # it should assume we're adding a forward link.
        self.assertTrue(linkID_1 % 2 == 0)
        self.assertTrue(linkID_2 % 2 == 0)

        self.assertFalse(linkID_1 == linkID_2)

        # This is only necessary against Windows, since we depend
        # on the previously added links in the next ones and Windows
        # won't refresh the schema as we add them.
        ldif = """
dn:
changetype: modify
replace: schemaupdatenow
schemaupdatenow: 1
"""
        self.ldb.modify_ldif(ldif)

        # If we add a new link with the same linkID, it should fail
        attr_name = "test-generated-linkID-duplicate" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.18." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
linkID: """ + str(linkID_1) + """
attributeSyntax: 2.5.5.1
ldapDisplayName: """ + attr_ldap_display_name + """
omSyntax: 127
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""

        try:
            self.ldb.add_ldif(ldif)
            self.fail("Should have failed to add duplicate linkID value")
        except LdbError as e15:
            (enum, estr) = e15.args
            self.assertEquals(enum, ERR_UNWILLING_TO_PERFORM)

        # If we add another attribute with the attributeID or lDAPDisplayName
        # of a forward link in its linkID field, it should add as a backlink

        attr_name_3 = "test-generated-linkID-backlink" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name_3 = attr_name_3.replace("-", "")
        attributeID_3 = "1.3.6.1.4.1.7165.4.6.1.6.19." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name_3, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name_3 + """
adminDisplayName: """ + attr_name_3 + """
cn: """ + attr_name_3 + """
attributeId: """ + attributeID_3 + """
linkID: """ + str(linkID_1+1) + """
attributeSyntax: 2.5.5.1
ldapDisplayName: """ + attr_ldap_display_name_3 + """
omSyntax: 127
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""

        try:
            self.ldb.add_ldif(ldif)
        except LdbError as e16:
            (enum, estr) = e16.args
            self.fail(estr)

        res = self.ldb.search("CN=%s,%s" % (attr_name_3, self.schema_dn),
                              scope=SCOPE_BASE,
                              attrs=["linkID"])
        self.assertEquals(len(res), 1)
        linkID = int(res[0]["linkID"][0])
        self.assertEquals(linkID, linkID_1 + 1)

        attr_name_4 = "test-generated-linkID-backlink-2" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name_4 = attr_name_4.replace("-", "")
        attributeID_4 = "1.3.6.1.4.1.7165.4.6.1.6.20." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name_4, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name_4 + """
adminDisplayName: """ + attr_name_4 + """
cn: """ + attr_name_4 + """
attributeId: """ + attributeID_4 + """
linkID: """ + attr_ldap_display_name_2 + """
attributeSyntax: 2.5.5.1
ldapDisplayName: """ + attr_ldap_display_name_4 + """
omSyntax: 127
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""

        try:
            self.ldb.add_ldif(ldif)
        except LdbError as e17:
            (enum, estr) = e17.args
            self.fail(estr)

        res = self.ldb.search("CN=%s,%s" % (attr_name_4, self.schema_dn),
                              scope=SCOPE_BASE,
                              attrs=["linkID"])
        self.assertEquals(len(res), 1)
        linkID = int(res[0]["linkID"][0])
        self.assertEquals(linkID, linkID_2 + 1)

        # If we then try to add another backlink in the same way
        # for the same forwards link, we should fail.

        attr_name = "test-generated-linkID-backlink-duplicate" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.21." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
linkID: """ + attributeID_1 + """
attributeSyntax: 2.5.5.1
ldapDisplayName: """ + attr_ldap_display_name + """
omSyntax: 127
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""

        try:
            self.ldb.add_ldif(ldif)
            self.fail("Should have failed to add duplicate backlink")
        except LdbError as e18:
            (enum, estr) = e18.args
            self.assertEquals(enum, ERR_UNWILLING_TO_PERFORM)

        # If we try to supply the attributeID or ldapDisplayName
        # of an existing backlink in the linkID field of a new link,
        # it should fail.

        attr_name = "test-generated-linkID-backlink-invalid" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.22." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
linkID: """ + attributeID_3 + """
attributeSyntax: 2.5.5.1
ldapDisplayName: """ + attr_ldap_display_name + """
omSyntax: 127
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""

        try:
            self.ldb.add_ldif(ldif)
            self.fail("Should have failed to add backlink of backlink")
        except LdbError as e19:
            (enum, estr) = e19.args
            self.assertEquals(enum, ERR_UNWILLING_TO_PERFORM)

        attr_name = "test-generated-linkID-backlink-invalid-2" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.23." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
linkID: """ + attr_ldap_display_name_4 + """
attributeSyntax: 2.5.5.1
ldapDisplayName: """ + attr_ldap_display_name + """
omSyntax: 127
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""

        try:
            self.ldb.add_ldif(ldif)
            self.fail("Should have failed to add backlink of backlink")
        except LdbError as e20:
            (enum, estr) = e20.args
            self.assertEquals(enum, ERR_UNWILLING_TO_PERFORM)

    def test_generated_mAPIID(self):
        """
        Test that we automatically generate a mAPIID if the
        OID "1.2.840.113556.1.2.49" is given as the mAPIID
        of a new attribute, and that we don't get/can't add
        duplicate mAPIIDs.
        """

        rand = str(random.randint(1,100000))

        attr_name_1 = "test-generated-mAPIID" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name_1 = attr_name_1.replace("-", "")
        attributeID_1 = "1.3.6.1.4.1.7165.4.6.1.6.24." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name_1, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name_1 + """
adminDisplayName: """ + attr_name_1 + """
cn: """ + attr_name_1 + """
attributeId: """ + attributeID_1 + """
mAPIID: 1.2.840.113556.1.2.49
attributeSyntax: 2.5.5.1
ldapDisplayName: """ + attr_ldap_display_name_1 + """
omSyntax: 127
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""

        try:
            self.ldb.add_ldif(ldif)
        except LdbError as e21:
            (enum, estr) = e21.args
            self.fail(estr)

        res = self.ldb.search("CN=%s,%s" % (attr_name_1, self.schema_dn),
                              scope=SCOPE_BASE,
                              attrs=["mAPIID"])
        self.assertEquals(len(res), 1)
        mAPIID_1 = int(res[0]["mAPIID"][0])

        ldif = """
dn:
changetype: modify
replace: schemaupdatenow
schemaupdatenow: 1
"""
        self.ldb.modify_ldif(ldif)

        # If we add a new attribute with the same mAPIID, it should fail
        attr_name = "test-generated-mAPIID-duplicate" + time.strftime("%s", time.gmtime()) + "-" + rand
        attr_ldap_display_name = attr_name.replace("-", "")
        attributeID = "1.3.6.1.4.1.7165.4.6.1.6.25." + rand
        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: """ + attributeID + """
mAPIID: """ + str(mAPIID_1) + """
attributeSyntax: 2.5.5.1
ldapDisplayName: """ + attr_ldap_display_name + """
omSyntax: 127
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""

        try:
            self.ldb.add_ldif(ldif)
            self.fail("Should have failed to add duplicate mAPIID value")
        except LdbError as e22:
            (enum, estr) = e22.args
            self.assertEquals(enum, ERR_UNWILLING_TO_PERFORM)


    def test_change_governsID(self):
        """Testing change the governsID"""
        rand = str(random.randint(1,100000))
        class_name = "test-Class" + time.strftime("%s", time.gmtime()) + "-" + rand
        class_ldap_display_name = class_name.replace("-", "")
        governsID = "1.3.6.1.4.1.7165.4.6.2.6.5." + rand
        ldif = """
dn: CN=%s,%s""" % (class_name, self.schema_dn) + """
objectClass: top
objectClass: classSchema
adminDescription: """ + class_name + """
adminDisplayName: """ + class_name + """
cn: """ + class_name + """
governsId: """ + governsID + """
ldapDisplayName: """ + class_ldap_display_name + """
instanceType: 4
objectClassCategory: 1
subClassOf: organizationalPerson
rDNAttID: cn
systemMustContain: cn
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s,%s""" % (class_name, self.schema_dn) + """
changetype: modify
replace: governsID
governsId: """ + governsID + """.1

"""
        try:
            self.ldb.modify_ldif(ldif)
            self.fail("Should have failed to modify schema to have different governsID")
        except LdbError as e23:
            (enum, estr) = e23.args
            self.assertEquals(enum, ERR_CONSTRAINT_VIOLATION)


    def test_change_governsID_same(self):
        """Testing change the governsID"""
        rand = str(random.randint(1,100000))
        class_name = "test-Class" + time.strftime("%s", time.gmtime()) + "-" + rand
        class_ldap_display_name = class_name.replace("-", "")
        governsID = "1.3.6.1.4.1.7165.4.6.2.6.6." + rand
        ldif = """
dn: CN=%s,%s""" % (class_name, self.schema_dn) + """
objectClass: top
objectClass: classSchema
adminDescription: """ + class_name + """
adminDisplayName: """ + class_name + """
cn: """ + class_name + """
governsId: """ + governsID + """
ldapDisplayName: """ + class_ldap_display_name + """
instanceType: 4
objectClassCategory: 1
subClassOf: organizationalPerson
rDNAttID: cn
systemMustContain: cn
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        ldif = """
dn: CN=%s,%s""" % (class_name, self.schema_dn) + """
changetype: modify
replace: governsID
governsId: """ + governsID + """.1

"""
        try:
            self.ldb.modify_ldif(ldif)
            self.fail("Should have failed to modify schema to have the same governsID")
        except LdbError as e24:
            (enum, estr) = e24.args
            self.assertEquals(enum, ERR_CONSTRAINT_VIOLATION)


    def test_subClassOf(self):
        """ Testing usage of custom child classSchema
        """

        class_name = "my-Class" + time.strftime("%s", time.gmtime())
        class_ldap_display_name = class_name.replace("-", "")

        ldif = """
dn: CN=%s,%s""" % (class_name, self.schema_dn) + """
objectClass: top
objectClass: classSchema
adminDescription: """ + class_name + """
adminDisplayName: """ + class_name + """
cn: """ + class_name + """
governsId: 1.3.6.1.4.1.7165.4.6.2.6.7.""" + str(random.randint(1,100000)) + """
instanceType: 4
objectClassCategory: 1
subClassOf: organizationalUnit
systemFlags: 16
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        # Search for created objectclass
        res = []
        res = self.ldb.search("cn=%s,%s" % (class_name, self.schema_dn), scope=SCOPE_BASE,
                              attrs=["lDAPDisplayName", "defaultObjectCategory",
                                     "schemaIDGUID", "distinguishedName"])
        self.assertEquals(len(res), 1)
        self.assertEquals(res[0]["lDAPDisplayName"][0], class_ldap_display_name)
        self.assertEquals(res[0]["defaultObjectCategory"][0], res[0]["distinguishedName"][0])
        self.assertTrue("schemaIDGUID" in res[0])

        ldif = """
dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
"""
        self.ldb.modify_ldif(ldif)

        object_name = "org" + time.strftime("%s", time.gmtime())

        ldif = """
dn: OU=%s,%s""" % (object_name, self.base_dn) + """
objectClass: """ + class_ldap_display_name + """
ou: """ + object_name + """
instanceType: 4
"""
        self.ldb.add_ldif(ldif)

        # Search for created object
        res = []
        res = self.ldb.search("ou=%s,%s" % (object_name, self.base_dn), scope=SCOPE_BASE, attrs=["dn"])
        self.assertEquals(len(res), 1)
        # Delete the object
        delete_force(self.ldb, "ou=%s,%s" % (object_name, self.base_dn))


class SchemaTests_msDS_IntId(samba.tests.TestCase):

    def setUp(self):
        super(SchemaTests_msDS_IntId, self).setUp()
        self.ldb = SamDB(host, credentials=creds,
            session_info=system_session(lp), lp=lp, options=ldb_options)
        res = self.ldb.search(base="", expression="", scope=SCOPE_BASE,
                         attrs=["schemaNamingContext", "defaultNamingContext",
                                "forestFunctionality"])
        self.assertEquals(len(res), 1)
        self.schema_dn = res[0]["schemaNamingContext"][0]
        self.base_dn = res[0]["defaultNamingContext"][0]
        self.forest_level = int(res[0]["forestFunctionality"][0])

    def _ldap_schemaUpdateNow(self):
        ldif = """
dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
"""
        self.ldb.modify_ldif(ldif)

    def _make_obj_names(self, prefix):
        class_name = prefix + time.strftime("%s", time.gmtime())
        class_ldap_name = class_name.replace("-", "")
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        return (class_name, class_ldap_name, class_dn)

    def _is_schema_base_object(self, ldb_msg):
        """Test systemFlags for SYSTEM_FLAG_SCHEMA_BASE_OBJECT (16)"""
        systemFlags = 0
        if "systemFlags" in ldb_msg:
            systemFlags = int(ldb_msg["systemFlags"][0])
        return (systemFlags & 16) != 0

    def _make_attr_ldif(self, attr_name, attr_dn):
        ldif = """
dn: """ + attr_dn + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: 1.3.6.1.4.1.7165.4.6.1.6.14.""" + str(random.randint(1,100000)) + """
attributeSyntax: 2.5.5.12
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        return ldif

    def test_msDS_IntId_on_attr(self):
        """Testing msDs-IntId creation for Attributes.
        See MS-ADTS - 3.1.1.Attributes

        This test should verify that:
        - Creating attribute with 'msDS-IntId' fails with ERR_UNWILLING_TO_PERFORM
        - Adding 'msDS-IntId' on existing attribute fails with ERR_CONSTRAINT_VIOLATION
        - Creating attribute with 'msDS-IntId' set and FLAG_SCHEMA_BASE_OBJECT flag
          set fails with ERR_UNWILLING_TO_PERFORM
        - Attributes created with FLAG_SCHEMA_BASE_OBJECT not set have
          'msDS-IntId' attribute added internally
        """

        # 1. Create attribute without systemFlags
        # msDS-IntId should be created if forest functional
        # level is >= DS_DOMAIN_FUNCTION_2003
        # and missing otherwise
        (attr_name, attr_ldap_name, attr_dn) = self._make_obj_names("msDS-IntId-Attr-1-")
        ldif = self._make_attr_ldif(attr_name, attr_dn)

        # try to add msDS-IntId during Attribute creation
        ldif_fail = ldif + "msDS-IntId: -1993108831\n"
        try:
            self.ldb.add_ldif(ldif_fail)
            self.fail("Adding attribute with preset msDS-IntId should fail")
        except LdbError as e25:
            (num, _) = e25.args
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        # add the new attribute and update schema
        self.ldb.add_ldif(ldif)
        self._ldap_schemaUpdateNow()

        # Search for created attribute
        res = []
        res = self.ldb.search(attr_dn, scope=SCOPE_BASE,
                              attrs=["lDAPDisplayName", "msDS-IntId", "systemFlags"])
        self.assertEquals(len(res), 1)
        self.assertEquals(res[0]["lDAPDisplayName"][0], attr_ldap_name)
        if self.forest_level >= DS_DOMAIN_FUNCTION_2003:
            if self._is_schema_base_object(res[0]):
                self.assertTrue("msDS-IntId" not in res[0])
            else:
                self.assertTrue("msDS-IntId" in res[0])
        else:
            self.assertTrue("msDS-IntId" not in res[0])

        msg = Message()
        msg.dn = Dn(self.ldb, attr_dn)
        msg["msDS-IntId"] = MessageElement("-1993108831", FLAG_MOD_REPLACE, "msDS-IntId")
        try:
            self.ldb.modify(msg)
            self.fail("Modifying msDS-IntId should return error")
        except LdbError as e26:
            (num, _) = e26.args
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        # 2. Create attribute with systemFlags = FLAG_SCHEMA_BASE_OBJECT
        # msDS-IntId should be created if forest functional
        # level is >= DS_DOMAIN_FUNCTION_2003
        # and missing otherwise
        (attr_name, attr_ldap_name, attr_dn) = self._make_obj_names("msDS-IntId-Attr-2-")
        ldif = self._make_attr_ldif(attr_name, attr_dn)
        ldif += "systemFlags: 16\n"

        # try to add msDS-IntId during Attribute creation
        ldif_fail = ldif + "msDS-IntId: -1993108831\n"
        try:
            self.ldb.add_ldif(ldif_fail)
            self.fail("Adding attribute with preset msDS-IntId should fail")
        except LdbError as e27:
            (num, _) = e27.args
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        # add the new attribute and update schema
        self.ldb.add_ldif(ldif)
        self._ldap_schemaUpdateNow()

        # Search for created attribute
        res = []
        res = self.ldb.search(attr_dn, scope=SCOPE_BASE,
                              attrs=["lDAPDisplayName", "msDS-IntId"])
        self.assertEquals(len(res), 1)
        self.assertEquals(res[0]["lDAPDisplayName"][0], attr_ldap_name)
        if self.forest_level >= DS_DOMAIN_FUNCTION_2003:
            if self._is_schema_base_object(res[0]):
                self.assertTrue("msDS-IntId" not in res[0])
            else:
                self.assertTrue("msDS-IntId" in res[0])
        else:
            self.assertTrue("msDS-IntId" not in res[0])

        msg = Message()
        msg.dn = Dn(self.ldb, attr_dn)
        msg["msDS-IntId"] = MessageElement("-1993108831", FLAG_MOD_REPLACE, "msDS-IntId")
        try:
            self.ldb.modify(msg)
            self.fail("Modifying msDS-IntId should return error")
        except LdbError as e28:
            (num, _) = e28.args
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)


    def _make_class_ldif(self, class_dn, class_name, sub_oid):
        ldif = """
dn: """ + class_dn + """
objectClass: top
objectClass: classSchema
adminDescription: """ + class_name + """
adminDisplayName: """ + class_name + """
cn: """ + class_name + """
governsId: 1.3.6.1.4.1.7165.4.6.2.6.%d.""" % sub_oid + str(random.randint(1,100000)) + """
instanceType: 4
objectClassCategory: 1
subClassOf: organizationalPerson
rDNAttID: cn
systemMustContain: cn
systemOnly: FALSE
"""
        return ldif

    def test_msDS_IntId_on_class(self):
        """Testing msDs-IntId creation for Class
           Reference: MS-ADTS - 3.1.1.2.4.8 Class classSchema"""

        # 1. Create Class without systemFlags
        # msDS-IntId should be created if forest functional
        # level is >= DS_DOMAIN_FUNCTION_2003
        # and missing otherwise
        (class_name, class_ldap_name, class_dn) = self._make_obj_names("msDS-IntId-Class-1-")
        ldif = self._make_class_ldif(class_dn, class_name, 8)

        # try to add msDS-IntId during Class creation
        ldif_add = ldif + "msDS-IntId: -1993108831\n"
        self.ldb.add_ldif(ldif_add)
        self._ldap_schemaUpdateNow()

        res = self.ldb.search(class_dn, scope=SCOPE_BASE, attrs=["msDS-IntId"])
        self.assertEquals(len(res), 1)
        self.assertEquals(res[0]["msDS-IntId"][0], "-1993108831")

        # add a new Class and update schema
        (class_name, class_ldap_name, class_dn) = self._make_obj_names("msDS-IntId-Class-2-")
        ldif = self._make_class_ldif(class_dn, class_name, 9)

        self.ldb.add_ldif(ldif)
        self._ldap_schemaUpdateNow()

        # Search for created Class
        res = self.ldb.search(class_dn, scope=SCOPE_BASE, attrs=["msDS-IntId"])
        self.assertEquals(len(res), 1)
        self.assertFalse("msDS-IntId" in res[0])

        msg = Message()
        msg.dn = Dn(self.ldb, class_dn)
        msg["msDS-IntId"] = MessageElement("-1993108831", FLAG_MOD_REPLACE, "msDS-IntId")
        try:
            self.ldb.modify(msg)
            self.fail("Modifying msDS-IntId should return error")
        except LdbError as e29:
            (num, _) = e29.args
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        # 2. Create Class with systemFlags = FLAG_SCHEMA_BASE_OBJECT
        # msDS-IntId should be created if forest functional
        # level is >= DS_DOMAIN_FUNCTION_2003
        # and missing otherwise
        (class_name, class_ldap_name, class_dn) = self._make_obj_names("msDS-IntId-Class-3-")
        ldif = self._make_class_ldif(class_dn, class_name, 10)
        ldif += "systemFlags: 16\n"

        # try to add msDS-IntId during Class creation
        ldif_add = ldif + "msDS-IntId: -1993108831\n"
        self.ldb.add_ldif(ldif_add)

        res = self.ldb.search(class_dn, scope=SCOPE_BASE, attrs=["msDS-IntId"])
        self.assertEquals(len(res), 1)
        self.assertEquals(res[0]["msDS-IntId"][0], "-1993108831")

        # add the new Class and update schema
        (class_name, class_ldap_name, class_dn) = self._make_obj_names("msDS-IntId-Class-4-")
        ldif = self._make_class_ldif(class_dn, class_name, 11)
        ldif += "systemFlags: 16\n"

        self.ldb.add_ldif(ldif)
        self._ldap_schemaUpdateNow()

        # Search for created Class
        res = self.ldb.search(class_dn, scope=SCOPE_BASE, attrs=["msDS-IntId"])
        self.assertEquals(len(res), 1)
        self.assertFalse("msDS-IntId" in res[0])

        msg = Message()
        msg.dn = Dn(self.ldb, class_dn)
        msg["msDS-IntId"] = MessageElement("-1993108831", FLAG_MOD_REPLACE, "msDS-IntId")
        try:
            self.ldb.modify(msg)
            self.fail("Modifying msDS-IntId should return error")
        except LdbError as e30:
            (num, _) = e30.args
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)
        res = self.ldb.search(class_dn, scope=SCOPE_BASE, attrs=["msDS-IntId"])
        self.assertEquals(len(res), 1)
        self.assertFalse("msDS-IntId" in res[0])


    def test_verify_msDS_IntId(self):
        """Verify msDS-IntId exists only on attributes without FLAG_SCHEMA_BASE_OBJECT flag set"""
        count = 0
        res = self.ldb.search(self.schema_dn, scope=SCOPE_ONELEVEL,
                              expression="objectClass=attributeSchema",
                              attrs=["systemFlags", "msDS-IntId", "attributeID", "cn"])
        self.assertTrue(len(res) > 1)
        for ldb_msg in res:
            if self.forest_level >= DS_DOMAIN_FUNCTION_2003:
                if self._is_schema_base_object(ldb_msg):
                    self.assertTrue("msDS-IntId" not in ldb_msg)
                else:
                    # don't assert here as there are plenty of
                    # attributes under w2k8 that are not part of
                    # Base Schema (SYSTEM_FLAG_SCHEMA_BASE_OBJECT flag not set)
                    # has not msDS-IntId attribute set
                    #self.assertTrue("msDS-IntId" in ldb_msg, "msDS-IntId expected on: %s" % ldb_msg.dn)
                    if "msDS-IntId" not in ldb_msg:
                        count = count + 1
                        print("%3d warning: msDS-IntId expected on: %-30s %s" % (count, ldb_msg["attributeID"], ldb_msg["cn"]))
            else:
                self.assertTrue("msDS-IntId" not in ldb_msg)


class SchemaTests_msDS_isRODC(samba.tests.TestCase):

    def setUp(self):
        super(SchemaTests_msDS_isRODC, self).setUp()
        self.ldb =  SamDB(host, credentials=creds,
            session_info=system_session(lp), lp=lp, options=ldb_options)
        res = self.ldb.search(base="", expression="", scope=SCOPE_BASE, attrs=["defaultNamingContext"])
        self.assertEquals(len(res), 1)
        self.base_dn = res[0]["defaultNamingContext"][0]

    def test_objectClass_ntdsdsa(self):
        res = self.ldb.search(self.base_dn, expression="objectClass=nTDSDSA",
                              attrs=["msDS-isRODC"], controls=["search_options:1:2"])
        for ldb_msg in res:
            self.assertTrue("msDS-isRODC" in ldb_msg)

    def test_objectClass_server(self):
        res = self.ldb.search(self.base_dn, expression="objectClass=server",
                              attrs=["msDS-isRODC"], controls=["search_options:1:2"])
        for ldb_msg in res:
            ntds_search_dn = "CN=NTDS Settings,%s" % ldb_msg['dn']
            try:
                res_check = self.ldb.search(ntds_search_dn, attrs=["objectCategory"])
            except LdbError as e:
                (num, _) = e.args
                self.assertEquals(num, ERR_NO_SUCH_OBJECT)
                print("Server entry %s doesn't have a NTDS settings object" % res[0]['dn'])
            else:
                self.assertTrue("objectCategory" in res_check[0])
                self.assertTrue("msDS-isRODC" in ldb_msg)

    def test_objectClass_computer(self):
        res = self.ldb.search(self.base_dn, expression="objectClass=computer",
                              attrs=["serverReferenceBL","msDS-isRODC"], controls=["search_options:1:2"])
        for ldb_msg in res:
            if "serverReferenceBL" not in ldb_msg:
                print("Computer entry %s doesn't have a serverReferenceBL attribute" % ldb_msg['dn'])
            else:
                self.assertTrue("msDS-isRODC" in ldb_msg)

if not "://" in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host

ldb_options = []
if host.startswith("ldap://"):
    # user 'paged_search' module when connecting remotely
    ldb_options = ["modules:paged_searches"]

TestProgram(module=__name__, opts=subunitopts)
