#!/usr/bin/python
# -*- coding: utf-8 -*-
# This is a port of the original in testprogs/ejs/ldap.js

import getopt
import optparse
import sys
import time
import random
import base64
import os

sys.path.append("bin/python")
sys.path.append("../lib/subunit/python")

import samba.getopt as options

from samba.auth import system_session
from ldb import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE, LdbError
from ldb import ERR_NO_SUCH_OBJECT, ERR_ATTRIBUTE_OR_VALUE_EXISTS
from ldb import ERR_ENTRY_ALREADY_EXISTS, ERR_UNWILLING_TO_PERFORM
from ldb import ERR_NOT_ALLOWED_ON_NON_LEAF, ERR_OTHER, ERR_INVALID_DN_SYNTAX
from ldb import ERR_NO_SUCH_ATTRIBUTE, ERR_INSUFFICIENT_ACCESS_RIGHTS
from ldb import ERR_OBJECT_CLASS_VIOLATION, ERR_NOT_ALLOWED_ON_RDN
from ldb import ERR_NAMING_VIOLATION, ERR_CONSTRAINT_VIOLATION
from ldb import ERR_UNDEFINED_ATTRIBUTE_TYPE
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from samba import Ldb, param, dom_sid_to_rid
from samba import UF_NORMAL_ACCOUNT, UF_TEMP_DUPLICATE_ACCOUNT
from samba import UF_SERVER_TRUST_ACCOUNT, UF_WORKSTATION_TRUST_ACCOUNT
from samba import UF_INTERDOMAIN_TRUST_ACCOUNT
from samba import UF_PASSWD_NOTREQD, UF_ACCOUNTDISABLE
from samba import GTYPE_SECURITY_BUILTIN_LOCAL_GROUP
from samba import GTYPE_SECURITY_GLOBAL_GROUP, GTYPE_SECURITY_DOMAIN_LOCAL_GROUP
from samba import GTYPE_SECURITY_UNIVERSAL_GROUP
from samba import GTYPE_DISTRIBUTION_GLOBAL_GROUP
from samba import GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP
from samba import GTYPE_DISTRIBUTION_UNIVERSAL_GROUP
from samba import ATYPE_NORMAL_ACCOUNT, ATYPE_WORKSTATION_TRUST
from samba import ATYPE_SECURITY_GLOBAL_GROUP, ATYPE_SECURITY_LOCAL_GROUP
from samba import ATYPE_SECURITY_UNIVERSAL_GROUP
from samba import ATYPE_DISTRIBUTION_GLOBAL_GROUP
from samba import ATYPE_DISTRIBUTION_LOCAL_GROUP
from samba import ATYPE_DISTRIBUTION_UNIVERSAL_GROUP

from subunit import SubunitTestRunner
import unittest

from samba.ndr import ndr_pack, ndr_unpack
from samba.dcerpc import security

parser = optparse.OptionParser("ldap [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)


class SchemaTests(unittest.TestCase):
    def delete_force(self, ldb, dn):
        try:
            ldb.delete(dn)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

    def find_schemadn(self, ldb):
        res = ldb.search(base="", expression="", scope=SCOPE_BASE, attrs=["schemaNamingContext"])
        self.assertEquals(len(res), 1)
        return res[0]["schemaNamingContext"][0]

    def find_basedn(self, ldb):
        res = ldb.search(base="", expression="", scope=SCOPE_BASE,
                         attrs=["defaultNamingContext"])
        self.assertEquals(len(res), 1)
        return res[0]["defaultNamingContext"][0]

    def setUp(self):
        self.ldb = ldb
        self.schema_dn = self.find_schemadn(ldb)
        self.base_dn = self.find_basedn(ldb)

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
        res = self.ldb.search("cn=aggregate,"+self.schema_dn, scope=SCOPE_BASE,
                attrs=["*"])
        self.assertEquals(len(res), 1)
        self.assertFalse("dITContentRules" in res[0])
        self.assertFalse("objectClasses" in res[0])
        self.assertFalse("attributeTypes" in res[0])


    def test_schemaUpdateNow(self):
        """Testing schemaUpdateNow"""
        attr_name = "test-Attr" + time.strftime("%s", time.gmtime())
        attr_ldap_display_name = attr_name.replace("-", "")

        ldif = """
dn: CN=%s,%s""" % (attr_name, self.schema_dn) + """
objectClass: top
objectClass: attributeSchema
adminDescription: """ + attr_name + """
adminDisplayName: """ + attr_name + """
cn: """ + attr_name + """
attributeId: 1.2.840.""" + str(random.randint(1,100000)) + """.1.5.9940
attributeSyntax: 2.5.5.12
omSyntax: 64
instanceType: 4
isSingleValued: TRUE
systemOnly: FALSE
"""
        self.ldb.add_ldif(ldif)

        class_name = "test-Class" + time.strftime("%s", time.gmtime())
        class_ldap_display_name = class_name.replace("-", "")

        ldif = """
dn: CN=%s,%s""" % (class_name, self.schema_dn) + """
objectClass: top
objectClass: classSchema
adminDescription: """ + class_name + """
adminDisplayName: """ + class_name + """
cn: """ + class_name + """
governsId: 1.2.840.""" + str(random.randint(1,100000)) + """.1.5.9939
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

        # Search for created attribute
        res = []
        res = self.ldb.search("cn=%s,%s" % (attr_name, self.schema_dn), scope=SCOPE_BASE, attrs=["*"])
        self.assertEquals(len(res), 1)
        self.assertEquals(res[0]["lDAPDisplayName"][0], attr_ldap_display_name)
        self.assertTrue("schemaIDGUID" in res[0])

        # Search for created objectclass
        res = []
        res = self.ldb.search("cn=%s,%s" % (class_name, self.schema_dn), scope=SCOPE_BASE, attrs=["*"])
        self.assertEquals(len(res), 1)
        self.assertEquals(res[0]["lDAPDisplayName"][0], class_ldap_display_name)
        self.assertEquals(res[0]["defaultObjectCategory"][0], res[0]["distinguishedName"][0])
        self.assertTrue("schemaIDGUID" in res[0])

        # Search for created object
        res = []
        res = self.ldb.search("cn=%s,cn=Users,%s" % (object_name, self.base_dn), scope=SCOPE_BASE, attrs=["*"])
        self.assertEquals(len(res), 1)
        # Delete the object
        self.delete_force(self.ldb, "cn=%s,cn=Users,%s" % (object_name, self.base_dn))

if not "://" in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host

ldb = Ldb(host, credentials=creds, session_info=system_session(), lp=lp)
if not "tdb://" in host:
    gc_ldb = Ldb("%s:3268" % host, credentials=creds,
                 session_info=system_session(), lp=lp)
else:
    gc_ldb = None

runner = SubunitTestRunner()
rc = 0
if not runner.run(unittest.makeSuite(SchemaTests)).wasSuccessful():
    rc = 1
sys.exit(rc)
