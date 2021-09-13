#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This tests the restrictions on userAccountControl that apply even if write access is permitted
#
# Copyright Samuel Cabrero 2014 <samuelcabrero@kernevil.me>
# Copyright Andrew Bartlett 2014 <abartlet@samba.org>
#
# Licenced under the GPLv3
#

import optparse
import sys
import unittest
import samba
import samba.getopt as options
import samba.tests
import ldb
import base64

sys.path.insert(0, "bin/python")
from samba.tests.subunitrun import TestProgram, SubunitOptions
from samba.tests import DynamicTestCase
from samba.subunit.run import SubunitTestRunner
from samba.auth import system_session
from samba.samdb import SamDB
from samba.dcerpc import samr, security, lsa
from samba.credentials import Credentials
from samba.ndr import ndr_unpack, ndr_pack
from samba.tests import delete_force
from samba import gensec, sd_utils
from samba.credentials import DONT_USE_KERBEROS
from ldb import SCOPE_SUBTREE, SCOPE_BASE, LdbError
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from samba.dsdb import UF_SCRIPT, UF_ACCOUNTDISABLE, UF_00000004, UF_HOMEDIR_REQUIRED, \
    UF_LOCKOUT, UF_PASSWD_NOTREQD, UF_PASSWD_CANT_CHANGE, UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED,\
    UF_TEMP_DUPLICATE_ACCOUNT, UF_NORMAL_ACCOUNT, UF_00000400, UF_INTERDOMAIN_TRUST_ACCOUNT, \
    UF_WORKSTATION_TRUST_ACCOUNT, UF_SERVER_TRUST_ACCOUNT, UF_00004000, \
    UF_00008000, UF_DONT_EXPIRE_PASSWD, UF_MNS_LOGON_ACCOUNT, UF_SMARTCARD_REQUIRED, \
    UF_TRUSTED_FOR_DELEGATION, UF_NOT_DELEGATED, UF_USE_DES_KEY_ONLY, UF_DONT_REQUIRE_PREAUTH, \
    UF_PASSWORD_EXPIRED, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION, UF_NO_AUTH_DATA_REQUIRED, \
    UF_PARTIAL_SECRETS_ACCOUNT, UF_USE_AES_KEYS


parser = optparse.OptionParser("user_account_control.py [options] <host>")
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

if "://" not in host:
    ldaphost = "ldap://%s" % host
else:
    ldaphost = host
    start = host.rindex("://")
    host = host.lstrip(start + 3)

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)
creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)


"""
Check the combinations of:

rodc kdc
a2d2
useraccountcontrol (trusted for delegation)
sidHistory

x

add
modify(replace)
modify(add)

x

sd WP on add
cc default perms
admin created, WP to user

x

computer
user
"""

attrs = {"sidHistory":
         {"value": ndr_pack(security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)),
          "priv-error": ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS,
          "unpriv-error": ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS},

         "msDS-AllowedToDelegateTo":
         {"value": f"host/{host}",
          "unpriv-error": ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS},

         "userAccountControl-a2d-user":
         {"attr": "userAccountControl",
          "value": str(UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION|UF_NORMAL_ACCOUNT|UF_PASSWD_NOTREQD),
          "unpriv-error": ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS},

         "userAccountControl-a2d-computer":
         {"attr": "userAccountControl",
          "value": str(UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION|UF_WORKSTATION_TRUST_ACCOUNT),
          "unpriv-error": ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS,
          "only-1": "computer"},

         # This flag makes many legitimate authenticated clients
         # send a forwardable ticket-granting-ticket to the server
         "userAccountControl-t4d-user":
         {"attr": "userAccountControl",
          "value": str(UF_TRUSTED_FOR_DELEGATION|UF_NORMAL_ACCOUNT|UF_PASSWD_NOTREQD),
          "unpriv-error": ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS},

         "userAccountControl-t4d-computer":
         {"attr": "userAccountControl",
          "value": str(UF_TRUSTED_FOR_DELEGATION|UF_WORKSTATION_TRUST_ACCOUNT),
          "unpriv-error": ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS,
          "only-1": "computer"},

         "userAccountControl-DC":
         {"attr": "userAccountControl",
          "value": str(UF_SERVER_TRUST_ACCOUNT),
          "unpriv-error": ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS,
          "only-2": "computer"},

         "userAccountControl-RODC":
         {"attr": "userAccountControl",
          "value": str(UF_PARTIAL_SECRETS_ACCOUNT|UF_WORKSTATION_TRUST_ACCOUNT),
          "unpriv-error": ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS,
          "only-1": "computer"},

         "msDS-SecondaryKrbTgtNumber":
         {"value": "65536",
          "unpriv-error": ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS},
         "primaryGroupID":
         {"value": str(security.DOMAIN_RID_ADMINS),
          "priv-error": ldb.ERR_UNWILLING_TO_PERFORM,
          "unpriv-add-error": ldb.ERR_UNWILLING_TO_PERFORM,
          "unpriv-error": ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS}
        }



@DynamicTestCase
class PrivAttrsTests(samba.tests.TestCase):

    def get_creds(self, target_username, target_password):
        creds_tmp = Credentials()
        creds_tmp.set_username(target_username)
        creds_tmp.set_password(target_password)
        creds_tmp.set_domain(creds.get_domain())
        creds_tmp.set_realm(creds.get_realm())
        creds_tmp.set_workstation(creds.get_workstation())
        creds_tmp.set_gensec_features(creds_tmp.get_gensec_features()
                                      | gensec.FEATURE_SEAL)
        creds_tmp.set_kerberos_state(DONT_USE_KERBEROS)  # kinit is too expensive to use in a tight loop
        return creds_tmp

    def assertGotLdbError(self, got, wanted):
        if not self.strict_checking:
            self.assertNotEqual(got, ldb.SUCCESS)
        else:
            self.assertEqual(got, wanted)

    def setUp(self):
        super().setUp()

        strict_checking = samba.tests.env_get_var_value('STRICT_CHECKING', allow_missing=True)
        if strict_checking is None:
            strict_checking = '1'
        self.strict_checking = bool(int(strict_checking))

        self.admin_creds = creds
        self.admin_samdb = SamDB(url=ldaphost, credentials=self.admin_creds, lp=lp)
        self.domain_sid = security.dom_sid(self.admin_samdb.get_domain_sid())
        self.base_dn = self.admin_samdb.domain_dn()

        self.unpriv_user = "testuser1"
        self.unpriv_user_pw = "samba123@"
        self.unpriv_creds = self.get_creds(self.unpriv_user, self.unpriv_user_pw)

        self.admin_sd_utils = sd_utils.SDUtils(self.admin_samdb)

        self.test_ou_name = "OU=test_priv_attrs"
        self.test_ou = self.test_ou_name + "," + self.base_dn

        delete_force(self.admin_samdb, self.test_ou, controls=["tree_delete:0"])

        self.admin_samdb.create_ou(self.test_ou)

        expected_user_dn = f"CN={self.unpriv_user},{self.test_ou_name},{self.base_dn}"

        self.admin_samdb.newuser(self.unpriv_user, self.unpriv_user_pw, userou=self.test_ou_name)
        res = self.admin_samdb.search(expected_user_dn,
                                      scope=SCOPE_BASE,
                                      attrs=["objectSid"])

        self.assertEqual(1, len(res))

        self.unpriv_user_dn = res[0].dn
        self.addCleanup(delete_force, self.admin_samdb, self.unpriv_user_dn, controls=["tree_delete:0"])

        self.unpriv_user_sid = self.admin_sd_utils.get_object_sid(self.unpriv_user_dn)

        self.unpriv_samdb = SamDB(url=ldaphost, credentials=self.unpriv_creds, lp=lp)

    @classmethod
    def setUpDynamicTestCases(cls):
        for test_name in attrs.keys():
            for add_or_mod in ["add", "mod-del-add", "mod-replace"]:
                for permission in ["admin-add", "CC"]:
                    for sd in ["default", "WP"]:
                        for objectclass in ["computer", "user"]:
                            tname = f"{test_name}_{add_or_mod}_{permission}_{sd}_{objectclass}"
                            targs = (test_name,
                                     add_or_mod,
                                     permission,
                                     sd,
                                     objectclass)
                            cls.generate_dynamic_test("test_priv_attr",
                                                      tname,
                                                      *targs)

    def add_computer_ldap(self, computername, others=None, samdb=None):
        dn = "CN=%s,%s" % (computername, self.test_ou)
        domainname = ldb.Dn(samdb, samdb.domain_dn()).canonical_str().replace("/", "")
        samaccountname = "%s$" % computername
        dnshostname = "%s.%s" % (computername, domainname)
        msg_dict = {
            "dn": dn,
            "objectclass": "computer"}
        if others is not None:
            msg_dict = dict(list(msg_dict.items()) + list(others.items()))

        msg = ldb.Message.from_dict(samdb, msg_dict)
        msg["sAMAccountName"] = samaccountname

        print("Adding computer account %s" % computername)
        try:
            samdb.add(msg)
        except ldb.LdbError:
            print(msg)
            raise
        return msg.dn

    def add_user_ldap(self, username, others=None, samdb=None):
        dn = "CN=%s,%s" % (username, self.test_ou)
        domainname = ldb.Dn(samdb, samdb.domain_dn()).canonical_str().replace("/", "")
        samaccountname = "%s$" % username
        msg_dict = {
            "dn": dn,
            "objectclass": "user"}
        if others is not None:
            msg_dict = dict(list(msg_dict.items()) + list(others.items()))

        msg = ldb.Message.from_dict(samdb, msg_dict)
        msg["sAMAccountName"] = samaccountname

        print("Adding user account %s" % username)
        try:
            samdb.add(msg)
        except ldb.LdbError:
            print(msg)
            raise
        return msg.dn

    def add_thing_ldap(self, user, others, samdb, objectclass):
        if objectclass == "user":
            dn = self.add_user_ldap(user, others, samdb=samdb)
        elif objectclass == "computer":
            dn = self.add_computer_ldap(user, others, samdb=samdb)
        return dn

    def _test_priv_attr_with_args(self, test_name, add_or_mod, permission, sd, objectclass):
        user="privattrs"
        if "attr" in attrs[test_name]:
            attr = attrs[test_name]["attr"]
        else:
            attr = test_name
        if add_or_mod == "add":
            others = {attr: attrs[test_name]["value"]}
        else:
            others = {}

        if permission == "CC":
            samdb = self.unpriv_samdb
            # Set CC on container to allow user add
            mod = "(OA;CI;CC;bf967aba-0de6-11d0-a285-00aa003049e2;;%s)" % str(self.unpriv_user_sid)
            self.admin_sd_utils.dacl_add_ace(self.test_ou, mod)
            mod = "(OA;CI;CC;bf967a86-0de6-11d0-a285-00aa003049e2;;%s)" % str(self.unpriv_user_sid)
            self.admin_sd_utils.dacl_add_ace(self.test_ou, mod)

        else:
            samdb = self.admin_samdb

        if sd == "WP":
            # Set SD to WP to the target user as part of add
            sd = "O:%sG:DUD:(OA;CIID;RPWP;;;%s)(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;%s)" % (self.unpriv_user_sid, self.unpriv_user_sid, self.unpriv_user_sid)
            tmp_desc = security.descriptor.from_sddl(sd, self.domain_sid)
            others["ntSecurityDescriptor"] = ndr_pack(tmp_desc)

        if add_or_mod == "add":

            # only-1 and only-2 are due to windows behaviour

            if "only-1" in attrs[test_name] and \
                 attrs[test_name]["only-1"] != objectclass:
                try:
                    dn = self.add_thing_ldap(user, others, samdb, objectclass)
                    self.fail(f"{test_name}: Unexpectedly able to set {attr} on new {objectclass} as ADMIN (should fail LDAP_OBJECT_CLASS_VIOLATION)")
                except LdbError as e5:
                    (enum, estr) = e5.args
                    self.assertGotLdbError(ldb.ERR_OBJECT_CLASS_VIOLATION, enum)
            elif permission == "CC":
                try:
                    dn = self.add_thing_ldap(user, others, samdb, objectclass)
                    self.fail(f"{test_name}: Unexpectedly able to set {attr} on new {objectclass}")
                except LdbError as e5:
                    (enum, estr) = e5.args
                    if "unpriv-add-error" in attrs[test_name]:
                        self.assertGotLdbError(attrs[test_name]["unpriv-add-error"], \
                                         enum)
                    else:
                        self.assertGotLdbError(attrs[test_name]["unpriv-error"], \
                                         enum)
            elif "only-2" in attrs[test_name] and \
                 attrs[test_name]["only-2"] != objectclass:
                try:
                    dn = self.add_thing_ldap(user, others, samdb, objectclass)
                    self.fail(f"{test_name}: Unexpectedly able to set {attr} on new {objectclass} as ADMIN (should fail LDAP_OBJECT_CLASS_VIOLATION)")
                except LdbError as e5:
                    (enum, estr) = e5.args
                    self.assertGotLdbError(ldb.ERR_OBJECT_CLASS_VIOLATION, enum)
            elif "priv-error" in attrs[test_name]:
                try:
                    dn = self.add_thing_ldap(user, others, samdb, objectclass)
                    self.fail(f"{test_name}: Unexpectedly able to set {attr} on new {objectclass} as ADMIN")
                except LdbError as e5:
                    (enum, estr) = e5.args
                    self.assertGotLdbError(attrs[test_name]["priv-error"], enum)
            else:
                try:
                    dn = self.add_thing_ldap(user, others, samdb, objectclass)
                except LdbError as e5:
                    (enum, estr) = e5.args
                    self.fail(f"Failed to add account {user} as objectclass {objectclass}")
        else:
            try:
                 dn = self.add_thing_ldap(user, others, samdb, objectclass)
            except LdbError as e5:
                (enum, estr) = e5.args
                self.fail(f"Failed to add account {user} as objectclass {objectclass}")

        if add_or_mod == "add":
            return

        m = ldb.Message()
        m.dn = dn

        # Do modify
        if add_or_mod == "mod-del-add":
            m["0"] = ldb.MessageElement([],
                                          ldb.FLAG_MOD_DELETE,
                                          attr)
            m["1"] = ldb.MessageElement(attrs[test_name]["value"],
                                                ldb.FLAG_MOD_ADD,
                                                attr)
        else:
            m["0"] = ldb.MessageElement(attrs[test_name]["value"],
                                      ldb.FLAG_MOD_REPLACE,
                                      attr)

        try:
            self.unpriv_samdb.modify(m)
            self.fail(f"{test_name}: Unexpectedly able to set {attr} on {m.dn}")
        except LdbError as e5:
            (enum, estr) = e5.args
            self.assertGotLdbError(attrs[test_name]["unpriv-error"], enum)




runner = SubunitTestRunner()
rc = 0
if not runner.run(unittest.makeSuite(PrivAttrsTests)).wasSuccessful():
    rc = 1
sys.exit(rc)
