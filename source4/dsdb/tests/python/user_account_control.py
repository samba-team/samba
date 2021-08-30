#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This tests the restrictions on userAccountControl that apply even if write access is permitted
#
# Copyright Samuel Cabrero 2014 <samuelcabrero@kernevil.me>
# Copyright Andrew Bartlett 2014 <abartlet@samba.org>
#
# Licenced under the GPLv3
#

from __future__ import print_function
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

from samba.subunit.run import SubunitTestRunner
from samba.auth import system_session
from samba.samdb import SamDB
from samba.dcerpc import samr, security, lsa
from samba.credentials import Credentials
from samba.ndr import ndr_unpack, ndr_pack
from samba.tests import delete_force, DynamicTestCase
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
from samba import dsdb


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

bits = [UF_SCRIPT, UF_ACCOUNTDISABLE, UF_00000004, UF_HOMEDIR_REQUIRED,
        UF_LOCKOUT, UF_PASSWD_NOTREQD, UF_PASSWD_CANT_CHANGE,
        UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED,
        UF_TEMP_DUPLICATE_ACCOUNT, UF_NORMAL_ACCOUNT, UF_00000400,
        UF_INTERDOMAIN_TRUST_ACCOUNT,
        UF_WORKSTATION_TRUST_ACCOUNT, UF_SERVER_TRUST_ACCOUNT, UF_00004000,
        UF_00008000, UF_DONT_EXPIRE_PASSWD, UF_MNS_LOGON_ACCOUNT, UF_SMARTCARD_REQUIRED,
        UF_TRUSTED_FOR_DELEGATION, UF_NOT_DELEGATED, UF_USE_DES_KEY_ONLY,
        UF_DONT_REQUIRE_PREAUTH,
        UF_PASSWORD_EXPIRED, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
        UF_NO_AUTH_DATA_REQUIRED,
        UF_PARTIAL_SECRETS_ACCOUNT, UF_USE_AES_KEYS,
        int("0x10000000", 16), int("0x20000000", 16), int("0x40000000", 16), int("0x80000000", 16)]

account_types = set([UF_NORMAL_ACCOUNT, UF_WORKSTATION_TRUST_ACCOUNT, UF_SERVER_TRUST_ACCOUNT])


@DynamicTestCase
class UserAccountControlTests(samba.tests.TestCase):
    @classmethod
    def setUpDynamicTestCases(cls):
        for account_type in [UF_NORMAL_ACCOUNT, UF_WORKSTATION_TRUST_ACCOUNT]:
            account_type_str = dsdb.user_account_control_flag_bit_to_string(account_type)
            cls.generate_dynamic_test("test_uac_bits_unrelated_modify",
                                      account_type_str, account_type)

        for bit in bits:
            try:
                bit_str = dsdb.user_account_control_flag_bit_to_string(bit)
            except KeyError:
                bit_str = hex(bit)

            cls.generate_dynamic_test("test_uac_bits_add",
                                      bit_str, bit, bit_str)

            cls.generate_dynamic_test("test_uac_bits_set",
                                      bit_str, bit, bit_str)


    def add_computer_ldap(self, computername, others=None, samdb=None):
        if samdb is None:
            samdb = self.samdb
        dn = "CN=%s,%s" % (computername, self.OU)
        domainname = ldb.Dn(self.samdb, self.samdb.domain_dn()).canonical_str().replace("/", "")
        samaccountname = "%s$" % computername
        dnshostname = "%s.%s" % (computername, domainname)
        msg_dict = {
            "dn": dn,
            "objectclass": "computer"}
        if others is not None:
            msg_dict = dict(list(msg_dict.items()) + list(others.items()))

        msg = ldb.Message.from_dict(self.samdb, msg_dict)
        msg["sAMAccountName"] = samaccountname

        print("Adding computer account %s" % computername)
        samdb.add(msg)

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

    def setUp(self):
        super(UserAccountControlTests, self).setUp()
        self.admin_creds = creds
        self.admin_samdb = SamDB(url=ldaphost,
                                 session_info=system_session(),
                                 credentials=self.admin_creds, lp=lp)
        self.domain_sid = security.dom_sid(self.admin_samdb.get_domain_sid())
        self.base_dn = self.admin_samdb.domain_dn()

        self.unpriv_user = "testuser1"
        self.unpriv_user_pw = "samba123@"
        self.unpriv_creds = self.get_creds(self.unpriv_user, self.unpriv_user_pw)

        self.OU = "OU=test_computer_ou1,%s" % (self.base_dn)

        delete_force(self.admin_samdb, self.OU, controls=["tree_delete:0"])
        delete_force(self.admin_samdb, "CN=%s,CN=Users,%s" % (self.unpriv_user, self.base_dn))

        self.admin_samdb.newuser(self.unpriv_user, self.unpriv_user_pw)
        res = self.admin_samdb.search("CN=%s,CN=Users,%s" % (self.unpriv_user, self.admin_samdb.domain_dn()),
                                      scope=SCOPE_BASE,
                                      attrs=["objectSid"])
        self.assertEqual(1, len(res))

        self.unpriv_user_sid = ndr_unpack(security.dom_sid, res[0]["objectSid"][0])
        self.unpriv_user_dn = res[0].dn
        self.addCleanup(self.admin_samdb.delete, self.unpriv_user_dn)

        self.samdb = SamDB(url=ldaphost, credentials=self.unpriv_creds, lp=lp)

        self.samr = samr.samr("ncacn_ip_tcp:%s[seal]" % host, lp, self.unpriv_creds)
        self.samr_handle = self.samr.Connect2(None, security.SEC_FLAG_MAXIMUM_ALLOWED)
        self.samr_domain = self.samr.OpenDomain(self.samr_handle, security.SEC_FLAG_MAXIMUM_ALLOWED, self.domain_sid)

        self.sd_utils = sd_utils.SDUtils(self.admin_samdb)
        self.admin_samdb.create_ou(self.OU)
        self.addCleanup(self.admin_samdb.delete, self.OU, ["tree_delete:1"])

        self.unpriv_user_sid = self.sd_utils.get_object_sid(self.unpriv_user_dn)
        mod = "(OA;;CC;bf967a86-0de6-11d0-a285-00aa003049e2;;%s)" % str(self.unpriv_user_sid)

        old_sd = self.sd_utils.read_sd_on_dn(self.OU)

        self.sd_utils.dacl_add_ace(self.OU, mod)

        self.add_computer_ldap("testcomputer-t")

        self.sd_utils.modify_sd_on_dn(self.OU, old_sd)

        self.computernames = ["testcomputer-0"]

        # Get the SD of the template account, then force it to match
        # what we expect for SeMachineAccountPrivilege accounts, so we
        # can confirm we created the accounts correctly
        self.sd_reference_cc = self.sd_utils.read_sd_on_dn("CN=testcomputer-t,%s" % (self.OU))

        self.sd_reference_modify = self.sd_utils.read_sd_on_dn("CN=testcomputer-t,%s" % (self.OU))
        for ace in self.sd_reference_modify.dacl.aces:
            if ace.type == security.SEC_ACE_TYPE_ACCESS_ALLOWED and ace.trustee == self.unpriv_user_sid:
                ace.access_mask = ace.access_mask | security.SEC_ADS_SELF_WRITE | security.SEC_ADS_WRITE_PROP

        # Now reconnect without domain admin rights
        self.samdb = SamDB(url=ldaphost, credentials=self.unpriv_creds, lp=lp)

    def test_add_computer_sd_cc(self):
        user_sid = self.sd_utils.get_object_sid(self.unpriv_user_dn)
        mod = "(OA;;CC;bf967a86-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)

        old_sd = self.sd_utils.read_sd_on_dn(self.OU)
        self.sd_utils.dacl_add_ace(self.OU, mod)

        computername = self.computernames[0]
        sd = ldb.MessageElement((ndr_pack(self.sd_reference_modify)),
                                ldb.FLAG_MOD_ADD,
                                "nTSecurityDescriptor")
        self.add_computer_ldap(computername,
                               others={"nTSecurityDescriptor": sd})

        res = self.admin_samdb.search("%s" % self.base_dn,
                                      expression="(&(objectClass=computer)(samAccountName=%s$))" % computername,
                                      scope=SCOPE_SUBTREE,
                                      attrs=["ntSecurityDescriptor"])

        desc = res[0]["nTSecurityDescriptor"][0]
        desc = ndr_unpack(security.descriptor, desc, allow_remaining=True)

        sddl = desc.as_sddl(self.domain_sid)
        self.assertEqual(self.sd_reference_modify.as_sddl(self.domain_sid), sddl)

        m = ldb.Message()
        m.dn = res[0].dn
        m["description"] = ldb.MessageElement(
            ("A description"), ldb.FLAG_MOD_REPLACE,
            "description")
        self.samdb.modify(m)

        m = ldb.Message()
        m.dn = res[0].dn
        m["userAccountControl"] = ldb.MessageElement(str(samba.dsdb.UF_SERVER_TRUST_ACCOUNT),
                                                     ldb.FLAG_MOD_REPLACE, "userAccountControl")
        try:
            self.samdb.modify(m)
            self.fail("Unexpectedly able to set userAccountControl to be a DC on %s" % m.dn)
        except LdbError as e5:
            (enum, estr) = e5.args
            self.assertEqual(ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS, enum)

        m = ldb.Message()
        m.dn = res[0].dn
        m["userAccountControl"] = ldb.MessageElement(str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT |
                                                         samba.dsdb.UF_PARTIAL_SECRETS_ACCOUNT),
                                                     ldb.FLAG_MOD_REPLACE, "userAccountControl")
        try:
            self.samdb.modify(m)
            self.fail("Unexpectedly able to set userAccountControl to be an RODC on %s" % m.dn)
        except LdbError as e6:
            (enum, estr) = e6.args
            self.assertEqual(ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS, enum)

        m = ldb.Message()
        m.dn = res[0].dn
        m["userAccountControl"] = ldb.MessageElement(str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT),
                                                     ldb.FLAG_MOD_REPLACE, "userAccountControl")
        try:
            self.samdb.modify(m)
            self.fail("Unexpectedly able to set userAccountControl to be an Workstation on %s" % m.dn)
        except LdbError as e7:
            (enum, estr) = e7.args
            self.assertEqual(ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS, enum)

        m = ldb.Message()
        m.dn = res[0].dn
        m["userAccountControl"] = ldb.MessageElement(str(samba.dsdb.UF_NORMAL_ACCOUNT),
                                                     ldb.FLAG_MOD_REPLACE, "userAccountControl")
        self.samdb.modify(m)

        m = ldb.Message()
        m.dn = res[0].dn
        m["primaryGroupID"] = ldb.MessageElement(str(security.DOMAIN_RID_ADMINS),
                                                 ldb.FLAG_MOD_REPLACE, "primaryGroupID")
        try:
            self.samdb.modify(m)
        except LdbError as e8:
            (enum, estr) = e8.args
            self.assertEqual(ldb.ERR_UNWILLING_TO_PERFORM, enum)
            return
        self.fail()

    def test_mod_computer_cc(self):
        user_sid = self.sd_utils.get_object_sid(self.unpriv_user_dn)
        mod = "(OA;;CC;bf967a86-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)

        old_sd = self.sd_utils.read_sd_on_dn(self.OU)

        self.sd_utils.dacl_add_ace(self.OU, mod)

        computername = self.computernames[0]
        self.add_computer_ldap(computername)

        res = self.admin_samdb.search("%s" % self.base_dn,
                                      expression="(&(objectClass=computer)(samAccountName=%s$))" % computername,
                                      scope=SCOPE_SUBTREE,
                                      attrs=[])

        m = ldb.Message()
        m.dn = res[0].dn
        m["description"] = ldb.MessageElement(
            ("A description"), ldb.FLAG_MOD_REPLACE,
            "description")
        self.samdb.modify(m)

        m = ldb.Message()
        m.dn = res[0].dn
        m["userAccountControl"] = ldb.MessageElement(str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT |
                                                         samba.dsdb.UF_PARTIAL_SECRETS_ACCOUNT),
                                                     ldb.FLAG_MOD_REPLACE, "userAccountControl")
        try:
            self.samdb.modify(m)
            self.fail("Unexpectedly able to set userAccountControl on %s" % m.dn)
        except LdbError as e9:
            (enum, estr) = e9.args
            self.assertEqual(ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS, enum)

        m = ldb.Message()
        m.dn = res[0].dn
        m["userAccountControl"] = ldb.MessageElement(str(samba.dsdb.UF_SERVER_TRUST_ACCOUNT),
                                                     ldb.FLAG_MOD_REPLACE, "userAccountControl")
        try:
            self.samdb.modify(m)
            self.fail()
        except LdbError as e10:
            (enum, estr) = e10.args
            self.assertEqual(ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS, enum)

        m = ldb.Message()
        m.dn = res[0].dn
        m["userAccountControl"] = ldb.MessageElement(str(samba.dsdb.UF_NORMAL_ACCOUNT),
                                                     ldb.FLAG_MOD_REPLACE, "userAccountControl")
        self.samdb.modify(m)

        m = ldb.Message()
        m.dn = res[0].dn
        m["userAccountControl"] = ldb.MessageElement(str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT),
                                                     ldb.FLAG_MOD_REPLACE, "userAccountControl")
        try:
            self.samdb.modify(m)
            self.fail("Unexpectedly able to set userAccountControl to be an Workstation on %s" % m.dn)
        except LdbError as e11:
            (enum, estr) = e11.args
            self.assertEqual(ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS, enum)

    def test_admin_mod_uac(self):
        computername = self.computernames[0]
        self.add_computer_ldap(computername, samdb=self.admin_samdb)

        res = self.admin_samdb.search("%s" % self.base_dn,
                                      expression="(&(objectClass=computer)(samAccountName=%s$))" % computername,
                                      scope=SCOPE_SUBTREE,
                                      attrs=["userAccountControl"])

        self.assertEqual(int(res[0]["userAccountControl"][0]), (UF_NORMAL_ACCOUNT |
                                                                UF_ACCOUNTDISABLE |
                                                                UF_PASSWD_NOTREQD))

        m = ldb.Message()
        m.dn = res[0].dn
        m["userAccountControl"] = ldb.MessageElement(str(UF_WORKSTATION_TRUST_ACCOUNT |
                                                         UF_PARTIAL_SECRETS_ACCOUNT |
                                                         UF_TRUSTED_FOR_DELEGATION),
                                                     ldb.FLAG_MOD_REPLACE, "userAccountControl")
        try:
            self.admin_samdb.modify(m)
            self.fail("Unexpectedly able to set userAccountControl to UF_WORKSTATION_TRUST_ACCOUNT|UF_PARTIAL_SECRETS_ACCOUNT|UF_TRUSTED_FOR_DELEGATION on %s" % m.dn)
        except LdbError as e12:
            (enum, estr) = e12.args
            self.assertEqual(ldb.ERR_OTHER, enum)

        m = ldb.Message()
        m.dn = res[0].dn
        m["userAccountControl"] = ldb.MessageElement(str(UF_WORKSTATION_TRUST_ACCOUNT |
                                                         UF_PARTIAL_SECRETS_ACCOUNT),
                                                     ldb.FLAG_MOD_REPLACE, "userAccountControl")
        self.admin_samdb.modify(m)

        res = self.admin_samdb.search("%s" % self.base_dn,
                                      expression="(&(objectClass=computer)(samAccountName=%s$))" % computername,
                                      scope=SCOPE_SUBTREE,
                                      attrs=["userAccountControl"])

        self.assertEqual(int(res[0]["userAccountControl"][0]), (UF_WORKSTATION_TRUST_ACCOUNT |
                                                                UF_PARTIAL_SECRETS_ACCOUNT))
        m = ldb.Message()
        m.dn = res[0].dn
        m["userAccountControl"] = ldb.MessageElement(str(UF_ACCOUNTDISABLE),
                                                     ldb.FLAG_MOD_REPLACE, "userAccountControl")
        self.admin_samdb.modify(m)

        res = self.admin_samdb.search("%s" % self.base_dn,
                                      expression="(&(objectClass=computer)(samAccountName=%s$))" % computername,
                                      scope=SCOPE_SUBTREE,
                                      attrs=["userAccountControl"])

        self.assertEqual(int(res[0]["userAccountControl"][0]), UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE)

    def _test_uac_bits_set_with_args(self, bit, bit_str):
        user_sid = self.sd_utils.get_object_sid(self.unpriv_user_dn)
        mod = "(OA;;CC;bf967a86-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)

        old_sd = self.sd_utils.read_sd_on_dn(self.OU)

        self.sd_utils.dacl_add_ace(self.OU, mod)

        computername = self.computernames[0]
        self.add_computer_ldap(computername)

        res = self.admin_samdb.search("%s" % self.base_dn,
                                      expression="(&(objectClass=computer)(samAccountName=%s$))" % computername,
                                      scope=SCOPE_SUBTREE,
                                      attrs=[])

        m = ldb.Message()
        m.dn = res[0].dn
        m["description"] = ldb.MessageElement(
            ("A description"), ldb.FLAG_MOD_REPLACE,
            "description")
        self.samdb.modify(m)

        # These bits are privileged, but authenticated users have that CAR by default, so this is a pain to test
        priv_to_auth_users_bits = set([UF_PASSWD_NOTREQD, UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED,
                                       UF_DONT_EXPIRE_PASSWD])

        # These bits really are privileged, or can't be changed from UF_NORMAL as a non-admin
        priv_bits = set([UF_INTERDOMAIN_TRUST_ACCOUNT, UF_SERVER_TRUST_ACCOUNT,
                         UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
                         UF_WORKSTATION_TRUST_ACCOUNT])

        invalid_bits = set([UF_TEMP_DUPLICATE_ACCOUNT, UF_PARTIAL_SECRETS_ACCOUNT])

        m = ldb.Message()
        m.dn = res[0].dn
        m["userAccountControl"] = ldb.MessageElement(str(bit | UF_PASSWD_NOTREQD),
                                                     ldb.FLAG_MOD_REPLACE, "userAccountControl")
        try:
            self.samdb.modify(m)
            if (bit in priv_bits):
                self.fail("Unexpectedly able to set userAccountControl bit 0x%08X (%s), on %s"
                          % (bit, bit_str, m.dn))
        except LdbError as e:
            (enum, estr) = e.args
            if bit in invalid_bits:
                self.assertEqual(enum,
                                 ldb.ERR_OTHER,
                                 "was not able to set 0x%08X (%s) on %s"
                                 % (bit, bit_str, m.dn))
            elif (bit in priv_bits):
                self.assertEqual(ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS, enum)
            else:
                self.fail("Unable to set userAccountControl bit 0x%08X (%s) on %s: %s"
                          % (bit, bit_str, m.dn, estr))

    def _test_uac_bits_unrelated_modify_with_args(self, account_type):
        user_sid = self.sd_utils.get_object_sid(self.unpriv_user_dn)
        mod = "(OA;;CC;bf967a86-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)

        old_sd = self.sd_utils.read_sd_on_dn(self.OU)

        self.sd_utils.dacl_add_ace(self.OU, mod)

        computername = self.computernames[0]
        self.add_computer_ldap(computername, others={"userAccountControl": [str(account_type)]})

        res = self.admin_samdb.search("%s" % self.base_dn,
                                      expression="(&(objectClass=computer)(samAccountName=%s$))" % computername,
                                      scope=SCOPE_SUBTREE,
                                      attrs=["userAccountControl"])
        self.assertEqual(int(res[0]["userAccountControl"][0]), account_type)

        m = ldb.Message()
        m.dn = res[0].dn
        m["description"] = ldb.MessageElement(
            ("A description"), ldb.FLAG_MOD_REPLACE,
            "description")
        self.samdb.modify(m)

        invalid_bits = set([UF_TEMP_DUPLICATE_ACCOUNT, UF_PARTIAL_SECRETS_ACCOUNT])

        # UF_LOCKOUT isn't actually ignored, it changes other
        # attributes but does not stick here.  See MS-SAMR 2.2.1.13
        # UF_FLAG Codes clarification that UF_SCRIPT and
        # UF_PASSWD_CANT_CHANGE are simply ignored by both clients and
        # servers.  Other bits are ignored as they are undefined, or
        # are not set into the attribute (instead triggering other
        # events).
        ignored_bits = set([UF_SCRIPT, UF_00000004, UF_LOCKOUT, UF_PASSWD_CANT_CHANGE,
                            UF_00000400, UF_00004000, UF_00008000, UF_PASSWORD_EXPIRED,
                            int("0x10000000", 16), int("0x20000000", 16), int("0x40000000", 16), int("0x80000000", 16)])
        super_priv_bits = set([UF_INTERDOMAIN_TRUST_ACCOUNT])

        priv_to_remove_bits = set([UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION, UF_WORKSTATION_TRUST_ACCOUNT])

        for bit in bits:
            # Reset this to the initial position, just to be sure
            m = ldb.Message()
            m.dn = res[0].dn
            m["userAccountControl"] = ldb.MessageElement(str(account_type),
                                                         ldb.FLAG_MOD_REPLACE, "userAccountControl")
            self.admin_samdb.modify(m)

            res = self.admin_samdb.search("%s" % self.base_dn,
                                          expression="(&(objectClass=computer)(samAccountName=%s$))" % computername,
                                          scope=SCOPE_SUBTREE,
                                          attrs=["userAccountControl"])

            self.assertEqual(int(res[0]["userAccountControl"][0]), account_type)

            m = ldb.Message()
            m.dn = res[0].dn
            m["userAccountControl"] = ldb.MessageElement(str(bit | UF_PASSWD_NOTREQD),
                                                         ldb.FLAG_MOD_REPLACE, "userAccountControl")
            try:
                self.admin_samdb.modify(m)
                if bit in invalid_bits:
                    self.fail("Should have been unable to set userAccountControl bit 0x%08X on %s" % (bit, m.dn))

            except LdbError as e1:
                (enum, estr) = e1.args
                if bit in invalid_bits:
                    self.assertEqual(enum, ldb.ERR_OTHER)
                    # No point going on, try the next bit
                    continue
                elif bit in super_priv_bits:
                    self.assertEqual(enum, ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS)
                    # No point going on, try the next bit
                    continue
                else:
                    self.fail("Unable to set userAccountControl bit 0x%08X on %s: %s" % (bit, m.dn, estr))

            res = self.admin_samdb.search("%s" % self.base_dn,
                                          expression="(&(objectClass=computer)(samAccountName=%s$))" % computername,
                                          scope=SCOPE_SUBTREE,
                                          attrs=["userAccountControl"])

            if bit in ignored_bits:
                self.assertEqual(int(res[0]["userAccountControl"][0]),
                                 UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD,
                                 "Bit 0x%08x shouldn't stick" % bit)
            else:
                if bit in account_types:
                    self.assertEqual(int(res[0]["userAccountControl"][0]),
                                     bit | UF_PASSWD_NOTREQD,
                                     "Bit 0x%08x didn't stick" % bit)
                else:
                    self.assertEqual(int(res[0]["userAccountControl"][0]),
                                     bit | UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD,
                                     "Bit 0x%08x didn't stick" % bit)

            try:
                m = ldb.Message()
                m.dn = res[0].dn
                m["userAccountControl"] = ldb.MessageElement(str(bit | UF_PASSWD_NOTREQD | UF_ACCOUNTDISABLE),
                                                             ldb.FLAG_MOD_REPLACE, "userAccountControl")
                self.samdb.modify(m)

            except LdbError as e2:
                (enum, estr) = e2.args
                self.fail("Unable to set userAccountControl bit 0x%08X on %s: %s" % (bit, m.dn, estr))

            res = self.admin_samdb.search("%s" % self.base_dn,
                                          expression="(&(objectClass=computer)(samAccountName=%s$))" % computername,
                                          scope=SCOPE_SUBTREE,
                                          attrs=["userAccountControl"])

            if bit in account_types:
                self.assertEqual(int(res[0]["userAccountControl"][0]),
                                 bit | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD,
                                 "bit 0X%08x should have been added (0X%08x vs 0X%08x)"
                                 % (bit, int(res[0]["userAccountControl"][0]),
                                    bit | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD))
            elif bit in ignored_bits:
                self.assertEqual(int(res[0]["userAccountControl"][0]),
                                 UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD,
                                 "bit 0X%08x should have been added (0X%08x vs 0X%08x)"
                                 % (bit, int(res[0]["userAccountControl"][0]),
                                    UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD))

            else:
                self.assertEqual(int(res[0]["userAccountControl"][0]),
                                 bit | UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD,
                                 "bit 0X%08x should have been added (0X%08x vs 0X%08x)"
                                 % (bit, int(res[0]["userAccountControl"][0]),
                                    bit | UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD))

            try:
                m = ldb.Message()
                m.dn = res[0].dn
                m["userAccountControl"] = ldb.MessageElement(str(UF_PASSWD_NOTREQD | UF_ACCOUNTDISABLE),
                                                             ldb.FLAG_MOD_REPLACE, "userAccountControl")
                self.samdb.modify(m)
                if bit in priv_to_remove_bits:
                    self.fail("Should have been unable to remove userAccountControl bit 0x%08X on %s" % (bit, m.dn))

            except LdbError as e3:
                (enum, estr) = e3.args
                if bit in priv_to_remove_bits:
                    self.assertEqual(enum, ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS)
                else:
                    self.fail("Unexpectedly unable to remove userAccountControl bit 0x%08X on %s: %s" % (bit, m.dn, estr))

            res = self.admin_samdb.search("%s" % self.base_dn,
                                          expression="(&(objectClass=computer)(samAccountName=%s$))" % computername,
                                          scope=SCOPE_SUBTREE,
                                          attrs=["userAccountControl"])

            if bit in priv_to_remove_bits:
                if bit in account_types:
                    self.assertEqual(int(res[0]["userAccountControl"][0]),
                                     bit | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD,
                                     "bit 0X%08x should not have been removed" % bit)
                else:
                    self.assertEqual(int(res[0]["userAccountControl"][0]),
                                     bit | UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD,
                                     "bit 0X%08x should not have been removed" % bit)
            else:
                self.assertEqual(int(res[0]["userAccountControl"][0]),
                                 UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD,
                                 "bit 0X%08x should have been removed" % bit)

    def _test_uac_bits_add_with_args(self, bit, bit_str):
        computername = self.computernames[0]

        user_sid = self.sd_utils.get_object_sid(self.unpriv_user_dn)
        mod = "(OA;;CC;bf967a86-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)

        old_sd = self.sd_utils.read_sd_on_dn(self.OU)

        self.sd_utils.dacl_add_ace(self.OU, mod)

        invalid_bits = set([UF_TEMP_DUPLICATE_ACCOUNT, UF_PARTIAL_SECRETS_ACCOUNT])
        # These bits are privileged, but authenticated users have that CAR by default, so this is a pain to test
        priv_to_auth_users_bits = set([UF_PASSWD_NOTREQD, UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED,
                                       UF_DONT_EXPIRE_PASSWD])

        # These bits really are privileged
        priv_bits = set([UF_INTERDOMAIN_TRUST_ACCOUNT, UF_SERVER_TRUST_ACCOUNT,
                         UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION])

        try:
            self.add_computer_ldap(computername, others={"userAccountControl": [str(bit)]})
            delete_force(self.admin_samdb, "CN=%s,%s" % (computername, self.OU))
            if bit in priv_bits:
                self.fail("Unexpectdly able to set userAccountControl bit 0x%08X (%s) on %s"
                          % (bit, bit_str, computername))

        except LdbError as e4:
            (enum, estr) = e4.args
            if bit in invalid_bits:
                self.assertEqual(enum,
                                 ldb.ERR_OTHER,
                                 "Invalid bit 0x%08X (%s) was able to be set on %s"
                                 % (bit,
                                    bit_str,
                                    computername))
            elif bit in priv_bits:
                self.assertEqual(enum, ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS)
            else:
                self.fail("Unable to set userAccountControl bit 0x%08X (%s) on %s: %s"
                          % (bit,
                             bit_str,
                             computername,
                             estr))

    def test_primarygroupID_cc_add(self):
        computername = self.computernames[0]

        user_sid = self.sd_utils.get_object_sid(self.unpriv_user_dn)
        mod = "(OA;;CC;bf967a86-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)

        old_sd = self.sd_utils.read_sd_on_dn(self.OU)

        self.sd_utils.dacl_add_ace(self.OU, mod)
        try:
            # When creating a new object, you can not ever set the primaryGroupID
            self.add_computer_ldap(computername, others={"primaryGroupID": [str(security.DOMAIN_RID_ADMINS)]})
            self.fail("Unexpectedly able to set primaryGruopID to be an admin on %s" % computername)
        except LdbError as e13:
            (enum, estr) = e13.args
            self.assertEqual(enum, ldb.ERR_UNWILLING_TO_PERFORM)

    def test_primarygroupID_priv_DC_modify(self):
        computername = self.computernames[0]

        self.add_computer_ldap(computername,
                               others={"userAccountControl": [str(UF_SERVER_TRUST_ACCOUNT)]},
                               samdb=self.admin_samdb)
        res = self.admin_samdb.search("%s" % self.base_dn,
                                      expression="(&(objectClass=computer)(samAccountName=%s$))" % computername,
                                      scope=SCOPE_SUBTREE,
                                      attrs=[""])

        m = ldb.Message()
        m.dn = ldb.Dn(self.admin_samdb, "<SID=%s-%d>" % (str(self.domain_sid),
                                                         security.DOMAIN_RID_USERS))
        m["member"] = ldb.MessageElement(
            [str(res[0].dn)], ldb.FLAG_MOD_ADD,
            "member")
        self.admin_samdb.modify(m)

        m = ldb.Message()
        m.dn = res[0].dn
        m["primaryGroupID"] = ldb.MessageElement(
            [str(security.DOMAIN_RID_USERS)], ldb.FLAG_MOD_REPLACE,
            "primaryGroupID")
        try:
            self.admin_samdb.modify(m)

            # When creating a new object, you can not ever set the primaryGroupID
            self.fail("Unexpectedly able to set primaryGroupID to be other than DCS on %s" % computername)
        except LdbError as e14:
            (enum, estr) = e14.args
            self.assertEqual(enum, ldb.ERR_UNWILLING_TO_PERFORM)

    def test_primarygroupID_priv_member_modify(self):
        computername = self.computernames[0]

        self.add_computer_ldap(computername,
                               others={"userAccountControl": [str(UF_WORKSTATION_TRUST_ACCOUNT | UF_PARTIAL_SECRETS_ACCOUNT)]},
                               samdb=self.admin_samdb)
        res = self.admin_samdb.search("%s" % self.base_dn,
                                      expression="(&(objectClass=computer)(samAccountName=%s$))" % computername,
                                      scope=SCOPE_SUBTREE,
                                      attrs=[""])

        m = ldb.Message()
        m.dn = ldb.Dn(self.admin_samdb, "<SID=%s-%d>" % (str(self.domain_sid),
                                                         security.DOMAIN_RID_USERS))
        m["member"] = ldb.MessageElement(
            [str(res[0].dn)], ldb.FLAG_MOD_ADD,
            "member")
        self.admin_samdb.modify(m)

        m = ldb.Message()
        m.dn = res[0].dn
        m["primaryGroupID"] = ldb.MessageElement(
            [str(security.DOMAIN_RID_USERS)], ldb.FLAG_MOD_REPLACE,
            "primaryGroupID")
        try:
            self.admin_samdb.modify(m)

            # When creating a new object, you can not ever set the primaryGroupID
            self.fail("Unexpectedly able to set primaryGroupID to be other than DCS on %s" % computername)
        except LdbError as e15:
            (enum, estr) = e15.args
            self.assertEqual(enum, ldb.ERR_UNWILLING_TO_PERFORM)

    def test_primarygroupID_priv_user_modify(self):
        computername = self.computernames[0]

        self.add_computer_ldap(computername,
                               others={"userAccountControl": [str(UF_WORKSTATION_TRUST_ACCOUNT)]},
                               samdb=self.admin_samdb)
        res = self.admin_samdb.search("%s" % self.base_dn,
                                      expression="(&(objectClass=computer)(samAccountName=%s$))" % computername,
                                      scope=SCOPE_SUBTREE,
                                      attrs=[""])

        m = ldb.Message()
        m.dn = ldb.Dn(self.admin_samdb, "<SID=%s-%d>" % (str(self.domain_sid),
                                                         security.DOMAIN_RID_ADMINS))
        m["member"] = ldb.MessageElement(
            [str(res[0].dn)], ldb.FLAG_MOD_ADD,
            "member")
        self.admin_samdb.modify(m)

        m = ldb.Message()
        m.dn = res[0].dn
        m["primaryGroupID"] = ldb.MessageElement(
            [str(security.DOMAIN_RID_ADMINS)], ldb.FLAG_MOD_REPLACE,
            "primaryGroupID")
        self.admin_samdb.modify(m)


runner = SubunitTestRunner()
rc = 0
if not runner.run(unittest.makeSuite(UserAccountControlTests)).wasSuccessful():
    rc = 1
sys.exit(rc)
