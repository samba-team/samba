#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import optparse
import sys
sys.path.insert(0, "bin/python")
import samba

from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

from ldb import ERR_INSUFFICIENT_ACCESS_RIGHTS
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from samba.dcerpc import security

from samba.auth import system_session
from samba import gensec, sd_utils
from samba.samdb import SamDB
from samba.credentials import Credentials, DONT_USE_KERBEROS
import samba.tests
import samba.dsdb


parser = optparse.OptionParser("acl.py [options] <host>")
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
if "://" not in host:
    ldaphost = "ldap://%s" % host
else:
    ldaphost = host
    start = host.rindex("://")
    host = host.lstrip(start + 3)

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)
creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

#
# Tests start here
#


class AclTests(samba.tests.TestCase):

    def setUp(self):
        super(AclTests, self).setUp()

        strict_checking = samba.tests.env_get_var_value('STRICT_CHECKING', allow_missing=True)
        if strict_checking is None:
            strict_checking = '1'
        self.strict_checking = bool(int(strict_checking))

        self.ldb_admin = SamDB(ldaphost, credentials=creds, session_info=system_session(lp), lp=lp)
        self.base_dn = self.ldb_admin.domain_dn()
        self.domain_sid = security.dom_sid(self.ldb_admin.get_domain_sid())
        self.user_pass = "samba123@"
        self.configuration_dn = self.ldb_admin.get_config_basedn().get_linearized()
        self.sd_utils = sd_utils.SDUtils(self.ldb_admin)
        self.addCleanup(self.delete_admin_connection)
        # used for anonymous login
        self.creds_tmp = Credentials()
        self.creds_tmp.set_username("")
        self.creds_tmp.set_password("")
        self.creds_tmp.set_domain(creds.get_domain())
        self.creds_tmp.set_realm(creds.get_realm())
        self.creds_tmp.set_workstation(creds.get_workstation())
        print("baseDN: %s" % self.base_dn)

        # set AttributeAuthorizationOnLDAPAdd and BlockOwnerImplicitRights
        self.set_heuristic(samba.dsdb.DS_HR_ATTR_AUTHZ_ON_LDAP_ADD, b'11')

    def set_heuristic(self, index, values):
        self.assertGreater(index, 0)
        self.assertLess(index, 30)
        self.assertIsInstance(values, bytes)

        # Get the old "dSHeuristics" if it was set
        dsheuristics = self.ldb_admin.get_dsheuristics()
        # Reset the "dSHeuristics" as they were before
        self.addCleanup(self.ldb_admin.set_dsheuristics, dsheuristics)
        # Set the "dSHeuristics" to activate the correct behaviour
        default_heuristics = b"000000000100000000020000000003"
        if dsheuristics is None:
            dsheuristics = b""
        dsheuristics += default_heuristics[len(dsheuristics):]
        dsheuristics = (dsheuristics[:index - 1] +
                        values +
                        dsheuristics[index - 1 + len(values):])
        self.ldb_admin.set_dsheuristics(dsheuristics)

    def get_user_dn(self, name):
        return "CN=%s,CN=Users,%s" % (name, self.base_dn)

    def get_ldb_connection(self, target_username, target_password):
        creds_tmp = Credentials()
        creds_tmp.set_username(target_username)
        creds_tmp.set_password(target_password)
        creds_tmp.set_domain(creds.get_domain())
        creds_tmp.set_realm(creds.get_realm())
        creds_tmp.set_workstation(creds.get_workstation())
        creds_tmp.set_gensec_features(creds_tmp.get_gensec_features()
                                      | gensec.FEATURE_SEAL)
        creds_tmp.set_kerberos_state(DONT_USE_KERBEROS)  # kinit is too expensive to use in a tight loop
        ldb_target = SamDB(url=ldaphost, credentials=creds_tmp, lp=lp)
        return ldb_target

    # Test if we have any additional groups for users than default ones
    def assert_user_no_group_member(self, username):
        res = self.ldb_admin.search(self.base_dn, expression="(distinguishedName=%s)" % self.get_user_dn(username))
        try:
            self.assertEqual(res[0]["memberOf"][0], "")
        except KeyError:
            pass
        else:
            self.fail()

    def delete_admin_connection(self):
        del self.sd_utils
        del self.ldb_admin


class AclModifyTests(AclTests):

    def setup_computer_with_hostname(self, account_name):
        ou_dn = f'OU={account_name},{self.base_dn}'
        dn = f'CN={account_name},{ou_dn}'

        user, password = "mouse", "mus musculus 123!"
        self.addCleanup(self.ldb_admin.deleteuser, user)

        self.ldb_admin.newuser(user, password)
        self.ldb_user = self.get_ldb_connection(user, password)

        self.addCleanup(self.ldb_admin.delete, ou_dn,
                        controls=["tree_delete:0"])
        self.ldb_admin.create_ou(ou_dn)

        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': account_name + '$',
        })

        host_name = f'{account_name}.{self.ldb_user.domain_dns_name()}'

        m = Message(Dn(self.ldb_admin, dn))
        m['dNSHostName'] = MessageElement(host_name,
                                          FLAG_MOD_REPLACE,
                                          'dNSHostName')

        self.ldb_admin.modify(m)
        return host_name, dn

    def test_modify_delete_dns_host_name_specified(self):
        '''Test deleting dNSHostName'''
        account_name = self.id().rsplit(".", 1)[1][:63]
        host_name, dn = self.setup_computer_with_hostname(account_name)

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement(host_name,
                                          FLAG_MOD_DELETE,
                                          'dNSHostName')

        self.assertRaisesLdbError(
            ERR_INSUFFICIENT_ACCESS_RIGHTS,
            "User able to delete dNSHostName (with specified name)",
            self.ldb_user.modify, m)

    def test_modify_delete_dns_host_name_unspecified(self):
        '''Test deleting dNSHostName'''
        account_name = self.id().rsplit(".", 1)[1][:63]
        host_name, dn = self.setup_computer_with_hostname(account_name)

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement([],
                                          FLAG_MOD_DELETE,
                                          'dNSHostName')

        self.assertRaisesLdbError(
            ERR_INSUFFICIENT_ACCESS_RIGHTS,
            "User able to delete dNSHostName (without specified name)",
            self.ldb_user.modify, m)

    def test_modify_delete_dns_host_name_ldif_specified(self):
        '''Test deleting dNSHostName'''
        account_name = self.id().rsplit(".", 1)[1][:63]
        host_name, dn = self.setup_computer_with_hostname(account_name)

        ldif = f"""
dn: {dn}
changetype: modify
delete: dNSHostName
dNSHostName: {host_name}
"""
        self.assertRaisesLdbError(
            ERR_INSUFFICIENT_ACCESS_RIGHTS,
            "User able to delete dNSHostName (with specified name)",
            self.ldb_user.modify_ldif, ldif)

    def test_modify_delete_dns_host_name_ldif_unspecified(self):
        '''Test deleting dNSHostName'''
        account_name = self.id().rsplit(".", 1)[1][:63]
        host_name, dn = self.setup_computer_with_hostname(account_name)

        ldif = f"""
dn: {dn}
changetype: modify
delete: dNSHostName
"""
        self.assertRaisesLdbError(
            ERR_INSUFFICIENT_ACCESS_RIGHTS,
            "User able to delete dNSHostName (without specific name)",
            self.ldb_user.modify_ldif, ldif)


ldb = SamDB(ldaphost, credentials=creds, session_info=system_session(lp), lp=lp)

TestProgram(module=__name__, opts=subunitopts)
