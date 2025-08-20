#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# These are unit tests for LDAP access checks

import optparse
import sys

sys.path.insert(0, "bin/python")
import samba

from typing import List, Optional

from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

from ldb import (
    LdbError,
    ERR_INSUFFICIENT_ACCESS_RIGHTS,
)
from ldb import ERR_CONSTRAINT_VIOLATION
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_REPLACE, FLAG_MOD_ADD, FLAG_MOD_DELETE
from samba.dcerpc import security

from samba.auth import system_session
from samba import gensec, key_credential_link, sd_utils
from samba.samdb import BinaryDn, SamDB
from samba.credentials import Credentials, DONT_USE_KERBEROS
import samba.tests
from samba.tests import delete_force
import samba.dsdb

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.backends import default_backend

parser = optparse.OptionParser("key_credential_link.py [options] <host>")
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

        strict_checking = samba.tests.env_get_var_value(
            "STRICT_CHECKING", allow_missing=True
        )
        if strict_checking is None:
            strict_checking = "1"
        self.strict_checking = bool(int(strict_checking))

        self.ldb_admin = SamDB(
            ldaphost, credentials=creds, session_info=system_session(lp), lp=lp
        )
        self.base_dn = self.ldb_admin.domain_dn()
        self.domain_sid = security.dom_sid(self.ldb_admin.get_domain_sid())
        self.user_pass = "samba123@"
        self.configuration_dn = self.ldb_admin.get_config_basedn().get_linearized()
        self.sd_utils = sd_utils.SDUtils(self.ldb_admin)
        self.addCleanup(self.delete_admin_connection)

        # set AttributeAuthorizationOnLDAPAdd and BlockOwnerImplicitRights
        self.set_heuristic(samba.dsdb.DS_HR_ATTR_AUTHZ_ON_LDAP_ADD, b"11")

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
        dsheuristics += default_heuristics[len(dsheuristics) :]
        dsheuristics = (
            dsheuristics[: index - 1] + values + dsheuristics[index - 1 + len(values) :]
        )
        self.ldb_admin.set_dsheuristics(dsheuristics)

    def get_user_dn(self, name):
        return "CN=%s,CN=Users,%s" % (name, self.base_dn)

    def get_computer_dn(self, name):
        return f"CN={name},CN=Computers,{self.base_dn}"

    def get_creds(self, target_username, target_password):
        creds_tmp = Credentials()
        creds_tmp.set_username(target_username)
        creds_tmp.set_password(target_password)
        creds_tmp.set_domain(creds.get_domain())
        creds_tmp.set_realm(creds.get_realm())
        creds_tmp.set_workstation(creds.get_workstation())
        creds_tmp.set_gensec_features(
            creds_tmp.get_gensec_features() | gensec.FEATURE_SEAL
        )
        creds_tmp.set_kerberos_state(
            DONT_USE_KERBEROS
        )  # kinit is too expensive to use in a tight loop
        return creds_tmp

    def get_ldb_connection(self, target_username, target_password):
        creds_tmp = self.get_creds(target_username, target_password)
        ldb_target = SamDB(url=ldaphost, credentials=creds_tmp, lp=lp)
        return ldb_target

    def delete_admin_connection(self):
        del self.sd_utils
        del self.ldb_admin


class AclKeyCredentialLinkTests(AclTests):
    def setUp(self):
        super().setUp()
        self.user = "acl_key_cred_user"
        self.computer = "acl_key_cred_comp"
        self.user_dn = self.get_user_dn(self.user)
        self.computer_dn = self.get_computer_dn(self.computer)
        delete_force(self.ldb_admin, self.user_dn)
        delete_force(self.ldb_admin, self.computer_dn)
        self.ldb_admin.newuser(self.user, self.user_pass)
        self.ldb_admin.newcomputer(self.computer)
        self.ldb_admin.setpassword(f"sAMAccountName={self.computer}$", self.user_pass)
        self.user_creds = self.get_creds(self.user, self.user_pass)
        self.ldb_user = self.get_ldb_connection(self.user, self.user_pass)
        self.ldb_computer = self.get_ldb_connection(f"{self.computer}$", self.user_pass)

    def tearDown(self):
        super().tearDown()
        delete_force(self.ldb_admin, self.user_dn)
        delete_force(self.ldb_admin, self.computer_dn)

    def create_key_credential_link_value(self, target_dn):
        private_key = asymmetric.rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        public_data = public_key.public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )

        return key_credential_link.create_key_credential_link(
            self.ldb_admin, target_dn, public_data
        )

    def test_can_add_with_write_property(self):
        self._test_key_cred_link(
            self.ldb_computer,
            self.computer_dn,
            [self.create_key_credential_link_value(self.computer_dn)],
            allow_write=True,
        )

    def test_cannot_add_without_write_property_or_validated_write(self):
        self._test_key_cred_link(
            self.ldb_computer,
            self.computer_dn,
            [self.create_key_credential_link_value(self.computer_dn)],
            expect_error=ERR_INSUFFICIENT_ACCESS_RIGHTS,
        )

    def test_can_delete_with_validated_write(self):
        target_dn = self.computer_dn
        target_sid = self.sd_utils.get_object_sid(target_dn)

        msg = Message(Dn(self.ldb_admin, target_dn))
        msg["msDS-KeyCredentialLink"] = MessageElement(
            [
                self.create_key_credential_link_value(self.computer_dn)
                .get_linearized()
                .encode()
            ],
            FLAG_MOD_ADD,
            "msDS-KeyCredentialLink",
        )
        self.ldb_admin.modify(msg)

        mod = f"(OD;;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_MS_DS_KEY_CREDENTIAL_LINK};;{target_sid})"
        self.sd_utils.dacl_add_ace(target_dn, mod)

        mod = f"(OA;;SW;{security.GUID_DRS_DS_VALIDATED_WRITE_COMPUTER};;{target_sid})"
        self.sd_utils.dacl_add_ace(target_dn, mod)

        msg = Message(Dn(self.ldb_admin, target_dn))
        msg["msDS-KeyCredentialLink"] = MessageElement(
            [],
            FLAG_MOD_DELETE,
            "msDS-KeyCredentialLink",
        )
        self.ldb_computer.modify(msg)

    def test_cannot_delete_without_write_property_or_validated_write(self):
        target_dn = self.computer_dn
        target_sid = self.sd_utils.get_object_sid(target_dn)

        msg = Message(Dn(self.ldb_admin, target_dn))
        msg["msDS-KeyCredentialLink"] = MessageElement(
            [
                self.create_key_credential_link_value(self.computer_dn)
                .get_linearized()
                .encode()
            ],
            FLAG_MOD_ADD,
            "msDS-KeyCredentialLink",
        )
        self.ldb_admin.modify(msg)

        mod = f"(OD;;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_MS_DS_KEY_CREDENTIAL_LINK};;{target_sid})"
        self.sd_utils.dacl_add_ace(target_dn, mod)

        mod = f"(OD;;SW;{security.GUID_DRS_DS_VALIDATED_WRITE_COMPUTER};;{target_sid})"
        self.sd_utils.dacl_add_ace(target_dn, mod)

        msg = Message(Dn(self.ldb_admin, target_dn))
        msg["msDS-KeyCredentialLink"] = MessageElement(
            [],
            FLAG_MOD_DELETE,
            "msDS-KeyCredentialLink",
        )
        try:
            self.ldb_computer.modify(msg)
        except LdbError as err:
            self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, err.args[0])
        else:
            self.fail("expected to fail")

    def test_can_add_to_computer_with_validated_write(self):
        self._test_key_cred_link(
            self.ldb_computer,
            self.computer_dn,
            [self.create_key_credential_link_value(self.computer_dn)],
            allow_validated_write=True,
        )

    def test_cannot_add_to_non_computer_with_validated_write(self):
        self._test_key_cred_link(
            self.ldb_user,
            self.user_dn,
            [self.create_key_credential_link_value(self.computer_dn)],
            allow_validated_write=True,
            expect_error=ERR_INSUFFICIENT_ACCESS_RIGHTS,
        )

    def test_can_add_to_non_computer_with_write_property(self):
        self._test_key_cred_link(
            self.ldb_user,
            self.user_dn,
            [self.create_key_credential_link_value(self.computer_dn)],
            allow_write=True,
        )

    def test_can_add_multiple_values_with_write_property(self):
        self._test_key_cred_link(
            self.ldb_computer,
            self.computer_dn,
            [
                self.create_key_credential_link_value(self.computer_dn),
                self.create_key_credential_link_value(self.computer_dn),
            ],
            allow_write=True,
        )

    def test_cannot_add_multiple_values_with_validated_write(self):
        self._test_key_cred_link(
            self.ldb_computer,
            self.computer_dn,
            [
                self.create_key_credential_link_value(self.computer_dn),
                self.create_key_credential_link_value(self.computer_dn),
            ],
            allow_validated_write=True,
            expect_error=ERR_INSUFFICIENT_ACCESS_RIGHTS,
        )

    def test_can_replace_no_values_with_validated_write(self):
        self._test_key_cred_link(
            self.ldb_computer,
            self.computer_dn,
            [],
            allow_validated_write=True,
            replace_existing=True,
        )

    def test_cannot_add_no_values(self):
        self._test_key_cred_link(
            self.ldb_computer,
            self.computer_dn,
            [],
            allow_write=True,
            expect_error=ERR_CONSTRAINT_VIOLATION,
        )

    def test_can_add_to_existing_value_with_write_property(self):
        for _ in range(2):
            self._test_key_cred_link(
                self.ldb_computer,
                self.computer_dn,
                [self.create_key_credential_link_value(self.computer_dn)],
                allow_write=True,
            )

    def test_cannot_add_to_existing_value_with_validated_write(self):
        self._test_key_cred_link(
            self.ldb_computer,
            self.computer_dn,
            [self.create_key_credential_link_value(self.computer_dn)],
            allow_validated_write=True,
        )
        self._test_key_cred_link(
            self.ldb_computer,
            self.computer_dn,
            [self.create_key_credential_link_value(self.computer_dn)],
            allow_validated_write=True,
            expect_error=ERR_INSUFFICIENT_ACCESS_RIGHTS,
        )

    def test_can_replace_existing_value_with_write_property(self):
        self._test_key_cred_link(
            self.ldb_computer,
            self.computer_dn,
            [self.create_key_credential_link_value(self.computer_dn)],
            allow_write=True,
        )
        self._test_key_cred_link(
            self.ldb_computer,
            self.computer_dn,
            [self.create_key_credential_link_value(self.computer_dn)],
            allow_write=True,
            replace_existing=True,
        )

    def test_cannot_replace_existing_value_with_validated_write(self):
        self._test_key_cred_link(
            self.ldb_computer,
            self.computer_dn,
            [self.create_key_credential_link_value(self.computer_dn)],
            allow_validated_write=True,
        )
        self._test_key_cred_link(
            self.ldb_computer,
            self.computer_dn,
            [self.create_key_credential_link_value(self.computer_dn)],
            allow_validated_write=True,
            replace_existing=True,
            expect_error=ERR_INSUFFICIENT_ACCESS_RIGHTS,
        )

    def test_can_add_malformed_value_with_write_property(self):
        key_cred_link = BinaryDn.from_bytes_and_dn(
            self.ldb_admin, b"foo bar baz", self.computer_dn
        )

        self._test_key_cred_link(
            self.ldb_computer,
            self.computer_dn,
            [key_cred_link],
            allow_write=True,
        )

    def test_cannot_add_malformed_value_with_validated_write(self):
        key_cred_link = BinaryDn.from_bytes_and_dn(
            self.ldb_admin, b"foo bar baz", self.computer_dn
        )

        self._test_key_cred_link(
            self.ldb_computer,
            self.computer_dn,
            [key_cred_link],
            allow_validated_write=True,
            expect_error=ERR_INSUFFICIENT_ACCESS_RIGHTS,
        )

    def test_can_add_to_other_with_write_property(self):
        self._test_key_cred_link(
            self.ldb_user,
            self.computer_dn,
            [self.create_key_credential_link_value(self.computer_dn)],
            user_sid=self.sd_utils.get_object_sid(self.user_dn),
            allow_write=True,
        )

    def test_cannot_add_to_other_with_validated_write(self):
        self._test_key_cred_link(
            self.ldb_user,
            self.computer_dn,
            [self.create_key_credential_link_value(self.computer_dn)],
            user_sid=self.sd_utils.get_object_sid(self.user_dn),
            allow_validated_write=True,
            expect_error=ERR_INSUFFICIENT_ACCESS_RIGHTS,
        )

    def _test_key_cred_link(
        self,
        samdb: SamDB,
        target_dn: str,
        key_cred_link_dns: List[key_credential_link.KeyCredentialLinkDn],
        *,
        user_sid: Optional[security.dom_sid] = None,
        allow_write: bool = False,
        allow_validated_write: bool = False,
        replace_existing: bool = False,
        expect_error: int = 0,
    ):
        if user_sid is None:
            user_sid = self.sd_utils.get_object_sid(target_dn)

        mod = f"(O{'A' if allow_write else 'D'};;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_MS_DS_KEY_CREDENTIAL_LINK};;{user_sid})"
        self.sd_utils.dacl_add_ace(target_dn, mod)

        # Note: SELF and OWNER have GUID_DRS_DS_VALIDATED_WRITE_COMPUTER by
        # default.
        mod = f"(O{'A' if allow_validated_write else 'D'};;SW;{security.GUID_DRS_DS_VALIDATED_WRITE_COMPUTER};;{user_sid})"
        self.sd_utils.dacl_add_ace(target_dn, mod)

        key_cred_links = [dn.get_linearized().encode() for dn in key_cred_link_dns]

        msg = Message(Dn(samdb, target_dn))
        msg["msDS-KeyCredentialLink"] = MessageElement(
            key_cred_links,
            FLAG_MOD_REPLACE if replace_existing else FLAG_MOD_ADD,
            "msDS-KeyCredentialLink",
        )
        try:
            samdb.modify(msg)
        except LdbError as err:
            if not expect_error:
                self.fail("got unexpected error")

            self.assertEqual(expect_error, err.args[0])
        else:
            if expect_error:
                self.fail(f"expected to fail with error code {expect_error}")


# Important unit running information

ldb = SamDB(ldaphost, credentials=creds, session_info=system_session(lp), lp=lp)

TestProgram(module=__name__, opts=subunitopts)
