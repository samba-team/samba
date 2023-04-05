#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import optparse

sys.path.insert(0, "bin/python")
import samba.getopt as options
from ldb import Message, MessageElement, Dn
from ldb import LdbError, FLAG_MOD_REPLACE, ERR_UNWILLING_TO_PERFORM, SCOPE_BASE
from samba import gensec
from samba.auth import system_session
from samba.samdb import SamDB
from samba.tests import delete_force
from samba.tests.password_test import PasswordTestCase
from samba.tests.subunitrun import SubunitOptions, TestProgram

parser = optparse.OptionParser("unicodepwd_encrypted.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)
lp = sambaopts.get_loadparm()
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]
host_ldaps = f"ldaps://{host}"
host_ldap = f"ldap://{host}"


class UnicodePwdEncryptedConnectionTests(PasswordTestCase):

    def setUp(self):
        super().setUp()
        self.creds = self.insta_creds(template=credopts.get_credentials(lp))
        self.ldb = SamDB(host_ldap, credentials=self.creds,
                         session_info=system_session(lp),
                         lp=lp)
        self.base_dn = self.ldb.domain_dn()
        self.user_dn_str = f"cn=testuser,cn=users,{self.base_dn}"
        self.user_dn = Dn(self.ldb, self.user_dn_str)
        print(f"baseDN: {self.base_dn}\n")

        # permit password changes during this test
        self.allow_password_changes()

        # (Re)adds the test user "testuser" with no password.
        delete_force(self.ldb, str(self.user_dn))
        self.ldb.add({
            "dn": str(self.user_dn),
            "objectclass": "user",
            "sAMAccountName": "testuser"
        })

        # Set the test user initial password and enable account.
        m = Message(self.user_dn)
        m["0"] = MessageElement("Password#2", FLAG_MOD_REPLACE, "userPassword")
        self.ldb.modify(m)
        self.ldb.enable_account("(sAMAccountName=testuser)")

    def modify_unicode_pwd(self, ldb, password):
        """Replaces user password using unicodePwd."""
        m = Message()
        m.dn = self.user_dn
        m["unicodePwd"] = MessageElement(
            f'"{password}"'.encode('utf-16-le'),
            FLAG_MOD_REPLACE, "unicodePwd"
        )
        ldb.modify(m)

    def get_admin_sid(self, ldb):
        res = self.ldb.search(
            base="", expression="", scope=SCOPE_BASE, attrs=["tokenGroups"])

        return self.ldb.schema_format_value(
            "tokenGroups", res[0]["tokenGroups"][0]).decode("utf8")

    def test_with_seal(self):
        """Test unicodePwd on connection with seal.

        This should allow unicodePwd.
        """
        self.modify_unicode_pwd(self.ldb, "thatsAcomplPASS2")

    def test_without_seal(self):
        """Test unicodePwd on connection without seal.

        Should not allow unicodePwd on an unencrypted connection.

        Requires --use-kerberos=required, or it automatically upgrades
        to an encrypted connection.
        """
        # Remove FEATURE_SEAL which gets added by insta_creds.
        creds_noseal = self.insta_creds(template=credopts.get_credentials(lp))
        creds_noseal.set_gensec_features(creds_noseal.get_gensec_features() &
                                         ~gensec.FEATURE_SEAL)

        sasl_wrap = lp.get('client ldap sasl wrapping')
        self.addCleanup(lp.set, 'client ldap sasl wrapping', sasl_wrap)
        lp.set('client ldap sasl wrapping', 'sign')

        # Create a second ldb connection without seal.
        ldb = SamDB(host_ldap, credentials=creds_noseal,
                    session_info=system_session(lp),
                    lp=lp)

        with self.assertRaises(LdbError) as e:
            self.modify_unicode_pwd(ldb, "thatsAcomplPASS2")

        # Server should not allow unicodePwd on an unencrypted connection.
        self.assertEqual(e.exception.args[0], ERR_UNWILLING_TO_PERFORM)
        self.assertIn(
            "Password modification over LDAP must be over an encrypted connection",
            e.exception.args[1]
        )

    def test_simple_bind_plain(self):
        """Test unicodePwd using simple bind without encryption."""
        admin_sid = self.get_admin_sid(self.ldb)

        self.creds.set_bind_dn(admin_sid)
        ldb = SamDB(url=host_ldap, credentials=self.creds, lp=lp)

        with self.assertRaises(LdbError) as e:
            self.modify_unicode_pwd(ldb, "thatsAcomplPASS2")

        # Server should not allow unicodePwd on an unencrypted connection.
        self.assertEqual(e.exception.args[0], ERR_UNWILLING_TO_PERFORM)
        self.assertIn(
            "Password modification over LDAP must be over an encrypted connection",
            e.exception.args[1]
        )

    def test_simple_bind_tls(self):
        """Test unicodePwd using simple bind with encryption."""
        admin_sid = self.get_admin_sid(self.ldb)

        self.creds.set_bind_dn(admin_sid)
        ldb = SamDB(url=host_ldaps, credentials=self.creds, lp=lp)

        self.modify_unicode_pwd(ldb, "thatsAcomplPASS2")


TestProgram(module=__name__, opts=subunitopts)
