# Unix SMB/CIFS implementation.
#
# Tests for `samba-tool user keytrust`
#
# Copyright © Douglas Bagnall <dbagnall@samba.org> 2025
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

import os
from pathlib import Path

from samba.domain.models import User
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba import key_credential_link as kcl


HOST = "ldap://{DC_SERVER}".format(**os.environ)
CREDS = "-U{DC_USERNAME}%{DC_PASSWORD}".format(**os.environ)

ROOT = (Path(__file__) / '../../../../../').resolve()
TESTDATA = ROOT / 'testdata' / 'keytrust'

GOOD_CERTS = [
    str(TESTDATA / 'cert-rsa-2048.pem'),
    str(TESTDATA / 'ca-cert-rsa-2048.pem'),
]

WRONG_SIZE_CERTS = [
    str(TESTDATA / 'cert-rsa-1024.pem'),
    str(TESTDATA / 'ca-cert-rsa-4096.pem'),
]

NON_RSA_CERTS = [
    str(TESTDATA / 'ca-cert-ecdsa-p256.pem'),
]

GOOD_KEYS = [
    str(TESTDATA / 'rsa2048-pkcs1.der'),
    str(TESTDATA / 'rsa2048b-spki.pem'),
]

DUPLICATE_KEYS = [
    str(TESTDATA / 'cert-rsa-2048.pem'),
    str(TESTDATA / 'public-key-from-cert-rsa-2048-pkcs1.pem'),
]


class SambaToolUserKeyTrustTest(SambaToolCmdTest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.samdb = cls.getSamDB("-H", HOST, CREDS)
        cls.runcmd("user", "key-trust", "delete",
                   "-H", HOST, CREDS,
                   'joe', '--all')
        cls.runcmd("user", "key-trust", "delete",
                   "-H", HOST, CREDS,
                   'alice', '--all')

    def get_links(self, username):
        result = self.samdb.search(expression=f'sAMAccountName={username}',
                                   attrs=['msDS-KeyCredentialLink'])
        self.assertEqual(len(result), 1)
        links = result[0].get('msDS-KeyCredentialLink', [])
        return [kcl.KeyCredentialLinkDn(self.samdb, v) for v in links]

    def test_add_good_cert(self):
        """These ones should just succeed."""
        links = self.get_links('joe')
        n = len(links)
        for f in GOOD_CERTS:
            result, out, err = self.runcmd("user", "key-trust", "add",
                                           "-H", HOST, CREDS,
                                           'joe', f)
            self.assertCmdSuccess(result, out, err)

            n += 1
            links = self.get_links('joe')
            self.assertEqual(len(links), n)

        result, out, err = self.runcmd("user", "key-trust", "delete",
                                       "-H", HOST, CREDS,
                                       'joe', '--all')
        self.assertCmdSuccess(result, out, err)

        for link in links:
            self.assertIn(f"Deleted {link}", out)

        links = self.get_links('joe')
        self.assertEqual(links, [])

    def test_add_and_delete_good_keys(self):
        """Add known good keys, and also check the view and delete commands."""
        links = self.get_links('alice')
        self.assertEqual(links, [])

        result, out, err = self.runcmd("user", "key-trust", "add",
                                       "-H", HOST, CREDS,
                                       'alice', GOOD_KEYS[0])
        self.assertCmdSuccess(result, out, err)
        links = self.get_links('alice')
        self.assertEqual(len(links), 1)

        result, out, err = self.runcmd("user", "key-trust", "view",
                                       "-H", HOST, CREDS,
                                       'alice')
        self.assertCmdSuccess(result, out, err)
        self.assertIn('alice has 1 key credential link\n', out)
        self.assertIn('Link target: CN=alice,CN=Users,DC=addom,DC=samba,DC=example,DC=com\n', out)
        self.assertIn('Number of key entries:            5', out)

        result, out, err = self.runcmd("user", "key-trust", "add",
                                       "-H", HOST, CREDS,
                                       'alice', GOOD_KEYS[1])
        self.assertCmdSuccess(result, out, err)
        result, out, err = self.runcmd("user", "key-trust", "view",
                                       "-H", HOST, CREDS,
                                       'alice', '--verbose')
        self.assertCmdSuccess(result, out, err)
        self.assertIn('alice has 2 key credential links\n', out)

        links = self.get_links('alice')
        fingerprints = [('16:CD:1B:C2:7A:0B:FC:C9:4B:95:11:9F:AD:97:EC:1B:'
                         'ED:BD:64:91:42:2E:AF:CA:CB:1E:C3:EE:86:6D:F1:5A'),
                        ('86:61:6D:B2:6A:3A:04:BD:E0:59:10:13:21:9A:2B:2C:'
                         'C4:FD:CE:50:05:16:3C:66:1B:38:63:79:8C:B1:DA:17')]

        self.assertEqual(set(x.fingerprint() for x in links),
                         set(fingerprints))

        # test delete --dry-run / -n
        result, out, err = self.runcmd("user", "key-trust", "delete",
                                       "-H", HOST, CREDS,
                                       'alice', '--all', '-n')
        self.assertCmdSuccess(result, out, err)
        self.assertIn('Without --dry-run, this would happen:\n', out)
        self.assertIn(f'DELETE {links[0]} (fingerprint {links[0].fingerprint()})',
                      out)
        self.assertIn(f'DELETE {links[1]} (fingerprint {links[1].fingerprint()})',
                      out)
        self.assertNotIn('KEEP', out)
        self.assertIn('alice would now have 0 key credential links\n', out)

        result, out, err = self.runcmd("user", "key-trust", "delete",
                                       "-H", HOST, CREDS,
                                       'alice', '--fingerprint=whatever',
                                       '--dry-run')
        self.assertCmdSuccess(result, out, err)
        self.assertIn('NO key credential links are deleted\n', out)

        self.assertIn(f'KEEP {links[0]} (fingerprint {links[0].fingerprint()})',
                      out)
        self.assertIn(f'KEEP {links[1]} (fingerprint {links[1].fingerprint()})',
                      out)
        self.assertIn('alice would now have 2 key credential links\n', out)

        result, out, err = self.runcmd("user", "key-trust", "delete",
                                       "-H", HOST, CREDS,
                                       'alice',
                                       '--fingerprint',
                                       fingerprints[1],
                                       '--dry-run')
        self.assertCmdSuccess(result, out, err)
        self.assertIn(f'DELETE {links[1]} (fingerprint {links[1].fingerprint()})',
                      out)
        self.assertIn(f'KEEP {links[0]} (fingerprint {links[0].fingerprint()})',
                      out)
        self.assertIn('alice would now have 1 key credential link\n', out)

        # this time deleting for real
        result, out, err = self.runcmd("user", "key-trust", "delete",
                                       "-H", HOST, CREDS,
                                       'alice', '--all')
        self.assertCmdSuccess(result, out, err)
        links = self.get_links('alice')
        self.assertEqual(links, [])

        result, out, err = self.runcmd("user", "key-trust", "view",
                                       "-H", HOST, CREDS,
                                       'alice')
        self.assertCmdSuccess(result, out, err)
        self.assertIn('alice has 0 key credential links\n', out)

    def test_add_duplicate_keys(self):
        """You should not be able to add the same link twice."""

        self.addCleanup(self.runcmd, "user", "key-trust", "delete",
                        "-H", HOST, CREDS,
                        'alice', '--all')

        result, out, err = self.runcmd("user", "key-trust", "add",
                                       "-H", HOST, CREDS,
                                       'alice', DUPLICATE_KEYS[0])
        self.assertCmdSuccess(result, out, err)

        # This source file is different, but contains the same public
        # key. samba-tool should notice this and fail *before* it
        # fails in the dsdb layer with ERR_ATTRIBUTE_OR_VALUE_EXISTS
        result, out, err = self.runcmd("user", "key-trust", "add",
                                       "-H", HOST, CREDS,
                                       'alice', DUPLICATE_KEYS[1])
        self.assertCmdFail(result)
        self.assertNotIn('ATTRIBUTE_OR_VALUE_EXISTS', err)

        # adding the first file again should also fail.
        result, out, err = self.runcmd("user", "key-trust", "add",
                                       "-H", HOST, CREDS,
                                       'alice', DUPLICATE_KEYS[0])
        self.assertCmdFail(result)

        # adding to a different DN is OK
        base_dn = self.samdb.domain_dn()
        result, out, err = self.runcmd("user", "key-trust", "add",
                                       "-H", HOST, CREDS,
                                       "--link-target", base_dn,
                                       'alice', DUPLICATE_KEYS[1])
        self.assertCmdSuccess(result, out, err)

        self.assertEqual(len(self.get_links('alice')), 2)

    def test_add_wrong_size_keys(self):
        """You should not be able to add the same link twice."""

        self.addCleanup(self.runcmd, "user", "key-trust", "delete",
                        "-H", HOST, CREDS,
                        'joe', '--all')

        for fn in WRONG_SIZE_CERTS:
            result, out, err = self.runcmd("user", "key-trust", "add",
                                           "-H", HOST, CREDS,
                                           'joe', fn)
            self.assertCmdFail(result)
            self.assertIn('ERROR: 2048 bit RSA key expected, not', err)

        self.assertEqual(self.get_links('joe'), [])

        for fn in WRONG_SIZE_CERTS:
            # it will work with --force
            result, out, err = self.runcmd("user", "key-trust", "add",
                                           "-H", HOST, CREDS,
                                           '--force',
                                           'joe', fn)

            self.assertCmdSuccess(result, out, err)

        self.assertEqual(len(self.get_links('joe')), 2)

    def test_add_non_rsa_keys(self):
        """You should not be able to add the same link twice."""

        self.addCleanup(self.runcmd, "user", "key-trust", "delete",
                        "-H", HOST, CREDS,
                        'joe', '--all')

        for fn in NON_RSA_CERTS:
            result, out, err = self.runcmd("user", "key-trust", "add",
                                           "-H", HOST, CREDS,
                                           'joe', fn)
            self.assertCmdFail(result)
            self.assertIn('only RSA Public Keys are supported', err)

        self.assertEqual(self.get_links('joe'), [])

        for fn in NON_RSA_CERTS:
            # it will NOT work with --force
            result, out, err = self.runcmd("user", "key-trust", "add",
                                           "-H", HOST, CREDS,
                                           '--force',
                                           'joe', fn)

            self.assertCmdFail(result)
            self.assertIn('only RSA Public Keys are supported', err)

        self.assertEqual(self.get_links('joe'), [])

    def test_add_good_cert_bad_dn(self):
        """Fails differently with --force"""
        links = self.get_links('joe')
        n = len(links)
        target = f"CN=an RDN that is not there,{self.samdb.domain_dn()}"
        result, out, err = self.runcmd("user", "key-trust", "add",
                                       "-H", HOST, CREDS,
                                       '--link-target', target,
                                       'joe', GOOD_CERTS[0])
        self.assertCmdFail(result)
        self.assertIn(f"ERROR: Link target '{target}' does not exist", err)
        self.assertEqual(len(links), 0)

        result, out, err = self.runcmd("user", "key-trust", "add",
                                       "-H", HOST, CREDS,
                                       '--link-target', target,
                                       '--force',
                                       'joe', GOOD_CERTS[1])
        self.assertCmdFail(result)
        self.assertIn("ERROR(ldb): uncaught exception", err)
        self.assertIn("LDAP_CONSTRAINT_VIOLATION", err)
        self.assertEqual(len(links), 0)

    def test_add_good_cert_bad_encoding(self):
        """If we use --encoding=pem with a DER file or vice versa, it
        should fail."""
        self.addCleanup(self.runcmd, "user", "key-trust", "delete",
                        "-H", HOST, CREDS,
                        'joe', '--all')

        result, out, err = self.runcmd("user", "key-trust", "add",
                                       "-H", HOST, CREDS,
                                       '--encoding', 'der',
                                       'joe', GOOD_CERTS[0])
        self.assertCmdFail(result)
        self.assertIn("ERROR: could not decode public key", err)
        self.assertEqual(self.get_links('joe'), [])

        # try to --force this one, to no avail
        result, out, err = self.runcmd("user", "key-trust", "add",
                                       "-H", HOST, CREDS,
                                       '--force',
                                       '--encoding', 'pem',
                                       'joe', GOOD_KEYS[0])
        self.assertCmdFail(result)
        self.assertIn("ERROR: could not decode public key", err)
        self.assertEqual(self.get_links('joe'), [])

        with self.assertRaises(SystemExit):
            # we can't catch result and output here because it fails
            # in optparse which prints straight to stderr.
            self.runcmd("user", "key-trust", "add",
                        "-H", HOST, CREDS,
                        '--encoding', 'pineapple',
                        'joe', GOOD_CERTS[1])
        self.assertCmdFail(result)
        self.assertEqual(self.get_links('joe'), [])

        # right encoding
        result, out, err = self.runcmd("user", "key-trust", "add",
                                       "-H", HOST, CREDS,
                                       '--encoding', 'pem',
                                       'joe', GOOD_CERTS[1])
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(len(self.get_links('joe')), 1)

        # 'auto' encoding
        result, out, err = self.runcmd("user", "key-trust", "add",
                                       "-H", HOST, CREDS,
                                       '--encoding', 'auto',
                                       'joe', GOOD_CERTS[0])
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(len(self.get_links('joe')), 2)
