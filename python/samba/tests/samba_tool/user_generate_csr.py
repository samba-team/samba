# Unix SMB/CIFS implementation.
#
# Tests for `samba-tool user generate-csr`
#
# Copyright (C) Catalyst.Net Ltd 2025
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
from typing import Optional

from samba.domain.models import Computer, User
from samba.tests.samba_tool.base import SambaToolCmdTest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


szOID_NTDS_CA_SECURITY_EXT = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2")


HOST = "ldap://{DC_SERVER}".format(**os.environ)
CREDS = "-U{DC_USERNAME}%{DC_PASSWORD}".format(**os.environ)


class SambaToolUserGenerateCsrTest(SambaToolCmdTest):
    cmd = "user"
    model = User
    user = "alice"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.samdb = cls.getSamDB("-H", HOST, CREDS)

    def test_create_private_key_pem(self):
        self._test_create_private_key(encoding=serialization.Encoding.PEM)

    def test_create_private_key_der(self):
        self._test_create_private_key(encoding=serialization.Encoding.DER)

    def test_create_private_key_password(self):
        self._test_create_private_key(password="pass1234")

    def _test_create_private_key(
        self,
        *,
        encoding: serialization.Encoding = serialization.Encoding.PEM,
        password: Optional[str] = None,
    ):
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        if password is not None:
            encryption_algorithm = serialization.BestAvailableEncryption(
                password.encode("utf-8")
            )
        else:
            encryption_algorithm = serialization.NoEncryption()

        private_key_bytes = private_key.private_bytes(
            encoding=encoding,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )

        user = self.model.find(self.samdb, self.user)
        account_name = user.account_name
        if user.user_principal_name is not None:
            account_upn = user.user_principal_name
        else:
            realm = self.samdb.domain_dns_name()
            account_upn = f"{account_name}@{realm.lower()}"

        subject_name = x509.Name([
            # Note that the subject name is used in certificate mappings
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "SambaState"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SambaSelfTesting"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Users"),
            x509.NameAttribute(NameOID.COMMON_NAME, account_upn),
        ])
        subject_name_str = subject_name.rfc4514_string()

        with self.mktemp() as private_key_filename, self.mktemp() as csr_filename:
            with open(private_key_filename, "wb") as private_key_file:
                _ = private_key_file.write(private_key_bytes)

            cmd = [
                self.cmd,
                "generate-csr",
                "-H",
                HOST,
                CREDS,
                self.user,
                subject_name_str,
                private_key_filename,
                csr_filename,
            ]
            if password is not None:
                cmd.append("--private-key-pass")
                cmd.append(password)

            result, out, err = self.runcmd(*cmd)
            self.assertCmdSuccess(result, out, err)

            with open(csr_filename, "rb") as csr_file:
                csr_bytes = csr_file.read()

            csr = x509.load_pem_x509_csr(csr_bytes)

            self.assertEqual(subject_name, csr.subject)

            try:
                sid_extension = csr.extensions.get_extension_for_oid(
                    szOID_NTDS_CA_SECURITY_EXT,
                )
            except x509.ExtensionNotFound:
                self.fail("expected to find SID extension")

            # We don’t check the whole ASN.1 structure is correct, just that it
            # contains the encoded SID.
            encoded_sid = user.object_sid.encode("utf-8")
            self.assertIn(encoded_sid, sid_extension.value.value)


class SambaToolComputerGenerateCsrTest(SambaToolUserGenerateCsrTest):
    cmd = "computer"
    model = Computer
    user = "ADDC"


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest

    unittest.main()
