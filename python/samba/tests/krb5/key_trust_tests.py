#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
#
# Tests for Key Trust authentication
#
# Based on pkinit_tests.py
#
# Copyright (C) Gary Lockyer <gary@catalyst.net.nz> 2025
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

import sys
import os

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID

from samba.dcerpc import security
from samba.domain.models import User
from samba.key_credential_link import create_key_credential_link
from samba.tests.krb5 import kcrypto
from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.raw_testcase import PkInit, RawKerberosTest
from samba.tests.krb5.rfc4120_constants import (
    DES_EDE3_CBC,
    KDC_ERR_CLIENT_NOT_TRUSTED,
    NT_PRINCIPAL,
    PADATA_PK_AS_REQ,
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1

SidType = RawKerberosTest.SidType

global_asn1_print = False
global_hexdump = False


class KeyTrustTests(KDCBaseTest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def test_key_trust_user(self):
        """
        Test key trust logon for a normal account
        """
        client_creds = self._get_creds()
        target_creds = self.get_service_creds()
        certificate = self._create_certificate(client_creds)
        public_key = certificate.public_bytes(Encoding.DER)
        self._add_key_cred_link(client_creds, public_key)

        self._pkinit_req(client_creds, target_creds, certificate)

    def test_key_trust_user_mismatched_keys(self):
        """
        Test key trust logon for a normal account, where the certificate
        public key does not match the msDS-KeyCredentialLink value
        """
        client_creds = self._get_creds()
        target_creds = self.get_service_creds()
        certificate = self._create_certificate(client_creds)

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )
        self._add_key_cred_link(client_creds, public_key)

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate,
            expect_error=KDC_ERR_CLIENT_NOT_TRUSTED,
        )

    def test_key_trust_user_no_keys(self):
        """
        Test key trust logon for a normal account,
        with no msDS-KeyCredentialLink
        """
        client_creds = self._get_creds()
        target_creds = self.get_service_creds()
        certificate = self._create_certificate(client_creds)

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate,
            expect_error=KDC_ERR_CLIENT_NOT_TRUSTED,
        )

    def test_key_trust_computer(self):
        """
        Test key trust logon with a computer account.
        """
        client_creds = self._get_creds(self.AccountType.COMPUTER)
        target_creds = self.get_service_creds()
        certificate = self._create_certificate(client_creds)
        public_key = certificate.public_bytes(Encoding.DER)
        self._add_key_cred_link(client_creds, public_key)

        self._pkinit_req(client_creds, target_creds, certificate)

    def test_key_trust_computer_mismatched_keys(self):
        """
        Test key trust logon for a computer account, where the certificate
        public key does not match the msDS-KeyCredentialLink value
        """
        client_creds = self._get_creds(self.AccountType.COMPUTER)
        target_creds = self.get_service_creds()
        certificate = self._create_certificate(client_creds)

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )
        self._add_key_cred_link(client_creds, public_key)

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate,
            expect_error=KDC_ERR_CLIENT_NOT_TRUSTED,
        )

    def test_key_trust_computer_no_keys(self):
        """
        Test key trust logon with a computer account,
        with no msDS-KeyCredentialLink
        """
        client_creds = self._get_creds(self.AccountType.COMPUTER)
        target_creds = self.get_service_creds()
        certificate = self._create_certificate(client_creds)

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate = certificate,
            expect_error=KDC_ERR_CLIENT_NOT_TRUSTED,
        )

    def _get_creds(self, account_type=KDCBaseTest.AccountType.USER, use_cache=False):
        """
        Return credentials with an account having a UPN for performing
        PK-INIT.

        Modified from the version in python/samba/tests/krb5/pkinit_tests.py
        """
        samdb = self.get_samdb()
        realm = samdb.domain_dns_name().upper()

        opts = {"upn": f"{{account}}.{realm}@{realm}"}

        return self.get_cached_creds(
            account_type=account_type, opts=opts, use_cache=use_cache
        )

    def _add_key_cred_link(self, creds, public_key):
        """
        Update the msDS-KeyCredentialLink for the user specified in creds with
        the supplied public key
        """
        link = create_key_credential_link(self.get_samdb(), creds.get_dn(), public_key)

        user = User.find(self.get_samdb(), creds.get_username())
        self.assertIsNotNone(user)
        if user is not None:
            user.key_credential_link = link
            user.save(self.get_samdb())

    def _create_certificate(self, creds):
        """
        Create a new self signed certificate

        Modified from the version in python/samba/tests/krb5/pkinit_tests.py
        """

        certificate_signature = hashes.SHA256

        user_name = creds.get_username()

        builder = x509.CertificateBuilder()

        # Add the subject name.
        cert_name = f"{user_name}@{creds.get_realm().lower()}"
        subject_name = x509.Name(
            [
                # This name can be anything; it isn’t needed to authorize the
                # user. The SubjectAlternativeName is used for that instead.
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "SambaState"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SambaSelfTesting"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Users"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"{cert_name}"),
            ]
        )
        builder = builder.subject_name(subject_name)

        # The new certificate is self signed
        builder = builder.issuer_name(subject_name)

        one_day = timedelta(1, 0, 0)

        # Put the certificate start time in the past to avoid issues where the
        # KDC considers the certificate to be invalid due to clock skew. Note
        # that if the certificate predates the existence of the account in AD,
        # Windows will refuse authentication unless a strong mapping is
        # present (in the certificate, or in AD).
        # See https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16#ID0EFR
        builder = builder.not_valid_before(datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.today() + (one_day * 30))

        builder = builder.serial_number(x509.random_serial_number())

        public_key = creds.get_public_key()
        builder = builder.public_key(public_key)

        # Add the SubjectAlternativeName. Windows uses this to map the account
        # to the certificate.
        id_pkinit_ms_san = x509.ObjectIdentifier(str(krb5_asn1.id_pkinit_ms_san))
        encoded_upn = self.der_encode(creds.get_upn(), asn1Spec=krb5_asn1.MS_UPN_SAN())
        ms_upn_san = x509.OtherName(id_pkinit_ms_san, encoded_upn)
        builder = builder.add_extension(
            x509.SubjectAlternativeName([ms_upn_san]),
            critical=False,
        )

        # The key identifier is used to identify the certificate.
        subject_key_id = x509.SubjectKeyIdentifier.from_public_key(public_key)
        builder = builder.add_extension(
            subject_key_id,
            critical=True,
        )

        # Add the key usages for which this certificate is valid.
        builder = builder.add_extension(
            # Heimdal requires that the certificate be valid for digital
            # signatures.
            x509.KeyUsage(digital_signature=True,
                          content_commitment=False,
                          key_encipherment=False,
                          data_encipherment=False,
                          key_agreement=False,
                          key_cert_sign=False,
                          crl_sign=False,
                          encipher_only=False,
                          decipher_only=False),
                          critical=True,
        )

        certificate = builder.sign(
            private_key=creds.get_private_key(),
            algorithm=certificate_signature(),
            backend=default_backend(),
        )

        return certificate

    def _pkinit_req(
        self,
        creds,
        target_creds,
        certificate,
        expect_error=0,
    ):
        """
        Modified from the version in python/samba/tests/krb5/pkinit_tests.py
        """
        signature_algorithm = krb5_asn1.sha1WithRSAEncryption
        signature_algorithm_id = self.AlgorithmIdentifier_create(signature_algorithm)

        private_key = creds.get_private_key()

        preauth_key = private_key

        pk_nonce = self.get_Nonce()

        def generate_pk_padata(_kdc_exchange_dict, _callback_dict, req_body):
            # Suppress unused parameter warnings
            _ = (_kdc_exchange_dict, _callback_dict)

            checksum_blob = self.der_encode(req_body, asn1Spec=krb5_asn1.KDC_REQ_BODY())

            # Calculate the SHA1 checksum over the KDC-REQ-BODY. This checksum
            # is required to be present in the authenticator, and must be SHA1.
            digest = hashes.Hash(hashes.SHA1(), default_backend())
            digest.update(checksum_blob)
            digest = digest.finalize()

            ctime, cusec = self.get_KerberosTimeWithUsec()

            # Create the authenticator, which shows that we had possession of
            # the private key at some point.
            authenticator_obj = self.PKAuthenticator_create(
                cusec, ctime, pk_nonce, pa_checksum=digest
            )

            client_public_value = None

            # An optional set of algorithms supported by the client in
            # decreasing order of preference. For whatever reason, if this
            # field is missing or empty, Windows will respond with a slightly
            # differently encoded ReplyKeyPack, wrapping it first in a
            # ContentInfo structure.
            supported_cms_types = [
                self.AlgorithmIdentifier_create(
                    krb5_asn1.id_pkcs1_sha256WithRSAEncryption
                ),
            ]
            auth_pack_obj = self.AuthPack_create(
                authenticator_obj,
                client_public_value=client_public_value,
                supported_cms_types=supported_cms_types,
            )

            asn1_spec = krb5_asn1.AuthPack
            auth_pack = self.der_encode(auth_pack_obj, asn1Spec=asn1_spec())

            signature_hash = self.hash_from_algorithm(signature_algorithm)

            pad = padding.PKCS1v15()
            signed = private_key.sign(
                auth_pack, padding=pad, algorithm=signature_hash()
            )

            encap_content_info_obj = self.EncapsulatedContentInfo_create(
                krb5_asn1.id_pkinit_authData, auth_pack
            )

            subject_key_id = certificate.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER
            )
            signer_identifier = self.SignerIdentifier_create(
                subject_key_id=subject_key_id.value.digest
            )

            signer_info = self.SignerInfo_create(
                signer_identifier,
                signature_algorithm_id,
                signature_algorithm_id,
                signed,
                signed_attrs=[
                    # Note: these attributes are optional.
                    krb5_asn1.id_pkinit_authData,
                    krb5_asn1.id_messageDigest,
                ],
            )

            encoded_cert = certificate.public_bytes(serialization.Encoding.DER)
            decoded_cert = self.der_decode(
                encoded_cert, asn1Spec=krb5_asn1.CertificateChoices()
            )

            signed_auth_pack = self.SignedData_create(
                [signature_algorithm_id],
                encap_content_info_obj,
                signer_infos=[signer_info],
                certificates=[decoded_cert],
                crls=None,
            )

            signed_auth_pack = self.der_encode(
                signed_auth_pack, asn1Spec=krb5_asn1.SignedData()
            )

            pk_as_req = self.PK_AS_REQ_create(signed_auth_pack)

            pa_type = PADATA_PK_AS_REQ
            padata = [self.PA_DATA_create(pa_type, pk_as_req)]

            return padata, req_body

        user_name = creds.get_username()
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=user_name.split("/")
        )

        target_name = target_creds.get_username()
        target_realm = target_creds.get_realm()

        target_sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=["host", target_name[:-1]]
        )
        expected_sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[target_name]
        )

        if expect_error:
            check_error_fn = self.generic_check_kdc_error
            check_rep_fn = None

            expected_sname = target_sname
        else:
            check_error_fn = None
            check_rep_fn = self.generic_check_kdc_rep

        kdc_options = "forwardable,renewable,canonicalize,renewable-ok"
        kdc_options = krb5_asn1.KDCOptions(kdc_options)

        ticket_decryption_key = self.TicketDecryptionKey_from_creds(target_creds)

        expected_groups = None
        unexpected_groups = {
            (
                security.SID_FRESH_PUBLIC_KEY_IDENTITY,
                SidType.EXTRA_SID,
                security.SE_GROUP_DEFAULT_FLAGS,
            )
        }

        kdc_exchange_dict = self.as_exchange_dict(
            creds=creds,
            client_cert=certificate,
            expected_crealm=creds.get_realm(),
            expected_cname=cname,
            expected_srealm=target_realm,
            expected_sname=expected_sname,
            expected_supported_etypes=target_creds.tgs_supported_enctypes,
            expected_groups=expected_groups,
            unexpected_groups=unexpected_groups,
            ticket_decryption_key=ticket_decryption_key,
            generate_padata_fn=generate_pk_padata,
            check_error_fn=check_error_fn,
            check_rep_fn=check_rep_fn,
            check_kdc_private_fn=self.generic_check_kdc_private,
            expected_error_mode=expect_error,
            expected_salt=creds.get_salt(),
            preauth_key=preauth_key,
            kdc_options=str(kdc_options),
            using_pkinit=PkInit.PUBLIC_KEY,
            pk_nonce=pk_nonce,
            expect_edata=False,
            expect_matching_nt_hash_in_pac=True,
        )

        till = self.get_KerberosTime(offset=36000)

        etypes = (
            kcrypto.Enctype.AES256,
            kcrypto.Enctype.RC4,
        )
        # DES-EDE3-CBC is required for public-key PK-INIT to work on Windows.
        etypes += (DES_EDE3_CBC,)

        rep = self._generic_kdc_exchange(
            kdc_exchange_dict,
            cname=cname,
            realm=target_realm,
            sname=target_sname,
            till_time=till,
            etypes=etypes,
        )
        if expect_error:
            self.check_error_rep(rep, expect_error)
            return None

        self.check_as_reply(rep)
        return kdc_exchange_dict


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest

    unittest.main()
