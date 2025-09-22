#!/usr/bin/env python3
#
# Tests for pkinit with "strong certificate binding enforcement"
# See: https://support.microsoft.com/en-us/topic/
#      kb5014754-certificate-based-authentication-changes-on-windows-domain
#      -controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
#      KB5014754: Certificate-based authentication changes on Windows
#      domain controllers
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

from pyasn1.type import univ

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.x509.oid import NameOID

from samba.domain.models import User
import samba.tests
from samba.dcerpc import security
from samba.param import LoadParm
from samba.tests.krb5 import kcrypto
from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.raw_testcase import PkInit, RawKerberosTest
from samba.tests.krb5.rfc4120_constants import (
    DES_EDE3_CBC,
    KDC_ERR_CERTIFICATE_MISMATCH,
    KU_PA_ENC_TIMESTAMP,
    NT_PRINCIPAL,
    NT_SRV_INST,
    PADATA_AS_FRESHNESS,
    PADATA_ENC_TIMESTAMP,
    PADATA_PK_AS_REP_19,
    PADATA_PK_AS_REQ,
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1

SidType = RawKerberosTest.SidType

global_asn1_print = False
global_hexdump = False


class PkInitCertificateMappingTests(KDCBaseTest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

        #
        # get_loadparm loads the client smb.conf
        # we need to load the server smb.conf to get the server
        # settings.

        server_conf = os.getenv("SERVERCONFFILE")
        lp = LoadParm(filename_for_non_global_lp=server_conf)

        compensation = lp.get("certificate backdating compensation")
        # Convert the compensation to seconds, and add 1 hour (3600 seconds)
        backdating = (compensation * 60) + 3600
        self.backdating = timedelta(0, backdating, 0)

        enforcement = lp.get("strong certificate binding enforcement")
        if enforcement is None:
            enforcement = "full"

        # Set the expected results based on the server configuration
        if enforcement == "full":
            # Full enforcement, only Strong bindings should succeed
            self.STRONG_EXPECTED_RESULT      = 0
            self.WEAK_EXPECTED_RESULT        = KDC_ERR_CERTIFICATE_MISMATCH
            self.WEAK_EXPECTED_RESULT_BEFORE = KDC_ERR_CERTIFICATE_MISMATCH
            self.NONE_EXPECTED_RESULT        = KDC_ERR_CERTIFICATE_MISMATCH
            self.NAME_FAIL_RESULT            = KDC_ERR_CERTIFICATE_MISMATCH
        elif enforcement == "compatibility":
            # Compatibility enforcement.
            # Strong bindings should succeed
            # Weak bindings should succeed if the certificate was created
            # after the user accounts creation minus the backdating compensation
            self.STRONG_EXPECTED_RESULT      = 0
            self.WEAK_EXPECTED_RESULT        = 0
            self.WEAK_EXPECTED_RESULT_BEFORE = KDC_ERR_CERTIFICATE_MISMATCH
            self.NONE_EXPECTED_RESULT        = KDC_ERR_CERTIFICATE_MISMATCH
            self.NAME_FAIL_RESULT            = KDC_ERR_CERTIFICATE_MISMATCH
        else:
            # Enforcement is none, no certificate binding checks performed
            # all tests should succeed
            self.STRONG_EXPECTED_RESULT      = 0
            self.WEAK_EXPECTED_RESULT        = 0
            self.WEAK_EXPECTED_RESULT_BEFORE = 0
            self.NONE_EXPECTED_RESULT        = 0
            self.NAME_FAIL_RESULT            = 0

    def test_no_mapping(self):
        """
        Test PKINIT logon with a user account, and no certificate mappings
        """

        client_creds = self._get_creds()
        target_creds = self.get_service_creds()
        ca_cert, ca_private_key = self.get_ca_cert_and_private_key()

        # Create a certificate for the client signed by the CA.
        certificate = self.create_certificate(
            client_creds, ca_cert, ca_private_key, None, []
        )

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate=certificate,
            expect_error=self.NONE_EXPECTED_RESULT,
        )

    def test_computer_account_no_mapping(self):
        """
        Test PKINIT logon with a computer account and no certificate mappings
        """

        client_creds = self._get_creds(self.AccountType.COMPUTER)
        target_creds = self.get_service_creds()
        ca_cert, ca_private_key = self.get_ca_cert_and_private_key()

        # Create a certificate for the client signed by the CA.
        certificate = self.create_certificate(
            client_creds, ca_cert, ca_private_key, None, []
        )

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate=certificate,
            expect_error=self.NONE_EXPECTED_RESULT,
        )

    def test_subject_name(self):
        """
        Test PKINIT logon with a user account
        and the weak mapping subject name
        certificate created after the start of the compensation window
        """

        client_creds = self._get_creds()
        target_creds = self.get_service_creds()
        ca_cert, ca_private_key = self.get_ca_cert_and_private_key()

        # Create a certificate for the client signed by the CA.
        certificate = self.create_certificate(
            client_creds, ca_cert, ca_private_key, None, []
        )

        identity = f"X509:<S>{self._rfc4514_string(certificate.subject)}"
        self._add_altSecurityIdentities(client_creds, identity)

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate=certificate,
            expect_error=self.WEAK_EXPECTED_RESULT,
        )

    def test_subject_name_before(self):
        """
        Test PKINIT logon with a user account
        and the weak mapping subject name
        certificate created before the start of the compensation window
        """

        client_creds = self._get_creds()
        target_creds = self.get_service_creds()
        ca_cert, ca_private_key = self.get_ca_cert_and_private_key()

        now = datetime.now()
        not_before = now - self.backdating
        # Create a certificate for the client signed by the CA.
        certificate = self.create_certificate(
            client_creds, ca_cert, ca_private_key, None, [], not_before
        )

        identity = f"X509:<S>{self._rfc4514_string(certificate.subject)}"
        self._add_altSecurityIdentities(client_creds, identity)

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate=certificate,
            expect_error=self.WEAK_EXPECTED_RESULT_BEFORE,
        )

    def test_subject_name_reversed(self):
        """
        Test PKINIT logon with a user account
        and the weak mapping subject name
        certificate created after the start of the compensation window
        however the subject name has been reversed.

        NOTE:This currently fails, as normalization/canonicalization of
             the subject and issuer name is not currently implemented
        """

        client_creds = self._get_creds()
        target_creds = self.get_service_creds()
        ca_cert, ca_private_key = self.get_ca_cert_and_private_key()

        # Create a certificate for the client signed by the CA.
        certificate = self.create_certificate(
            client_creds, ca_cert, ca_private_key, None, []
        )

        # Reverse the order of the subject name components
        components = self._rfc4514_string(certificate.subject).split(",")
        components.reverse()
        subject = ",".join(components)
        identity = f"X509:<S>{subject}"
        self._add_altSecurityIdentities(client_creds, identity)

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate=certificate,
            expect_error=self.NAME_FAIL_RESULT,
        )

    def test_issuer_subject(self):
        """
        Test PKINIT logon with a user account
        and the weak mapping issuer and subject name
        certificate created after the start of the compensation window
        """

        client_creds = self._get_creds()
        target_creds = self.get_service_creds()
        ca_cert, ca_private_key = self.get_ca_cert_and_private_key()

        # Create a certificate for the client signed by the CA.
        certificate = self.create_certificate(
            client_creds, ca_cert, ca_private_key, None, []
        )

        identity = (
            "X509:"
            f"<I>{self._rfc4514_string(certificate.issuer)}"
            f"<S>{self._rfc4514_string(certificate.subject)}"
        )
        self._add_altSecurityIdentities(client_creds, identity)

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate=certificate,
            expect_error=self.WEAK_EXPECTED_RESULT,
        )

    def test_issuer_subject_before(self):
        """
        Test PKINIT logon with a user account
        and the weak mapping issuer and subject name
        certificate created before the start of the compensation window
        """

        client_creds = self._get_creds()
        target_creds = self.get_service_creds()
        ca_cert, ca_private_key = self.get_ca_cert_and_private_key()

        now = datetime.now()
        not_before = now - self.backdating
        # Create a certificate for the client signed by the CA.
        certificate = self.create_certificate(
            client_creds, ca_cert, ca_private_key, None, [], not_before
        )

        identity = (
            "X509:"
            f"<I>{self._rfc4514_string(certificate.issuer)}"
            f"<S>{self._rfc4514_string(certificate.subject)}"
        )
        self._add_altSecurityIdentities(client_creds, identity)

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate=certificate,
            expect_error=self.WEAK_EXPECTED_RESULT_BEFORE,
        )

    def test_rfc822(self):
        """
        Test PKINIT logon with a user account
        and the weak mapping rfc822 (email address)
        certificate created after the start of the compensation window
        """

        client_creds = self._get_creds()
        target_creds = self.get_service_creds()
        ca_cert, ca_private_key = self.get_ca_cert_and_private_key()

        # Create a certificate for the client signed by the CA.
        email = "testad@test.samba.org"
        san = x509.RFC822Name(email)
        certificate = self.create_certificate(
            client_creds, ca_cert, ca_private_key, None, [san]
        )

        identity = f"X509:<RFC822>{email}"
        self._add_altSecurityIdentities(client_creds, identity)

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate=certificate,
            expect_error=self.WEAK_EXPECTED_RESULT,
        )

    def test_rfc822_before(self):
        """
        Test PKINIT logon with a user account
        and the weak mapping rfc822 (email address)
        certificate created before the start of the compensation window
        """

        client_creds = self._get_creds()
        target_creds = self.get_service_creds()
        ca_cert, ca_private_key = self.get_ca_cert_and_private_key()

        now = datetime.now()
        not_before = now - self.backdating
        # Create a certificate for the client signed by the CA.
        email = "testad@test.samba.org"
        san = x509.RFC822Name(email)
        certificate = self.create_certificate(
            client_creds, ca_cert, ca_private_key, None, [san], not_before
        )

        identity = f"X509:<RFC822>{email}"
        self._add_altSecurityIdentities(client_creds, identity)

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate=certificate,
            expect_error=self.WEAK_EXPECTED_RESULT_BEFORE,
        )

    def test_issuer_serial_number(self):
        """
        Test PKINIT logon with a user account
        and the strong mapping issuer and subject name
        """

        client_creds = self._get_creds()
        target_creds = self.get_service_creds()
        ca_cert, ca_private_key = self.get_ca_cert_and_private_key()

        # Create a certificate for the client signed by the CA.
        certificate = self.create_certificate(
            client_creds, ca_cert, ca_private_key, None, []
        )

        serial = hex(certificate.serial_number)[2:]
        if len(serial) % 2:
            # Add a leading 0 if needed
            serial = '0' + serial
        identity = f"X509:<I>{self._rfc4514_string(certificate.issuer)}<SR>{serial}"
        self._add_altSecurityIdentities(client_creds, identity)

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate=certificate,
            expect_error=self.STRONG_EXPECTED_RESULT,
        )

    def test_subject_key_identifier(self):
        """
        Test PKINIT logon with a user account
        and the strong mapping subject key identifier
        """

        client_creds = self._get_creds()
        target_creds = self.get_service_creds()
        ca_cert, ca_private_key = self.get_ca_cert_and_private_key()

        # Create a certificate for the client signed by the CA.
        certificate = self.create_certificate(
            client_creds, ca_cert, ca_private_key, None, []
        )

        ski = x509.SubjectKeyIdentifier.from_public_key(
            certificate.public_key())
        identity = f"X509:<SKI>{ski.digest.hex()}"
        self._add_altSecurityIdentities(client_creds, identity)

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate=certificate,
            expect_error=self.STRONG_EXPECTED_RESULT,
        )

    def test_public_key(self):
        """
        Test PKINIT logon with a user account
        and the strong mapping public key
        """

        client_creds = self._get_creds()
        target_creds = self.get_service_creds()
        ca_cert, ca_private_key = self.get_ca_cert_and_private_key()

        # Create a certificate for the client signed by the CA.
        certificate = self.create_certificate(
            client_creds, ca_cert, ca_private_key, None, []
        )

        hash = x509.SubjectKeyIdentifier.from_public_key(certificate.public_key())
        identity = f"X509:<SHA1-PUKEY>{hash.digest.hex()}"
        self._add_altSecurityIdentities(client_creds, identity)

        self._pkinit_req(
            client_creds,
            target_creds,
            certificate=certificate,
            expect_error=self.STRONG_EXPECTED_RESULT,
        )

    def _rfc4514_string(self, name):
        """
        Convert an X509 name to it's RFC 4514 form, however we need
        to fix the generated names to match heimdals expectations
        """
        ns = name.rfc4514_string()
        ns = ns.replace("1.2.840.113549.1.9.1", "emailAddress")
        ns = ns.replace("ST=", "S=")
        return ns

    def _add_altSecurityIdentities(self, creds, identity):
        """
        Update the altSecurityIdentities attribute of the account under test
        """
        user = User.find(self.get_samdb(), creds.get_username())
        self.assertIsNotNone(user)
        if user is not None:
            user.alt_security_identities = identity
            user.save(self.get_samdb())

    def _get_creds(
        self,
        account_type=KDCBaseTest.AccountType.USER,
        use_cache=False,
        smartcard_required=False,
        assigned_policy=None,
    ):
        """Return credentials with an account having a UPN for performing
        PK-INIT."""
        samdb = self.get_samdb()
        realm = samdb.domain_dns_name().upper()

        opts = {
            "upn": f"{{account}}.{realm}@{realm}",
            "smartcard_required": smartcard_required,
        }
        if assigned_policy is not None:
            opts["assigned_policy"] = str(assigned_policy.dn)
        return self.get_cached_creds(
            account_type=account_type, opts=opts, use_cache=use_cache
        )

    def _as_req(
        self,
        creds,
        target_creds,
        *,
        expect_error=0,
        expect_status=False,
        expected_status=None,
        expect_edata=False,
        etypes=None,
        freshness=None,
        send_enc_ts=False,
    ):
        if send_enc_ts:
            if creds.get_password() is None:
                # Try the NT hash if there isn't a password
                preauth_key = self.PasswordKey_from_creds(creds, kcrypto.Enctype.RC4)
            else:
                preauth_key = self.PasswordKey_from_creds(creds, kcrypto.Enctype.AES256)
        else:
            preauth_key = None

        if freshness is not None or send_enc_ts:

            def generate_padata_fn(_kdc_exchange_dict, _callback_dict, req_body):
                padata = []

                if freshness is not None:
                    freshness_padata = self.PA_DATA_create(
                        PADATA_AS_FRESHNESS, freshness
                    )
                    padata.append(freshness_padata)

                if send_enc_ts:
                    patime, pausec = self.get_KerberosTimeWithUsec()
                    enc_ts = self.PA_ENC_TS_ENC_create(patime, pausec)
                    enc_ts = self.der_encode(enc_ts, asn1Spec=krb5_asn1.PA_ENC_TS_ENC())

                    enc_ts = self.EncryptedData_create(
                        preauth_key, KU_PA_ENC_TIMESTAMP, enc_ts
                    )
                    enc_ts = self.der_encode(enc_ts, asn1Spec=krb5_asn1.EncryptedData())

                    enc_ts = self.PA_DATA_create(PADATA_ENC_TIMESTAMP, enc_ts)

                    padata.append(enc_ts)

                return padata, req_body
        else:
            generate_padata_fn = None

        user_name = creds.get_username()
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=user_name.split("/")
        )

        target_name = target_creds.get_username()
        target_realm = target_creds.get_realm()

        if target_name == "krbtgt":
            sname = self.PrincipalName_create(
                name_type=NT_SRV_INST, names=["krbtgt", target_realm]
            )
        else:
            sname = self.PrincipalName_create(
                name_type=NT_PRINCIPAL, names=["host", target_name[:-1]]
            )

        if expect_error:
            check_error_fn = self.generic_check_kdc_error
            check_rep_fn = None

            expected_sname = sname
        else:
            check_error_fn = None
            check_rep_fn = self.generic_check_kdc_rep

            if target_name == "krbtgt":
                expected_sname = sname
            else:
                expected_sname = self.PrincipalName_create(
                    name_type=NT_PRINCIPAL, names=[target_name]
                )

        kdc_options = "forwardable,renewable,canonicalize,renewable-ok"
        kdc_options = krb5_asn1.KDCOptions(kdc_options)

        ticket_decryption_key = self.TicketDecryptionKey_from_creds(target_creds)

        kdc_exchange_dict = self.as_exchange_dict(
            creds=creds,
            expected_crealm=creds.get_realm(),
            expected_cname=cname,
            expected_srealm=target_realm,
            expected_sname=expected_sname,
            expected_supported_etypes=target_creds.tgs_supported_enctypes,
            ticket_decryption_key=ticket_decryption_key,
            generate_padata_fn=generate_padata_fn,
            check_error_fn=check_error_fn,
            check_rep_fn=check_rep_fn,
            check_kdc_private_fn=self.generic_check_kdc_private,
            expected_error_mode=expect_error,
            expected_salt=creds.get_salt(),
            preauth_key=preauth_key,
            kdc_options=str(kdc_options),
            expect_edata=expect_edata,
            expect_status=expect_status,
            expected_status=expected_status,
        )

        till = self.get_KerberosTime(offset=36000)

        if etypes is None:
            etypes = (
                kcrypto.Enctype.AES256,
                kcrypto.Enctype.RC4,
            )

        rep = self._generic_kdc_exchange(
            kdc_exchange_dict,
            cname=cname,
            realm=target_realm,
            sname=sname,
            till_time=till,
            etypes=etypes,
        )
        if expect_error:
            self.check_error_rep(rep, expect_error)
        else:
            self.check_as_reply(rep)

        return kdc_exchange_dict

    def get_ca_cert_and_private_key(self):
        # The password with which to try to encrypt the certificate or private
        # key specified on the command line.
        ca_pass = samba.tests.env_get_var_value("CA_PASS", allow_missing=True)
        if ca_pass is not None:
            ca_pass = ca_pass.encode("utf-8")

        # The root certificate of the CA, with which we can issue new
        # certificates.
        ca_cert_path = samba.tests.env_get_var_value("CA_CERT")
        with open(ca_cert_path, mode="rb") as f:
            ca_cert_data = f.read()

            try:
                # If the certificate file is in the PKCS#12 format (such as is
                # found in a .pfx file) try to get the private key and the
                # certificate all in one go.
                ca_private_key, ca_cert, _additional_ca_certs = (
                    pkcs12.load_key_and_certificates(
                        ca_cert_data, ca_pass, default_backend()
                    )
                )
            except ValueError:
                # Fall back to loading a PEM-encoded certificate.
                ca_private_key = None
                ca_cert = x509.load_pem_x509_certificate(
                    ca_cert_data, default_backend()
                )

        # If we didn’t get the private key, do that now.
        if ca_private_key is None:
            ca_private_key_path = samba.tests.env_get_var_value("CA_PRIVATE_KEY")
            with open(ca_private_key_path, mode="rb") as f:
                ca_private_key = serialization.load_pem_private_key(
                    f.read(), password=ca_pass, backend=default_backend()
                )

        return ca_cert, ca_private_key

    def create_certificate(
        self,
        creds,
        ca_cert,
        ca_private_key,
        certificate_signature=None,
        san=[],
        notBefore=None,
    ):
        if certificate_signature is None:
            certificate_signature = hashes.SHA256

        user_name = creds.get_username()

        builder = x509.CertificateBuilder()

        # Add the subject name.
        cert_name = f"{user_name}@{creds.get_realm().lower()}"
        builder = builder.subject_name(
            x509.Name(
                [
                    # Note that the subject name is used in certificate mappings
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "SambaState"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SambaSelfTesting"),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Users"),
                    x509.NameAttribute(NameOID.COMMON_NAME, f"{cert_name}"),
                ]
            )
        )

        # The new certificate must be issued by the root CA.
        builder = builder.issuer_name(ca_cert.issuer)

        # Note that if the certificate predates the existence of the account
        # in AD, Authentication will fail unless there is a valid strong mapping
        # See https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16#ID0EFR
        one_day = timedelta(1, 0, 0)
        if notBefore is None:
            builder = builder.not_valid_before(datetime.today() - one_day)
        else:
            builder = builder.not_valid_before(notBefore)
        builder = builder.not_valid_after(datetime.today() + (one_day * 30))

        builder = builder.serial_number(x509.random_serial_number())

        public_key = creds.get_public_key()
        builder = builder.public_key(public_key)

        # Add the SubjectAlternativeName. Windows uses this to map the account
        # to the certificate.
        id_pkinit_ms_san = x509.ObjectIdentifier(str(krb5_asn1.id_pkinit_ms_san))
        encoded_upn = self.der_encode(creds.get_upn(), asn1Spec=krb5_asn1.MS_UPN_SAN())
        ms_upn_san = x509.OtherName(id_pkinit_ms_san, encoded_upn)
        alt_names = san
        alt_names.append(ms_upn_san)
        builder = builder.add_extension(
            x509.SubjectAlternativeName(alt_names),
            critical=False,
        )

        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

        # The key identifier is used to identify the certificate.
        subject_key_id = x509.SubjectKeyIdentifier.from_public_key(public_key)
        builder = builder.add_extension(
            subject_key_id,
            critical=True,
        )

        # Add the key usages for which this certificate is valid. Windows
        # doesn’t actually require this extension to be present.
        builder = builder.add_extension(
            # Heimdal requires that the certificate be valid for digital
            # signatures.
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # Windows doesn’t require this extension to be present either; but if
        # it is, Windows will not accept the certificate unless either client
        # authentication or smartcard logon is specified, returning
        # KDC_ERR_INCONSISTENT_KEY_PURPOSE otherwise.
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
            critical=False,
        )

        # If the certificate predates (as ours does) the existence of the
        # account that presents it Windows will refuse to accept it unless
        # there exists a strong mapping from one to the other. This strong
        # mapping will in this case take the form of a certificate extension
        # described in [MS-WCCE] 2.2.2.7.7.4 (szOID_NTDS_CA_SECURITY_EXT) and
        # containing the account’s SID.

        # Encode this structure manually until we are able to produce the same
        # ASN.1 encoding that Windows does.

        encoded_sid = creds.get_sid().encode("utf-8")

        # The OCTET STRING tag, followed by length and encoded SID…
        security_ext = bytes([0x04]) + self.asn1_length(encoded_sid) + (encoded_sid)

        # …enclosed in a construct tagged with the application-specific value
        # 0…
        security_ext = bytes([0xA0]) + self.asn1_length(security_ext) + (security_ext)

        # …preceded by the extension OID…
        encoded_oid = self.der_encode(
            krb5_asn1.szOID_NTDS_OBJECTSID, univ.ObjectIdentifier()
        )
        security_ext = encoded_oid + security_ext

        # …and another application-specific tag 0…
        # (This is the part about which I’m unsure. This length is not just of
        # the OID, but of the entire structure so far, as if there’s some
        # nesting going on.  So far I haven’t been able to replicate this with
        # pyasn1.)
        security_ext = bytes([0xA0]) + self.asn1_length(security_ext) + (security_ext)

        # …all enclosed in a structure with a SEQUENCE tag.
        security_ext = bytes([0x30]) + self.asn1_length(security_ext) + (security_ext)

        # Add the security extension to the certificate.
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(str(krb5_asn1.szOID_NTDS_CA_SECURITY_EXT)),
                security_ext,
            ),
            critical=False,
        )

        # Sign the certificate with the CA’s private key. Windows accepts both
        # SHA1 and SHA256 hashes.
        certificate = builder.sign(
            private_key=ca_private_key,
            algorithm=certificate_signature(),
            backend=default_backend(),
        )

        return certificate

    def _pkinit_req(
        self,
        creds,
        target_creds,
        *,
        certificate=None,
        expect_error=0,
        expect_edata=False,
        expected_status=None,
        using_pkinit=PkInit.PUBLIC_KEY,
        etypes=None,
        pk_nonce=None,
        supported_cms_types=None,
        signature_algorithm=None,
        certificate_signature=None,
        freshness_token=None,
        win2k_variant=False,
        expect_matching_nt_hash_in_pac=True,
        target_sname=None,
    ):
        self.assertIsNot(using_pkinit, PkInit.NOT_USED)

        if signature_algorithm is None:
            # This algorithm must be one of ‘sig_algs’ for it to be supported
            # by Heimdal.
            signature_algorithm = krb5_asn1.sha1WithRSAEncryption

        signature_algorithm_id = self.AlgorithmIdentifier_create(signature_algorithm)

        if certificate is None:
            ca_cert, ca_private_key = self.get_ca_cert_and_private_key()

            # Create a certificate for the client signed by the CA.
            certificate = self.create_certificate(
                creds, ca_cert, ca_private_key, certificate_signature
            )

        private_key = creds.get_private_key()

        if using_pkinit is PkInit.DIFFIE_HELLMAN:
            # This is the 2048-bit MODP Group from RFC 3526. Heimdal refers to
            # it as “rfc3526-MODP-group14”.
            p, g = (
                32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559,
                2,
            )

            numbers = dh.DHParameterNumbers(p, g)
            dh_params = numbers.parameters(default_backend())

            dh_private_key = dh_params.generate_private_key()

            preauth_key = dh_private_key
        else:
            preauth_key = private_key

        if pk_nonce is None:
            pk_nonce = self.get_Nonce()

        def generate_pk_padata(_kdc_exchange_dict, _callback_dict, req_body):
            if win2k_variant:
                digest = None
            else:
                checksum_blob = self.der_encode(
                    req_body, asn1Spec=krb5_asn1.KDC_REQ_BODY()
                )

                # Calculate the SHA1 checksum over the KDC-REQ-BODY. This checksum
                # is required to be present in the authenticator, and must be SHA1.
                digest = hashes.Hash(hashes.SHA1(), default_backend())
                digest.update(checksum_blob)
                digest = digest.finalize()

            ctime, cusec = self.get_KerberosTimeWithUsec()

            if win2k_variant:
                krbtgt_sname = self.get_krbtgt_sname()
                krbtgt_realm = self.get_krbtgt_creds().get_realm()
            else:
                krbtgt_sname = None
                krbtgt_realm = None

            # Create the authenticator, which shows that we had possession of
            # the private key at some point.
            authenticator_obj = self.PKAuthenticator_create(
                cusec,
                ctime,
                pk_nonce,
                pa_checksum=digest,
                freshness_token=freshness_token,
                kdc_name=krbtgt_sname,
                kdc_realm=krbtgt_realm,
                win2k_variant=win2k_variant,
            )

            if using_pkinit is PkInit.DIFFIE_HELLMAN:
                dh_public_key = dh_private_key.public_key()

                encoded_dh_public_key = dh_public_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                decoded_dh_public_key = self.der_decode(
                    encoded_dh_public_key, asn1Spec=krb5_asn1.SubjectPublicKeyInfo()
                )
                dh_public_key_bitstring = decoded_dh_public_key["subjectPublicKey"]

                # Encode the Diffie-Hellman parameters.
                params = dh_params.parameter_bytes(
                    serialization.Encoding.DER, serialization.ParameterFormat.PKCS3
                )

                pk_algorithm = self.AlgorithmIdentifier_create(
                    krb5_asn1.dhpublicnumber, parameters=params
                )

                # Create the structure containing information about the public
                # key of the certificate that we shall present.
                client_public_value = self.SubjectPublicKeyInfo_create(
                    pk_algorithm, dh_public_key_bitstring
                )
            else:
                client_public_value = None

            # An optional set of algorithms supported by the client in
            # decreasing order of preference. For whatever reason, if this
            # field is missing or empty, Windows will respond with a slightly
            # differently encoded ReplyKeyPack, wrapping it first in a
            # ContentInfo structure.
            nonlocal supported_cms_types
            if win2k_variant:
                self.assertIsNone(supported_cms_types)
            elif supported_cms_types is False:
                # Exclude this field.
                supported_cms_types = None
            elif supported_cms_types is None:
                supported_cms_types = [
                    self.AlgorithmIdentifier_create(
                        krb5_asn1.id_pkcs1_sha256WithRSAEncryption
                    ),
                ]

            # The client may include this field if it wishes to reuse DH keys
            # or allow the KDC to do so.
            client_dh_nonce = None

            auth_pack_obj = self.AuthPack_create(
                authenticator_obj,
                client_public_value=client_public_value,
                supported_cms_types=supported_cms_types,
                client_dh_nonce=client_dh_nonce,
                win2k_variant=win2k_variant,
            )

            asn1_spec = (
                krb5_asn1.AuthPack_Win2k if win2k_variant else krb5_asn1.AuthPack
            )
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

            pk_as_req = self.PK_AS_REQ_create(
                signed_auth_pack,
                # This contains a list of CAs,
                # trusted by the client, that can
                # be used to certify the KDC.
                trusted_certifiers=None,
                kdc_pk_id=None,
                win2k_variant=win2k_variant,
            )

            pa_type = PADATA_PK_AS_REP_19 if win2k_variant else PADATA_PK_AS_REQ
            padata = [self.PA_DATA_create(pa_type, pk_as_req)]

            return padata, req_body

        user_name = creds.get_username()
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=user_name.split("/")
        )

        target_name = target_creds.get_username()
        target_realm = target_creds.get_realm()

        expected_sname = target_sname
        if target_sname is None:
            target_name = target_creds.get_username()
            if target_name == "krbtgt":
                target_sname = self.PrincipalName_create(
                    name_type=NT_SRV_INST, names=["krbtgt", target_realm]
                )
                expected_sname = target_sname
            else:
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

        if freshness_token is None:
            expected_groups = None
            unexpected_groups = {
                (
                    security.SID_FRESH_PUBLIC_KEY_IDENTITY,
                    SidType.EXTRA_SID,
                    security.SE_GROUP_DEFAULT_FLAGS,
                )
            }
        else:
            expected_groups = {
                (
                    security.SID_FRESH_PUBLIC_KEY_IDENTITY,
                    SidType.EXTRA_SID,
                    security.SE_GROUP_DEFAULT_FLAGS,
                ),
                ...,
            }
            unexpected_groups = None

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
            using_pkinit=using_pkinit,
            pk_nonce=pk_nonce,
            expect_edata=expect_edata,
            expected_status=expected_status,
            expect_matching_nt_hash_in_pac=expect_matching_nt_hash_in_pac,
        )

        till = self.get_KerberosTime(offset=36000)

        if etypes is None:
            etypes = (
                kcrypto.Enctype.AES256,
                kcrypto.Enctype.RC4,
            )

            if using_pkinit is PkInit.PUBLIC_KEY:
                # DES-EDE3-CBC is required for public-key PK-INIT to work on
                # Windows.
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
