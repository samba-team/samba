# Generate a Certificate Signing Request for a certificate
#
# Copyright (C) Catalyst.Net Ltd 2025
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_pem_private_key,
)
from cryptography.x509.base import CertificateSigningRequest
from samba import asn1, ldb
from samba.samdb import SamDB

from samba.domain.models import User


ID_PKINIT_MS_SAN = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
szOID_NTDS_CA_SECURITY_EXT = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2")


# As the version of python3-cryptography used in CI is too old to include the
# method x509.Name.from_rfc4514_string(), we must implement it ourselves.
def x509_name_from_rfc4514_string(rfc4514_string: str) -> x509.Name:
    # Derived from https://datatracker.ietf.org/doc/html/rfc4514#page-7
    name_oid_map = {
        "CN": x509.NameOID.COMMON_NAME,
        "L": x509.NameOID.LOCALITY_NAME,
        "ST": x509.NameOID.STATE_OR_PROVINCE_NAME,
        "O": x509.NameOID.ORGANIZATION_NAME,
        "OU": x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
        "C": x509.NameOID.COUNTRY_NAME,
        "STREET": x509.NameOID.STREET_ADDRESS,
        "DC": x509.NameOID.DOMAIN_COMPONENT,
        "UID": x509.NameOID.USER_ID,
    }

    def name_to_name_oid(name: str) -> x509.ObjectIdentifier:
        try:
            return name_oid_map[name]
        except KeyError:
            raise ValueError(f"Unknown component ‘{name}’ in RFC4514 string")

    try:
        dn = ldb.Dn(ldb.Ldb(), rfc4514_string)
    except ValueError:
        raise ValueError("Unable to parse RFC4514 string as DN")

    return x509.Name([
        x509.RelativeDistinguishedName([
            x509.NameAttribute(
                name_to_name_oid(dn.get_component_name(i)), dn.get_component_value(i)
            )
        ])
        for i in reversed(range(len(dn)))
    ])


def get_private_key(
    data: bytes, encoding: Optional[str] = None, password: Optional[str] = None
) -> RSAPrivateKey:
    """decode a key in PEM or DER format.

    So far only RSA keys are supported.
    """
    encoded_password = None
    if password is not None:
        encoded_password = password.encode("utf-8")

    if encoding is None:
        if data[:11] == b"-----BEGIN ":
            encoding = "PEM"
        else:
            encoding = "DER"

    encoding = encoding.upper()

    # The cryptography module also supports ssh keys, PKCS1, and other formats,
    # as well as non-RSA keys. It might not be wise to tolerate all of this, but
    # we can do it by adding to key_fns here.
    if encoding == "PEM":
        key_fns = [load_pem_private_key]
    elif encoding == "DER":
        key_fns = [load_der_private_key]
    else:
        raise ValueError(
            f"Private key encoding '{encoding}' not supported (try 'PEM' or 'DER')"
        )

    key = None
    for fn in key_fns:
        try:
            key = fn(data, encoded_password)
            break
        except ValueError:
            continue
        except TypeError:
            if password is None:
                raise ValueError("No password supplied to decrypt private key")
            else:
                raise ValueError("Password supplied but private key isn’t encrypted")

    if key is None:
        raise ValueError("could not decode private key")

    if not isinstance(key, RSAPrivateKey):
        raise ValueError(f"Currently only RSA Private Keys are supported (not '{key}')")

    return key


def generate_csr(
    samdb: SamDB,
    user: User,
    subject_name: str,
    private_key_filename: str,
    *,
    private_key_encoding: Optional[str] = "auto",
    private_key_pass: Optional[str] = None,
) -> CertificateSigningRequest:
    if private_key_encoding == "auto":
        private_key_encoding = None

    certificate_signature = hashes.SHA256

    account_name = user.account_name
    if user.user_principal_name is not None:
        account_upn = user.user_principal_name
    else:
        realm = samdb.domain_dns_name()
        account_upn = f"{account_name}@{realm.lower()}"

    builder = x509.CertificateSigningRequestBuilder()
    # Add the subject name.
    builder = builder.subject_name(x509_name_from_rfc4514_string(subject_name))

    with open(private_key_filename, "rb") as private_key_file:
        private_key_bytes = private_key_file.read()

    private_key = get_private_key(
        private_key_bytes, encoding=private_key_encoding, password=private_key_pass
    )
    public_key = private_key.public_key()

    # Add the SubjectAlternativeName. Windows uses this to map the account
    # to the certificate.

    encoded_upn = account_upn.encode("utf-8")
    encoded_upn = bytes([0x0C]) + asn1.asn1_length(encoded_upn) + encoded_upn

    ms_upn_san = x509.OtherName(ID_PKINIT_MS_SAN, encoded_upn)
    alt_names = [ms_upn_san]
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
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
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

    encoded_sid = user.object_sid.encode("utf-8")

    # The OCTET STRING tag, followed by length and encoded SID…
    security_ext = bytes([0x04]) + asn1.asn1_length(encoded_sid) + (encoded_sid)

    # …enclosed in a construct tagged with the application-specific value
    # 0…
    security_ext = bytes([0xA0]) + asn1.asn1_length(security_ext) + (security_ext)

    # …preceded by the extension OID…

    encoded_oid = bytes.fromhex("060a2b060104018237190201")
    security_ext = encoded_oid + security_ext

    # …and another application-specific tag 0…
    # (This is the part about which I’m unsure. This length is not just of
    # the OID, but of the entire structure so far, as if there’s some
    # nesting going on.  So far I haven’t been able to replicate this with
    # pyasn1.)
    security_ext = bytes([0xA0]) + asn1.asn1_length(security_ext) + (security_ext)

    # …all enclosed in a structure with a SEQUENCE tag.
    security_ext = bytes([0x30]) + asn1.asn1_length(security_ext) + (security_ext)

    # Add the security extension to the certificate.
    builder = builder.add_extension(
        x509.UnrecognizedExtension(
            szOID_NTDS_CA_SECURITY_EXT,
            security_ext,
        ),
        critical=False,
    )

    # Sign the certificate with the user’s private key.
    return builder.sign(
        private_key=private_key,
        algorithm=certificate_signature(),
        backend=default_backend(),
    )
