# Unix SMB/CIFS implementation.
# Copyright (C) Isaac Boukris 2020
# Copyright (C) Stefan Metzmacher 2020
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
import socket
import struct
import time
import datetime
import random
import binascii
import itertools
import collections
import math

from enum import Enum
from pprint import pprint

from cryptography import x509
from cryptography.hazmat.primitives import asymmetric, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from pyasn1.codec.der.decoder import decode as pyasn1_der_decode
from pyasn1.codec.der.encoder import encode as pyasn1_der_encode
from pyasn1.codec.native.decoder import decode as pyasn1_native_decode
from pyasn1.codec.native.encoder import encode as pyasn1_native_encode

from pyasn1.codec.ber.encoder import BitStringEncoder
import pyasn1.type.univ

from pyasn1.error import PyAsn1Error

from samba import unix2nttime
from samba.credentials import Credentials
from samba.dcerpc import claims, krb5pac, netlogon, samr, security, krb5ccache
from samba.gensec import FEATURE_SEAL
from samba.ndr import ndr_pack, ndr_unpack
from samba.dcerpc.misc import (
    SEC_CHAN_WKSTA,
    SEC_CHAN_BDC,
    SEC_CHAN_RODC,
    SEC_CHAN_DOMAIN,
    SEC_CHAN_DNS_DOMAIN,
)
from samba.dsdb import (
    UF_SMARTCARD_REQUIRED
)
import samba.tests
from samba.tests import TestCase

import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
from samba.tests.krb5.rfc4120_constants import (
    AD_IF_RELEVANT,
    AD_WIN2K_PAC,
    FX_FAST_ARMOR_AP_REQUEST,
    KDC_ERR_CLIENT_REVOKED,
    KDC_ERR_GENERIC,
    KDC_ERR_KEY_EXPIRED,
    KDC_ERR_POLICY,
    KDC_ERR_PREAUTH_FAILED,
    KDC_ERR_SKEW,
    KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS,
    KERB_ERR_TYPE_EXTENDED,
    KRB_AP_REP,
    KRB_AP_REQ,
    KRB_AS_REP,
    KRB_AS_REQ,
    KRB_ERROR,
    KRB_PRIV,
    KRB_TGS_REP,
    KRB_TGS_REQ,
    KU_AP_REQ_AUTH,
    KU_AP_REQ_ENC_PART,
    KU_AS_FRESHNESS,
    KU_AS_REP_ENC_PART,
    KU_AS_REQ,
    KU_ENC_CHALLENGE_KDC,
    KU_FAST_ENC,
    KU_FAST_FINISHED,
    KU_FAST_REP,
    KU_FAST_REQ_CHKSUM,
    KU_KRB_PRIV,
    KU_NON_KERB_CKSUM_SALT,
    KU_NON_KERB_SALT,
    KU_PKINIT_AS_REQ,
    KU_TGS_REP_ENC_PART_SESSION,
    KU_TGS_REP_ENC_PART_SUB_KEY,
    KU_TGS_REQ_AUTH,
    KU_TGS_REQ_AUTH_CKSUM,
    KU_TGS_REQ_AUTH_DAT_SESSION,
    KU_TGS_REQ_AUTH_DAT_SUBKEY,
    KU_TICKET,
    NT_UNKNOWN,
    NT_PRINCIPAL,
    NT_SRV_INST,
    NT_WELLKNOWN,
    PADATA_AS_FRESHNESS,
    PADATA_ENCRYPTED_CHALLENGE,
    PADATA_ENC_TIMESTAMP,
    PADATA_ETYPE_INFO,
    PADATA_ETYPE_INFO2,
    PADATA_FOR_USER,
    PADATA_FX_COOKIE,
    PADATA_FX_ERROR,
    PADATA_FX_FAST,
    PADATA_GSS,
    PADATA_KDC_REQ,
    PADATA_PAC_OPTIONS,
    PADATA_PAC_REQUEST,
    PADATA_PKINIT_KX,
    PADATA_PK_AS_REP,
    PADATA_PK_AS_REP_19,
    PADATA_PK_AS_REQ,
    PADATA_PW_SALT,
    PADATA_REQ_ENC_PA_REP,
    PADATA_SUPPORTED_ETYPES,
)
import samba.tests.krb5.kcrypto as kcrypto


def BitStringEncoder_encodeValue32(
        self, value, asn1Spec, encodeFun, **options):
    #
    # BitStrings like KDCOptions or TicketFlags should at least
    # be 32-Bit on the wire
    #
    if asn1Spec is not None:
        # TODO: try to avoid ASN.1 schema instantiation
        value = asn1Spec.clone(value)

    valueLength = len(value)
    if valueLength % 8:
        alignedValue = value << (8 - valueLength % 8)
    else:
        alignedValue = value

    substrate = alignedValue.asOctets()
    length = len(substrate)
    # We need at least 32-Bit / 4-Bytes
    if length < 4:
        padding = 4 - length
    else:
        padding = 0
    ret = b'\x00' + substrate + (b'\x00' * padding)
    return ret, False, True


BitStringEncoder.encodeValue = BitStringEncoder_encodeValue32


def BitString_NamedValues_prettyPrint(self, scope=0):
    ret = "%s" % self.asBinary()
    bits = []
    highest_bit = 32
    for byte in self.asNumbers():
        for bit in [7, 6, 5, 4, 3, 2, 1, 0]:
            mask = 1 << bit
            if byte & mask:
                val = 1
            else:
                val = 0
            bits.append(val)
    if len(bits) < highest_bit:
        for bitPosition in range(len(bits), highest_bit):
            bits.append(0)
    indent = " " * scope
    delim = ": (\n%s " % indent
    for bitPosition in range(highest_bit):
        if bitPosition in self.prettyPrintNamedValues:
            name = self.prettyPrintNamedValues[bitPosition]
        elif bits[bitPosition] != 0:
            name = "unknown-bit-%u" % bitPosition
        else:
            continue
        ret += "%s%s:%u" % (delim, name, bits[bitPosition])
        delim = ",\n%s " % indent
    ret += "\n%s)" % indent
    return ret


krb5_asn1.TicketFlags.prettyPrintNamedValues =\
    krb5_asn1.TicketFlagsValues.namedValues
krb5_asn1.TicketFlags.namedValues =\
    krb5_asn1.TicketFlagsValues.namedValues
krb5_asn1.TicketFlags.prettyPrint =\
    BitString_NamedValues_prettyPrint
krb5_asn1.KDCOptions.prettyPrintNamedValues =\
    krb5_asn1.KDCOptionsValues.namedValues
krb5_asn1.KDCOptions.namedValues =\
    krb5_asn1.KDCOptionsValues.namedValues
krb5_asn1.KDCOptions.prettyPrint =\
    BitString_NamedValues_prettyPrint
krb5_asn1.APOptions.prettyPrintNamedValues =\
    krb5_asn1.APOptionsValues.namedValues
krb5_asn1.APOptions.namedValues =\
    krb5_asn1.APOptionsValues.namedValues
krb5_asn1.APOptions.prettyPrint =\
    BitString_NamedValues_prettyPrint
krb5_asn1.PACOptionFlags.prettyPrintNamedValues =\
    krb5_asn1.PACOptionFlagsValues.namedValues
krb5_asn1.PACOptionFlags.namedValues =\
    krb5_asn1.PACOptionFlagsValues.namedValues
krb5_asn1.PACOptionFlags.prettyPrint =\
    BitString_NamedValues_prettyPrint


def Integer_NamedValues_prettyPrint(self, scope=0):
    intval = int(self)
    if intval in self.prettyPrintNamedValues:
        name = self.prettyPrintNamedValues[intval]
    else:
        name = "<__unknown__>"
    ret = "%d (0x%x) %s" % (intval, intval, name)
    return ret


krb5_asn1.NameType.prettyPrintNamedValues =\
    krb5_asn1.NameTypeValues.namedValues
krb5_asn1.NameType.prettyPrint =\
    Integer_NamedValues_prettyPrint
krb5_asn1.AuthDataType.prettyPrintNamedValues =\
    krb5_asn1.AuthDataTypeValues.namedValues
krb5_asn1.AuthDataType.prettyPrint =\
    Integer_NamedValues_prettyPrint
krb5_asn1.PADataType.prettyPrintNamedValues =\
    krb5_asn1.PADataTypeValues.namedValues
krb5_asn1.PADataType.prettyPrint =\
    Integer_NamedValues_prettyPrint
krb5_asn1.EncryptionType.prettyPrintNamedValues =\
    krb5_asn1.EncryptionTypeValues.namedValues
krb5_asn1.EncryptionType.prettyPrint =\
    Integer_NamedValues_prettyPrint
krb5_asn1.ChecksumType.prettyPrintNamedValues =\
    krb5_asn1.ChecksumTypeValues.namedValues
krb5_asn1.ChecksumType.prettyPrint =\
    Integer_NamedValues_prettyPrint
krb5_asn1.KerbErrorDataType.prettyPrintNamedValues =\
    krb5_asn1.KerbErrorDataTypeValues.namedValues
krb5_asn1.KerbErrorDataType.prettyPrint =\
    Integer_NamedValues_prettyPrint


class Krb5EncryptionKey:
    __slots__ = [
        'ctype',
        'etype',
        'key',
        'kvno',
    ]

    def __init__(self, key, kvno):
        EncTypeChecksum = {
            kcrypto.Enctype.AES256: kcrypto.Cksumtype.SHA1_AES256,
            kcrypto.Enctype.AES128: kcrypto.Cksumtype.SHA1_AES128,
            kcrypto.Enctype.RC4: kcrypto.Cksumtype.HMAC_MD5,
        }
        self.key = key
        self.etype = key.enctype
        self.ctype = EncTypeChecksum[self.etype]
        self.kvno = kvno

    def __str__(self):
        return "etype=%d ctype=%d kvno=%d key=%s" % (
                self.etype, self.ctype, self.kvno, self.key)

    def encrypt(self, usage, plaintext):
        ciphertext = kcrypto.encrypt(self.key, usage, plaintext)
        return ciphertext

    def decrypt(self, usage, ciphertext):
        plaintext = kcrypto.decrypt(self.key, usage, ciphertext)
        return plaintext

    def make_zeroed_checksum(self, ctype=None):
        if ctype is None:
            ctype = self.ctype

        checksum_len = kcrypto.checksum_len(ctype)
        return bytes(checksum_len)

    def make_checksum(self, usage, plaintext, ctype=None):
        if ctype is None:
            ctype = self.ctype
        cksum = kcrypto.make_checksum(ctype, self.key, usage, plaintext)
        return cksum

    def verify_checksum(self, usage, plaintext, ctype, cksum):
        if self.ctype != ctype:
            raise AssertionError(f'key checksum type ({self.ctype}) != '
                                 f'checksum type ({ctype})')

        kcrypto.verify_checksum(ctype,
                                self.key,
                                usage,
                                plaintext,
                                cksum)

    def export_obj(self):
        EncryptionKey_obj = {
            'keytype': self.etype,
            'keyvalue': self.key.contents,
        }
        return EncryptionKey_obj


class RodcPacEncryptionKey(Krb5EncryptionKey):
    __slots__ = ['rodc_id']

    def __init__(self, key, kvno, rodc_id=None):
        super().__init__(key, kvno)

        if rodc_id is None:
            kvno = self.kvno
            if kvno is not None:
                kvno >>= 16
                kvno &= (1 << 16) - 1

            rodc_id = kvno or None

        if rodc_id is not None:
            self.rodc_id = rodc_id.to_bytes(2, byteorder='little')
        else:
            self.rodc_id = b''

    def make_rodc_zeroed_checksum(self, ctype=None):
        checksum = super().make_zeroed_checksum(ctype)
        return checksum + bytes(len(self.rodc_id))

    def make_rodc_checksum(self, usage, plaintext, ctype=None):
        checksum = super().make_checksum(usage, plaintext, ctype)
        return checksum + self.rodc_id

    def verify_rodc_checksum(self, usage, plaintext, ctype, cksum):
        if self.rodc_id:
            cksum, cksum_rodc_id = cksum[:-2], cksum[-2:]

            if self.rodc_id != cksum_rodc_id:
                raise AssertionError(f'{self.rodc_id.hex()} != '
                                     f'{cksum_rodc_id.hex()}')

        super().verify_checksum(usage,
                                plaintext,
                                ctype,
                                cksum)


class ZeroedChecksumKey(RodcPacEncryptionKey):
    def make_checksum(self, usage, plaintext, ctype=None):
        return self.make_zeroed_checksum(ctype)

    def make_rodc_checksum(self, usage, plaintext, ctype=None):
        return self.make_rodc_zeroed_checksum(ctype)


class WrongLengthChecksumKey(RodcPacEncryptionKey):
    __slots__ = ['_length']

    def __init__(self, key, kvno, length):
        super().__init__(key, kvno)

        self._length = length

    @classmethod
    def _adjust_to_length(cls, checksum, length):
        diff = length - len(checksum)
        if diff > 0:
            checksum += bytes(diff)
        elif diff < 0:
            checksum = checksum[:length]

        return checksum

    def make_zeroed_checksum(self, ctype=None):
        return bytes(self._length)

    def make_checksum(self, usage, plaintext, ctype=None):
        checksum = super().make_checksum(usage, plaintext, ctype)
        return self._adjust_to_length(checksum, self._length)

    def make_rodc_zeroed_checksum(self, ctype=None):
        return bytes(self._length)

    def make_rodc_checksum(self, usage, plaintext, ctype=None):
        checksum = super().make_rodc_checksum(usage, plaintext, ctype)
        return self._adjust_to_length(checksum, self._length)


class KerberosCredentials(Credentials):
    __slots__ = [
        '_private_key',
        'account_type',
        'ap_supported_enctypes',
        'as_supported_enctypes',
        'dn',
        'forced_keys',
        'forced_salt',
        'kvno',
        'sid',
        'guid',
        'rodc_computer_creds',
        'trust_incoming_creds',
        'trust_outgoing_creds',
        'trust_account_creds',
        'spn',
        'tgs_supported_enctypes',
        'upn',
        'user_account_control'
    ]

    non_etype_bits = (
        security.KERB_ENCTYPE_FAST_SUPPORTED) | (
        security.KERB_ENCTYPE_COMPOUND_IDENTITY_SUPPORTED) | (
        security.KERB_ENCTYPE_CLAIMS_SUPPORTED) | (
        security.KERB_ENCTYPE_RESOURCE_SID_COMPRESSION_DISABLED) | (
        security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96_SK)

    def __init__(self):
        super().__init__()
        all_enc_types = 0
        all_enc_types |= security.KERB_ENCTYPE_RC4_HMAC_MD5
        all_enc_types |= security.KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96
        all_enc_types |= security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96

        self.as_supported_enctypes = all_enc_types
        self.tgs_supported_enctypes = all_enc_types
        self.ap_supported_enctypes = all_enc_types

        self.kvno = None
        self.forced_keys = {}

        self.forced_salt = None

        self.dn = None
        self.upn = None
        self.spn = None
        self.sid = None
        self.guid = None
        self.account_type = None

        self.user_account_control = None

        self._private_key = None

        self.rodc_computer_creds = None

        self.trust_incoming_creds = None
        self.trust_outgoing_creds = None
        self.trust_account_creds = None

    def set_as_supported_enctypes(self, value):
        self.as_supported_enctypes = int(value)

    def set_tgs_supported_enctypes(self, value):
        self.tgs_supported_enctypes = int(value)

    def set_ap_supported_enctypes(self, value):
        self.ap_supported_enctypes = int(value)

    def set_user_account_control(self, value):
        self.user_account_control = int(value)

    etype_map = collections.OrderedDict([
        (kcrypto.Enctype.AES256,
            security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96),
        (kcrypto.Enctype.AES128,
            security.KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96),
        (kcrypto.Enctype.RC4,
            security.KERB_ENCTYPE_RC4_HMAC_MD5),
        (kcrypto.Enctype.DES_MD5,
            security.KERB_ENCTYPE_DES_CBC_MD5),
        (kcrypto.Enctype.DES_CRC,
            security.KERB_ENCTYPE_DES_CBC_CRC)
    ])

    @classmethod
    def etypes_to_bits(cls, etypes):
        bits = 0
        for etype in etypes:
            bit = cls.etype_map[etype]
            if bits & bit:
                raise ValueError(f'Got duplicate etype: {etype}')
            bits |= bit

        return bits

    @classmethod
    def bits_to_etypes(cls, bits):
        etypes = ()
        for etype, bit in cls.etype_map.items():
            if bit & bits:
                bits &= ~bit
                etypes += (etype,)

        bits &= ~cls.non_etype_bits
        if bits != 0:
            raise ValueError(f'Unsupported etype bits: {bits}')

        return etypes

    def get_as_krb5_etypes(self):
        return self.bits_to_etypes(self.as_supported_enctypes)

    def get_tgs_krb5_etypes(self):
        return self.bits_to_etypes(self.tgs_supported_enctypes)

    def get_ap_krb5_etypes(self):
        return self.bits_to_etypes(self.ap_supported_enctypes)

    def set_kvno(self, kvno):
        # Sign-extend from 32 bits.
        if kvno & 1 << 31:
            kvno |= -1 << 31
        self.kvno = kvno

    def get_kvno(self):
        return self.kvno

    def set_forced_key(self, etype, hexkey):
        etype = int(etype)
        contents = binascii.a2b_hex(hexkey)
        key = kcrypto.Key(etype, contents)
        self.forced_keys[etype] = RodcPacEncryptionKey(key, self.kvno)

        # Also set the NT hash of computer accounts for which we don’t know the
        # password.
        if etype == kcrypto.Enctype.RC4 and self.get_password() is None:
            nt_hash = samr.Password()
            nt_hash.hash = list(contents)

            self.set_nt_hash(nt_hash)

    def get_forced_key(self, etype):
        etype = int(etype)
        return self.forced_keys.get(etype)

    def clear_forced_keys(self):
        self.forced_keys.clear()

    def set_forced_salt(self, salt):
        self.forced_salt = bytes(salt)

    def get_forced_salt(self):
        return self.forced_salt

    def get_salt(self):
        if self.forced_salt is not None:
            return self.forced_salt

        upn = self.get_upn()
        if upn is not None:
            salt_name = upn.rsplit('@', 1)[0].replace('/', '')
        else:
            salt_name = self.get_username()

        secure_schannel_type = self.get_secure_channel_type()
        if secure_schannel_type in [SEC_CHAN_WKSTA,SEC_CHAN_BDC,SEC_CHAN_RODC]:
            salt_name = self.get_username().lower()
            if salt_name[-1] == '$':
                salt_name = salt_name[:-1]
            salt_string = '%shost%s.%s' % (
                self.get_realm().upper(),
                salt_name,
                self.get_realm().lower())
        else:
            salt_string = self.get_realm().upper() + salt_name

        return salt_string.encode('utf-8')

    def set_dn(self, dn):
        self.dn = dn

    def get_dn(self):
        return self.dn

    def set_spn(self, spn):
        self.spn = spn

    def get_spn(self):
        return self.spn

    def set_upn(self, upn):
        self.upn = upn

    def get_upn(self):
        return self.upn

    def set_sid(self, sid):
        self.sid = sid

    def get_sid(self):
        return self.sid

    def set_guid(self, guid):
        self.guid = guid

    def get_guid(self):
        return self.guid

    def get_rid(self):
        sid = self.get_sid()
        if sid is None:
            return None

        _, rid = sid.rsplit('-', 1)
        return int(rid)

    def set_type(self, account_type):
        self.account_type = account_type

    def get_type(self):
        return self.account_type

    def update_password(self, password):
        self.set_password(password)
        self.set_kvno(self.get_kvno() + 1)

    def get_private_key(self):
        if self._private_key is None:
            # Generate a new keypair.
            self._private_key = asymmetric.rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

        return self._private_key

    def get_public_key(self):
        return self.get_private_key().public_key()

    def set_rodc_computer_creds(self, computer_creds):
        self.rodc_computer_creds = computer_creds

    def get_rodc_computer_creds(self):
        return self.rodc_computer_creds

    def set_trust_incoming_creds(self, incoming_creds):
        self.trust_incoming_creds = incoming_creds

    def get_trust_incoming_creds(self):
        return self.trust_incoming_creds

    def set_trust_outgoing_creds(self, outgoing_creds):
        self.trust_outgoing_creds = outgoing_creds

    def get_trust_outgoing_creds(self):
        return self.trust_outgoing_creds

    def set_trust_account_creds(self, account_creds):
        self.trust_account_creds = account_creds

    def get_trust_account_creds(self):
        return self.trust_account_creds

class KerberosTicketCreds:
    __slots__ = [
        'cname',
        'crealm',
        'decryption_key',
        'encpart_private',
        'session_key',
        'sname',
        'srealm',
        'ticket_private',
        'ticket',
    ]

    def __init__(self, ticket, session_key,
                 crealm=None, cname=None,
                 srealm=None, sname=None,
                 decryption_key=None,
                 ticket_private=None,
                 encpart_private=None):
        self.ticket = ticket
        self.session_key = session_key
        self.crealm = crealm
        self.cname = cname
        self.srealm = srealm
        self.sname = sname
        self.decryption_key = decryption_key
        self.ticket_private = ticket_private
        self.encpart_private = encpart_private

    def set_sname(self, sname):
        self.ticket['sname'] = sname
        self.sname = sname


class PkInit(Enum):
    NOT_USED = object()
    PUBLIC_KEY = object()
    DIFFIE_HELLMAN = object()


class RawKerberosTest(TestCase):
    """A raw Kerberos Test case."""

    class KpasswdMode(Enum):
        SET = object()
        CHANGE = object()

    # The location of a SID within the PAC
    class SidType(Enum):
        BASE_SID = object()  # in info3.base.groups
        EXTRA_SID = object()  # in info3.sids
        RESOURCE_SID = object()  # in resource_groups
        PRIMARY_GID = object()  # the (sole) primary group

        def __repr__(self):
            return self.__str__()

    pac_checksum_types = {krb5pac.PAC_TYPE_SRV_CHECKSUM,
                          krb5pac.PAC_TYPE_KDC_CHECKSUM,
                          krb5pac.PAC_TYPE_TICKET_CHECKSUM,
                          krb5pac.PAC_TYPE_FULL_CHECKSUM}

    etypes_to_test = (
        {"value": -1111, "name": "dummy", },
        {"value": kcrypto.Enctype.AES256, "name": "aes256", },
        {"value": kcrypto.Enctype.AES128, "name": "aes128", },
        {"value": kcrypto.Enctype.RC4, "name": "rc4", },
    )

    expect_padata_outer = object()

    setup_etype_test_permutations_done = False

    @classmethod
    def setup_etype_test_permutations(cls):
        if cls.setup_etype_test_permutations_done:
            return

        res = []

        num_idxs = len(cls.etypes_to_test)
        permutations = []
        for num in range(1, num_idxs + 1):
            chunk = list(itertools.permutations(range(num_idxs), num))
            for e in chunk:
                el = list(e)
                permutations.append(el)

        for p in permutations:
            name = None
            etypes = ()
            for idx in p:
                n = cls.etypes_to_test[idx]["name"]
                if name is None:
                    name = n
                else:
                    name += "_%s" % n
                etypes += (cls.etypes_to_test[idx]["value"],)

            r = {"name": name, "etypes": etypes, }
            res.append(r)

        cls.etype_test_permutations = res
        cls.setup_etype_test_permutations_done = True

    @classmethod
    def etype_test_permutation_name_idx(cls):
        cls.setup_etype_test_permutations()
        res = []
        idx = 0
        for e in cls.etype_test_permutations:
            r = (e['name'], idx)
            idx += 1
            res.append(r)
        return res

    def etype_test_permutation_by_idx(self, idx):
        e = self.etype_test_permutations[idx]
        return (e['name'], e['etypes'])

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.host = samba.tests.env_get_var_value('SERVER')
        cls.dc_host = samba.tests.env_get_var_value('DC_SERVER')

        # A dictionary containing credentials that have already been
        # obtained.
        cls.creds_dict = {}

        kdc_fast_support = samba.tests.env_get_var_value('FAST_SUPPORT',
                                                         allow_missing=True)
        if kdc_fast_support is None:
            kdc_fast_support = '0'
        cls.kdc_fast_support = bool(int(kdc_fast_support))

        kdc_claims_support = samba.tests.env_get_var_value('CLAIMS_SUPPORT',
                                                           allow_missing=True)
        if kdc_claims_support is None:
            kdc_claims_support = '0'
        cls.kdc_claims_support = bool(int(kdc_claims_support))

        kdc_compound_id_support = samba.tests.env_get_var_value(
            'COMPOUND_ID_SUPPORT',
            allow_missing=True)
        if kdc_compound_id_support is None:
            kdc_compound_id_support = '0'
        cls.kdc_compound_id_support = bool(int(kdc_compound_id_support))

        tkt_sig_support = samba.tests.env_get_var_value('TKT_SIG_SUPPORT',
                                                        allow_missing=True)
        if tkt_sig_support is None:
            tkt_sig_support = '1'
        cls.tkt_sig_support = bool(int(tkt_sig_support))

        full_sig_support = samba.tests.env_get_var_value('FULL_SIG_SUPPORT',
                                                         allow_missing=True)
        if full_sig_support is None:
            full_sig_support = '1'
        cls.full_sig_support = bool(int(full_sig_support))

        expect_pac = samba.tests.env_get_var_value('EXPECT_PAC',
                                                   allow_missing=True)
        if expect_pac is None:
            expect_pac = '1'
        cls.expect_pac = bool(int(expect_pac))

        expect_extra_pac_buffers = samba.tests.env_get_var_value(
            'EXPECT_EXTRA_PAC_BUFFERS',
            allow_missing=True)
        if expect_extra_pac_buffers is None:
            expect_extra_pac_buffers = '1'
        cls.expect_extra_pac_buffers = bool(int(expect_extra_pac_buffers))

        cname_checking = samba.tests.env_get_var_value('CHECK_CNAME',
                                                       allow_missing=True)
        if cname_checking is None:
            cname_checking = '1'
        cls.cname_checking = bool(int(cname_checking))

        padata_checking = samba.tests.env_get_var_value('CHECK_PADATA',
                                                        allow_missing=True)
        if padata_checking is None:
            padata_checking = '1'
        cls.padata_checking = bool(int(padata_checking))

        kadmin_is_tgs = samba.tests.env_get_var_value('KADMIN_IS_TGS',
                                                      allow_missing=True)
        if kadmin_is_tgs is None:
            kadmin_is_tgs = '0'
        cls.kadmin_is_tgs = bool(int(kadmin_is_tgs))

        default_etypes = samba.tests.env_get_var_value('DEFAULT_ETYPES',
                                                       allow_missing=True)
        if default_etypes is not None:
            default_etypes = int(default_etypes)
        cls.default_etypes = default_etypes

        forced_rc4 = samba.tests.env_get_var_value('FORCED_RC4',
                                                   allow_missing=True)
        if forced_rc4 is None:
            forced_rc4 = '0'
        cls.forced_rc4 = bool(int(forced_rc4))

        expect_nt_hash = samba.tests.env_get_var_value('EXPECT_NT_HASH',
                                                       allow_missing=True)
        if expect_nt_hash is None:
            expect_nt_hash = '1'
        cls.expect_nt_hash = bool(int(expect_nt_hash))

        expect_nt_status = samba.tests.env_get_var_value('EXPECT_NT_STATUS',
                                                         allow_missing=True)
        if expect_nt_status is None:
            expect_nt_status = '1'
        cls.expect_nt_status = bool(int(expect_nt_status))

        crash_windows = samba.tests.env_get_var_value('CRASH_WINDOWS',
                                                      allow_missing=True)
        if crash_windows is None:
            crash_windows = '1'
        cls.crash_windows = bool(int(crash_windows))

        export_keytab_file = samba.tests.env_get_var_value('EXPORT_KEYTAB_FILE',
                                                           allow_missing=True)
        cls.export_keytab_file = export_keytab_file
        cls.keytab_entries = []
        export_keytab_append = samba.tests.env_get_var_value('EXPORT_KEYTAB_APPEND',
                                                           allow_missing=True)
        if export_keytab_append is None:
            export_keytab_append = '0'
        cls.export_keytab_append = bool(int(export_keytab_append))
        export_existing_creds = samba.tests.env_get_var_value('EXPORT_EXISTING_CREDS_TO_KEYTAB',
                                                              allow_missing=True)
        if export_existing_creds is None:
            export_existing_creds = '0'
        cls.export_existing_creds = bool(int(export_existing_creds))
        export_given_creds = samba.tests.env_get_var_value('EXPORT_GIVEN_CREDS_TO_KEYTAB',
                                                           allow_missing=True)
        if export_given_creds is None:
            export_given_creds = '0'
        cls.export_given_creds = bool(int(export_given_creds))

    @classmethod
    def tearDownClass(cls):
        cls.export_keytab()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.do_asn1_print = False
        self.do_hexdump = False

        cls = type(self)
        if cls.export_keytab_file and \
           not cls.export_keytab_append and \
           os.path.exists(cls.export_keytab_file):
            self.fail("export_keytab_file[%s] already exists" % cls.export_keytab_file)

        strict_checking = samba.tests.env_get_var_value('STRICT_CHECKING',
                                                        allow_missing=True)
        if strict_checking is None:
            strict_checking = '1'
        self.strict_checking = bool(int(strict_checking))

        self.s = None

        self.unspecified_kvno = object()

    def tearDown(self):
        self._disconnect("tearDown")
        super().tearDown()

    def _disconnect(self, reason):
        if self.s is None:
            return
        self.s.close()
        self.s = None
        if self.do_hexdump:
            sys.stderr.write("disconnect[%s]\n" % reason)

    def _connect_tcp(self, host, port=None):
        if port is None:
            port = 88
        try:
            self.a = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                        socket.SOCK_STREAM, socket.SOL_TCP,
                                        0)
            self.s = socket.socket(self.a[0][0], self.a[0][1], self.a[0][2])
            self.s.settimeout(10)
            self.s.connect(self.a[0][4])
        except socket.error:
            self.s.close()
            raise

    def connect(self, host, port=None):
        self.assertNotConnected()
        self._connect_tcp(host, port)
        if self.do_hexdump:
            sys.stderr.write("connected[%s]\n" % host)

    def env_get_var(self, varname, prefix,
                    fallback_default=True,
                    allow_missing=False):
        val = None
        if prefix is not None:
            allow_missing_prefix = allow_missing or fallback_default
            val = samba.tests.env_get_var_value(
                '%s_%s' % (prefix, varname),
                allow_missing=allow_missing_prefix)
        else:
            fallback_default = True
        if val is None and fallback_default:
            val = samba.tests.env_get_var_value(varname,
                                                allow_missing=allow_missing)
        return val

    def remember_keytab_entry(self, princ, realm, enctype, key, kvno=None):
        cls = type(self)
        if cls.export_keytab_file is None:
            return

        if kvno is None:
            kvno = 0

        keyb = krb5ccache.KEYTAB_KEYBLOCK()
        keyb.data = list(key)
        keyb.length = len(key)

        comps = princ.split('/')
        keyp = krb5ccache.KEYTAB_PRINCIPAL()
        keyp.realm = realm
        keyp.component_count = len(comps)
        keyp.components = comps
        keyp.name_type = NT_UNKNOWN

        keye = krb5ccache.KEYTAB_ENTRY()
        keye.principal = keyp
        keye.timestamp = 0
        # key_version is only 1 byte
        # full_key_version below is the full 32-bit value
        keye.key_version = kvno & 0xff
        keye.enctype = enctype
        keye.key = keyb
        keye.full_key_version = kvno

        cls.keytab_entries.append(keye)

    def remember_creds_for_keytab_export(self, creds):
        princ = creds.get_username()
        realm = creds.get_realm()
        kvno = creds.get_kvno()

        sec_chan = creds.get_secure_channel_type()
        if sec_chan in [SEC_CHAN_DOMAIN, SEC_CHAN_DNS_DOMAIN]:
            incoming_creds = creds.get_trust_incoming_creds()
            outgoing_creds = creds.get_trust_outgoing_creds()
            if incoming_creds and outgoing_creds:
                # creds is the account_creds
                pass
            elif incoming_creds:
                # creds is the outgoing_creds
                princ = "krbtgt/%s" % incoming_creds.get_realm()
            elif outgoing_creds:
                # creds is the incoming_creds
                princ = "krbtgt/%s" % outgoing_creds.get_realm()

        need_rc4 = False
        need_aes256_sha1 = False
        if creds.get_password() is not None:
            need_aes256_sha1 = True
            need_rc4 = True
        elif creds.get_nt_hash() is not None:
            need_rc4 = True
        etypes = creds.get_tgs_krb5_etypes()
        for etype in etypes:
            if etype == kcrypto.Enctype.AES256:
                need_aes256_sha1 = False
            if etype == kcrypto.Enctype.RC4:
                need_rc4 = False
            try:
                key = self.TicketDecryptionKey_from_creds(creds, etype=etype)
            except ValueError:
                pass
            except AssertionError:
                pass
            else:
                key = key.export_obj()['keyvalue']
                self.remember_keytab_entry(princ, realm, etype, key, kvno=kvno)

        if need_aes256_sha1:
            etype = kcrypto.Enctype.AES256
            try:
                key = self.TicketDecryptionKey_from_creds(creds, etype=etype)
            except ValueError:
                pass
            except AssertionError:
                pass
            else:
                key = key.export_obj()['keyvalue']
                self.remember_keytab_entry(princ, realm, etype, key, kvno=kvno)
        if need_rc4:
            etype = kcrypto.Enctype.RC4
            try:
                key = self.TicketDecryptionKey_from_creds(creds, etype=etype)
            except ValueError:
                pass
            except AssertionError:
                pass
            else:
                key = key.export_obj()['keyvalue']
                self.remember_keytab_entry(princ, realm, etype, key, kvno=kvno)

    @classmethod
    def export_keytab(cls):
        if cls.export_keytab_file is None:
            return

        last_mke = None

        if os.path.exists(cls.export_keytab_file):
            if not cls.export_keytab_append:
                return
            with open(cls.export_keytab_file, 'rb') as f:
                blob = f.read()
                ke = ndr_unpack(krb5ccache.KEYTAB, blob)
                tmp_mke = krb5ccache.MULTIPLE_KEYTAB_ENTRIES()
                tmp_mke.entry = ke.entry
                tmp_mke.further_entry = ke.further_entry
                last_mke = tmp_mke

        for keye in cls.keytab_entries:
            if last_mke:
                further_entry = ndr_pack(last_mke)
            else:
                further_entry = b''
            tmp_mke = krb5ccache.MULTIPLE_KEYTAB_ENTRIES()
            tmp_mke.entry = keye
            tmp_mke.further_entry = further_entry
            last_mke = tmp_mke

        if last_mke is None:
            return

        ke = krb5ccache.KEYTAB()
        ke.entry = last_mke.entry
        ke.further_entry = last_mke.further_entry
        blob = ndr_pack(ke)

        with open(cls.export_keytab_file, 'wb') as f:
            f.write(blob)

    def _get_krb5_creds_from_env(self, prefix,
                                 default_username=None,
                                 allow_missing_password=False,
                                 allow_missing_keys=True,
                                 require_strongest_key=False):
        c = KerberosCredentials()
        c.guess()

        domain = self.env_get_var('DOMAIN', prefix)
        realm = self.env_get_var('REALM', prefix)
        allow_missing_username = default_username is not None
        username = self.env_get_var('USERNAME', prefix,
                                    fallback_default=False,
                                    allow_missing=allow_missing_username)
        if username is None:
            username = default_username
        password = self.env_get_var('PASSWORD', prefix,
                                    fallback_default=False,
                                    allow_missing=allow_missing_password)
        c.set_domain(domain)
        c.set_realm(realm)
        c.set_username(username)
        if password is not None:
            c.set_password(password)
        as_supported_enctypes = self.env_get_var('AS_SUPPORTED_ENCTYPES',
                                                 prefix, allow_missing=True)
        if as_supported_enctypes is not None:
            c.set_as_supported_enctypes(as_supported_enctypes)
        tgs_supported_enctypes = self.env_get_var('TGS_SUPPORTED_ENCTYPES',
                                                  prefix, allow_missing=True)
        if tgs_supported_enctypes is not None:
            c.set_tgs_supported_enctypes(tgs_supported_enctypes)
        ap_supported_enctypes = self.env_get_var('AP_SUPPORTED_ENCTYPES',
                                                 prefix, allow_missing=True)
        if ap_supported_enctypes is not None:
            c.set_ap_supported_enctypes(ap_supported_enctypes)

        if require_strongest_key:
            kvno_allow_missing = False
            if password is None:
                aes256_allow_missing = False
            else:
                aes256_allow_missing = True
        else:
            kvno_allow_missing = allow_missing_keys
            aes256_allow_missing = allow_missing_keys
        kvno = self.env_get_var('KVNO', prefix,
                                fallback_default=False,
                                allow_missing=kvno_allow_missing)
        if kvno is not None:
            c.set_kvno(int(kvno))
        aes256_key = self.env_get_var('AES256_KEY_HEX', prefix,
                                      fallback_default=False,
                                      allow_missing=aes256_allow_missing)
        if aes256_key is not None:
            c.set_forced_key(kcrypto.Enctype.AES256, aes256_key)
        aes128_key = self.env_get_var('AES128_KEY_HEX', prefix,
                                      fallback_default=False,
                                      allow_missing=True)
        if aes128_key is not None:
            c.set_forced_key(kcrypto.Enctype.AES128, aes128_key)
        rc4_key = self.env_get_var('RC4_KEY_HEX', prefix,
                                   fallback_default=False, allow_missing=True)
        if rc4_key is not None:
            c.set_forced_key(kcrypto.Enctype.RC4, rc4_key)

        if not allow_missing_keys:
            self.assertTrue(c.forced_keys,
                            'Please supply %s encryption keys '
                            'in environment' % prefix)

        if type(self).export_given_creds:
            self.remember_creds_for_keytab_export(c)

        return c

    def _get_krb5_creds(self,
                        prefix,
                        default_username=None,
                        allow_missing_password=False,
                        allow_missing_keys=True,
                        require_strongest_key=False,
                        fallback_creds_fn=None):
        if prefix in self.creds_dict:
            return self.creds_dict[prefix]

        # We don't have the credentials already
        creds = None
        env_err = None
        try:
            # Try to obtain them from the environment
            creds = self._get_krb5_creds_from_env(
                prefix,
                default_username=default_username,
                allow_missing_password=allow_missing_password,
                allow_missing_keys=allow_missing_keys,
                require_strongest_key=require_strongest_key)
        except Exception as err:
            # An error occurred, so save it for later
            env_err = err
        else:
            self.assertIsNotNone(creds)
            # Save the obtained credentials
            self.creds_dict[prefix] = creds
            return creds

        if fallback_creds_fn is not None:
            try:
                # Try to use the fallback method
                creds = fallback_creds_fn()
            except Exception as err:
                print("ERROR FROM ENV: %r" % (env_err))
                print("FALLBACK-FN: %s" % (fallback_creds_fn))
                print("FALLBACK-ERROR: %r" % (err))
            else:
                self.assertIsNotNone(creds)
                # Save the obtained credentials
                self.creds_dict[prefix] = creds
                return creds

        # Both methods failed, so raise the exception from the
        # environment method
        raise env_err

    def get_user_creds(self,
                       allow_missing_password=False,
                       allow_missing_keys=True):
        c = self._get_krb5_creds(prefix=None,
                                 allow_missing_password=allow_missing_password,
                                 allow_missing_keys=allow_missing_keys)
        return c

    def get_service_creds(self,
                          allow_missing_password=False,
                          allow_missing_keys=True):
        c = self._get_krb5_creds(prefix='SERVICE',
                                 allow_missing_password=allow_missing_password,
                                 allow_missing_keys=allow_missing_keys)
        return c

    def get_client_creds(self,
                         allow_missing_password=False,
                         allow_missing_keys=True):
        c = self._get_krb5_creds(prefix='CLIENT',
                                 allow_missing_password=allow_missing_password,
                                 allow_missing_keys=allow_missing_keys)
        return c

    def get_server_creds(self,
                         allow_missing_password=False,
                         allow_missing_keys=True):
        c = self._get_krb5_creds(prefix='SERVER',
                                 allow_missing_password=allow_missing_password,
                                 allow_missing_keys=allow_missing_keys)
        return c

    def get_admin_creds(self,
                        allow_missing_password=False,
                        allow_missing_keys=True):
        c = self._get_krb5_creds(prefix='ADMIN',
                                 allow_missing_password=allow_missing_password,
                                 allow_missing_keys=allow_missing_keys)
        c.set_gensec_features(c.get_gensec_features() | FEATURE_SEAL)
        c.set_workstation('')
        return c

    def get_rodc_krbtgt_creds(self,
                              require_keys=True,
                              require_strongest_key=False):
        if require_strongest_key:
            self.assertTrue(require_keys)
        c = self._get_krb5_creds(prefix='RODC_KRBTGT',
                                 allow_missing_password=True,
                                 allow_missing_keys=not require_keys,
                                 require_strongest_key=require_strongest_key)
        return c

    def get_krbtgt_creds(self,
                         require_keys=True,
                         require_strongest_key=False):
        if require_strongest_key:
            self.assertTrue(require_keys)
        c = self._get_krb5_creds(prefix='KRBTGT',
                                 default_username='krbtgt',
                                 allow_missing_password=True,
                                 allow_missing_keys=not require_keys,
                                 require_strongest_key=require_strongest_key)
        return c

    def get_anon_creds(self):
        c = Credentials()
        c.set_anonymous()
        return c

    # Overridden by KDCBaseTest. At this level we don't know what actual
    # enctypes are supported, so the best we can do is go by whether NT hashes
    # are expected and whether the account is a workstation or not. This
    # matches the behaviour that tests expect by default.
    def get_default_enctypes(self, creds):
        self.assertIsNotNone(creds)

        default_enctypes = [
            kcrypto.Enctype.AES256,
            kcrypto.Enctype.AES128,
        ]

        if self.expect_nt_hash or creds.get_workstation():
            default_enctypes.append(kcrypto.Enctype.RC4)

        return default_enctypes

    def asn1_dump(self, name, obj, asn1_print=None):
        if asn1_print is None:
            asn1_print = self.do_asn1_print
        if asn1_print:
            if name is not None:
                sys.stderr.write("%s:\n%s" % (name, obj))
            else:
                sys.stderr.write("%s" % (obj))

    def hex_dump(self, name, blob, hexdump=None):
        if hexdump is None:
            hexdump = self.do_hexdump
        if hexdump:
            sys.stderr.write(
                "%s: %d\n%s" % (name, len(blob), self.hexdump(blob)))

    def der_decode(
            self,
            blob,
            asn1Spec=None,
            native_encode=True,
            asn1_print=None,
            hexdump=None):
        if asn1Spec is not None:
            class_name = type(asn1Spec).__name__.split(':')[0]
        else:
            class_name = "<None-asn1Spec>"
        self.hex_dump(class_name, blob, hexdump=hexdump)
        obj, _ = pyasn1_der_decode(blob, asn1Spec=asn1Spec)
        self.asn1_dump(None, obj, asn1_print=asn1_print)
        if native_encode:
            obj = pyasn1_native_encode(obj)
        return obj

    def der_encode(
            self,
            obj,
            asn1Spec=None,
            native_decode=True,
            asn1_print=None,
            hexdump=None):
        if native_decode:
            obj = pyasn1_native_decode(obj, asn1Spec=asn1Spec)
        class_name = type(obj).__name__.split(':')[0]
        if class_name is not None:
            self.asn1_dump(None, obj, asn1_print=asn1_print)
        blob = pyasn1_der_encode(obj)
        if class_name is not None:
            self.hex_dump(class_name, blob, hexdump=hexdump)
        return blob

    def send_pdu(self, req, asn1_print=None, hexdump=None):
        k5_pdu = self.der_encode(
            req, native_decode=False, asn1_print=asn1_print, hexdump=False)
        self.send_msg(k5_pdu, hexdump=hexdump)

    def send_msg(self, msg, hexdump=None):
        header = struct.pack('>I', len(msg))
        req_pdu = header
        req_pdu += msg
        self.hex_dump("send_msg", header, hexdump=hexdump)
        self.hex_dump("send_msg", msg, hexdump=hexdump)

        try:
            while True:
                sent = self.s.send(req_pdu, 0)
                if sent == len(req_pdu):
                    return
                req_pdu = req_pdu[sent:]
        except socket.error as e:
            self._disconnect("send_msg: %s" % e)
            raise

    def recv_raw(self, num_recv=0xffff, hexdump=None, timeout=None):
        rep_pdu = None
        try:
            if timeout is not None:
                self.s.settimeout(timeout)
            rep_pdu = self.s.recv(num_recv, 0)
            self.s.settimeout(10)
            if len(rep_pdu) == 0:
                self._disconnect("recv_raw: EOF")
                return None
            self.hex_dump("recv_raw", rep_pdu, hexdump=hexdump)
        except socket.timeout:
            self.s.settimeout(10)
            sys.stderr.write("recv_raw: TIMEOUT\n")
        except socket.error as e:
            self._disconnect("recv_raw: %s" % e)
            raise
        return rep_pdu

    def recv_pdu_raw(self, asn1_print=None, hexdump=None, timeout=None):
        raw_pdu = self.recv_raw(
            num_recv=4, hexdump=hexdump, timeout=timeout)
        if raw_pdu is None:
            return None
        header = struct.unpack(">I", raw_pdu[0:4])
        k5_len = header[0]
        if k5_len == 0:
            return ""
        missing = k5_len
        rep_pdu = b''
        while missing > 0:
            raw_pdu = self.recv_raw(
                num_recv=missing, hexdump=hexdump, timeout=timeout)
            self.assertGreaterEqual(len(raw_pdu), 1)
            rep_pdu += raw_pdu
            missing = k5_len - len(rep_pdu)
        return rep_pdu

    def recv_reply(self, asn1_print=None, hexdump=None, timeout=None):
        rep_pdu = self.recv_pdu_raw(asn1_print=asn1_print,
                                    hexdump=hexdump,
                                    timeout=timeout)
        if not rep_pdu:
            return None, rep_pdu
        k5_raw = self.der_decode(
            rep_pdu,
            asn1Spec=None,
            native_encode=False,
            asn1_print=False,
            hexdump=False)
        pvno = k5_raw['field-0']
        self.assertEqual(pvno, 5)
        msg_type = k5_raw['field-1']
        self.assertIn(msg_type, [KRB_AS_REP, KRB_TGS_REP, KRB_ERROR])
        if msg_type == KRB_AS_REP:
            asn1Spec = krb5_asn1.AS_REP()
        elif msg_type == KRB_TGS_REP:
            asn1Spec = krb5_asn1.TGS_REP()
        elif msg_type == KRB_ERROR:
            asn1Spec = krb5_asn1.KRB_ERROR()
        rep = self.der_decode(rep_pdu, asn1Spec=asn1Spec,
                              asn1_print=asn1_print, hexdump=False)
        return (rep, rep_pdu)

    def recv_pdu(self, asn1_print=None, hexdump=None, timeout=None):
        (rep, rep_pdu) = self.recv_reply(asn1_print=asn1_print,
                                         hexdump=hexdump,
                                         timeout=timeout)
        return rep

    def assertIsConnected(self):
        self.assertIsNotNone(self.s, msg="Not connected")

    def assertNotConnected(self):
        self.assertIsNone(self.s, msg="Is connected")

    def send_recv_transaction(
            self,
            req,
            asn1_print=None,
            hexdump=None,
            timeout=None,
            to_rodc=False):
        host = self.host if to_rodc else self.dc_host
        self.connect(host)
        try:
            self.send_pdu(req, asn1_print=asn1_print, hexdump=hexdump)
            rep = self.recv_pdu(
                asn1_print=asn1_print, hexdump=hexdump, timeout=timeout)
        except Exception:
            self._disconnect("transaction failed")
            raise
        self._disconnect("transaction done")
        return rep

    def getElementValue(self, obj, elem):
        return obj.get(elem)

    def assertElementMissing(self, obj, elem):
        v = self.getElementValue(obj, elem)
        self.assertIsNone(v)

    def assertElementPresent(self, obj, elem, expect_empty=False):
        v = self.getElementValue(obj, elem)
        self.assertIsNotNone(v)
        if self.strict_checking:
            if isinstance(v, collections.abc.Container):
                if expect_empty:
                    self.assertEqual(0, len(v))
                else:
                    self.assertNotEqual(0, len(v))

    def assertElementEqual(self, obj, elem, value):
        v = self.getElementValue(obj, elem)
        self.assertIsNotNone(v)
        self.assertEqual(v, value)

    def assertElementEqualUTF8(self, obj, elem, value):
        v = self.getElementValue(obj, elem)
        self.assertIsNotNone(v)
        self.assertEqual(v, bytes(value, 'utf8'))

    def assertPrincipalEqual(self, princ1, princ2):
        self.assertEqual(princ1['name-type'], princ2['name-type'])
        self.assertEqual(
            len(princ1['name-string']),
            len(princ2['name-string']),
            msg="princ1=%s != princ2=%s" % (princ1, princ2))
        for idx in range(len(princ1['name-string'])):
            self.assertEqual(
                princ1['name-string'][idx],
                princ2['name-string'][idx],
                msg="princ1=%s != princ2=%s" % (princ1, princ2))

    def assertElementEqualPrincipal(self, obj, elem, value):
        v = self.getElementValue(obj, elem)
        self.assertIsNotNone(v)
        v = pyasn1_native_decode(v, asn1Spec=krb5_asn1.PrincipalName())
        self.assertPrincipalEqual(v, value)

    def assertElementKVNO(self, obj, elem, value):
        v = self.getElementValue(obj, elem)
        if value == "autodetect":
            value = v
        if value is not None:
            self.assertIsNotNone(v)
            # The value on the wire should never be 0
            self.assertNotEqual(v, 0)
            # unspecified_kvno means we don't know the kvno,
            # but want to enforce its presence
            if value is not self.unspecified_kvno:
                value = int(value)
                self.assertNotEqual(value, 0)
                self.assertEqual(v, value)
        else:
            self.assertIsNone(v)

    def assertElementFlags(self, obj, elem, expected, unexpected):
        v = self.getElementValue(obj, elem)
        self.assertIsNotNone(v)
        if expected is not None:
            self.assertIsInstance(expected, krb5_asn1.TicketFlags)
            for i, flag in enumerate(expected):
                if flag == 1:
                    self.assertEqual('1', v[i],
                                     f"'{expected.namedValues[i]}' "
                                     f"expected in {v}")
        if unexpected is not None:
            self.assertIsInstance(unexpected, krb5_asn1.TicketFlags)
            for i, flag in enumerate(unexpected):
                if flag == 1:
                    self.assertEqual('0', v[i],
                                     f"'{unexpected.namedValues[i]}' "
                                     f"unexpected in {v}")

    def assertSequenceElementsEqual(self, expected, got, *,
                                    require_strict=None,
                                    unchecked=None,
                                    require_ordered=True):
        if self.strict_checking and require_ordered and not unchecked:
            self.assertEqual(expected, got)
        else:
            fail_msg = f'expected: {expected} got: {got}'

            ignored = set()
            if unchecked:
                ignored.update(unchecked)
            if require_strict and not self.strict_checking:
                ignored.update(require_strict)

            if ignored:
                fail_msg += f' (ignoring: {ignored})'
                expected = (x for x in expected if x not in ignored)
                got = (x for x in got if x not in ignored)

            self.assertCountEqual(expected, got, fail_msg)

    def assertLocalSamDB(self, samdb):
        if samdb.url.startswith('tdb://'):
            return
        if samdb.url.startswith('mdb://'):
            return

        self.fail(f'connection to {samdb.url} is not local!')

    def get_KerberosTimeWithUsec(self, epoch=None, offset=None):
        if epoch is None:
            epoch = time.time()
        if offset is not None:
            epoch = epoch + int(offset)
        dt = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
        return (dt.strftime("%Y%m%d%H%M%SZ"), dt.microsecond)

    def get_KerberosTime(self, epoch=None, offset=None):
        (s, _) = self.get_KerberosTimeWithUsec(epoch=epoch, offset=offset)
        return s

    def get_EpochFromKerberosTime(self, kerberos_time):
        if isinstance(kerberos_time, bytes):
            kerberos_time = kerberos_time.decode()

        epoch = datetime.datetime.strptime(kerberos_time,
                                           '%Y%m%d%H%M%SZ')
        epoch = epoch.replace(tzinfo=datetime.timezone.utc)
        epoch = int(epoch.timestamp())

        return epoch

    def get_Nonce(self):
        nonce_min = 0x7f000000
        nonce_max = 0x7fffffff
        v = random.randint(nonce_min, nonce_max)
        return v

    def get_pa_dict(self, pa_data):
        pa_dict = {}

        if pa_data is not None:
            for pa in pa_data:
                pa_type = pa['padata-type']
                if pa_type in pa_dict:
                    raise RuntimeError(f'Duplicate type {pa_type}')
                pa_dict[pa_type] = pa['padata-value']

        return pa_dict

    def SessionKey_create(self, etype, contents, kvno=None):
        key = kcrypto.Key(etype, contents)
        return RodcPacEncryptionKey(key, kvno)

    def PasswordKey_create(self, etype=None, pwd=None, salt=None, kvno=None,
                           params=None):
        self.assertIsNotNone(pwd)
        self.assertIsNotNone(salt)
        key = kcrypto.string_to_key(etype, pwd, salt, params=params)
        return RodcPacEncryptionKey(key, kvno)

    def PasswordKey_from_etype_info2(self, creds, etype_info2, kvno=None):
        e = etype_info2['etype']
        salt = etype_info2.get('salt')
        _params = etype_info2.get('s2kparams')
        return self.PasswordKey_from_etype(creds, e,
                                           kvno=kvno,
                                           salt=salt)

    def PasswordKey_from_creds(self, creds, etype):
        kvno = creds.get_kvno()
        salt = creds.get_salt()
        return self.PasswordKey_from_etype(creds, etype,
                                           kvno=kvno,
                                           salt=salt)

    def PasswordKey_from_etype(self, creds, etype, kvno=None, salt=None):
        if etype == kcrypto.Enctype.RC4:
            nthash = creds.get_nt_hash()
            return self.SessionKey_create(etype=etype, contents=nthash, kvno=kvno)

        password = creds.get_password().encode('utf-8')
        return self.PasswordKey_create(
            etype=etype, pwd=password, salt=salt, kvno=kvno)

    def TicketDecryptionKey_from_creds(self, creds, etype=None):

        if etype is None:
            etypes = creds.get_tgs_krb5_etypes()
            if etypes and etypes[0] not in (kcrypto.Enctype.DES_CRC,
                                            kcrypto.Enctype.DES_MD5):
                etype = etypes[0]
            else:
                etype = kcrypto.Enctype.RC4

        forced_key = creds.get_forced_key(etype)
        if forced_key is not None:
            return forced_key

        kvno = creds.get_kvno()

        fail_msg = ("%s has no fixed key for etype[%s] kvno[%s] "
                    "nor a password specified, " % (
                        creds.get_username(), etype, kvno))

        if etype == kcrypto.Enctype.RC4:
            nthash = creds.get_nt_hash()
            self.assertIsNotNone(nthash, msg=fail_msg)
            return self.SessionKey_create(etype=etype,
                                          contents=nthash,
                                          kvno=kvno)

        password = creds.get_password()
        self.assertIsNotNone(password, msg=fail_msg)
        salt = creds.get_salt()
        return self.PasswordKey_create(etype=etype,
                                       pwd=password,
                                       salt=salt,
                                       kvno=kvno)

    def RandomKey(self, etype):
        e = kcrypto._get_enctype_profile(etype)
        contents = samba.generate_random_bytes(e.keysize)
        return self.SessionKey_create(etype=etype, contents=contents)

    def EncryptionKey_import(self, EncryptionKey_obj):
        return self.SessionKey_create(EncryptionKey_obj['keytype'],
                                      EncryptionKey_obj['keyvalue'])

    def EncryptedData_create(self, key, usage, plaintext):
        # EncryptedData   ::= SEQUENCE {
        #         etype   [0] Int32 -- EncryptionType --,
        #         kvno    [1] Int32 OPTIONAL,
        #         cipher  [2] OCTET STRING -- ciphertext
        # }
        ciphertext = key.encrypt(usage, plaintext)
        EncryptedData_obj = {
            'etype': key.etype,
            'cipher': ciphertext
        }
        if key.kvno is not None:
            EncryptedData_obj['kvno'] = key.kvno
        return EncryptedData_obj

    def Checksum_create(self, key, usage, plaintext, ctype=None):
        # Checksum        ::= SEQUENCE {
        #        cksumtype       [0] Int32,
        #        checksum        [1] OCTET STRING
        # }
        if ctype is None:
            ctype = key.ctype
        checksum = key.make_checksum(usage, plaintext, ctype=ctype)
        Checksum_obj = {
            'cksumtype': ctype,
            'checksum': checksum,
        }
        return Checksum_obj

    @classmethod
    def PrincipalName_create(cls, name_type, names):
        # PrincipalName   ::= SEQUENCE {
        #         name-type       [0] Int32,
        #         name-string     [1] SEQUENCE OF KerberosString
        # }
        PrincipalName_obj = {
            'name-type': name_type,
            'name-string': names,
        }
        return PrincipalName_obj

    def AuthorizationData_create(self, ad_type, ad_data):
        # AuthorizationData ::= SEQUENCE {
        #         ad-type         [0] Int32,
        #         ad-data         [1] OCTET STRING
        # }
        AUTH_DATA_obj = {
            'ad-type': ad_type,
            'ad-data': ad_data
        }
        return AUTH_DATA_obj

    def PA_DATA_create(self, padata_type, padata_value):
        # PA-DATA         ::= SEQUENCE {
        #         -- NOTE: first tag is [1], not [0]
        #         padata-type     [1] Int32,
        #         padata-value    [2] OCTET STRING -- might be encoded AP-REQ
        # }
        PA_DATA_obj = {
            'padata-type': padata_type,
            'padata-value': padata_value,
        }
        return PA_DATA_obj

    def PA_ENC_TS_ENC_create(self, ts, usec):
        # PA-ENC-TS-ENC ::= SEQUENCE {
        #        patimestamp[0]          KerberosTime, -- client's time
        #        pausec[1]               krb5int32 OPTIONAL
        # }
        PA_ENC_TS_ENC_obj = {
            'patimestamp': ts,
            'pausec': usec,
        }
        return PA_ENC_TS_ENC_obj

    def PA_PAC_OPTIONS_create(self, options):
        # PA-PAC-OPTIONS  ::= SEQUENCE {
        #         options         [0] PACOptionFlags
        # }
        PA_PAC_OPTIONS_obj = {
            'options': options
        }
        return PA_PAC_OPTIONS_obj

    def KRB_FAST_ARMOR_create(self, armor_type, armor_value):
        # KrbFastArmor    ::= SEQUENCE {
        #         armor-type      [0] Int32,
        #         armor-value     [1] OCTET STRING,
        #         ...
        # }
        KRB_FAST_ARMOR_obj = {
            'armor-type': armor_type,
            'armor-value': armor_value
        }
        return KRB_FAST_ARMOR_obj

    def KRB_FAST_REQ_create(self, fast_options, padata, req_body):
        # KrbFastReq      ::= SEQUENCE {
        #         fast-options    [0] FastOptions,
        #         padata          [1] SEQUENCE OF PA-DATA,
        #         req-body        [2] KDC-REQ-BODY,
        #         ...
        # }
        KRB_FAST_REQ_obj = {
            'fast-options': fast_options,
            'padata': padata,
            'req-body': req_body
        }
        return KRB_FAST_REQ_obj

    def KRB_FAST_ARMORED_REQ_create(self, armor, req_checksum, enc_fast_req):
        # KrbFastArmoredReq ::= SEQUENCE {
        #         armor           [0] KrbFastArmor OPTIONAL,
        #         req-checksum    [1] Checksum,
        #         enc-fast-req    [2] EncryptedData -- KrbFastReq --
        # }
        KRB_FAST_ARMORED_REQ_obj = {
            'req-checksum': req_checksum,
            'enc-fast-req': enc_fast_req
        }
        if armor is not None:
            KRB_FAST_ARMORED_REQ_obj['armor'] = armor
        return KRB_FAST_ARMORED_REQ_obj

    def PA_FX_FAST_REQUEST_create(self, armored_data):
        # PA-FX-FAST-REQUEST ::= CHOICE {
        #         armored-data    [0] KrbFastArmoredReq,
        #         ...
        # }
        PA_FX_FAST_REQUEST_obj = {
            'armored-data': armored_data
        }
        return PA_FX_FAST_REQUEST_obj

    def KERB_PA_PAC_REQUEST_create(self, include_pac, pa_data_create=True):
        # KERB-PA-PAC-REQUEST ::= SEQUENCE {
        #         include-pac[0] BOOLEAN --If TRUE, and no pac present,
        #                                --    include PAC.
        #                                --If FALSE, and PAC present,
        #                                --    remove PAC.
        # }
        KERB_PA_PAC_REQUEST_obj = {
            'include-pac': include_pac,
        }
        if not pa_data_create:
            return KERB_PA_PAC_REQUEST_obj
        pa_pac = self.der_encode(KERB_PA_PAC_REQUEST_obj,
                                 asn1Spec=krb5_asn1.KERB_PA_PAC_REQUEST())
        pa_data = self.PA_DATA_create(PADATA_PAC_REQUEST, pa_pac)
        return pa_data

    def get_pa_pac_options(self, options):
        pac_options = self.PA_PAC_OPTIONS_create(options)
        pac_options = self.der_encode(pac_options,
                                      asn1Spec=krb5_asn1.PA_PAC_OPTIONS())
        pac_options = self.PA_DATA_create(PADATA_PAC_OPTIONS, pac_options)

        return pac_options

    def KDC_REQ_BODY_create(self,
                            kdc_options,
                            cname,
                            realm,
                            sname,
                            from_time,
                            till_time,
                            renew_time,
                            nonce,
                            etypes,
                            addresses,
                            additional_tickets,
                            EncAuthorizationData,
                            EncAuthorizationData_key,
                            EncAuthorizationData_usage,
                            asn1_print=None,
                            hexdump=None):
        # KDC-REQ-BODY    ::= SEQUENCE {
        #        kdc-options             [0] KDCOptions,
        #        cname                   [1] PrincipalName OPTIONAL
        #                                    -- Used only in AS-REQ --,
        #        realm                   [2] Realm
        #                                    -- Server's realm
        #                                    -- Also client's in AS-REQ --,
        #        sname                   [3] PrincipalName OPTIONAL,
        #        from                    [4] KerberosTime OPTIONAL,
        #        till                    [5] KerberosTime,
        #        rtime                   [6] KerberosTime OPTIONAL,
        #        nonce                   [7] UInt32,
        #        etype                   [8] SEQUENCE OF Int32
        #                                    -- EncryptionType
        #                                    -- in preference order --,
        #        addresses               [9] HostAddresses OPTIONAL,
        #        enc-authorization-data  [10] EncryptedData OPTIONAL
        #                                    -- AuthorizationData --,
        #        additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
        #                                        -- NOTE: not empty
        # }
        if EncAuthorizationData is not None:
            enc_ad_plain = self.der_encode(
                EncAuthorizationData,
                asn1Spec=krb5_asn1.AuthorizationData(),
                asn1_print=asn1_print,
                hexdump=hexdump)
            enc_ad = self.EncryptedData_create(EncAuthorizationData_key,
                                               EncAuthorizationData_usage,
                                               enc_ad_plain)
        else:
            enc_ad = None
        KDC_REQ_BODY_obj = {
            'kdc-options': kdc_options,
            'realm': realm,
            'till': till_time,
            'nonce': nonce,
            'etype': etypes,
        }
        if cname is not None:
            KDC_REQ_BODY_obj['cname'] = cname
        if sname is not None:
            KDC_REQ_BODY_obj['sname'] = sname
        if from_time is not None:
            KDC_REQ_BODY_obj['from'] = from_time
        if renew_time is not None:
            KDC_REQ_BODY_obj['rtime'] = renew_time
        if addresses is not None:
            KDC_REQ_BODY_obj['addresses'] = addresses
        if enc_ad is not None:
            KDC_REQ_BODY_obj['enc-authorization-data'] = enc_ad
        if additional_tickets is not None:
            KDC_REQ_BODY_obj['additional-tickets'] = additional_tickets
        return KDC_REQ_BODY_obj

    def KDC_REQ_create(self,
                       msg_type,
                       padata,
                       req_body,
                       asn1Spec=None,
                       asn1_print=None,
                       hexdump=None):
        # KDC-REQ         ::= SEQUENCE {
        #        -- NOTE: first tag is [1], not [0]
        #        pvno            [1] INTEGER (5) ,
        #        msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
        #        padata          [3] SEQUENCE OF PA-DATA OPTIONAL
        #                            -- NOTE: not empty --,
        #        req-body        [4] KDC-REQ-BODY
        # }
        #
        KDC_REQ_obj = {
            'pvno': 5,
            'msg-type': msg_type,
            'req-body': req_body,
        }
        if padata is not None:
            KDC_REQ_obj['padata'] = padata
        if asn1Spec is not None:
            KDC_REQ_decoded = pyasn1_native_decode(
                KDC_REQ_obj, asn1Spec=asn1Spec)
        else:
            KDC_REQ_decoded = None
        return KDC_REQ_obj, KDC_REQ_decoded

    def AS_REQ_create(self,
                      padata,       # optional
                      kdc_options,  # required
                      cname,        # optional
                      realm,        # required
                      sname,        # optional
                      from_time,    # optional
                      till_time,    # required
                      renew_time,   # optional
                      nonce,        # required
                      etypes,       # required
                      addresses,    # optional
                      additional_tickets,
                      native_decoded_only=True,
                      asn1_print=None,
                      hexdump=None):
        # KDC-REQ         ::= SEQUENCE {
        #        -- NOTE: first tag is [1], not [0]
        #        pvno            [1] INTEGER (5) ,
        #        msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
        #        padata          [3] SEQUENCE OF PA-DATA OPTIONAL
        #                            -- NOTE: not empty --,
        #        req-body        [4] KDC-REQ-BODY
        # }
        #
        # KDC-REQ-BODY    ::= SEQUENCE {
        #        kdc-options             [0] KDCOptions,
        #        cname                   [1] PrincipalName OPTIONAL
        #                                    -- Used only in AS-REQ --,
        #        realm                   [2] Realm
        #                                    -- Server's realm
        #                                    -- Also client's in AS-REQ --,
        #        sname                   [3] PrincipalName OPTIONAL,
        #        from                    [4] KerberosTime OPTIONAL,
        #        till                    [5] KerberosTime,
        #        rtime                   [6] KerberosTime OPTIONAL,
        #        nonce                   [7] UInt32,
        #        etype                   [8] SEQUENCE OF Int32
        #                                    -- EncryptionType
        #                                    -- in preference order --,
        #        addresses               [9] HostAddresses OPTIONAL,
        #        enc-authorization-data  [10] EncryptedData OPTIONAL
        #                                    -- AuthorizationData --,
        #        additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
        #                                        -- NOTE: not empty
        # }
        KDC_REQ_BODY_obj = self.KDC_REQ_BODY_create(
            kdc_options,
            cname,
            realm,
            sname,
            from_time,
            till_time,
            renew_time,
            nonce,
            etypes,
            addresses,
            additional_tickets,
            EncAuthorizationData=None,
            EncAuthorizationData_key=None,
            EncAuthorizationData_usage=None,
            asn1_print=asn1_print,
            hexdump=hexdump)
        obj, decoded = self.KDC_REQ_create(
            msg_type=KRB_AS_REQ,
            padata=padata,
            req_body=KDC_REQ_BODY_obj,
            asn1Spec=krb5_asn1.AS_REQ(),
            asn1_print=asn1_print,
            hexdump=hexdump)
        if native_decoded_only:
            return decoded
        return decoded, obj

    def AP_REQ_create(self, ap_options, ticket, authenticator):
        # AP-REQ          ::= [APPLICATION 14] SEQUENCE {
        #        pvno            [0] INTEGER (5),
        #        msg-type        [1] INTEGER (14),
        #        ap-options      [2] APOptions,
        #        ticket          [3] Ticket,
        #        authenticator   [4] EncryptedData -- Authenticator
        # }
        AP_REQ_obj = {
            'pvno': 5,
            'msg-type': KRB_AP_REQ,
            'ap-options': ap_options,
            'ticket': ticket,
            'authenticator': authenticator,
        }
        return AP_REQ_obj

    def Authenticator_create(
            self, crealm, cname, cksum, cusec, ctime, subkey, seq_number,
            authorization_data):
        # -- Unencrypted authenticator
        # Authenticator   ::= [APPLICATION 2] SEQUENCE  {
        #        authenticator-vno       [0] INTEGER (5),
        #        crealm                  [1] Realm,
        #        cname                   [2] PrincipalName,
        #        cksum                   [3] Checksum OPTIONAL,
        #        cusec                   [4] Microseconds,
        #        ctime                   [5] KerberosTime,
        #        subkey                  [6] EncryptionKey OPTIONAL,
        #        seq-number              [7] UInt32 OPTIONAL,
        #        authorization-data      [8] AuthorizationData OPTIONAL
        # }
        Authenticator_obj = {
            'authenticator-vno': 5,
            'crealm': crealm,
            'cname': cname,
            'cusec': cusec,
            'ctime': ctime,
        }
        if cksum is not None:
            Authenticator_obj['cksum'] = cksum
        if subkey is not None:
            Authenticator_obj['subkey'] = subkey
        if seq_number is not None:
            Authenticator_obj['seq-number'] = seq_number
        if authorization_data is not None:
            Authenticator_obj['authorization-data'] = authorization_data
        return Authenticator_obj

    def PKAuthenticator_create(self,
                               cusec,
                               ctime,
                               nonce,
                               *,
                               pa_checksum=None,
                               freshness_token=None,
                               kdc_name=None,
                               kdc_realm=None,
                               win2k_variant=False):
        if win2k_variant:
            self.assertIsNone(pa_checksum)
            self.assertIsNone(freshness_token)
            self.assertIsNotNone(kdc_name)
            self.assertIsNotNone(kdc_realm)
        else:
            self.assertIsNone(kdc_name)
            self.assertIsNone(kdc_realm)

        pk_authenticator_obj = {
            'cusec': cusec,
            'ctime': ctime,
            'nonce': nonce,
        }
        if pa_checksum is not None:
            pk_authenticator_obj['paChecksum'] = pa_checksum
        if freshness_token is not None:
            pk_authenticator_obj['freshnessToken'] = freshness_token
        if kdc_name is not None:
            pk_authenticator_obj['kdcName'] = kdc_name
        if kdc_realm is not None:
            pk_authenticator_obj['kdcRealm'] = kdc_realm

        return pk_authenticator_obj

    def TGS_REQ_create(self,
                       padata,       # optional
                       cusec,
                       ctime,
                       ticket,
                       kdc_options,  # required
                       cname,        # optional
                       realm,        # required
                       sname,        # optional
                       from_time,    # optional
                       till_time,    # required
                       renew_time,   # optional
                       nonce,        # required
                       etypes,       # required
                       addresses,    # optional
                       EncAuthorizationData,
                       EncAuthorizationData_key,
                       additional_tickets,
                       ticket_session_key,
                       authenticator_subkey=None,
                       body_checksum_type=None,
                       native_decoded_only=True,
                       asn1_print=None,
                       hexdump=None):
        # KDC-REQ         ::= SEQUENCE {
        #        -- NOTE: first tag is [1], not [0]
        #        pvno            [1] INTEGER (5) ,
        #        msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
        #        padata          [3] SEQUENCE OF PA-DATA OPTIONAL
        #                            -- NOTE: not empty --,
        #        req-body        [4] KDC-REQ-BODY
        # }
        #
        # KDC-REQ-BODY    ::= SEQUENCE {
        #        kdc-options             [0] KDCOptions,
        #        cname                   [1] PrincipalName OPTIONAL
        #                                    -- Used only in AS-REQ --,
        #        realm                   [2] Realm
        #                                    -- Server's realm
        #                                    -- Also client's in AS-REQ --,
        #        sname                   [3] PrincipalName OPTIONAL,
        #        from                    [4] KerberosTime OPTIONAL,
        #        till                    [5] KerberosTime,
        #        rtime                   [6] KerberosTime OPTIONAL,
        #        nonce                   [7] UInt32,
        #        etype                   [8] SEQUENCE OF Int32
        #                                    -- EncryptionType
        #                                    -- in preference order --,
        #        addresses               [9] HostAddresses OPTIONAL,
        #        enc-authorization-data  [10] EncryptedData OPTIONAL
        #                                    -- AuthorizationData --,
        #        additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
        #                                        -- NOTE: not empty
        # }

        if authenticator_subkey is not None:
            EncAuthorizationData_usage = KU_TGS_REQ_AUTH_DAT_SUBKEY
        else:
            EncAuthorizationData_usage = KU_TGS_REQ_AUTH_DAT_SESSION

        req_body = self.KDC_REQ_BODY_create(
            kdc_options=kdc_options,
            cname=None,
            realm=realm,
            sname=sname,
            from_time=from_time,
            till_time=till_time,
            renew_time=renew_time,
            nonce=nonce,
            etypes=etypes,
            addresses=addresses,
            additional_tickets=additional_tickets,
            EncAuthorizationData=EncAuthorizationData,
            EncAuthorizationData_key=EncAuthorizationData_key,
            EncAuthorizationData_usage=EncAuthorizationData_usage)
        req_body_blob = self.der_encode(req_body,
                                        asn1Spec=krb5_asn1.KDC_REQ_BODY(),
                                        asn1_print=asn1_print, hexdump=hexdump)

        req_body_checksum = self.Checksum_create(ticket_session_key,
                                                 KU_TGS_REQ_AUTH_CKSUM,
                                                 req_body_blob,
                                                 ctype=body_checksum_type)

        subkey_obj = None
        if authenticator_subkey is not None:
            subkey_obj = authenticator_subkey.export_obj()
        seq_number = random.randint(0, 0xfffffffe)
        authenticator = self.Authenticator_create(
            crealm=realm,
            cname=cname,
            cksum=req_body_checksum,
            cusec=cusec,
            ctime=ctime,
            subkey=subkey_obj,
            seq_number=seq_number,
            authorization_data=None)
        authenticator = self.der_encode(
            authenticator,
            asn1Spec=krb5_asn1.Authenticator(),
            asn1_print=asn1_print,
            hexdump=hexdump)

        authenticator = self.EncryptedData_create(
            ticket_session_key, KU_TGS_REQ_AUTH, authenticator)

        ap_options = krb5_asn1.APOptions('0')
        ap_req = self.AP_REQ_create(ap_options=str(ap_options),
                                    ticket=ticket,
                                    authenticator=authenticator)
        ap_req = self.der_encode(ap_req, asn1Spec=krb5_asn1.AP_REQ(),
                                 asn1_print=asn1_print, hexdump=hexdump)
        pa_tgs_req = self.PA_DATA_create(PADATA_KDC_REQ, ap_req)
        if padata is not None:
            padata.append(pa_tgs_req)
        else:
            padata = [pa_tgs_req]

        obj, decoded = self.KDC_REQ_create(
            msg_type=KRB_TGS_REQ,
            padata=padata,
            req_body=req_body,
            asn1Spec=krb5_asn1.TGS_REQ(),
            asn1_print=asn1_print,
            hexdump=hexdump)
        if native_decoded_only:
            return decoded
        return decoded, obj

    def PA_S4U2Self_create(self, name, realm, tgt_session_key, ctype=None):
        # PA-S4U2Self     ::= SEQUENCE {
        #        name            [0] PrincipalName,
        #        realm           [1] Realm,
        #        cksum           [2] Checksum,
        #        auth            [3] GeneralString
        # }
        cksum_data = name['name-type'].to_bytes(4, byteorder='little')
        for n in name['name-string']:
            cksum_data += n.encode()
        cksum_data += realm.encode()
        cksum_data += "Kerberos".encode()
        cksum = self.Checksum_create(tgt_session_key,
                                     KU_NON_KERB_CKSUM_SALT,
                                     cksum_data,
                                     ctype)

        PA_S4U2Self_obj = {
            'name': name,
            'realm': realm,
            'cksum': cksum,
            'auth': "Kerberos",
        }
        pa_s4u2self = self.der_encode(
            PA_S4U2Self_obj, asn1Spec=krb5_asn1.PA_S4U2Self())
        return self.PA_DATA_create(PADATA_FOR_USER, pa_s4u2self)

    def ChangePasswdDataMS_create(self,
                                  new_password,
                                  target_princ=None,
                                  target_realm=None):
        ChangePasswdDataMS_obj = {
            'newpasswd': new_password,
        }
        if target_princ is not None:
            ChangePasswdDataMS_obj['targname'] = target_princ
        if target_realm is not None:
            ChangePasswdDataMS_obj['targrealm'] = target_realm

        change_password_data = self.der_encode(
            ChangePasswdDataMS_obj, asn1Spec=krb5_asn1.ChangePasswdDataMS())

        return change_password_data

    def KRB_PRIV_create(self,
                        subkey,
                        user_data,
                        s_address,
                        timestamp=None,
                        usec=None,
                        seq_number=None,
                        r_address=None):
        EncKrbPrivPart_obj = {
            'user-data': user_data,
            's-address': s_address,
        }
        if timestamp is not None:
            EncKrbPrivPart_obj['timestamp'] = timestamp
        if usec is not None:
            EncKrbPrivPart_obj['usec'] = usec
        if seq_number is not None:
            EncKrbPrivPart_obj['seq-number'] = seq_number
        if r_address is not None:
            EncKrbPrivPart_obj['r-address'] = r_address

        enc_krb_priv_part = self.der_encode(
            EncKrbPrivPart_obj, asn1Spec=krb5_asn1.EncKrbPrivPart())

        enc_data = self.EncryptedData_create(subkey,
                                             KU_KRB_PRIV,
                                             enc_krb_priv_part)

        KRB_PRIV_obj = {
            'pvno': 5,
            'msg-type': KRB_PRIV,
            'enc-part': enc_data,
        }

        krb_priv = self.der_encode(
            KRB_PRIV_obj, asn1Spec=krb5_asn1.KRB_PRIV())

        return krb_priv

    def ContentInfo_create(self, content_type, content):
        content_info_obj = {
            'contentType': content_type,
            'content': content,
        }

        return content_info_obj

    def EncapsulatedContentInfo_create(self, content_type, content):
        encapsulated_content_info_obj = {
            'eContentType': content_type,
            'eContent': content,
        }

        return encapsulated_content_info_obj

    def SignedData_create(self,
                          digest_algorithms,
                          encap_content_info,
                          signer_infos,
                          *,
                          version=None,
                          certificates=None,
                          crls=None):
        def is_cert_version_present(version):
            return certificates is not None and any(
                version in cert for cert in certificates)

        def is_crl_version_present(version):
            return crls is not None and any(
                version in crl for crl in crls)

        def is_signer_info_version_present(version):
            return signer_infos is not None and any(
                signer_info['version'] == version
                for signer_info in signer_infos)

        def data_version():
            # per RFC5652 5.1:
            if is_cert_version_present('other') or (
                    is_crl_version_present('other')):
                return 5

            if is_cert_version_present('v2AttrCert'):
                return 4

            if is_cert_version_present('v1AttrCert') or (
                    is_signer_info_version_present(3)) or (
                        encap_content_info['eContentType'] != krb5_asn1.id_data
                    ):
                return 3

            return 1

        if version is None:
            version = data_version()

        signed_data_obj = {
            'version': version,
            'digestAlgorithms': digest_algorithms,
            'encapContentInfo': encap_content_info,
            'signerInfos': signer_infos,
        }

        if certificates is not None:
            signed_data_obj['certificates'] = certificates
        if crls is not None:
            signed_data_obj['crls'] = crls

        return signed_data_obj

    def AuthPack_create(self,
                        pk_authenticator,
                        *,
                        client_public_value=None,
                        supported_cms_types=None,
                        client_dh_nonce=None,
                        win2k_variant=False):
        if win2k_variant:
            self.assertIsNone(supported_cms_types)
            self.assertIsNone(client_dh_nonce)

        auth_pack_obj = {
            'pkAuthenticator': pk_authenticator,
        }

        if client_public_value is not None:
            auth_pack_obj['clientPublicValue'] = client_public_value
        if supported_cms_types is not None:
            auth_pack_obj['supportedCMSTypes'] = supported_cms_types
        if client_dh_nonce is not None:
            auth_pack_obj['clientDHNonce'] = client_dh_nonce

        return auth_pack_obj

    def PK_AS_REQ_create(self,
                         signed_auth_pack,
                         *,
                         trusted_certifiers=None,
                         kdc_pk_id=None,
                         kdc_cert=None,
                         encryption_cert=None,
                         win2k_variant=False):
        if win2k_variant:
            self.assertIsNone(kdc_pk_id)
            asn1_spec = krb5_asn1.PA_PK_AS_REQ_Win2k
        else:
            self.assertIsNone(kdc_cert)
            self.assertIsNone(encryption_cert)
            asn1_spec = krb5_asn1.PA_PK_AS_REQ

        content_info_obj = self.ContentInfo_create(
            krb5_asn1.id_signedData, signed_auth_pack)
        content_info = self.der_encode(content_info_obj,
                                       asn1Spec=krb5_asn1.ContentInfo())

        pk_as_req_obj = {
            'signedAuthPack': content_info,
        }

        if trusted_certifiers is not None:
            pk_as_req_obj['trustedCertifiers'] = trusted_certifiers
        if kdc_pk_id is not None:
            pk_as_req_obj['kdcPkId'] = kdc_pk_id
        if kdc_cert is not None:
            pk_as_req_obj['kdcCert'] = kdc_cert
        if encryption_cert is not None:
            pk_as_req_obj['encryptionCert'] = encryption_cert

        return self.der_encode(pk_as_req_obj, asn1Spec=asn1_spec())

    def SignerInfo_create(self,
                          signer_id,
                          digest_algorithm,
                          signature_algorithm,
                          signature,
                          *,
                          version=None,
                          signed_attrs=None,
                          unsigned_attrs=None):
        if version is None:
            # per RFC5652 5.3:
            if 'issuerAndSerialNumber' in signer_id:
                version = 1
            elif 'subjectKeyIdentifier' in signer_id:
                version = 3
            else:
                self.fail(f'unknown signer ID version ({signer_id})')

        signer_info_obj = {
            'version': version,
            'sid': signer_id,
            'digestAlgorithm': digest_algorithm,
            'signatureAlgorithm': signature_algorithm,
            'signature': signature,
        }

        if signed_attrs is not None:
            signer_info_obj['signedAttrs'] = signed_attrs
        if unsigned_attrs is not None:
            signer_info_obj['unsignedAttrs'] = unsigned_attrs

        return signer_info_obj

    def SignerIdentifier_create(self, *,
                                issuer_and_serial_number=None,
                                subject_key_id=None):
        if issuer_and_serial_number is not None:
            return {'issuerAndSerialNumber': issuer_and_serial_number}

        if subject_key_id is not None:
            return {'subjectKeyIdentifier': subject_key_id}

        self.fail('identifier not specified')

    def AlgorithmIdentifier_create(self,
                                   algorithm,
                                   *,
                                   parameters=None):
        algorithm_id_obj = {
            'algorithm': algorithm,
        }

        if parameters is not None:
            algorithm_id_obj['parameters'] = parameters

        return algorithm_id_obj

    def SubjectPublicKeyInfo_create(self,
                                    algorithm,
                                    public_key):
        return {
            'algorithm': algorithm,
            'subjectPublicKey': public_key,
        }

    def ValidationParms_create(self,
                               seed,
                               pgen_counter):
        return {
            'seed': seed,
            'pgenCounter': pgen_counter,
        }

    def DomainParameters_create(self,
                                p,
                                g,
                                *,
                                q=None,
                                j=None,
                                validation_parms=None):
        domain_params_obj = {
            'p': p,
            'g': g,
        }

        if q is not None:
            domain_params_obj['q'] = q
        if j is not None:
            domain_params_obj['j'] = j
        if validation_parms is not None:
            domain_params_obj['validationParms'] = validation_parms

        return domain_params_obj

    def length_in_bytes(self, value):
        """Return the length in bytes of an integer once it is encoded as
        bytes."""

        self.assertGreaterEqual(value, 0, 'value must be positive')
        self.assertIsInstance(value, int)

        length_in_bits = max(1, math.log2(value + 1))
        length_in_bytes = math.ceil(length_in_bits / 8)
        return length_in_bytes

    def bytes_from_int(self, value, *, length=None):
        """Return an integer encoded big-endian into bytes of an optionally
        specified length.
        """
        if length is None:
            length = self.length_in_bytes(value)
        return value.to_bytes(length, 'big')

    def int_from_bytes(self, data):
        """Return an integer decoded from bytes in big-endian format."""
        return int.from_bytes(data, 'big')

    def int_from_bit_string(self, string):
        """Return an integer decoded from a bitstring."""
        return int(string, base=2)

    def bit_string_from_int(self, value):
        """Return a bitstring encoding of an integer."""

        string = f'{value:b}'

        # The bitstring must be padded to a multiple of 8 bits in length, or
        # pyasn1 will interpret it incorrectly (as if the padding bits were
        # present, but on the wrong end).
        length = len(string)
        padding_len = math.ceil(length / 8) * 8 - length
        return '0' * padding_len + string

    def bit_string_from_bytes(self, data):
        """Return a bitstring encoding of bytes in big-endian format."""
        value = self.int_from_bytes(data)
        return self.bit_string_from_int(value)

    def bytes_from_bit_string(self, string):
        """Return big-endian format bytes encoded from a bitstring."""
        value = self.int_from_bit_string(string)
        length = math.ceil(len(string) / 8)
        return value.to_bytes(length, 'big')

    def asn1_length(self, data):
        """Return the ASN.1 encoding of the length of some data."""

        length = len(data)

        self.assertGreater(length, 0)
        if length < 0x80:
            return bytes([length])

        encoding_len = self.length_in_bytes(length)
        self.assertLess(encoding_len, 0x80,
                        'item is too long to be ASN.1 encoded')

        data = self.bytes_from_int(length, length=encoding_len)
        return bytes([0x80 | encoding_len]) + data

    @staticmethod
    def octetstring2key(x, enctype):
        """This implements the function defined in RFC4556 3.2.3.1 “Using
        Diffie-Hellman Key Exchange”."""

        seedsize = kcrypto.seedsize(enctype)
        seed = b''

        # A counter that cycles through the bytes 0x00–0xff.
        counter = itertools.cycle(map(lambda x: bytes([x]),
                                      range(256)))

        while len(seed) < seedsize:
            digest = hashes.Hash(hashes.SHA1(), default_backend())
            digest.update(next(counter) + x)
            seed += digest.finalize()

        key = kcrypto.random_to_key(enctype, seed[:seedsize])
        return RodcPacEncryptionKey(key, kvno=None)

    def unpad(self, data):
        """Return unpadded data."""
        padding_len = data[-1]
        expected_padding = bytes([padding_len]) * padding_len
        self.assertEqual(expected_padding, data[-padding_len:],
                         'invalid padding bytes')

        return data[:-padding_len]

    def try_decode(self, data, module=None):
        """Try to decode some data of unknown type with various known ASN.1
        schemata (optionally restricted to those from a particular module) and
        print any results that seem promising. For use when debugging.
        """

        if module is None:
            # Try a couple of known ASN.1 modules.
            self.try_decode(data, krb5_asn1)
            self.try_decode(data, pyasn1.type.univ)

            # It’s helpful to stop and give the user a chance to examine the
            # results.
            self.fail('decoding done')

        names = dir(module)
        for name in names:
            item = getattr(module, name)
            if not callable(item):
                continue

            try:
                decoded = self.der_decode(data, asn1Spec=item())
            except Exception:
                # Initiating the schema or decoding the ASN.1 failed for
                # whatever reason.
                pass
            else:
                # Decoding succeeded: print the structure to be examined.
                print(f'\t{name}')
                pprint(decoded)

    def cipher_from_algorithm(self, algorithm):
        if algorithm == str(krb5_asn1.aes256_CBC_PAD):
            return algorithms.AES

        if algorithm == str(krb5_asn1.des_EDE3_CBC):
            return algorithms.TripleDES

        self.fail(f'unknown cipher algorithm {algorithm}')

    def hash_from_algorithm(self, algorithm):
        # Let someone pass in an ObjectIdentifier.
        algorithm = str(algorithm)

        if algorithm == str(krb5_asn1.id_sha1):
            return hashes.SHA1

        if algorithm == str(krb5_asn1.sha1WithRSAEncryption):
            return hashes.SHA1

        if algorithm == str(krb5_asn1.rsaEncryption):
            return hashes.SHA1

        if algorithm == str(krb5_asn1.id_pkcs1_sha256WithRSAEncryption):
            return hashes.SHA256

        if algorithm == str(krb5_asn1.id_sha512):
            return hashes.SHA512

        self.fail(f'unknown hash algorithm {algorithm}')

    def hash_from_algorithm_id(self, algorithm_id):
        self.assertIsInstance(algorithm_id, dict)

        hash = self.hash_from_algorithm(algorithm_id['algorithm'])

        parameters = algorithm_id.get('parameters')
        if self.strict_checking:
            self.assertIsNotNone(parameters)
        if parameters is not None:
            self.assertEqual(b'\x05\x00', parameters)

        return hash

    def create_freshness_token(self,
                               epoch=None,
                               *,
                               offset=None,
                               krbtgt_creds=None):
        timestamp, usec = self.get_KerberosTimeWithUsec(epoch, offset)

        # Encode the freshness token as PA-ENC-TS-ENC.
        ts_enc = self.PA_ENC_TS_ENC_create(timestamp, usec)
        ts_enc = self.der_encode(ts_enc, asn1Spec=krb5_asn1.PA_ENC_TS_ENC())

        if krbtgt_creds is None:
            krbtgt_creds = self.get_krbtgt_creds()
        krbtgt_key = self.TicketDecryptionKey_from_creds(krbtgt_creds)

        # Encrypt the freshness token.
        freshness = self.EncryptedData_create(krbtgt_key, KU_AS_FRESHNESS, ts_enc)

        freshness_token = self.der_encode(freshness,
                                          asn1Spec=krb5_asn1.EncryptedData())

        # Prepend a couple of zero bytes.
        freshness_token = bytes(2) + freshness_token

        return freshness_token

    def kpasswd_create(self,
                       subkey,
                       user_data,
                       version,
                       seq_number,
                       ap_req,
                       local_address,
                       remote_address):
        self.assertIsNotNone(self.s, 'call self.connect() first')

        timestamp, usec = self.get_KerberosTimeWithUsec()

        krb_priv = self.KRB_PRIV_create(subkey,
                                        user_data,
                                        s_address=local_address,
                                        timestamp=timestamp,
                                        usec=usec,
                                        seq_number=seq_number,
                                        r_address=remote_address)

        size = 6 + len(ap_req) + len(krb_priv)
        self.assertLess(size, 0x10000)

        msg = bytearray()
        msg.append(size >> 8)
        msg.append(size & 0xff)
        msg.append(version >> 8)
        msg.append(version & 0xff)
        msg.append(len(ap_req) >> 8)
        msg.append(len(ap_req) & 0xff)
        # Note: for sets, there could be a little-endian four-byte length here.

        msg.extend(ap_req)
        msg.extend(krb_priv)

        return msg

    def get_enc_part(self, obj, key, usage):
        self.assertElementEqual(obj, 'pvno', 5)

        enc_part = obj['enc-part']
        self.assertElementEqual(enc_part, 'etype', key.etype)
        self.assertElementKVNO(enc_part, 'kvno', key.kvno)

        enc_part = key.decrypt(usage, enc_part['cipher'])

        return enc_part

    def kpasswd_exchange(self,
                         ticket,
                         new_password,
                         expected_code,
                         expected_msg,
                         mode,
                         target_princ=None,
                         target_realm=None,
                         ap_options=None,
                         send_seq_number=True):
        if mode is self.KpasswdMode.SET:
            version = 0xff80
            user_data = self.ChangePasswdDataMS_create(new_password,
                                                       target_princ,
                                                       target_realm)
        elif mode is self.KpasswdMode.CHANGE:
            self.assertIsNone(target_princ,
                              'target_princ only valid for pw set')
            self.assertIsNone(target_realm,
                              'target_realm only valid for pw set')

            version = 1
            user_data = new_password.encode('utf-8')
        else:
            self.fail(f'invalid mode {mode}')

        subkey = self.RandomKey(kcrypto.Enctype.AES256)

        if ap_options is None:
            ap_options = '0'
        ap_options = str(krb5_asn1.APOptions(ap_options))

        kdc_exchange_dict = {
            'tgt': ticket,
            'authenticator_subkey': subkey,
            'auth_data': None,
            'ap_options': ap_options,
        }

        if send_seq_number:
            seq_number = random.randint(0, 0xfffffffe)
        else:
            seq_number = None

        ap_req = self.generate_ap_req(kdc_exchange_dict,
                                      None,
                                      req_body=None,
                                      armor=False,
                                      usage=KU_AP_REQ_AUTH,
                                      seq_number=seq_number)

        self.connect(self.host, port=464)
        self.assertIsNotNone(self.s)

        family = self.s.family

        if family == socket.AF_INET:
            addr_type = 2  # IPv4
        elif family == socket.AF_INET6:
            addr_type = 24  # IPv6
        else:
            self.fail(f'unknown family {family}')

        def create_address(ip):
            return {
                'addr-type': addr_type,
                'address': socket.inet_pton(family, ip),
            }

        local_ip = self.s.getsockname()[0]
        local_address = create_address(local_ip)

        # remote_ip = self.s.getpeername()[0]
        # remote_address = create_address(remote_ip)

        # TODO: due to a bug (?), MIT Kerberos will not accept the request
        # unless r-address is set to our _local_ address. Heimdal, on the other
        # hand, requires the r-address is set to the remote address (as
        # expected). To avoid problems, avoid sending r-address for now.
        remote_address = None

        msg = self.kpasswd_create(subkey,
                                  user_data,
                                  version,
                                  seq_number,
                                  ap_req,
                                  local_address,
                                  remote_address)

        self.send_msg(msg)
        rep_pdu = self.recv_pdu_raw()

        self._disconnect('transaction done')

        self.assertIsNotNone(rep_pdu)

        header = rep_pdu[:6]
        reply = rep_pdu[6:]

        reply_len = (header[0] << 8) | header[1]
        reply_version = (header[2] << 8) | header[3]
        ap_rep_len = (header[4] << 8) | header[5]

        self.assertEqual(reply_len, len(rep_pdu))
        self.assertEqual(1, reply_version)  # KRB5_KPASSWD_VERS_CHANGEPW
        self.assertLess(ap_rep_len, reply_len)

        self.assertNotEqual(0x7e, rep_pdu[1])
        self.assertNotEqual(0x5e, rep_pdu[1])

        if ap_rep_len:
            # We received an AP-REQ and KRB-PRIV as a response. This may or may
            # not indicate an error, depending on the status code.
            ap_rep = reply[:ap_rep_len]
            krb_priv = reply[ap_rep_len:]

            key = ticket.session_key

            ap_rep = self.der_decode(ap_rep, asn1Spec=krb5_asn1.AP_REP())
            self.assertElementEqual(ap_rep, 'msg-type', KRB_AP_REP)
            enc_part = self.get_enc_part(ap_rep, key, KU_AP_REQ_ENC_PART)
            enc_part = self.der_decode(
                enc_part, asn1Spec=krb5_asn1.EncAPRepPart())

            self.assertElementPresent(enc_part, 'ctime')
            self.assertElementPresent(enc_part, 'cusec')
            # self.assertElementMissing(enc_part, 'subkey') # TODO
            # self.assertElementPresent(enc_part, 'seq-number') # TODO

            try:
                krb_priv = self.der_decode(krb_priv, asn1Spec=krb5_asn1.KRB_PRIV())
            except PyAsn1Error:
                self.fail()

            self.assertElementEqual(krb_priv, 'msg-type', KRB_PRIV)
            priv_enc_part = self.get_enc_part(krb_priv, subkey, KU_KRB_PRIV)
            priv_enc_part = self.der_decode(
                priv_enc_part, asn1Spec=krb5_asn1.EncKrbPrivPart())

            self.assertElementMissing(priv_enc_part, 'timestamp')
            self.assertElementMissing(priv_enc_part, 'usec')
            # self.assertElementPresent(priv_enc_part, 'seq-number') # TODO
            # self.assertElementEqual(priv_enc_part, 's-address', remote_address) # TODO
            # self.assertElementMissing(priv_enc_part, 'r-address') # TODO

            result_data = priv_enc_part['user-data']
        else:
            # We received a KRB-ERROR as a response, indicating an error.
            krb_error = self.der_decode(reply, asn1Spec=krb5_asn1.KRB_ERROR())

            sname = self.PrincipalName_create(
                name_type=NT_PRINCIPAL,
                names=['kadmin', 'changepw'])
            realm = self.get_krbtgt_creds().get_realm().upper()

            self.assertElementEqual(krb_error, 'pvno', 5)
            self.assertElementEqual(krb_error, 'msg-type', KRB_ERROR)
            self.assertElementMissing(krb_error, 'ctime')
            self.assertElementMissing(krb_error, 'usec')
            self.assertElementPresent(krb_error, 'stime')
            self.assertElementPresent(krb_error, 'susec')

            error_code = krb_error['error-code']
            if isinstance(expected_code, int):
                self.assertEqual(error_code, expected_code)
            else:
                self.assertIn(error_code, expected_code)

            self.assertElementMissing(krb_error, 'crealm')
            self.assertElementMissing(krb_error, 'cname')
            self.assertElementEqual(krb_error, 'realm', realm.encode('utf-8'))
            self.assertElementEqualPrincipal(krb_error, 'sname', sname)
            self.assertElementMissing(krb_error, 'e-text')

            result_data = krb_error['e-data']

        status = result_data[:2]
        message = result_data[2:]

        status_code = (status[0] << 8) | status[1]
        if isinstance(expected_code, int):
            self.assertEqual(status_code, expected_code)
        else:
            self.assertIn(status_code, expected_code)

        if not message:
            self.assertEqual(0, status_code,
                             'got an error result, but no message')
            return

        # Check the first character of the message.
        if message[0]:
            if isinstance(expected_msg, bytes):
                self.assertEqual(message, expected_msg)
            else:
                self.assertIn(message, expected_msg)
        else:
            # We got AD password policy information.
            self.assertEqual(30, len(message))

            (empty_bytes,
             min_length,
             history_length,
             properties,
             expire_time,
             min_age) = struct.unpack('>HIIIQQ', message)

    def _generic_kdc_exchange(self,
                              kdc_exchange_dict,  # required
                              cname=None,  # optional
                              realm=None,  # required
                              sname=None,  # optional
                              from_time=None,  # optional
                              till_time=None,  # required
                              renew_time=None,  # optional
                              etypes=None,  # required
                              addresses=None,  # optional
                              additional_tickets=None,  # optional
                              EncAuthorizationData=None,  # optional
                              EncAuthorizationData_key=None,  # optional
                              EncAuthorizationData_usage=None):  # optional

        check_error_fn = kdc_exchange_dict['check_error_fn']
        check_rep_fn = kdc_exchange_dict['check_rep_fn']
        generate_fast_fn = kdc_exchange_dict['generate_fast_fn']
        generate_fast_armor_fn = kdc_exchange_dict['generate_fast_armor_fn']
        generate_fast_padata_fn = kdc_exchange_dict['generate_fast_padata_fn']
        generate_padata_fn = kdc_exchange_dict['generate_padata_fn']
        callback_dict = kdc_exchange_dict['callback_dict']
        req_msg_type = kdc_exchange_dict['req_msg_type']
        req_asn1Spec = kdc_exchange_dict['req_asn1Spec']
        rep_msg_type = kdc_exchange_dict['rep_msg_type']

        expected_error_mode = kdc_exchange_dict['expected_error_mode']
        kdc_options = kdc_exchange_dict['kdc_options']

        pac_request = kdc_exchange_dict['pac_request']
        pac_options = kdc_exchange_dict['pac_options']

        # Parameters specific to the inner request body
        inner_req = kdc_exchange_dict['inner_req']

        # Parameters specific to the outer request body
        outer_req = kdc_exchange_dict['outer_req']

        if till_time is None:
            till_time = self.get_KerberosTime(offset=36000)

        if 'nonce' in kdc_exchange_dict:
            nonce = kdc_exchange_dict['nonce']
        else:
            nonce = self.get_Nonce()
            kdc_exchange_dict['nonce'] = nonce

        req_body = self.KDC_REQ_BODY_create(
            kdc_options=kdc_options,
            cname=cname,
            realm=realm,
            sname=sname,
            from_time=from_time,
            till_time=till_time,
            renew_time=renew_time,
            nonce=nonce,
            etypes=etypes,
            addresses=addresses,
            additional_tickets=additional_tickets,
            EncAuthorizationData=EncAuthorizationData,
            EncAuthorizationData_key=EncAuthorizationData_key,
            EncAuthorizationData_usage=EncAuthorizationData_usage)

        inner_req_body = dict(req_body)
        if inner_req is not None:
            for key, value in inner_req.items():
                if value is not None:
                    inner_req_body[key] = value
                else:
                    del inner_req_body[key]
        if outer_req is not None:
            for key, value in outer_req.items():
                if value is not None:
                    req_body[key] = value
                else:
                    del req_body[key]

        additional_padata = []
        if pac_request is not None:
            pa_pac_request = self.KERB_PA_PAC_REQUEST_create(pac_request)
            additional_padata.append(pa_pac_request)
        if pac_options is not None:
            pa_pac_options = self.get_pa_pac_options(pac_options)
            additional_padata.append(pa_pac_options)

        if req_msg_type == KRB_AS_REQ:
            tgs_req = None
            tgs_req_padata = None
        else:
            self.assertEqual(KRB_TGS_REQ, req_msg_type)

            tgs_req = self.generate_ap_req(kdc_exchange_dict,
                                           callback_dict,
                                           req_body,
                                           armor=False)
            tgs_req_padata = self.PA_DATA_create(PADATA_KDC_REQ, tgs_req)

        if generate_fast_padata_fn is not None:
            self.assertIsNotNone(generate_fast_fn)
            # This can alter req_body...
            fast_padata, req_body = generate_fast_padata_fn(kdc_exchange_dict,
                                                            callback_dict,
                                                            req_body)
        else:
            fast_padata = []

        if generate_fast_armor_fn is not None:
            self.assertIsNotNone(generate_fast_fn)
            fast_ap_req = generate_fast_armor_fn(kdc_exchange_dict,
                                                 callback_dict,
                                                 None,
                                                 armor=True)

            fast_armor_type = kdc_exchange_dict['fast_armor_type']
            fast_armor = self.KRB_FAST_ARMOR_create(fast_armor_type,
                                                    fast_ap_req)
        else:
            fast_armor = None

        if generate_padata_fn is not None:
            # This can alter req_body...
            outer_padata, req_body = generate_padata_fn(kdc_exchange_dict,
                                                        callback_dict,
                                                        req_body)
            self.assertIsNotNone(outer_padata)
            self.assertNotIn(PADATA_KDC_REQ,
                             [pa['padata-type'] for pa in outer_padata],
                             'Don\'t create TGS-REQ manually')
        else:
            outer_padata = None

        if generate_fast_fn is not None:
            armor_key = kdc_exchange_dict['armor_key']
            self.assertIsNotNone(armor_key)

            if req_msg_type == KRB_AS_REQ:
                checksum_blob = self.der_encode(
                    req_body,
                    asn1Spec=krb5_asn1.KDC_REQ_BODY())
            else:
                self.assertEqual(KRB_TGS_REQ, req_msg_type)
                checksum_blob = tgs_req

            checksum = self.Checksum_create(armor_key,
                                            KU_FAST_REQ_CHKSUM,
                                            checksum_blob)

            fast_padata += additional_padata
            fast = generate_fast_fn(kdc_exchange_dict,
                                    callback_dict,
                                    inner_req_body,
                                    fast_padata,
                                    fast_armor,
                                    checksum)
        else:
            fast = None

        padata = []

        if tgs_req_padata is not None:
            padata.append(tgs_req_padata)

        if fast is not None:
            padata.append(fast)

        if outer_padata is not None:
            padata += outer_padata

        if fast is None:
            padata += additional_padata

        if not padata:
            padata = None

        kdc_exchange_dict['req_padata'] = padata
        kdc_exchange_dict['fast_padata'] = fast_padata
        kdc_exchange_dict['req_body'] = inner_req_body

        req_obj, req_decoded = self.KDC_REQ_create(msg_type=req_msg_type,
                                                   padata=padata,
                                                   req_body=req_body,
                                                   asn1Spec=req_asn1Spec())

        kdc_exchange_dict['req_obj'] = req_obj

        to_rodc = kdc_exchange_dict['to_rodc']

        rep = self.send_recv_transaction(req_decoded, to_rodc=to_rodc)
        self.assertIsNotNone(rep)

        msg_type = self.getElementValue(rep, 'msg-type')
        self.assertIsNotNone(msg_type)

        expected_msg_type = None
        if check_error_fn is not None:
            expected_msg_type = KRB_ERROR
            self.assertIsNone(check_rep_fn)
            self.assertNotEqual(0, len(expected_error_mode))
            self.assertNotIn(0, expected_error_mode)
        if check_rep_fn is not None:
            expected_msg_type = rep_msg_type
            self.assertIsNone(check_error_fn)
            self.assertEqual(0, len(expected_error_mode))
        self.assertIsNotNone(expected_msg_type)
        if msg_type == KRB_ERROR:
            error_code = self.getElementValue(rep, 'error-code')
            fail_msg = f'Got unexpected error: {error_code}'
        else:
            fail_msg = f'Expected to fail with error: {expected_error_mode}'
        self.assertEqual(msg_type, expected_msg_type, fail_msg)

        if msg_type == KRB_ERROR:
            return check_error_fn(kdc_exchange_dict,
                                  callback_dict,
                                  rep)

        return check_rep_fn(kdc_exchange_dict, callback_dict, rep)

    def as_exchange_dict(self,
                         creds=None,
                         client_cert=None,
                         expected_crealm=None,
                         expected_cname=None,
                         expected_anon=False,
                         expected_srealm=None,
                         expected_sname=None,
                         expected_account_name=None,
                         expected_groups=None,
                         unexpected_groups=None,
                         expected_upn_name=None,
                         expected_sid=None,
                         expected_requester_sid=None,
                         expected_domain_sid=None,
                         expected_device_domain_sid=None,
                         expected_supported_etypes=None,
                         expected_flags=None,
                         unexpected_flags=None,
                         ticket_decryption_key=None,
                         expect_ticket_checksum=None,
                         expect_full_checksum=None,
                         generate_fast_fn=None,
                         generate_fast_armor_fn=None,
                         generate_fast_padata_fn=None,
                         fast_armor_type=FX_FAST_ARMOR_AP_REQUEST,
                         generate_padata_fn=None,
                         check_error_fn=None,
                         check_rep_fn=None,
                         check_kdc_private_fn=None,
                         check_patypes=True,
                         callback_dict=None,
                         expected_error_mode=0,
                         expect_status=None,
                         expected_status=None,
                         expected_salt=None,
                         authenticator_subkey=None,
                         preauth_key=None,
                         armor_key=None,
                         armor_tgt=None,
                         armor_subkey=None,
                         auth_data=None,
                         kdc_options='',
                         inner_req=None,
                         outer_req=None,
                         pac_request=None,
                         pac_options=None,
                         ap_options=None,
                         fast_ap_options=None,
                         strict_edata_checking=True,
                         using_pkinit=PkInit.NOT_USED,
                         pk_nonce=None,
                         expect_edata=None,
                         expect_pac=True,
                         expect_client_claims=None,
                         expect_device_info=None,
                         expect_device_claims=None,
                         expect_upn_dns_info_ex=None,
                         expect_pac_attrs=None,
                         expect_pac_attrs_pac_request=None,
                         expect_requester_sid=None,
                         rc4_support=True,
                         expected_client_claims=None,
                         unexpected_client_claims=None,
                         expected_device_claims=None,
                         unexpected_device_claims=None,
                         expect_resource_groups_flag=None,
                         expected_device_groups=None,
                         expected_extra_pac_buffers=None,
                         expect_matching_nt_hash_in_pac=None,
                         to_rodc=False):
        if expected_error_mode == 0:
            expected_error_mode = ()
        elif not isinstance(expected_error_mode, collections.abc.Container):
            expected_error_mode = (expected_error_mode,)

        kdc_exchange_dict = {
            'req_msg_type': KRB_AS_REQ,
            'req_asn1Spec': krb5_asn1.AS_REQ,
            'rep_msg_type': KRB_AS_REP,
            'rep_asn1Spec': krb5_asn1.AS_REP,
            'rep_encpart_asn1Spec': krb5_asn1.EncASRepPart,
            'creds': creds,
            'client_cert': client_cert,
            'expected_crealm': expected_crealm,
            'expected_cname': expected_cname,
            'expected_anon': expected_anon,
            'expected_srealm': expected_srealm,
            'expected_sname': expected_sname,
            'expected_account_name': expected_account_name,
            'expected_groups': expected_groups,
            'unexpected_groups': unexpected_groups,
            'expected_upn_name': expected_upn_name,
            'expected_sid': expected_sid,
            'expected_requester_sid': expected_requester_sid,
            'expected_domain_sid': expected_domain_sid,
            'expected_device_domain_sid': expected_device_domain_sid,
            'expected_supported_etypes': expected_supported_etypes,
            'expected_flags': expected_flags,
            'unexpected_flags': unexpected_flags,
            'ticket_decryption_key': ticket_decryption_key,
            'expect_ticket_checksum': expect_ticket_checksum,
            'expect_full_checksum': expect_full_checksum,
            'expect_ticket_kvno': True,
            'generate_fast_fn': generate_fast_fn,
            'generate_fast_armor_fn': generate_fast_armor_fn,
            'generate_fast_padata_fn': generate_fast_padata_fn,
            'fast_armor_type': fast_armor_type,
            'generate_padata_fn': generate_padata_fn,
            'check_error_fn': check_error_fn,
            'check_rep_fn': check_rep_fn,
            'check_kdc_private_fn': check_kdc_private_fn,
            'check_patypes': check_patypes,
            'callback_dict': callback_dict,
            'expected_error_mode': expected_error_mode,
            'expect_status': expect_status,
            'expected_status': expected_status,
            'expected_salt': expected_salt,
            'authenticator_subkey': authenticator_subkey,
            'preauth_key': preauth_key,
            'armor_key': armor_key,
            'armor_tgt': armor_tgt,
            'armor_subkey': armor_subkey,
            'auth_data': auth_data,
            'kdc_options': kdc_options,
            'inner_req': inner_req,
            'outer_req': outer_req,
            'pac_request': pac_request,
            'pac_options': pac_options,
            'ap_options': ap_options,
            'fast_ap_options': fast_ap_options,
            'strict_edata_checking': strict_edata_checking,
            'using_pkinit': using_pkinit,
            'pk_nonce': pk_nonce,
            'expect_edata': expect_edata,
            'expect_pac': expect_pac,
            'expect_client_claims': expect_client_claims,
            'expect_device_info': expect_device_info,
            'expect_device_claims': expect_device_claims,
            'expect_upn_dns_info_ex': expect_upn_dns_info_ex,
            'expect_pac_attrs': expect_pac_attrs,
            'expect_pac_attrs_pac_request': expect_pac_attrs_pac_request,
            'expect_requester_sid': expect_requester_sid,
            'rc4_support': rc4_support,
            'expected_client_claims': expected_client_claims,
            'unexpected_client_claims': unexpected_client_claims,
            'expected_device_claims': expected_device_claims,
            'unexpected_device_claims': unexpected_device_claims,
            'expect_resource_groups_flag': expect_resource_groups_flag,
            'expected_device_groups': expected_device_groups,
            'expected_extra_pac_buffers': expected_extra_pac_buffers,
            'expect_matching_nt_hash_in_pac': expect_matching_nt_hash_in_pac,
            'to_rodc': to_rodc
        }
        if callback_dict is None:
            callback_dict = {}

        return kdc_exchange_dict

    def tgs_exchange_dict(self,
                          creds=None,
                          expected_crealm=None,
                          expected_cname=None,
                          expected_anon=False,
                          expected_srealm=None,
                          expected_sname=None,
                          expected_account_name=None,
                          expected_groups=None,
                          unexpected_groups=None,
                          expected_upn_name=None,
                          expected_sid=None,
                          expected_requester_sid=None,
                          expected_domain_sid=None,
                          expected_device_domain_sid=None,
                          expected_supported_etypes=None,
                          expected_flags=None,
                          unexpected_flags=None,
                          ticket_decryption_key=None,
                          expect_ticket_checksum=None,
                          expect_full_checksum=None,
                          expect_ticket_kvno=True,
                          generate_fast_fn=None,
                          generate_fast_armor_fn=None,
                          generate_fast_padata_fn=None,
                          fast_armor_type=FX_FAST_ARMOR_AP_REQUEST,
                          generate_padata_fn=None,
                          check_error_fn=None,
                          check_rep_fn=None,
                          check_kdc_private_fn=None,
                          check_patypes=True,
                          expected_error_mode=0,
                          expect_status=None,
                          expected_status=None,
                          callback_dict=None,
                          tgt=None,
                          armor_key=None,
                          armor_tgt=None,
                          armor_subkey=None,
                          authenticator_subkey=None,
                          auth_data=None,
                          body_checksum_type=None,
                          kdc_options='',
                          inner_req=None,
                          outer_req=None,
                          pac_request=None,
                          pac_options=None,
                          ap_options=None,
                          fast_ap_options=None,
                          strict_edata_checking=True,
                          expect_edata=None,
                          expect_pac=True,
                          expect_client_claims=None,
                          expect_device_info=None,
                          expect_device_claims=None,
                          expect_upn_dns_info_ex=None,
                          expect_pac_attrs=None,
                          expect_pac_attrs_pac_request=None,
                          expect_requester_sid=None,
                          expected_proxy_target=None,
                          expected_transited_services=None,
                          rc4_support=True,
                          expected_client_claims=None,
                          unexpected_client_claims=None,
                          expected_device_claims=None,
                          unexpected_device_claims=None,
                          expect_resource_groups_flag=None,
                          expected_device_groups=None,
                          expected_extra_pac_buffers=None,
                          to_rodc=False):
        if expected_error_mode == 0:
            expected_error_mode = ()
        elif not isinstance(expected_error_mode, collections.abc.Container):
            expected_error_mode = (expected_error_mode,)

        kdc_exchange_dict = {
            'req_msg_type': KRB_TGS_REQ,
            'req_asn1Spec': krb5_asn1.TGS_REQ,
            'rep_msg_type': KRB_TGS_REP,
            'rep_asn1Spec': krb5_asn1.TGS_REP,
            'rep_encpart_asn1Spec': krb5_asn1.EncTGSRepPart,
            'creds': creds,
            'expected_crealm': expected_crealm,
            'expected_cname': expected_cname,
            'expected_anon': expected_anon,
            'expected_srealm': expected_srealm,
            'expected_sname': expected_sname,
            'expected_account_name': expected_account_name,
            'expected_groups': expected_groups,
            'unexpected_groups': unexpected_groups,
            'expected_upn_name': expected_upn_name,
            'expected_sid': expected_sid,
            'expected_requester_sid': expected_requester_sid,
            'expected_domain_sid': expected_domain_sid,
            'expected_device_domain_sid': expected_device_domain_sid,
            'expected_supported_etypes': expected_supported_etypes,
            'expected_flags': expected_flags,
            'unexpected_flags': unexpected_flags,
            'ticket_decryption_key': ticket_decryption_key,
            'expect_ticket_checksum': expect_ticket_checksum,
            'expect_full_checksum': expect_full_checksum,
            'expect_ticket_kvno': expect_ticket_kvno,
            'generate_fast_fn': generate_fast_fn,
            'generate_fast_armor_fn': generate_fast_armor_fn,
            'generate_fast_padata_fn': generate_fast_padata_fn,
            'fast_armor_type': fast_armor_type,
            'generate_padata_fn': generate_padata_fn,
            'check_error_fn': check_error_fn,
            'check_rep_fn': check_rep_fn,
            'check_kdc_private_fn': check_kdc_private_fn,
            'check_patypes': check_patypes,
            'callback_dict': callback_dict,
            'expected_error_mode': expected_error_mode,
            'expect_status': expect_status,
            'expected_status': expected_status,
            'tgt': tgt,
            'body_checksum_type': body_checksum_type,
            'armor_key': armor_key,
            'armor_tgt': armor_tgt,
            'armor_subkey': armor_subkey,
            'auth_data': auth_data,
            'authenticator_subkey': authenticator_subkey,
            'kdc_options': kdc_options,
            'inner_req': inner_req,
            'outer_req': outer_req,
            'pac_request': pac_request,
            'pac_options': pac_options,
            'ap_options': ap_options,
            'fast_ap_options': fast_ap_options,
            'strict_edata_checking': strict_edata_checking,
            'expect_edata': expect_edata,
            'expect_pac': expect_pac,
            'expect_client_claims': expect_client_claims,
            'expect_device_info': expect_device_info,
            'expect_device_claims': expect_device_claims,
            'expect_upn_dns_info_ex': expect_upn_dns_info_ex,
            'expect_pac_attrs': expect_pac_attrs,
            'expect_pac_attrs_pac_request': expect_pac_attrs_pac_request,
            'expect_requester_sid': expect_requester_sid,
            'expected_proxy_target': expected_proxy_target,
            'expected_transited_services': expected_transited_services,
            'rc4_support': rc4_support,
            'expected_client_claims': expected_client_claims,
            'unexpected_client_claims': unexpected_client_claims,
            'expected_device_claims': expected_device_claims,
            'unexpected_device_claims': unexpected_device_claims,
            'expect_resource_groups_flag': expect_resource_groups_flag,
            'expected_device_groups': expected_device_groups,
            'expected_extra_pac_buffers': expected_extra_pac_buffers,
            'to_rodc': to_rodc
        }
        if callback_dict is None:
            callback_dict = {}

        return kdc_exchange_dict

    def generic_check_kdc_rep(self,
                              kdc_exchange_dict,
                              callback_dict,
                              rep):

        expected_crealm = kdc_exchange_dict['expected_crealm']
        expected_anon = kdc_exchange_dict['expected_anon']
        expected_srealm = kdc_exchange_dict['expected_srealm']
        expected_sname = kdc_exchange_dict['expected_sname']
        ticket_decryption_key = kdc_exchange_dict['ticket_decryption_key']
        check_kdc_private_fn = kdc_exchange_dict['check_kdc_private_fn']
        rep_encpart_asn1Spec = kdc_exchange_dict['rep_encpart_asn1Spec']
        msg_type = kdc_exchange_dict['rep_msg_type']
        armor_key = kdc_exchange_dict['armor_key']
        expect_ticket_kvno = kdc_exchange_dict['expect_ticket_kvno']

        self.assertElementEqual(rep, 'msg-type', msg_type)  # AS-REP | TGS-REP
        padata = self.getElementValue(rep, 'padata')
        if self.strict_checking:
            self.assertElementEqualUTF8(rep, 'crealm', expected_crealm)
        if self.cname_checking:
            if expected_anon:
                expected_cname = self.PrincipalName_create(
                    name_type=NT_WELLKNOWN,
                    names=['WELLKNOWN', 'ANONYMOUS'])
            else:
                expected_cname = kdc_exchange_dict['expected_cname']
            self.assertElementEqualPrincipal(rep, 'cname', expected_cname)
        self.assertElementPresent(rep, 'ticket')
        ticket = self.getElementValue(rep, 'ticket')
        ticket_encpart = None
        ticket_cipher = None
        self.assertIsNotNone(ticket)
        if ticket is not None:  # Never None, but gives indentation
            self.assertElementEqual(ticket, 'tkt-vno', 5)
            self.assertElementEqualUTF8(ticket, 'realm', expected_srealm)
            self.assertElementEqualPrincipal(ticket, 'sname', expected_sname)
            self.assertElementPresent(ticket, 'enc-part')
            ticket_encpart = self.getElementValue(ticket, 'enc-part')
            self.assertIsNotNone(ticket_encpart)
            if ticket_encpart is not None:  # Never None, but gives indentation
                self.assertElementPresent(ticket_encpart, 'etype')

                kdc_options = kdc_exchange_dict['kdc_options']
                pos = len(tuple(krb5_asn1.KDCOptions('enc-tkt-in-skey'))) - 1
                expect_kvno = (pos >= len(kdc_options)
                               or kdc_options[pos] != '1')
                if expect_ticket_kvno and expect_kvno:
                    # 'unspecified' means present, with any value != 0
                    self.assertElementKVNO(ticket_encpart, 'kvno',
                                           self.unspecified_kvno)
                else:
                    # For user-to-user, don't expect a kvno.
                    self.assertElementMissing(ticket_encpart, 'kvno')

                self.assertElementPresent(ticket_encpart, 'cipher')
                ticket_cipher = self.getElementValue(ticket_encpart, 'cipher')
        self.assertElementPresent(rep, 'enc-part')
        encpart = self.getElementValue(rep, 'enc-part')
        encpart_cipher = None
        self.assertIsNotNone(encpart)
        if encpart is not None:  # Never None, but gives indentation
            self.assertElementPresent(encpart, 'etype')
            self.assertElementKVNO(ticket_encpart, 'kvno', 'autodetect')
            self.assertElementPresent(encpart, 'cipher')
            encpart_cipher = self.getElementValue(encpart, 'cipher')

        if self.padata_checking:
            self.check_reply_padata(kdc_exchange_dict,
                                    callback_dict,
                                    encpart,
                                    padata)

        ticket_checksum = None

        # Get the decryption key for the encrypted part
        encpart_decryption_key, encpart_decryption_usage = (
            self.get_preauth_key(kdc_exchange_dict))

        pa_dict = self.get_pa_dict(padata)

        pk_as_rep = pa_dict.get(PADATA_PK_AS_REP)
        if pk_as_rep is not None:
            pk_as_rep_asn1_spec = krb5_asn1.PA_PK_AS_REP
            reply_key_pack_asn1_spec = krb5_asn1.ReplyKeyPack
            pk_win2k = False
        else:
            pk_as_rep = pa_dict.get(PADATA_PK_AS_REP_19)
            pk_as_rep_asn1_spec = krb5_asn1.PA_PK_AS_REP_Win2k
            reply_key_pack_asn1_spec = krb5_asn1.ReplyKeyPack_Win2k
            pk_win2k = True
        if pk_as_rep is not None:
            pk_as_rep = self.der_decode(pk_as_rep,
                                        asn1Spec=pk_as_rep_asn1_spec())

            using_pkinit = kdc_exchange_dict['using_pkinit']
            if using_pkinit is PkInit.PUBLIC_KEY:
                content_info = self.der_decode(
                    pk_as_rep['encKeyPack'],
                    asn1Spec=krb5_asn1.ContentInfo())
                self.assertEqual(str(krb5_asn1.id_envelopedData),
                                 content_info['contentType'])

                content = self.der_decode(content_info['content'],
                                          asn1Spec=krb5_asn1.EnvelopedData())

                self.assertEqual(0, content['version'])
                originator_info = content['originatorInfo']
                self.assertFalse(originator_info.get('certs'))
                self.assertFalse(originator_info.get('crls'))
                self.assertFalse(content.get('unprotectedAttrs'))

                encrypted_content_info = content['encryptedContentInfo']
                recipient_infos = content['recipientInfos']

                self.assertEqual(1, len(recipient_infos))
                ktri = recipient_infos[0]['ktri']

                if self.strict_checking:
                    self.assertEqual(0, ktri['version'])

                private_key = encpart_decryption_key
                self.assertIsInstance(private_key,
                                      asymmetric.rsa.RSAPrivateKey)

                client_subject_key_id = (
                    x509.SubjectKeyIdentifier.from_public_key(
                        private_key.public_key()))

                # Check that the client certificate is named as the recipient.
                ktri_rid = ktri['rid']
                try:
                    issuer_and_serial_number = ktri_rid[
                        'issuerAndSerialNumber']
                except KeyError:
                    subject_key_id = ktri_rid['subjectKeyIdentifier']
                    self.assertEqual(subject_key_id,
                                     client_subject_key_id.digest)
                else:
                    client_certificate = kdc_exchange_dict['client_cert']

                    self.assertIsNotNone(issuer_and_serial_number['issuer'])
                    self.assertEqual(issuer_and_serial_number['serialNumber'],
                                     client_certificate.serial_number)

                key_encryption_algorithm = ktri['keyEncryptionAlgorithm']
                self.assertEqual(str(krb5_asn1.rsaEncryption),
                                 key_encryption_algorithm['algorithm'])
                if self.strict_checking:
                    self.assertEqual(
                        b'\x05\x00',
                        key_encryption_algorithm.get('parameters'))

                encrypted_key = ktri['encryptedKey']

                # Decrypt the key.
                pad_len = 256 - len(encrypted_key)
                if pad_len:
                    encrypted_key = bytes(pad_len) + encrypted_key
                decrypted_key = private_key.decrypt(
                    encrypted_key,
                    padding=asymmetric.padding.PKCS1v15())

                self.assertEqual(str(krb5_asn1.id_signedData),
                                 encrypted_content_info['contentType'])

                encrypted_content = encrypted_content_info['encryptedContent']
                encryption_algorithm = encrypted_content_info[
                    'contentEncryptionAlgorithm']

                cipher_algorithm = self.cipher_from_algorithm(encryption_algorithm['algorithm'])

                # This will serve as the IV.
                parameters = self.der_decode(
                    encryption_algorithm['parameters'],
                    asn1Spec=krb5_asn1.CMSCBCParameter())

                # Decrypt the content.
                cipher = Cipher(cipher_algorithm(decrypted_key),
                                modes.CBC(parameters),
                                default_backend())
                decryptor = cipher.decryptor()
                decrypted_content = decryptor.update(encrypted_content)
                decrypted_content += decryptor.finalize()

                # The padding doesn’t fully comply to PKCS7 with a specified
                # blocksize, so we must unpad the data ourselves.
                decrypted_content = self.unpad(decrypted_content)

                signed_data = None
                signed_data_rfc2315 = None

                first_tag = decrypted_content[0]
                if first_tag == 0x30:  # ASN.1 SEQUENCE tag
                    signed_data = decrypted_content
                else:
                    # Windows encodes the ASN.1 incorrectly, neglecting to add
                    # the SEQUENCE tag. We’ll have to prepend it ourselves in
                    # order for the decoding to work.
                    encoded_len = self.asn1_length(decrypted_content)
                    decrypted_content = bytes([0x30]) + encoded_len + (
                        decrypted_content)

                    if first_tag == 0x02:  # ASN.1 INTEGER tag

                        # The INTEGER tag indicates that the data is encoded
                        # with the earlier variant of the SignedData ASN.1
                        # schema specified in RFC2315, as per [MS-PKCA] 2.2.4
                        # (PA-PK-AS-REP).
                        signed_data_rfc2315 = decrypted_content

                    elif first_tag == 0x06:  # ASN.1 OBJECT IDENTIFIER tag

                        # The OBJECT IDENTIFIER tag indicates that the data is
                        # encoded as SignedData and wrapped in a ContentInfo
                        # structure, which we shall have to decode first. This
                        # seems to be the case when the supportedCMSTypes field
                        # in the client’s AuthPack is missing or empty.

                        content_info = self.der_decode(
                            decrypted_content,
                            asn1Spec=krb5_asn1.ContentInfo())
                        self.assertEqual(str(krb5_asn1.id_signedData),
                                         content_info['contentType'])
                        signed_data = content_info['content']
                    else:
                        self.fail(f'got reply with unknown initial tag '
                                  f'({first_tag})')

                if signed_data is not None:
                    signed_data = self.der_decode(
                        signed_data, asn1Spec=krb5_asn1.SignedData())

                    encap_content_info = signed_data['encapContentInfo']

                    content_type = encap_content_info['eContentType']
                    content = encap_content_info['eContent']
                elif signed_data_rfc2315 is not None:
                    signed_data = self.der_decode(
                        signed_data_rfc2315,
                        asn1Spec=krb5_asn1.SignedData_RFC2315())

                    encap_content_info = signed_data['contentInfo']

                    content_type = encap_content_info['contentType']
                    content = self.der_decode(
                        encap_content_info['content'],
                        asn1Spec=pyasn1.type.univ.OctetString())
                else:
                    self.fail('we must have got SignedData')

                self.assertEqual(str(krb5_asn1.id_pkinit_rkeyData),
                                 content_type)
                reply_key_pack = self.der_decode(
                    content, asn1Spec=reply_key_pack_asn1_spec())

                req_obj = kdc_exchange_dict['req_obj']
                req_asn1Spec = kdc_exchange_dict['req_asn1Spec']
                req_obj = self.der_encode(req_obj,
                                          asn1Spec=req_asn1Spec())

                reply_key = reply_key_pack['replyKey']

                # Reply the encpart decryption key with the decrypted key from
                # the reply.
                encpart_decryption_key = self.SessionKey_create(
                    etype=reply_key['keytype'],
                    contents=reply_key['keyvalue'],
                    kvno=None)

                if not pk_win2k:
                    as_checksum = reply_key_pack['asChecksum']

                    # Verify the checksum over the AS request body.
                    kcrypto.verify_checksum(as_checksum['cksumtype'],
                                            encpart_decryption_key.key,
                                            KU_PKINIT_AS_REQ,
                                            req_obj,
                                            as_checksum['checksum'])
            elif using_pkinit is PkInit.DIFFIE_HELLMAN:
                content_info = self.der_decode(
                    pk_as_rep['dhInfo']['dhSignedData'],
                    asn1Spec=krb5_asn1.ContentInfo())
                self.assertEqual(str(krb5_asn1.id_signedData),
                                 content_info['contentType'])

                signed_data = self.der_decode(content_info['content'],
                                              asn1Spec=krb5_asn1.SignedData())

                encap_content_info = signed_data['encapContentInfo']
                content = encap_content_info['eContent']

                self.assertEqual(str(krb5_asn1.id_pkinit_DHKeyData),
                                 encap_content_info['eContentType'])

                dh_key_info = self.der_decode(
                    content, asn1Spec=krb5_asn1.KDCDHKeyInfo())

                self.assertNotIn('dhKeyExpiration', dh_key_info)

                dh_private_key = encpart_decryption_key
                self.assertIsInstance(dh_private_key,
                                      asymmetric.dh.DHPrivateKey)

                self.assertElementEqual(dh_key_info, 'nonce',
                                        kdc_exchange_dict['pk_nonce'])

                dh_public_key_data = self.bytes_from_bit_string(
                    dh_key_info['subjectPublicKey'])
                dh_public_key_decoded = self.der_decode(
                    dh_public_key_data, asn1Spec=krb5_asn1.DHPublicKey())

                dh_numbers = dh_private_key.parameters().parameter_numbers()

                public_numbers = asymmetric.dh.DHPublicNumbers(
                    dh_public_key_decoded, dh_numbers)
                dh_public_key = public_numbers.public_key(default_backend())

                # Perform the Diffie-Hellman key exchange.
                shared_secret = dh_private_key.exchange(dh_public_key)

                # Pad the shared secret out to the length of ‘p’.
                p_len = self.length_in_bytes(dh_numbers.p)
                padding_len = p_len - len(shared_secret)
                self.assertGreaterEqual(padding_len, 0)
                padded_shared_secret = bytes(padding_len) + shared_secret

                reply_key_enc_type = self.expected_etype(kdc_exchange_dict)

                # At the moment, we don’t specify a nonce in the request, so we
                # can assume these are empty.
                client_nonce = b''
                server_nonce = b''

                ciphertext = padded_shared_secret + client_nonce + server_nonce

                # Replace the encpart decryption key with the key derived from
                # the Diffie-Hellman key exchange.
                encpart_decryption_key = self.octetstring2key(
                    ciphertext, reply_key_enc_type)
            else:
                self.fail(f'invalid value for using_pkinit: {using_pkinit}')

            self.assertEqual(3, signed_data['version'])

            digest_algorithms = signed_data['digestAlgorithms']
            self.assertEqual(1, len(digest_algorithms))
            digest_algorithm = digest_algorithms[0]
            # Ensure the hash algorithm is valid.
            _ = self.hash_from_algorithm_id(digest_algorithm)

            self.assertFalse(signed_data.get('crls'))

            signer_infos = signed_data['signerInfos']
            self.assertEqual(1, len(signer_infos))
            signer_info = signer_infos[0]

            self.assertEqual(1, signer_info['version'])

            # Get the certificate presented by the KDC.
            kdc_certificates = signed_data['certificates']
            self.assertEqual(1, len(kdc_certificates))
            kdc_certificate = self.der_encode(
                kdc_certificates[0], asn1Spec=krb5_asn1.CertificateChoices())
            kdc_certificate = x509.load_der_x509_certificate(kdc_certificate,
                                                             default_backend())

            # Verify that the KDC’s certificate is named as the signer.
            sid = signer_info['sid']
            try:
                issuer_and_serial_number = sid['issuerAndSerialNumber']
            except KeyError:
                extension = kdc_certificate.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                cert_subject_key_id = extension.value.digest
                self.assertEqual(sid['subjectKeyIdentifier'], cert_subject_key_id)
            else:
                self.assertIsNotNone(issuer_and_serial_number['issuer'])
                self.assertEqual(issuer_and_serial_number['serialNumber'],
                                 kdc_certificate.serial_number)

            digest_algorithm = signer_info['digestAlgorithm']
            digest_hash_fn = self.hash_from_algorithm_id(digest_algorithm)

            signed_attrs = signer_info['signedAttrs']
            self.assertEqual(2, len(signed_attrs))

            signed_attr0 = signed_attrs[0]
            self.assertEqual(str(krb5_asn1.id_contentType),
                             signed_attr0['type'])
            signed_attr0_values = signed_attr0['values']
            self.assertEqual(1, len(signed_attr0_values))
            signed_attr0_value = self.der_decode(
                signed_attr0_values[0],
                asn1Spec=krb5_asn1.ContentType())
            if using_pkinit is PkInit.DIFFIE_HELLMAN:
                self.assertEqual(str(krb5_asn1.id_pkinit_DHKeyData),
                                 signed_attr0_value)
            else:
                self.assertEqual(str(krb5_asn1.id_pkinit_rkeyData),
                                 signed_attr0_value)

            signed_attr1 = signed_attrs[1]
            self.assertEqual(str(krb5_asn1.id_messageDigest),
                             signed_attr1['type'])
            signed_attr1_values = signed_attr1['values']
            self.assertEqual(1, len(signed_attr1_values))
            message_digest = self.der_decode(signed_attr1_values[0],
                                             krb5_asn1.MessageDigest())

            signature_algorithm = signer_info['signatureAlgorithm']
            hash_fn = self.hash_from_algorithm_id(signature_algorithm)

            # Compute the hash of the content to be signed. With the
            # Diffie-Hellman key exchange, this signature is over the type
            # KDCDHKeyInfo; otherwise, it is over the type ReplyKeyPack.
            digest = hashes.Hash(digest_hash_fn(), default_backend())
            digest.update(content)
            digest = digest.finalize()

            # Verify the hash. Note: this is a non–constant time comparison.
            self.assertEqual(digest, message_digest)

            # Re-encode the attributes ready for verifying the signature.
            cms_attrs = self.der_encode(signed_attrs,
                                        asn1Spec=krb5_asn1.CMSAttributes())

            # Verify the signature.
            kdc_public_key = kdc_certificate.public_key()
            kdc_public_key.verify(
                signer_info['signature'],
                cms_attrs,
                asymmetric.padding.PKCS1v15(),
                hash_fn())

            self.assertFalse(signer_info.get('unsignedAttrs'))

        if armor_key is not None:
            if PADATA_FX_FAST in pa_dict:
                fx_fast_data = pa_dict[PADATA_FX_FAST]
                fast_response = self.check_fx_fast_data(kdc_exchange_dict,
                                                        fx_fast_data,
                                                        armor_key,
                                                        finished=True)

                if 'strengthen-key' in fast_response:
                    strengthen_key = self.EncryptionKey_import(
                        fast_response['strengthen-key'])
                    encpart_decryption_key = (
                        self.generate_strengthen_reply_key(
                            strengthen_key,
                            encpart_decryption_key))

                fast_finished = fast_response.get('finished')
                if fast_finished is not None:
                    ticket_checksum = fast_finished['ticket-checksum']

                self.check_rep_padata(kdc_exchange_dict,
                                      callback_dict,
                                      fast_response['padata'],
                                      error_code=0)

        ticket_private = None
        if ticket_decryption_key is not None:
            self.assertElementEqual(ticket_encpart, 'etype',
                                    ticket_decryption_key.etype)
            self.assertElementKVNO(ticket_encpart, 'kvno',
                                   ticket_decryption_key.kvno)
            ticket_decpart = ticket_decryption_key.decrypt(KU_TICKET,
                                                           ticket_cipher)
            ticket_private = self.der_decode(
                ticket_decpart,
                asn1Spec=krb5_asn1.EncTicketPart())

        encpart_private = None
        self.assertIsNotNone(encpart_decryption_key)
        if encpart_decryption_key is not None:
            self.assertElementEqual(encpart, 'etype',
                                    encpart_decryption_key.etype)
            if self.strict_checking:
                self.assertElementKVNO(encpart, 'kvno',
                                       encpart_decryption_key.kvno)
            rep_decpart = encpart_decryption_key.decrypt(
                encpart_decryption_usage,
                encpart_cipher)
            # MIT KDC encodes both EncASRepPart and EncTGSRepPart with
            # application tag 26
            try:
                encpart_private = self.der_decode(
                    rep_decpart,
                    asn1Spec=rep_encpart_asn1Spec())
            except Exception:
                encpart_private = self.der_decode(
                    rep_decpart,
                    asn1Spec=krb5_asn1.EncTGSRepPart())

        kdc_exchange_dict['reply_key'] = encpart_decryption_key

        self.assertIsNotNone(check_kdc_private_fn)
        if check_kdc_private_fn is not None:
            check_kdc_private_fn(kdc_exchange_dict, callback_dict,
                                 rep, ticket_private, encpart_private,
                                 ticket_checksum)

        return rep

    def check_fx_fast_data(self,
                           kdc_exchange_dict,
                           fx_fast_data,
                           armor_key,
                           finished=False,
                           expect_strengthen_key=True):
        fx_fast_data = self.der_decode(fx_fast_data,
                                       asn1Spec=krb5_asn1.PA_FX_FAST_REPLY())

        enc_fast_rep = fx_fast_data['armored-data']['enc-fast-rep']
        self.assertEqual(enc_fast_rep['etype'], armor_key.etype)

        fast_rep = armor_key.decrypt(KU_FAST_REP, enc_fast_rep['cipher'])

        fast_response = self.der_decode(fast_rep,
                                        asn1Spec=krb5_asn1.KrbFastResponse())

        if expect_strengthen_key and self.strict_checking:
            self.assertIn('strengthen-key', fast_response)

        if finished:
            self.assertIn('finished', fast_response)

        # Ensure that the nonce matches the nonce in the body of the request
        # (RFC6113 5.4.3).
        nonce = kdc_exchange_dict['nonce']
        self.assertEqual(nonce, fast_response['nonce'])

        return fast_response

    def generic_check_kdc_private(self,
                                  kdc_exchange_dict,
                                  callback_dict,
                                  rep,
                                  ticket_private,
                                  encpart_private,
                                  ticket_checksum):
        kdc_options = kdc_exchange_dict['kdc_options']
        canon_pos = len(tuple(krb5_asn1.KDCOptions('canonicalize'))) - 1
        canonicalize = (canon_pos < len(kdc_options)
                        and kdc_options[canon_pos] == '1')
        renewable_pos = len(tuple(krb5_asn1.KDCOptions('renewable'))) - 1
        renewable = (renewable_pos < len(kdc_options)
                     and kdc_options[renewable_pos] == '1')
        renew_pos = len(tuple(krb5_asn1.KDCOptions('renew'))) - 1
        renew = (renew_pos < len(kdc_options)
                 and kdc_options[renew_pos] == '1')
        expect_renew_till = renewable or renew

        expected_crealm = kdc_exchange_dict['expected_crealm']
        expected_cname = kdc_exchange_dict['expected_cname']
        expected_srealm = kdc_exchange_dict['expected_srealm']
        expected_sname = kdc_exchange_dict['expected_sname']
        ticket_decryption_key = kdc_exchange_dict['ticket_decryption_key']

        rep_msg_type = kdc_exchange_dict['rep_msg_type']

        expected_flags = kdc_exchange_dict.get('expected_flags')
        unexpected_flags = kdc_exchange_dict.get('unexpected_flags')

        ticket = self.getElementValue(rep, 'ticket')

        if ticket_checksum is not None:
            armor_key = kdc_exchange_dict['armor_key']
            self.verify_ticket_checksum(ticket, ticket_checksum, armor_key)

        to_rodc = kdc_exchange_dict['to_rodc']
        if to_rodc:
            krbtgt_creds = self.get_rodc_krbtgt_creds()
        else:
            krbtgt_creds = self.get_krbtgt_creds()
        krbtgt_key = self.TicketDecryptionKey_from_creds(krbtgt_creds)

        krbtgt_keys = [krbtgt_key]
        if not self.strict_checking:
            krbtgt_key_rc4 = self.TicketDecryptionKey_from_creds(
                krbtgt_creds,
                etype=kcrypto.Enctype.RC4)
            krbtgt_keys.append(krbtgt_key_rc4)

        if self.expect_pac and self.is_tgs(expected_sname):
            expect_pac = True
        else:
            expect_pac = kdc_exchange_dict['expect_pac']

        ticket_session_key = None
        if ticket_private is not None:
            self.assertElementFlags(ticket_private, 'flags',
                                    expected_flags,
                                    unexpected_flags)
            self.assertElementPresent(ticket_private, 'key')
            ticket_key = self.getElementValue(ticket_private, 'key')
            self.assertIsNotNone(ticket_key)
            if ticket_key is not None:  # Never None, but gives indentation
                self.assertElementPresent(ticket_key, 'keytype')
                self.assertElementPresent(ticket_key, 'keyvalue')
                ticket_session_key = self.EncryptionKey_import(ticket_key)
            self.assertElementEqualUTF8(ticket_private, 'crealm',
                                        expected_crealm)
            if self.cname_checking:
                self.assertElementEqualPrincipal(ticket_private, 'cname',
                                                 expected_cname)
            self.assertElementPresent(ticket_private, 'transited')
            self.assertElementPresent(ticket_private, 'authtime')
            if self.strict_checking:
                self.assertElementPresent(ticket_private, 'starttime')
            self.assertElementPresent(ticket_private, 'endtime')
            if self.strict_checking:
                if expect_renew_till:
                    self.assertElementPresent(ticket_private, 'renew-till')
                else:
                    self.assertElementMissing(ticket_private, 'renew-till')
            if self.strict_checking and \
               self.getElementValue(ticket_private,
                                    'caddr') != []:
                self.assertElementMissing(ticket_private, 'caddr')
            if expect_pac is not None:
                if expect_pac:
                    self.assertElementPresent(ticket_private,
                                              'authorization-data',
                                              expect_empty=not expect_pac)
                else:
                    # It is more correct to not have an authorization-data
                    # present than an empty one.
                    #
                    # https://github.com/krb5/krb5/pull/1225#issuecomment-995104193
                    v = self.getElementValue(ticket_private,
                                             'authorization-data')
                    if v is not None:
                        self.assertElementPresent(ticket_private,
                                                  'authorization-data',
                                                  expect_empty=True)

        encpart_session_key = None
        if encpart_private is not None:
            self.assertElementPresent(encpart_private, 'key')
            encpart_key = self.getElementValue(encpart_private, 'key')
            self.assertIsNotNone(encpart_key)
            if encpart_key is not None:  # Never None, but gives indentation
                self.assertElementPresent(encpart_key, 'keytype')
                self.assertElementPresent(encpart_key, 'keyvalue')
                encpart_session_key = self.EncryptionKey_import(encpart_key)
            self.assertElementPresent(encpart_private, 'last-req')
            expected_nonce = kdc_exchange_dict.get('pk_nonce')
            if not expected_nonce:
                expected_nonce = kdc_exchange_dict['nonce']
            self.assertElementEqual(encpart_private, 'nonce',
                                    expected_nonce)
            if rep_msg_type == KRB_AS_REP:
                if self.strict_checking:
                    self.assertElementPresent(encpart_private,
                                              'key-expiration')
            else:
                self.assertElementMissing(encpart_private,
                                          'key-expiration')
            self.assertElementFlags(encpart_private, 'flags',
                                    expected_flags,
                                    unexpected_flags)
            self.assertElementPresent(encpart_private, 'authtime')
            if self.strict_checking:
                self.assertElementPresent(encpart_private, 'starttime')
            self.assertElementPresent(encpart_private, 'endtime')
            if self.strict_checking:
                if expect_renew_till:
                    self.assertElementPresent(encpart_private, 'renew-till')
                else:
                    self.assertElementMissing(encpart_private, 'renew-till')
            self.assertElementEqualUTF8(encpart_private, 'srealm',
                                        expected_srealm)
            self.assertElementEqualPrincipal(encpart_private, 'sname',
                                             expected_sname)
            if self.strict_checking and \
               self.getElementValue(ticket_private,
                                    'caddr') != []:
                self.assertElementMissing(ticket_private, 'caddr')

            sent_pac_options = self.get_sent_pac_options(kdc_exchange_dict)

            sent_enc_pa_rep = self.sent_enc_pa_rep(kdc_exchange_dict)

            enc_padata = self.getElementValue(encpart_private,
                                              'encrypted-pa-data')
            if (canonicalize or '1' in sent_pac_options or (
                    rep_msg_type == KRB_AS_REP and sent_enc_pa_rep)):
                if self.strict_checking:
                    self.assertIsNotNone(enc_padata)

                if enc_padata is not None:
                    enc_pa_dict = self.get_pa_dict(enc_padata)
                    if self.strict_checking:
                        if canonicalize:
                            self.assertIn(PADATA_SUPPORTED_ETYPES, enc_pa_dict)
                        else:
                            self.assertNotIn(PADATA_SUPPORTED_ETYPES,
                                             enc_pa_dict)

                        if '1' in sent_pac_options:
                            self.assertIn(PADATA_PAC_OPTIONS, enc_pa_dict)
                        else:
                            self.assertNotIn(PADATA_PAC_OPTIONS, enc_pa_dict)

                    if rep_msg_type == KRB_AS_REP and sent_enc_pa_rep:
                        self.assertIn(PADATA_REQ_ENC_PA_REP, enc_pa_dict)
                    else:
                        self.assertNotIn(PADATA_REQ_ENC_PA_REP, enc_pa_dict)

                    if PADATA_SUPPORTED_ETYPES in enc_pa_dict and self.strict_checking:
                        expected_supported_etypes = kdc_exchange_dict[
                            'expected_supported_etypes']

                        (supported_etypes,) = struct.unpack(
                            '<L',
                            enc_pa_dict[PADATA_SUPPORTED_ETYPES])

                        ignore_bits = (security.KERB_ENCTYPE_DES_CBC_CRC |
                                       security.KERB_ENCTYPE_DES_CBC_MD5)

                        self.assertEqual(
                            supported_etypes & ~ignore_bits,
                            expected_supported_etypes & ~ignore_bits,
                            f'PADATA_SUPPORTED_ETYPES: got: {supported_etypes} (0x{supported_etypes:X}), '
                            f'expected: {expected_supported_etypes} (0x{expected_supported_etypes:X})')

                    if PADATA_PAC_OPTIONS in enc_pa_dict:
                        pac_options = self.der_decode(
                            enc_pa_dict[PADATA_PAC_OPTIONS],
                            asn1Spec=krb5_asn1.PA_PAC_OPTIONS())

                        self.assertElementEqual(pac_options, 'options',
                                                sent_pac_options)

                    if PADATA_REQ_ENC_PA_REP in enc_pa_dict:
                        enc_pa_rep = enc_pa_dict[PADATA_REQ_ENC_PA_REP]

                        enc_pa_rep = self.der_decode(
                            enc_pa_rep,
                            asn1Spec=krb5_asn1.Checksum())

                        reply_key = kdc_exchange_dict['reply_key']
                        req_obj = kdc_exchange_dict['req_obj']
                        req_asn1Spec = kdc_exchange_dict['req_asn1Spec']

                        req_obj = self.der_encode(req_obj,
                                                  asn1Spec=req_asn1Spec())

                        checksum = enc_pa_rep['checksum']
                        ctype = enc_pa_rep['cksumtype']

                        reply_key.verify_checksum(KU_AS_REQ,
                                                  req_obj,
                                                  ctype,
                                                  checksum)
            else:
                if enc_padata is not None:
                    self.assertEqual(enc_padata, [])

        if ticket_session_key is not None and encpart_session_key is not None:
            self.assertEqual(ticket_session_key.etype,
                             encpart_session_key.etype)
            self.assertEqual(ticket_session_key.key.contents,
                             encpart_session_key.key.contents)
        if encpart_session_key is not None:
            session_key = encpart_session_key
        else:
            session_key = ticket_session_key
        ticket_creds = KerberosTicketCreds(
            ticket,
            session_key,
            crealm=expected_crealm,
            cname=expected_cname,
            srealm=expected_srealm,
            sname=expected_sname,
            decryption_key=ticket_decryption_key,
            ticket_private=ticket_private,
            encpart_private=encpart_private)

        if ticket_private is not None:
            pac_data = self.get_ticket_pac(ticket_creds, expect_pac=expect_pac)
            if expect_pac is True:
                self.assertIsNotNone(pac_data)
            elif expect_pac is False:
                self.assertIsNone(pac_data)

            if pac_data is not None:
                self.check_pac_buffers(pac_data, kdc_exchange_dict)

        expect_ticket_checksum = kdc_exchange_dict['expect_ticket_checksum']
        expect_full_checksum = kdc_exchange_dict['expect_full_checksum']
        if expect_ticket_checksum or expect_full_checksum:
            self.assertIsNotNone(ticket_decryption_key)

        if ticket_decryption_key is not None:
            service_ticket = not self.is_tgs_principal(expected_sname)
            self.verify_ticket(ticket_creds, krbtgt_keys,
                               service_ticket=service_ticket,
                               expect_pac=expect_pac,
                               expect_ticket_checksum=expect_ticket_checksum
                               or self.tkt_sig_support,
                               expect_full_checksum=expect_full_checksum
                               or self.full_sig_support)

        kdc_exchange_dict['rep_ticket_creds'] = ticket_creds

    # Check the SIDs in a LOGON_INFO PAC buffer.
    def check_logon_info_sids(self, logon_info_buffer, kdc_exchange_dict):
        info3 = logon_info_buffer.info.info.info3
        logon_info = info3.base
        resource_groups = logon_info_buffer.info.info.resource_groups

        expected_groups = kdc_exchange_dict['expected_groups']
        unexpected_groups = kdc_exchange_dict['unexpected_groups']
        expected_domain_sid = kdc_exchange_dict['expected_domain_sid']
        expected_sid = kdc_exchange_dict['expected_sid']

        domain_sid = logon_info.domain_sid
        if expected_domain_sid is not None:
            self.assertEqual(expected_domain_sid, str(domain_sid))

        if expected_sid is not None:
            got_sid = f'{domain_sid}-{logon_info.rid}'
            self.assertEqual(expected_sid, got_sid)

        if expected_groups is None and unexpected_groups is None:
            # Nothing more to do.
            return

        # Check the SIDs in the PAC.

        # Form a representation of the PAC, containing at first the primary
        # GID.
        primary_sid = f'{domain_sid}-{logon_info.primary_gid}'
        pac_sids = {
            (primary_sid, self.SidType.PRIMARY_GID, None),
        }

        # Collect the Extra SIDs.
        if info3.sids is not None:
            self.assertTrue(logon_info.user_flags & (
                netlogon.NETLOGON_EXTRA_SIDS),
                            'extra SIDs present, but EXTRA_SIDS flag not set')
            self.assertTrue(info3.sids, 'got empty SIDs')

            for sid_attr in info3.sids:
                got_sid = str(sid_attr.sid)
                if unexpected_groups is not None:
                    self.assertNotIn(got_sid, unexpected_groups)

                pac_sid = (got_sid,
                           self.SidType.EXTRA_SID,
                           sid_attr.attributes)
                self.assertNotIn(pac_sid, pac_sids, 'got duplicated SID')
                pac_sids.add(pac_sid)
        else:
            self.assertFalse(logon_info.user_flags & (
                netlogon.NETLOGON_EXTRA_SIDS),
                             'no extra SIDs present, but EXTRA_SIDS flag set')

        # Collect the Base RIDs.
        if logon_info.groups.rids is not None:
            self.assertTrue(logon_info.groups.rids, 'got empty RIDs')

            for group in logon_info.groups.rids:
                got_sid = f'{domain_sid}-{group.rid}'
                if unexpected_groups is not None:
                    self.assertNotIn(got_sid, unexpected_groups)

                pac_sid = (got_sid, self.SidType.BASE_SID, group.attributes)
                self.assertNotIn(pac_sid, pac_sids, 'got duplicated SID')
                pac_sids.add(pac_sid)

        # Collect the Resource SIDs.
        expect_resource_groups_flag = kdc_exchange_dict[
            'expect_resource_groups_flag']
        expect_set_reason = ''
        expect_reset_reason = ''
        if expect_resource_groups_flag is None:
            expect_resource_groups_flag = (
                resource_groups.groups.rids is not None)
            expect_set_reason = 'resource groups present, but '
            expect_reset_reason = 'no resource groups present, but '

        if expect_resource_groups_flag:
            self.assertTrue(
                logon_info.user_flags & netlogon.NETLOGON_RESOURCE_GROUPS,
                f'{expect_set_reason}RESOURCE_GROUPS flag unexpectedly reset')
        else:
            self.assertFalse(
                logon_info.user_flags & netlogon.NETLOGON_RESOURCE_GROUPS,
                f'{expect_reset_reason}RESOURCE_GROUPS flag unexpectedly set')

        if resource_groups.groups.rids is not None:
            self.assertTrue(resource_groups.groups.rids, 'got empty RIDs')

            resource_group_sid = resource_groups.domain_sid
            for resource_group in resource_groups.groups.rids:
                got_sid = f'{resource_group_sid}-{resource_group.rid}'
                if unexpected_groups is not None:
                    self.assertNotIn(got_sid, unexpected_groups)

                pac_sid = (got_sid,
                           self.SidType.RESOURCE_SID,
                           resource_group.attributes)
                self.assertNotIn(pac_sid, pac_sids, 'got duplicated SID')
                pac_sids.add(pac_sid)

        # Compare the aggregated SIDs against the set of expected SIDs.
        if expected_groups is not None:
            if ... in expected_groups:
                # The caller is only interested in asserting the
                # presence of particular groups, and doesn't mind if
                # other groups are present as well.
                pac_sids.add(...)
                self.assertLessEqual(expected_groups, pac_sids,
                                     'expected groups')
            else:
                # The caller wants to make sure the groups match
                # exactly.
                self.assertEqual(expected_groups, pac_sids,
                                 'expected != got')

    def check_device_info(self, device_info, kdc_exchange_dict):
        armor_tgt = kdc_exchange_dict['armor_tgt']
        armor_auth_data = armor_tgt.ticket_private.get(
            'authorization-data')
        self.assertIsNotNone(armor_auth_data,
                             'missing authdata for armor TGT')
        armor_pac_data = self.get_pac(armor_auth_data)
        armor_pac = ndr_unpack(krb5pac.PAC_DATA, armor_pac_data)
        for armor_pac_buffer in armor_pac.buffers:
            if armor_pac_buffer.type == krb5pac.PAC_TYPE_LOGON_INFO:
                armor_info = armor_pac_buffer.info.info.info3
                break
        else:
            self.fail('missing logon info for armor PAC')
        self.assertEqual(armor_info.base.rid, device_info.rid)

        device_domain_sid = kdc_exchange_dict['expected_device_domain_sid']
        expected_device_groups = kdc_exchange_dict['expected_device_groups']
        if kdc_exchange_dict['expect_device_info']:
            self.assertIsNotNone(device_domain_sid)
            self.assertIsNotNone(expected_device_groups)

        if device_domain_sid is not None:
            self.assertEqual(device_domain_sid, str(device_info.domain_sid))
        else:
            device_domain_sid = str(device_info.domain_sid)

        # Check the device info SIDs.

        # A representation of the device info groups.
        primary_sid = f'{device_domain_sid}-{device_info.primary_gid}'
        got_sids = {
            (primary_sid, self.SidType.PRIMARY_GID, None),
        }

        # Collect the groups.
        if device_info.groups.rids is not None:
            self.assertTrue(device_info.groups.rids, 'got empty RIDs')

            for group in device_info.groups.rids:
                got_sid = f'{device_domain_sid}-{group.rid}'

                device_sid = (got_sid, self.SidType.BASE_SID, group.attributes)
                self.assertNotIn(device_sid, got_sids, 'got duplicated SID')
                got_sids.add(device_sid)

        # Collect the SIDs.
        if device_info.sids is not None:
            self.assertTrue(device_info.sids, 'got empty SIDs')

            for sid_attr in device_info.sids:
                got_sid = str(sid_attr.sid)

                in_a_domain = sid_attr.sid.num_auths == 5 and (
                    str(sid_attr.sid).startswith('S-1-5-21-'))
                self.assertFalse(in_a_domain,
                                 f'got unexpected SID for domain: {got_sid} '
                                 f'(should be in device_info.domain_groups)')

                device_sid = (got_sid,
                              self.SidType.EXTRA_SID,
                              sid_attr.attributes)
                self.assertNotIn(device_sid, got_sids, 'got duplicated SID')
                got_sids.add(device_sid)

        # Collect the domain groups.
        if device_info.domain_groups is not None:
            self.assertTrue(device_info.domain_groups, 'got empty domain groups')

            for domain_group in device_info.domain_groups:
                self.assertTrue(domain_group, 'got empty domain group')

                got_domain_sids = set()

                resource_group_sid = domain_group.domain_sid

                in_a_domain = resource_group_sid.num_auths == 4 and (
                    str(resource_group_sid).startswith('S-1-5-21-'))
                self.assertTrue(
                    in_a_domain,
                    f'got unexpected domain SID for non-domain: {resource_group_sid} '
                    f'(should be in device_info.sids)')

                for resource_group in domain_group.groups.rids:
                    got_sid = f'{resource_group_sid}-{resource_group.rid}'

                    device_sid = (got_sid,
                                  self.SidType.RESOURCE_SID,
                                  resource_group.attributes)
                    self.assertNotIn(device_sid, got_domain_sids, 'got duplicated SID')
                    got_domain_sids.add(device_sid)

                got_domain_sids = frozenset(got_domain_sids)
                self.assertNotIn(got_domain_sids, got_sids)
                got_sids.add(got_domain_sids)

        # Compare the aggregated device SIDs against the set of expected device
        # SIDs.
        if expected_device_groups is not None:
            self.assertEqual(expected_device_groups, got_sids,
                             'expected != got')

    def check_pac_buffers(self, pac_data, kdc_exchange_dict):
        pac = ndr_unpack(krb5pac.PAC_DATA, pac_data)

        rep_msg_type = kdc_exchange_dict['rep_msg_type']
        armor_tgt = kdc_exchange_dict['armor_tgt']

        compound_id = rep_msg_type == KRB_TGS_REP and armor_tgt is not None

        expected_sname = kdc_exchange_dict['expected_sname']
        expect_client_claims = kdc_exchange_dict['expect_client_claims']
        expect_device_info = kdc_exchange_dict['expect_device_info']
        expect_device_claims = kdc_exchange_dict['expect_device_claims']

        expected_types = [krb5pac.PAC_TYPE_LOGON_INFO,
                          krb5pac.PAC_TYPE_SRV_CHECKSUM,
                          krb5pac.PAC_TYPE_KDC_CHECKSUM,
                          krb5pac.PAC_TYPE_LOGON_NAME,
                          krb5pac.PAC_TYPE_UPN_DNS_INFO]

        kdc_options = kdc_exchange_dict['kdc_options']
        pos = len(tuple(krb5_asn1.KDCOptions('cname-in-addl-tkt'))) - 1
        constrained_delegation = (pos < len(kdc_options)
                                  and kdc_options[pos] == '1')
        if constrained_delegation:
            expected_types.append(krb5pac.PAC_TYPE_CONSTRAINED_DELEGATION)

        require_strict = set()
        unchecked = set()
        if not self.tkt_sig_support:
            require_strict.add(krb5pac.PAC_TYPE_TICKET_CHECKSUM)
        if not self.full_sig_support:
            require_strict.add(krb5pac.PAC_TYPE_FULL_CHECKSUM)

        expected_client_claims = kdc_exchange_dict['expected_client_claims']
        unexpected_client_claims = kdc_exchange_dict[
            'unexpected_client_claims']

        if self.kdc_claims_support and expect_client_claims:
            expected_types.append(krb5pac.PAC_TYPE_CLIENT_CLAIMS_INFO)
        else:
            self.assertFalse(
                expected_client_claims,
                'expected client claims, but client claims not expected in '
                'PAC')
            self.assertFalse(
                unexpected_client_claims,
                'unexpected client claims, but client claims not expected in '
                'PAC')

            if expect_client_claims is None:
                unchecked.add(krb5pac.PAC_TYPE_CLIENT_CLAIMS_INFO)

        expected_device_claims = kdc_exchange_dict['expected_device_claims']
        unexpected_device_claims = kdc_exchange_dict['unexpected_device_claims']

        expected_device_groups = kdc_exchange_dict['expected_device_groups']

        if (self.kdc_claims_support and self.kdc_compound_id_support
                and expect_device_claims and compound_id):
            expected_types.append(krb5pac.PAC_TYPE_DEVICE_CLAIMS_INFO)
        else:
            self.assertFalse(
                expect_device_claims,
                'expected device claims buffer, but device claims not '
                'expected in PAC')
            self.assertFalse(
                expected_device_claims,
                'expected device claims, but device claims not expected in '
                'PAC')
            self.assertFalse(
                unexpected_device_claims,
                'unexpected device claims, but device claims not expected in '
                'PAC')

            if expect_device_claims is None and compound_id:
                unchecked.add(krb5pac.PAC_TYPE_DEVICE_CLAIMS_INFO)

        if self.kdc_compound_id_support and compound_id and expect_device_info:
            expected_types.append(krb5pac.PAC_TYPE_DEVICE_INFO)
        else:
            self.assertFalse(expect_device_info,
                             'expected device info with no armor TGT or '
                             'for non-TGS request')
            self.assertFalse(expected_device_groups,
                             'expected device groups, but device info not '
                             'expected in PAC')

            if expect_device_info is None and compound_id:
                unchecked.add(krb5pac.PAC_TYPE_DEVICE_INFO)

        if not self.is_tgs_principal(expected_sname):
            expected_types.append(krb5pac.PAC_TYPE_TICKET_CHECKSUM)
            expected_types.append(krb5pac.PAC_TYPE_FULL_CHECKSUM)

        expect_extra_pac_buffers = self.is_tgs(expected_sname)

        expect_pac_attrs = kdc_exchange_dict['expect_pac_attrs']

        if expect_pac_attrs:
            expect_pac_attrs_pac_request = kdc_exchange_dict[
                'expect_pac_attrs_pac_request']
        else:
            expect_pac_attrs_pac_request = kdc_exchange_dict[
                'pac_request']

            if expect_pac_attrs is None:
                if self.expect_extra_pac_buffers:
                    expect_pac_attrs = expect_extra_pac_buffers
                else:
                    require_strict.add(krb5pac.PAC_TYPE_ATTRIBUTES_INFO)
        if expect_pac_attrs:
            expected_types.append(krb5pac.PAC_TYPE_ATTRIBUTES_INFO)

        expect_requester_sid = kdc_exchange_dict['expect_requester_sid']
        expected_requester_sid = kdc_exchange_dict['expected_requester_sid']

        if expect_requester_sid is None:
            if self.expect_extra_pac_buffers:
                expect_requester_sid = expect_extra_pac_buffers
            else:
                require_strict.add(krb5pac.PAC_TYPE_REQUESTER_SID)
        if expected_requester_sid is not None:
            expect_requester_sid = True
        if expect_requester_sid:
            expected_types.append(krb5pac.PAC_TYPE_REQUESTER_SID)

        sent_pk_as_req = self.sent_pk_as_req(kdc_exchange_dict) or (
            self.sent_pk_as_req_win2k(kdc_exchange_dict))
        if sent_pk_as_req:
            expected_types.append(krb5pac.PAC_TYPE_CREDENTIAL_INFO)

        expected_extra_pac_buffers = kdc_exchange_dict['expected_extra_pac_buffers']
        if expected_extra_pac_buffers is not None:
            expected_types.extend(expected_extra_pac_buffers)

        buffer_types = [pac_buffer.type
                        for pac_buffer in pac.buffers]
        self.assertSequenceElementsEqual(
            expected_types, buffer_types,
            require_ordered=False,
            require_strict=require_strict,
            unchecked=unchecked)

        expected_account_name = kdc_exchange_dict['expected_account_name']
        expected_sid = kdc_exchange_dict['expected_sid']

        expect_upn_dns_info_ex = kdc_exchange_dict['expect_upn_dns_info_ex']
        if expect_upn_dns_info_ex is None and (
                expected_account_name is not None
                or expected_sid is not None):
            expect_upn_dns_info_ex = True

        for pac_buffer in pac.buffers:
            if pac_buffer.type == krb5pac.PAC_TYPE_CONSTRAINED_DELEGATION:
                expected_proxy_target = kdc_exchange_dict[
                    'expected_proxy_target']
                expected_transited_services = kdc_exchange_dict[
                    'expected_transited_services']

                delegation_info = pac_buffer.info.info

                self.assertEqual(expected_proxy_target,
                                 str(delegation_info.proxy_target))

                transited_services = list(map(
                    str, delegation_info.transited_services))
                self.assertEqual(expected_transited_services,
                                 transited_services)

            elif pac_buffer.type == krb5pac.PAC_TYPE_LOGON_NAME:
                expected_cname = kdc_exchange_dict['expected_cname']
                account_name = '/'.join(expected_cname['name-string'])

                self.assertEqual(account_name, pac_buffer.info.account_name)

            elif pac_buffer.type == krb5pac.PAC_TYPE_LOGON_INFO:
                info3 = pac_buffer.info.info.info3
                logon_info = info3.base

                if expected_account_name is not None:
                    self.assertEqual(expected_account_name,
                                     str(logon_info.account_name))

                self.check_logon_info_sids(pac_buffer, kdc_exchange_dict)

            elif pac_buffer.type == krb5pac.PAC_TYPE_UPN_DNS_INFO:
                upn_dns_info = pac_buffer.info
                upn_dns_info_ex = upn_dns_info.ex

                expected_realm = kdc_exchange_dict['expected_crealm']
                self.assertEqual(expected_realm,
                                 upn_dns_info.dns_domain_name)

                expected_upn_name = kdc_exchange_dict['expected_upn_name']
                if expected_upn_name is not None:
                    self.assertEqual(expected_upn_name,
                                     upn_dns_info.upn_name)

                if expect_upn_dns_info_ex:
                    self.assertIsNotNone(upn_dns_info_ex)

                if upn_dns_info_ex is not None:
                    if expected_account_name is not None:
                        self.assertEqual(expected_account_name,
                                         upn_dns_info_ex.samaccountname)

                    if expected_sid is not None:
                        self.assertEqual(expected_sid,
                                         str(upn_dns_info_ex.objectsid))

            elif (pac_buffer.type == krb5pac.PAC_TYPE_ATTRIBUTES_INFO
                      and expect_pac_attrs):
                attr_info = pac_buffer.info

                self.assertEqual(2, attr_info.flags_length)

                flags = attr_info.flags

                requested_pac = bool(flags & 1)
                given_pac = bool(flags & 2)

                self.assertEqual(expect_pac_attrs_pac_request is True,
                                 requested_pac)
                self.assertEqual(expect_pac_attrs_pac_request is None,
                                 given_pac)

            elif (pac_buffer.type == krb5pac.PAC_TYPE_REQUESTER_SID
                      and expect_requester_sid):
                requester_sid = pac_buffer.info.sid

                if expected_requester_sid is None:
                    expected_requester_sid = expected_sid
                if expected_sid is not None:
                    self.assertEqual(expected_requester_sid,
                                     str(requester_sid))

            elif pac_buffer.type in {krb5pac.PAC_TYPE_CLIENT_CLAIMS_INFO,
                                     krb5pac.PAC_TYPE_DEVICE_CLAIMS_INFO}:
                remaining = pac_buffer.info.remaining

                if pac_buffer.type == krb5pac.PAC_TYPE_CLIENT_CLAIMS_INFO:
                    claims_type = 'client claims'
                    expected_claims = expected_client_claims
                    unexpected_claims = unexpected_client_claims
                else:
                    claims_type = 'device claims'
                    expected_claims = expected_device_claims
                    unexpected_claims = unexpected_device_claims

                if not remaining:
                    # Windows may produce an empty claims buffer.
                    self.assertFalse(expected_claims,
                                     f'expected {claims_type}, but the PAC '
                                     f'buffer was empty')
                    continue

                if expected_claims:
                    empty_msg = f', and {claims_type} were expected'
                else:
                    empty_msg = f' for {claims_type} (should be missing)'

                claims_metadata_ndr = ndr_unpack(claims.CLAIMS_SET_METADATA_NDR,
                                                 remaining)
                claims_metadata = claims_metadata_ndr.claims.metadata
                self.assertIsNotNone(claims_metadata,
                                     f'got empty CLAIMS_SET_METADATA_NDR '
                                     f'inner structure {empty_msg}')

                self.assertIsNotNone(claims_metadata.claims_set,
                                     f'got empty CLAIMS_SET_METADATA '
                                     f'structure {empty_msg}')

                uncompressed_size = claims_metadata.uncompressed_claims_set_size
                compression_format = claims_metadata.compression_format

                if uncompressed_size < (
                        claims.CLAIM_LOWER_COMPRESSION_THRESHOLD):
                    self.assertEqual(claims.CLAIMS_COMPRESSION_FORMAT_NONE,
                                     compression_format,
                                     f'{claims_type} unexpectedly '
                                     f'compressed ({uncompressed_size} '
                                     f'bytes uncompressed)')
                elif uncompressed_size >= (
                        claims.CLAIM_UPPER_COMPRESSION_THRESHOLD):
                    self.assertEqual(
                        claims.CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF,
                        compression_format,
                        f'{claims_type} unexpectedly not compressed '
                        f'({uncompressed_size} bytes uncompressed)')

                claims_set = claims_metadata.claims_set.claims.claims
                self.assertIsNotNone(claims_set,
                                     f'got empty CLAIMS_SET_NDR inner '
                                     f'structure {empty_msg}')

                claims_arrays = claims_set.claims_arrays
                self.assertIsNotNone(claims_arrays,
                                     f'got empty CLAIMS_SET structure '
                                     f'{empty_msg}')
                self.assertGreater(len(claims_arrays), 0,
                                   f'got empty claims array {empty_msg}')
                self.assertEqual(len(claims_arrays),
                                 claims_set.claims_array_count,
                                 f'{claims_type} arrays size mismatch')

                got_claims = {}

                for claims_array in claims_arrays:
                    claim_entries = claims_array.claim_entries
                    self.assertIsNotNone(claim_entries,
                                         f'got empty CLAIMS_ARRAY structure '
                                         f'{empty_msg}')
                    self.assertGreater(len(claim_entries), 0,
                                       f'got empty claim entries array '
                                       f'{empty_msg}')
                    self.assertEqual(len(claim_entries),
                                     claims_array.claims_count,
                                     f'{claims_type} entries array size '
                                     f'mismatch')

                    for entry in claim_entries:
                        if unexpected_claims is not None:
                            self.assertNotIn(entry.id, unexpected_claims,
                                             f'got unexpected {claims_type} '
                                             f'in PAC')
                        if expected_claims is None:
                            continue

                        expected_claim = expected_claims.get(entry.id)
                        if expected_claim is None:
                            continue

                        self.assertNotIn(entry.id, got_claims,
                                         f'got duplicate {claims_type}')

                        self.assertIsNotNone(entry.values.values,
                                             f'got {claims_type} with no '
                                             f'values')
                        self.assertGreater(len(entry.values.values), 0,
                                           f'got empty {claims_type} values '
                                           f'array')
                        self.assertEqual(len(entry.values.values),
                                         entry.values.value_count,
                                         f'{claims_type} values array size '
                                         f'mismatch')

                        expected_claim_values = expected_claim.get('values')
                        self.assertIsNotNone(expected_claim_values,
                                             f'got expected {claims_type} '
                                             f'with no values')

                        values = type(expected_claim_values)(
                            entry.values.values)

                        got_claims[entry.id] = {
                            'source_type': claims_array.claims_source_type,
                            'type': entry.type,
                            'values': values,
                        }

                self.assertEqual(expected_claims, got_claims or None,
                                 f'{claims_type} did not match expectations')

            elif pac_buffer.type == krb5pac.PAC_TYPE_DEVICE_INFO:
                device_info = pac_buffer.info.info

                self.check_device_info(device_info, kdc_exchange_dict)

            elif pac_buffer.type == krb5pac.PAC_TYPE_CREDENTIAL_INFO:
                credential_info = pac_buffer.info

                expected_etype = self.expected_etype(kdc_exchange_dict)

                self.assertEqual(0, credential_info.version)
                self.assertEqual(expected_etype,
                                 credential_info.encryption_type)

                encrypted_data = credential_info.encrypted_data
                reply_key = kdc_exchange_dict['reply_key']

                data = reply_key.decrypt(KU_NON_KERB_SALT, encrypted_data)

                credential_data_ndr = ndr_unpack(
                    krb5pac.PAC_CREDENTIAL_DATA_NDR, data)

                credential_data = credential_data_ndr.ctr.data

                self.assertEqual(1, credential_data.credential_count)
                self.assertEqual(credential_data.credential_count,
                                 len(credential_data.credentials))

                package = credential_data.credentials[0]
                self.assertEqual('NTLM', str(package.package_name))

                ntlm_blob = bytes(package.credential)

                ntlm_package = ndr_unpack(krb5pac.PAC_CREDENTIAL_NTLM_SECPKG,
                                          ntlm_blob)

                self.assertEqual(0, ntlm_package.version)
                self.assertEqual(krb5pac.PAC_CREDENTIAL_NTLM_HAS_NT_HASH,
                                 ntlm_package.flags)

                creds = kdc_exchange_dict['creds']
                nt_password = bytes(ntlm_package.nt_password.hash)
                if kdc_exchange_dict['expect_matching_nt_hash_in_pac']:
                    self.assertEqual(creds.get_nt_hash(), nt_password)
                else:
                    self.assertNotEqual(creds.get_nt_hash(), nt_password)

                kdc_exchange_dict['nt_hash_from_pac'] = ntlm_package.nt_password

                lm_password = bytes(ntlm_package.lm_password.hash)
                self.assertEqual(bytes(16), lm_password)

    def generic_check_kdc_error(self,
                                kdc_exchange_dict,
                                callback_dict,
                                rep,
                                inner=False):

        rep_msg_type = kdc_exchange_dict['rep_msg_type']

        expected_anon = kdc_exchange_dict['expected_anon']
        expected_srealm = kdc_exchange_dict['expected_srealm']
        expected_sname = kdc_exchange_dict['expected_sname']
        expected_error_mode = kdc_exchange_dict['expected_error_mode']

        sent_fast = self.sent_fast(kdc_exchange_dict)

        fast_armor_type = kdc_exchange_dict['fast_armor_type']

        self.assertElementEqual(rep, 'pvno', 5)
        self.assertElementEqual(rep, 'msg-type', KRB_ERROR)
        error_code = self.getElementValue(rep, 'error-code')
        self.assertIn(error_code, expected_error_mode)
        if self.strict_checking:
            self.assertElementMissing(rep, 'ctime')
            self.assertElementMissing(rep, 'cusec')
        self.assertElementPresent(rep, 'stime')
        self.assertElementPresent(rep, 'susec')
        # error-code checked above
        if expected_anon and not inner:
            expected_cname = self.PrincipalName_create(
                name_type=NT_WELLKNOWN,
                names=['WELLKNOWN', 'ANONYMOUS'])
            self.assertElementEqualPrincipal(rep, 'cname', expected_cname)
        elif self.strict_checking:
            self.assertElementMissing(rep, 'cname')
        if self.strict_checking:
            self.assertElementMissing(rep, 'crealm')
            self.assertElementEqualUTF8(rep, 'realm', expected_srealm)
            self.assertElementEqualPrincipal(rep, 'sname', expected_sname)
            self.assertElementMissing(rep, 'e-text')
        expect_status = kdc_exchange_dict['expect_status']
        expected_status = kdc_exchange_dict['expected_status']
        expect_edata = kdc_exchange_dict['expect_edata']
        if expect_edata is None:
            expect_edata = (error_code != KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS
                            and (not sent_fast or fast_armor_type is None
                                 or fast_armor_type == FX_FAST_ARMOR_AP_REQUEST)
                            and not inner)
        if inner and expect_edata is self.expect_padata_outer:
            expect_edata = False
        if not expect_edata:
            self.assertFalse(expect_status)
            if self.strict_checking or expect_status is False:
                self.assertElementMissing(rep, 'e-data')
            return rep
        edata = self.getElementValue(rep, 'e-data')
        if self.strict_checking or expect_status:
            self.assertIsNotNone(edata)
        if edata is not None:
            try:
                error_data = self.der_decode(
                    edata,
                    asn1Spec=krb5_asn1.KERB_ERROR_DATA())
            except PyAsn1Error:
                if expect_status:
                    # The test requires that the KDC be declared to support
                    # NTSTATUS values in e-data to proceed.
                    self.assertTrue(
                        self.expect_nt_status,
                        'expected status code (which, according to '
                        'EXPECT_NT_STATUS=0, the KDC does not support)')

                    self.fail('expected to get status code')

                rep_padata = self.der_decode(
                    edata, asn1Spec=krb5_asn1.METHOD_DATA())
                self.assertGreater(len(rep_padata), 0)

                if sent_fast:
                    self.assertEqual(1, len(rep_padata))
                    rep_pa_dict = self.get_pa_dict(rep_padata)
                    self.assertIn(PADATA_FX_FAST, rep_pa_dict)

                    armor_key = kdc_exchange_dict['armor_key']
                    self.assertIsNotNone(armor_key)
                    fast_response = self.check_fx_fast_data(
                        kdc_exchange_dict,
                        rep_pa_dict[PADATA_FX_FAST],
                        armor_key,
                        expect_strengthen_key=False)

                    rep_padata = fast_response['padata']

                etype_info2 = self.check_rep_padata(kdc_exchange_dict,
                                                    callback_dict,
                                                    rep_padata,
                                                    error_code)

                kdc_exchange_dict['preauth_etype_info2'] = etype_info2
            else:
                self.assertTrue(self.expect_nt_status,
                                'got status code, but EXPECT_NT_STATUS=0')

                if expect_status is not None:
                    self.assertTrue(expect_status,
                                    'got unexpected status code')

                self.assertEqual(KERB_ERR_TYPE_EXTENDED,
                                 error_data['data-type'])

                extended_error = error_data['data-value']

                self.assertEqual(12, len(extended_error))

                status = int.from_bytes(extended_error[:4], 'little')
                flags = int.from_bytes(extended_error[8:], 'little')

                self.assertEqual(expected_status, status)

                if rep_msg_type == KRB_TGS_REP:
                    self.assertEqual(3, flags)
                else:
                    self.assertEqual(1, flags)

        return rep

    def check_reply_padata(self,
                           kdc_exchange_dict,
                           callback_dict,
                           encpart,
                           rep_padata):
        expected_patypes = ()

        sent_fast = self.sent_fast(kdc_exchange_dict)
        rep_msg_type = kdc_exchange_dict['rep_msg_type']

        if sent_fast:
            expected_patypes += (PADATA_FX_FAST,)
        elif rep_msg_type == KRB_AS_REP:
            if self.sent_pk_as_req(kdc_exchange_dict):
                expected_patypes += PADATA_PK_AS_REP,
            elif self.sent_pk_as_req_win2k(kdc_exchange_dict):
                expected_patypes += PADATA_PK_AS_REP_19,
            else:
                chosen_etype = self.getElementValue(encpart, 'etype')
                self.assertIsNotNone(chosen_etype)

                if chosen_etype in {kcrypto.Enctype.AES256,
                                    kcrypto.Enctype.AES128}:
                    expected_patypes += (PADATA_ETYPE_INFO2,)

                preauth_key = kdc_exchange_dict['preauth_key']
                self.assertIsInstance(preauth_key, Krb5EncryptionKey)
                if preauth_key.etype == kcrypto.Enctype.RC4 and rep_padata is None:
                    rep_padata = ()
        elif rep_msg_type == KRB_TGS_REP:
            if expected_patypes == () and rep_padata is None:
                rep_padata = ()

        if not self.strict_checking and rep_padata is None:
            rep_padata = ()

        self.assertIsNotNone(rep_padata)
        got_patypes = tuple(pa['padata-type'] for pa in rep_padata)
        self.assertSequenceElementsEqual(expected_patypes, got_patypes,
                                         # Windows does not add this.
                                         unchecked={PADATA_PKINIT_KX})

        if len(expected_patypes) == 0:
            return None

        pa_dict = self.get_pa_dict(rep_padata)

        etype_info2 = pa_dict.get(PADATA_ETYPE_INFO2)
        if etype_info2 is not None:
            etype_info2 = self.der_decode(etype_info2,
                                          asn1Spec=krb5_asn1.ETYPE_INFO2())
            self.assertEqual(len(etype_info2), 1)
            elem = etype_info2[0]

            e = self.getElementValue(elem, 'etype')
            self.assertEqual(e, chosen_etype)
            salt = self.getElementValue(elem, 'salt')
            self.assertIsNotNone(salt)
            expected_salt = kdc_exchange_dict['expected_salt']
            if expected_salt is not None:
                self.assertEqual(salt, expected_salt)
            s2kparams = self.getElementValue(elem, 's2kparams')
            if self.strict_checking:
                self.assertIsNone(s2kparams)

    @staticmethod
    def greatest_common_etype(etypes, proposed_etypes):
        return max(filter(lambda e: e in etypes, proposed_etypes),
                   default=None)

    @staticmethod
    def first_common_etype(etypes, proposed_etypes):
        return next(filter(lambda e: e in etypes, proposed_etypes), None)

    def supported_aes_rc4_etypes(self, kdc_exchange_dict):
        creds = kdc_exchange_dict['creds']
        supported_etypes = self.get_default_enctypes(creds)

        rc4_support = kdc_exchange_dict['rc4_support']

        aes_etypes = set()
        if kcrypto.Enctype.AES256 in supported_etypes:
            aes_etypes.add(kcrypto.Enctype.AES256)
        if kcrypto.Enctype.AES128 in supported_etypes:
            aes_etypes.add(kcrypto.Enctype.AES128)

        rc4_etypes = set()
        if rc4_support and kcrypto.Enctype.RC4 in supported_etypes:
            rc4_etypes.add(kcrypto.Enctype.RC4)

        return aes_etypes, rc4_etypes

    def greatest_aes_rc4_etypes(self, kdc_exchange_dict):
        req_body = kdc_exchange_dict['req_body']
        proposed_etypes = req_body['etype']

        aes_etypes, rc4_etypes = self.supported_aes_rc4_etypes(kdc_exchange_dict)

        expected_aes = self.greatest_common_etype(aes_etypes, proposed_etypes)
        expected_rc4 = self.greatest_common_etype(rc4_etypes, proposed_etypes)

        return expected_aes, expected_rc4

    def expected_etype(self, kdc_exchange_dict):
        req_body = kdc_exchange_dict['req_body']
        proposed_etypes = req_body['etype']

        aes_etypes, rc4_etypes = self.supported_aes_rc4_etypes(
            kdc_exchange_dict)

        return self.first_common_etype(aes_etypes | rc4_etypes,
                                       proposed_etypes)

    def check_rep_padata(self,
                         kdc_exchange_dict,
                         callback_dict,
                         rep_padata,
                         error_code):
        rep_msg_type = kdc_exchange_dict['rep_msg_type']

        sent_fast = self.sent_fast(kdc_exchange_dict)
        sent_enc_challenge = self.sent_enc_challenge(kdc_exchange_dict)

        if rep_msg_type == KRB_TGS_REP:
            self.assertTrue(sent_fast)

        rc4_support = kdc_exchange_dict['rc4_support']

        expected_aes, expected_rc4 = self.greatest_aes_rc4_etypes(
            kdc_exchange_dict)

        expect_etype_info2 = ()
        expect_etype_info = False
        if expected_aes is not None:
            expect_etype_info2 += (expected_aes,)
        if expected_rc4 is not None:
            if error_code != 0:
                expect_etype_info2 += (expected_rc4,)
            if expected_aes is None:
                expect_etype_info = True

        if expect_etype_info:
            self.assertGreater(len(expect_etype_info2), 0)

        sent_pac_options = self.get_sent_pac_options(kdc_exchange_dict)

        check_patypes = kdc_exchange_dict['check_patypes']
        if check_patypes:
            expected_patypes = ()
            if sent_fast and error_code != 0:
                expected_patypes += (PADATA_FX_ERROR,)
                expected_patypes += (PADATA_FX_COOKIE,)

            if rep_msg_type == KRB_TGS_REP:
                if ('1' in sent_pac_options
                        and error_code not in (0, KDC_ERR_GENERIC)):
                    expected_patypes += (PADATA_PAC_OPTIONS,)
            elif error_code == KDC_ERR_KEY_EXPIRED:
                expected_patypes += (PADATA_PK_AS_REP,)
            elif error_code != KDC_ERR_GENERIC:
                if expect_etype_info:
                    expected_patypes += (PADATA_ETYPE_INFO,)
                if len(expect_etype_info2) != 0:
                    expected_patypes += (PADATA_ETYPE_INFO2,)

                sent_freshness = self.sent_freshness(kdc_exchange_dict)

                if error_code not in (KDC_ERR_PREAUTH_FAILED, KDC_ERR_SKEW,
                                      KDC_ERR_POLICY, KDC_ERR_CLIENT_REVOKED):
                    if sent_fast:
                        expected_patypes += (PADATA_ENCRYPTED_CHALLENGE,)
                    else:
                        expected_patypes += (PADATA_ENC_TIMESTAMP,)

                    if not sent_enc_challenge:
                        expected_patypes += (PADATA_PK_AS_REQ,)
                        if not sent_freshness:
                            expected_patypes += (PADATA_PK_AS_REP_19,)

                if sent_freshness:
                    expected_patypes += PADATA_AS_FRESHNESS,

                if (error_code != KDC_ERR_PREAUTH_FAILED
                        and self.kdc_fast_support
                        and not sent_fast
                        and not sent_enc_challenge):
                    expected_patypes += (PADATA_FX_FAST,)
                    expected_patypes += (PADATA_FX_COOKIE,)

            require_strict = {PADATA_FX_COOKIE,
                              PADATA_FX_FAST,
                              PADATA_PAC_OPTIONS,
                              PADATA_PK_AS_REP_19,
                              PADATA_PK_AS_REQ,
                              PADATA_PKINIT_KX,
                              PADATA_GSS}
            strict_edata_checking = kdc_exchange_dict['strict_edata_checking']
            if not strict_edata_checking:
                require_strict.add(PADATA_ETYPE_INFO2)
                require_strict.add(PADATA_ENCRYPTED_CHALLENGE)

            got_patypes = tuple(pa['padata-type'] for pa in rep_padata)
            TD_CMS_DIGEST_ALGORITHMS = 111
            self.assertSequenceElementsEqual(expected_patypes, got_patypes,
                                             require_strict=require_strict,
                                             unchecked={PADATA_PW_SALT,TD_CMS_DIGEST_ALGORITHMS})

            if not expected_patypes:
                return None

        pa_dict = self.get_pa_dict(rep_padata)

        enc_timestamp = pa_dict.get(PADATA_ENC_TIMESTAMP)
        if enc_timestamp is not None:
            self.assertEqual(len(enc_timestamp), 0)

        pk_as_req = pa_dict.get(PADATA_PK_AS_REQ)
        if pk_as_req is not None:
            self.assertEqual(len(pk_as_req), 0)

        pk_as_rep19 = pa_dict.get(PADATA_PK_AS_REP_19)
        if pk_as_rep19 is not None:
            self.assertEqual(len(pk_as_rep19), 0)

        freshness_token = pa_dict.get(PADATA_AS_FRESHNESS)
        if freshness_token is not None:
            self.assertEqual(bytes(2), freshness_token[:2])

            freshness = self.der_decode(freshness_token[2:],
                                        asn1Spec=krb5_asn1.EncryptedData())

            krbtgt_creds = self.get_krbtgt_creds()
            krbtgt_key = self.TicketDecryptionKey_from_creds(krbtgt_creds)

            self.assertElementEqual(freshness, 'etype', krbtgt_key.etype)
            self.assertElementKVNO(freshness, 'kvno', krbtgt_key.kvno)

            # Decrypt the freshness token.
            ts_enc = krbtgt_key.decrypt(KU_AS_FRESHNESS,
                                        freshness['cipher'])

            # Ensure that we can decode it as PA-ENC-TS-ENC.
            ts_enc = self.der_decode(ts_enc,
                                     asn1Spec=krb5_asn1.PA_ENC_TS_ENC())
            freshness_time = self.get_EpochFromKerberosTime(
                ts_enc['patimestamp'])
            freshness_time += ts_enc['pausec'] / 1e6

            # Ensure that it is reasonably close to the current time (within
            # five minutes, to allow for clock skew).
            current_time = datetime.datetime.now(
                datetime.timezone.utc).timestamp()
            self.assertLess(current_time - 5 * 60, freshness_time)
            self.assertLess(freshness_time, current_time + 5 * 60)

            kdc_exchange_dict['freshness_token'] = freshness_token

        fx_fast = pa_dict.get(PADATA_FX_FAST)
        if fx_fast is not None:
            self.assertEqual(len(fx_fast), 0)

        fast_cookie = pa_dict.get(PADATA_FX_COOKIE)
        if fast_cookie is not None:
            kdc_exchange_dict['fast_cookie'] = fast_cookie

        fast_error = pa_dict.get(PADATA_FX_ERROR)
        if fast_error is not None:
            fast_error = self.der_decode(fast_error,
                                         asn1Spec=krb5_asn1.KRB_ERROR())
            self.generic_check_kdc_error(kdc_exchange_dict,
                                         callback_dict,
                                         fast_error,
                                         inner=True)

        pac_options = pa_dict.get(PADATA_PAC_OPTIONS)
        if pac_options is not None:
            pac_options = self.der_decode(
                pac_options,
                asn1Spec=krb5_asn1.PA_PAC_OPTIONS())
            self.assertElementEqual(pac_options, 'options', sent_pac_options)

        enc_challenge = pa_dict.get(PADATA_ENCRYPTED_CHALLENGE)
        if enc_challenge is not None:
            if not sent_enc_challenge:
                self.assertEqual(len(enc_challenge), 0)
            else:
                armor_key = kdc_exchange_dict['armor_key']
                self.assertIsNotNone(armor_key)

                preauth_key, _ = self.get_preauth_key(kdc_exchange_dict)

                kdc_challenge_key = self.generate_kdc_challenge_key(
                    armor_key, preauth_key)

                # Ensure that the encrypted challenge FAST factor is supported
                # (RFC6113 5.4.6).
                if self.strict_checking:
                    self.assertNotEqual(len(enc_challenge), 0)
                if len(enc_challenge) != 0:
                    encrypted_challenge = self.der_decode(
                        enc_challenge,
                        asn1Spec=krb5_asn1.EncryptedData())
                    self.assertEqual(encrypted_challenge['etype'],
                                     kdc_challenge_key.etype)

                    challenge = kdc_challenge_key.decrypt(
                        KU_ENC_CHALLENGE_KDC,
                        encrypted_challenge['cipher'])
                    challenge = self.der_decode(
                        challenge,
                        asn1Spec=krb5_asn1.PA_ENC_TS_ENC())

                    # Retrieve the returned timestamp.
                    rep_patime = challenge['patimestamp']
                    self.assertIn('pausec', challenge)

                    # Ensure the returned time is within five minutes of the
                    # current time.
                    rep_time = self.get_EpochFromKerberosTime(rep_patime)
                    current_time = time.time()

                    self.assertLess(current_time - 300, rep_time)
                    self.assertLess(rep_time, current_time + 300)

        etype_info2 = pa_dict.get(PADATA_ETYPE_INFO2)
        if etype_info2 is not None:
            etype_info2 = self.der_decode(etype_info2,
                                          asn1Spec=krb5_asn1.ETYPE_INFO2())
            self.assertGreaterEqual(len(etype_info2), 1)
            if self.strict_checking:
                self.assertEqual(len(etype_info2), len(expect_etype_info2))
            for i in range(0, len(etype_info2)):
                e = self.getElementValue(etype_info2[i], 'etype')
                if self.strict_checking:
                    self.assertEqual(e, expect_etype_info2[i])
                salt = self.getElementValue(etype_info2[i], 'salt')
                if e == kcrypto.Enctype.RC4:
                    if self.strict_checking:
                        self.assertIsNone(salt)
                else:
                    self.assertIsNotNone(salt)
                    expected_salt = kdc_exchange_dict['expected_salt']
                    if expected_salt is not None:
                        self.assertEqual(salt, expected_salt)
                s2kparams = self.getElementValue(etype_info2[i], 's2kparams')
                if self.strict_checking:
                    self.assertIsNone(s2kparams)

        etype_info = pa_dict.get(PADATA_ETYPE_INFO)
        if etype_info is not None:
            etype_info = self.der_decode(etype_info,
                                         asn1Spec=krb5_asn1.ETYPE_INFO())
            self.assertEqual(len(etype_info), 1)
            e = self.getElementValue(etype_info[0], 'etype')
            self.assertEqual(e, kcrypto.Enctype.RC4)
            if rc4_support:
                self.assertEqual(e, expect_etype_info2[0])
            salt = self.getElementValue(etype_info[0], 'salt')
            if self.strict_checking:
                self.assertIsNotNone(salt)
                self.assertEqual(len(salt), 0)

        return etype_info2

    def generate_simple_fast(self,
                             kdc_exchange_dict,
                             _callback_dict,
                             req_body,
                             fast_padata,
                             fast_armor,
                             checksum,
                             fast_options=''):
        armor_key = kdc_exchange_dict['armor_key']

        fast_req = self.KRB_FAST_REQ_create(fast_options,
                                            fast_padata,
                                            req_body)
        fast_req = self.der_encode(fast_req,
                                   asn1Spec=krb5_asn1.KrbFastReq())
        fast_req = self.EncryptedData_create(armor_key,
                                             KU_FAST_ENC,
                                             fast_req)

        fast_armored_req = self.KRB_FAST_ARMORED_REQ_create(fast_armor,
                                                            checksum,
                                                            fast_req)

        fx_fast_request = self.PA_FX_FAST_REQUEST_create(fast_armored_req)
        fx_fast_request = self.der_encode(
            fx_fast_request,
            asn1Spec=krb5_asn1.PA_FX_FAST_REQUEST())

        fast_padata = self.PA_DATA_create(PADATA_FX_FAST,
                                          fx_fast_request)

        return fast_padata

    def generate_ap_req(self,
                        kdc_exchange_dict,
                        _callback_dict,
                        req_body,
                        armor,
                        usage=None,
                        seq_number=None):
        req_body_checksum = None

        if armor:
            self.assertIsNone(req_body)

            tgt = kdc_exchange_dict['armor_tgt']
            authenticator_subkey = kdc_exchange_dict['armor_subkey']
        else:
            tgt = kdc_exchange_dict['tgt']
            authenticator_subkey = kdc_exchange_dict['authenticator_subkey']

            if req_body is not None:
                body_checksum_type = kdc_exchange_dict['body_checksum_type']

                req_body_blob = self.der_encode(
                    req_body, asn1Spec=krb5_asn1.KDC_REQ_BODY())

                req_body_checksum = self.Checksum_create(
                    tgt.session_key,
                    KU_TGS_REQ_AUTH_CKSUM,
                    req_body_blob,
                    ctype=body_checksum_type)

        auth_data = kdc_exchange_dict['auth_data']

        subkey_obj = None
        if authenticator_subkey is not None:
            subkey_obj = authenticator_subkey.export_obj()
        if seq_number is None:
            seq_number = random.randint(0, 0xfffffffe)
        (ctime, cusec) = self.get_KerberosTimeWithUsec()
        authenticator_obj = self.Authenticator_create(
            crealm=tgt.crealm,
            cname=tgt.cname,
            cksum=req_body_checksum,
            cusec=cusec,
            ctime=ctime,
            subkey=subkey_obj,
            seq_number=seq_number,
            authorization_data=auth_data)
        authenticator_blob = self.der_encode(
            authenticator_obj,
            asn1Spec=krb5_asn1.Authenticator())

        if usage is None:
            usage = KU_AP_REQ_AUTH if armor else KU_TGS_REQ_AUTH
        authenticator = self.EncryptedData_create(tgt.session_key,
                                                  usage,
                                                  authenticator_blob)

        if armor:
            ap_options = kdc_exchange_dict['fast_ap_options']
        else:
            ap_options = kdc_exchange_dict['ap_options']
        if ap_options is None:
            ap_options = str(krb5_asn1.APOptions('0'))
        ap_req_obj = self.AP_REQ_create(ap_options=ap_options,
                                        ticket=tgt.ticket,
                                        authenticator=authenticator)
        ap_req = self.der_encode(ap_req_obj, asn1Spec=krb5_asn1.AP_REQ())

        return ap_req

    def generate_simple_tgs_padata(self,
                                   kdc_exchange_dict,
                                   callback_dict,
                                   req_body):
        ap_req = self.generate_ap_req(kdc_exchange_dict,
                                      callback_dict,
                                      req_body,
                                      armor=False)
        pa_tgs_req = self.PA_DATA_create(PADATA_KDC_REQ, ap_req)
        padata = [pa_tgs_req]

        return padata, req_body

    def get_preauth_key(self, kdc_exchange_dict):
        msg_type = kdc_exchange_dict['rep_msg_type']

        if msg_type == KRB_AS_REP:
            key = kdc_exchange_dict['preauth_key']
            usage = KU_AS_REP_ENC_PART
        else:  # KRB_TGS_REP
            authenticator_subkey = kdc_exchange_dict['authenticator_subkey']
            if authenticator_subkey is not None:
                key = authenticator_subkey
                usage = KU_TGS_REP_ENC_PART_SUB_KEY
            else:
                tgt = kdc_exchange_dict['tgt']
                key = tgt.session_key
                usage = KU_TGS_REP_ENC_PART_SESSION

        self.assertIsNotNone(key)

        return key, usage

    def generate_armor_key(self, subkey, session_key):
        armor_key = kcrypto.cf2(subkey.key,
                                session_key.key,
                                b'subkeyarmor',
                                b'ticketarmor')
        armor_key = Krb5EncryptionKey(armor_key, None)

        return armor_key

    def generate_strengthen_reply_key(self, strengthen_key, reply_key):
        strengthen_reply_key = kcrypto.cf2(strengthen_key.key,
                                           reply_key.key,
                                           b'strengthenkey',
                                           b'replykey')
        strengthen_reply_key = Krb5EncryptionKey(strengthen_reply_key,
                                                 reply_key.kvno)

        return strengthen_reply_key

    def generate_client_challenge_key(self, armor_key, longterm_key):
        client_challenge_key = kcrypto.cf2(armor_key.key,
                                           longterm_key.key,
                                           b'clientchallengearmor',
                                           b'challengelongterm')
        client_challenge_key = Krb5EncryptionKey(client_challenge_key, None)

        return client_challenge_key

    def generate_kdc_challenge_key(self, armor_key, longterm_key):
        kdc_challenge_key = kcrypto.cf2(armor_key.key,
                                        longterm_key.key,
                                        b'kdcchallengearmor',
                                        b'challengelongterm')
        kdc_challenge_key = Krb5EncryptionKey(kdc_challenge_key, None)

        return kdc_challenge_key

    def verify_ticket_checksum(self, ticket, expected_checksum, armor_key):
        expected_type = expected_checksum['cksumtype']
        self.assertEqual(armor_key.ctype, expected_type)

        ticket_blob = self.der_encode(ticket,
                                      asn1Spec=krb5_asn1.Ticket())
        checksum = self.Checksum_create(armor_key,
                                        KU_FAST_FINISHED,
                                        ticket_blob)
        self.assertEqual(expected_checksum, checksum)

    def verify_ticket(self, ticket, krbtgt_keys, service_ticket,
                      expect_pac=True,
                      expect_ticket_checksum=True,
                      expect_full_checksum=None):
        # Decrypt the ticket.

        key = ticket.decryption_key
        enc_part = ticket.ticket['enc-part']

        self.assertElementEqual(enc_part, 'etype', key.etype)
        self.assertElementKVNO(enc_part, 'kvno', key.kvno)

        enc_part = key.decrypt(KU_TICKET, enc_part['cipher'])
        enc_part = self.der_decode(
            enc_part, asn1Spec=krb5_asn1.EncTicketPart())

        # Fetch the authorization data from the ticket.
        auth_data = enc_part.get('authorization-data')
        if expect_pac:
            self.assertIsNotNone(auth_data)
        elif auth_data is None:
            return

        # Get a copy of the authdata with an empty PAC, and the existing PAC
        # (if present).
        empty_pac = self.get_empty_pac()
        auth_data, pac_data = self.replace_pac(auth_data,
                                               empty_pac,
                                               expect_pac=expect_pac)
        if not expect_pac:
            return

        # Unpack the PAC as both PAC_DATA and PAC_DATA_RAW types. We use the
        # raw type to create a new PAC with zeroed signatures for
        # verification. This is because on Windows, the resource_groups field
        # is added to PAC_LOGON_INFO after the info3 field has been created,
        # which results in a different ordering of pointer values than Samba
        # (see commit 0e201ecdc53). Using the raw type avoids changing
        # PAC_LOGON_INFO, so verification against Windows can work. We still
        # need the PAC_DATA type to retrieve the actual checksums, because the
        # signatures in the raw type may contain padding bytes.
        pac = ndr_unpack(krb5pac.PAC_DATA,
                         pac_data)
        raw_pac = ndr_unpack(krb5pac.PAC_DATA_RAW,
                             pac_data)

        checksums = {}

        full_checksum_buffer = None

        for pac_buffer, raw_pac_buffer in zip(pac.buffers, raw_pac.buffers):
            buffer_type = pac_buffer.type
            if buffer_type in self.pac_checksum_types:
                self.assertNotIn(buffer_type, checksums,
                                 f'Duplicate checksum type {buffer_type}')

                # Fetch the checksum and the checksum type from the PAC buffer.
                checksum = pac_buffer.info.signature
                ctype = pac_buffer.info.type
                if ctype & 1 << 31:
                    ctype |= -1 << 31

                checksums[buffer_type] = checksum, ctype

                if buffer_type == krb5pac.PAC_TYPE_FULL_CHECKSUM:
                    full_checksum_buffer = raw_pac_buffer
                elif buffer_type != krb5pac.PAC_TYPE_TICKET_CHECKSUM:
                    # Zero the checksum field so that we can later verify the
                    # checksums. The ticket checksum field is not zeroed.

                    signature = ndr_unpack(
                        krb5pac.PAC_SIGNATURE_DATA,
                        raw_pac_buffer.info.remaining)
                    signature.signature = bytes(len(checksum))
                    raw_pac_buffer.info.remaining = ndr_pack(
                        signature)

        # Re-encode the PAC.
        pac_data = ndr_pack(raw_pac)

        if full_checksum_buffer is not None:
            signature = ndr_unpack(
                krb5pac.PAC_SIGNATURE_DATA,
                full_checksum_buffer.info.remaining)
            signature.signature = bytes(len(checksum))
            full_checksum_buffer.info.remaining = ndr_pack(
                signature)

            # Re-encode the PAC.
            full_pac_data = ndr_pack(raw_pac)

        # Verify the signatures.

        server_checksum, server_ctype = checksums[
            krb5pac.PAC_TYPE_SRV_CHECKSUM]
        key.verify_checksum(KU_NON_KERB_CKSUM_SALT,
                            pac_data,
                            server_ctype,
                            server_checksum)

        kdc_checksum, kdc_ctype = checksums[
            krb5pac.PAC_TYPE_KDC_CHECKSUM]

        if isinstance(krbtgt_keys, collections.abc.Container):
            if self.strict_checking:
                krbtgt_key = krbtgt_keys[0]
            else:
                krbtgt_key = next(key for key in krbtgt_keys
                                  if key.ctype == kdc_ctype)
        else:
            krbtgt_key = krbtgt_keys

        krbtgt_key.verify_rodc_checksum(KU_NON_KERB_CKSUM_SALT,
                                        server_checksum,
                                        kdc_ctype,
                                        kdc_checksum)

        if not service_ticket:
            self.assertNotIn(krb5pac.PAC_TYPE_TICKET_CHECKSUM, checksums)
            self.assertNotIn(krb5pac.PAC_TYPE_FULL_CHECKSUM, checksums)
        else:
            ticket_checksum, ticket_ctype = checksums.get(
                krb5pac.PAC_TYPE_TICKET_CHECKSUM,
                (None, None))
            if expect_ticket_checksum:
                self.assertIsNotNone(ticket_checksum)
            elif expect_ticket_checksum is False:
                self.assertIsNone(ticket_checksum)
            if ticket_checksum is not None:
                enc_part['authorization-data'] = auth_data
                enc_part = self.der_encode(enc_part,
                                           asn1Spec=krb5_asn1.EncTicketPart())

                krbtgt_key.verify_rodc_checksum(KU_NON_KERB_CKSUM_SALT,
                                                enc_part,
                                                ticket_ctype,
                                                ticket_checksum)

            full_checksum, full_ctype = checksums.get(
                krb5pac.PAC_TYPE_FULL_CHECKSUM,
                (None, None))
            if expect_full_checksum:
                self.assertIsNotNone(full_checksum)
            elif expect_full_checksum is False:
                self.assertIsNone(full_checksum)
            if full_checksum is not None:
                krbtgt_key.verify_rodc_checksum(KU_NON_KERB_CKSUM_SALT,
                                                full_pac_data,
                                                full_ctype,
                                                full_checksum)

    def modified_ticket(self,
                        ticket, *,
                        new_ticket_key=None,
                        modify_fn=None,
                        modify_pac_fn=None,
                        exclude_pac=False,
                        allow_empty_authdata=False,
                        update_pac_checksums=None,
                        checksum_keys=None,
                        include_checksums=None):
        if checksum_keys is None:
            # A dict containing a key for each checksum type to be created in
            # the PAC.
            checksum_keys = {}
        else:
            checksum_keys = dict(checksum_keys)

        if include_checksums is None:
            # A dict containing a value for each checksum type; True if the
            # checksum type is to be included in the PAC, False if it is to be
            # excluded, or None/not present if the checksum is to be included
            # based on its presence in the original PAC.
            include_checksums = {}
        else:
            include_checksums = dict(include_checksums)

        # Check that the values passed in by the caller make sense.

        self.assertLessEqual(checksum_keys.keys(), self.pac_checksum_types)
        self.assertLessEqual(include_checksums.keys(), self.pac_checksum_types)

        if update_pac_checksums is None:
            update_pac_checksums = not exclude_pac

        if exclude_pac:
            self.assertIsNone(modify_pac_fn)
            self.assertFalse(update_pac_checksums)

        if not update_pac_checksums:
            self.assertFalse(checksum_keys)
            self.assertFalse(include_checksums)

        expect_pac = bool(modify_pac_fn)

        key = ticket.decryption_key

        if new_ticket_key is None:
            # Use the same key to re-encrypt the ticket.
            new_ticket_key = key

        if krb5pac.PAC_TYPE_SRV_CHECKSUM not in checksum_keys:
            # If the server signature key is not present, fall back to the key
            # used to encrypt the ticket.
            checksum_keys[krb5pac.PAC_TYPE_SRV_CHECKSUM] = new_ticket_key

        if krb5pac.PAC_TYPE_TICKET_CHECKSUM not in checksum_keys:
            # If the ticket signature key is not present, fall back to the key
            # used for the KDC signature.
            kdc_checksum_key = checksum_keys.get(krb5pac.PAC_TYPE_KDC_CHECKSUM)
            if kdc_checksum_key is not None:
                checksum_keys[krb5pac.PAC_TYPE_TICKET_CHECKSUM] = (
                    kdc_checksum_key)

        if krb5pac.PAC_TYPE_FULL_CHECKSUM not in checksum_keys:
            # If the full signature key is not present, fall back to the key
            # used for the KDC signature.
            kdc_checksum_key = checksum_keys.get(krb5pac.PAC_TYPE_KDC_CHECKSUM)
            if kdc_checksum_key is not None:
                checksum_keys[krb5pac.PAC_TYPE_FULL_CHECKSUM] = (
                    kdc_checksum_key)

        # Decrypt the ticket.

        enc_part = ticket.ticket['enc-part']

        self.assertElementEqual(enc_part, 'etype', key.etype)
        self.assertElementKVNO(enc_part, 'kvno', key.kvno)

        enc_part = key.decrypt(KU_TICKET, enc_part['cipher'])
        enc_part = self.der_decode(
            enc_part, asn1Spec=krb5_asn1.EncTicketPart())

        # Modify the ticket here.
        if callable(modify_fn):
            enc_part = modify_fn(enc_part)
        elif modify_fn:
            for fn in modify_fn:
                enc_part = fn(enc_part)

        auth_data = enc_part.get('authorization-data')
        if expect_pac:
            self.assertIsNotNone(auth_data)
        if auth_data is not None:
            new_pac = None
            if exclude_pac:
                need_to_call_replace_pac = True
            elif not modify_pac_fn and not update_pac_checksums:
                need_to_call_replace_pac = False
            else:
                need_to_call_replace_pac = True
                # Get a copy of the authdata with an empty PAC, and the
                # existing PAC (if present).
                empty_pac = self.get_empty_pac()
                empty_pac_auth_data, pac_data = self.replace_pac(
                    auth_data,
                    empty_pac,
                    expect_pac=expect_pac)

                if pac_data is not None:
                    pac = ndr_unpack(krb5pac.PAC_DATA, pac_data)

                    # Modify the PAC here.
                    if callable(modify_pac_fn):
                        pac = modify_pac_fn(pac)
                    elif modify_pac_fn:
                        for fn in modify_pac_fn:
                            pac = fn(pac)

                    if update_pac_checksums:
                        # Get the enc-part with an empty PAC, which is needed
                        # to create a ticket signature.
                        enc_part_to_sign = enc_part.copy()
                        enc_part_to_sign['authorization-data'] = (
                            empty_pac_auth_data)
                        enc_part_to_sign = self.der_encode(
                            enc_part_to_sign,
                            asn1Spec=krb5_asn1.EncTicketPart())

                        self.update_pac_checksums(pac,
                                                  checksum_keys,
                                                  include_checksums,
                                                  enc_part_to_sign)

                    # Re-encode the PAC.
                    pac_data = ndr_pack(pac)
                    new_pac = self.AuthorizationData_create(AD_WIN2K_PAC,
                                                            pac_data)

            # Replace the PAC in the authorization data and re-add it to the
            # ticket enc-part.
            if need_to_call_replace_pac:
                auth_data, _ = self.replace_pac(
                    auth_data, new_pac,
                    expect_pac=expect_pac,
                    allow_empty_authdata=allow_empty_authdata)
                enc_part['authorization-data'] = auth_data

        # Re-encrypt the ticket enc-part with the new key.
        enc_part_new = self.der_encode(enc_part,
                                       asn1Spec=krb5_asn1.EncTicketPart())
        enc_part_new = self.EncryptedData_create(new_ticket_key,
                                                 KU_TICKET,
                                                 enc_part_new)

        # Create a copy of the ticket with the new enc-part.
        new_ticket = ticket.ticket.copy()
        new_ticket['enc-part'] = enc_part_new

        new_ticket_creds = KerberosTicketCreds(
            new_ticket,
            session_key=ticket.session_key,
            crealm=ticket.crealm,
            cname=ticket.cname,
            srealm=ticket.srealm,
            sname=ticket.sname,
            decryption_key=new_ticket_key,
            ticket_private=enc_part,
            encpart_private=ticket.encpart_private)

        return new_ticket_creds

    def update_pac_checksums(self,
                             pac,
                             checksum_keys,
                             include_checksums,
                             enc_part=None):
        pac_buffers = pac.buffers
        checksum_buffers = {}

        # Find the relevant PAC checksum buffers.
        for pac_buffer in pac_buffers:
            buffer_type = pac_buffer.type
            if buffer_type in self.pac_checksum_types:
                self.assertNotIn(buffer_type, checksum_buffers,
                                 f'Duplicate checksum type {buffer_type}')

                checksum_buffers[buffer_type] = pac_buffer

        # Create any additional buffers that were requested but not
        # present. Conversely, remove any buffers that were requested to be
        # removed.
        for buffer_type in self.pac_checksum_types:
            if buffer_type in checksum_buffers:
                if include_checksums.get(buffer_type) is False:
                    checksum_buffer = checksum_buffers.pop(buffer_type)

                    pac.num_buffers -= 1
                    pac_buffers.remove(checksum_buffer)

            elif include_checksums.get(buffer_type) is True:
                info = krb5pac.PAC_SIGNATURE_DATA()

                checksum_buffer = krb5pac.PAC_BUFFER()
                checksum_buffer.type = buffer_type
                checksum_buffer.info = info

                pac_buffers.append(checksum_buffer)
                pac.num_buffers += 1

                checksum_buffers[buffer_type] = checksum_buffer

        # Fill the relevant checksum buffers.
        for buffer_type, checksum_buffer in checksum_buffers.items():
            checksum_key = checksum_keys[buffer_type]
            ctype = checksum_key.ctype & ((1 << 32) - 1)

            if buffer_type == krb5pac.PAC_TYPE_TICKET_CHECKSUM:
                self.assertIsNotNone(enc_part)

                signature = checksum_key.make_rodc_checksum(
                    KU_NON_KERB_CKSUM_SALT,
                    enc_part)

            elif buffer_type == krb5pac.PAC_TYPE_SRV_CHECKSUM:
                signature = checksum_key.make_zeroed_checksum()

            else:
                signature = checksum_key.make_rodc_zeroed_checksum()

            checksum_buffer.info.signature = signature
            checksum_buffer.info.type = ctype

        # Add the new checksum buffers to the PAC.
        pac.buffers = pac_buffers

        # Calculate the full checksum and insert it into the PAC.
        full_checksum_buffer = checksum_buffers.get(
            krb5pac.PAC_TYPE_FULL_CHECKSUM)
        if full_checksum_buffer is not None:
            full_checksum_key = checksum_keys[krb5pac.PAC_TYPE_FULL_CHECKSUM]

            pac_data = ndr_pack(pac)
            full_checksum = full_checksum_key.make_rodc_checksum(
                KU_NON_KERB_CKSUM_SALT,
                pac_data)

            full_checksum_buffer.info.signature = full_checksum

        # Calculate the server and KDC checksums and insert them into the PAC.

        server_checksum_buffer = checksum_buffers.get(
            krb5pac.PAC_TYPE_SRV_CHECKSUM)
        if server_checksum_buffer is not None:
            server_checksum_key = checksum_keys[krb5pac.PAC_TYPE_SRV_CHECKSUM]

            pac_data = ndr_pack(pac)
            server_checksum = server_checksum_key.make_checksum(
                KU_NON_KERB_CKSUM_SALT,
                pac_data)

            server_checksum_buffer.info.signature = server_checksum

        kdc_checksum_buffer = checksum_buffers.get(
            krb5pac.PAC_TYPE_KDC_CHECKSUM)
        if kdc_checksum_buffer is not None:
            if server_checksum_buffer is None:
                # There's no server signature to make the checksum over, so
                # just make the checksum over an empty bytes object.
                server_checksum = bytes()

            kdc_checksum_key = checksum_keys[krb5pac.PAC_TYPE_KDC_CHECKSUM]

            kdc_checksum = kdc_checksum_key.make_rodc_checksum(
                KU_NON_KERB_CKSUM_SALT,
                server_checksum)

            kdc_checksum_buffer.info.signature = kdc_checksum

    def replace_pac(self, auth_data, new_pac, expect_pac=True,
                    allow_empty_authdata=False):
        if new_pac is not None:
            self.assertElementEqual(new_pac, 'ad-type', AD_WIN2K_PAC)
            self.assertElementPresent(new_pac, 'ad-data')

        new_auth_data = []

        ad_relevant = None
        old_pac = None

        for authdata_elem in auth_data:
            if authdata_elem['ad-type'] == AD_IF_RELEVANT:
                ad_relevant = self.der_decode(
                    authdata_elem['ad-data'],
                    asn1Spec=krb5_asn1.AD_IF_RELEVANT())

                relevant_elems = []
                for relevant_elem in ad_relevant:
                    if relevant_elem['ad-type'] == AD_WIN2K_PAC:
                        self.assertIsNone(old_pac, 'Multiple PACs detected')
                        old_pac = relevant_elem['ad-data']

                        if new_pac is not None:
                            relevant_elems.append(new_pac)
                    else:
                        relevant_elems.append(relevant_elem)
                if expect_pac:
                    self.assertIsNotNone(old_pac, 'Expected PAC')

                if relevant_elems or allow_empty_authdata:
                    ad_relevant = self.der_encode(
                        relevant_elems,
                        asn1Spec=krb5_asn1.AD_IF_RELEVANT())

                    authdata_elem = self.AuthorizationData_create(
                        AD_IF_RELEVANT,
                        ad_relevant)
                else:
                    authdata_elem = None

            if authdata_elem is not None or allow_empty_authdata:
                new_auth_data.append(authdata_elem)

        if expect_pac:
            self.assertIsNotNone(ad_relevant, 'Expected AD-RELEVANT')

        return new_auth_data, old_pac

    def get_pac(self, auth_data, expect_pac=True):
        _, pac = self.replace_pac(auth_data, None, expect_pac)
        return pac

    def get_ticket_pac(self, ticket, expect_pac=True):
        auth_data = ticket.ticket_private.get('authorization-data')
        if expect_pac:
            self.assertIsNotNone(auth_data)
        elif auth_data is None:
            return None

        return self.get_pac(auth_data, expect_pac=expect_pac)

    def get_krbtgt_checksum_key(self):
        krbtgt_creds = self.get_krbtgt_creds()
        krbtgt_key = self.TicketDecryptionKey_from_creds(krbtgt_creds)

        return {
            krb5pac.PAC_TYPE_KDC_CHECKSUM: krbtgt_key
        }

    def is_tgs_principal(self, principal):
        if self.is_tgs(principal):
            return True

        if self.kadmin_is_tgs and self.is_kadmin(principal):
            return True

        return False

    def is_kadmin(self, principal):
        name = principal['name-string'][0]
        return name in ('kadmin', b'kadmin')

    def is_tgs(self, principal):
        name_string = principal['name-string']
        if 1 <= len(name_string) <= 2:
            return name_string[0] in ('krbtgt', b'krbtgt')

        return False

    def is_tgt(self, ticket):
        sname = ticket.ticket['sname']
        return self.is_tgs(sname)

    def get_empty_pac(self):
        return self.AuthorizationData_create(AD_WIN2K_PAC, bytes(1))

    def get_outer_pa_dict(self, kdc_exchange_dict):
        return self.get_pa_dict(kdc_exchange_dict['req_padata'])

    def get_fast_pa_dict(self, kdc_exchange_dict):
        req_pa_dict = self.get_pa_dict(kdc_exchange_dict['fast_padata'])

        if req_pa_dict:
            return req_pa_dict

        return self.get_outer_pa_dict(kdc_exchange_dict)

    def sent_fast(self, kdc_exchange_dict):
        outer_pa_dict = self.get_outer_pa_dict(kdc_exchange_dict)

        return PADATA_FX_FAST in outer_pa_dict

    def sent_enc_challenge(self, kdc_exchange_dict):
        fast_pa_dict = self.get_fast_pa_dict(kdc_exchange_dict)

        return PADATA_ENCRYPTED_CHALLENGE in fast_pa_dict

    def sent_enc_pa_rep(self, kdc_exchange_dict):
        fast_pa_dict = self.get_fast_pa_dict(kdc_exchange_dict)

        return PADATA_REQ_ENC_PA_REP in fast_pa_dict

    def sent_pk_as_req(self, kdc_exchange_dict):
        fast_pa_dict = self.get_fast_pa_dict(kdc_exchange_dict)

        return PADATA_PK_AS_REQ in fast_pa_dict

    def sent_pk_as_req_win2k(self, kdc_exchange_dict):
        fast_pa_dict = self.get_fast_pa_dict(kdc_exchange_dict)

        return PADATA_PK_AS_REP_19 in fast_pa_dict

    def sent_freshness(self, kdc_exchange_dict):
        fast_pa_dict = self.get_fast_pa_dict(kdc_exchange_dict)

        return PADATA_AS_FRESHNESS in fast_pa_dict

    def get_sent_pac_options(self, kdc_exchange_dict):
        fast_pa_dict = self.get_fast_pa_dict(kdc_exchange_dict)

        if PADATA_PAC_OPTIONS not in fast_pa_dict:
            return ''

        pac_options = self.der_decode(fast_pa_dict[PADATA_PAC_OPTIONS],
                                      asn1Spec=krb5_asn1.PA_PAC_OPTIONS())
        pac_options = pac_options['options']

        # Mask out unsupported bits.
        pac_options, remaining = pac_options[:4], pac_options[4:]
        pac_options += '0' * len(remaining)

        return pac_options

    def get_krbtgt_sname(self):
        krbtgt_creds = self.get_krbtgt_creds()
        krbtgt_username = krbtgt_creds.get_username()
        krbtgt_realm = krbtgt_creds.get_realm()
        krbtgt_sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=[krbtgt_username, krbtgt_realm])

        return krbtgt_sname

    def get_kpasswd_sname(self):
        return self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                         names=['kadmin', 'changepw'])

    def add_requester_sid(self, pac, sid):
        pac_buffers = pac.buffers

        buffer_types = [pac_buffer.type for pac_buffer in pac_buffers]
        self.assertNotIn(krb5pac.PAC_TYPE_REQUESTER_SID, buffer_types)

        requester_sid = krb5pac.PAC_REQUESTER_SID()
        requester_sid.sid = security.dom_sid(sid)

        requester_sid_buffer = krb5pac.PAC_BUFFER()
        requester_sid_buffer.type = krb5pac.PAC_TYPE_REQUESTER_SID
        requester_sid_buffer.info = requester_sid

        pac_buffers.append(requester_sid_buffer)

        pac.buffers = pac_buffers
        pac.num_buffers += 1

        return pac

    def modify_lifetime(self, ticket, lifetime, requester_sid=None):
        # Get the krbtgt key.
        krbtgt_creds = self.get_krbtgt_creds()

        krbtgt_key = self.TicketDecryptionKey_from_creds(krbtgt_creds)
        checksum_keys = {
            krb5pac.PAC_TYPE_KDC_CHECKSUM: krbtgt_key,
        }

        current_time = time.time()

        # Set authtime and starttime to an hour in the past, to show that they
        # do not affect ticket rejection.
        start_time = self.get_KerberosTime(epoch=current_time, offset=-60 * 60)

        # Set the endtime of the ticket relative to our current time, so that
        # the ticket has 'lifetime' seconds remaining to live.
        end_time = self.get_KerberosTime(epoch=current_time, offset=lifetime)

        # Modify the times in the ticket.
        def modify_ticket_times(enc_part):
            enc_part['authtime'] = start_time
            if 'starttime' in enc_part:
                enc_part['starttime'] = start_time

            enc_part['endtime'] = end_time

            return enc_part

        # We have to set the times in both the ticket and the PAC, otherwise
        # Heimdal will complain.
        def modify_pac_time(pac):
            pac_buffers = pac.buffers

            for pac_buffer in pac_buffers:
                if pac_buffer.type == krb5pac.PAC_TYPE_LOGON_NAME:
                    logon_time = self.get_EpochFromKerberosTime(start_time)
                    pac_buffer.info.logon_time = unix2nttime(logon_time)
                    break
            else:
                self.fail('failed to find LOGON_NAME PAC buffer')

            pac.buffers = pac_buffers

            return pac

        def modify_pac_fn(pac):
            if requester_sid is not None:
                # Add a requester SID to show that the KDC will then accept
                # this kpasswd ticket as if it were a TGT.
                pac = self.add_requester_sid(pac, sid=requester_sid)
            pac = modify_pac_time(pac)
            return pac

        # Do the actual modification.
        return self.modified_ticket(ticket,
                                    new_ticket_key=krbtgt_key,
                                    modify_fn=modify_ticket_times,
                                    modify_pac_fn=modify_pac_fn,
                                    checksum_keys=checksum_keys)

    def _test_as_exchange(self,
                          cname,
                          realm,
                          sname,
                          till,
                          expected_error_mode,
                          expected_crealm,
                          expected_cname,
                          expected_srealm,
                          expected_sname,
                          expected_salt,
                          etypes,
                          padata,
                          kdc_options,
                          creds=None,
                          renew_time=None,
                          expected_account_name=None,
                          expected_groups=None,
                          unexpected_groups=None,
                          expected_upn_name=None,
                          expected_sid=None,
                          expected_domain_sid=None,
                          expected_flags=None,
                          unexpected_flags=None,
                          expected_supported_etypes=None,
                          preauth_key=None,
                          ticket_decryption_key=None,
                          pac_request=None,
                          pac_options=None,
                          expect_pac=True,
                          expect_pac_attrs=None,
                          expect_pac_attrs_pac_request=None,
                          expect_requester_sid=None,
                          expect_client_claims=None,
                          expect_device_claims=None,
                          expected_client_claims=None,
                          unexpected_client_claims=None,
                          expected_device_claims=None,
                          unexpected_device_claims=None,
                          expect_edata=None,
                          expect_status=None,
                          expected_status=None,
                          rc4_support=True,
                          to_rodc=False):

        def _generate_padata_copy(_kdc_exchange_dict,
                                  _callback_dict,
                                  req_body):
            return padata, req_body

        if not expected_error_mode:
            check_error_fn = None
            check_rep_fn = self.generic_check_kdc_rep
        else:
            check_error_fn = self.generic_check_kdc_error
            check_rep_fn = None

        if padata is not None:
            generate_padata_fn = _generate_padata_copy
        else:
            generate_padata_fn = None

        kdc_exchange_dict = self.as_exchange_dict(
            creds=creds,
            expected_crealm=expected_crealm,
            expected_cname=expected_cname,
            expected_srealm=expected_srealm,
            expected_sname=expected_sname,
            expected_account_name=expected_account_name,
            expected_groups=expected_groups,
            unexpected_groups=unexpected_groups,
            expected_upn_name=expected_upn_name,
            expected_sid=expected_sid,
            expected_domain_sid=expected_domain_sid,
            expected_supported_etypes=expected_supported_etypes,
            ticket_decryption_key=ticket_decryption_key,
            generate_padata_fn=generate_padata_fn,
            check_error_fn=check_error_fn,
            check_rep_fn=check_rep_fn,
            check_kdc_private_fn=self.generic_check_kdc_private,
            expected_error_mode=expected_error_mode,
            expected_salt=expected_salt,
            expected_flags=expected_flags,
            unexpected_flags=unexpected_flags,
            preauth_key=preauth_key,
            kdc_options=str(kdc_options),
            pac_request=pac_request,
            pac_options=pac_options,
            expect_pac=expect_pac,
            expect_pac_attrs=expect_pac_attrs,
            expect_pac_attrs_pac_request=expect_pac_attrs_pac_request,
            expect_requester_sid=expect_requester_sid,
            expect_client_claims=expect_client_claims,
            expect_device_claims=expect_device_claims,
            expected_client_claims=expected_client_claims,
            unexpected_client_claims=unexpected_client_claims,
            expected_device_claims=expected_device_claims,
            unexpected_device_claims=unexpected_device_claims,
            expect_edata=expect_edata,
            expect_status=expect_status,
            expected_status=expected_status,
            rc4_support=rc4_support,
            to_rodc=to_rodc)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=cname,
                                         realm=realm,
                                         sname=sname,
                                         till_time=till,
                                         renew_time=renew_time,
                                         etypes=etypes)

        return rep, kdc_exchange_dict
