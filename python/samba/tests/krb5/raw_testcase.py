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
import socket
import struct
import time
import datetime
import random
import binascii
import itertools
import collections

from pyasn1.codec.der.decoder import decode as pyasn1_der_decode
from pyasn1.codec.der.encoder import encode as pyasn1_der_encode
from pyasn1.codec.native.decoder import decode as pyasn1_native_decode
from pyasn1.codec.native.encoder import encode as pyasn1_native_encode

from pyasn1.codec.ber.encoder import BitStringEncoder

from samba.credentials import Credentials
from samba.dcerpc import krb5pac, security
from samba.gensec import FEATURE_SEAL
from samba.ndr import ndr_pack, ndr_unpack

import samba.tests
from samba.tests import TestCaseInTempDir

import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
from samba.tests.krb5.rfc4120_constants import (
    AD_IF_RELEVANT,
    AD_WIN2K_PAC,
    FX_FAST_ARMOR_AP_REQUEST,
    KDC_ERR_GENERIC,
    KDC_ERR_PREAUTH_FAILED,
    KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS,
    KERB_ERR_TYPE_EXTENDED,
    KRB_AP_REQ,
    KRB_AS_REP,
    KRB_AS_REQ,
    KRB_ERROR,
    KRB_TGS_REP,
    KRB_TGS_REQ,
    KU_AP_REQ_AUTH,
    KU_AS_REP_ENC_PART,
    KU_ENC_CHALLENGE_KDC,
    KU_FAST_ENC,
    KU_FAST_FINISHED,
    KU_FAST_REP,
    KU_FAST_REQ_CHKSUM,
    KU_NON_KERB_CKSUM_SALT,
    KU_TGS_REP_ENC_PART_SESSION,
    KU_TGS_REP_ENC_PART_SUB_KEY,
    KU_TGS_REQ_AUTH,
    KU_TGS_REQ_AUTH_CKSUM,
    KU_TGS_REQ_AUTH_DAT_SESSION,
    KU_TGS_REQ_AUTH_DAT_SUBKEY,
    KU_TICKET,
    NT_SRV_INST,
    NT_WELLKNOWN,
    PADATA_ENCRYPTED_CHALLENGE,
    PADATA_ENC_TIMESTAMP,
    PADATA_ETYPE_INFO,
    PADATA_ETYPE_INFO2,
    PADATA_FOR_USER,
    PADATA_FX_COOKIE,
    PADATA_FX_ERROR,
    PADATA_FX_FAST,
    PADATA_KDC_REQ,
    PADATA_PAC_OPTIONS,
    PADATA_PAC_REQUEST,
    PADATA_PK_AS_REQ,
    PADATA_PK_AS_REP_19,
    PADATA_SUPPORTED_ETYPES
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

    fast_supported_bits = (security.KERB_ENCTYPE_FAST_SUPPORTED |
                           security.KERB_ENCTYPE_COMPOUND_IDENTITY_SUPPORTED |
                           security.KERB_ENCTYPE_CLAIMS_SUPPORTED)

    def __init__(self):
        super(KerberosCredentials, self).__init__()
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

    def set_as_supported_enctypes(self, value):
        self.as_supported_enctypes = int(value)

    def set_tgs_supported_enctypes(self, value):
        self.tgs_supported_enctypes = int(value)

    def set_ap_supported_enctypes(self, value):
        self.ap_supported_enctypes = int(value)

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

        bits &= ~cls.fast_supported_bits
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

    def get_forced_key(self, etype):
        etype = int(etype)
        return self.forced_keys.get(etype)

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

        if self.get_workstation():
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


class KerberosTicketCreds:
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


class RawKerberosTest(TestCaseInTempDir):
    """A raw Kerberos Test case."""

    pac_checksum_types = {krb5pac.PAC_TYPE_SRV_CHECKSUM,
                          krb5pac.PAC_TYPE_KDC_CHECKSUM,
                          krb5pac.PAC_TYPE_TICKET_CHECKSUM}

    etypes_to_test = (
        {"value": -1111, "name": "dummy", },
        {"value": kcrypto.Enctype.AES256, "name": "aes128", },
        {"value": kcrypto.Enctype.AES128, "name": "aes256", },
        {"value": kcrypto.Enctype.RC4, "name": "rc4", },
    )

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

        tkt_sig_support = samba.tests.env_get_var_value('TKT_SIG_SUPPORT',
                                                        allow_missing=True)
        if tkt_sig_support is None:
            tkt_sig_support = '0'
        cls.tkt_sig_support = bool(int(tkt_sig_support))

    def setUp(self):
        super().setUp()
        self.do_asn1_print = False
        self.do_hexdump = False

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

    def _connect_tcp(self, host):
        tcp_port = 88
        try:
            self.a = socket.getaddrinfo(host, tcp_port, socket.AF_UNSPEC,
                                        socket.SOCK_STREAM, socket.SOL_TCP,
                                        0)
            self.s = socket.socket(self.a[0][0], self.a[0][1], self.a[0][2])
            self.s.settimeout(10)
            self.s.connect(self.a[0][4])
        except socket.error:
            self.s.close()
            raise
        except IOError:
            self.s.close()
            raise

    def connect(self, host):
        self.assertNotConnected()
        self._connect_tcp(host)
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
            c.set_kvno(kvno)
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
        try:
            k5_pdu = self.der_encode(
                req, native_decode=False, asn1_print=asn1_print, hexdump=False)
            header = struct.pack('>I', len(k5_pdu))
            req_pdu = header
            req_pdu += k5_pdu
            self.hex_dump("send_pdu", header, hexdump=hexdump)
            self.hex_dump("send_pdu", k5_pdu, hexdump=hexdump)
            while True:
                sent = self.s.send(req_pdu, 0)
                if sent == len(req_pdu):
                    break
                req_pdu = req_pdu[sent:]
        except socket.error as e:
            self._disconnect("send_pdu: %s" % e)
            raise
        except IOError as e:
            self._disconnect("send_pdu: %s" % e)
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
        except IOError as e:
            self._disconnect("recv_raw: %s" % e)
            raise
        return rep_pdu

    def recv_pdu_raw(self, asn1_print=None, hexdump=None, timeout=None):
        rep_pdu = None
        rep = None
        raw_pdu = self.recv_raw(
            num_recv=4, hexdump=hexdump, timeout=timeout)
        if raw_pdu is None:
            return (None, None)
        header = struct.unpack(">I", raw_pdu[0:4])
        k5_len = header[0]
        if k5_len == 0:
            return (None, "")
        missing = k5_len
        rep_pdu = b''
        while missing > 0:
            raw_pdu = self.recv_raw(
                num_recv=missing, hexdump=hexdump, timeout=timeout)
            self.assertGreaterEqual(len(raw_pdu), 1)
            rep_pdu += raw_pdu
            missing = k5_len - len(rep_pdu)
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
        (rep, rep_pdu) = self.recv_pdu_raw(asn1_print=asn1_print,
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

    def assertNoValue(self, value):
        self.assertTrue(value.isNoValue)

    def assertHasValue(self, value):
        self.assertIsNotNone(value)

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
                                    require_strict=None):
        if self.strict_checking:
            self.assertEqual(expected, got)
        else:
            fail_msg = f'expected: {expected} got: {got}'

            if require_strict is not None:
                fail_msg += f' (ignoring: {require_strict})'
                expected = (x for x in expected if x not in require_strict)
                got = (x for x in got if x not in require_strict)

            self.assertCountEqual(expected, got, fail_msg)

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

    def PasswordKey_create(self, etype=None, pwd=None, salt=None, kvno=None):
        self.assertIsNotNone(pwd)
        self.assertIsNotNone(salt)
        key = kcrypto.string_to_key(etype, pwd, salt)
        return RodcPacEncryptionKey(key, kvno)

    def PasswordKey_from_etype_info2(self, creds, etype_info2, kvno=None):
        e = etype_info2['etype']

        salt = etype_info2.get('salt')

        if e == kcrypto.Enctype.RC4:
            nthash = creds.get_nt_hash()
            return self.SessionKey_create(etype=e, contents=nthash, kvno=kvno)

        password = creds.get_password()
        return self.PasswordKey_create(
            etype=e, pwd=password, salt=salt, kvno=kvno)

    def TicketDecryptionKey_from_creds(self, creds, etype=None):

        if etype is None:
            etypes = creds.get_tgs_krb5_etypes()
            if etypes:
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
                                                 req_body,
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
                         expected_crealm=None,
                         expected_cname=None,
                         expected_anon=False,
                         expected_srealm=None,
                         expected_sname=None,
                         expected_account_name=None,
                         expected_sid=None,
                         expected_supported_etypes=None,
                         expected_flags=None,
                         unexpected_flags=None,
                         ticket_decryption_key=None,
                         expect_ticket_checksum=None,
                         generate_fast_fn=None,
                         generate_fast_armor_fn=None,
                         generate_fast_padata_fn=None,
                         fast_armor_type=FX_FAST_ARMOR_AP_REQUEST,
                         generate_padata_fn=None,
                         check_error_fn=None,
                         check_rep_fn=None,
                         check_kdc_private_fn=None,
                         callback_dict=None,
                         expected_error_mode=0,
                         expected_status=None,
                         client_as_etypes=None,
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
                         expect_edata=None,
                         expect_pac=True,
                         expect_claims=True,
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
            'expected_crealm': expected_crealm,
            'expected_cname': expected_cname,
            'expected_anon': expected_anon,
            'expected_srealm': expected_srealm,
            'expected_sname': expected_sname,
            'expected_account_name': expected_account_name,
            'expected_sid': expected_sid,
            'expected_supported_etypes': expected_supported_etypes,
            'expected_flags': expected_flags,
            'unexpected_flags': unexpected_flags,
            'ticket_decryption_key': ticket_decryption_key,
            'expect_ticket_checksum': expect_ticket_checksum,
            'generate_fast_fn': generate_fast_fn,
            'generate_fast_armor_fn': generate_fast_armor_fn,
            'generate_fast_padata_fn': generate_fast_padata_fn,
            'fast_armor_type': fast_armor_type,
            'generate_padata_fn': generate_padata_fn,
            'check_error_fn': check_error_fn,
            'check_rep_fn': check_rep_fn,
            'check_kdc_private_fn': check_kdc_private_fn,
            'callback_dict': callback_dict,
            'expected_error_mode': expected_error_mode,
            'expected_status': expected_status,
            'client_as_etypes': client_as_etypes,
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
            'expect_edata': expect_edata,
            'expect_pac': expect_pac,
            'expect_claims': expect_claims,
            'to_rodc': to_rodc
        }
        if callback_dict is None:
            callback_dict = {}

        return kdc_exchange_dict

    def tgs_exchange_dict(self,
                          expected_crealm=None,
                          expected_cname=None,
                          expected_anon=False,
                          expected_srealm=None,
                          expected_sname=None,
                          expected_account_name=None,
                          expected_sid=None,
                          expected_supported_etypes=None,
                          expected_flags=None,
                          unexpected_flags=None,
                          ticket_decryption_key=None,
                          expect_ticket_checksum=None,
                          generate_fast_fn=None,
                          generate_fast_armor_fn=None,
                          generate_fast_padata_fn=None,
                          fast_armor_type=FX_FAST_ARMOR_AP_REQUEST,
                          generate_padata_fn=None,
                          check_error_fn=None,
                          check_rep_fn=None,
                          check_kdc_private_fn=None,
                          expected_error_mode=0,
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
                          expect_edata=None,
                          expect_pac=True,
                          expect_claims=True,
                          expected_proxy_target=None,
                          expected_transited_services=None,
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
            'expected_crealm': expected_crealm,
            'expected_cname': expected_cname,
            'expected_anon': expected_anon,
            'expected_srealm': expected_srealm,
            'expected_sname': expected_sname,
            'expected_account_name': expected_account_name,
            'expected_sid': expected_sid,
            'expected_supported_etypes': expected_supported_etypes,
            'expected_flags': expected_flags,
            'unexpected_flags': unexpected_flags,
            'ticket_decryption_key': ticket_decryption_key,
            'expect_ticket_checksum': expect_ticket_checksum,
            'generate_fast_fn': generate_fast_fn,
            'generate_fast_armor_fn': generate_fast_armor_fn,
            'generate_fast_padata_fn': generate_fast_padata_fn,
            'fast_armor_type': fast_armor_type,
            'generate_padata_fn': generate_padata_fn,
            'check_error_fn': check_error_fn,
            'check_rep_fn': check_rep_fn,
            'check_kdc_private_fn': check_kdc_private_fn,
            'callback_dict': callback_dict,
            'expected_error_mode': expected_error_mode,
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
            'expect_edata': expect_edata,
            'expect_pac': expect_pac,
            'expect_claims': expect_claims,
            'expected_proxy_target': expected_proxy_target,
            'expected_transited_services': expected_transited_services,
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

        self.assertElementEqual(rep, 'msg-type', msg_type)  # AS-REP | TGS-REP
        padata = self.getElementValue(rep, 'padata')
        if self.strict_checking:
            self.assertElementEqualUTF8(rep, 'crealm', expected_crealm)
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
                # 'unspecified' means present, with any value != 0
                self.assertElementKVNO(ticket_encpart, 'kvno',
                                       self.unspecified_kvno)
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

        ticket_checksum = None

        # Get the decryption key for the encrypted part
        encpart_decryption_key, encpart_decryption_usage = (
            self.get_preauth_key(kdc_exchange_dict))

        if armor_key is not None:
            pa_dict = self.get_pa_dict(padata)

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
            if self.strict_checking:
                self.assertElementEqualPrincipal(ticket_private, 'cname',
                                                 expected_cname)
            self.assertElementPresent(ticket_private, 'transited')
            self.assertElementPresent(ticket_private, 'authtime')
            if self.strict_checking:
                self.assertElementPresent(ticket_private, 'starttime')
            self.assertElementPresent(ticket_private, 'endtime')
            if renewable:
                if self.strict_checking:
                    self.assertElementPresent(ticket_private, 'renew-till')
            else:
                self.assertElementMissing(ticket_private, 'renew-till')
            if self.strict_checking:
                self.assertElementEqual(ticket_private, 'caddr', [])
            self.assertElementPresent(ticket_private, 'authorization-data',
                                      expect_empty=not expect_pac)

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
            self.assertElementEqual(encpart_private, 'nonce',
                                    kdc_exchange_dict['nonce'])
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
            if renewable:
                if self.strict_checking:
                    self.assertElementPresent(encpart_private, 'renew-till')
            else:
                self.assertElementMissing(encpart_private, 'renew-till')
            self.assertElementEqualUTF8(encpart_private, 'srealm',
                                        expected_srealm)
            self.assertElementEqualPrincipal(encpart_private, 'sname',
                                             expected_sname)
            if self.strict_checking:
                self.assertElementEqual(encpart_private, 'caddr', [])

            sent_pac_options = self.get_sent_pac_options(kdc_exchange_dict)

            if self.strict_checking:
                if canonicalize or '1' in sent_pac_options:
                    self.assertElementPresent(encpart_private,
                                              'encrypted-pa-data')
                    enc_pa_dict = self.get_pa_dict(
                        encpart_private['encrypted-pa-data'])
                    if canonicalize:
                        self.assertIn(PADATA_SUPPORTED_ETYPES, enc_pa_dict)

                        expected_supported_etypes = kdc_exchange_dict[
                            'expected_supported_etypes']
                        expected_supported_etypes |= (
                            security.KERB_ENCTYPE_DES_CBC_CRC |
                            security.KERB_ENCTYPE_DES_CBC_MD5 |
                            security.KERB_ENCTYPE_RC4_HMAC_MD5)

                        (supported_etypes,) = struct.unpack(
                            '<L',
                            enc_pa_dict[PADATA_SUPPORTED_ETYPES])

                        self.assertEqual(supported_etypes,
                                         expected_supported_etypes)
                    else:
                        self.assertNotIn(PADATA_SUPPORTED_ETYPES, enc_pa_dict)

                    if '1' in sent_pac_options:
                        self.assertIn(PADATA_PAC_OPTIONS, enc_pa_dict)

                        pac_options = self.der_decode(
                            enc_pa_dict[PADATA_PAC_OPTIONS],
                            asn1Spec=krb5_asn1.PA_PAC_OPTIONS())

                        self.assertElementEqual(pac_options, 'options',
                                                sent_pac_options)
                    else:
                        self.assertNotIn(PADATA_PAC_OPTIONS, enc_pa_dict)
                else:
                    self.assertElementEqual(encpart_private,
                                            'encrypted-pa-data',
                                            [])

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
            if expect_pac:
                self.check_pac_buffers(pac_data, kdc_exchange_dict)
            else:
                self.assertIsNone(pac_data)

        expect_ticket_checksum = kdc_exchange_dict['expect_ticket_checksum']
        if expect_ticket_checksum:
            self.assertIsNotNone(ticket_decryption_key)

        if ticket_decryption_key is not None:
            self.verify_ticket(ticket_creds, krbtgt_keys, expect_pac=expect_pac,
                               expect_ticket_checksum=expect_ticket_checksum
                               or self.tkt_sig_support)

        kdc_exchange_dict['rep_ticket_creds'] = ticket_creds

    def check_pac_buffers(self, pac_data, kdc_exchange_dict):
        pac = ndr_unpack(krb5pac.PAC_DATA, pac_data)

        rep_msg_type = kdc_exchange_dict['rep_msg_type']
        armor_tgt = kdc_exchange_dict['armor_tgt']

        expected_sname = kdc_exchange_dict['expected_sname']
        expect_claims = kdc_exchange_dict['expect_claims']

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

        if self.kdc_fast_support:
            if expect_claims:
                expected_types.append(krb5pac.PAC_TYPE_CLIENT_CLAIMS_INFO)

            if (rep_msg_type == KRB_TGS_REP
                    and armor_tgt is not None):
                expected_types.append(krb5pac.PAC_TYPE_DEVICE_INFO)
                expected_types.append(krb5pac.PAC_TYPE_DEVICE_CLAIMS_INFO)

        if not self.is_tgs(expected_sname):
            expected_types.append(krb5pac.PAC_TYPE_TICKET_CHECKSUM)

        if self.strict_checking:
            buffer_types = [pac_buffer.type
                            for pac_buffer in pac.buffers]
            self.assertCountEqual(expected_types, buffer_types,
                                  f'expected: {expected_types} '
                                  f'got: {buffer_types}')

        expected_account_name = kdc_exchange_dict['expected_account_name']
        expected_sid = kdc_exchange_dict['expected_sid']

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
                account_name = expected_cname['name-string'][0]

                self.assertEqual(account_name, pac_buffer.info.account_name)

            elif pac_buffer.type == krb5pac.PAC_TYPE_LOGON_INFO:
                logon_info = pac_buffer.info.info.info3.base

                if expected_account_name is not None:
                    self.assertEqual(expected_account_name,
                                     str(logon_info.account_name))

                if expected_sid is not None:
                    expected_rid = int(expected_sid.rsplit('-', 1)[1])
                    self.assertEqual(expected_rid, logon_info.rid)

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
        if self.strict_checking:
            self.assertElementMissing(rep, 'crealm')
            if expected_anon and not inner:
                expected_cname = self.PrincipalName_create(
                    name_type=NT_WELLKNOWN,
                    names=['WELLKNOWN', 'ANONYMOUS'])
                self.assertElementEqualPrincipal(rep, 'cname', expected_cname)
            else:
                self.assertElementMissing(rep, 'cname')
            self.assertElementEqualUTF8(rep, 'realm', expected_srealm)
            self.assertElementEqualPrincipal(rep, 'sname', expected_sname)
            self.assertElementMissing(rep, 'e-text')
        expected_status = kdc_exchange_dict['expected_status']
        expect_edata = kdc_exchange_dict['expect_edata']
        if expect_edata is None:
            expect_edata = (error_code != KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS
                            and (not sent_fast or fast_armor_type is None
                                 or fast_armor_type == FX_FAST_ARMOR_AP_REQUEST)
                            and not inner)
        if not expect_edata:
            self.assertIsNone(expected_status)
            self.assertElementMissing(rep, 'e-data')
            return rep
        edata = self.getElementValue(rep, 'e-data')
        if self.strict_checking:
            self.assertIsNotNone(edata)
        if edata is not None:
            if rep_msg_type == KRB_TGS_REP and not sent_fast:
                error_data = self.der_decode(
                    edata,
                    asn1Spec=krb5_asn1.KERB_ERROR_DATA())
                self.assertEqual(KERB_ERR_TYPE_EXTENDED,
                                 error_data['data-type'])

                extended_error = error_data['data-value']

                self.assertEqual(12, len(extended_error))

                status = int.from_bytes(extended_error[:4], 'little')
                flags = int.from_bytes(extended_error[8:], 'little')

                self.assertEqual(expected_status, status)

                self.assertEqual(3, flags)
            else:
                self.assertIsNone(expected_status)

                rep_padata = self.der_decode(edata,
                                             asn1Spec=krb5_asn1.METHOD_DATA())
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

        return rep

    def check_rep_padata(self,
                         kdc_exchange_dict,
                         callback_dict,
                         rep_padata,
                         error_code):
        rep_msg_type = kdc_exchange_dict['rep_msg_type']

        req_body = kdc_exchange_dict['req_body']
        proposed_etypes = req_body['etype']
        client_as_etypes = kdc_exchange_dict.get('client_as_etypes', [])

        sent_fast = self.sent_fast(kdc_exchange_dict)
        sent_enc_challenge = self.sent_enc_challenge(kdc_exchange_dict)

        if rep_msg_type == KRB_TGS_REP:
            self.assertTrue(sent_fast)

        expect_etype_info2 = ()
        expect_etype_info = False
        unexpect_etype_info = True
        expected_aes_type = 0
        expected_rc4_type = 0
        if kcrypto.Enctype.RC4 in proposed_etypes:
            expect_etype_info = True
        for etype in proposed_etypes:
            if etype not in client_as_etypes:
                continue
            if etype in (kcrypto.Enctype.AES256, kcrypto.Enctype.AES128):
                expect_etype_info = False
                if etype > expected_aes_type:
                    expected_aes_type = etype
            if etype in (kcrypto.Enctype.RC4,) and error_code != 0:
                unexpect_etype_info = False
                if etype > expected_rc4_type:
                    expected_rc4_type = etype

        if expected_aes_type != 0:
            expect_etype_info2 += (expected_aes_type,)
        if expected_rc4_type != 0:
            expect_etype_info2 += (expected_rc4_type,)

        expected_patypes = ()
        if sent_fast and error_code != 0:
            expected_patypes += (PADATA_FX_ERROR,)
            expected_patypes += (PADATA_FX_COOKIE,)

        if rep_msg_type == KRB_TGS_REP:
            sent_pac_options = self.get_sent_pac_options(kdc_exchange_dict)
            if ('1' in sent_pac_options
                    and error_code not in (0, KDC_ERR_GENERIC)):
                expected_patypes += (PADATA_PAC_OPTIONS,)
        elif error_code != KDC_ERR_GENERIC:
            if expect_etype_info:
                self.assertGreater(len(expect_etype_info2), 0)
                expected_patypes += (PADATA_ETYPE_INFO,)
            if len(expect_etype_info2) != 0:
                expected_patypes += (PADATA_ETYPE_INFO2,)

            if error_code != KDC_ERR_PREAUTH_FAILED:
                if sent_fast:
                    expected_patypes += (PADATA_ENCRYPTED_CHALLENGE,)
                else:
                    expected_patypes += (PADATA_ENC_TIMESTAMP,)

                if not sent_enc_challenge:
                    expected_patypes += (PADATA_PK_AS_REQ,)
                    expected_patypes += (PADATA_PK_AS_REP_19,)

            if (self.kdc_fast_support
                    and not sent_fast
                    and not sent_enc_challenge):
                expected_patypes += (PADATA_FX_FAST,)
                expected_patypes += (PADATA_FX_COOKIE,)

        got_patypes = tuple(pa['padata-type'] for pa in rep_padata)
        self.assertSequenceElementsEqual(expected_patypes, got_patypes,
                                         require_strict={PADATA_FX_COOKIE,
                                                         PADATA_FX_FAST,
                                                         PADATA_PAC_OPTIONS,
                                                         PADATA_PK_AS_REP_19,
                                                         PADATA_PK_AS_REQ})

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
                        armor):
        if armor:
            tgt = kdc_exchange_dict['armor_tgt']
            authenticator_subkey = kdc_exchange_dict['armor_subkey']

            req_body_checksum = None
        else:
            tgt = kdc_exchange_dict['tgt']
            authenticator_subkey = kdc_exchange_dict['authenticator_subkey']
            body_checksum_type = kdc_exchange_dict['body_checksum_type']

            req_body_blob = self.der_encode(req_body,
                                            asn1Spec=krb5_asn1.KDC_REQ_BODY())

            req_body_checksum = self.Checksum_create(tgt.session_key,
                                                     KU_TGS_REQ_AUTH_CKSUM,
                                                     req_body_blob,
                                                     ctype=body_checksum_type)

        auth_data = kdc_exchange_dict['auth_data']

        subkey_obj = None
        if authenticator_subkey is not None:
            subkey_obj = authenticator_subkey.export_obj()
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

        usage = KU_AP_REQ_AUTH if armor else KU_TGS_REQ_AUTH
        authenticator = self.EncryptedData_create(tgt.session_key,
                                                  usage,
                                                  authenticator_blob)

        ap_options = krb5_asn1.APOptions('0')
        ap_req_obj = self.AP_REQ_create(ap_options=str(ap_options),
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

    def verify_ticket(self, ticket, krbtgt_keys, expect_pac=True,
                      expect_ticket_checksum=True):
        # Check if the ticket is a TGT.
        is_tgt = self.is_tgt(ticket)

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

                if buffer_type != krb5pac.PAC_TYPE_TICKET_CHECKSUM:
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

        if is_tgt:
            self.assertNotIn(krb5pac.PAC_TYPE_TICKET_CHECKSUM, checksums)
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

    def modified_ticket(self,
                        ticket, *,
                        new_ticket_key=None,
                        modify_fn=None,
                        modify_pac_fn=None,
                        exclude_pac=False,
                        update_pac_checksums=True,
                        checksum_keys=None,
                        include_checksums=None):
        if checksum_keys is None:
            # A dict containing a key for each checksum type to be created in
            # the PAC.
            checksum_keys = {}

        if include_checksums is None:
            # A dict containing a value for each checksum type; True if the
            # checksum type is to be included in the PAC, False if it is to be
            # excluded, or None/not present if the checksum is to be included
            # based on its presence in the original PAC.
            include_checksums = {}

        # Check that the values passed in by the caller make sense.

        self.assertLessEqual(checksum_keys.keys(), self.pac_checksum_types)
        self.assertLessEqual(include_checksums.keys(), self.pac_checksum_types)

        if exclude_pac:
            self.assertIsNone(modify_pac_fn)

            update_pac_checksums = False

        if not update_pac_checksums:
            self.assertFalse(checksum_keys)
            self.assertFalse(include_checksums)

        expect_pac = update_pac_checksums or modify_pac_fn is not None

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

        # Decrypt the ticket.

        enc_part = ticket.ticket['enc-part']

        self.assertElementEqual(enc_part, 'etype', key.etype)
        self.assertElementKVNO(enc_part, 'kvno', key.kvno)

        enc_part = key.decrypt(KU_TICKET, enc_part['cipher'])
        enc_part = self.der_decode(
            enc_part, asn1Spec=krb5_asn1.EncTicketPart())

        # Modify the ticket here.
        if modify_fn is not None:
            enc_part = modify_fn(enc_part)

        auth_data = enc_part.get('authorization-data')
        if expect_pac:
            self.assertIsNotNone(auth_data)
        if auth_data is not None:
            new_pac = None
            if not exclude_pac:
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
                    if modify_pac_fn is not None:
                        pac = modify_pac_fn(pac)

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
            auth_data, _ = self.replace_pac(auth_data, new_pac,
                                            expect_pac=expect_pac)
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

    def replace_pac(self, auth_data, new_pac, expect_pac=True):
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

                if relevant_elems:
                    ad_relevant = self.der_encode(
                        relevant_elems,
                        asn1Spec=krb5_asn1.AD_IF_RELEVANT())

                    authdata_elem = self.AuthorizationData_create(
                        AD_IF_RELEVANT,
                        ad_relevant)
                else:
                    authdata_elem = None

            if authdata_elem is not None:
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

    def is_tgs(self, principal):
        name = principal['name-string'][0]
        return name in ('krbtgt', b'krbtgt')

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

    def _test_as_exchange(self,
                          cname,
                          realm,
                          sname,
                          till,
                          client_as_etypes,
                          expected_error_mode,
                          expected_crealm,
                          expected_cname,
                          expected_srealm,
                          expected_sname,
                          expected_salt,
                          etypes,
                          padata,
                          kdc_options,
                          expected_account_name=None,
                          expected_sid=None,
                          expected_flags=None,
                          unexpected_flags=None,
                          expected_supported_etypes=None,
                          preauth_key=None,
                          ticket_decryption_key=None,
                          pac_request=None,
                          pac_options=None,
                          expect_pac=True,
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
            expected_crealm=expected_crealm,
            expected_cname=expected_cname,
            expected_srealm=expected_srealm,
            expected_sname=expected_sname,
            expected_account_name=expected_account_name,
            expected_sid=expected_sid,
            expected_supported_etypes=expected_supported_etypes,
            ticket_decryption_key=ticket_decryption_key,
            generate_padata_fn=generate_padata_fn,
            check_error_fn=check_error_fn,
            check_rep_fn=check_rep_fn,
            check_kdc_private_fn=self.generic_check_kdc_private,
            expected_error_mode=expected_error_mode,
            client_as_etypes=client_as_etypes,
            expected_salt=expected_salt,
            expected_flags=expected_flags,
            unexpected_flags=unexpected_flags,
            preauth_key=preauth_key,
            kdc_options=str(kdc_options),
            pac_request=pac_request,
            pac_options=pac_options,
            expect_pac=expect_pac,
            to_rodc=to_rodc)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=cname,
                                         realm=realm,
                                         sname=sname,
                                         till_time=till,
                                         etypes=etypes)

        return rep, kdc_exchange_dict
