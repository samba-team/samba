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
from samba.dcerpc import security
from samba.gensec import FEATURE_SEAL

import samba.tests
from samba.tests import TestCaseInTempDir

import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
from samba.tests.krb5.rfc4120_constants import (
    KDC_ERR_GENERIC,
    KRB_AP_REQ,
    KRB_AS_REP,
    KRB_AS_REQ,
    KRB_ERROR,
    KRB_TGS_REP,
    KRB_TGS_REQ,
    KU_AS_REP_ENC_PART,
    KU_NON_KERB_CKSUM_SALT,
    KU_TGS_REP_ENC_PART_SESSION,
    KU_TGS_REP_ENC_PART_SUB_KEY,
    KU_TGS_REQ_AUTH,
    KU_TGS_REQ_AUTH_CKSUM,
    KU_TGS_REQ_AUTH_DAT_SESSION,
    KU_TGS_REQ_AUTH_DAT_SUBKEY,
    KU_TICKET,
    PADATA_ENC_TIMESTAMP,
    PADATA_ETYPE_INFO,
    PADATA_ETYPE_INFO2,
    PADATA_FOR_USER,
    PADATA_KDC_REQ,
    PADATA_PAC_REQUEST,
    PADATA_PK_AS_REQ,
    PADATA_PK_AS_REP_19
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

    def make_checksum(self, usage, plaintext, ctype=None):
        if ctype is None:
            ctype = self.ctype
        cksum = kcrypto.make_checksum(ctype, self.key, usage, plaintext)
        return cksum

    def export_obj(self):
        EncryptionKey_obj = {
            'keytype': self.etype,
            'keyvalue': self.key.contents,
        }
        return EncryptionKey_obj


class KerberosCredentials(Credentials):
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

    def set_as_supported_enctypes(self, value):
        self.as_supported_enctypes = int(value)

    def set_tgs_supported_enctypes(self, value):
        self.tgs_supported_enctypes = int(value)

    def set_ap_supported_enctypes(self, value):
        self.ap_supported_enctypes = int(value)

    def _get_krb5_etypes(self, supported_enctypes):
        etypes = ()

        if supported_enctypes & security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96:
            etypes += (kcrypto.Enctype.AES256,)
        if supported_enctypes & security.KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96:
            etypes += (kcrypto.Enctype.AES128,)
        if supported_enctypes & security.KERB_ENCTYPE_RC4_HMAC_MD5:
            etypes += (kcrypto.Enctype.RC4,)

        return etypes

    def get_as_krb5_etypes(self):
        return self._get_krb5_etypes(self.as_supported_enctypes)

    def get_tgs_krb5_etypes(self):
        return self._get_krb5_etypes(self.tgs_supported_enctypes)

    def get_ap_krb5_etypes(self):
        return self._get_krb5_etypes(self.ap_supported_enctypes)

    def set_kvno(self, kvno):
        self.kvno = kvno

    def get_kvno(self):
        return self.kvno

    def set_forced_key(self, etype, hexkey):
        etype = int(etype)
        contents = binascii.a2b_hex(hexkey)
        key = kcrypto.Key(etype, contents)
        self.forced_keys[etype] = Krb5EncryptionKey(key, self.kvno)

    def get_forced_key(self, etype):
        etype = int(etype)
        return self.forced_keys.get(etype, None)

    def set_forced_salt(self, salt):
        self.forced_salt = bytes(salt)

    def get_forced_salt(self):
        return self.forced_salt

    def get_salt(self):
        if self.forced_salt is not None:
            return self.forced_salt

        if self.get_workstation():
            salt_string = '%shost%s.%s' % (
                self.get_realm().upper(),
                self.get_username().lower().rsplit('$', 1)[0],
                self.get_realm().lower())
        else:
            salt_string = self.get_realm().upper() + self.get_username()

        return salt_string.encode('utf-8')


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

        # A dictionary containing credentials that have already been
        # obtained.
        cls.creds_dict = {}

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

    def _connect_tcp(self):
        tcp_port = 88
        try:
            self.a = socket.getaddrinfo(self.host, tcp_port, socket.AF_UNSPEC,
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

    def connect(self):
        self.assertNotConnected()
        self._connect_tcp()
        if self.do_hexdump:
            sys.stderr.write("connected[%s]\n" % self.host)

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
            timeout=None):
        self.connect()
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
        return obj.get(elem, None)

    def assertElementMissing(self, obj, elem):
        v = self.getElementValue(obj, elem)
        self.assertIsNone(v)

    def assertElementPresent(self, obj, elem):
        v = self.getElementValue(obj, elem)
        self.assertIsNotNone(v)
        if self.strict_checking:
            if isinstance(v, collections.abc.Container):
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
        return Krb5EncryptionKey(key, kvno)

    def PasswordKey_create(self, etype=None, pwd=None, salt=None, kvno=None):
        self.assertIsNotNone(pwd)
        self.assertIsNotNone(salt)
        key = kcrypto.string_to_key(etype, pwd, salt)
        return Krb5EncryptionKey(key, kvno)

    def PasswordKey_from_etype_info2(self, creds, etype_info2, kvno=None):
        e = etype_info2['etype']

        salt = etype_info2.get('salt', None)

        if e == kcrypto.Enctype.RC4:
            nthash = creds.get_nt_hash()
            return self.SessionKey_create(etype=e, contents=nthash, kvno=kvno)

        password = creds.get_password()
        return self.PasswordKey_create(
            etype=e, pwd=password, salt=salt, kvno=kvno)

    def TicketDecryptionKey_from_creds(self, creds, etype=None):

        if etype is None:
            etypes = creds.get_tgs_krb5_etypes()
            etype = etypes[0]

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
        #         kvno    [1] UInt32 OPTIONAL,
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
        generate_padata_fn = kdc_exchange_dict['generate_padata_fn']
        callback_dict = kdc_exchange_dict['callback_dict']
        req_msg_type = kdc_exchange_dict['req_msg_type']
        req_asn1Spec = kdc_exchange_dict['req_asn1Spec']
        rep_msg_type = kdc_exchange_dict['rep_msg_type']

        expected_error_mode = kdc_exchange_dict['expected_error_mode']
        kdc_options = kdc_exchange_dict['kdc_options']

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
        if generate_padata_fn is not None:
            # This can alter req_body...
            padata, req_body = generate_padata_fn(kdc_exchange_dict,
                                                  callback_dict,
                                                  req_body)
            self.assertIsNotNone(padata)
        else:
            padata = None

        kdc_exchange_dict['req_padata'] = padata
        kdc_exchange_dict['req_body'] = req_body

        req_obj, req_decoded = self.KDC_REQ_create(msg_type=req_msg_type,
                                                   padata=padata,
                                                   req_body=req_body,
                                                   asn1Spec=req_asn1Spec())

        rep = self.send_recv_transaction(req_decoded)
        self.assertIsNotNone(rep)

        msg_type = self.getElementValue(rep, 'msg-type')
        self.assertIsNotNone(msg_type)

        expected_msg_type = None
        if check_error_fn is not None:
            expected_msg_type = KRB_ERROR
            self.assertIsNone(check_rep_fn)
            self.assertNotEqual(0, expected_error_mode)
        if check_rep_fn is not None:
            expected_msg_type = rep_msg_type
            self.assertIsNone(check_error_fn)
            self.assertEqual(0, expected_error_mode)
        self.assertIsNotNone(expected_msg_type)
        self.assertEqual(msg_type, expected_msg_type)

        if msg_type == KRB_ERROR:
            return check_error_fn(kdc_exchange_dict,
                                  callback_dict,
                                  rep)

        return check_rep_fn(kdc_exchange_dict, callback_dict, rep)

    def as_exchange_dict(self,
                         expected_crealm=None,
                         expected_cname=None,
                         expected_srealm=None,
                         expected_sname=None,
                         ticket_decryption_key=None,
                         generate_padata_fn=None,
                         check_error_fn=None,
                         check_rep_fn=None,
                         check_padata_fn=None,
                         check_kdc_private_fn=None,
                         callback_dict=None,
                         expected_error_mode=0,
                         client_as_etypes=None,
                         expected_salt=None,
                         kdc_options=''):
        kdc_exchange_dict = {
            'req_msg_type': KRB_AS_REQ,
            'req_asn1Spec': krb5_asn1.AS_REQ,
            'rep_msg_type': KRB_AS_REP,
            'rep_asn1Spec': krb5_asn1.AS_REP,
            'rep_encpart_asn1Spec': krb5_asn1.EncASRepPart,
            'expected_crealm': expected_crealm,
            'expected_cname': expected_cname,
            'expected_srealm': expected_srealm,
            'expected_sname': expected_sname,
            'ticket_decryption_key': ticket_decryption_key,
            'generate_padata_fn': generate_padata_fn,
            'check_error_fn': check_error_fn,
            'check_rep_fn': check_rep_fn,
            'check_padata_fn': check_padata_fn,
            'check_kdc_private_fn': check_kdc_private_fn,
            'callback_dict': callback_dict,
            'expected_error_mode': expected_error_mode,
            'client_as_etypes': client_as_etypes,
            'expected_salt': expected_salt,
            'kdc_options': kdc_options,
        }
        if callback_dict is None:
            callback_dict = {}

        return kdc_exchange_dict

    def tgs_exchange_dict(self,
                          expected_crealm=None,
                          expected_cname=None,
                          expected_srealm=None,
                          expected_sname=None,
                          ticket_decryption_key=None,
                          generate_padata_fn=None,
                          check_error_fn=None,
                          check_rep_fn=None,
                          check_padata_fn=None,
                          check_kdc_private_fn=None,
                          callback_dict=None,
                          tgt=None,
                          authenticator_subkey=None,
                          body_checksum_type=None,
                          kdc_options=''):
        kdc_exchange_dict = {
            'req_msg_type': KRB_TGS_REQ,
            'req_asn1Spec': krb5_asn1.TGS_REQ,
            'rep_msg_type': KRB_TGS_REP,
            'rep_asn1Spec': krb5_asn1.TGS_REP,
            'rep_encpart_asn1Spec': krb5_asn1.EncTGSRepPart,
            'expected_crealm': expected_crealm,
            'expected_cname': expected_cname,
            'expected_srealm': expected_srealm,
            'expected_sname': expected_sname,
            'ticket_decryption_key': ticket_decryption_key,
            'generate_padata_fn': generate_padata_fn,
            'check_error_fn': check_error_fn,
            'check_rep_fn': check_rep_fn,
            'check_padata_fn': check_padata_fn,
            'check_kdc_private_fn': check_kdc_private_fn,
            'callback_dict': callback_dict,
            'tgt': tgt,
            'body_checksum_type': body_checksum_type,
            'authenticator_subkey': authenticator_subkey,
            'kdc_options': kdc_options
        }
        if callback_dict is None:
            callback_dict = {}

        return kdc_exchange_dict

    def generic_check_kdc_rep(self,
                              kdc_exchange_dict,
                              callback_dict,
                              rep):

        expected_crealm = kdc_exchange_dict['expected_crealm']
        expected_cname = kdc_exchange_dict['expected_cname']
        expected_srealm = kdc_exchange_dict['expected_srealm']
        expected_sname = kdc_exchange_dict['expected_sname']
        ticket_decryption_key = kdc_exchange_dict['ticket_decryption_key']
        check_padata_fn = kdc_exchange_dict['check_padata_fn']
        check_kdc_private_fn = kdc_exchange_dict['check_kdc_private_fn']
        rep_encpart_asn1Spec = kdc_exchange_dict['rep_encpart_asn1Spec']
        msg_type = kdc_exchange_dict['rep_msg_type']

        self.assertElementEqual(rep, 'msg-type', msg_type)  # AS-REP | TGS-REP
        padata = self.getElementValue(rep, 'padata')
        if self.strict_checking:
            self.assertElementEqualUTF8(rep, 'crealm', expected_crealm)
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

        encpart_decryption_key = None
        self.assertIsNotNone(check_padata_fn)
        if check_padata_fn is not None:
            # See if we can get the decryption key from the preauth phase
            encpart_decryption_key, encpart_decryption_usage = (
                check_padata_fn(kdc_exchange_dict, callback_dict,
                                rep, padata))

        ticket_private = None
        self.assertIsNotNone(ticket_decryption_key)
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
                                 rep, ticket_private, encpart_private)

        return rep

    def generic_check_kdc_private(self,
                                  kdc_exchange_dict,
                                  callback_dict,
                                  rep,
                                  ticket_private,
                                  encpart_private):

        expected_crealm = kdc_exchange_dict['expected_crealm']
        expected_cname = kdc_exchange_dict['expected_cname']
        expected_srealm = kdc_exchange_dict['expected_srealm']
        expected_sname = kdc_exchange_dict['expected_sname']
        ticket_decryption_key = kdc_exchange_dict['ticket_decryption_key']

        ticket = self.getElementValue(rep, 'ticket')

        ticket_session_key = None
        if ticket_private is not None:
            self.assertElementPresent(ticket_private, 'flags')
            self.assertElementPresent(ticket_private, 'key')
            ticket_key = self.getElementValue(ticket_private, 'key')
            self.assertIsNotNone(ticket_key)
            if ticket_key is not None:  # Never None, but gives indentation
                self.assertElementPresent(ticket_key, 'keytype')
                self.assertElementPresent(ticket_key, 'keyvalue')
                ticket_session_key = self.EncryptionKey_import(ticket_key)
            self.assertElementEqualUTF8(ticket_private, 'crealm',
                                        expected_crealm)
            self.assertElementEqualPrincipal(ticket_private, 'cname',
                                             expected_cname)
            self.assertElementPresent(ticket_private, 'transited')
            self.assertElementPresent(ticket_private, 'authtime')
            if self.strict_checking:
                self.assertElementPresent(ticket_private, 'starttime')
            self.assertElementPresent(ticket_private, 'endtime')
            # TODO self.assertElementPresent(ticket_private, 'renew-till')
            # TODO self.assertElementMissing(ticket_private, 'caddr')
            self.assertElementPresent(ticket_private, 'authorization-data')

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
            # TODO self.assertElementPresent(encpart_private,
            #                                'key-expiration')
            self.assertElementPresent(encpart_private, 'flags')
            self.assertElementPresent(encpart_private, 'authtime')
            if self.strict_checking:
                self.assertElementPresent(encpart_private, 'starttime')
            self.assertElementPresent(encpart_private, 'endtime')
            # TODO self.assertElementPresent(encpart_private, 'renew-till')
            self.assertElementEqualUTF8(encpart_private, 'srealm',
                                        expected_srealm)
            self.assertElementEqualPrincipal(encpart_private, 'sname',
                                             expected_sname)
            # TODO self.assertElementMissing(encpart_private, 'caddr')

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

        kdc_exchange_dict['rep_ticket_creds'] = ticket_creds

    def generic_check_as_error(self,
                               kdc_exchange_dict,
                               callback_dict,
                               rep):

        expected_crealm = kdc_exchange_dict['expected_crealm']
        expected_cname = kdc_exchange_dict['expected_cname']
        expected_srealm = kdc_exchange_dict['expected_srealm']
        expected_sname = kdc_exchange_dict['expected_sname']
        expected_salt = kdc_exchange_dict['expected_salt']
        client_as_etypes = kdc_exchange_dict['client_as_etypes']
        expected_error_mode = kdc_exchange_dict['expected_error_mode']
        req_body = kdc_exchange_dict['req_body']
        proposed_etypes = req_body['etype']

        kdc_exchange_dict['preauth_etype_info2'] = None

        expect_etype_info2 = ()
        expect_etype_info = False
        unexpect_etype_info = True
        expected_aes_type = 0
        expected_rc4_type = 0
        if kcrypto.Enctype.RC4 in proposed_etypes:
            expect_etype_info = True
        for etype in proposed_etypes:
            if etype in (kcrypto.Enctype.AES256, kcrypto.Enctype.AES128):
                expect_etype_info = False
            if etype not in client_as_etypes:
                continue
            if etype in (kcrypto.Enctype.AES256, kcrypto.Enctype.AES128):
                if etype > expected_aes_type:
                    expected_aes_type = etype
            if etype in (kcrypto.Enctype.RC4,):
                unexpect_etype_info = False
                if etype > expected_rc4_type:
                    expected_rc4_type = etype

        if expected_aes_type != 0:
            expect_etype_info2 += (expected_aes_type,)
        if expected_rc4_type != 0:
            expect_etype_info2 += (expected_rc4_type,)

        expected_patypes = ()
        if expect_etype_info:
            self.assertGreater(len(expect_etype_info2), 0)
            expected_patypes += (PADATA_ETYPE_INFO,)
        if len(expect_etype_info2) != 0:
            expected_patypes += (PADATA_ETYPE_INFO2,)

        expected_patypes += (PADATA_ENC_TIMESTAMP,)
        expected_patypes += (PADATA_PK_AS_REQ,)
        expected_patypes += (PADATA_PK_AS_REP_19,)

        self.assertElementEqual(rep, 'pvno', 5)
        self.assertElementEqual(rep, 'msg-type', KRB_ERROR)
        self.assertElementEqual(rep, 'error-code', expected_error_mode)
        if self.strict_checking:
            self.assertElementMissing(rep, 'ctime')
            self.assertElementMissing(rep, 'cusec')
        self.assertElementPresent(rep, 'stime')
        self.assertElementPresent(rep, 'susec')
        # error-code checked above
        if self.strict_checking:
            self.assertElementMissing(rep, 'crealm')
            self.assertElementMissing(rep, 'cname')
            self.assertElementEqualUTF8(rep, 'realm', expected_srealm)
            self.assertElementEqualPrincipal(rep, 'sname', expected_sname)
            self.assertElementMissing(rep, 'e-text')
        if expected_error_mode == KDC_ERR_GENERIC:
            self.assertElementMissing(rep, 'e-data')
            return
        edata = self.getElementValue(rep, 'e-data')
        if self.strict_checking:
            self.assertIsNotNone(edata)
        if edata is not None:
            rep_padata = self.der_decode(edata,
                                         asn1Spec=krb5_asn1.METHOD_DATA())
            self.assertGreater(len(rep_padata), 0)
        else:
            rep_padata = []

        if self.strict_checking:
            for i, patype in enumerate(expected_patypes):
                self.assertElementEqual(rep_padata[i], 'padata-type', patype)
            self.assertEqual(len(rep_padata), len(expected_patypes))

        etype_info2 = None
        etype_info = None
        enc_timestamp = None
        pk_as_req = None
        pk_as_rep19 = None
        for pa in rep_padata:
            patype = self.getElementValue(pa, 'padata-type')
            pavalue = self.getElementValue(pa, 'padata-value')
            if patype == PADATA_ETYPE_INFO2:
                self.assertIsNone(etype_info2)
                etype_info2 = self.der_decode(pavalue,
                                              asn1Spec=krb5_asn1.ETYPE_INFO2())
                continue
            if patype == PADATA_ETYPE_INFO:
                self.assertIsNone(etype_info)
                etype_info = self.der_decode(pavalue,
                                             asn1Spec=krb5_asn1.ETYPE_INFO())
                continue
            if patype == PADATA_ENC_TIMESTAMP:
                self.assertIsNone(enc_timestamp)
                enc_timestamp = pavalue
                self.assertEqual(len(enc_timestamp), 0)
                continue
            if patype == PADATA_PK_AS_REQ:
                self.assertIsNone(pk_as_req)
                pk_as_req = pavalue
                self.assertEqual(len(pk_as_req), 0)
                continue
            if patype == PADATA_PK_AS_REP_19:
                self.assertIsNone(pk_as_rep19)
                pk_as_rep19 = pavalue
                self.assertEqual(len(pk_as_rep19), 0)
                continue

        if all(etype not in client_as_etypes or etype not in proposed_etypes
               for etype in (kcrypto.Enctype.AES256,
                             kcrypto.Enctype.AES128,
                             kcrypto.Enctype.RC4)):
            self.assertIsNone(etype_info2)
            self.assertIsNone(etype_info)
            if self.strict_checking:
                self.assertIsNotNone(enc_timestamp)
                self.assertIsNotNone(pk_as_req)
                self.assertIsNotNone(pk_as_rep19)
            return

        if self.strict_checking:
            self.assertIsNotNone(etype_info2)
        if expect_etype_info:
            self.assertIsNotNone(etype_info)
        else:
            if self.strict_checking:
                self.assertIsNone(etype_info)
        if unexpect_etype_info:
            self.assertIsNone(etype_info)

        if self.strict_checking:
            self.assertGreaterEqual(len(etype_info2), 1)
            self.assertEqual(len(etype_info2), len(expect_etype_info2))
            for i in range(0, len(etype_info2)):
                e = self.getElementValue(etype_info2[i], 'etype')
                self.assertEqual(e, expect_etype_info2[i])
                salt = self.getElementValue(etype_info2[i], 'salt')
                if e == kcrypto.Enctype.RC4:
                    self.assertIsNone(salt)
                else:
                    self.assertIsNotNone(salt)
                    if expected_salt is not None:
                        self.assertEqual(salt, expected_salt)
                s2kparams = self.getElementValue(etype_info2[i], 's2kparams')
                if self.strict_checking:
                    self.assertIsNone(s2kparams)
        if etype_info is not None:
            self.assertEqual(len(etype_info), 1)
            e = self.getElementValue(etype_info[0], 'etype')
            self.assertEqual(e, kcrypto.Enctype.RC4)
            self.assertEqual(e, expect_etype_info2[0])
            salt = self.getElementValue(etype_info[0], 'salt')
            if self.strict_checking:
                self.assertIsNotNone(salt)
                self.assertEqual(len(salt), 0)

        self.assertIsNotNone(enc_timestamp)
        self.assertIsNotNone(pk_as_req)
        self.assertIsNotNone(pk_as_rep19)

        kdc_exchange_dict['preauth_etype_info2'] = etype_info2
        return

    def generate_ap_req(self,
                        kdc_exchange_dict,
                        _callback_dict,
                        req_body):
        tgt = kdc_exchange_dict['tgt']
        authenticator_subkey = kdc_exchange_dict['authenticator_subkey']
        body_checksum_type = kdc_exchange_dict['body_checksum_type']

        req_body_blob = self.der_encode(req_body,
                                        asn1Spec=krb5_asn1.KDC_REQ_BODY())

        req_body_checksum = self.Checksum_create(tgt.session_key,
                                                 KU_TGS_REQ_AUTH_CKSUM,
                                                 req_body_blob,
                                                 ctype=body_checksum_type)

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
            authorization_data=None)
        authenticator_blob = self.der_encode(
            authenticator_obj,
            asn1Spec=krb5_asn1.Authenticator())

        authenticator = self.EncryptedData_create(tgt.session_key,
                                                  KU_TGS_REQ_AUTH,
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
                                      req_body)
        pa_tgs_req = self.PA_DATA_create(PADATA_KDC_REQ, ap_req)
        padata = [pa_tgs_req]

        return padata, req_body

    def check_simple_tgs_padata(self,
                                kdc_exchange_dict,
                                callback_dict,
                                rep,
                                padata):
        tgt = kdc_exchange_dict['tgt']
        authenticator_subkey = kdc_exchange_dict['authenticator_subkey']
        if authenticator_subkey is not None:
            subkey = authenticator_subkey
            subkey_usage = KU_TGS_REP_ENC_PART_SUB_KEY
        else:
            subkey = tgt.session_key
            subkey_usage = KU_TGS_REP_ENC_PART_SESSION

        return subkey, subkey_usage

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
                          preauth_key=None,
                          ticket_decryption_key=None):

        def _generate_padata_copy(_kdc_exchange_dict,
                                  _callback_dict,
                                  req_body):
            return padata, req_body

        def _check_padata_preauth_key(_kdc_exchange_dict,
                                      _callback_dict,
                                      rep,
                                      padata):
            as_rep_usage = KU_AS_REP_ENC_PART
            return preauth_key, as_rep_usage

        if expected_error_mode == 0:
            check_error_fn = None
            check_rep_fn = self.generic_check_kdc_rep
        else:
            check_error_fn = self.generic_check_as_error
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
            ticket_decryption_key=ticket_decryption_key,
            generate_padata_fn=generate_padata_fn,
            check_error_fn=check_error_fn,
            check_rep_fn=check_rep_fn,
            check_padata_fn=_check_padata_preauth_key,
            check_kdc_private_fn=self.generic_check_kdc_private,
            expected_error_mode=expected_error_mode,
            client_as_etypes=client_as_etypes,
            expected_salt=expected_salt,
            kdc_options=str(kdc_options))

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=cname,
                                         realm=realm,
                                         sname=sname,
                                         till_time=till,
                                         etypes=etypes)

        return rep, kdc_exchange_dict
