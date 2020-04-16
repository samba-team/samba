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

import samba.tests
from samba.credentials import Credentials
from samba.tests import TestCaseInTempDir
from samba.dcerpc import security
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
import samba.tests.krb5.kcrypto as kcrypto

from pyasn1.codec.der.decoder import decode as pyasn1_der_decode
from pyasn1.codec.der.encoder import encode as pyasn1_der_encode
from pyasn1.codec.native.decoder import decode as pyasn1_native_decode
from pyasn1.codec.native.encoder import encode as pyasn1_native_encode

from pyasn1.codec.ber.encoder import BitStringEncoder as BitStringEncoder


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


class Krb5EncryptionKey(object):
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
        return

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
        return

    def set_as_supported_enctypes(self, value):
        self.as_supported_enctypes = int(value)
        return

    def set_tgs_supported_enctypes(self, value):
        self.tgs_supported_enctypes = int(value)
        return

    def set_ap_supported_enctypes(self, value):
        self.ap_supported_enctypes = int(value)
        return

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
        if etype in self.forced_keys:
            return self.forced_keys[etype]
        return None

    def set_forced_salt(self, salt):
        self.forced_salt = bytes(salt)
        return

    def get_forced_salt(self):
        return self.forced_salt

class RawKerberosTest(TestCaseInTempDir):
    """A raw Kerberos Test case."""

    def setUp(self):
        super().setUp()
        self.do_asn1_print = False
        self.do_hexdump = False

        strict_checking = samba.tests.env_get_var_value('STRICT_CHECKING', allow_missing=True)
        if strict_checking is None:
            strict_checking = '1'
        self.strict_checking = bool(int(strict_checking))

        self.host = samba.tests.env_get_var_value('SERVER')

        self.s = None

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
        except Exception:
            raise
        finally:
            pass

    def connect(self):
        self.assertNotConnected()
        self._connect_tcp()
        if self.do_hexdump:
            sys.stderr.write("connected[%s]\n" % self.host)
        return

    def _get_krb5_creds(self, prefix,
                        default_username=None,
                        allow_missing_password=False,
                        require_strongest_key=False):
        c = KerberosCredentials()
        c.guess()

        def env_get_var(varname, prefix, fallback_default=True, allow_missing=False):
            val = None
            if prefix is not None:
                allow_missing_prefix = allow_missing
                if fallback_default:
                    allow_missing_prefix = True
                val = samba.tests.env_get_var_value('%s_%s' % (prefix, varname),
                                        allow_missing=allow_missing_prefix)
            else:
                fallback_default = True
            if val is None and fallback_default:
                val = samba.tests.env_get_var_value(varname,
                                                    allow_missing=allow_missing)
            return val

        domain = env_get_var('DOMAIN', prefix)
        realm = env_get_var('REALM', prefix)
        allow_missing_username = False
        if default_username is not None:
            allow_missing_username = True
        username = env_get_var('USERNAME', prefix,
                               fallback_default=False,
                               allow_missing=allow_missing_username)
        if username is None:
            username = default_username
        password = env_get_var('PASSWORD', prefix,
                               fallback_default=False,
                               allow_missing=allow_missing_password)
        c.set_domain(domain)
        c.set_realm(realm)
        c.set_username(username)
        if password is not None:
            c.set_password(password)
        as_supported_enctypes = env_get_var('AS_SUPPORTED_ENCTYPES',
                                            prefix, allow_missing=True)
        if as_supported_enctypes is not None:
            c.set_as_supported_enctypes(as_supported_enctypes)
        tgs_supported_enctypes = env_get_var('TGS_SUPPORTED_ENCTYPES',
                                             prefix, allow_missing=True)
        if tgs_supported_enctypes is not None:
            c.set_tgs_supported_enctypes(tgs_supported_enctypes)
        ap_supported_enctypes = env_get_var('AP_SUPPORTED_ENCTYPES',
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
            kvno_allow_missing = True
            aes256_allow_missing = True
        kvno = env_get_var('KVNO', prefix,
                           fallback_default=False,
                           allow_missing=kvno_allow_missing)
        if kvno is not None:
            c.set_kvno(kvno)
        aes256_key = env_get_var('AES256_KEY_HEX', prefix,
                                 fallback_default=False,
                                 allow_missing=aes256_allow_missing)
        if aes256_key is not None:
            c.set_forced_key(kcrypto.Enctype.AES256, aes256_key)
        aes128_key = env_get_var('AES128_KEY_HEX', prefix,
                                 fallback_default=False, allow_missing=True)
        if aes128_key is not None:
            c.set_forced_key(kcrypto.Enctype.AES128, aes128_key)
        rc4_key = env_get_var('RC4_KEY_HEX', prefix,
                              fallback_default=False, allow_missing=True)
        if rc4_key is not None:
            c.set_forced_key(kcrypto.Enctype.RC4, rc4_key)
        return c

    def get_user_creds(self, allow_missing_password=False):
        c = self._get_krb5_creds(prefix=None,
                                 allow_missing_password=allow_missing_password)
        return c

    def get_service_creds(self, allow_missing_password=False):
        c = self._get_krb5_creds(prefix='SERVICE',
                                 allow_missing_password=allow_missing_password)
        return c

    def get_client_creds(self, allow_missing_password=False):
        c = self._get_krb5_creds(prefix='CLIENT',
                                 allow_missing_password=allow_missing_password)
        return c

    def get_server_creds(self, allow_missing_password=False):
        c = self._get_krb5_creds(prefix='SERVER',
                                 allow_missing_password=allow_missing_password)
        return c

    def get_krbtgt_creds(self, require_strongest_key=False):
        c = self._get_krb5_creds(prefix='KRBTGT',
                                 default_username='krbtgt',
                                 allow_missing_password=True,
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
        finally:
            pass

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
            pass
        except socket.error as e:
            self._disconnect("recv_raw: %s" % e)
            raise
        except IOError as e:
            self._disconnect("recv_raw: %s" % e)
            raise
        finally:
            pass
        return rep_pdu

    def recv_pdu_raw(self, asn1_print=None, hexdump=None, timeout=None):
        rep_pdu = None
        rep = None
        try:
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
            self.assertIn(msg_type, [11, 13, 30])
            if msg_type == 11:
                asn1Spec = krb5_asn1.AS_REP()
            elif msg_type == 13:
                asn1Spec = krb5_asn1.TGS_REP()
            elif msg_type == 30:
                asn1Spec = krb5_asn1.KRB_ERROR()
            rep = self.der_decode(rep_pdu, asn1Spec=asn1Spec,
                                  asn1_print=asn1_print, hexdump=False)
        finally:
            pass
        return (rep, rep_pdu)

    def recv_pdu(self, asn1_print=None, hexdump=None, timeout=None):
        (rep, rep_pdu) = self.recv_pdu_raw(asn1_print=asn1_print,
                                           hexdump=hexdump,
                                           timeout=timeout)
        return rep

    def assertIsConnected(self):
        self.assertIsNotNone(self.s, msg="Not connected")
        return

    def assertNotConnected(self):
        self.assertIsNone(self.s, msg="Is connected")
        return

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
        return

    def assertHasValue(self, value):
        self.assertIsNotNone(value)
        return

    def getElementValue(self, obj, elem):
        v = None
        try:
            v = obj[elem]
        except KeyError:
            pass
        return v

    def assertElementMissing(self, obj, elem):
        v = self.getElementValue(obj, elem)
        self.assertIsNone(v)
        return

    def assertElementPresent(self, obj, elem):
        v = self.getElementValue(obj, elem)
        self.assertIsNotNone(v)
        return

    def assertElementEqual(self, obj, elem, value):
        v = self.getElementValue(obj, elem)
        self.assertIsNotNone(v)
        self.assertEqual(v, value)
        return

    def assertElementEqualUTF8(self, obj, elem, value):
        v = self.getElementValue(obj, elem)
        self.assertIsNotNone(v)
        self.assertEqual(v, bytes(value, 'utf8'))
        return

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
        return

    def assertElementEqualPrincipal(self, obj, elem, value):
        v = self.getElementValue(obj, elem)
        self.assertIsNotNone(v)
        v = pyasn1_native_decode(v, asn1Spec=krb5_asn1.PrincipalName())
        self.assertPrincipalEqual(v, value)
        return

    def assertElementKVNO(self, obj, elem, value):
        v = self.getElementValue(obj, elem)
        if value == "autodetect":
            value = v
        if value is not None:
            self.assertIsNotNone(v)
            # The value on the wire should never be 0
            self.assertNotEqual(v, 0)
            # value == 0 means we don't know the kvno
            # but enforce at any value != 0 is present
            value = int(value)
            if value != 0:
                self.assertEqual(v, value)
        else:
            self.assertIsNone(v)
        return

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
        salt = None
        try:
            salt = etype_info2['salt']
        except Exception:
            pass

        if e == kcrypto.Enctype.RC4:
            nthash = creds.get_nt_hash()
            return self.SessionKey_create(etype=e, contents=nthash, kvno=kvno)

        password = creds.get_password()
        return self.PasswordKey_create(
            etype=e, pwd=password, salt=salt, kvno=kvno)

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
    def PrincipalName_create(self, name_type, names):
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
        #KERB-PA-PAC-REQUEST ::= SEQUENCE {
        #        include-pac[0] BOOLEAN --If TRUE, and no pac present, include PAC.
        #                               --If FALSE, and PAC present, remove PAC
        #}
        KERB_PA_PAC_REQUEST_obj = {
            'include-pac': include_pac,
        }
        if not pa_data_create:
            return KERB_PA_PAC_REQUEST_obj
        pa_pac = self.der_encode(KERB_PA_PAC_REQUEST_obj,
                                 asn1Spec=krb5_asn1.KERB_PA_PAC_REQUEST())
        pa_data = self.PA_DATA_create(128, pa_pac) # PA-PAC-REQUEST
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
                            EncAuthorizationData,
                            EncAuthorizationData_key,
                            additional_tickets,
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
            enc_ad = self.EncryptedData_create(
                EncAuthorizationData_key, enc_ad_plain)
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
                      EncAuthorizationData,
                      EncAuthorizationData_key,
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
            EncAuthorizationData,
            EncAuthorizationData_key,
            additional_tickets,
            asn1_print=asn1_print,
            hexdump=hexdump)
        obj, decoded = self.KDC_REQ_create(
            msg_type=10,
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
            'msg-type': 14,
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
            EncAuthorizationData=EncAuthorizationData,
            EncAuthorizationData_key=EncAuthorizationData_key,
            additional_tickets=additional_tickets)
        req_body_blob = self.der_encode(req_body, asn1Spec=krb5_asn1.KDC_REQ_BODY(),
                                        asn1_print=asn1_print, hexdump=hexdump)

        req_body_checksum = self.Checksum_create(
            ticket_session_key, 6, req_body_blob, ctype=body_checksum_type)

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
            ticket_session_key, 7, authenticator)

        ap_options = krb5_asn1.APOptions('0')
        ap_req = self.AP_REQ_create(ap_options=str(ap_options),
                                    ticket=ticket,
                                    authenticator=authenticator)
        ap_req = self.der_encode(ap_req, asn1Spec=krb5_asn1.AP_REQ(),
                                 asn1_print=asn1_print, hexdump=hexdump)
        pa_tgs_req = self.PA_DATA_create(1, ap_req)
        if padata is not None:
            padata.append(pa_tgs_req)
        else:
            padata = [pa_tgs_req]

        obj, decoded = self.KDC_REQ_create(
            msg_type=12,
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
        cksum = self.Checksum_create(tgt_session_key, 17, cksum_data, ctype)

        PA_S4U2Self_obj = {
            'name': name,
            'realm': realm,
            'cksum': cksum,
            'auth': "Kerberos",
        }
        pa_s4u2self = self.der_encode(
            PA_S4U2Self_obj, asn1Spec=krb5_asn1.PA_S4U2Self())
        return self.PA_DATA_create(129, pa_s4u2self)
