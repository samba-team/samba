#!/usr/bin/env python3
#
# Copyright (C) 2013 by the Massachusetts Institute of Technology.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.

# XXX current status:
# * Done and tested
#   - AES encryption, checksum, string2key, prf
#   - cf2 (needed for FAST)
# * Still to do:
#   - DES enctypes and cksumtypes
#   - RC4 exported enctype (if we need it for anything)
#   - Unkeyed checksums
#   - Special RC4, raw DES/DES3 operations for GSSAPI
# * Difficult or low priority:
#   - Camellia not supported by PyCrypto
#   - Cipher state only needed for kcmd suite
#   - Nonstandard enctypes and cksumtypes like des-hmac-sha1

import sys
import os

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

from math import gcd
from functools import reduce
from struct import pack, unpack
from binascii import crc32
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import algorithms as ciphers
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers.base import Cipher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from samba.tests import TestCase
from samba.credentials import Credentials
from samba import generate_random_bytes as get_random_bytes
from samba.compat import get_string, get_bytes


class Enctype(object):
    DES_CRC = 1
    DES_MD4 = 2
    DES_MD5 = 3
    DES3 = 16
    AES128 = 17
    AES256 = 18
    RC4 = 23


class Cksumtype(object):
    CRC32 = 1
    MD4 = 2
    MD4_DES = 3
    MD5 = 7
    MD5_DES = 8
    SHA1_DES3 = 12
    SHA1 = 14
    SHA1_AES128 = 15
    SHA1_AES256 = 16
    HMAC_MD5 = -138


class InvalidChecksum(ValueError):
    pass


def _zeropad(s, padsize):
    # Return s padded with 0 bytes to a multiple of padsize.
    padlen = (padsize - (len(s) % padsize)) % padsize
    return s + bytes(padlen)


def _xorbytes(b1, b2):
    # xor two strings together and return the resulting string.
    assert len(b1) == len(b2)
    return bytes([x ^ y for x, y in zip(b1, b2)])


def _mac_equal(mac1, mac2):
    # Constant-time comparison function.  (We can't use HMAC.verify
    # since we use truncated macs.)
    assert len(mac1) == len(mac2)
    res = 0
    for x, y in zip(mac1, mac2):
        res |= x ^ y
    return res == 0


def SIMPLE_HASH(string, algo_cls):
    hash_ctx = hashes.Hash(algo_cls(), default_backend())
    hash_ctx.update(string)
    return hash_ctx.finalize()


def HMAC_HASH(key, string, algo_cls):
    hmac_ctx = hmac.HMAC(key, algo_cls(), default_backend())
    hmac_ctx.update(string)
    return hmac_ctx.finalize()


def _nfold(str, nbytes):
    # Convert str to a string of length nbytes using the RFC 3961 nfold
    # operation.

    # Rotate the bytes in str to the right by nbits bits.
    def rotate_right(str, nbits):
        nbytes, remain = (nbits // 8) % len(str), nbits % 8
        return bytes([
            (str[i - nbytes] >> remain)
            | (str[i - nbytes - 1] << (8 - remain) & 0xff)
            for i in range(len(str))])

    # Add equal-length strings together with end-around carry.
    def add_ones_complement(str1, str2):
        n = len(str1)
        v = [a + b for a, b in zip(str1, str2)]
        # Propagate carry bits to the left until there aren't any left.
        while any(x & ~0xff for x in v):
            v = [(v[i - n + 1] >> 8) + (v[i] & 0xff) for i in range(n)]
        return bytes([x for x in v])

    # Concatenate copies of str to produce the least common multiple
    # of len(str) and nbytes, rotating each copy of str to the right
    # by 13 bits times its list position.  Decompose the concatenation
    # into slices of length nbytes, and add them together as
    # big-endian ones' complement integers.
    slen = len(str)
    lcm = nbytes * slen // gcd(nbytes, slen)
    bigstr = b''.join((rotate_right(str, 13 * i) for i in range(lcm // slen)))
    slices = (bigstr[p:p + nbytes] for p in range(0, lcm, nbytes))
    return reduce(add_ones_complement, slices)


def _is_weak_des_key(keybytes):
    return keybytes in (b'\x01\x01\x01\x01\x01\x01\x01\x01',
                        b'\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE',
                        b'\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E',
                        b'\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1',
                        b'\x01\xFE\x01\xFE\x01\xFE\x01\xFE',
                        b'\xFE\x01\xFE\x01\xFE\x01\xFE\x01',
                        b'\x1F\xE0\x1F\xE0\x0E\xF1\x0E\xF1',
                        b'\xE0\x1F\xE0\x1F\xF1\x0E\xF1\x0E',
                        b'\x01\xE0\x01\xE0\x01\xF1\x01\xF1',
                        b'\xE0\x01\xE0\x01\xF1\x01\xF1\x01',
                        b'\x1F\xFE\x1F\xFE\x0E\xFE\x0E\xFE',
                        b'\xFE\x1F\xFE\x1F\xFE\x0E\xFE\x0E',
                        b'\x01\x1F\x01\x1F\x01\x0E\x01\x0E',
                        b'\x1F\x01\x1F\x01\x0E\x01\x0E\x01',
                        b'\xE0\xFE\xE0\xFE\xF1\xFE\xF1\xFE',
                        b'\xFE\xE0\xFE\xE0\xFE\xF1\xFE\xF1')


class _EnctypeProfile(object):
    # Base class for enctype profiles.  Usable enctype classes must define:
    #   * enctype: enctype number
    #   * keysize: protocol size of key in bytes
    #   * seedsize: random_to_key input size in bytes
    #   * random_to_key (if the keyspace is not dense)
    #   * string_to_key
    #   * encrypt
    #   * decrypt
    #   * prf

    @classmethod
    def random_to_key(cls, seed):
        if len(seed) != cls.seedsize:
            raise ValueError('Wrong seed length')
        return Key(cls.enctype, seed)


class _SimplifiedEnctype(_EnctypeProfile):
    # Base class for enctypes using the RFC 3961 simplified profile.
    # Defines the encrypt, decrypt, and prf methods.  Subclasses must
    # define:
    #   * blocksize: Underlying cipher block size in bytes
    #   * padsize: Underlying cipher padding multiple (1 or blocksize)
    #   * macsize: Size of integrity MAC in bytes
    #   * hashmod: PyCrypto hash module for underlying hash function
    #   * basic_encrypt, basic_decrypt: Underlying CBC/CTS cipher

    @classmethod
    def derive(cls, key, constant):
        # RFC 3961 only says to n-fold the constant only if it is
        # shorter than the cipher block size.  But all Unix
        # implementations n-fold constants if their length is larger
        # than the block size as well, and n-folding when the length
        # is equal to the block size is a no-op.
        plaintext = _nfold(constant, cls.blocksize)
        rndseed = b''
        while len(rndseed) < cls.seedsize:
            ciphertext = cls.basic_encrypt(key, plaintext)
            rndseed += ciphertext
            plaintext = ciphertext
        return cls.random_to_key(rndseed[0:cls.seedsize])

    @classmethod
    def encrypt(cls, key, keyusage, plaintext, confounder):
        ki = cls.derive(key, pack('>iB', keyusage, 0x55))
        ke = cls.derive(key, pack('>iB', keyusage, 0xAA))
        if confounder is None:
            confounder = get_random_bytes(cls.blocksize)
        basic_plaintext = confounder + _zeropad(plaintext, cls.padsize)
        hmac = HMAC_HASH(ki.contents, basic_plaintext, cls.hashalgo)
        return cls.basic_encrypt(ke, basic_plaintext) + hmac[:cls.macsize]

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext):
        ki = cls.derive(key, pack('>iB', keyusage, 0x55))
        ke = cls.derive(key, pack('>iB', keyusage, 0xAA))
        if len(ciphertext) < cls.blocksize + cls.macsize:
            raise ValueError('ciphertext too short')
        basic_ctext, mac = ciphertext[:-cls.macsize], ciphertext[-cls.macsize:]
        if len(basic_ctext) % cls.padsize != 0:
            raise ValueError('ciphertext does not meet padding requirement')
        basic_plaintext = cls.basic_decrypt(ke, basic_ctext)
        hmac = HMAC_HASH(ki.contents, basic_plaintext, cls.hashalgo)
        expmac = hmac[:cls.macsize]
        if not _mac_equal(mac, expmac):
            raise InvalidChecksum('ciphertext integrity failure')
        # Discard the confounder.
        return basic_plaintext[cls.blocksize:]

    @classmethod
    def prf(cls, key, string):
        # Hash the input.  RFC 3961 says to truncate to the padding
        # size, but implementations truncate to the block size.
        hashval = SIMPLE_HASH(string, cls.hashalgo)
        truncated = hashval[:-(len(hashval) % cls.blocksize)]
        # Encrypt the hash with a derived key.
        kp = cls.derive(key, b'prf')
        return cls.basic_encrypt(kp, truncated)


class _DES3CBC(_SimplifiedEnctype):
    enctype = Enctype.DES3
    keysize = 24
    seedsize = 21
    blocksize = 8
    padsize = 8
    macsize = 20
    hashalgo = hashes.SHA1

    @classmethod
    def random_to_key(cls, seed):
        # XXX Maybe reframe as _DESEnctype.random_to_key and use that
        # way from DES3 random-to-key when DES is implemented, since
        # MIT does this instead of the RFC 3961 random-to-key.
        def expand(seed):
            def parity(b):
                # Return b with the low-order bit set to yield odd parity.
                b &= ~1
                return b if bin(b & ~1).count('1') % 2 else b | 1
            assert len(seed) == 7
            firstbytes = [parity(b & ~1) for b in seed]
            lastbyte = parity(sum((seed[i] & 1) << i + 1 for i in range(7)))
            keybytes = bytes([b for b in firstbytes + [lastbyte]])
            if _is_weak_des_key(keybytes):
                keybytes[7] = bytes([keybytes[7] ^ 0xF0])
            return keybytes

        if len(seed) != 21:
            raise ValueError('Wrong seed length')
        k1, k2, k3 = expand(seed[:7]), expand(seed[7:14]), expand(seed[14:])
        return Key(cls.enctype, k1 + k2 + k3)

    @classmethod
    def string_to_key(cls, string, salt, params):
        if params is not None and params != b'':
            raise ValueError('Invalid DES3 string-to-key parameters')
        k = cls.random_to_key(_nfold(string + salt, 21))
        return cls.derive(k, b'kerberos')

    @classmethod
    def basic_encrypt(cls, key, plaintext):
        assert len(plaintext) % 8 == 0
        algo = ciphers.TripleDES(key.contents)
        cbc = modes.CBC(bytes(8))
        encryptor = Cipher(algo, cbc, default_backend()).encryptor()
        ciphertext = encryptor.update(plaintext)
        return ciphertext

    @classmethod
    def basic_decrypt(cls, key, ciphertext):
        assert len(ciphertext) % 8 == 0
        algo = ciphers.TripleDES(key.contents)
        cbc = modes.CBC(bytes(8))
        decryptor = Cipher(algo, cbc, default_backend()).decryptor()
        plaintext = decryptor.update(ciphertext)
        return plaintext


class _AESEnctype(_SimplifiedEnctype):
    # Base class for aes128-cts and aes256-cts.
    blocksize = 16
    padsize = 1
    macsize = 12
    hashalgo = hashes.SHA1

    @classmethod
    def string_to_key(cls, string, salt, params):
        (iterations,) = unpack('>L', params or b'\x00\x00\x10\x00')
        pwbytes = get_bytes(string)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA1(),
                         length=cls.seedsize,
                         salt=salt,
                         iterations=iterations,
                         backend=default_backend())
        seed = kdf.derive(pwbytes)
        tkey = cls.random_to_key(seed)
        return cls.derive(tkey, b'kerberos')

    @classmethod
    def basic_encrypt(cls, key, plaintext):
        assert len(plaintext) >= 16

        algo = ciphers.AES(key.contents)
        cbc = modes.CBC(bytes(16))
        aes_ctx = Cipher(algo, cbc, default_backend())

        def aes_encrypt(plaintext):
            encryptor = aes_ctx.encryptor()
            ciphertext = encryptor.update(plaintext)
            return ciphertext

        ctext = aes_encrypt(_zeropad(plaintext, 16))
        if len(plaintext) > 16:
            # Swap the last two ciphertext blocks and truncate the
            # final block to match the plaintext length.
            lastlen = len(plaintext) % 16 or 16
            ctext = ctext[:-32] + ctext[-16:] + ctext[-32:-16][:lastlen]
        return ctext

    @classmethod
    def basic_decrypt(cls, key, ciphertext):
        assert len(ciphertext) >= 16

        algo = ciphers.AES(key.contents)
        cbc = modes.CBC(bytes(16))
        aes_ctx = Cipher(algo, cbc, default_backend())

        def aes_decrypt(ciphertext):
            decryptor = aes_ctx.decryptor()
            plaintext = decryptor.update(ciphertext)
            return plaintext

        if len(ciphertext) == 16:
            return aes_decrypt(ciphertext)
        # Split the ciphertext into blocks.  The last block may be partial.
        cblocks = [ciphertext[p:p + 16] for p in range(0, len(ciphertext), 16)]
        lastlen = len(cblocks[-1])
        # CBC-decrypt all but the last two blocks.
        prev_cblock = bytes(16)
        plaintext = b''
        for b in cblocks[:-2]:
            plaintext += _xorbytes(aes_decrypt(b), prev_cblock)
            prev_cblock = b
        # Decrypt the second-to-last cipher block.  The left side of
        # the decrypted block will be the final block of plaintext
        # xor'd with the final partial cipher block; the right side
        # will be the omitted bytes of ciphertext from the final
        # block.
        b = aes_decrypt(cblocks[-2])
        lastplaintext = _xorbytes(b[:lastlen], cblocks[-1])
        omitted = b[lastlen:]
        # Decrypt the final cipher block plus the omitted bytes to get
        # the second-to-last plaintext block.
        plaintext += _xorbytes(aes_decrypt(cblocks[-1] + omitted), prev_cblock)
        return plaintext + lastplaintext


class _AES128CTS(_AESEnctype):
    enctype = Enctype.AES128
    keysize = 16
    seedsize = 16


class _AES256CTS(_AESEnctype):
    enctype = Enctype.AES256
    keysize = 32
    seedsize = 32


class _RC4(_EnctypeProfile):
    enctype = Enctype.RC4
    keysize = 16
    seedsize = 16

    @staticmethod
    def usage_str(keyusage):
        # Return a four-byte string for an RFC 3961 keyusage, using
        # the RFC 4757 rules.  Per the errata, do not map 9 to 8.
        table = {3: 8, 23: 13}
        msusage = table[keyusage] if keyusage in table else keyusage
        return pack('<i', msusage)

    @classmethod
    def string_to_key(cls, string, salt, params):
        utf8string = get_string(string)
        tmp = Credentials()
        tmp.set_anonymous()
        tmp.set_password(utf8string)
        nthash = tmp.get_nt_hash()
        return Key(cls.enctype, nthash)

    @classmethod
    def encrypt(cls, key, keyusage, plaintext, confounder):
        if confounder is None:
            confounder = get_random_bytes(8)
        ki = HMAC_HASH(key.contents, cls.usage_str(keyusage), hashes.MD5)
        cksum = HMAC_HASH(ki, confounder + plaintext, hashes.MD5)
        ke = HMAC_HASH(ki, cksum, hashes.MD5)

        encryptor = Cipher(
            ciphers.ARC4(ke), None, default_backend()).encryptor()
        ctext = encryptor.update(confounder + plaintext)

        return cksum + ctext

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext):
        if len(ciphertext) < 24:
            raise ValueError('ciphertext too short')
        cksum, basic_ctext = ciphertext[:16], ciphertext[16:]
        ki = HMAC_HASH(key.contents, cls.usage_str(keyusage), hashes.MD5)
        ke = HMAC_HASH(ki, cksum, hashes.MD5)

        decryptor = Cipher(
            ciphers.ARC4(ke), None, default_backend()).decryptor()
        basic_plaintext = decryptor.update(basic_ctext)

        exp_cksum = HMAC_HASH(ki, basic_plaintext, hashes.MD5)
        ok = _mac_equal(cksum, exp_cksum)
        if not ok and keyusage == 9:
            # Try again with usage 8, due to RFC 4757 errata.
            ki = HMAC_HASH(key.contents, pack('<i', 8), hashes.MD5)
            exp_cksum = HMAC_HASH(ki, basic_plaintext, hashes.MD5)
            ok = _mac_equal(cksum, exp_cksum)
        if not ok:
            raise InvalidChecksum('ciphertext integrity failure')
        # Discard the confounder.
        return basic_plaintext[8:]

    @classmethod
    def prf(cls, key, string):
        return HMAC_HASH(key.contents, string, hashes.SHA1)


class _ChecksumProfile(object):
    # Base class for checksum profiles.  Usable checksum classes must
    # define:
    #   * checksum
    #   * verify (if verification is not just checksum-and-compare)
    #   * checksum_len
    @classmethod
    def verify(cls, key, keyusage, text, cksum):
        expected = cls.checksum(key, keyusage, text)
        if not _mac_equal(cksum, expected):
            raise InvalidChecksum('checksum verification failure')


class _SimplifiedChecksum(_ChecksumProfile):
    # Base class for checksums using the RFC 3961 simplified profile.
    # Defines the checksum and verify methods.  Subclasses must
    # define:
    #   * macsize: Size of checksum in bytes
    #   * enc: Profile of associated enctype

    @classmethod
    def checksum(cls, key, keyusage, text):
        kc = cls.enc.derive(key, pack('>iB', keyusage, 0x99))
        hmac = HMAC_HASH(kc.contents, text, cls.enc.hashalgo)
        return hmac[:cls.macsize]

    @classmethod
    def verify(cls, key, keyusage, text, cksum):
        if key.enctype != cls.enc.enctype:
            raise ValueError('Wrong key type for checksum')
        super(_SimplifiedChecksum, cls).verify(key, keyusage, text, cksum)

    @classmethod
    def checksum_len(cls):
        return cls.macsize


class _SHA1AES128(_SimplifiedChecksum):
    macsize = 12
    enc = _AES128CTS


class _SHA1AES256(_SimplifiedChecksum):
    macsize = 12
    enc = _AES256CTS


class _SHA1DES3(_SimplifiedChecksum):
    macsize = 20
    enc = _DES3CBC


class _HMACMD5(_ChecksumProfile):
    @classmethod
    def checksum(cls, key, keyusage, text):
        ksign = HMAC_HASH(key.contents, b'signaturekey\0', hashes.MD5)
        md5hash = SIMPLE_HASH(_RC4.usage_str(keyusage) + text, hashes.MD5)
        return HMAC_HASH(ksign, md5hash, hashes.MD5)

    @classmethod
    def verify(cls, key, keyusage, text, cksum):
        if key.enctype != Enctype.RC4:
            raise ValueError('Wrong key type for checksum')
        super(_HMACMD5, cls).verify(key, keyusage, text, cksum)

    @classmethod
    def checksum_len(cls):
        return hashes.MD5.digest_size


class _MD5(_ChecksumProfile):
    @classmethod
    def checksum(cls, key, keyusage, text):
        # This is unkeyed!
        return SIMPLE_HASH(text, hashes.MD5)

    @classmethod
    def checksum_len(cls):
        return hashes.MD5.digest_size


class _SHA1(_ChecksumProfile):
    @classmethod
    def checksum(cls, key, keyusage, text):
        # This is unkeyed!
        return SIMPLE_HASH(text, hashes.SHA1)

    @classmethod
    def checksum_len(cls):
        return hashes.SHA1.digest_size


class _CRC32(_ChecksumProfile):
    @classmethod
    def checksum(cls, key, keyusage, text):
        # This is unkeyed!
        cksum = (~crc32(text, 0xffffffff)) & 0xffffffff
        return pack('<I', cksum)

    @classmethod
    def checksum_len(cls):
        return 4


_enctype_table = {
    Enctype.DES3: _DES3CBC,
    Enctype.AES128: _AES128CTS,
    Enctype.AES256: _AES256CTS,
    Enctype.RC4: _RC4
}


_checksum_table = {
    Cksumtype.SHA1_DES3: _SHA1DES3,
    Cksumtype.SHA1_AES128: _SHA1AES128,
    Cksumtype.SHA1_AES256: _SHA1AES256,
    Cksumtype.HMAC_MD5: _HMACMD5,
    Cksumtype.MD5: _MD5,
    Cksumtype.SHA1: _SHA1,
    Cksumtype.CRC32: _CRC32,
}


def _get_enctype_profile(enctype):
    if enctype not in _enctype_table:
        raise ValueError('Invalid enctype %d' % enctype)
    return _enctype_table[enctype]


def _get_checksum_profile(cksumtype):
    if cksumtype not in _checksum_table:
        raise ValueError('Invalid cksumtype %d' % cksumtype)
    return _checksum_table[cksumtype]


class Key(object):
    def __init__(self, enctype, contents):
        e = _get_enctype_profile(enctype)
        if len(contents) != e.keysize:
            raise ValueError('Wrong key length')
        self.enctype = enctype
        self.contents = contents


def seedsize(enctype):
    e = _get_enctype_profile(enctype)
    return e.seedsize


def random_to_key(enctype, seed):
    e = _get_enctype_profile(enctype)
    if len(seed) != e.seedsize:
        raise ValueError('Wrong crypto seed length')
    return e.random_to_key(seed)


def string_to_key(enctype, string, salt, params=None):
    e = _get_enctype_profile(enctype)
    return e.string_to_key(string, salt, params)


def encrypt(key, keyusage, plaintext, confounder=None):
    e = _get_enctype_profile(key.enctype)
    return e.encrypt(key, keyusage, plaintext, confounder)


def decrypt(key, keyusage, ciphertext):
    # Throw InvalidChecksum on checksum failure.  Throw ValueError on
    # invalid key enctype or malformed ciphertext.
    e = _get_enctype_profile(key.enctype)
    return e.decrypt(key, keyusage, ciphertext)


def prf(key, string):
    e = _get_enctype_profile(key.enctype)
    return e.prf(key, string)


def make_checksum(cksumtype, key, keyusage, text):
    c = _get_checksum_profile(cksumtype)
    return c.checksum(key, keyusage, text)


def verify_checksum(cksumtype, key, keyusage, text, cksum):
    # Throw InvalidChecksum exception on checksum failure.  Throw
    # ValueError on invalid cksumtype, invalid key enctype, or
    # malformed checksum.
    c = _get_checksum_profile(cksumtype)
    c.verify(key, keyusage, text, cksum)


def checksum_len(cksumtype):
    c = _get_checksum_profile(cksumtype)
    return c.checksum_len()


def prfplus(key, pepper, ln):
    # Produce ln bytes of output using the RFC 6113 PRF+ function.
    out = b''
    count = 1
    while len(out) < ln:
        out += prf(key, bytes([count]) + pepper)
        count += 1
    return out[:ln]


def cf2(key1, key2, pepper1, pepper2, enctype=None):
    # Combine two keys and two pepper strings to produce a result key
    # of type enctype, using the RFC 6113 KRB-FX-CF2 function.
    if enctype is None:
        enctype = key1.enctype
    e = _get_enctype_profile(enctype)
    return e.random_to_key(_xorbytes(prfplus(key1, pepper1, e.seedsize),
                                     prfplus(key2, pepper2, e.seedsize)))


def h(hexstr):
    return bytes.fromhex(hexstr)


class KcrytoTest(TestCase):
    """kcrypto Test case."""

    def test_aes128_crypr(self):
        # AES128 encrypt and decrypt
        kb = h('9062430C8CDA3388922E6D6A509F5B7A')
        conf = h('94B491F481485B9A0678CD3C4EA386AD')
        keyusage = 2
        plain = b'9 bytesss'
        ctxt = h('68FB9679601F45C78857B2BF820FD6E53ECA8D42FD4B1D7024A09205ABB7'
                 'CD2EC26C355D2F')
        k = Key(Enctype.AES128, kb)
        self.assertEqual(encrypt(k, keyusage, plain, conf), ctxt)
        self.assertEqual(decrypt(k, keyusage, ctxt), plain)

    def test_aes256_crypt(self):
        # AES256 encrypt and decrypt
        kb = h('F1C795E9248A09338D82C3F8D5B567040B0110736845041347235B14042313'
               '98')
        conf = h('E45CA518B42E266AD98E165E706FFB60')
        keyusage = 4
        plain = b'30 bytes bytes bytes bytes byt'
        ctxt = h('D1137A4D634CFECE924DBC3BF6790648BD5CFF7DE0E7B99460211D0DAEF3'
                 'D79A295C688858F3B34B9CBD6EEBAE81DAF6B734D4D498B6714F1C1D')
        k = Key(Enctype.AES256, kb)
        self.assertEqual(encrypt(k, keyusage, plain, conf), ctxt)
        self.assertEqual(decrypt(k, keyusage, ctxt), plain)

    def test_aes128_checksum(self):
        # AES128 checksum
        kb = h('9062430C8CDA3388922E6D6A509F5B7A')
        keyusage = 3
        plain = b'eight nine ten eleven twelve thirteen'
        cksum = h('01A4B088D45628F6946614E3')
        k = Key(Enctype.AES128, kb)
        verify_checksum(Cksumtype.SHA1_AES128, k, keyusage, plain, cksum)

    def test_aes256_checksum(self):
        # AES256 checksum
        kb = h('B1AE4CD8462AFF1677053CC9279AAC30B796FB81CE21474DD3DDBC'
               'FEA4EC76D7')
        keyusage = 4
        plain = b'fourteen'
        cksum = h('E08739E3279E2903EC8E3836')
        k = Key(Enctype.AES256, kb)
        verify_checksum(Cksumtype.SHA1_AES256, k, keyusage, plain, cksum)

    def test_aes128_string_to_key(self):
        # AES128 string-to-key
        string = b'password'
        salt = b'ATHENA.MIT.EDUraeburn'
        params = h('00000002')
        kb = h('C651BF29E2300AC27FA469D693BDDA13')
        k = string_to_key(Enctype.AES128, string, salt, params)
        self.assertEqual(k.contents, kb)

    def test_aes256_string_to_key(self):
        # AES256 string-to-key
        string = b'X' * 64
        salt = b'pass phrase equals block size'
        params = h('000004B0')
        kb = h('89ADEE3608DB8BC71F1BFBFE459486B05618B70CBAE22092534E56'
               'C553BA4B34')
        k = string_to_key(Enctype.AES256, string, salt, params)
        self.assertEqual(k.contents, kb)

    def test_aes128_prf(self):
        # AES128 prf
        kb = h('77B39A37A868920F2A51F9DD150C5717')
        k = string_to_key(Enctype.AES128, b'key1', b'key1')
        self.assertEqual(prf(k, b'\x01\x61'), kb)

    def test_aes256_prf(self):
        # AES256 prf
        kb = h('0D674DD0F9A6806525A4D92E828BD15A')
        k = string_to_key(Enctype.AES256, b'key2', b'key2')
        self.assertEqual(prf(k, b'\x02\x62'), kb)

    def test_aes128_cf2(self):
        # AES128 cf2
        kb = h('97DF97E4B798B29EB31ED7280287A92A')
        k1 = string_to_key(Enctype.AES128, b'key1', b'key1')
        k2 = string_to_key(Enctype.AES128, b'key2', b'key2')
        k = cf2(k1, k2, b'a', b'b')
        self.assertEqual(k.contents, kb)

    def test_aes256_cf2(self):
        # AES256 cf2
        kb = h('4D6CA4E629785C1F01BAF55E2E548566B9617AE3A96868C337CB93B5'
               'E72B1C7B')
        k1 = string_to_key(Enctype.AES256, b'key1', b'key1')
        k2 = string_to_key(Enctype.AES256, b'key2', b'key2')
        k = cf2(k1, k2, b'a', b'b')
        self.assertEqual(k.contents, kb)

    def test_des3_crypt(self):
        # DES3 encrypt and decrypt
        kb = h('0DD52094E0F41CECCB5BE510A764B35176E3981332F1E598')
        conf = h('94690A17B2DA3C9B')
        keyusage = 3
        plain = b'13 bytes byte'
        ctxt = h('839A17081ECBAFBCDC91B88C6955DD3C4514023CF177B77BF0D0177A16F7'
                 '05E849CB7781D76A316B193F8D30')
        k = Key(Enctype.DES3, kb)
        self.assertEqual(encrypt(k, keyusage, plain, conf), ctxt)
        self.assertEqual(decrypt(k, keyusage, ctxt), _zeropad(plain, 8))

    def test_des3_string_to_key(self):
        # DES3 string-to-key
        string = b'password'
        salt = b'ATHENA.MIT.EDUraeburn'
        kb = h('850BB51358548CD05E86768C313E3BFEF7511937DCF72C3E')
        k = string_to_key(Enctype.DES3, string, salt)
        self.assertEqual(k.contents, kb)

    def test_des3_checksum(self):
        # DES3 checksum
        kb = h('7A25DF8992296DCEDA0E135BC4046E2375B3C14C98FBC162')
        keyusage = 2
        plain = b'six seven'
        cksum = h('0EEFC9C3E049AABC1BA5C401677D9AB699082BB4')
        k = Key(Enctype.DES3, kb)
        verify_checksum(Cksumtype.SHA1_DES3, k, keyusage, plain, cksum)

    def test_des3_cf2(self):
        # DES3 cf2
        kb = h('E58F9EB643862C13AD38E529313462A7F73E62834FE54A01')
        k1 = string_to_key(Enctype.DES3, b'key1', b'key1')
        k2 = string_to_key(Enctype.DES3, b'key2', b'key2')
        k = cf2(k1, k2, b'a', b'b')
        self.assertEqual(k.contents, kb)

    def test_rc4_crypt(self):
        # RC4 encrypt and decrypt
        kb = h('68F263DB3FCE15D031C9EAB02D67107A')
        conf = h('37245E73A45FBF72')
        keyusage = 4
        plain = b'30 bytes bytes bytes bytes byt'
        ctxt = h('95F9047C3AD75891C2E9B04B16566DC8B6EB9CE4231AFB2542EF87A7B5A0'
                 'F260A99F0460508DE0CECC632D07C354124E46C5D2234EB8')
        k = Key(Enctype.RC4, kb)
        self.assertEqual(encrypt(k, keyusage, plain, conf), ctxt)
        self.assertEqual(decrypt(k, keyusage, ctxt), plain)

    def test_rc4_string_to_key(self):
        # RC4 string-to-key
        string = b'foo'
        kb = h('AC8E657F83DF82BEEA5D43BDAF7800CC')
        k = string_to_key(Enctype.RC4, string, None)
        self.assertEqual(k.contents, kb)

    def test_rc4_checksum(self):
        # RC4 checksum
        kb = h('F7D3A155AF5E238A0B7A871A96BA2AB2')
        keyusage = 6
        plain = b'seventeen eighteen nineteen twenty'
        cksum = h('EB38CC97E2230F59DA4117DC5859D7EC')
        k = Key(Enctype.RC4, kb)
        verify_checksum(Cksumtype.HMAC_MD5, k, keyusage, plain, cksum)

    def test_rc4_cf2(self):
        # RC4 cf2
        kb = h('24D7F6B6BAE4E5C00D2082C5EBAB3672')
        k1 = string_to_key(Enctype.RC4, b'key1', b'key1')
        k2 = string_to_key(Enctype.RC4, b'key2', b'key2')
        k = cf2(k1, k2, b'a', b'b')
        self.assertEqual(k.contents, kb)

    def _test_md5_unkeyed_checksum(self, etype, usage):
        # MD5 unkeyed checksum
        pw = b'pwd'
        salt = b'bytes'
        key = string_to_key(etype, pw, salt)
        plain = b'seventeen eighteen nineteen twenty'
        cksum = h('9d9588cdef3a8cefc9d2c208d978f60c')
        verify_checksum(Cksumtype.MD5, key, usage, plain, cksum)

    def test_md5_unkeyed_checksum_des3_usage_40(self):
        return self._test_md5_unkeyed_checksum(Enctype.DES3, 40)

    def test_md5_unkeyed_checksum_des3_usage_50(self):
        return self._test_md5_unkeyed_checksum(Enctype.DES3, 50)

    def test_md5_unkeyed_checksum_rc4_usage_40(self):
        return self._test_md5_unkeyed_checksum(Enctype.RC4, 40)

    def test_md5_unkeyed_checksum_rc4_usage_50(self):
        return self._test_md5_unkeyed_checksum(Enctype.RC4, 50)

    def test_md5_unkeyed_checksum_aes128_usage_40(self):
        return self._test_md5_unkeyed_checksum(Enctype.AES128, 40)

    def test_md5_unkeyed_checksum_aes128_usage_50(self):
        return self._test_md5_unkeyed_checksum(Enctype.AES128, 50)

    def test_md5_unkeyed_checksum_aes256_usage_40(self):
        return self._test_md5_unkeyed_checksum(Enctype.AES256, 40)

    def test_md5_unkeyed_checksum_aes256_usage_50(self):
        return self._test_md5_unkeyed_checksum(Enctype.AES256, 50)

    def _test_sha1_unkeyed_checksum(self, etype, usage):
        # SHA1 unkeyed checksum
        pw = b'password'
        salt = b'salt'
        key = string_to_key(etype, pw, salt)
        plain = b'twenty nineteen eighteen seventeen'
        cksum = h('381c870d8875d1913555de19af5c885fd27b7da9')
        verify_checksum(Cksumtype.SHA1, key, usage, plain, cksum)

    def test_sha1_unkeyed_checksum_des3_usage_40(self):
        return self._test_sha1_unkeyed_checksum(Enctype.DES3, 40)

    def test_sha1_unkeyed_checksum_des3_usage_50(self):
        return self._test_sha1_unkeyed_checksum(Enctype.DES3, 50)

    def test_sha1_unkeyed_checksum_rc4_usage_40(self):
        return self._test_sha1_unkeyed_checksum(Enctype.RC4, 40)

    def test_sha1_unkeyed_checksum_rc4_usage_50(self):
        return self._test_sha1_unkeyed_checksum(Enctype.RC4, 50)

    def test_sha1_unkeyed_checksum_aes128_usage_40(self):
        return self._test_sha1_unkeyed_checksum(Enctype.AES128, 40)

    def test_sha1_unkeyed_checksum_aes128_usage_50(self):
        return self._test_sha1_unkeyed_checksum(Enctype.AES128, 50)

    def test_sha1_unkeyed_checksum_aes256_usage_40(self):
        return self._test_sha1_unkeyed_checksum(Enctype.AES256, 40)

    def test_sha1_unkeyed_checksum_aes256_usage_50(self):
        return self._test_sha1_unkeyed_checksum(Enctype.AES256, 50)

    def _test_crc32_unkeyed_checksum(self, etype, usage):
        # CRC32 unkeyed checksum
        pw = b'password'
        salt = b'salt'
        key = string_to_key(etype, pw, salt)
        plain = b'africa america asia australia europe'
        cksum = h('ce595a53')
        verify_checksum(Cksumtype.CRC32, key, usage, plain, cksum)

    def test_crc32_unkeyed_checksum_des3_usage_40(self):
        return self._test_crc32_unkeyed_checksum(Enctype.DES3, 40)

    def test_crc32_unkeyed_checksum_des3_usage_50(self):
        return self._test_crc32_unkeyed_checksum(Enctype.DES3, 50)

    def test_crc32_unkeyed_checksum_rc4_usage_40(self):
        return self._test_crc32_unkeyed_checksum(Enctype.RC4, 40)

    def test_crc32_unkeyed_checksum_rc4_usage_50(self):
        return self._test_crc32_unkeyed_checksum(Enctype.RC4, 50)

    def test_crc32_unkeyed_checksum_aes128_usage_40(self):
        return self._test_crc32_unkeyed_checksum(Enctype.AES128, 40)

    def test_crc32_unkeyed_checksum_aes128_usage_50(self):
        return self._test_crc32_unkeyed_checksum(Enctype.AES128, 50)

    def test_crc32_unkeyed_checksum_aes256_usage_40(self):
        return self._test_crc32_unkeyed_checksum(Enctype.AES256, 40)

    def test_crc32_unkeyed_checksum_aes256_usage_50(self):
        return self._test_crc32_unkeyed_checksum(Enctype.AES256, 50)


if __name__ == "__main__":
    import unittest
    unittest.main()
