# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst.Net Ltd 2025
#
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
#

"""Functions for processing key_credential_link"""

import base64
from hashlib import sha256
import struct
import time
from typing import Optional, Union, Iterable

from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_pem_public_key,
    PublicFormat,
    Encoding)

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from cryptography.x509 import (
    load_pem_x509_certificate,
    load_der_x509_certificate)


from samba import nttime2unix
from samba.samdb import SamDB, BinaryDn
from samba.ndr import ndr_unpack, ndr_pack
from ldb import Dn
from samba.dcerpc import keycredlink, misc


class KeyCredLinkError(Exception):
    """The key credential link is inconsistent."""
    # For bad values handed in, we use ValueError. For internal bad
    # values, we use this.


def key_usage_string(i):
    # there must be a better way.
    for s in ('KEY_USAGE_NGC', 'KEY_USAGE_FIDO', 'KEY_USAGE_FEK',):
        if i == getattr(keycredlink, s):
            return s
    return "unknown"


def nttime_as_date(nt):
    secs = nttime2unix(nt)
    ts = time.gmtime(secs)
    return time.strftime('%Y-%m-%d %H:%M:%S', ts)


class KeyCredentialLinkDn(BinaryDn):
    """KeyCredentialLink attributes are stored as DN+Binary.

    The binary part is a KEYCREDENTIALLINK_BLOB, which is basically an
    array of KEYCREDENTIALLINK_ENTRY collectively describing a public
    key.

    Usually the DN refers to the object the KeyCredentialLink was
    found on.
    """
    # We make .binary a @property, so that BinaryDn's .parse() and
    # .prefix just work without knowing that assigning to .binary is
    # doing validation checks.
    blob = None

    @property
    def binary(self) -> bytes:
        """The binary is stored as a keycredlink.KEYCREDENTIALLINK_BLOB"""
        if self.blob is None:
            return None
        return ndr_pack(self.blob)

    @binary.setter
    def binary(self, value:bytes):
        try:
            self.blob = ndr_unpack(keycredlink.KEYCREDENTIALLINK_BLOB,
                                   value)
        except Exception as e:
            raise ValueError("Could not parse value as KEYCREDENTIALLINK_BLOB "
                             f" (internal error: {e})")

    def get_entry(self, entry_id):
        if self.blob is None:
            raise KeyCredLinkError("no key material")

        for entry in self.blob.entries:
            if entry.identifier == entry_id:
                return entry.value

        raise KeyCredLinkError(f"Key information entry {entry_id} not found")

    def fingerprint(self) -> str:
        """The SHA256 of the key material in DER encoding, formatted
        as hex pairs separated by colons ("hh:hh:...")"""
        # A competing format is '2048 SHA256:<base64bytes>' (ssh style).

        # This sha256 value should also be stored in the KeyID field.
        data = self.get_entry(keycredlink.KeyMaterial)
        hash = sha256(data).digest()
        # Python 3.8+ will do this with hash.hex(':')
        return ':'.join(f'{_:02X}' for _ in hash)

    def description(self, verbosity=2) -> str:
        """Text describing key credential link characteristics.

        verbosity is adjustable between 1 and 3.
        """
        out = []

        def write(msg, verbose_level=0):
            if verbosity > verbose_level:
                out.append(msg)

        write(f'Link target: {self.dn}', 1)
        write(f'Binary Dn: {self}', 2)
        write(f'Key Credential Link Blob version: {self.blob.version}', 2)
        write(f'Number of key entries:            {self.blob.count}', 1)

        write('Key entries:')
        entries = []
        longest = 0
        for description, verbose_level, fn, attr in [
                ("key material fingerprint", 0,
                 lambda x: ':'.join(f"{_:02X}" for _ in x),
                 'KeyID'),
                ("key parameters fingerprint", 2,
                 lambda x: ':'.join(f"{_:02X}" for _ in x),
                 'KeyHash'),
                ("key usage", 1, key_usage_string, 'KeyUsage'),
                ("Device GUID", 1, misc.GUID, 'DeviceId'),
                ("last logon", 0, nttime_as_date,
                 'KeyApproximateLastLogonTimeStamp'),
                ("creation time", 0, nttime_as_date, 'KeyCreationTime'),
                # for now we are ignoring KeySource and CustomKeyInformation
                # KeyMaterial is decoded separately
                ]:

            if verbosity > 1:
                description = f"{description} ({attr})"

            i = getattr(keycredlink, attr)

            try:
                entry = self.get_entry(i)
                value = fn(entry)
            except KeyCredLinkError:
                value = "not found"

            if verbosity > verbose_level:
                entries.append((description, value))
                longest = max(longest, len(description))

        for desc, val in entries:
            write(f"  {desc + ':':{longest + 1}} {val}")

        data = self.get_entry(keycredlink.KeyMaterial)
        key = get_public_key(data, 'der')

        write("RSA public key properties:", 1)
        write(f"  key size: {key.key_size}", 1)
        write(f"  fingerprint: {self.fingerprint()}", 1)

        return '\n'.join(out)

    def key_material(self) -> bytes:
        return self.get_entry(keycredlink.KeyMaterial)

    def as_pem(self) -> str:
        """Get the key out of the keycredlink blob, and return it in
        PEM format as a string.

        PEM is the ASCII format that starts '-----BEGIN PUBLIC KEY-----'.
        """
        # The key is in DER format in an entry in the blob.
        data = self.key_material()
        key = get_public_key(data, 'der')
        pem =  key.public_bytes(Encoding.PEM,
                                PublicFormat.SubjectPublicKeyInfo)
        return pem.decode()


def get_public_key(data:bytes, encoding:Optional[str] = None) -> RSAPublicKey:
    """decode a key in PEM or DER format.

    If it turns out to be a certificate or something, we try to get
    the public key from that.

    So far only RSA keys are supported.
    """
    if encoding is None:
        if data[:11] == b'-----BEGIN ':
            encoding = 'PEM'
        else:
            encoding = 'DER'

    encoding = encoding.upper()

    # The cryptography module also supports ssh keys, PKCS1, and other
    # formats, as well as non-RSA keys and extracting public keys from
    # private. It might not be wise to tolerate all of this, but we
    # can do it by adding to key_fns and cert_fns here.
    if encoding == 'PEM':
        key_fns = [load_pem_public_key]
        cert_fns = [load_pem_x509_certificate]
    elif encoding == 'DER':
        key_fns = [load_der_public_key]
        cert_fns = [load_der_x509_certificate]
    else:
        raise ValueError(f"Public key encoding '{encoding}' not supported "
                         "(try 'PEM' or 'DER')")

    key = None
    for fn in key_fns:
        try:
            key = fn(data)
            break
        except ValueError:
            continue

    if key is None:
        for fn in cert_fns:
            try:
                cert = fn(data)
                key = cert.public_key()
                break
            except ValueError:
                continue

    if key is None:
        raise ValueError("could not decode public key")

    if not isinstance(key, RSAPublicKey):
        raise ValueError("Currently only RSA Public Keys are supported "
                         f"(not '{key}')")

    return key


def kcl_entry_bytes(entry_type:int, data:bytes) -> bytes:
    """helper to pack key credential link entries"""
    return struct.pack('<HB', len(data), entry_type) + data


def create_key_credential_link(samdb: SamDB,
                               target: Union[str, Dn],
                               data: bytes,
                               encoding: Optional[str] = None,
                               force: bool = False):
    """Convert a public key in a common format into a binary DN"""
    if not force:
        res = samdb.search(base=target)
        if len(res) == 0:
            raise ValueError(f"link target {target} does not exist")

    if encoding == 'auto':
        encoding = None

    key = get_public_key(data, encoding)

    if key.key_size != 2048:
        # According to [MS-ADTS] 2.2.20.5.1, KEY_USAGE_NGC means a
        # 2048 bit public key.
        if not force:
            raise ValueError(f"2048 bit RSA key expected, not {key.key_size}")

    key_bytes = key.public_bytes(Encoding.DER,
                                 PublicFormat.SubjectPublicKeyInfo)

    # that's the key.
    # but there's more.
    kcl_header = bytes.fromhex("00 02 00 00")  # Always version 2

    # Entries are added in the enum order, as follows.
    #
    # Here '**' means MUST exist, '*' means SHOULD, and '-' means
    # SHOULD which we ignore. We ignore all the un-SHOULDed values
    # ([MS-ADTS] 2.2.20.6). For KeyUsage, only use KEY_USAGE_NGC.
    #
    # ** 1 KeyID            hash of the key material
    #  * 2 KeyHash          hash of following entries (i.e. 3, 4, 9)
    # ** 3 KeyMaterial      the key
    # ** 4 KeyUsage         KEY_USAGE_NGC, KEY_USAGE_FIDO, or KEY_USAGE_FEK
    #    5 KeySource        KEY_SOURCE_AD.
    #    6 DeviceId         16 byte device ID (GUID, I guess) or zeros
    #    7 CustomKeyInformation  CUSTOM_KEY_INFORMATION struct
    #  - 8 KeyApproximateLastLogonTimeStamp  nttime
    #  * 9 KeyCreationTime   nttime

    # sha256 of the actual key
    kcl_key_id = kcl_entry_bytes(keycredlink.KeyID,
                                 sha256(key_bytes).digest())

    # the actual key
    kcl_material = kcl_entry_bytes(keycredlink.KeyMaterial,
                                   key_bytes)

    # always KEY_USAGE_NGC
    kcl_key_usage = kcl_entry_bytes(keycredlink.KeyUsage,
                                    keycredlink.KEY_USAGE_NGC.to_bytes(1, byteorder='big'))

    # nttime for now
    kcl_creation = kcl_entry_bytes(keycredlink.KeyCreationTime,
                                   struct.pack('<Q', samdb.get_nttime()))

    # always KEY_SOURCE_AD
    #kcl_key_source = kcl_entry_bytes(keycredlink.KeySource,
    #                                 KEY_SOURCE_AD.to_bytes())

    # the KeyHash field is a sha256 of all the values after the
    # KeyHash field.

    kcl_key_hash = kcl_entry_bytes(keycredlink.KeyHash,
                                   sha256(kcl_material +
                                          kcl_key_usage +
                                          kcl_creation).digest())

    kcl_bytes = (kcl_header +
                 kcl_key_id +
                 kcl_key_hash +
                 kcl_material +
                 kcl_key_usage +
                 kcl_creation)

    k = KeyCredentialLinkDn.from_bytes_and_dn(samdb, kcl_bytes, target)
    return k

def kcl_in_list(kcl: KeyCredentialLinkDn, others: Iterable[KeyCredentialLinkDn]):
    """True if kcl is in the list, otherwise False, disregarding
    everything except key material and DN for the comparison.
    """
    # this helps us avoid duplicate key credential links, which are
    # otherwise disallowed only if all fields are identical, but which
    # are generally useless.
    km = kcl.key_material()
    for other in others:
        if km == other.key_material() and kcl.dn == other.dn:
            return True
    return False
