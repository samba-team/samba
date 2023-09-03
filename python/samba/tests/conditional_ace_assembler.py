# Unix SMB/CIFS implementation.
# Copyright © Catalyst IT 2023
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
"""Fine-grained control over conditional ACE contents.

This deliberately allows you to do broken things that SDDL doesn't.

- token sequences that make no real sense
- sequences that make sense which SDDL can't encode
- strings that aren't proper utf-16
- etc.
"""

import struct
from samba.dcerpc import security, conditional_ace as ca
from samba.ndr import ndr_pack


class Composite:
    token = ca.CONDITIONAL_ACE_TOKEN_COMPOSITE

    def __init__(self, *tokens):
        self.members = []
        for t in tokens:
            self.members.append(dwim_one_token(t))

    def __bytes__(self):
        v = []
        for x in self.members:
            v.extend(bytes(x))

        return (bytes([self.token]) +
                struct.pack("<I", len(v)) +
                bytes(v))


class Int:
    def __init__(self, value,
                 bits=ca.CONDITIONAL_ACE_TOKEN_INT64,
                 base=ca.CONDITIONAL_ACE_INT_BASE_10,
                 sign=ca.CONDITIONAL_ACE_INT_SIGN_NONE):
        self.value = value
        self.bits = int(bits)
        self.base = int(base)
        self.sign = int(sign)

    def __bytes__(self):
        n = struct.pack('<q', self.value)
        return bytes([self.bits]) + n + bytes([self.sign, self.base])


class String:
    """A string is decoded as UTF-16.
    Other iterables allows the insertion of arbitrary raw bytes."""
    token = ca.CONDITIONAL_ACE_TOKEN_UNICODE

    def __init__(self, value):
        if isinstance(value, str):
            value = value.encode('utf-16-le')
        self.value = list(value)

    def __bytes__(self):
        header = struct.pack('<BI', self.token, len(self.value))
        return header + bytes(self.value)


class LocalAttr(String):
    token = ca.CONDITIONAL_ACE_LOCAL_ATTRIBUTE


class UserAttr(String):
    token = ca.CONDITIONAL_ACE_USER_ATTRIBUTE


class DeviceAttr(String):
    token = ca.CONDITIONAL_ACE_DEVICE_ATTRIBUTE


class ResourceAttr(String):
    token = ca.CONDITIONAL_ACE_RESOURCE_ATTRIBUTE


class ByteString:
    """takes an iterable of 8-bit numbers, or a string."""
    token = ca.CONDITIONAL_ACE_TOKEN_OCTET_STRING

    def __init__(self, value):
        if isinstance(value, str):
            value = value.encode()
        self.value = bytes(value)
        if max(self.value) > 255 or min(self.value) < 0:
            raise ValueError("bytes do need to be bytes (0-255)")

    def __bytes__(self):
        header = struct.pack('<BI', self.token, len(self.value))
        return header + self.value


class SID:
    token = ca.CONDITIONAL_ACE_TOKEN_SID

    def __init__(self, sidstring):
        self.sid = security.domsid(sidstring)

    def __bytes__(self):
        value = ndr_pack(self.sid)
        header = struct.pack('B<I', self.token, len(value))
        return header + value


class Token:
    """To add a raw byte, like
    Token(ca.CONDITIONAL_ACE_TOKEN_COMPOSITE)
    """
    def __init__(self, v):
        self.token = v

    def __bytes__(self):
        return bytes([self.token])


def _add_tokens():
    for tok in dir(ca):
        if not tok[:22] == 'CONDITIONAL_ACE_TOKEN_':
            continue
        k = tok[22:]
        globals()[k] = Token(getattr(ca, tok))

_add_tokens()


def dwim_one_token(t):
    if isinstance(t, int):
        return Int(t)
    if isinstance(t, str):
        return String(t)
    if isinstance(t, tuple):
        return Composite(*t)
    if isinstance(t, bytes):
        return ByteString(t)

    return t


def assemble(*tokens):
    program = b'artx'
    if len(tokens) == 1 and isinstance(tokens, (list, tuple, set)):
        print("WARNING: single argument container will become a composite. "
              "you might have meant 'assemble(*args)', not 'assemble(args)'")

    for t in tokens:
        t = dwim_one_token(t)
        program += bytes(t)

    program += b'\x00\x00\x00'
    program = program[:-(len(program) & 3)]

    return program


def assemble_ace(tokens=[],
                 type=security.SEC_ACE_TYPE_ACCESS_ALLOWED_CALLBACK,
                 trustee=None,
                 flags=None,
                 object=None,
                 access_mask=None):
    type_strings = {
        'XA': security.SEC_ACE_TYPE_ACCESS_ALLOWED_CALLBACK,
        'XD': security.SEC_ACE_TYPE_ACCESS_DENIED_CALLBACK,
        'ZA': security.SEC_ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
    }

    a = security.ace()
    a.type = type_strings.get(type, type)
    if trustee is not None:
        a.trustee = trustee
    if flags is not None:
        a.flags = flags
    if object is not None:
        a.object = object

    a.coda = assemble(*tokens)
    return a
