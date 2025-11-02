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

"""ASN.1 module"""

import math
from typing import Optional


class Asn1Error(Exception):
    pass


def length_in_bytes(value: int) -> int:
    """Return the length in bytes of an integer once it is encoded as
    bytes."""

    if value < 0:
        raise Asn1Error("value must be positive")
    if not isinstance(value, int):
        raise Asn1Error("value must be an integer")

    length_in_bits = max(1, math.log2(value + 1))
    length_in_bytes = math.ceil(length_in_bits / 8)
    return length_in_bytes


def bytes_from_int(value: int, *, length: Optional[int] = None) -> bytes:
    """Return an integer encoded big-endian into bytes of an optionally
    specified length.
    """
    if length is None:
        length = length_in_bytes(value)
    return value.to_bytes(length, "big")


def int_from_bytes(data: bytes) -> int:
    """Return an integer decoded from bytes in big-endian format."""
    return int.from_bytes(data, "big")


def int_from_bit_string(string: str) -> int:
    """Return an integer decoded from a bitstring."""
    return int(string, base=2)


def bit_string_from_int(value: int) -> str:
    """Return a bitstring encoding of an integer."""

    string = f"{value:b}"

    # The bitstring must be padded to a multiple of 8 bits in length, or
    # pyasn1 will interpret it incorrectly (as if the padding bits were
    # present, but on the wrong end).
    length = len(string)
    padding_len = math.ceil(length / 8) * 8 - length
    return "0" * padding_len + string


def bit_string_from_bytes(data: bytes) -> str:
    """Return a bitstring encoding of bytes in big-endian format."""
    value = int_from_bytes(data)
    return bit_string_from_int(value)


def bytes_from_bit_string(string: str) -> bytes:
    """Return big-endian format bytes encoded from a bitstring."""
    value = int_from_bit_string(string)
    length = math.ceil(len(string) / 8)
    return value.to_bytes(length, "big")


def asn1_length(data: bytes) -> bytes:
    """Return the ASN.1 encoding of the length of some data."""

    length = len(data)

    if length <= 0:
        raise Asn1Error("length must be greater than zero")
    if length < 0x80:
        return bytes([length])

    encoding_len = length_in_bytes(length)
    if encoding_len >= 0x80:
        raise Asn1Error("item is too long to be ASN.1 encoded")

    data = bytes_from_int(length, length=encoding_len)
    return bytes([0x80 | encoding_len]) + data
