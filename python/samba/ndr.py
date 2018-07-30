# -*- coding: utf-8 -*-

# Unix SMB/CIFS implementation.
# Copyright © Jelmer Vernooij <jelmer@samba.org> 2008
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


"""Network Data Representation (NDR) marshalling and unmarshalling."""


def ndr_pack(object):
    """Pack a NDR object.

    :param object: Object to pack
    :return: String object with marshalled object.
    """
    ndr_pack = getattr(object, "__ndr_pack__", None)
    if ndr_pack is None:
        raise TypeError("%r is not a NDR object" % object)
    return ndr_pack()


def ndr_unpack(cls, data, allow_remaining=False):
    """NDR unpack an object.

    :param cls: Class of the object to unpack
    :param data: Buffer to unpack
    :param allow_remaining: allows remaining data at the end (default=False)
    :return: Unpacked object
    """
    object = cls()
    ndr_unpack = getattr(object, "__ndr_unpack__", None)
    if ndr_unpack is None:
        raise TypeError("%r is not a NDR object" % object)
    ndr_unpack(data, allow_remaining=allow_remaining)
    return object


def ndr_print(object):
    ndr_print = getattr(object, "__ndr_print__", None)
    if ndr_print is None:
        raise TypeError("%r is not a NDR object" % object)
    return ndr_print()


def ndr_pack_in(object, bigendian=False, ndr64=False):
    """Pack the input of an NDR function object.

    :param object: Object to pack
    :param bigendian: use LIBNDR_FLAG_BIGENDIAN (default=False)
    :param ndr64: use LIBNDR_FLAG_NDR64 (default=False)
    :return: String object with marshalled object.
    """
    ndr_pack_in_fn = getattr(object, "__ndr_pack_in__", None)
    if ndr_pack_in_fn is None:
        raise TypeError("%r is not a NDR function object" % object)
    return ndr_pack_in_fn(bigendian=bigendian, ndr64=ndr64)


def ndr_unpack_in(object, data, bigendian=False, ndr64=False, allow_remaining=False):
    """Unpack the input of an NDR function object.

    :param cls: Class of the object to unpack
    :param data: Buffer to unpack
    :param bigendian: use LIBNDR_FLAG_BIGENDIAN (default=False)
    :param ndr64: use LIBNDR_FLAG_NDR64 (default=False)
    :param allow_remaining: allows remaining data at the end (default=False)
    :return: Unpacked object
    """
    ndr_unpack_in_fn = getattr(object, "__ndr_unpack_in__", None)
    if ndr_unpack_in_fn is None:
        raise TypeError("%r is not a NDR function object" % object)
    ndr_unpack_in_fn(data, bigendian=bigendian, ndr64=ndr64,
                     allow_remaining=allow_remaining)
    return object


def ndr_print_in(object):
    ndr_print_in_fn = getattr(object, "__ndr_print_in__", None)
    if ndr_print_in_fn is None:
        raise TypeError("%r is not a NDR function object" % object)
    return ndr_print_in_fn()


def ndr_pack_out(object, bigendian=False, ndr64=False):
    """Pack the output of an NDR function object.

    :param object: Object to pack
    :param bigendian: use LIBNDR_FLAG_BIGENDIAN (default=False)
    :param ndr64: use LIBNDR_FLAG_NDR64 (default=False)
    :return: String object with marshalled object.
    """
    ndr_pack_out_fn = getattr(object, "__ndr_pack_out__", None)
    if ndr_pack_out_fn is None:
        raise TypeError("%r is not a NDR function object" % object)
    return ndr_pack_out_fn(bigendian=bigendian, ndr64=ndr64)


def ndr_unpack_out(object, data, bigendian=False, ndr64=False, allow_remaining=False):
    """Unpack the output of an NDR function object.

    :param cls: Class of the object to unpack
    :param data: Buffer to unpack
    :param bigendian: use LIBNDR_FLAG_BIGENDIAN (default=False)
    :param ndr64: use LIBNDR_FLAG_NDR64 (default=False)
    :param allow_remaining: allows remaining data at the end (default=False)
    :return: Unpacked object
    """
    ndr_unpack_out_fn = getattr(object, "__ndr_unpack_out__", None)
    if ndr_unpack_out_fn is None:
        raise TypeError("%r is not a NDR function object" % object)
    ndr_unpack_out_fn(data, bigendian=bigendian, ndr64=ndr64,
                      allow_remaining=allow_remaining)
    return object


def ndr_print_out(object):
    ndr_print_out_fn = getattr(object, "__ndr_print_out__", None)
    if ndr_print_out_fn is None:
        raise TypeError("%r is not a NDR function object" % object)
    return ndr_print_out_fn()
