# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst.Net Ltd 2023
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

from samba.tests.krb5.rfc4120_pyasn1_generated import *

# Kerberos strings should generally be treated as UTF‐8 encoded, but asn1ate
# (the tool which generates Python definitions from our ASN.1 modules) provides
# no way to specify the encoding to use. By the time we’ve imported
# ‘rfc4120_pyasn1_generated’, KerberosString in the process having been
# instantiated as part of several schema objects, it’s too late to change the
# existing objects. But by overriding the __getattribute__() method on
# KerberosString, we can have objects of that type, or a subtype thereof,
# encoded as UTF‐8 strings instead of as ISO-8859-1 strings (the default).

class ReadOnlyUtf8EncodingDict(dict):
    # Don’t allow any attributes to be set.
    __slots__ = []

    def __getitem__(self, key):
        # Get the original item. This will raise KeyError if it’s not present.
        val = super().__getitem__(key)

        # If anyone wants to know our encoding, say it’s UTF‐8.
        if key == 'encoding':
            return 'utf-8'

        return val

    # Python’s default implementations of the following methods don’t call
    # __getitem__(), so we’ll need to override them with our own replacements.
    # In behaviour, they are close enough to the originals for our purposes.

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def items(self):
        for key in self:
            yield key, self[key]

    def values(self):
        for key in self:
            yield self[key]

    # Don’t let anyone modify the dict’s contents.

    def __setitem__(self, key, val):
        raise TypeError('item assignment not supported')

    def __delitem__(self, key):
        raise TypeError('item deletion not supported')


KerberosString_get_attribute = KerberosString.__getattribute__

def get_attribute_override(self, attr):
    # Get the original attribute. This will raise AttributeError if it’s not
    # present.
    val = KerberosString_get_attribute(self, attr)

    # If anyone wants to know our encoding, say it’s UTF‐8.
    if attr == 'encoding':
        return 'utf-8'

    if attr == '_readOnly':
        # Return a copy of the read‐only attributes with the encoding overridden
        # to be UTF-8. To avoid the possibility of changes being made to the
        # original dict that do not propagate to its copies, the returned dict
        # does not allow modification of its contents. Besides, this is supposed
        # to be read‐only.
        return ReadOnlyUtf8EncodingDict(val)

    return val

# Override the __getattribute__() method on KerberosString.
KerberosString.__getattribute__ = get_attribute_override
