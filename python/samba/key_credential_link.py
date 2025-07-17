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


from samba.samdb import BinaryDn
from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc import keycredlink


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
