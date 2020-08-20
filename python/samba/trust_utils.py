# trust utils
#
# Copyright Isaac Boukris 2020
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


from samba.dcerpc import lsa, drsblobs
from samba.ndr import ndr_pack
from samba import arcfour_encrypt, string_to_byte_array
import random
from samba import crypto

def CreateTrustedDomainRelax(lsaconn, policy, trust_info, mask, in_blob, out_blob):

    def generate_AuthInfoInternal(session_key, incoming=None, outgoing=None):
        confounder = [0] * 512
        for i in range(len(confounder)):
            confounder[i] = random.randint(0, 255)

        trustpass = drsblobs.trustDomainPasswords()

        trustpass.confounder = confounder
        trustpass.outgoing = outgoing
        trustpass.incoming = incoming

        trustpass_blob = ndr_pack(trustpass)

        encrypted_trustpass = arcfour_encrypt(session_key, trustpass_blob)

        auth_blob = lsa.DATA_BUF2()
        auth_blob.size = len(encrypted_trustpass)
        auth_blob.data = string_to_byte_array(encrypted_trustpass)

        auth_info = lsa.TrustDomainInfoAuthInfoInternal()
        auth_info.auth_blob = auth_blob

        return auth_info

    session_key = lsaconn.session_key

    try:
        if lsaconn.transport_encrypted():
            crypto.set_relax_mode()
        auth_info = generate_AuthInfoInternal(session_key,
                                              incoming=in_blob,
                                              outgoing=out_blob)
    finally:
        crypto.set_strict_mode()

    return lsaconn.CreateTrustedDomainEx2(policy, trust_info, auth_info, mask)
