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


from samba.dcerpc import lsa, drsblobs, misc
from samba.ndr import ndr_pack
from samba import NTSTATUSError, arcfour_encrypt, string_to_byte_array
from samba.ntstatus import (
    NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE
)
from samba import crypto
from secrets import token_bytes


def OpenPolicyFallback(
    conn: lsa.lsarpc,
    system_name: str,
    in_version: int,
    in_revision_info: lsa.revision_info1,
    sec_qos: bool = False,
    access_mask: int = 0,
):
    attr = lsa.ObjectAttribute()
    if sec_qos:
        qos = lsa.QosInfo()
        qos.len = 0xc
        qos.impersonation_level = 2
        qos.context_mode = 1
        qos.effective_only = 0

        attr.sec_qos = qos

    try:
        out_version, out_rev_info, policy = conn.OpenPolicy3(
            system_name,
            attr,
            access_mask,
            in_version,
            in_revision_info
        )
    except NTSTATUSError as e:
        if e.args[0] == NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE:
            out_version = 1
            out_rev_info = lsa.revision_info1()
            out_rev_info.revision = 1
            out_rev_info.supported_features = 0

            policy = conn.OpenPolicy2(system_name, attr, access_mask)
        else:
            raise

    return out_version, out_rev_info, policy


def CreateTrustedDomainRelax(
    lsaconn: lsa.lsarpc,
    policy: misc.policy_handle,
    trust_info: lsa.TrustDomainInfoInfoEx,
    mask: int,
    in_blob: drsblobs.trustAuthInOutBlob,
    out_blob: drsblobs.trustAuthInOutBlob
):

    def generate_AuthInfoInternal(session_key, incoming=None, outgoing=None):
        confounder = string_to_byte_array(token_bytes(512))

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
