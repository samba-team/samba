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
from samba import (
    NTSTATUSError,
    ntstatus,
    aead_aes_256_cbc_hmac_sha512,
    arcfour_encrypt,
)
from samba import crypto
from secrets import token_bytes
# FIXME from collections.abc import Callable


def OpenPolicyFallback(
    # new_lsa_conn: Callable[[], lsa.lsarpc], - FIXME the type doesn't work
    # with python version 3.6 (CentOS8, SLES15).
    new_lsa_conn,
    system_name: str,
    in_version: int,
    in_revision_info: lsa.revision_info1,
    sec_qos: bool,
    access_mask: int,
):
    conn = new_lsa_conn()

    attr = lsa.ObjectAttribute()
    if sec_qos:
        qos = lsa.QosInfo()
        qos.len = 0xc
        qos.impersonation_level = 2
        qos.context_mode = 1
        qos.effective_only = 0

        attr.sec_qos = qos

    open_policy2 = False
    if in_revision_info is not None:
        try:
            out_version, out_rev_info, policy = conn.OpenPolicy3(
                system_name,
                attr,
                access_mask,
                in_version,
                in_revision_info
            )
        except NTSTATUSError as e:
            if e.args[0] == ntstatus.NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE:
                open_policy2 = True
            if e.args[0] == ntstatus.NT_STATUS_ACCESS_DENIED:
                # We need a new connection
                conn = new_lsa_conn(basis_connection=conn)

                open_policy2 = True
            else:
                raise
    else:
        open_policy2 = True

    if open_policy2:
        out_version = 1
        out_rev_info = lsa.revision_info1()
        out_rev_info.revision = 1
        out_rev_info.supported_features = 0

        policy = conn.OpenPolicy2(system_name, attr, access_mask)

    return conn, out_version, out_rev_info, policy


def CreateTrustedDomainRelax(
    lsaconn: lsa.lsarpc,
    policy: misc.policy_handle,
    trust_info: lsa.TrustDomainInfoInfoEx,
    mask: int,
    in_blob: drsblobs.trustAuthInOutBlob,
    out_blob: drsblobs.trustAuthInOutBlob
):

    def generate_AuthInfoInternal(session_key, incoming=None, outgoing=None):
        confounder = list(token_bytes(512))

        trustpass = drsblobs.trustDomainPasswords()

        trustpass.confounder = confounder
        trustpass.outgoing = outgoing
        trustpass.incoming = incoming

        trustpass_blob = ndr_pack(trustpass)

        encrypted_trustpass = arcfour_encrypt(session_key, trustpass_blob)

        auth_blob = lsa.DATA_BUF2()
        auth_blob.size = len(encrypted_trustpass)
        auth_blob.data = list(encrypted_trustpass)

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


def CreateTrustedDomainFallback(
    conn: lsa.lsarpc,
    policy_handle: misc.policy_handle,
    trust_info: lsa.TrustDomainInfoInfoEx,
    access_mask: int,
    srv_version: int,
    srv_revision_info1: lsa.revision_info1,
    in_blob: drsblobs.trustAuthInOutBlob,
    out_blob: drsblobs.trustAuthInOutBlob
):
    def generate_AuthInfoInternalAES(
        session_key,
        incoming=None,
        outgoing=None
    ):
        trustpass = drsblobs.trustDomainPasswords()

        trustpass.outgoing = outgoing
        trustpass.incoming = incoming

        trustpass_blob = ndr_pack(trustpass)

        lsa_aes256_enc_key = (
            "Microsoft LSAD encryption key AEAD-AES-256-CBC-HMAC-SHA512 16".encode()
            + b'\x00'
        )
        lsa_aes256_mac_key = (
            "Microsoft LSAD MAC key AEAD-AES-256-CBC-HMAC-SHA512 16".encode()
            + b'\x00'
        )

        iv = token_bytes(16)
        ciphertext, auth_data = aead_aes_256_cbc_hmac_sha512(
            trustpass_blob,
            session_key,
            lsa_aes256_enc_key,
            lsa_aes256_mac_key,
            iv,
        )

        return ciphertext, iv, auth_data

    if (srv_version == 1
        and srv_revision_info1.revision == 1
        and (srv_revision_info1.supported_features
             & lsa.LSA_FEATURE_TDO_AUTH_INFO_AES_CIPHER)):

        ciphertext, iv, auth_data = generate_AuthInfoInternalAES(
            conn.session_key, in_blob, out_blob
        )

        auth_blob = lsa.DATA_BUF2()
        auth_blob.size = len(ciphertext)
        auth_blob.data = list(ciphertext)

        auth_info = lsa.TrustDomainInfoAuthInfoInternalAES()
        auth_info.cipher = auth_blob
        auth_info.salt = list(iv)
        auth_info.auth_data = list(auth_data)

        return conn.CreateTrustedDomainEx3(
            policy_handle,
            trust_info,
            auth_info,
            access_mask
        )

    return CreateTrustedDomainRelax(
        conn,
        policy_handle,
        trust_info,
        access_mask,
        in_blob,
        out_blob
    )
