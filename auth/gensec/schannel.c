/*
   Unix SMB/CIFS implementation.

   dcerpc schannel operations

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "librpc/gen_ndr/ndr_schannel.h"
#include "auth/auth.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "auth/gensec/gensec_proto.h"
#include "../libcli/auth/schannel.h"
#include "librpc/gen_ndr/dcerpc.h"
#include "param/param.h"
#include "auth/gensec/gensec_toplevel_proto.h"
#include "lib/crypto/crypto.h"

struct schannel_state {
	struct gensec_security *gensec;
	uint64_t seq_num;
	bool initiator;
	struct netlogon_creds_CredentialState *creds;
	struct auth_user_info_dc *user_info_dc;
};

#define SETUP_SEQNUM(state, buf, initiator) do { \
	uint8_t *_buf = buf; \
	uint32_t _seq_num_low = (state)->seq_num & UINT32_MAX; \
	uint32_t _seq_num_high = (state)->seq_num >> 32; \
	if (initiator) { \
		_seq_num_high |= 0x80000000; \
	} \
	RSIVAL(_buf, 0, _seq_num_low); \
	RSIVAL(_buf, 4, _seq_num_high); \
} while(0)

static struct schannel_state *netsec_create_state(
				struct gensec_security *gensec,
				struct netlogon_creds_CredentialState *creds,
				bool initiator)
{
	struct schannel_state *state;

	state = talloc_zero(gensec, struct schannel_state);
	if (state == NULL) {
		return NULL;
	}

	state->gensec = gensec;
	state->initiator = initiator;
	state->creds = netlogon_creds_copy(state, creds);
	if (state->creds == NULL) {
		talloc_free(state);
		return NULL;
	}

	gensec->private_data = state;

	return state;
}

static void netsec_offset_and_sizes(struct schannel_state *state,
				    bool do_seal,
				    uint32_t *_min_sig_size,
				    uint32_t *_used_sig_size,
				    uint32_t *_checksum_length,
				    uint32_t *_confounder_ofs)
{
	uint32_t min_sig_size;
	uint32_t used_sig_size;
	uint32_t checksum_length;
	uint32_t confounder_ofs;

	if (state->creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		min_sig_size = 48;
		used_sig_size = 56;
		/*
		 * Note: windows has a bug here and uses the old values...
		 *
		 * checksum_length = 32;
		 * confounder_ofs = 48;
		 */
		checksum_length = 8;
		confounder_ofs = 24;
	} else {
		min_sig_size = 24;
		used_sig_size = 32;
		checksum_length = 8;
		confounder_ofs = 24;
	}

	if (do_seal) {
		min_sig_size += 8;
	}

	if (_min_sig_size) {
		*_min_sig_size = min_sig_size;
	}

	if (_used_sig_size) {
		*_used_sig_size = used_sig_size;
	}

	if (_checksum_length) {
		*_checksum_length = checksum_length;
	}

	if (_confounder_ofs) {
		*_confounder_ofs = confounder_ofs;
	}
}

/*******************************************************************
 Encode or Decode the sequence number (which is symmetric)
 ********************************************************************/
static void netsec_do_seq_num(struct schannel_state *state,
			      const uint8_t *checksum,
			      uint32_t checksum_length,
			      uint8_t seq_num[8])
{
	if (state->creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		AES_KEY key;
		uint8_t iv[AES_BLOCK_SIZE];

		AES_set_encrypt_key(state->creds->session_key, 128, &key);
		ZERO_STRUCT(iv);
		memcpy(iv+0, checksum, 8);
		memcpy(iv+8, checksum, 8);

		aes_cfb8_encrypt(seq_num, seq_num, 8, &key, iv, AES_ENCRYPT);
	} else {
		static const uint8_t zeros[4];
		uint8_t sequence_key[16];
		uint8_t digest1[16];

		hmac_md5(state->creds->session_key, zeros, sizeof(zeros), digest1);
		hmac_md5(digest1, checksum, checksum_length, sequence_key);
		arcfour_crypt(seq_num, sequence_key, 8);
	}

	state->seq_num++;
}

static void netsec_do_seal(struct schannel_state *state,
			   const uint8_t seq_num[8],
			   uint8_t confounder[8],
			   uint8_t *data, uint32_t length,
			   bool forward)
{
	if (state->creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		AES_KEY key;
		uint8_t iv[AES_BLOCK_SIZE];
		uint8_t sess_kf0[16];
		int i;

		for (i = 0; i < 16; i++) {
			sess_kf0[i] = state->creds->session_key[i] ^ 0xf0;
		}

		AES_set_encrypt_key(sess_kf0, 128, &key);
		ZERO_STRUCT(iv);
		memcpy(iv+0, seq_num, 8);
		memcpy(iv+8, seq_num, 8);

		if (forward) {
			aes_cfb8_encrypt(confounder, confounder, 8, &key, iv, AES_ENCRYPT);
			aes_cfb8_encrypt(data, data, length, &key, iv, AES_ENCRYPT);
		} else {
			aes_cfb8_encrypt(confounder, confounder, 8, &key, iv, AES_DECRYPT);
			aes_cfb8_encrypt(data, data, length, &key, iv, AES_DECRYPT);
		}
	} else {
		uint8_t sealing_key[16];
		static const uint8_t zeros[4];
		uint8_t digest2[16];
		uint8_t sess_kf0[16];
		int i;

		for (i = 0; i < 16; i++) {
			sess_kf0[i] = state->creds->session_key[i] ^ 0xf0;
		}

		hmac_md5(sess_kf0, zeros, 4, digest2);
		hmac_md5(digest2, seq_num, 8, sealing_key);

		arcfour_crypt(confounder, sealing_key, 8);
		arcfour_crypt(data, sealing_key, length);
	}
}

/*******************************************************************
 Create a digest over the entire packet (including the data), and
 MD5 it with the session key.
 ********************************************************************/
static void netsec_do_sign(struct schannel_state *state,
			   const uint8_t *confounder,
			   const uint8_t *data, size_t length,
			   uint8_t header[8],
			   uint8_t *checksum)
{
	if (state->creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		struct HMACSHA256Context ctx;

		hmac_sha256_init(state->creds->session_key,
				 sizeof(state->creds->session_key),
				 &ctx);

		if (confounder) {
			SSVAL(header, 0, NL_SIGN_HMAC_SHA256);
			SSVAL(header, 2, NL_SEAL_AES128);
			SSVAL(header, 4, 0xFFFF);
			SSVAL(header, 6, 0x0000);

			hmac_sha256_update(header, 8, &ctx);
			hmac_sha256_update(confounder, 8, &ctx);
		} else {
			SSVAL(header, 0, NL_SIGN_HMAC_SHA256);
			SSVAL(header, 2, NL_SEAL_NONE);
			SSVAL(header, 4, 0xFFFF);
			SSVAL(header, 6, 0x0000);

			hmac_sha256_update(header, 8, &ctx);
		}

		hmac_sha256_update(data, length, &ctx);

		hmac_sha256_final(checksum, &ctx);
	} else {
		uint8_t packet_digest[16];
		static const uint8_t zeros[4];
		MD5_CTX ctx;

		MD5Init(&ctx);
		MD5Update(&ctx, zeros, 4);
		if (confounder) {
			SSVAL(header, 0, NL_SIGN_HMAC_MD5);
			SSVAL(header, 2, NL_SEAL_RC4);
			SSVAL(header, 4, 0xFFFF);
			SSVAL(header, 6, 0x0000);

			MD5Update(&ctx, header, 8);
			MD5Update(&ctx, confounder, 8);
		} else {
			SSVAL(header, 0, NL_SIGN_HMAC_MD5);
			SSVAL(header, 2, NL_SEAL_NONE);
			SSVAL(header, 4, 0xFFFF);
			SSVAL(header, 6, 0x0000);

			MD5Update(&ctx, header, 8);
		}
		MD5Update(&ctx, data, length);
		MD5Final(packet_digest, &ctx);

		hmac_md5(state->creds->session_key,
			 packet_digest, sizeof(packet_digest),
			 checksum);
	}
}

static NTSTATUS netsec_incoming_packet(struct schannel_state *state,
				bool do_unseal,
				uint8_t *data, size_t length,
				const uint8_t *whole_pdu, size_t pdu_length,
				const DATA_BLOB *sig)
{
	uint32_t min_sig_size = 0;
	uint8_t header[8];
	uint8_t checksum[32];
	uint32_t checksum_length = sizeof(checksum_length);
	uint8_t _confounder[8];
	uint8_t *confounder = NULL;
	uint32_t confounder_ofs = 0;
	uint8_t seq_num[8];
	int ret;
	const uint8_t *sign_data = NULL;
	size_t sign_length = 0;

	netsec_offset_and_sizes(state,
				do_unseal,
				&min_sig_size,
				NULL,
				&checksum_length,
				&confounder_ofs);

	if (sig->length < min_sig_size) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (do_unseal) {
		confounder = _confounder;
		memcpy(confounder, sig->data+confounder_ofs, 8);
	} else {
		confounder = NULL;
	}

	SETUP_SEQNUM(state, seq_num, !state->initiator);

	if (do_unseal) {
		netsec_do_seal(state, seq_num,
			       confounder,
			       data, length,
			       false);
	}

	if (state->gensec->want_features & GENSEC_FEATURE_SIGN_PKT_HEADER) {
		sign_data = whole_pdu;
		sign_length = pdu_length;
	} else {
		sign_data = data;
		sign_length = length;
	}

	netsec_do_sign(state, confounder,
		       sign_data, sign_length,
		       header, checksum);

	ret = memcmp(checksum, sig->data+16, checksum_length);
	if (ret != 0) {
		dump_data_pw("calc digest:", checksum, checksum_length);
		dump_data_pw("wire digest:", sig->data+16, checksum_length);
		return NT_STATUS_ACCESS_DENIED;
	}

	netsec_do_seq_num(state, checksum, checksum_length, seq_num);

	ret = memcmp(seq_num, sig->data+8, 8);
	if (ret != 0) {
		dump_data_pw("calc seq num:", seq_num, 8);
		dump_data_pw("wire seq num:", sig->data+8, 8);
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

static uint32_t netsec_outgoing_sig_size(struct schannel_state *state)
{
	uint32_t sig_size = 0;

	netsec_offset_and_sizes(state,
				true,
				NULL,
				&sig_size,
				NULL,
				NULL);

	return sig_size;
}

static NTSTATUS netsec_outgoing_packet(struct schannel_state *state,
				TALLOC_CTX *mem_ctx,
				bool do_seal,
				uint8_t *data, size_t length,
				const uint8_t *whole_pdu, size_t pdu_length,
				DATA_BLOB *sig)
{
	uint32_t min_sig_size = 0;
	uint32_t used_sig_size = 0;
	uint8_t header[8];
	uint8_t checksum[32];
	uint32_t checksum_length = sizeof(checksum_length);
	uint8_t _confounder[8];
	uint8_t *confounder = NULL;
	uint32_t confounder_ofs = 0;
	uint8_t seq_num[8];
	const uint8_t *sign_data = NULL;
	size_t sign_length = 0;

	netsec_offset_and_sizes(state,
				do_seal,
				&min_sig_size,
				&used_sig_size,
				&checksum_length,
				&confounder_ofs);

	SETUP_SEQNUM(state, seq_num, state->initiator);

	if (do_seal) {
		confounder = _confounder;
		generate_random_buffer(confounder, 8);
	} else {
		confounder = NULL;
	}

	if (state->gensec->want_features & GENSEC_FEATURE_SIGN_PKT_HEADER) {
		sign_data = whole_pdu;
		sign_length = pdu_length;
	} else {
		sign_data = data;
		sign_length = length;
	}

	netsec_do_sign(state, confounder,
		       sign_data, sign_length,
		       header, checksum);

	if (do_seal) {
		netsec_do_seal(state, seq_num,
			       confounder,
			       data, length,
			       true);
	}

	netsec_do_seq_num(state, checksum, checksum_length, seq_num);

	(*sig) = data_blob_talloc_zero(mem_ctx, used_sig_size);

	memcpy(sig->data, header, 8);
	memcpy(sig->data+8, seq_num, 8);
	memcpy(sig->data+16, checksum, checksum_length);

	if (confounder) {
		memcpy(sig->data+confounder_ofs, confounder, 8);
	}

	dump_data_pw("signature:", sig->data+ 0, 8);
	dump_data_pw("seq_num  :", sig->data+ 8, 8);
	dump_data_pw("digest   :", sig->data+16, checksum_length);
	dump_data_pw("confound :", sig->data+confounder_ofs, 8);

	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS gensec_schannel_init(void);

static size_t schannel_sig_size(struct gensec_security *gensec_security, size_t data_size)
{
	struct schannel_state *state =
		talloc_get_type_abort(gensec_security->private_data,
		struct schannel_state);

	return netsec_outgoing_sig_size(state);
}

static NTSTATUS schannel_update(struct gensec_security *gensec_security, TALLOC_CTX *out_mem_ctx,
				struct tevent_context *ev,
				const DATA_BLOB in, DATA_BLOB *out)
{
	struct schannel_state *state =
		talloc_get_type(gensec_security->private_data,
		struct schannel_state);
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	struct NL_AUTH_MESSAGE bind_schannel;
	struct NL_AUTH_MESSAGE bind_schannel_ack;
	struct netlogon_creds_CredentialState *creds;
	const char *workstation;
	const char *domain;

	*out = data_blob(NULL, 0);

	switch (gensec_security->gensec_role) {
	case GENSEC_CLIENT:
		if (state != NULL) {
			/* we could parse the bind ack, but we don't know what it is yet */
			return NT_STATUS_OK;
		}

		creds = cli_credentials_get_netlogon_creds(gensec_security->credentials);
		if (creds == NULL) {
			return NT_STATUS_INVALID_PARAMETER_MIX;
		}

		state = netsec_create_state(gensec_security,
					    creds, true /* initiator */);
		if (state == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		bind_schannel.MessageType = NL_NEGOTIATE_REQUEST;
#if 0
		/* to support this we'd need to have access to the full domain name */
		/* 0x17, 23 */
		bind_schannel.Flags = NL_FLAG_OEM_NETBIOS_DOMAIN_NAME |
				      NL_FLAG_OEM_NETBIOS_COMPUTER_NAME |
				      NL_FLAG_UTF8_DNS_DOMAIN_NAME |
				      NL_FLAG_UTF8_NETBIOS_COMPUTER_NAME;
		bind_schannel.oem_netbios_domain.a = cli_credentials_get_domain(gensec_security->credentials);
		bind_schannel.oem_netbios_computer.a = creds->computer_name;
		bind_schannel.utf8_dns_domain = cli_credentials_get_realm(gensec_security->credentials);
		/* w2k3 refuses us if we use the full DNS workstation?
		 why? perhaps because we don't fill in the dNSHostName
		 attribute in the machine account? */
		bind_schannel.utf8_netbios_computer = creds->computer_name;
#else
		bind_schannel.Flags = NL_FLAG_OEM_NETBIOS_DOMAIN_NAME |
				      NL_FLAG_OEM_NETBIOS_COMPUTER_NAME;
		bind_schannel.oem_netbios_domain.a = cli_credentials_get_domain(gensec_security->credentials);
		bind_schannel.oem_netbios_computer.a = creds->computer_name;
#endif

		ndr_err = ndr_push_struct_blob(out, out_mem_ctx, &bind_schannel,
					       (ndr_push_flags_fn_t)ndr_push_NL_AUTH_MESSAGE);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			status = ndr_map_error2ntstatus(ndr_err);
			DEBUG(3, ("Could not create schannel bind: %s\n",
				  nt_errstr(status)));
			return status;
		}

		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	case GENSEC_SERVER:

		if (state != NULL) {
			/* no third leg on this protocol */
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* parse the schannel startup blob */
		ndr_err = ndr_pull_struct_blob(&in, out_mem_ctx, &bind_schannel,
			(ndr_pull_flags_fn_t)ndr_pull_NL_AUTH_MESSAGE);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			status = ndr_map_error2ntstatus(ndr_err);
			DEBUG(3, ("Could not parse incoming schannel bind: %s\n",
				  nt_errstr(status)));
			return status;
		}

		if (bind_schannel.Flags & NL_FLAG_OEM_NETBIOS_DOMAIN_NAME) {
			domain = bind_schannel.oem_netbios_domain.a;
			if (strcasecmp_m(domain, lpcfg_workgroup(gensec_security->settings->lp_ctx)) != 0) {
				DEBUG(3, ("Request for schannel to incorrect domain: %s != our domain %s\n",
					  domain, lpcfg_workgroup(gensec_security->settings->lp_ctx)));
				return NT_STATUS_LOGON_FAILURE;
			}
		} else if (bind_schannel.Flags & NL_FLAG_UTF8_DNS_DOMAIN_NAME) {
			domain = bind_schannel.utf8_dns_domain.u;
			if (strcasecmp_m(domain, lpcfg_dnsdomain(gensec_security->settings->lp_ctx)) != 0) {
				DEBUG(3, ("Request for schannel to incorrect domain: %s != our domain %s\n",
					  domain, lpcfg_dnsdomain(gensec_security->settings->lp_ctx)));
				return NT_STATUS_LOGON_FAILURE;
			}
		} else {
			DEBUG(3, ("Request for schannel to without domain\n"));
			return NT_STATUS_LOGON_FAILURE;
		}

		if (bind_schannel.Flags & NL_FLAG_OEM_NETBIOS_COMPUTER_NAME) {
			workstation = bind_schannel.oem_netbios_computer.a;
		} else if (bind_schannel.Flags & NL_FLAG_UTF8_NETBIOS_COMPUTER_NAME) {
			workstation = bind_schannel.utf8_netbios_computer.u;
		} else {
			DEBUG(3, ("Request for schannel to without netbios workstation\n"));
			return NT_STATUS_LOGON_FAILURE;
		}

		status = schannel_get_creds_state(out_mem_ctx,
						  gensec_security->settings->lp_ctx,
						  workstation, &creds);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("Could not find session key for attempted schannel connection from %s: %s\n",
				  workstation, nt_errstr(status)));
			if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
				return NT_STATUS_LOGON_FAILURE;
			}
			return status;
		}

		state = netsec_create_state(gensec_security,
					    creds, false /* not initiator */);
		if (state == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		status = auth_anonymous_user_info_dc(state,
				lpcfg_netbios_name(gensec_security->settings->lp_ctx),
				&state->user_info_dc);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		bind_schannel_ack.MessageType = NL_NEGOTIATE_RESPONSE;
		bind_schannel_ack.Flags = 0;
		bind_schannel_ack.Buffer.dummy = 0x6c0000; /* actually I think
							    * this does not have
							    * any meaning here
							    * - gd */

		ndr_err = ndr_push_struct_blob(out, out_mem_ctx, &bind_schannel_ack,
					       (ndr_push_flags_fn_t)ndr_push_NL_AUTH_MESSAGE);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			status = ndr_map_error2ntstatus(ndr_err);
			DEBUG(3, ("Could not return schannel bind ack for client %s: %s\n",
				  workstation, nt_errstr(status)));
			return status;
		}

		return NT_STATUS_OK;
	}
	return NT_STATUS_INVALID_PARAMETER;
}

/**
 * Returns anonymous credentials for schannel, matching Win2k3.
 *
 */

static NTSTATUS schannel_session_info(struct gensec_security *gensec_security,
				      TALLOC_CTX *mem_ctx,
				      struct auth_session_info **_session_info)
{
	struct schannel_state *state =
		talloc_get_type(gensec_security->private_data,
		struct schannel_state);
	struct auth4_context *auth_ctx = gensec_security->auth_context;
	struct auth_session_info *session_info = NULL;
	uint32_t session_info_flags = 0;
	NTSTATUS status;

	if (auth_ctx == NULL) {
		DEBUG(0, ("Cannot generate a session_info without the auth_context\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (auth_ctx->generate_session_info == NULL) {
		DEBUG(0, ("Cannot generate a session_info without the generate_session_info hook\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (gensec_security->want_features & GENSEC_FEATURE_UNIX_TOKEN) {
		session_info_flags |= AUTH_SESSION_INFO_UNIX_TOKEN;
	}

	session_info_flags |= AUTH_SESSION_INFO_SIMPLE_PRIVILEGES;

	status = auth_ctx->generate_session_info(
				auth_ctx,
				mem_ctx,
				state->user_info_dc,
				state->user_info_dc->info->account_name,
				session_info_flags,
				&session_info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*_session_info = session_info;
	return NT_STATUS_OK;
}

static NTSTATUS schannel_server_start(struct gensec_security *gensec_security)
{
	return NT_STATUS_OK;
}

static NTSTATUS schannel_client_start(struct gensec_security *gensec_security)
{
	return NT_STATUS_OK;
}

static bool schannel_have_feature(struct gensec_security *gensec_security,
					 uint32_t feature)
{
	if (feature & (GENSEC_FEATURE_SIGN |
		       GENSEC_FEATURE_SEAL)) {
		return true;
	}
	if (feature & GENSEC_FEATURE_DCE_STYLE) {
		return true;
	}
	if (feature & GENSEC_FEATURE_SIGN_PKT_HEADER) {
		return true;
	}
	return false;
}

/*
  unseal a packet
*/
static NTSTATUS schannel_unseal_packet(struct gensec_security *gensec_security,
				       uint8_t *data, size_t length,
				       const uint8_t *whole_pdu, size_t pdu_length,
				       const DATA_BLOB *sig)
{
	struct schannel_state *state =
		talloc_get_type_abort(gensec_security->private_data,
		struct schannel_state);

	return netsec_incoming_packet(state, true,
				      discard_const_p(uint8_t, data),
				      length,
				      whole_pdu, pdu_length,
				      sig);
}

/*
  check the signature on a packet
*/
static NTSTATUS schannel_check_packet(struct gensec_security *gensec_security,
				      const uint8_t *data, size_t length,
				      const uint8_t *whole_pdu, size_t pdu_length,
				      const DATA_BLOB *sig)
{
	struct schannel_state *state =
		talloc_get_type_abort(gensec_security->private_data,
		struct schannel_state);

	return netsec_incoming_packet(state, false,
				      discard_const_p(uint8_t, data),
				      length,
				      whole_pdu, pdu_length,
				      sig);
}
/*
  seal a packet
*/
static NTSTATUS schannel_seal_packet(struct gensec_security *gensec_security,
				     TALLOC_CTX *mem_ctx,
				     uint8_t *data, size_t length,
				     const uint8_t *whole_pdu, size_t pdu_length,
				     DATA_BLOB *sig)
{
	struct schannel_state *state =
		talloc_get_type_abort(gensec_security->private_data,
		struct schannel_state);

	return netsec_outgoing_packet(state, mem_ctx, true,
				      data, length,
				      whole_pdu, pdu_length,
				      sig);
}

/*
  sign a packet
*/
static NTSTATUS schannel_sign_packet(struct gensec_security *gensec_security,
				     TALLOC_CTX *mem_ctx,
				     const uint8_t *data, size_t length,
				     const uint8_t *whole_pdu, size_t pdu_length,
				     DATA_BLOB *sig)
{
	struct schannel_state *state =
		talloc_get_type_abort(gensec_security->private_data,
		struct schannel_state);

	return netsec_outgoing_packet(state, mem_ctx, false,
				      discard_const_p(uint8_t, data),
				      length,
				      whole_pdu, pdu_length,
				      sig);
}

static const struct gensec_security_ops gensec_schannel_security_ops = {
	.name		= "schannel",
	.auth_type	= DCERPC_AUTH_TYPE_SCHANNEL,
	.client_start   = schannel_client_start,
	.server_start   = schannel_server_start,
	.update 	= schannel_update,
	.seal_packet 	= schannel_seal_packet,
	.sign_packet   	= schannel_sign_packet,
	.check_packet	= schannel_check_packet,
	.unseal_packet 	= schannel_unseal_packet,
	.session_info	= schannel_session_info,
	.sig_size	= schannel_sig_size,
	.have_feature   = schannel_have_feature,
	.enabled        = true,
	.priority       = GENSEC_SCHANNEL
};

_PUBLIC_ NTSTATUS gensec_schannel_init(void)
{
	NTSTATUS ret;
	ret = gensec_register(&gensec_schannel_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_schannel_security_ops.name));
		return ret;
	}

	return ret;
}
