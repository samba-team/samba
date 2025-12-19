/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009

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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/smb/smb_common.h"
#include "../libcli/smb/smb2_negotiate_context.h"
#include "../lib/tsocket/tsocket.h"
#include "../librpc/ndr/libndr.h"
#include "../libcli/smb/smb_signing.h"
#include "auth.h"
#include "auth/gensec/gensec.h"
#include "lib/util/string_wrappers.h"
#include "source3/lib/substitute.h"
#ifdef HAVE_VALGRIND_CALLGRIND_H
#include <valgrind/callgrind.h>
#endif /* HAVE_VALGRIND_CALLGRIND_H */

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SMB2

/*
 * this is the entry point if SMB2 is selected via
 * the SMB negprot and the given dialect.
 */
static NTSTATUS reply_smb20xx(struct smb_request *req, uint16_t dialect)
{
	uint8_t *smb2_inpdu;
	uint8_t *smb2_hdr;
	uint8_t *smb2_body;
	uint8_t *smb2_dyn;
	size_t len = SMB2_HDR_BODY + 0x24 + 2;

	smb2_inpdu = talloc_zero_array(talloc_tos(), uint8_t, len);
	if (smb2_inpdu == NULL) {
		DEBUG(0, ("Could not push spnego blob\n"));
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return NT_STATUS_NO_MEMORY;
	}
	smb2_hdr = smb2_inpdu;
	smb2_body = smb2_hdr + SMB2_HDR_BODY;
	smb2_dyn = smb2_body + 0x24;

	SIVAL(smb2_hdr, SMB2_HDR_PROTOCOL_ID,	SMB2_MAGIC);
	SIVAL(smb2_hdr, SMB2_HDR_LENGTH,	SMB2_HDR_BODY);

	SSVAL(smb2_body, 0x00, 0x0024);	/* struct size */
	SSVAL(smb2_body, 0x02, 0x0001);	/* dialect count */

	SSVAL(smb2_dyn,  0x00, dialect);

	req->outbuf = NULL;

	return smbd_smb2_process_negprot(req->xconn, 0, smb2_inpdu, len);
}

/*
 * this is the entry point if SMB2 is selected via
 * the SMB negprot and the "SMB 2.002" dialect.
 */
NTSTATUS reply_smb2002(struct smb_request *req, uint16_t choice)
{
	return reply_smb20xx(req, SMB2_DIALECT_REVISION_202);
}

/*
 * this is the entry point if SMB2 is selected via
 * the SMB negprot and the "SMB 2.???" dialect.
 */
NTSTATUS reply_smb20ff(struct smb_request *req, uint16_t choice)
{
	struct smbXsrv_connection *xconn = req->xconn;
	xconn->smb2.allow_2ff = true;
	return reply_smb20xx(req, SMB2_DIALECT_REVISION_2FF);
}

enum protocol_types smbd_smb2_protocol_dialect_match(const uint8_t *indyn,
				const int dialect_count,
				uint16_t *dialect)
{
	static const struct {
		enum protocol_types proto;
		uint16_t dialect;
	} pd[] = {
		{ PROTOCOL_SMB3_11, SMB3_DIALECT_REVISION_311 },
		{ PROTOCOL_SMB3_02, SMB3_DIALECT_REVISION_302 },
		{ PROTOCOL_SMB3_00, SMB3_DIALECT_REVISION_300 },
		{ PROTOCOL_SMB2_10, SMB2_DIALECT_REVISION_210 },
		{ PROTOCOL_SMB2_02, SMB2_DIALECT_REVISION_202 },
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(pd); i ++) {
		int c = 0;

		if (lp_server_max_protocol() < pd[i].proto) {
			continue;
		}
		if (lp_server_min_protocol() > pd[i].proto) {
			continue;
		}

		for (c = 0; c < dialect_count; c++) {
			*dialect = SVAL(indyn, c*2);
			if (*dialect == pd[i].dialect) {
				return pd[i].proto;
			}
		}
	}

	return PROTOCOL_NONE;
}

static NTSTATUS smb2_negotiate_context_process_posix(
	const struct smb2_negotiate_contexts *in_c,
	bool *posix)
{
	struct smb2_negotiate_context *in_posix = NULL;
	const uint8_t *inbuf = NULL;
	size_t inbuflen;
	bool posix_found = false;
	size_t ofs;
	int cmp;

	*posix = false;

	if (!lp_smb3_unix_extensions(GLOBAL_SECTION_SNUM)) {
		return NT_STATUS_OK;
	}

	in_posix = smb2_negotiate_context_find(in_c,
					       SMB2_POSIX_EXTENSIONS_AVAILABLE);
	if (in_posix == NULL) {
		return NT_STATUS_OK;
	}

	inbuf = in_posix->data.data;
	inbuflen = in_posix->data.length;

	/*
	 * For now the server only supports one variant.
	 * Check it's the right one.
	 */
	if ((inbuflen % 16) != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	SMB_ASSERT(strlen(SMB2_CREATE_TAG_POSIX) == 16);

	for (ofs = 0; ofs < inbuflen; ofs += 16) {
		cmp = memcmp(inbuf+ofs, SMB2_CREATE_TAG_POSIX, 16);
		if (cmp == 0) {
			posix_found = true;
			break;
		}
	}

	if (!posix_found) {
		DBG_DEBUG("Client requested unknown SMB3 Unix extensions:\n");
		dump_data(10, inbuf, inbuflen);
		return NT_STATUS_OK;
	}

	DBG_DEBUG("Client requested SMB3 Unix extensions\n");
	*posix = true;
	return NT_STATUS_OK;
}

struct smbd_smb2_request_process_negprot_state {
	struct smbd_smb2_request *req;
	DATA_BLOB outbody;
	DATA_BLOB outdyn;
};

static void smbd_smb2_request_process_negprot_mc_done(struct tevent_req *subreq);

NTSTATUS smbd_smb2_request_process_negprot(struct smbd_smb2_request *req)
{
	struct smbd_smb2_request_process_negprot_state *state = NULL;
	struct smbXsrv_connection *xconn = req->xconn;
	struct tevent_req *subreq = NULL;
	NTSTATUS status;
	const uint8_t *inbody;
	const uint8_t *indyn = NULL;
	DATA_BLOB outbody;
	DATA_BLOB outdyn;
	DATA_BLOB negprot_spnego_blob;
	uint16_t security_offset;
	DATA_BLOB security_buffer;
	size_t expected_dyn_size = 0;
	size_t c;
	uint16_t security_mode;
	uint16_t dialect_count;
	uint16_t in_security_mode;
	uint32_t in_capabilities;
	DATA_BLOB in_guid_blob;
	struct GUID in_guid;
	struct smb2_negotiate_contexts in_c = { .num_contexts = 0, };
	struct smb2_negotiate_context *in_preauth = NULL;
	struct smb2_negotiate_context *in_cipher = NULL;
	struct smb2_negotiate_context *in_sign_algo = NULL;
	struct smb2_negotiate_context *in_transport_caps = NULL;
	struct smb2_negotiate_contexts out_c = { .num_contexts = 0, };
	const struct smb311_capabilities default_smb3_capabilities =
		smb311_capabilities_parse(
			"server",
			lp_server_smb3_signing_algorithms(),
			lp_server_smb3_encryption_algorithms(),
			true);
	DATA_BLOB out_negotiate_context_blob = data_blob_null;
	uint32_t out_negotiate_context_offset = 0;
	uint16_t out_negotiate_context_count = 0;
	uint16_t dialect = 0;
	uint32_t capabilities;
	DATA_BLOB out_guid_blob;
	struct GUID out_guid;
	enum protocol_types protocol = PROTOCOL_NONE;
	uint32_t max_limit;
	uint32_t max_trans = lp_smb2_max_trans();
	uint32_t max_read = lp_smb2_max_read();
	uint32_t max_write = lp_smb2_max_write();
	NTTIME now = timeval_to_nttime(&req->request_time);
	bool posix = false;
	bool ok;

	status = smbd_smb2_request_verify_sizes(req, 0x24);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}
	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	dialect_count = SVAL(inbody, 0x02);

	in_security_mode = SVAL(inbody, 0x04);
	in_capabilities = IVAL(inbody, 0x08);
	in_guid_blob = data_blob_const(inbody + 0x0C, 16);

	if (dialect_count == 0) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	status = GUID_from_ndr_blob(&in_guid_blob, &in_guid);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	expected_dyn_size = dialect_count * 2;
	if (SMBD_SMB2_IN_DYN_LEN(req) < expected_dyn_size) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}
	indyn = SMBD_SMB2_IN_DYN_PTR(req);

	protocol = smbd_smb2_protocol_dialect_match(indyn,
					dialect_count,
					&dialect);

	for (c=0; protocol == PROTOCOL_NONE && c < dialect_count; c++) {
		if (lp_server_max_protocol() < PROTOCOL_SMB2_10) {
			break;
		}

		dialect = SVAL(indyn, c*2);
		if (dialect == SMB2_DIALECT_REVISION_2FF) {
			if (xconn->smb2.allow_2ff) {
				xconn->smb2.allow_2ff = false;
				protocol = PROTOCOL_SMB2_10;
				break;
			}
		}
	}

	if (protocol == PROTOCOL_NONE) {
		return smbd_smb2_request_error(req, NT_STATUS_NOT_SUPPORTED);
	}

	if (protocol >= PROTOCOL_SMB3_11) {
		uint32_t in_negotiate_context_offset = 0;
		uint16_t in_negotiate_context_count = 0;
		DATA_BLOB in_negotiate_context_blob = data_blob_null;
		size_t ofs;

		in_negotiate_context_offset = IVAL(inbody, 0x1C);
		in_negotiate_context_count = SVAL(inbody, 0x20);

		ofs = SMB2_HDR_BODY;
		ofs += SMBD_SMB2_IN_BODY_LEN(req);
		ofs += expected_dyn_size;
		if ((ofs % 8) != 0) {
			ofs += 8 - (ofs % 8);
		}

		if (in_negotiate_context_offset != ofs) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}

		ofs -= SMB2_HDR_BODY;
		ofs -= SMBD_SMB2_IN_BODY_LEN(req);

		if (SMBD_SMB2_IN_DYN_LEN(req) < ofs) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}

		in_negotiate_context_blob = data_blob_const(indyn,
						SMBD_SMB2_IN_DYN_LEN(req));

		in_negotiate_context_blob.data += ofs;
		in_negotiate_context_blob.length -= ofs;

		status = smb2_negotiate_context_parse(req,
						      in_negotiate_context_blob,
						      in_negotiate_context_count,
						      &in_c);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}

		status = smb2_negotiate_context_process_posix(&in_c, &posix);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
	}

	if ((dialect != SMB2_DIALECT_REVISION_2FF) &&
	    (protocol >= PROTOCOL_SMB2_10) &&
	    !GUID_all_zero(&in_guid))
	{
		ok = remote_arch_cache_update(&in_guid);
		if (!ok) {
			return smbd_smb2_request_error(
				req, NT_STATUS_UNSUCCESSFUL);
		}
	}

	switch (get_remote_arch()) {
	case RA_VISTA:
	case RA_SAMBA:
	case RA_CIFSFS:
	case RA_OSX:
		break;
	default:
		set_remote_arch(RA_VISTA);
		break;
	}

	{
		fstring proto;
		fstr_sprintf(proto,
			     "SMB%X_%02X",
			     (dialect >> 8) & 0xFF, dialect & 0xFF);
		set_remote_proto(proto);
		DEBUG(3,("Selected protocol %s\n", proto));
	}

	reload_services(req->sconn, conn_snum_used, true);

	in_preauth = smb2_negotiate_context_find(&in_c,
					SMB2_PREAUTH_INTEGRITY_CAPABILITIES);
	if (protocol >= PROTOCOL_SMB3_11 && in_preauth == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}
	in_cipher = smb2_negotiate_context_find(&in_c,
					SMB2_ENCRYPTION_CAPABILITIES);
	in_sign_algo = smb2_negotiate_context_find(&in_c,
					SMB2_SIGNING_CAPABILITIES);
	in_transport_caps =  smb2_negotiate_context_find(&in_c,
					SMB2_TRANSPORT_CAPABILITIES);

	/* negprot_spnego() returns the server guid in the first 16 bytes */
	negprot_spnego_blob = negprot_spnego(req, xconn);
	if (negprot_spnego_blob.data == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}

	if (negprot_spnego_blob.length < 16) {
		return smbd_smb2_request_error(req, NT_STATUS_INTERNAL_ERROR);
	}

	security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	if (xconn->smb2.signing_mandatory) {
		security_mode |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
	}

	capabilities = 0;
	if (lp_host_msdfs()) {
		capabilities |= SMB2_CAP_DFS;
	}

	if (protocol >= PROTOCOL_SMB2_10 &&
	    lp_smb2_leases() &&
	    lp_oplocks(GLOBAL_SECTION_SNUM) &&
	    !lp_kernel_oplocks(GLOBAL_SECTION_SNUM))
	{
		capabilities |= SMB2_CAP_LEASING;
	}

	if ((protocol >= PROTOCOL_SMB3_00) &&
	    (lp_server_smb_encrypt(xconn, -1) != SMB_ENCRYPTION_OFF) &&
	    (in_capabilities & SMB2_CAP_ENCRYPTION)) {
		capabilities |= SMB2_CAP_ENCRYPTION;
	}

	if (protocol >= PROTOCOL_SMB3_00 &&
	    in_capabilities & SMB2_CAP_DIRECTORY_LEASING &&
	    lp_smb3_directory_leases())
	{
		capabilities |= SMB2_CAP_DIRECTORY_LEASING;
	}

	/*
	 * 0x10000 (65536) is the maximum allowed message size
	 * for SMB 2.0
	 */
	max_limit = 0x10000;

	if (protocol >= PROTOCOL_SMB2_10) {
		/* largeMTU is not supported over NBT (tcp port 139) */
		if (xconn->transport.type != SMB_TRANSPORT_TYPE_NBT) {
			capabilities |= SMB2_CAP_LARGE_MTU;
			xconn->smb2.credits.multicredit = true;

			/*
			 * We allow up to almost 16MB.
			 *
			 * The maximum PDU size is 0xFFFFFF (16776960)
			 * and we need some space for the header.
			 */
			max_limit = 0xFFFF00;
		}
	}

	/*
	 * the defaults are 8MB, but we'll limit this to max_limit based on
	 * the dialect (64kb for SMB 2.0, 8MB for SMB >= 2.1 with LargeMTU)
	 *
	 * user configured values exceeding the limits will be overwritten,
	 * only smaller values will be accepted
	 */

	max_trans = MIN(max_limit, lp_smb2_max_trans());
	max_read = MIN(max_limit, lp_smb2_max_read());
	max_write = MIN(max_limit, lp_smb2_max_write());

	if (in_preauth != NULL) {
		size_t needed = 4;
		uint16_t hash_count;
		uint16_t salt_length;
		uint16_t selected_preauth = 0;
		const uint8_t *p;
		uint8_t buf[38];
		size_t i;

		if (in_preauth->data.length < needed) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}

		hash_count = SVAL(in_preauth->data.data, 0);
		salt_length = SVAL(in_preauth->data.data, 2);

		if (hash_count == 0) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}

		p = in_preauth->data.data + needed;
		needed += hash_count * 2;
		needed += salt_length;

		if (in_preauth->data.length < needed) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}

		for (i=0; i < hash_count; i++) {
			uint16_t v;

			v = SVAL(p, 0);
			p += 2;

			if (v == SMB2_PREAUTH_INTEGRITY_SHA512) {
				selected_preauth = v;
				break;
			}
		}

		if (selected_preauth == 0) {
			return smbd_smb2_request_error(req,
				NT_STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP);
		}

		SSVAL(buf, 0,  1); /* HashAlgorithmCount */
		SSVAL(buf, 2, 32); /* SaltLength */
		SSVAL(buf, 4, selected_preauth);
		generate_random_buffer(buf + 6, 32);

		status = smb2_negotiate_context_add(
			req,
			&out_c,
			SMB2_PREAUTH_INTEGRITY_CAPABILITIES,
			buf,
			sizeof(buf));
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}

		req->preauth = &req->xconn->smb2.preauth;
	}

	if (protocol >= PROTOCOL_SMB3_00) {
		xconn->smb2.server.sign_algo = SMB2_SIGNING_AES128_CMAC;
	} else {
		xconn->smb2.server.sign_algo = SMB2_SIGNING_HMAC_SHA256;
	}

	if ((capabilities & SMB2_CAP_ENCRYPTION) && (in_cipher != NULL)) {
		const struct smb3_encryption_capabilities *srv_ciphers =
			&default_smb3_capabilities.encryption;
		uint16_t srv_preferred_idx = UINT16_MAX;
		size_t needed = 2;
		uint16_t cipher_count;
		const uint8_t *p;
		uint8_t buf[4];
		size_t i;

		capabilities &= ~SMB2_CAP_ENCRYPTION;

		if (in_cipher->data.length < needed) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}

		cipher_count = SVAL(in_cipher->data.data, 0);
		if (cipher_count == 0) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}

		p = in_cipher->data.data + needed;
		needed += cipher_count * 2;

		if (in_cipher->data.length < needed) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}

		for (i=0; i < cipher_count; i++) {
			uint16_t si;
			uint16_t v;

			v = SVAL(p, 0);
			p += 2;

			for (si = 0; si < srv_ciphers->num_algos; si++) {
				if (srv_ciphers->algos[si] != v) {
					continue;
				}

				/*
				 * The server ciphers are listed
				 * with the lowest idx being preferred.
				 */
				if (si < srv_preferred_idx) {
					srv_preferred_idx = si;
				}
				break;
			}
		}

		if (srv_preferred_idx != UINT16_MAX) {
			xconn->smb2.server.cipher =
				srv_ciphers->algos[srv_preferred_idx];
		}

		SSVAL(buf, 0, 1); /* ChiperCount */
		SSVAL(buf, 2, xconn->smb2.server.cipher);

		status = smb2_negotiate_context_add(
			req,
			&out_c,
			SMB2_ENCRYPTION_CAPABILITIES,
			buf,
			sizeof(buf));
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
	}

	if (capabilities & SMB2_CAP_ENCRYPTION) {
		xconn->smb2.server.cipher = SMB2_ENCRYPTION_AES128_CCM;
	}

	if (in_sign_algo != NULL) {
		const struct smb3_signing_capabilities *srv_sign_algos =
			&default_smb3_capabilities.signing;
		uint16_t srv_preferred_idx = UINT16_MAX;
		size_t needed = 2;
		uint16_t sign_algo_count;
		const uint8_t *p;
		size_t i;

		if (in_sign_algo->data.length < needed) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}

		sign_algo_count = SVAL(in_sign_algo->data.data, 0);
		if (sign_algo_count == 0) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}

		p = in_sign_algo->data.data + needed;
		needed += sign_algo_count * 2;

		if (in_sign_algo->data.length < needed) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}

		for (i=0; i < sign_algo_count; i++) {
			uint16_t si;
			uint16_t v;

			v = SVAL(p, 0);
			p += 2;

			for (si = 0; si < srv_sign_algos->num_algos; si++) {
				if (srv_sign_algos->algos[si] != v) {
					continue;
				}

				/*
				 * The server sign_algos are listed
				 * with the lowest idx being preferred.
				 */
				if (si < srv_preferred_idx) {
					srv_preferred_idx = si;
				}
				break;
			}
		}

		/*
		 * If we found a match announce it
		 * otherwise we'll keep the default
		 * of SMB2_SIGNING_AES128_CMAC
		 */
		if (srv_preferred_idx != UINT16_MAX) {
			uint8_t buf[4];

			xconn->smb2.server.sign_algo =
				srv_sign_algos->algos[srv_preferred_idx];

			SSVAL(buf, 0, 1); /* SigningAlgorithmCount */
			SSVAL(buf, 2, xconn->smb2.server.sign_algo);

			status = smb2_negotiate_context_add(
				req,
				&out_c,
				SMB2_SIGNING_CAPABILITIES,
				buf,
				sizeof(buf));
			if (!NT_STATUS_IS_OK(status)) {
				return smbd_smb2_request_error(req, status);
			}
		}
	}

	if (in_transport_caps != NULL) {
		uint32_t caps_flags;

		if (in_transport_caps->data.length != 4) {
			return smbd_smb2_request_error(
				req, NT_STATUS_INVALID_PARAMETER);
		}

		caps_flags = PULL_LE_U32(in_transport_caps->data.data, 0);

		if ((xconn->transport.type == SMB_TRANSPORT_TYPE_QUIC) &&
		    (caps_flags & SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY) &&
		    !lp_server_smb_encryption_over_quic())
		{
			uint8_t buf[4];

			PUSH_LE_U32(buf,
				    0,
				    SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY);

			status = smb2_negotiate_context_add(
				req,
				&out_c,
				SMB2_TRANSPORT_CAPABILITIES,
				buf,
				sizeof(buf));
			if (!NT_STATUS_IS_OK(status)) {
				return smbd_smb2_request_error(req, status);
			}

			xconn->transport.trusted_quic = true;
		}
	}

	status = smb311_capabilities_check(&default_smb3_capabilities,
					   "smb2srv_negprot",
					   DBGLVL_NOTICE,
					   NT_STATUS_INVALID_PARAMETER,
					   "server",
					   protocol,
					   xconn->smb2.server.sign_algo,
					   xconn->smb2.server.cipher);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	if (protocol >= PROTOCOL_SMB3_00 &&
	    xconn->client->server_multi_channel_enabled)
	{
		if (in_capabilities & SMB2_CAP_MULTI_CHANNEL) {
			capabilities |= SMB2_CAP_MULTI_CHANNEL;
		}
	}

	security_offset = SMB2_HDR_BODY + 0x40;

#if 1
	/* Try SPNEGO auth... */
	security_buffer = data_blob_const(negprot_spnego_blob.data + 16,
					  negprot_spnego_blob.length - 16);
#else
	/* for now we want raw NTLMSSP */
	security_buffer = data_blob_const(NULL, 0);
#endif

	if (posix) {
		/* Client correctly negotiated SMB2 unix extensions. */
		const uint8_t *buf = (const uint8_t *)SMB2_CREATE_TAG_POSIX;
		status = smb2_negotiate_context_add(
				req,
				&out_c,
				SMB2_POSIX_EXTENSIONS_AVAILABLE,
				buf,
				16);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		xconn->smb2.server.posix_extensions_negotiated = true;
	}

	if (out_c.num_contexts != 0) {
		status = smb2_negotiate_context_push(req,
						&out_negotiate_context_blob,
						out_c);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
	}

	if (out_negotiate_context_blob.length != 0) {
		static const uint8_t zeros[8];
		size_t pad = 0;
		size_t ofs;

		outdyn = data_blob_dup_talloc(req, security_buffer);
		if (outdyn.length != security_buffer.length) {
			return smbd_smb2_request_error(req,
						NT_STATUS_NO_MEMORY);
		}

		ofs = security_offset + security_buffer.length;
		if ((ofs % 8) != 0) {
			pad = 8 - (ofs % 8);
		}
		ofs += pad;

		ok = data_blob_append(req, &outdyn, zeros, pad);
		if (!ok) {
			return smbd_smb2_request_error(req,
						NT_STATUS_NO_MEMORY);
		}

		ok = data_blob_append(req, &outdyn,
				      out_negotiate_context_blob.data,
				      out_negotiate_context_blob.length);
		if (!ok) {
			return smbd_smb2_request_error(req,
						NT_STATUS_NO_MEMORY);
		}

		out_negotiate_context_offset = ofs;
		out_negotiate_context_count = out_c.num_contexts;
	} else {
		outdyn = security_buffer;
	}

	out_guid_blob = data_blob_const(negprot_spnego_blob.data, 16);
	status = GUID_from_ndr_blob(&out_guid_blob, &out_guid);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	outbody = smbd_smb2_generate_outbody(req, 0x40);
	if (outbody.data == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}

	SSVAL(outbody.data, 0x00, 0x40 + 1);	/* struct size */
	SSVAL(outbody.data, 0x02,
	      security_mode);			/* security mode */
	SSVAL(outbody.data, 0x04, dialect);	/* dialect revision */
	SSVAL(outbody.data, 0x06,
	      out_negotiate_context_count);	/* reserved/NegotiateContextCount */
	memcpy(outbody.data + 0x08,
	       out_guid_blob.data, 16);	/* server guid */
	SIVAL(outbody.data, 0x18,
	      capabilities);			/* capabilities */
	SIVAL(outbody.data, 0x1C, max_trans);	/* max transact size */
	SIVAL(outbody.data, 0x20, max_read);	/* max read size */
	SIVAL(outbody.data, 0x24, max_write);	/* max write size */
	SBVAL(outbody.data, 0x28, now);		/* system time */
	SBVAL(outbody.data, 0x30, 0);		/* server start time */
	SSVAL(outbody.data, 0x38,
	      security_offset);			/* security buffer offset */
	SSVAL(outbody.data, 0x3A,
	      security_buffer.length);		/* security buffer length */
	SIVAL(outbody.data, 0x3C,
	      out_negotiate_context_offset);	/* reserved/NegotiateContextOffset */

	if (dialect == SMB2_DIALECT_REVISION_2FF) {
		return smbd_smb2_request_done(req, outbody, &outdyn);
	}

	status = smbXsrv_connection_init_tables(xconn, protocol);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	xconn->smb2.client.capabilities = in_capabilities;
	xconn->smb2.client.security_mode = in_security_mode;
	xconn->smb2.client.guid = in_guid;
	xconn->smb2.client.num_dialects = dialect_count;
	xconn->smb2.client.dialects = talloc_array(xconn,
						   uint16_t,
						   dialect_count);
	if (xconn->smb2.client.dialects == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	for (c=0; c < dialect_count; c++) {
		xconn->smb2.client.dialects[c] = SVAL(indyn, c*2);
	}

	xconn->smb2.server.capabilities = capabilities;
	xconn->smb2.server.security_mode = security_mode;
	xconn->smb2.server.guid = out_guid;
	xconn->smb2.server.dialect = dialect;
	xconn->smb2.server.max_trans = max_trans;
	xconn->smb2.server.max_read  = max_read;
	xconn->smb2.server.max_write = max_write;

	if (xconn->protocol < PROTOCOL_SMB2_10) {
		/*
		 * SMB2_02 doesn't support client guids
		 */
		return smbd_smb2_request_done(req, outbody, &outdyn);
	}

	if (!xconn->client->server_multi_channel_enabled) {
		/*
		 * Only deal with the client guid database
		 * if multi-channel is enabled.
		 *
		 * But we still need to setup
		 * xconn->client->global->client_guid to
		 * the correct value.
		 */
		xconn->client->global->client_guid =
			xconn->smb2.client.guid;
		return smbd_smb2_request_done(req, outbody, &outdyn);
	}

	if (xconn->smb2.client.guid_verified) {
		/*
		 * The connection was passed from another
		 * smbd process.
		 */
		return smbd_smb2_request_done(req, outbody, &outdyn);
	}

	state = talloc_zero(req, struct smbd_smb2_request_process_negprot_state);
	if (state == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	*state = (struct smbd_smb2_request_process_negprot_state) {
		.req = req,
		.outbody = outbody,
		.outdyn = outdyn,
	};

	subreq = smb2srv_client_mc_negprot_send(state,
						req->xconn->client->raw_ev_ctx,
						req);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq,
				smbd_smb2_request_process_negprot_mc_done,
				state);
	return NT_STATUS_OK;
}

static void smbd_smb2_request_process_negprot_mc_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request_process_negprot_state *state =
		tevent_req_callback_data(subreq,
		struct smbd_smb2_request_process_negprot_state);
	struct smbd_smb2_request *req = state->req;
	struct smbXsrv_connection *xconn = req->xconn;
	NTSTATUS status;

	status = smb2srv_client_mc_negprot_recv(subreq);
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, NT_STATUS_MESSAGE_RETRIEVED)) {
		/*
		 * The connection was passed to another process
		 *
		 * We mark the error as NT_STATUS_CONNECTION_IN_USE,
		 * in order to indicate to low level code if
		 * ctdbd_unregister_ips() or ctdbd_passed_ips()
		 * is more useful.
		 */
		smbXsrv_connection_disconnect_transport(xconn,
						NT_STATUS_CONNECTION_IN_USE);
		smbd_server_connection_terminate(xconn,
						 "passed connection");
		exit_server_cleanly("connection passed");
		return;
	}
	if (!NT_STATUS_IS_OK(status)) {
		status = smbd_smb2_request_error(req, status);
		if (NT_STATUS_IS_OK(status)) {
			return;
		}

		/*
		 * The connection was passed to another process
		 */
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		exit_server_cleanly("connection passed");
		return;
	}

	/*
	 * We're the first connection...
	 */
	status = smbd_smb2_request_done(req, state->outbody, &state->outdyn);
	if (NT_STATUS_IS_OK(status)) {
		/*
		 * This allows us to support starting smbd under
		 * callgrind and only start the overhead and
		 * instrumentation after the SMB2 negprot,
		 * this allows us to profile only useful
		 * stuff and not all the smbd startup, forking
		 * and multichannel handling.
		 *
		 * valgrind --tool=callgrind --instr-atstart=no smbd
		 */
#ifdef CALLGRIND_START_INSTRUMENTATION
		CALLGRIND_START_INSTRUMENTATION;
#endif
		return;
	}

	/*
	 * The connection was passed to another process
	 */
	smbd_server_connection_terminate(xconn, nt_errstr(status));
	exit_server_cleanly("connection passed");
	return;
}

/****************************************************************************
 Generate the spnego negprot reply blob. Return the number of bytes used.
****************************************************************************/

DATA_BLOB negprot_spnego(TALLOC_CTX *ctx, struct smbXsrv_connection *xconn)
{
	DATA_BLOB blob = data_blob_null;
	DATA_BLOB blob_out = data_blob_null;
	nstring dos_name;
	fstring unix_name;
	NTSTATUS status;
#ifdef DEVELOPER
	size_t slen;
#endif
	struct gensec_security *gensec_security;

	/* See if we can get an SPNEGO blob */
	status = auth_generic_prepare(talloc_tos(),
				      xconn->remote_address,
				      xconn->local_address,
				      "SMB",
				      &gensec_security);

	/*
	 * Despite including it above, there is no need to set a
	 * remote address or similar as we are just interested in the
	 * SPNEGO blob, we never keep this context.
	 */

	if (NT_STATUS_IS_OK(status)) {
		status = gensec_start_mech_by_oid(gensec_security, GENSEC_OID_SPNEGO);
		if (NT_STATUS_IS_OK(status)) {
			status = gensec_update(gensec_security, ctx,
					       data_blob_null, &blob);
			/* If we get the list of OIDs, the 'OK' answer
			 * is NT_STATUS_MORE_PROCESSING_REQUIRED */
			if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
				DEBUG(0, ("Failed to start SPNEGO handler for negprot OID list!\n"));
				blob = data_blob_null;
			}
		}
		TALLOC_FREE(gensec_security);
	}

#if defined(WITH_SMB1SERVER)
	xconn->smb1.negprot.spnego = true;
#endif

	/* strangely enough, NT does not sent the single OID NTLMSSP when
	   not a ADS member, it sends no OIDs at all

	   OLD COMMENT : "we can't do this until we teach our session setup parser to know
		   about raw NTLMSSP (clients send no ASN.1 wrapping if we do this)"

	   Our sessionsetup code now handles raw NTLMSSP connects, so we can go
	   back to doing what W2K3 does here. This is needed to make PocketPC 2003
	   CIFS connections work with SPNEGO. See bugzilla bugs #1828 and #3133
	   for details. JRA.

	*/

	if (blob.length == 0 || blob.data == NULL) {
		return data_blob_null;
	}

	blob_out = data_blob_talloc(ctx, NULL, 16 + blob.length);
	if (blob_out.data == NULL) {
		data_blob_free(&blob);
		return data_blob_null;
	}

	memset(blob_out.data, '\0', 16);

	checked_strlcpy(unix_name, lp_netbios_name(), sizeof(unix_name));
	(void)strlower_m(unix_name);
	push_ascii_nstring(dos_name, unix_name);
	strlcpy((char *)blob_out.data, dos_name, 17);

#ifdef DEVELOPER
	/* Fix valgrind 'uninitialized bytes' issue. */
	slen = strlen(dos_name);
	if (slen < 16) {
		memset(blob_out.data+slen, '\0', 16 - slen);
	}
#endif

	memcpy(&blob_out.data[16], blob.data, blob.length);

	data_blob_free(&blob);

	return blob_out;
}

/*
 * MS-CIFS, 2.2.4.52.2 SMB_COM_NEGOTIATE Response:
 * If the server does not support any of the listed dialects, it MUST return a
 * DialectIndex of 0XFFFF
 */
#define NO_PROTOCOL_CHOSEN	0xffff

#define PROT_SMB_2_002				0x1000
#define PROT_SMB_2_FF				0x2000

/* List of supported SMB1 protocols, most desired first.
 * This is for enabling multi-protocol negotiation in SMB2 when SMB1
 * is disabled.
 */
static const struct {
	const char *proto_name;
	const char *short_name;
	NTSTATUS (*proto_reply_fn)(struct smb_request *req, uint16_t choice);
	int protocol_level;
} supported_protocols[] = {
	{"SMB 2.???",               "SMB2_FF",  reply_smb20ff,  PROTOCOL_SMB2_10},
	{"SMB 2.002",               "SMB2_02",  reply_smb2002,  PROTOCOL_SMB2_02},
	{NULL,NULL,NULL,0},
};

/****************************************************************************
 Reply to a negprot.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

NTSTATUS smb2_multi_protocol_reply_negprot(struct smb_request *req)
{
	size_t choice = 0;
	bool choice_set = false;
	int protocol;
	const char *p;
	size_t num_cliprotos;
	char **cliprotos;
	size_t i;
	size_t converted_size;
	struct smbXsrv_connection *xconn = req->xconn;
	struct smbd_server_connection *sconn = req->sconn;
	int max_proto;
	int min_proto;
	NTSTATUS status;

	START_PROFILE(SMBnegprot);

	if (req->buflen == 0) {
		DEBUG(0, ("negprot got no protocols\n"));
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBnegprot);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (req->buf[req->buflen-1] != '\0') {
		DEBUG(0, ("negprot protocols not 0-terminated\n"));
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBnegprot);
		return NT_STATUS_INVALID_PARAMETER;
	}

	p = (const char *)req->buf + 1;

	num_cliprotos = 0;
	cliprotos = NULL;

	while (smbreq_bufrem(req, p) > 0) {

		char **tmp;

		tmp = talloc_realloc(talloc_tos(), cliprotos, char *,
					   num_cliprotos+1);
		if (tmp == NULL) {
			DEBUG(0, ("talloc failed\n"));
			TALLOC_FREE(cliprotos);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBnegprot);
			return NT_STATUS_NO_MEMORY;
		}

		cliprotos = tmp;

		if (!pull_ascii_talloc(cliprotos, &cliprotos[num_cliprotos], p,
				       &converted_size)) {
			DEBUG(0, ("pull_ascii_talloc failed\n"));
			TALLOC_FREE(cliprotos);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBnegprot);
			return NT_STATUS_NO_MEMORY;
		}

		DEBUG(3, ("Requested protocol [%s]\n",
			  cliprotos[num_cliprotos]));

		num_cliprotos += 1;
		p += strlen(p) + 2;
	}

	/* possibly reload - change of architecture */
	reload_services(sconn, conn_snum_used, true);

	/*
	 * Anything higher than PROTOCOL_SMB2_10 still
	 * needs to go via "SMB 2.???", which is marked
	 * as PROTOCOL_SMB2_10.
	 *
	 * The real negotiation happens via reply_smb20ff()
	 * using SMB2 Negotiation.
	 */
	max_proto = lp_server_max_protocol();
	if (max_proto > PROTOCOL_SMB2_10) {
		max_proto = PROTOCOL_SMB2_10;
	}
	min_proto = lp_server_min_protocol();
	if (min_proto > PROTOCOL_SMB2_10) {
		min_proto = PROTOCOL_SMB2_10;
	}

	/* Check for protocols, most desirable first */
	for (protocol = 0; supported_protocols[protocol].proto_name; protocol++) {
		i = 0;
		if ((supported_protocols[protocol].protocol_level <= max_proto) &&
		    (supported_protocols[protocol].protocol_level >= min_proto))
			while (i < num_cliprotos) {
				if (strequal(cliprotos[i],supported_protocols[protocol].proto_name)) {
					choice = i;
					choice_set = true;
				}
				i++;
			}
		if (choice_set) {
			break;
		}
	}

	if (!choice_set) {
		bool ok;

		DBG_NOTICE("No protocol supported !\n");
		reply_smb1_outbuf(req, 1, 0);
		SSVAL(req->outbuf, smb_vwv0, NO_PROTOCOL_CHOSEN);

		ok = smb1_srv_send(xconn, (char *)req->outbuf, false, 0, false);
		if (!ok) {
			DBG_NOTICE("smb1_srv_send failed\n");
		}
		exit_server_cleanly("no protocol supported\n");
	}

	set_remote_proto(supported_protocols[protocol].short_name);
	reload_services(sconn, conn_snum_used, true);
	status = supported_protocols[protocol].proto_reply_fn(req, choice);
	if (!NT_STATUS_IS_OK(status)) {
		exit_server_cleanly("negprot function failed\n");
	}

	DEBUG(3,("Selected protocol %s\n",supported_protocols[protocol].proto_name));

	DBG_INFO("negprot index=%zu\n", choice);

	TALLOC_FREE(cliprotos);

	END_PROFILE(SMBnegprot);
	return NT_STATUS_OK;
}
