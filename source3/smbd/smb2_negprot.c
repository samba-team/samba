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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SMB2

extern fstring remote_proto;

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
	struct {
		enum protocol_types proto;
		uint16_t dialect;
	} pd[] = {
		{ PROTOCOL_SMB3_11, SMB3_DIALECT_REVISION_311 },
		{ PROTOCOL_SMB3_10, SMB3_DIALECT_REVISION_310 },
		{ PROTOCOL_SMB3_02, SMB3_DIALECT_REVISION_302 },
		{ PROTOCOL_SMB3_00, SMB3_DIALECT_REVISION_300 },
		{ PROTOCOL_SMB2_24, SMB2_DIALECT_REVISION_224 },
		{ PROTOCOL_SMB2_22, SMB2_DIALECT_REVISION_222 },
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

NTSTATUS smbd_smb2_request_process_negprot(struct smbd_smb2_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;
	struct smbXsrv_client_global0 *global0 = NULL;
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
	struct smb2_negotiate_contexts out_c = { .num_contexts = 0, };
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
	bool signing_required = true;
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

	if (protocol >= PROTOCOL_SMB3_10) {
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
					in_negotiate_context_blob, &in_c);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}

		if (in_negotiate_context_count != in_c.num_contexts) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
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

	fstr_sprintf(remote_proto, "SMB%X_%02X",
		     (dialect >> 8) & 0xFF, dialect & 0xFF);

	reload_services(req->sconn, conn_snum_used, true);
	DEBUG(3,("Selected protocol %s\n", remote_proto));

	in_preauth = smb2_negotiate_context_find(&in_c,
					SMB2_PREAUTH_INTEGRITY_CAPABILITIES);
	if (protocol >= PROTOCOL_SMB3_10 && in_preauth == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}
	in_cipher = smb2_negotiate_context_find(&in_c,
					SMB2_ENCRYPTION_CAPABILITIES);

	/* negprot_spnego() returns a the server guid in the first 16 bytes */
	negprot_spnego_blob = negprot_spnego(req, xconn);
	if (negprot_spnego_blob.data == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}

	if (negprot_spnego_blob.length < 16) {
		return smbd_smb2_request_error(req, NT_STATUS_INTERNAL_ERROR);
	}

	security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	/*
	 * We use xconn->smb1.signing_state as that's already present
	 * and used lpcfg_server_signing_allowed() to get the correct
	 * defaults, e.g. signing_required for an ad_dc.
	 */
	signing_required = smb_signing_is_mandatory(xconn->smb1.signing_state);
	if (signing_required) {
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

	if ((protocol >= PROTOCOL_SMB2_24) &&
	    (lp_smb_encrypt(-1) != SMB_SIGNING_OFF) &&
	    (in_capabilities & SMB2_CAP_ENCRYPTION)) {
		capabilities |= SMB2_CAP_ENCRYPTION;
	}

	/*
	 * 0x10000 (65536) is the maximum allowed message size
	 * for SMB 2.0
	 */
	max_limit = 0x10000;

	if (protocol >= PROTOCOL_SMB2_10) {
		int p = 0;

		if (tsocket_address_is_inet(req->sconn->local_address, "ip")) {
			p = tsocket_address_inet_port(req->sconn->local_address);
		}

		/* largeMTU is not supported over NBT (tcp port 139) */
		if (p != NBT_SMB_PORT) {
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

	if ((capabilities & SMB2_CAP_ENCRYPTION) && (in_cipher != NULL)) {
		size_t needed = 2;
		uint16_t cipher_count;
		const uint8_t *p;
		uint8_t buf[4];
		size_t i;
		bool aes_128_ccm_supported = false;
		bool aes_128_gcm_supported = false;

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
			uint16_t v;

			v = SVAL(p, 0);
			p += 2;

			if (v == SMB2_ENCRYPTION_AES128_GCM) {
				aes_128_gcm_supported = true;
			}
			if (v == SMB2_ENCRYPTION_AES128_CCM) {
				aes_128_ccm_supported = true;
			}
		}

		if (aes_128_gcm_supported) {
			xconn->smb2.server.cipher = SMB2_ENCRYPTION_AES128_GCM;
		} else if (aes_128_ccm_supported) {
			xconn->smb2.server.cipher = SMB2_ENCRYPTION_AES128_CCM;
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

	if (protocol >= PROTOCOL_SMB2_22 &&
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

	req->sconn->using_smb2 = true;

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

	status = smb2srv_client_lookup_global(xconn->client,
					      xconn->smb2.client.guid,
					      req, &global0);
	/*
	 * TODO: check for races...
	 */
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECTID_NOT_FOUND)) {
		/*
		 * This stores the new client information in
		 * smbXsrv_client_global.tdb
		 */
		xconn->client->global->client_guid =
			xconn->smb2.client.guid;
		status = smbXsrv_client_update(xconn->client);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		xconn->smb2.client.guid_verified = true;
	} else if (NT_STATUS_IS_OK(status)) {
		status = smb2srv_client_connection_pass(req,
							global0);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}

		smbd_server_connection_terminate(xconn,
						 "passed connection");
		return NT_STATUS_OBJECTID_EXISTS;
	} else {
		return smbd_smb2_request_error(req, status);
	}

	return smbd_smb2_request_done(req, outbody, &outdyn);
}
