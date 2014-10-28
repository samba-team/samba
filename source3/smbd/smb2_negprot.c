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
#include "../lib/tsocket/tsocket.h"
#include "../librpc/ndr/libndr.h"

extern fstring remote_proto;

/*
 * this is the entry point if SMB2 is selected via
 * the SMB negprot and the given dialect.
 */
static void reply_smb20xx(struct smb_request *req, uint16_t dialect)
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
		return;
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

	smbd_smb2_first_negprot(req->xconn, smb2_inpdu, len);
	return;
}

/*
 * this is the entry point if SMB2 is selected via
 * the SMB negprot and the "SMB 2.002" dialect.
 */
void reply_smb2002(struct smb_request *req, uint16_t choice)
{
	reply_smb20xx(req, SMB2_DIALECT_REVISION_202);
}

/*
 * this is the entry point if SMB2 is selected via
 * the SMB negprot and the "SMB 2.???" dialect.
 */
void reply_smb20ff(struct smb_request *req, uint16_t choice)
{
	struct smbXsrv_connection *xconn = req->xconn;
	xconn->smb2.allow_2ff = true;
	reply_smb20xx(req, SMB2_DIALECT_REVISION_2FF);
}

enum protocol_types smbd_smb2_protocol_dialect_match(const uint8_t *indyn,
				const int dialect_count,
				uint16_t *dialect)
{
	struct {
		enum protocol_types proto;
		uint16_t dialect;
	} pd[] = {
		{ PROTOCOL_SMB3_00, SMB3_DIALECT_REVISION_300 },
		{ PROTOCOL_SMB2_24, SMB2_DIALECT_REVISION_224 },
		{ PROTOCOL_SMB2_22, SMB2_DIALECT_REVISION_222 },
		{ PROTOCOL_SMB2_10, SMB2_DIALECT_REVISION_210 },
		{ PROTOCOL_SMB2_02, SMB2_DIALECT_REVISION_202 },
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(pd); i ++) {
		size_t c = 0;

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

	if (get_remote_arch() != RA_SAMBA) {
		set_remote_arch(RA_VISTA);
	}

	fstr_sprintf(remote_proto, "SMB%X_%02X",
		     (dialect >> 8) & 0xFF, dialect & 0xFF);

	reload_services(req->sconn, conn_snum_used, true);
	DEBUG(3,("Selected protocol %s\n", remote_proto));

	/* negprot_spnego() returns a the server guid in the first 16 bytes */
	negprot_spnego_blob = negprot_spnego(req, xconn);
	if (negprot_spnego_blob.data == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}

	if (negprot_spnego_blob.length < 16) {
		return smbd_smb2_request_error(req, NT_STATUS_INTERNAL_ERROR);
	}

	security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	if (lp_server_signing() == SMB_SIGNING_REQUIRED) {
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
			 * We allow up to allmost 16MB.
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

	security_offset = SMB2_HDR_BODY + 0x40;

#if 1
	/* Try SPNEGO auth... */
	security_buffer = data_blob_const(negprot_spnego_blob.data + 16,
					  negprot_spnego_blob.length - 16);
#else
	/* for now we want raw NTLMSSP */
	security_buffer = data_blob_const(NULL, 0);
#endif

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
	SSVAL(outbody.data, 0x06, 0);		/* reserved */
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
	SIVAL(outbody.data, 0x3C, 0);		/* reserved */

	outdyn = security_buffer;

	req->sconn->using_smb2 = true;

	if (dialect != SMB2_DIALECT_REVISION_2FF) {
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
	}

	return smbd_smb2_request_done(req, outbody, &outdyn);
}
