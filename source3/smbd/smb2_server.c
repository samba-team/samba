/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Jeremy Allison 2010

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
#include "../lib/util/tevent_ntstatus.h"
#include "smbprofile.h"
#include "../lib/util/bitmap.h"
#include "../librpc/gen_ndr/krb5pac.h"
#include "auth.h"

static void smbd_smb2_connection_handler(struct tevent_context *ev,
					 struct tevent_fd *fde,
					 uint16_t flags,
					 void *private_data);
static NTSTATUS smbd_smb2_flush_send_queue(struct smbXsrv_connection *xconn);

static const struct smbd_smb2_dispatch_table {
	uint16_t opcode;
	const char *name;
	bool need_session;
	bool need_tcon;
	bool as_root;
	uint16_t fileid_ofs;
	bool allow_invalid_fileid;
} smbd_smb2_table[] = {
#define _OP(o) .opcode = o, .name = #o
	{
		_OP(SMB2_OP_NEGPROT),
		.as_root = true,
	},{
		_OP(SMB2_OP_SESSSETUP),
		.as_root = true,
	},{
		_OP(SMB2_OP_LOGOFF),
		.need_session = true,
		.as_root = true,
	},{
		_OP(SMB2_OP_TCON),
		.need_session = true,
		/*
		 * This call needs to be run as root.
		 *
		 * smbd_smb2_request_process_tcon()
		 * calls make_connection_snum(), which will call
		 * change_to_user(), when needed.
		 */
		.as_root = true,
	},{
		_OP(SMB2_OP_TDIS),
		.need_session = true,
		.need_tcon = true,
		.as_root = true,
	},{
		_OP(SMB2_OP_CREATE),
		.need_session = true,
		.need_tcon = true,
	},{
		_OP(SMB2_OP_CLOSE),
		.need_session = true,
		.need_tcon = true,
		.fileid_ofs = 0x08,
	},{
		_OP(SMB2_OP_FLUSH),
		.need_session = true,
		.need_tcon = true,
		.fileid_ofs = 0x08,
	},{
		_OP(SMB2_OP_READ),
		.need_session = true,
		.need_tcon = true,
		.fileid_ofs = 0x10,
	},{
		_OP(SMB2_OP_WRITE),
		.need_session = true,
		.need_tcon = true,
		.fileid_ofs = 0x10,
	},{
		_OP(SMB2_OP_LOCK),
		.need_session = true,
		.need_tcon = true,
		.fileid_ofs = 0x08,
	},{
		_OP(SMB2_OP_IOCTL),
		.need_session = true,
		.need_tcon = true,
		.fileid_ofs = 0x08,
		.allow_invalid_fileid = true,
	},{
		_OP(SMB2_OP_CANCEL),
		.as_root = true,
	},{
		_OP(SMB2_OP_KEEPALIVE),
		.as_root = true,
	},{
		_OP(SMB2_OP_FIND),
		.need_session = true,
		.need_tcon = true,
		.fileid_ofs = 0x08,
	},{
		_OP(SMB2_OP_NOTIFY),
		.need_session = true,
		.need_tcon = true,
		.fileid_ofs = 0x08,
	},{
		_OP(SMB2_OP_GETINFO),
		.need_session = true,
		.need_tcon = true,
		.fileid_ofs = 0x18,
	},{
		_OP(SMB2_OP_SETINFO),
		.need_session = true,
		.need_tcon = true,
		.fileid_ofs = 0x10,
	},{
		_OP(SMB2_OP_BREAK),
		.need_session = true,
		.need_tcon = true,
		/*
		 * we do not set
		 * .fileid_ofs here
		 * as LEASE breaks does not
		 * have a file id
		 */
	}
};

const char *smb2_opcode_name(uint16_t opcode)
{
	if (opcode >= ARRAY_SIZE(smbd_smb2_table)) {
		return "Bad SMB2 opcode";
	}
	return smbd_smb2_table[opcode].name;
}

static const struct smbd_smb2_dispatch_table *smbd_smb2_call(uint16_t opcode)
{
	const struct smbd_smb2_dispatch_table *ret = NULL;

	if (opcode >= ARRAY_SIZE(smbd_smb2_table)) {
		return NULL;
	}

	ret = &smbd_smb2_table[opcode];

	SMB_ASSERT(ret->opcode == opcode);

	return ret;
}

static void print_req_vectors(const struct smbd_smb2_request *req)
{
	int i;

	for (i = 0; i < req->in.vector_count; i++) {
		dbgtext("\treq->in.vector[%u].iov_len = %u\n",
			(unsigned int)i,
			(unsigned int)req->in.vector[i].iov_len);
	}
	for (i = 0; i < req->out.vector_count; i++) {
		dbgtext("\treq->out.vector[%u].iov_len = %u\n",
			(unsigned int)i,
			(unsigned int)req->out.vector[i].iov_len);
	}
}

bool smbd_is_smb2_header(const uint8_t *inbuf, size_t size)
{
	if (size < (4 + SMB2_HDR_BODY)) {
		return false;
	}

	if (IVAL(inbuf, 4) != SMB2_MAGIC) {
		return false;
	}

	return true;
}

static NTSTATUS smbd_initialize_smb2(struct smbXsrv_connection *xconn)
{
	TALLOC_FREE(xconn->transport.fde);

	xconn->smb2.credits.seq_low = 0;
	xconn->smb2.credits.seq_range = 1;
	xconn->smb2.credits.granted = 1;
	xconn->smb2.credits.max = lp_smb2_max_credits();
	xconn->smb2.credits.bitmap = bitmap_talloc(xconn,
						   xconn->smb2.credits.max);
	if (xconn->smb2.credits.bitmap == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	xconn->transport.fde = tevent_add_fd(xconn->ev_ctx,
					xconn,
					xconn->transport.sock,
					TEVENT_FD_READ,
					smbd_smb2_connection_handler,
					xconn);
	if (xconn->transport.fde == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Ensure child is set to non-blocking mode */
	set_blocking(xconn->transport.sock, false);
	return NT_STATUS_OK;
}

#define smb2_len(buf) (PVAL(buf,3)|(PVAL(buf,2)<<8)|(PVAL(buf,1)<<16))
#define _smb2_setlen(_buf,len) do { \
	uint8_t *buf = (uint8_t *)_buf; \
	buf[0] = 0; \
	buf[1] = ((len)&0xFF0000)>>16; \
	buf[2] = ((len)&0xFF00)>>8; \
	buf[3] = (len)&0xFF; \
} while (0)

static void smb2_setup_nbt_length(struct iovec *vector, int count)
{
	size_t len = 0;
	int i;

	for (i=1; i < count; i++) {
		len += vector[i].iov_len;
	}

	_smb2_setlen(vector[0].iov_base, len);
}

static int smbd_smb2_request_destructor(struct smbd_smb2_request *req)
{
	if (req->first_key.length > 0) {
		data_blob_clear_free(&req->first_key);
	}
	if (req->last_key.length > 0) {
		data_blob_clear_free(&req->last_key);
	}
	return 0;
}

static struct smbd_smb2_request *smbd_smb2_request_allocate(TALLOC_CTX *mem_ctx)
{
	TALLOC_CTX *mem_pool;
	struct smbd_smb2_request *req;

#if 0
	/* Enable this to find subtle valgrind errors. */
	mem_pool = talloc_init("smbd_smb2_request_allocate");
#else
	mem_pool = talloc_tos();
#endif
	if (mem_pool == NULL) {
		return NULL;
	}

	req = talloc_zero(mem_pool, struct smbd_smb2_request);
	if (req == NULL) {
		talloc_free(mem_pool);
		return NULL;
	}
	talloc_reparent(mem_pool, mem_ctx, req);
#if 0
	TALLOC_FREE(mem_pool);
#endif

	req->last_session_id = UINT64_MAX;
	req->last_tid = UINT32_MAX;

	talloc_set_destructor(req, smbd_smb2_request_destructor);

	return req;
}

static NTSTATUS smbd_smb2_inbuf_parse_compound(struct smbXsrv_connection *xconn,
					       NTTIME now,
					       uint8_t *buf,
					       size_t buflen,
					       struct smbd_smb2_request *req,
					       struct iovec **piov,
					       int *pnum_iov)
{
	TALLOC_CTX *mem_ctx = req;
	struct iovec *iov;
	int num_iov = 1;
	size_t taken = 0;
	uint8_t *first_hdr = buf;
	size_t verified_buflen = 0;
	uint8_t *tf = NULL;
	size_t tf_len = 0;

	/*
	 * Note: index '0' is reserved for the transport protocol
	 */
	iov = req->in._vector;

	while (taken < buflen) {
		size_t len = buflen - taken;
		uint8_t *hdr = first_hdr + taken;
		struct iovec *cur;
		size_t full_size;
		size_t next_command_ofs;
		uint16_t body_size;
		uint8_t *body = NULL;
		uint32_t dyn_size;
		uint8_t *dyn = NULL;
		struct iovec *iov_alloc = NULL;

		if (iov != req->in._vector) {
			iov_alloc = iov;
		}

		if (verified_buflen > taken) {
			len = verified_buflen - taken;
		} else {
			tf = NULL;
			tf_len = 0;
		}

		if (len < 4) {
			DEBUG(10, ("%d bytes left, expected at least %d\n",
				   (int)len, 4));
			goto inval;
		}
		if (IVAL(hdr, 0) == SMB2_TF_MAGIC) {
			struct smbXsrv_session *s = NULL;
			uint64_t uid;
			struct iovec tf_iov[2];
			NTSTATUS status;
			size_t enc_len;

			if (xconn->protocol < PROTOCOL_SMB2_24) {
				DEBUG(10, ("Got SMB2_TRANSFORM header, "
					   "but dialect[0x%04X] is used\n",
					   xconn->smb2.server.dialect));
				goto inval;
			}

			if (!(xconn->smb2.server.capabilities & SMB2_CAP_ENCRYPTION)) {
				DEBUG(10, ("Got SMB2_TRANSFORM header, "
					   "but not negotiated "
					   "client[0x%08X] server[0x%08X]\n",
					   xconn->smb2.client.capabilities,
					   xconn->smb2.server.capabilities));
				goto inval;
			}

			if (len < SMB2_TF_HDR_SIZE) {
				DEBUG(1, ("%d bytes left, expected at least %d\n",
					   (int)len, SMB2_TF_HDR_SIZE));
				goto inval;
			}
			tf = hdr;
			tf_len = SMB2_TF_HDR_SIZE;
			taken += tf_len;

			hdr = first_hdr + taken;
			enc_len = IVAL(tf, SMB2_TF_MSG_SIZE);
			uid = BVAL(tf, SMB2_TF_SESSION_ID);

			if (len < SMB2_TF_HDR_SIZE + enc_len) {
				DEBUG(1, ("%d bytes left, expected at least %d\n",
					   (int)len,
					   (int)(SMB2_TF_HDR_SIZE + enc_len)));
				goto inval;
			}

			status = smb2srv_session_lookup(xconn, uid, now, &s);
			if (s == NULL) {
				DEBUG(1, ("invalid session[%llu] in "
					  "SMB2_TRANSFORM header\n",
					   (unsigned long long)uid));
				TALLOC_FREE(iov_alloc);
				return NT_STATUS_USER_SESSION_DELETED;
			}

			tf_iov[0].iov_base = (void *)tf;
			tf_iov[0].iov_len = tf_len;
			tf_iov[1].iov_base = (void *)hdr;
			tf_iov[1].iov_len = enc_len;

			status = smb2_signing_decrypt_pdu(s->global->decryption_key,
							  xconn->protocol,
							  tf_iov, 2);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(iov_alloc);
				return status;
			}

			verified_buflen = taken + enc_len;
			len = enc_len;
		}

		/*
		 * We need the header plus the body length field
		 */

		if (len < SMB2_HDR_BODY + 2) {
			DEBUG(10, ("%d bytes left, expected at least %d\n",
				   (int)len, SMB2_HDR_BODY));
			goto inval;
		}
		if (IVAL(hdr, 0) != SMB2_MAGIC) {
			DEBUG(10, ("Got non-SMB2 PDU: %x\n",
				   IVAL(hdr, 0)));
			goto inval;
		}
		if (SVAL(hdr, 4) != SMB2_HDR_BODY) {
			DEBUG(10, ("Got HDR len %d, expected %d\n",
				   SVAL(hdr, 4), SMB2_HDR_BODY));
			goto inval;
		}

		full_size = len;
		next_command_ofs = IVAL(hdr, SMB2_HDR_NEXT_COMMAND);
		body_size = SVAL(hdr, SMB2_HDR_BODY);

		if (next_command_ofs != 0) {
			if (next_command_ofs < (SMB2_HDR_BODY + 2)) {
				goto inval;
			}
			if (next_command_ofs > full_size) {
				goto inval;
			}
			full_size = next_command_ofs;
		}
		if (body_size < 2) {
			goto inval;
		}
		body_size &= 0xfffe;

		if (body_size > (full_size - SMB2_HDR_BODY)) {
			/*
			 * let the caller handle the error
			 */
			body_size = full_size - SMB2_HDR_BODY;
		}
		body = hdr + SMB2_HDR_BODY;
		dyn = body + body_size;
		dyn_size = full_size - (SMB2_HDR_BODY + body_size);

		if (num_iov >= ARRAY_SIZE(req->in._vector)) {
			struct iovec *iov_tmp = NULL;

			iov_tmp = talloc_realloc(mem_ctx, iov_alloc,
						 struct iovec,
						 num_iov +
						 SMBD_SMB2_NUM_IOV_PER_REQ);
			if (iov_tmp == NULL) {
				TALLOC_FREE(iov_alloc);
				return NT_STATUS_NO_MEMORY;
			}

			if (iov_alloc == NULL) {
				memcpy(iov_tmp,
				       req->in._vector,
				       sizeof(req->in._vector));
			}

			iov = iov_tmp;
		}
		cur = &iov[num_iov];
		num_iov += SMBD_SMB2_NUM_IOV_PER_REQ;

		cur[SMBD_SMB2_TF_IOV_OFS].iov_base   = tf;
		cur[SMBD_SMB2_TF_IOV_OFS].iov_len    = tf_len;
		cur[SMBD_SMB2_HDR_IOV_OFS].iov_base  = hdr;
		cur[SMBD_SMB2_HDR_IOV_OFS].iov_len   = SMB2_HDR_BODY;
		cur[SMBD_SMB2_BODY_IOV_OFS].iov_base = body;
		cur[SMBD_SMB2_BODY_IOV_OFS].iov_len  = body_size;
		cur[SMBD_SMB2_DYN_IOV_OFS].iov_base  = dyn;
		cur[SMBD_SMB2_DYN_IOV_OFS].iov_len   = dyn_size;

		taken += full_size;
	}

	*piov = iov;
	*pnum_iov = num_iov;
	return NT_STATUS_OK;

inval:
	if (iov != req->in._vector) {
		TALLOC_FREE(iov);
	}
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS smbd_smb2_request_create(struct smbXsrv_connection *xconn,
					 const uint8_t *_inpdu, size_t size,
					 struct smbd_smb2_request **_req)
{
	struct smbd_server_connection *sconn = xconn->client->sconn;
	struct smbd_smb2_request *req;
	uint32_t protocol_version;
	uint8_t *inpdu = NULL;
	const uint8_t *inhdr = NULL;
	uint16_t cmd;
	uint32_t next_command_ofs;
	NTSTATUS status;
	NTTIME now;

	if (size < (SMB2_HDR_BODY + 2)) {
		DEBUG(0,("Invalid SMB2 packet length count %ld\n", (long)size));
		return NT_STATUS_INVALID_PARAMETER;
	}

	inhdr = _inpdu;

	protocol_version = IVAL(inhdr, SMB2_HDR_PROTOCOL_ID);
	if (protocol_version != SMB2_MAGIC) {
		DEBUG(0,("Invalid SMB packet: protocol prefix: 0x%08X\n",
			 protocol_version));
		return NT_STATUS_INVALID_PARAMETER;
	}

	cmd = SVAL(inhdr, SMB2_HDR_OPCODE);
	if (cmd != SMB2_OP_NEGPROT) {
		DEBUG(0,("Invalid SMB packet: first request: 0x%04X\n",
			 cmd));
		return NT_STATUS_INVALID_PARAMETER;
	}

	next_command_ofs = IVAL(inhdr, SMB2_HDR_NEXT_COMMAND);
	if (next_command_ofs != 0) {
		DEBUG(0,("Invalid SMB packet: next_command: 0x%08X\n",
			 next_command_ofs));
		return NT_STATUS_INVALID_PARAMETER;
	}

	req = smbd_smb2_request_allocate(xconn);
	if (req == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	req->sconn = sconn;
	req->xconn = xconn;

	inpdu = talloc_memdup(req, _inpdu, size);
	if (inpdu == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	req->request_time = timeval_current();
	now = timeval_to_nttime(&req->request_time);

	status = smbd_smb2_inbuf_parse_compound(xconn,
						now,
						inpdu,
						size,
						req, &req->in.vector,
						&req->in.vector_count);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(req);
		return status;
	}

	req->current_idx = 1;

	*_req = req;
	return NT_STATUS_OK;
}

static bool smb2_validate_sequence_number(struct smbXsrv_connection *xconn,
					  uint64_t message_id, uint64_t seq_id)
{
	struct bitmap *credits_bm = xconn->smb2.credits.bitmap;
	unsigned int offset;
	uint64_t seq_tmp;

	seq_tmp = xconn->smb2.credits.seq_low;
	if (seq_id < seq_tmp) {
		DEBUG(0,("smb2_validate_sequence_number: bad message_id "
			"%llu (sequence id %llu) "
			"(granted = %u, low = %llu, range = %u)\n",
			(unsigned long long)message_id,
			(unsigned long long)seq_id,
			(unsigned int)xconn->smb2.credits.granted,
			(unsigned long long)xconn->smb2.credits.seq_low,
			(unsigned int)xconn->smb2.credits.seq_range));
		return false;
	}

	seq_tmp += xconn->smb2.credits.seq_range;
	if (seq_id >= seq_tmp) {
		DEBUG(0,("smb2_validate_sequence_number: bad message_id "
			"%llu (sequence id %llu) "
			"(granted = %u, low = %llu, range = %u)\n",
			(unsigned long long)message_id,
			(unsigned long long)seq_id,
			(unsigned int)xconn->smb2.credits.granted,
			(unsigned long long)xconn->smb2.credits.seq_low,
			(unsigned int)xconn->smb2.credits.seq_range));
		return false;
	}

	offset = seq_id % xconn->smb2.credits.max;

	if (bitmap_query(credits_bm, offset)) {
		DEBUG(0,("smb2_validate_sequence_number: duplicate message_id "
			"%llu (sequence id %llu) "
			"(granted = %u, low = %llu, range = %u) "
			"(bm offset %u)\n",
			(unsigned long long)message_id,
			(unsigned long long)seq_id,
			(unsigned int)xconn->smb2.credits.granted,
			(unsigned long long)xconn->smb2.credits.seq_low,
			(unsigned int)xconn->smb2.credits.seq_range,
			offset));
		return false;
	}

	/* Mark the message_ids as seen in the bitmap. */
	bitmap_set(credits_bm, offset);

	if (seq_id != xconn->smb2.credits.seq_low) {
		return true;
	}

	/*
	 * Move the window forward by all the message_id's
	 * already seen.
	 */
	while (bitmap_query(credits_bm, offset)) {
		DEBUG(10,("smb2_validate_sequence_number: clearing "
			  "id %llu (position %u) from bitmap\n",
			  (unsigned long long)(xconn->smb2.credits.seq_low),
			  offset));
		bitmap_clear(credits_bm, offset);

		xconn->smb2.credits.seq_low += 1;
		xconn->smb2.credits.seq_range -= 1;
		offset = xconn->smb2.credits.seq_low % xconn->smb2.credits.max;
	}

	return true;
}

static bool smb2_validate_message_id(struct smbXsrv_connection *xconn,
				     const uint8_t *inhdr)
{
	uint64_t message_id = BVAL(inhdr, SMB2_HDR_MESSAGE_ID);
	uint16_t opcode = SVAL(inhdr, SMB2_HDR_OPCODE);
	uint16_t credit_charge = 1;
	uint64_t i;

	if (opcode == SMB2_OP_CANCEL) {
		/* SMB2_CANCEL requests by definition resend messageids. */
		return true;
	}

	if (xconn->smb2.credits.multicredit) {
		credit_charge = SVAL(inhdr, SMB2_HDR_CREDIT_CHARGE);
		credit_charge = MAX(credit_charge, 1);
	}

	DEBUG(11, ("smb2_validate_message_id: mid %llu (charge %llu), "
		   "credits_granted %llu, "
		   "seqnum low/range: %llu/%llu\n",
		   (unsigned long long) message_id,
		   (unsigned long long) credit_charge,
		   (unsigned long long) xconn->smb2.credits.granted,
		   (unsigned long long) xconn->smb2.credits.seq_low,
		   (unsigned long long) xconn->smb2.credits.seq_range));

	if (xconn->smb2.credits.granted < credit_charge) {
		DEBUG(0, ("smb2_validate_message_id: client used more "
			  "credits than granted, mid %llu, charge %llu, "
			  "credits_granted %llu, "
			  "seqnum low/range: %llu/%llu\n",
			  (unsigned long long) message_id,
			  (unsigned long long) credit_charge,
			  (unsigned long long) xconn->smb2.credits.granted,
			  (unsigned long long) xconn->smb2.credits.seq_low,
			  (unsigned long long) xconn->smb2.credits.seq_range));
		return false;
	}

	/*
	 * now check the message ids
	 *
	 * for multi-credit requests we need to check all current mid plus
	 * the implicit mids caused by the credit charge
	 * e.g. current mid = 15, charge 5 => mark 15-19 as used
	 */

	for (i = 0; i <= (credit_charge-1); i++) {
		uint64_t id = message_id + i;
		bool ok;

		DEBUG(11, ("Iterating mid %llu charge %u (sequence %llu)\n",
			   (unsigned long long)message_id,
			   credit_charge,
			   (unsigned long long)id));

		ok = smb2_validate_sequence_number(xconn, message_id, id);
		if (!ok) {
			return false;
		}
	}

	/* substract used credits */
	xconn->smb2.credits.granted -= credit_charge;

	return true;
}

static NTSTATUS smbd_smb2_request_validate(struct smbd_smb2_request *req)
{
	int count;
	int idx;

	count = req->in.vector_count;

	if (count < 1 + SMBD_SMB2_NUM_IOV_PER_REQ) {
		/* It's not a SMB2 request */
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (idx=1; idx < count; idx += SMBD_SMB2_NUM_IOV_PER_REQ) {
		struct iovec *hdr = SMBD_SMB2_IDX_HDR_IOV(req,in,idx);
		struct iovec *body = SMBD_SMB2_IDX_BODY_IOV(req,in,idx);
		const uint8_t *inhdr = NULL;

		if (hdr->iov_len != SMB2_HDR_BODY) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (body->iov_len < 2) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		inhdr = (const uint8_t *)hdr->iov_base;

		/* Check the SMB2 header */
		if (IVAL(inhdr, SMB2_HDR_PROTOCOL_ID) != SMB2_MAGIC) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (!smb2_validate_message_id(req->xconn, inhdr)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	return NT_STATUS_OK;
}

static void smb2_set_operation_credit(struct smbXsrv_connection *xconn,
				      const struct iovec *in_vector,
				      struct iovec *out_vector)
{
	const uint8_t *inhdr = (const uint8_t *)in_vector->iov_base;
	uint8_t *outhdr = (uint8_t *)out_vector->iov_base;
	uint16_t credit_charge = 1;
	uint16_t credits_requested;
	uint32_t out_flags;
	uint16_t cmd;
	NTSTATUS out_status;
	uint16_t credits_granted = 0;
	uint64_t credits_possible;
	uint16_t current_max_credits;

	/*
	 * first we grant only 1/16th of the max range.
	 *
	 * Windows also starts with the 1/16th and then grants
	 * more later. I was only able to trigger higher
	 * values, when using a very high credit charge.
	 *
	 * TODO: scale up depending on load, free memory
	 *       or other stuff.
	 *       Maybe also on the relationship between number
	 *       of requests and the used sequence number.
	 *       Which means we would grant more credits
	 *       for client which use multi credit requests.
	 */
	current_max_credits = xconn->smb2.credits.max / 16;
	current_max_credits = MAX(current_max_credits, 1);

	if (xconn->smb2.credits.multicredit) {
		credit_charge = SVAL(inhdr, SMB2_HDR_CREDIT_CHARGE);
		credit_charge = MAX(credit_charge, 1);
	}

	cmd = SVAL(inhdr, SMB2_HDR_OPCODE);
	credits_requested = SVAL(inhdr, SMB2_HDR_CREDIT);
	credits_requested = MAX(credits_requested, 1);
	out_flags = IVAL(outhdr, SMB2_HDR_FLAGS);
	out_status = NT_STATUS(IVAL(outhdr, SMB2_HDR_STATUS));

	SMB_ASSERT(xconn->smb2.credits.max >= xconn->smb2.credits.granted);

	if (xconn->smb2.credits.max < credit_charge) {
		smbd_server_connection_terminate(xconn,
			"client error: credit charge > max credits\n");
		return;
	}

	if (out_flags & SMB2_HDR_FLAG_ASYNC) {
		/*
		 * In case we already send an async interim
		 * response, we should not grant
		 * credits on the final response.
		 */
		credits_granted = 0;
	} else {
		uint16_t additional_possible =
			xconn->smb2.credits.max - credit_charge;
		uint16_t additional_max = 0;
		uint16_t additional_credits = credits_requested - 1;

		switch (cmd) {
		case SMB2_OP_NEGPROT:
			break;
		case SMB2_OP_SESSSETUP:
			/*
			 * Windows 2012 RC1 starts to grant
			 * additional credits
			 * with a successful session setup
			 */
			if (NT_STATUS_IS_OK(out_status)) {
				additional_max = 32;
			}
			break;
		default:
			/*
			 * We match windows and only grant additional credits
			 * in chunks of 32.
			 */
			additional_max = 32;
			break;
		}

		additional_max = MIN(additional_max, additional_possible);
		additional_credits = MIN(additional_credits, additional_max);

		credits_granted = credit_charge + additional_credits;
	}

	/*
	 * sequence numbers should not wrap
	 *
	 * 1. calculate the possible credits until
	 *    the sequence numbers start to wrap on 64-bit.
	 *
	 * 2. UINT64_MAX is used for Break Notifications.
	 *
	 * 2. truncate the possible credits to the maximum
	 *    credits we want to grant to the client in total.
	 *
	 * 3. remove the range we'll already granted to the client
	 *    this makes sure the client consumes the lowest sequence
	 *    number, before we can grant additional credits.
	 */
	credits_possible = UINT64_MAX - xconn->smb2.credits.seq_low;
	if (credits_possible > 0) {
		/* remove UINT64_MAX */
		credits_possible -= 1;
	}
	credits_possible = MIN(credits_possible, current_max_credits);
	credits_possible -= xconn->smb2.credits.seq_range;

	credits_granted = MIN(credits_granted, credits_possible);

	SSVAL(outhdr, SMB2_HDR_CREDIT, credits_granted);
	xconn->smb2.credits.granted += credits_granted;
	xconn->smb2.credits.seq_range += credits_granted;

	DEBUG(10,("smb2_set_operation_credit: requested %u, charge %u, "
		"granted %u, current possible/max %u/%u, "
		"total granted/max/low/range %u/%u/%llu/%u\n",
		(unsigned int)credits_requested,
		(unsigned int)credit_charge,
		(unsigned int)credits_granted,
		(unsigned int)credits_possible,
		(unsigned int)current_max_credits,
		(unsigned int)xconn->smb2.credits.granted,
		(unsigned int)xconn->smb2.credits.max,
		(unsigned long long)xconn->smb2.credits.seq_low,
		(unsigned int)xconn->smb2.credits.seq_range));
}

static void smb2_calculate_credits(const struct smbd_smb2_request *inreq,
				struct smbd_smb2_request *outreq)
{
	int count, idx;
	uint16_t total_credits = 0;

	count = outreq->out.vector_count;

	for (idx=1; idx < count; idx += SMBD_SMB2_NUM_IOV_PER_REQ) {
		struct iovec *inhdr_v = SMBD_SMB2_IDX_HDR_IOV(inreq,in,idx);
		struct iovec *outhdr_v = SMBD_SMB2_IDX_HDR_IOV(outreq,out,idx);
		uint8_t *outhdr = (uint8_t *)outhdr_v->iov_base;

		smb2_set_operation_credit(outreq->xconn, inhdr_v, outhdr_v);

		/* To match Windows, count up what we
		   just granted. */
		total_credits += SVAL(outhdr, SMB2_HDR_CREDIT);
		/* Set to zero in all but the last reply. */
		if (idx + SMBD_SMB2_NUM_IOV_PER_REQ < count) {
			SSVAL(outhdr, SMB2_HDR_CREDIT, 0);
		} else {
			SSVAL(outhdr, SMB2_HDR_CREDIT, total_credits);
		}
	}
}

DATA_BLOB smbd_smb2_generate_outbody(struct smbd_smb2_request *req, size_t size)
{
	if (req->current_idx <= 1) {
		if (size <= sizeof(req->out._body)) {
			return data_blob_const(req->out._body, size);
		}
	}

	return data_blob_talloc(req, NULL, size);
}

static NTSTATUS smbd_smb2_request_setup_out(struct smbd_smb2_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;
	TALLOC_CTX *mem_ctx;
	struct iovec *vector;
	int count;
	int idx;

	count = req->in.vector_count;
	if (count <= ARRAY_SIZE(req->out._vector)) {
		mem_ctx = req;
		vector = req->out._vector;
	} else {
		vector = talloc_zero_array(req, struct iovec, count);
		if (vector == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		mem_ctx = vector;
	}

	vector[0].iov_base	= req->out.nbt_hdr;
	vector[0].iov_len	= 4;
	SIVAL(req->out.nbt_hdr, 0, 0);

	for (idx=1; idx < count; idx += SMBD_SMB2_NUM_IOV_PER_REQ) {
		struct iovec *inhdr_v = SMBD_SMB2_IDX_HDR_IOV(req,in,idx);
		const uint8_t *inhdr = (const uint8_t *)inhdr_v->iov_base;
		uint8_t *outhdr = NULL;
		uint8_t *outbody = NULL;
		uint32_t next_command_ofs = 0;
		struct iovec *current = &vector[idx];

		if ((idx + SMBD_SMB2_NUM_IOV_PER_REQ) < count) {
			/* we have a next command -
			 * setup for the error case. */
			next_command_ofs = SMB2_HDR_BODY + 9;
		}

		if (idx == 1) {
			outhdr = req->out._hdr;
		} else {
			outhdr = talloc_zero_array(mem_ctx, uint8_t,
						   OUTVEC_ALLOC_SIZE);
			if (outhdr == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		}

		outbody = outhdr + SMB2_HDR_BODY;

		/*
		 * SMBD_SMB2_TF_IOV_OFS might be used later
		 */
		current[SMBD_SMB2_TF_IOV_OFS].iov_base   = NULL;
		current[SMBD_SMB2_TF_IOV_OFS].iov_len    = 0;

		current[SMBD_SMB2_HDR_IOV_OFS].iov_base  = (void *)outhdr;
		current[SMBD_SMB2_HDR_IOV_OFS].iov_len   = SMB2_HDR_BODY;

		current[SMBD_SMB2_BODY_IOV_OFS].iov_base = (void *)outbody;
		current[SMBD_SMB2_BODY_IOV_OFS].iov_len  = 8;

		current[SMBD_SMB2_DYN_IOV_OFS].iov_base  = NULL;
		current[SMBD_SMB2_DYN_IOV_OFS].iov_len   = 0;

		/* setup the SMB2 header */
		SIVAL(outhdr, SMB2_HDR_PROTOCOL_ID,	SMB2_MAGIC);
		SSVAL(outhdr, SMB2_HDR_LENGTH,		SMB2_HDR_BODY);
		SSVAL(outhdr, SMB2_HDR_CREDIT_CHARGE,
		      SVAL(inhdr, SMB2_HDR_CREDIT_CHARGE));
		SIVAL(outhdr, SMB2_HDR_STATUS,
		      NT_STATUS_V(NT_STATUS_INTERNAL_ERROR));
		SSVAL(outhdr, SMB2_HDR_OPCODE,
		      SVAL(inhdr, SMB2_HDR_OPCODE));
		SIVAL(outhdr, SMB2_HDR_FLAGS,
		      IVAL(inhdr, SMB2_HDR_FLAGS) | SMB2_HDR_FLAG_REDIRECT);
		SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND,	next_command_ofs);
		SBVAL(outhdr, SMB2_HDR_MESSAGE_ID,
		      BVAL(inhdr, SMB2_HDR_MESSAGE_ID));
		SIVAL(outhdr, SMB2_HDR_PID,
		      IVAL(inhdr, SMB2_HDR_PID));
		SIVAL(outhdr, SMB2_HDR_TID,
		      IVAL(inhdr, SMB2_HDR_TID));
		SBVAL(outhdr, SMB2_HDR_SESSION_ID,
		      BVAL(inhdr, SMB2_HDR_SESSION_ID));
		memcpy(outhdr + SMB2_HDR_SIGNATURE,
		       inhdr + SMB2_HDR_SIGNATURE, 16);

		/* setup error body header */
		SSVAL(outbody, 0x00, 0x08 + 1);
		SSVAL(outbody, 0x02, 0);
		SIVAL(outbody, 0x04, 0);
	}

	req->out.vector = vector;
	req->out.vector_count = count;

	/* setup the length of the NBT packet */
	smb2_setup_nbt_length(req->out.vector, req->out.vector_count);

	DLIST_ADD_END(xconn->smb2.requests, req, struct smbd_smb2_request *);

	return NT_STATUS_OK;
}

void smbd_server_connection_terminate_ex(struct smbXsrv_connection *xconn,
					 const char *reason,
					 const char *location)
{
	DEBUG(10,("smbd_server_connection_terminate_ex: reason[%s] at %s\n",
		  reason, location));
	exit_server_cleanly(reason);
}

static bool dup_smb2_vec4(TALLOC_CTX *ctx,
			struct iovec *outvec,
			const struct iovec *srcvec)
{
	const uint8_t *srctf;
	size_t srctf_len;
	const uint8_t *srchdr;
	size_t srchdr_len;
	const uint8_t *srcbody;
	size_t srcbody_len;
	const uint8_t *expected_srcbody;
	const uint8_t *srcdyn;
	size_t srcdyn_len;
	const uint8_t *expected_srcdyn;
	uint8_t *dsttf;
	uint8_t *dsthdr;
	uint8_t *dstbody;
	uint8_t *dstdyn;

	srctf  = (const uint8_t *)srcvec[SMBD_SMB2_TF_IOV_OFS].iov_base;
	srctf_len = srcvec[SMBD_SMB2_TF_IOV_OFS].iov_len;
	srchdr  = (const uint8_t *)srcvec[SMBD_SMB2_HDR_IOV_OFS].iov_base;
	srchdr_len = srcvec[SMBD_SMB2_HDR_IOV_OFS].iov_len;
	srcbody = (const uint8_t *)srcvec[SMBD_SMB2_BODY_IOV_OFS].iov_base;
	srcbody_len = srcvec[SMBD_SMB2_BODY_IOV_OFS].iov_len;
	expected_srcbody = srchdr + SMB2_HDR_BODY;
	srcdyn  = (const uint8_t *)srcvec[SMBD_SMB2_DYN_IOV_OFS].iov_base;
	srcdyn_len = srcvec[SMBD_SMB2_DYN_IOV_OFS].iov_len;
	expected_srcdyn = srcbody + 8;

	if ((srctf_len != SMB2_TF_HDR_SIZE) && (srctf_len != 0)) {
		return false;
	}

	if (srchdr_len != SMB2_HDR_BODY) {
		return false;
	}

	if (srctf_len == SMB2_TF_HDR_SIZE) {
		dsttf = talloc_memdup(ctx, srctf, SMB2_TF_HDR_SIZE);
		if (dsttf == NULL) {
			return false;
		}
	} else {
		dsttf = NULL;
	}
	outvec[SMBD_SMB2_TF_IOV_OFS].iov_base = (void *)dsttf;
	outvec[SMBD_SMB2_TF_IOV_OFS].iov_len = srctf_len;

	/* vec[SMBD_SMB2_HDR_IOV_OFS] is always boilerplate and must
	 * be allocated with size OUTVEC_ALLOC_SIZE. */

	dsthdr = talloc_memdup(ctx, srchdr, OUTVEC_ALLOC_SIZE);
	if (dsthdr == NULL) {
		return false;
	}
	outvec[SMBD_SMB2_HDR_IOV_OFS].iov_base = (void *)dsthdr;
	outvec[SMBD_SMB2_HDR_IOV_OFS].iov_len = SMB2_HDR_BODY;

	/*
	 * If this is a "standard" vec[SMBD_SMB2_BOFY_IOV_OFS] of length 8,
	 * pointing to srcvec[SMBD_SMB2_HDR_IOV_OFS].iov_base + SMB2_HDR_BODY,
	 * then duplicate this. Else use talloc_memdup().
	 */

	if ((srcbody == expected_srcbody) && (srcbody_len == 8)) {
		dstbody = dsthdr + SMB2_HDR_BODY;
	} else {
		dstbody = talloc_memdup(ctx, srcbody, srcbody_len);
		if (dstbody == NULL) {
			return false;
		}
	}
	outvec[SMBD_SMB2_BODY_IOV_OFS].iov_base = (void *)dstbody;
	outvec[SMBD_SMB2_BODY_IOV_OFS].iov_len = srcbody_len;

	/*
	 * If this is a "standard" vec[SMBD_SMB2_DYN_IOV_OFS] of length 1,
	 * pointing to
	 * srcvec[SMBD_SMB2_HDR_IOV_OFS].iov_base + 8
	 * then duplicate this. Else use talloc_memdup().
	 */

	if ((srcdyn == expected_srcdyn) && (srcdyn_len == 1)) {
		dstdyn = dsthdr + SMB2_HDR_BODY + 8;
	} else if (srcdyn == NULL) {
		dstdyn = NULL;
	} else {
		dstdyn = talloc_memdup(ctx, srcdyn, srcdyn_len);
		if (dstdyn == NULL) {
			return false;
		}
	}
	outvec[SMBD_SMB2_DYN_IOV_OFS].iov_base = (void *)dstdyn;
	outvec[SMBD_SMB2_DYN_IOV_OFS].iov_len = srcdyn_len;

	return true;
}

static struct smbd_smb2_request *dup_smb2_req(const struct smbd_smb2_request *req)
{
	struct smbd_smb2_request *newreq = NULL;
	struct iovec *outvec = NULL;
	int count = req->out.vector_count;
	int i;

	newreq = smbd_smb2_request_allocate(req->xconn);
	if (!newreq) {
		return NULL;
	}

	newreq->sconn = req->sconn;
	newreq->xconn = req->xconn;
	newreq->session = req->session;
	newreq->do_encryption = req->do_encryption;
	newreq->do_signing = req->do_signing;
	newreq->current_idx = req->current_idx;

	outvec = talloc_zero_array(newreq, struct iovec, count);
	if (!outvec) {
		TALLOC_FREE(newreq);
		return NULL;
	}
	newreq->out.vector = outvec;
	newreq->out.vector_count = count;

	/* Setup the outvec's identically to req. */
	outvec[0].iov_base = newreq->out.nbt_hdr;
	outvec[0].iov_len = 4;
	memcpy(newreq->out.nbt_hdr, req->out.nbt_hdr, 4);

	/* Setup the vectors identically to the ones in req. */
	for (i = 1; i < count; i += SMBD_SMB2_NUM_IOV_PER_REQ) {
		if (!dup_smb2_vec4(outvec, &outvec[i], &req->out.vector[i])) {
			break;
		}
	}

	if (i < count) {
		/* Alloc failed. */
		TALLOC_FREE(newreq);
		return NULL;
	}

	smb2_setup_nbt_length(newreq->out.vector,
		newreq->out.vector_count);

	return newreq;
}

static NTSTATUS smb2_send_async_interim_response(const struct smbd_smb2_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;
	int first_idx = 1;
	struct iovec *firsttf = NULL;
	struct iovec *outhdr_v = NULL;
	uint8_t *outhdr = NULL;
	struct smbd_smb2_request *nreq = NULL;
	NTSTATUS status;

	/* Create a new smb2 request we'll use
	   for the interim return. */
	nreq = dup_smb2_req(req);
	if (!nreq) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Lose the last X out vectors. They're the
	   ones we'll be using for the async reply. */
	nreq->out.vector_count -= SMBD_SMB2_NUM_IOV_PER_REQ;

	smb2_setup_nbt_length(nreq->out.vector,
		nreq->out.vector_count);

	/* Step back to the previous reply. */
	nreq->current_idx -= SMBD_SMB2_NUM_IOV_PER_REQ;
	firsttf = SMBD_SMB2_IDX_TF_IOV(nreq,out,first_idx);
	outhdr_v = SMBD_SMB2_OUT_HDR_IOV(nreq);
	outhdr = SMBD_SMB2_OUT_HDR_PTR(nreq);
	/* And end the chain. */
	SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND, 0);

	/* Calculate outgoing credits */
	smb2_calculate_credits(req, nreq);

	if (DEBUGLEVEL >= 10) {
		dbgtext("smb2_send_async_interim_response: nreq->current_idx = %u\n",
			(unsigned int)nreq->current_idx );
		dbgtext("smb2_send_async_interim_response: returning %u vectors\n",
			(unsigned int)nreq->out.vector_count );
		print_req_vectors(nreq);
	}

	/*
	 * As we have changed the header (SMB2_HDR_NEXT_COMMAND),
	 * we need to sign/encrypt here with the last/first key we remembered
	 */
	if (firsttf->iov_len == SMB2_TF_HDR_SIZE) {
		status = smb2_signing_encrypt_pdu(req->first_key,
					xconn->protocol,
					firsttf,
					nreq->out.vector_count - first_idx);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else if (req->last_key.length > 0) {
		status = smb2_signing_sign_pdu(req->last_key,
					       xconn->protocol,
					       outhdr_v,
					       SMBD_SMB2_NUM_IOV_PER_REQ - 1);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	nreq->queue_entry.mem_ctx = nreq;
	nreq->queue_entry.vector = nreq->out.vector;
	nreq->queue_entry.count = nreq->out.vector_count;
	DLIST_ADD_END(xconn->smb2.send_queue, &nreq->queue_entry, NULL);
	xconn->smb2.send_queue_len++;

	status = smbd_smb2_flush_send_queue(xconn);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

struct smbd_smb2_request_pending_state {
	struct smbd_smb2_send_queue queue_entry;
        uint8_t buf[NBT_HDR_SIZE + SMB2_TF_HDR_SIZE + SMB2_HDR_BODY + 0x08 + 1];
        struct iovec vector[1 + SMBD_SMB2_NUM_IOV_PER_REQ];
};

static void smbd_smb2_request_pending_timer(struct tevent_context *ev,
					    struct tevent_timer *te,
					    struct timeval current_time,
					    void *private_data);

NTSTATUS smbd_smb2_request_pending_queue(struct smbd_smb2_request *req,
					 struct tevent_req *subreq,
					 uint32_t defer_time)
{
	NTSTATUS status;
	struct timeval defer_endtime;
	uint8_t *outhdr = NULL;
	uint32_t flags;

	if (!tevent_req_is_in_progress(subreq)) {
		/*
		 * This is a performance optimization,
		 * it avoids one tevent_loop iteration,
		 * which means we avoid one
		 * talloc_stackframe_pool/talloc_free pair.
		 */
		tevent_req_notify_callback(subreq);
		return NT_STATUS_OK;
	}

	req->subreq = subreq;
	subreq = NULL;

	if (req->async_te) {
		/* We're already async. */
		return NT_STATUS_OK;
	}

	outhdr = SMBD_SMB2_OUT_HDR_PTR(req);
	flags = IVAL(outhdr, SMB2_HDR_FLAGS);
	if (flags & SMB2_HDR_FLAG_ASYNC) {
		/* We're already async. */
		return NT_STATUS_OK;
	}

	if (req->in.vector_count > req->current_idx + SMBD_SMB2_NUM_IOV_PER_REQ) {
		/*
		 * We're trying to go async in a compound request
		 * chain. This is only allowed for opens that cause an
		 * oplock break or for the last operation in the
		 * chain, otherwise it is not allowed. See
		 * [MS-SMB2].pdf note <206> on Section 3.3.5.2.7.
		 */
		const uint8_t *inhdr = SMBD_SMB2_IN_HDR_PTR(req);

		if (SVAL(inhdr, SMB2_HDR_OPCODE) != SMB2_OP_CREATE) {
			/*
			 * Cancel the outstanding request.
			 */
			bool ok = tevent_req_cancel(req->subreq);
			if (ok) {
				return NT_STATUS_OK;
			}
			TALLOC_FREE(req->subreq);
			return smbd_smb2_request_error(req,
				NT_STATUS_INTERNAL_ERROR);
		}
	}

	if (DEBUGLEVEL >= 10) {
		dbgtext("smbd_smb2_request_pending_queue: req->current_idx = %u\n",
			(unsigned int)req->current_idx );
		print_req_vectors(req);
	}

	if (req->current_idx > 1) {
		/*
		 * We're going async in a compound
		 * chain after the first request has
		 * already been processed. Send an
		 * interim response containing the
		 * set of replies already generated.
		 */
		int idx = req->current_idx;

		status = smb2_send_async_interim_response(req);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		if (req->first_key.length > 0) {
			data_blob_clear_free(&req->first_key);
		}

		req->current_idx = 1;

		/*
		 * Re-arrange the in.vectors to remove what
		 * we just sent.
		 */
		memmove(&req->in.vector[1],
			&req->in.vector[idx],
			sizeof(req->in.vector[0])*(req->in.vector_count - idx));
		req->in.vector_count = 1 + (req->in.vector_count - idx);

		/* Re-arrange the out.vectors to match. */
		memmove(&req->out.vector[1],
			&req->out.vector[idx],
			sizeof(req->out.vector[0])*(req->out.vector_count - idx));
		req->out.vector_count = 1 + (req->out.vector_count - idx);

		if (req->in.vector_count == 1 + SMBD_SMB2_NUM_IOV_PER_REQ) {
			/*
			 * We only have one remaining request as
			 * we've processed everything else.
			 * This is no longer a compound request.
			 */
			req->compound_related = false;
			outhdr = SMBD_SMB2_OUT_HDR_PTR(req);
			flags = (IVAL(outhdr, SMB2_HDR_FLAGS) & ~SMB2_HDR_FLAG_CHAINED);
			SIVAL(outhdr, SMB2_HDR_FLAGS, flags);
		}
	}
	if (req->last_key.length > 0) {
		data_blob_clear_free(&req->last_key);
	}

	defer_endtime = timeval_current_ofs_usec(defer_time);
	req->async_te = tevent_add_timer(req->sconn->ev_ctx,
					 req, defer_endtime,
					 smbd_smb2_request_pending_timer,
					 req);
	if (req->async_te == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static DATA_BLOB smbd_smb2_signing_key(struct smbXsrv_session *session,
				       struct smbXsrv_connection *xconn)
{
	struct smbXsrv_channel_global0 *c = NULL;
	NTSTATUS status;
	DATA_BLOB key = data_blob_null;

	status = smbXsrv_session_find_channel(session, xconn, &c);
	if (NT_STATUS_IS_OK(status)) {
		key = c->signing_key;
	}

	if (key.length == 0) {
		key = session->global->signing_key;
	}

	return key;
}

static void smbd_smb2_request_pending_timer(struct tevent_context *ev,
					    struct tevent_timer *te,
					    struct timeval current_time,
					    void *private_data)
{
	struct smbd_smb2_request *req =
		talloc_get_type_abort(private_data,
		struct smbd_smb2_request);
	struct smbXsrv_connection *xconn = req->xconn;
	struct smbd_smb2_request_pending_state *state = NULL;
	uint8_t *outhdr = NULL;
	const uint8_t *inhdr = NULL;
	uint8_t *tf = NULL;
	size_t tf_len = 0;
	uint8_t *hdr = NULL;
	uint8_t *body = NULL;
	uint8_t *dyn = NULL;
	uint32_t flags = 0;
	uint64_t session_id = 0;
	uint64_t message_id = 0;
	uint64_t nonce_high = 0;
	uint64_t nonce_low = 0;
	uint64_t async_id = 0;
	NTSTATUS status;

	TALLOC_FREE(req->async_te);

	/* Ensure our final reply matches the interim one. */
	inhdr = SMBD_SMB2_IN_HDR_PTR(req);
	outhdr = SMBD_SMB2_OUT_HDR_PTR(req);
	flags = IVAL(outhdr, SMB2_HDR_FLAGS);
	message_id = BVAL(outhdr, SMB2_HDR_MESSAGE_ID);
	session_id = BVAL(outhdr, SMB2_HDR_SESSION_ID);

	async_id = message_id; /* keep it simple for now... */

	SIVAL(outhdr, SMB2_HDR_FLAGS, flags | SMB2_HDR_FLAG_ASYNC);
	SBVAL(outhdr, SMB2_HDR_ASYNC_ID, async_id);

	DEBUG(10,("smbd_smb2_request_pending_queue: opcode[%s] mid %llu "
		"going async\n",
		smb2_opcode_name(SVAL(inhdr, SMB2_HDR_OPCODE)),
		(unsigned long long)async_id ));

	/*
	 * What we send is identical to a smbd_smb2_request_error
	 * packet with an error status of STATUS_PENDING. Make use
	 * of this fact sometime when refactoring. JRA.
	 */

	state = talloc_zero(req->xconn, struct smbd_smb2_request_pending_state);
	if (state == NULL) {
		smbd_server_connection_terminate(xconn,
						 nt_errstr(NT_STATUS_NO_MEMORY));
		return;
	}

	tf = state->buf + NBT_HDR_SIZE;
	tf_len = SMB2_TF_HDR_SIZE;

	hdr = tf + SMB2_TF_HDR_SIZE;
	body = hdr + SMB2_HDR_BODY;
	dyn = body + 8;

	if (req->do_encryption) {
		struct smbXsrv_session *x = req->session;

		nonce_high = x->nonce_high;
		nonce_low = x->nonce_low;

		x->nonce_low += 1;
		if (x->nonce_low == 0) {
			x->nonce_low += 1;
			x->nonce_high += 1;
		}
	}

	SIVAL(tf, SMB2_TF_PROTOCOL_ID, SMB2_TF_MAGIC);
	SBVAL(tf, SMB2_TF_NONCE+0, nonce_low);
	SBVAL(tf, SMB2_TF_NONCE+8, nonce_high);
	SBVAL(tf, SMB2_TF_SESSION_ID, session_id);

	SIVAL(hdr, SMB2_HDR_PROTOCOL_ID, SMB2_MAGIC);
	SSVAL(hdr, SMB2_HDR_LENGTH, SMB2_HDR_BODY);
	SSVAL(hdr, SMB2_HDR_EPOCH, 0);
	SIVAL(hdr, SMB2_HDR_STATUS, NT_STATUS_V(STATUS_PENDING));
	SSVAL(hdr, SMB2_HDR_OPCODE, SVAL(outhdr, SMB2_HDR_OPCODE));

	SIVAL(hdr, SMB2_HDR_FLAGS, flags);
	SIVAL(hdr, SMB2_HDR_NEXT_COMMAND, 0);
	SBVAL(hdr, SMB2_HDR_MESSAGE_ID, message_id);
	SBVAL(hdr, SMB2_HDR_PID, async_id);
	SBVAL(hdr, SMB2_HDR_SESSION_ID,
		BVAL(outhdr, SMB2_HDR_SESSION_ID));
	memcpy(hdr+SMB2_HDR_SIGNATURE,
	       outhdr+SMB2_HDR_SIGNATURE, 16);

	SSVAL(body, 0x00, 0x08 + 1);

	SCVAL(body, 0x02, 0);
	SCVAL(body, 0x03, 0);
	SIVAL(body, 0x04, 0);
	/* Match W2K8R2... */
	SCVAL(dyn,  0x00, 0x21);

	state->vector[0].iov_base = (void *)state->buf;
	state->vector[0].iov_len = NBT_HDR_SIZE;

	if (req->do_encryption) {
		state->vector[1+SMBD_SMB2_TF_IOV_OFS].iov_base   = tf;
		state->vector[1+SMBD_SMB2_TF_IOV_OFS].iov_len    = tf_len;
	} else {
		state->vector[1+SMBD_SMB2_TF_IOV_OFS].iov_base   = NULL;
		state->vector[1+SMBD_SMB2_TF_IOV_OFS].iov_len    = 0;
	}

	state->vector[1+SMBD_SMB2_HDR_IOV_OFS].iov_base  = hdr;
	state->vector[1+SMBD_SMB2_HDR_IOV_OFS].iov_len   = SMB2_HDR_BODY;

	state->vector[1+SMBD_SMB2_BODY_IOV_OFS].iov_base = body;
	state->vector[1+SMBD_SMB2_BODY_IOV_OFS].iov_len  = 8;

	state->vector[1+SMBD_SMB2_DYN_IOV_OFS].iov_base  = dyn;
	state->vector[1+SMBD_SMB2_DYN_IOV_OFS].iov_len   = 1;

	smb2_setup_nbt_length(state->vector, 1 + SMBD_SMB2_NUM_IOV_PER_REQ);

	/* Ensure we correctly go through crediting. Grant
	   the credits now, and zero credits on the final
	   response. */
	smb2_set_operation_credit(req->xconn,
			SMBD_SMB2_IN_HDR_IOV(req),
			&state->vector[1+SMBD_SMB2_HDR_IOV_OFS]);

	SIVAL(hdr, SMB2_HDR_FLAGS, flags | SMB2_HDR_FLAG_ASYNC);

	if (DEBUGLVL(10)) {
		int i;

		for (i = 0; i < ARRAY_SIZE(state->vector); i++) {
			dbgtext("\tstate->vector[%u/%u].iov_len = %u\n",
				(unsigned int)i,
				(unsigned int)ARRAY_SIZE(state->vector),
				(unsigned int)state->vector[i].iov_len);
		}
	}

	if (req->do_encryption) {
		struct smbXsrv_session *x = req->session;
		DATA_BLOB encryption_key = x->global->encryption_key;

		status = smb2_signing_encrypt_pdu(encryption_key,
					xconn->protocol,
					&state->vector[1+SMBD_SMB2_TF_IOV_OFS],
					SMBD_SMB2_NUM_IOV_PER_REQ);
		if (!NT_STATUS_IS_OK(status)) {
			smbd_server_connection_terminate(xconn,
						nt_errstr(status));
			return;
		}
	} else if (req->do_signing) {
		struct smbXsrv_session *x = req->session;
		DATA_BLOB signing_key = smbd_smb2_signing_key(x, xconn);

		status = smb2_signing_sign_pdu(signing_key,
					xconn->protocol,
					&state->vector[1+SMBD_SMB2_HDR_IOV_OFS],
					SMBD_SMB2_NUM_IOV_PER_REQ - 1);
		if (!NT_STATUS_IS_OK(status)) {
			smbd_server_connection_terminate(xconn,
						nt_errstr(status));
			return;
		}
	}

	state->queue_entry.mem_ctx = state;
	state->queue_entry.vector = state->vector;
	state->queue_entry.count = ARRAY_SIZE(state->vector);
	DLIST_ADD_END(xconn->smb2.send_queue, &state->queue_entry, NULL);
	xconn->smb2.send_queue_len++;

	status = smbd_smb2_flush_send_queue(xconn);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn,
						 nt_errstr(status));
		return;
	}
}

static NTSTATUS smbd_smb2_request_process_cancel(struct smbd_smb2_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;
	struct smbd_smb2_request *cur;
	const uint8_t *inhdr;
	uint32_t flags;
	uint64_t search_message_id;
	uint64_t search_async_id;
	uint64_t found_id;

	inhdr = SMBD_SMB2_IN_HDR_PTR(req);

	flags = IVAL(inhdr, SMB2_HDR_FLAGS);
	search_message_id = BVAL(inhdr, SMB2_HDR_MESSAGE_ID);
	search_async_id = BVAL(inhdr, SMB2_HDR_PID);

	/*
	 * we don't need the request anymore
	 * cancel requests never have a response
	 */
	DLIST_REMOVE(xconn->smb2.requests, req);
	TALLOC_FREE(req);

	for (cur = xconn->smb2.requests; cur; cur = cur->next) {
		const uint8_t *outhdr;
		uint64_t message_id;
		uint64_t async_id;

		if (cur->compound_related) {
			/*
			 * Never cancel anything in a compound request.
			 * Way too hard to deal with the result.
			 */
			continue;
		}

		outhdr = SMBD_SMB2_OUT_HDR_PTR(cur);

		message_id = BVAL(outhdr, SMB2_HDR_MESSAGE_ID);
		async_id = BVAL(outhdr, SMB2_HDR_PID);

		if (flags & SMB2_HDR_FLAG_ASYNC) {
			if (search_async_id == async_id) {
				found_id = async_id;
				break;
			}
		} else {
			if (search_message_id == message_id) {
				found_id = message_id;
				break;
			}
		}
	}

	if (cur && cur->subreq) {
		inhdr = SMBD_SMB2_IN_HDR_PTR(cur);
		DEBUG(10,("smbd_smb2_request_process_cancel: attempting to "
			"cancel opcode[%s] mid %llu\n",
			smb2_opcode_name(SVAL(inhdr, SMB2_HDR_OPCODE)),
                        (unsigned long long)found_id ));
		tevent_req_cancel(cur->subreq);
	}

	return NT_STATUS_OK;
}

/*************************************************************
 Ensure an incoming tid is a valid one for us to access.
 Change to the associated uid credentials and chdir to the
 valid tid directory.
*************************************************************/

static NTSTATUS smbd_smb2_request_check_tcon(struct smbd_smb2_request *req)
{
	const uint8_t *inhdr;
	uint32_t in_flags;
	uint32_t in_tid;
	struct smbXsrv_tcon *tcon;
	NTSTATUS status;
	NTTIME now = timeval_to_nttime(&req->request_time);

	req->tcon = NULL;

	inhdr = SMBD_SMB2_IN_HDR_PTR(req);

	in_flags = IVAL(inhdr, SMB2_HDR_FLAGS);
	in_tid = IVAL(inhdr, SMB2_HDR_TID);

	if (in_flags & SMB2_HDR_FLAG_CHAINED) {
		in_tid = req->last_tid;
	}

	req->last_tid = 0;

	status = smb2srv_tcon_lookup(req->session,
				     in_tid, now, &tcon);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!change_to_user(tcon->compat, req->session->compat->vuid)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	/* should we pass FLAG_CASELESS_PATHNAMES here? */
	if (!set_current_service(tcon->compat, 0, true)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	req->tcon = tcon;
	req->last_tid = in_tid;

	return NT_STATUS_OK;
}

/*************************************************************
 Ensure an incoming session_id is a valid one for us to access.
*************************************************************/

static NTSTATUS smbd_smb2_request_check_session(struct smbd_smb2_request *req)
{
	const uint8_t *inhdr;
	uint32_t in_flags;
	uint16_t in_opcode;
	uint64_t in_session_id;
	struct smbXsrv_session *session = NULL;
	struct auth_session_info *session_info;
	NTSTATUS status;
	NTTIME now = timeval_to_nttime(&req->request_time);

	req->session = NULL;
	req->tcon = NULL;

	inhdr = SMBD_SMB2_IN_HDR_PTR(req);

	in_flags = IVAL(inhdr, SMB2_HDR_FLAGS);
	in_opcode = SVAL(inhdr, SMB2_HDR_OPCODE);
	in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);

	if (in_flags & SMB2_HDR_FLAG_CHAINED) {
		in_session_id = req->last_session_id;
	}

	req->last_session_id = 0;

	/* lookup an existing session */
	status = smb2srv_session_lookup(req->xconn,
					in_session_id, now,
					&session);
	if (session) {
		req->session = session;
		req->last_session_id = in_session_id;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_SESSION_EXPIRED)) {
		switch (in_opcode) {
		case SMB2_OP_SESSSETUP:
			status = NT_STATUS_OK;
			break;
		default:
			break;
		}
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		switch (in_opcode) {
		case SMB2_OP_TCON:
		case SMB2_OP_CREATE:
		case SMB2_OP_GETINFO:
		case SMB2_OP_SETINFO:
			return NT_STATUS_INVALID_HANDLE;
		default:
			/*
			 * Notice the check for
			 * (session_info == NULL)
			 * below.
			 */
			status = NT_STATUS_OK;
			break;
		}
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	session_info = session->global->auth_session_info;
	if (session_info == NULL) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if (in_session_id != req->xconn->client->last_session_id) {
		req->xconn->client->last_session_id = in_session_id;
		set_current_user_info(session_info->unix_info->sanitized_username,
				      session_info->unix_info->unix_name,
				      session_info->info->domain_name);
	}

	return NT_STATUS_OK;
}

NTSTATUS smbd_smb2_request_verify_creditcharge(struct smbd_smb2_request *req,
						uint32_t data_length)
{
	struct smbXsrv_connection *xconn = req->xconn;
	uint16_t needed_charge;
	uint16_t credit_charge = 1;
	const uint8_t *inhdr;

	inhdr = SMBD_SMB2_IN_HDR_PTR(req);

	if (xconn->smb2.credits.multicredit) {
		credit_charge = SVAL(inhdr, SMB2_HDR_CREDIT_CHARGE);
		credit_charge = MAX(credit_charge, 1);
	}

	needed_charge = (data_length - 1)/ 65536 + 1;

	DEBUG(10, ("mid %llu, CreditCharge: %d, NeededCharge: %d\n",
		   (unsigned long long) BVAL(inhdr, SMB2_HDR_MESSAGE_ID),
		   credit_charge, needed_charge));

	if (needed_charge > credit_charge) {
		DEBUG(2, ("CreditCharge too low, given %d, needed %d\n",
			  credit_charge, needed_charge));
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

NTSTATUS smbd_smb2_request_verify_sizes(struct smbd_smb2_request *req,
					size_t expected_body_size)
{
	struct iovec *inhdr_v;
	const uint8_t *inhdr;
	uint16_t opcode;
	const uint8_t *inbody;
	size_t body_size;
	size_t min_dyn_size = expected_body_size & 0x00000001;
	int max_idx = req->in.vector_count - SMBD_SMB2_NUM_IOV_PER_REQ;

	/*
	 * The following should be checked already.
	 */
	if (req->in.vector_count < SMBD_SMB2_NUM_IOV_PER_REQ) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	if (req->current_idx > max_idx) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	inhdr_v = SMBD_SMB2_IN_HDR_IOV(req);
	if (inhdr_v->iov_len != SMB2_HDR_BODY) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	if (SMBD_SMB2_IN_BODY_LEN(req) < 2) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	inhdr = SMBD_SMB2_IN_HDR_PTR(req);
	opcode = SVAL(inhdr, SMB2_HDR_OPCODE);

	switch (opcode) {
	case SMB2_OP_IOCTL:
	case SMB2_OP_GETINFO:
		min_dyn_size = 0;
		break;
	case SMB2_OP_WRITE:
		if (req->smb1req != NULL && req->smb1req->unread_bytes > 0) {
			if (req->smb1req->unread_bytes < min_dyn_size) {
				return NT_STATUS_INVALID_PARAMETER;
			}

			min_dyn_size = 0;
		}
		break;
	}

	/*
	 * Now check the expected body size,
	 * where the last byte might be in the
	 * dynamic section..
	 */
	if (SMBD_SMB2_IN_BODY_LEN(req) != (expected_body_size & 0xFFFFFFFE)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (SMBD_SMB2_IN_DYN_LEN(req) < min_dyn_size) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	body_size = SVAL(inbody, 0x00);
	if (body_size != expected_body_size) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

NTSTATUS smbd_smb2_request_dispatch(struct smbd_smb2_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;
	const struct smbd_smb2_dispatch_table *call = NULL;
	const struct iovec *intf_v = SMBD_SMB2_IN_TF_IOV(req);
	const uint8_t *inhdr;
	uint16_t opcode;
	uint32_t flags;
	uint64_t mid;
	NTSTATUS status;
	NTSTATUS session_status;
	uint32_t allowed_flags;
	NTSTATUS return_value;
	struct smbXsrv_session *x = NULL;
	bool signing_required = false;
	bool encryption_required = false;

	inhdr = SMBD_SMB2_IN_HDR_PTR(req);

	/* TODO: verify more things */

	flags = IVAL(inhdr, SMB2_HDR_FLAGS);
	opcode = SVAL(inhdr, SMB2_HDR_OPCODE);
	mid = BVAL(inhdr, SMB2_HDR_MESSAGE_ID);
	DEBUG(10,("smbd_smb2_request_dispatch: opcode[%s] mid = %llu\n",
		smb2_opcode_name(opcode),
		(unsigned long long)mid));

	if (xconn->protocol >= PROTOCOL_SMB2_02) {
		/*
		 * once the protocol is negotiated
		 * SMB2_OP_NEGPROT is not allowed anymore
		 */
		if (opcode == SMB2_OP_NEGPROT) {
			/* drop the connection */
			return NT_STATUS_INVALID_PARAMETER;
		}
	} else {
		/*
		 * if the protocol is not negotiated yet
		 * only SMB2_OP_NEGPROT is allowed.
		 */
		if (opcode != SMB2_OP_NEGPROT) {
			/* drop the connection */
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	/*
	 * Check if the client provided a valid session id,
	 * if so smbd_smb2_request_check_session() calls
	 * set_current_user_info().
	 *
	 * As some command don't require a valid session id
	 * we defer the check of the session_status
	 */
	session_status = smbd_smb2_request_check_session(req);
	x = req->session;
	if (x != NULL) {
		signing_required = x->global->signing_required;
		encryption_required = x->global->encryption_required;
	}

	req->do_signing = false;
	req->do_encryption = false;
	if (intf_v->iov_len == SMB2_TF_HDR_SIZE) {
		const uint8_t *intf = SMBD_SMB2_IN_TF_PTR(req);
		uint64_t tf_session_id = BVAL(intf, SMB2_TF_SESSION_ID);

		if (x != NULL && x->global->session_wire_id != tf_session_id) {
			DEBUG(0,("smbd_smb2_request_dispatch: invalid session_id"
				 "in SMB2_HDR[%llu], SMB2_TF[%llu]\n",
				 (unsigned long long)x->global->session_wire_id,
				 (unsigned long long)tf_session_id));
			/*
			 * TODO: windows allows this...
			 * should we drop the connection?
			 *
			 * For now we just return ACCESS_DENIED
			 * (Windows clients never trigger this)
			 * and wait for an update of [MS-SMB2].
			 */
			return smbd_smb2_request_error(req,
					NT_STATUS_ACCESS_DENIED);
		}

		req->do_encryption = true;
	}

	if (encryption_required && !req->do_encryption) {
		return smbd_smb2_request_error(req,
				NT_STATUS_ACCESS_DENIED);
	}

	call = smbd_smb2_call(opcode);
	if (call == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	allowed_flags = SMB2_HDR_FLAG_CHAINED |
			SMB2_HDR_FLAG_SIGNED |
			SMB2_HDR_FLAG_DFS;
	if (opcode == SMB2_OP_CANCEL) {
		allowed_flags |= SMB2_HDR_FLAG_ASYNC;
	}
	if ((flags & ~allowed_flags) != 0) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	if (flags & SMB2_HDR_FLAG_CHAINED) {
		/*
		 * This check is mostly for giving the correct error code
		 * for compounded requests.
		 */
		if (!NT_STATUS_IS_OK(session_status)) {
			return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
		}
	} else {
		req->compat_chain_fsp = NULL;
	}

	if (req->do_encryption) {
		signing_required = false;
	} else if (signing_required || (flags & SMB2_HDR_FLAG_SIGNED)) {
		DATA_BLOB signing_key = data_blob_null;

		if (x == NULL) {
			/*
			 * MS-SMB2: 3.3.5.2.4 Verifying the Signature.
			 * If the SMB2 header of the SMB2 NEGOTIATE
			 * request has the SMB2_FLAGS_SIGNED bit set in the
			 * Flags field, the server MUST fail the request
			 * with STATUS_INVALID_PARAMETER.
			 *
			 * Microsoft test tool checks this.
			 */

			if ((opcode == SMB2_OP_NEGPROT) &&
					(flags & SMB2_HDR_FLAG_SIGNED)) {
				status = NT_STATUS_INVALID_PARAMETER;
			} else {
				status = NT_STATUS_USER_SESSION_DELETED;
			}
			return smbd_smb2_request_error(req, status);
		}

		signing_key = smbd_smb2_signing_key(x, xconn);

		/*
		 * If we have a signing key, we should
		 * sign the response
		 */
		if (signing_key.length > 0) {
			req->do_signing = true;
		}

		status = smb2_signing_check_pdu(signing_key,
						xconn->protocol,
						SMBD_SMB2_IN_HDR_IOV(req),
						SMBD_SMB2_NUM_IOV_PER_REQ - 1);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}

		/*
		 * Now that we know the request was correctly signed
		 * we have to sign the response too.
		 */
		req->do_signing = true;

		if (!NT_STATUS_IS_OK(session_status)) {
			return smbd_smb2_request_error(req, session_status);
		}
	} else if (opcode == SMB2_OP_CANCEL) {
		/* Cancel requests are allowed to skip the signing */
	} else if (signing_required) {
		/*
		 * If signing is required we try to sign
		 * a possible error response
		 */
		req->do_signing = true;
		return smbd_smb2_request_error(req, NT_STATUS_ACCESS_DENIED);
	}

	if (flags & SMB2_HDR_FLAG_CHAINED) {
		req->compound_related = true;
	}

	if (call->need_session) {
		if (!NT_STATUS_IS_OK(session_status)) {
			return smbd_smb2_request_error(req, session_status);
		}
	}

	if (call->need_tcon) {
		SMB_ASSERT(call->need_session);

		/*
		 * This call needs to be run as user.
		 *
		 * smbd_smb2_request_check_tcon()
		 * calls change_to_user() on success.
		 */
		status = smbd_smb2_request_check_tcon(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		if (req->tcon->global->encryption_required) {
			encryption_required = true;
		}
		if (encryption_required && !req->do_encryption) {
			return smbd_smb2_request_error(req,
				NT_STATUS_ACCESS_DENIED);
		}
	}

	if (call->fileid_ofs != 0) {
		size_t needed = call->fileid_ofs + 16;
		const uint8_t *body = SMBD_SMB2_IN_BODY_PTR(req);
		size_t body_size = SMBD_SMB2_IN_BODY_LEN(req);
		uint64_t file_id_persistent;
		uint64_t file_id_volatile;
		struct files_struct *fsp;

		SMB_ASSERT(call->need_tcon);

		if (needed > body_size) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}

		file_id_persistent	= BVAL(body, call->fileid_ofs + 0);
		file_id_volatile	= BVAL(body, call->fileid_ofs + 8);

		fsp = file_fsp_smb2(req, file_id_persistent, file_id_volatile);
		if (fsp == NULL) {
			if (!call->allow_invalid_fileid) {
				return smbd_smb2_request_error(req,
						NT_STATUS_FILE_CLOSED);
			}

			if (file_id_persistent != UINT64_MAX) {
				return smbd_smb2_request_error(req,
						NT_STATUS_FILE_CLOSED);
			}
			if (file_id_volatile != UINT64_MAX) {
				return smbd_smb2_request_error(req,
						NT_STATUS_FILE_CLOSED);
			}
		}
	}

	if (call->as_root) {
		SMB_ASSERT(call->fileid_ofs == 0);
		/* This call needs to be run as root */
		change_to_root_user();
	} else {
		SMB_ASSERT(call->need_tcon);
	}

	switch (opcode) {
	case SMB2_OP_NEGPROT:
		{
			START_PROFILE(smb2_negprot);
			return_value = smbd_smb2_request_process_negprot(req);
			END_PROFILE(smb2_negprot);
		}
		break;

	case SMB2_OP_SESSSETUP:
		{
			START_PROFILE(smb2_sesssetup);
			return_value = smbd_smb2_request_process_sesssetup(req);
			END_PROFILE(smb2_sesssetup);
		}
		break;

	case SMB2_OP_LOGOFF:
		{
			START_PROFILE(smb2_logoff);
			return_value = smbd_smb2_request_process_logoff(req);
			END_PROFILE(smb2_logoff);
		}
		break;

	case SMB2_OP_TCON:
		{
			START_PROFILE(smb2_tcon);
			return_value = smbd_smb2_request_process_tcon(req);
			END_PROFILE(smb2_tcon);
		}
		break;

	case SMB2_OP_TDIS:
		{
			START_PROFILE(smb2_tdis);
			return_value = smbd_smb2_request_process_tdis(req);
			END_PROFILE(smb2_tdis);
		}
		break;

	case SMB2_OP_CREATE:
		{
			START_PROFILE(smb2_create);
			return_value = smbd_smb2_request_process_create(req);
			END_PROFILE(smb2_create);
		}
		break;

	case SMB2_OP_CLOSE:
		{
			START_PROFILE(smb2_close);
			return_value = smbd_smb2_request_process_close(req);
			END_PROFILE(smb2_close);
		}
		break;

	case SMB2_OP_FLUSH:
		{
			START_PROFILE(smb2_flush);
			return_value = smbd_smb2_request_process_flush(req);
			END_PROFILE(smb2_flush);
		}
		break;

	case SMB2_OP_READ:
		{
			START_PROFILE(smb2_read);
			return_value = smbd_smb2_request_process_read(req);
			END_PROFILE(smb2_read);
		}
		break;

	case SMB2_OP_WRITE:
		{
			START_PROFILE(smb2_write);
			return_value = smbd_smb2_request_process_write(req);
			END_PROFILE(smb2_write);
		}
		break;

	case SMB2_OP_LOCK:
		{
			START_PROFILE(smb2_lock);
			return_value = smbd_smb2_request_process_lock(req);
			END_PROFILE(smb2_lock);
		}
		break;

	case SMB2_OP_IOCTL:
		{
			START_PROFILE(smb2_ioctl);
			return_value = smbd_smb2_request_process_ioctl(req);
			END_PROFILE(smb2_ioctl);
		}
		break;

	case SMB2_OP_CANCEL:
		{
			START_PROFILE(smb2_cancel);
			return_value = smbd_smb2_request_process_cancel(req);
			END_PROFILE(smb2_cancel);
		}
		break;

	case SMB2_OP_KEEPALIVE:
		{
			START_PROFILE(smb2_keepalive);
			return_value = smbd_smb2_request_process_keepalive(req);
			END_PROFILE(smb2_keepalive);
		}
		break;

	case SMB2_OP_FIND:
		{
			START_PROFILE(smb2_find);
			return_value = smbd_smb2_request_process_find(req);
			END_PROFILE(smb2_find);
		}
		break;

	case SMB2_OP_NOTIFY:
		{
			START_PROFILE(smb2_notify);
			return_value = smbd_smb2_request_process_notify(req);
			END_PROFILE(smb2_notify);
		}
		break;

	case SMB2_OP_GETINFO:
		{
			START_PROFILE(smb2_getinfo);
			return_value = smbd_smb2_request_process_getinfo(req);
			END_PROFILE(smb2_getinfo);
		}
		break;

	case SMB2_OP_SETINFO:
		{
			START_PROFILE(smb2_setinfo);
			return_value = smbd_smb2_request_process_setinfo(req);
			END_PROFILE(smb2_setinfo);
		}
		break;

	case SMB2_OP_BREAK:
		{
			START_PROFILE(smb2_break);
			return_value = smbd_smb2_request_process_break(req);
			END_PROFILE(smb2_break);
		}
		break;

	default:
		return_value = smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
		break;
	}
	return return_value;
}

static NTSTATUS smbd_smb2_request_reply(struct smbd_smb2_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;
	int first_idx = 1;
	struct iovec *firsttf = SMBD_SMB2_IDX_TF_IOV(req,out,first_idx);
	struct iovec *outhdr = SMBD_SMB2_OUT_HDR_IOV(req);
	struct iovec *outdyn = SMBD_SMB2_OUT_DYN_IOV(req);
	NTSTATUS status;

	req->subreq = NULL;
	TALLOC_FREE(req->async_te);

	if (req->do_encryption &&
	    (firsttf->iov_len == 0) &&
	    (req->first_key.length == 0) &&
	    (req->session != NULL) &&
	    (req->session->global->encryption_key.length != 0))
	{
		DATA_BLOB encryption_key = req->session->global->encryption_key;
		uint8_t *tf;
		uint64_t session_id = req->session->global->session_wire_id;
		struct smbXsrv_session *x = req->session;
		uint64_t nonce_high;
		uint64_t nonce_low;

		nonce_high = x->nonce_high;
		nonce_low = x->nonce_low;

		x->nonce_low += 1;
		if (x->nonce_low == 0) {
			x->nonce_low += 1;
			x->nonce_high += 1;
		}

		/*
		 * We need to place the SMB2_TRANSFORM header before the
		 * first SMB2 header
		 */

		/*
		 * we need to remember the encryption key
		 * and defer the signing/encryption until
		 * we are sure that we do not change
		 * the header again.
		 */
		req->first_key = data_blob_dup_talloc(req, encryption_key);
		if (req->first_key.data == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		tf = talloc_zero_array(req, uint8_t,
				       SMB2_TF_HDR_SIZE);
		if (tf == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		SIVAL(tf, SMB2_TF_PROTOCOL_ID, SMB2_TF_MAGIC);
		SBVAL(tf, SMB2_TF_NONCE+0, nonce_low);
		SBVAL(tf, SMB2_TF_NONCE+8, nonce_high);
		SBVAL(tf, SMB2_TF_SESSION_ID, session_id);

		firsttf->iov_base = (void *)tf;
		firsttf->iov_len = SMB2_TF_HDR_SIZE;
	}

	if ((req->current_idx > SMBD_SMB2_NUM_IOV_PER_REQ) &&
	    (req->last_key.length > 0) &&
	    (firsttf->iov_len == 0))
	{
		int last_idx = req->current_idx - SMBD_SMB2_NUM_IOV_PER_REQ;
		struct iovec *lasthdr = SMBD_SMB2_IDX_HDR_IOV(req,out,last_idx);

		/*
		 * As we are sure the header of the last request in the
		 * compound chain will not change, we can to sign here
		 * with the last signing key we remembered.
		 */
		status = smb2_signing_sign_pdu(req->last_key,
					       xconn->protocol,
					       lasthdr,
					       SMBD_SMB2_NUM_IOV_PER_REQ - 1);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	if (req->last_key.length > 0) {
		data_blob_clear_free(&req->last_key);
	}

	req->current_idx += SMBD_SMB2_NUM_IOV_PER_REQ;

	if (req->current_idx < req->out.vector_count) {
		/*
		 * We must process the remaining compound
		 * SMB2 requests before any new incoming SMB2
		 * requests. This is because incoming SMB2
		 * requests may include a cancel for a
		 * compound request we haven't processed
		 * yet.
		 */
		struct tevent_immediate *im = tevent_create_immediate(req);
		if (!im) {
			return NT_STATUS_NO_MEMORY;
		}

		if (req->do_signing && firsttf->iov_len == 0) {
			struct smbXsrv_session *x = req->session;
			DATA_BLOB signing_key = smbd_smb2_signing_key(x, xconn);

			/*
			 * we need to remember the signing key
			 * and defer the signing until
			 * we are sure that we do not change
			 * the header again.
			 */
			req->last_key = data_blob_dup_talloc(req, signing_key);
			if (req->last_key.data == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		}

		tevent_schedule_immediate(im,
					req->sconn->ev_ctx,
					smbd_smb2_request_dispatch_immediate,
					req);
		return NT_STATUS_OK;
	}

	if (req->compound_related) {
		req->compound_related = false;
	}

	smb2_setup_nbt_length(req->out.vector, req->out.vector_count);

	/* Set credit for these operations (zero credits if this
	   is a final reply for an async operation). */
	smb2_calculate_credits(req, req);

	/*
	 * now check if we need to sign the current response
	 */
	if (firsttf->iov_len == SMB2_TF_HDR_SIZE) {
		status = smb2_signing_encrypt_pdu(req->first_key,
					xconn->protocol,
					firsttf,
					req->out.vector_count - first_idx);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else if (req->do_signing) {
		struct smbXsrv_session *x = req->session;
		DATA_BLOB signing_key = smbd_smb2_signing_key(x, xconn);

		status = smb2_signing_sign_pdu(signing_key,
					       xconn->protocol,
					       outhdr,
					       SMBD_SMB2_NUM_IOV_PER_REQ - 1);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	if (req->first_key.length > 0) {
		data_blob_clear_free(&req->first_key);
	}

	/* I am a sick, sick man... :-). Sendfile hack ... JRA. */
	if (req->out.vector_count < (2*SMBD_SMB2_NUM_IOV_PER_REQ) &&
	    outdyn->iov_base == NULL && outdyn->iov_len != 0) {
		/* Dynamic part is NULL. Chop it off,
		   We're going to send it via sendfile. */
		req->out.vector_count -= 1;
	}

	/*
	 * We're done with this request -
	 * move it off the "being processed" queue.
	 */
	DLIST_REMOVE(xconn->smb2.requests, req);

	req->queue_entry.mem_ctx = req;
	req->queue_entry.vector = req->out.vector;
	req->queue_entry.count = req->out.vector_count;
	DLIST_ADD_END(xconn->smb2.send_queue, &req->queue_entry, NULL);
	xconn->smb2.send_queue_len++;

	status = smbd_smb2_flush_send_queue(xconn);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS smbd_smb2_request_next_incoming(struct smbXsrv_connection *xconn);

void smbd_smb2_request_dispatch_immediate(struct tevent_context *ctx,
					struct tevent_immediate *im,
					void *private_data)
{
	struct smbd_smb2_request *req = talloc_get_type_abort(private_data,
					struct smbd_smb2_request);
	struct smbXsrv_connection *xconn = req->xconn;
	NTSTATUS status;

	TALLOC_FREE(im);

	if (DEBUGLEVEL >= 10) {
		DEBUG(10,("smbd_smb2_request_dispatch_immediate: idx[%d] of %d vectors\n",
			req->current_idx, req->in.vector_count));
		print_req_vectors(req);
	}

	status = smbd_smb2_request_dispatch(req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return;
	}

	status = smbd_smb2_request_next_incoming(xconn);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return;
	}
}

NTSTATUS smbd_smb2_request_done_ex(struct smbd_smb2_request *req,
				   NTSTATUS status,
				   DATA_BLOB body, DATA_BLOB *dyn,
				   const char *location)
{
	uint8_t *outhdr;
	struct iovec *outbody_v;
	struct iovec *outdyn_v;
	uint32_t next_command_ofs;

	DEBUG(10,("smbd_smb2_request_done_ex: "
		  "idx[%d] status[%s] body[%u] dyn[%s:%u] at %s\n",
		  req->current_idx, nt_errstr(status), (unsigned int)body.length,
		  dyn ? "yes": "no",
		  (unsigned int)(dyn ? dyn->length : 0),
		  location));

	if (body.length < 2) {
		return smbd_smb2_request_error(req, NT_STATUS_INTERNAL_ERROR);
	}

	if ((body.length % 2) != 0) {
		return smbd_smb2_request_error(req, NT_STATUS_INTERNAL_ERROR);
	}

	outhdr = SMBD_SMB2_OUT_HDR_PTR(req);
	outbody_v = SMBD_SMB2_OUT_BODY_IOV(req);
	outdyn_v = SMBD_SMB2_OUT_DYN_IOV(req);

	next_command_ofs = IVAL(outhdr, SMB2_HDR_NEXT_COMMAND);
	SIVAL(outhdr, SMB2_HDR_STATUS, NT_STATUS_V(status));

	outbody_v->iov_base = (void *)body.data;
	outbody_v->iov_len = body.length;

	if (dyn) {
		outdyn_v->iov_base = (void *)dyn->data;
		outdyn_v->iov_len = dyn->length;
	} else {
		outdyn_v->iov_base = NULL;
		outdyn_v->iov_len = 0;
	}

	/*
	 * See if we need to recalculate the offset to the next response
	 *
	 * Note that all responses may require padding (including the very last
	 * one).
	 */
	if (req->out.vector_count >= (2 * SMBD_SMB2_NUM_IOV_PER_REQ)) {
		next_command_ofs  = SMB2_HDR_BODY;
		next_command_ofs += SMBD_SMB2_OUT_BODY_LEN(req);
		next_command_ofs += SMBD_SMB2_OUT_DYN_LEN(req);
	}

	if ((next_command_ofs % 8) != 0) {
		size_t pad_size = 8 - (next_command_ofs % 8);
		if (SMBD_SMB2_OUT_DYN_LEN(req) == 0) {
			/*
			 * if the dyn buffer is empty
			 * we can use it to add padding
			 */
			uint8_t *pad;

			pad = talloc_zero_array(req,
						uint8_t, pad_size);
			if (pad == NULL) {
				return smbd_smb2_request_error(req,
						NT_STATUS_NO_MEMORY);
			}

			outdyn_v->iov_base = (void *)pad;
			outdyn_v->iov_len = pad_size;
		} else {
			/*
			 * For now we copy the dynamic buffer
			 * and add the padding to the new buffer
			 */
			size_t old_size;
			uint8_t *old_dyn;
			size_t new_size;
			uint8_t *new_dyn;

			old_size = SMBD_SMB2_OUT_DYN_LEN(req);
			old_dyn = SMBD_SMB2_OUT_DYN_PTR(req);

			new_size = old_size + pad_size;
			new_dyn = talloc_zero_array(req,
					       uint8_t, new_size);
			if (new_dyn == NULL) {
				return smbd_smb2_request_error(req,
						NT_STATUS_NO_MEMORY);
			}

			memcpy(new_dyn, old_dyn, old_size);
			memset(new_dyn + old_size, 0, pad_size);

			outdyn_v->iov_base = (void *)new_dyn;
			outdyn_v->iov_len = new_size;
		}
		next_command_ofs += pad_size;
	}

	if ((req->current_idx + SMBD_SMB2_NUM_IOV_PER_REQ) >= req->out.vector_count) {
		SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND, 0);
	} else {
		SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND, next_command_ofs);
	}
	return smbd_smb2_request_reply(req);
}

NTSTATUS smbd_smb2_request_error_ex(struct smbd_smb2_request *req,
				    NTSTATUS status,
				    DATA_BLOB *info,
				    const char *location)
{
	struct smbXsrv_connection *xconn = req->xconn;
	DATA_BLOB body;
	DATA_BLOB _dyn;
	uint8_t *outhdr = SMBD_SMB2_OUT_HDR_PTR(req);
	size_t unread_bytes = smbd_smb2_unread_bytes(req);

	DEBUG(10,("smbd_smb2_request_error_ex: idx[%d] status[%s] |%s| at %s\n",
		  req->current_idx, nt_errstr(status), info ? " +info" : "",
		  location));

	if (unread_bytes) {
		/* Recvfile error. Drain incoming socket. */
		size_t ret;

		errno = 0;
		ret = drain_socket(xconn->transport.sock, unread_bytes);
		if (ret != unread_bytes) {
			NTSTATUS error;

			if (errno == 0) {
				error = NT_STATUS_IO_DEVICE_ERROR;
			} else {
				error = map_nt_error_from_unix_common(errno);
			}

			DEBUG(2, ("Failed to drain %u bytes from SMB2 socket: "
				  "ret[%u] errno[%d] => %s\n",
				  (unsigned)unread_bytes,
				  (unsigned)ret, errno, nt_errstr(error)));
			return error;
		}
	}

	body.data = outhdr + SMB2_HDR_BODY;
	body.length = 8;
	SSVAL(body.data, 0, 9);

	if (info) {
		SIVAL(body.data, 0x04, info->length);
	} else {
		/* Allocated size of req->out.vector[i].iov_base
		 * *MUST BE* OUTVEC_ALLOC_SIZE. So we have room for
		 * 1 byte without having to do an alloc.
		 */
		info = &_dyn;
		info->data = ((uint8_t *)outhdr) +
			OUTVEC_ALLOC_SIZE - 1;
		info->length = 1;
		SCVAL(info->data, 0, 0);
	}

	/*
	 * Note: Even if there is an error, continue to process the request.
	 * per MS-SMB2.
	 */

	return smbd_smb2_request_done_ex(req, status, body, info, __location__);
}


struct smbd_smb2_send_break_state {
	struct smbd_smb2_send_queue queue_entry;
	uint8_t nbt_hdr[NBT_HDR_SIZE];
	uint8_t tf[SMB2_TF_HDR_SIZE];
	uint8_t hdr[SMB2_HDR_BODY];
	struct iovec vector[1+SMBD_SMB2_NUM_IOV_PER_REQ];
	uint8_t body[1];
};

static NTSTATUS smbd_smb2_send_break(struct smbXsrv_connection *xconn,
				     struct smbXsrv_session *session,
				     struct smbXsrv_tcon *tcon,
				     const uint8_t *body,
				     size_t body_len)
{
	struct smbd_smb2_send_break_state *state;
	bool do_encryption = false;
	uint64_t session_wire_id = 0;
	uint64_t nonce_high = 0;
	uint64_t nonce_low = 0;
	NTSTATUS status;
	size_t statelen;

	if (session != NULL) {
		session_wire_id = session->global->session_wire_id;
		do_encryption = session->global->encryption_required;
		if (tcon->global->encryption_required) {
			do_encryption = true;
		}
	}

	statelen = offsetof(struct smbd_smb2_send_break_state, body) +
		body_len;

	state = talloc_zero_size(xconn, statelen);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_name_const(state, "struct smbd_smb2_send_break_state");

	if (do_encryption) {
		nonce_high = session->nonce_high;
		nonce_low = session->nonce_low;

		session->nonce_low += 1;
		if (session->nonce_low == 0) {
			session->nonce_low += 1;
			session->nonce_high += 1;
		}
	}

	SIVAL(state->tf, SMB2_TF_PROTOCOL_ID, SMB2_TF_MAGIC);
	SBVAL(state->tf, SMB2_TF_NONCE+0, nonce_low);
	SBVAL(state->tf, SMB2_TF_NONCE+8, nonce_high);
	SBVAL(state->tf, SMB2_TF_SESSION_ID, session_wire_id);

	SIVAL(state->hdr, 0,				SMB2_MAGIC);
	SSVAL(state->hdr, SMB2_HDR_LENGTH,		SMB2_HDR_BODY);
	SSVAL(state->hdr, SMB2_HDR_EPOCH,		0);
	SIVAL(state->hdr, SMB2_HDR_STATUS,		0);
	SSVAL(state->hdr, SMB2_HDR_OPCODE,		SMB2_OP_BREAK);
	SSVAL(state->hdr, SMB2_HDR_CREDIT,		0);
	SIVAL(state->hdr, SMB2_HDR_FLAGS,		SMB2_HDR_FLAG_REDIRECT);
	SIVAL(state->hdr, SMB2_HDR_NEXT_COMMAND,	0);
	SBVAL(state->hdr, SMB2_HDR_MESSAGE_ID,		UINT64_MAX);
	SIVAL(state->hdr, SMB2_HDR_PID,		0);
	SIVAL(state->hdr, SMB2_HDR_TID,		0);
	SBVAL(state->hdr, SMB2_HDR_SESSION_ID,		0);
	memset(state->hdr+SMB2_HDR_SIGNATURE, 0, 16);

	state->vector[0] = (struct iovec) {
		.iov_base = state->nbt_hdr,
		.iov_len  = sizeof(state->nbt_hdr)
	};

	if (do_encryption) {
		state->vector[1+SMBD_SMB2_TF_IOV_OFS] = (struct iovec) {
			.iov_base = state->tf,
			.iov_len  = sizeof(state->tf)
		};
	} else {
		state->vector[1+SMBD_SMB2_TF_IOV_OFS] = (struct iovec) {
			.iov_base = NULL,
			.iov_len  = 0
		};
	}

	state->vector[1+SMBD_SMB2_HDR_IOV_OFS] = (struct iovec) {
		.iov_base = state->hdr,
		.iov_len  = sizeof(state->hdr)
	};

	memcpy(state->body, body, body_len);

	state->vector[1+SMBD_SMB2_BODY_IOV_OFS] = (struct iovec) {
		.iov_base = state->body,
		.iov_len  = body_len /* no sizeof(state->body) .. :-) */
	};

	/*
	 * state->vector[1+SMBD_SMB2_DYN_IOV_OFS] is NULL by talloc_zero above
	 */

	smb2_setup_nbt_length(state->vector, 1 + SMBD_SMB2_NUM_IOV_PER_REQ);

	if (do_encryption) {
		DATA_BLOB encryption_key = session->global->encryption_key;

		status = smb2_signing_encrypt_pdu(encryption_key,
					xconn->protocol,
					&state->vector[1+SMBD_SMB2_TF_IOV_OFS],
					SMBD_SMB2_NUM_IOV_PER_REQ);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	state->queue_entry.mem_ctx = state;
	state->queue_entry.vector = state->vector;
	state->queue_entry.count = ARRAY_SIZE(state->vector);
	DLIST_ADD_END(xconn->smb2.send_queue, &state->queue_entry, NULL);
	xconn->smb2.send_queue_len++;

	status = smbd_smb2_flush_send_queue(xconn);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS smbd_smb2_send_oplock_break(struct smbXsrv_connection *xconn,
				     struct smbXsrv_session *session,
				     struct smbXsrv_tcon *tcon,
				     struct smbXsrv_open *op,
				     uint8_t oplock_level)
{
	uint8_t body[0x18];

	SSVAL(body, 0x00, sizeof(body));
	SCVAL(body, 0x02, oplock_level);
	SCVAL(body, 0x03, 0);		/* reserved */
	SIVAL(body, 0x04, 0);		/* reserved */
	SBVAL(body, 0x08, op->global->open_persistent_id);
	SBVAL(body, 0x10, op->global->open_volatile_id);

	return smbd_smb2_send_break(xconn, session, tcon, body, sizeof(body));
}

NTSTATUS smbd_smb2_send_lease_break(struct smbXsrv_connection *xconn,
				    uint16_t new_epoch,
				    uint32_t lease_flags,
				    struct smb2_lease_key *lease_key,
				    uint32_t current_lease_state,
				    uint32_t new_lease_state)
{
	uint8_t body[0x2c];

	SSVAL(body, 0x00, sizeof(body));
	SSVAL(body, 0x02, new_epoch);
	SIVAL(body, 0x04, lease_flags);
	SBVAL(body, 0x08, lease_key->data[0]);
	SBVAL(body, 0x10, lease_key->data[1]);
	SIVAL(body, 0x18, current_lease_state);
	SIVAL(body, 0x1c, new_lease_state);
	SIVAL(body, 0x20, 0);		/* BreakReason, MUST be 0 */
	SIVAL(body, 0x24, 0);		/* AccessMaskHint, MUST be 0 */
	SIVAL(body, 0x28, 0);		/* ShareMaskHint, MUST be 0 */

	return smbd_smb2_send_break(xconn, NULL, NULL, body, sizeof(body));
}

static bool is_smb2_recvfile_write(struct smbd_smb2_request_read_state *state)
{
	NTSTATUS status;
	uint32_t flags;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	struct smbXsrv_open *op = NULL;
	struct files_struct *fsp = NULL;
	const uint8_t *body = NULL;

	/*
	 * This is only called with a pktbuf
	 * of at least SMBD_SMB2_SHORT_RECEIVEFILE_WRITE_LEN
	 * bytes
	 */

	if (IVAL(state->pktbuf, 0) == SMB2_TF_MAGIC) {
		/* Transform header. Cannot recvfile. */
		return false;
	}
	if (IVAL(state->pktbuf, 0) != SMB2_MAGIC) {
		/* Not SMB2. Normal error path will cope. */
		return false;
	}
	if (SVAL(state->pktbuf, 4) != SMB2_HDR_BODY) {
		/* Not SMB2. Normal error path will cope. */
		return false;
	}
	if (SVAL(state->pktbuf, SMB2_HDR_OPCODE) != SMB2_OP_WRITE) {
		/* Needs to be a WRITE. */
		return false;
	}
	if (IVAL(state->pktbuf, SMB2_HDR_NEXT_COMMAND) != 0) {
		/* Chained. Cannot recvfile. */
		return false;
	}
	flags = IVAL(state->pktbuf, SMB2_HDR_FLAGS);
	if (flags & SMB2_HDR_FLAG_CHAINED) {
		/* Chained. Cannot recvfile. */
		return false;
	}
	if (flags & SMB2_HDR_FLAG_SIGNED) {
		/* Signed. Cannot recvfile. */
		return false;
	}

	body = &state->pktbuf[SMB2_HDR_BODY];

	file_id_persistent	= BVAL(body, 0x10);
	file_id_volatile	= BVAL(body, 0x18);

	status = smb2srv_open_lookup(state->req->xconn,
				     file_id_persistent,
				     file_id_volatile,
				     0, /* now */
				     &op);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	fsp = op->compat;
	if (fsp == NULL) {
		return false;
	}
	if (fsp->conn == NULL) {
		return false;
	}

	if (IS_IPC(fsp->conn)) {
		return false;
	}
	if (IS_PRINT(fsp->conn)) {
		return false;
	}

	DEBUG(10,("Doing recvfile write len = %u\n",
		(unsigned int)(state->pktfull - state->pktlen)));

	return true;
}

static NTSTATUS smbd_smb2_request_next_incoming(struct smbXsrv_connection *xconn)
{
	struct smbd_server_connection *sconn = xconn->client->sconn;
	struct smbd_smb2_request_read_state *state = &xconn->smb2.request_read_state;
	size_t max_send_queue_len;
	size_t cur_send_queue_len;

	if (!NT_STATUS_IS_OK(xconn->transport.status)) {
		/*
		 * we're not supposed to do any io
		 */
		return NT_STATUS_OK;
	}

	if (state->req != NULL) {
		/*
		 * if there is already a tstream_readv_pdu
		 * pending, we are done.
		 */
		return NT_STATUS_OK;
	}

	max_send_queue_len = MAX(1, xconn->smb2.credits.max/16);
	cur_send_queue_len = xconn->smb2.send_queue_len;

	if (cur_send_queue_len > max_send_queue_len) {
		/*
		 * if we have a lot of requests to send,
		 * we wait until they are on the wire until we
		 * ask for the next request.
		 */
		return NT_STATUS_OK;
	}

	/* ask for the next request */
	ZERO_STRUCTP(state);
	state->req = smbd_smb2_request_allocate(xconn);
	if (state->req == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->req->sconn = sconn;
	state->req->xconn = xconn;
	state->min_recv_size = lp_min_receive_file_size();

	TEVENT_FD_READABLE(xconn->transport.fde);

	return NT_STATUS_OK;
}

void smbd_smb2_first_negprot(struct smbXsrv_connection *xconn,
			     const uint8_t *inpdu, size_t size)
{
	struct smbd_server_connection *sconn = xconn->client->sconn;
	NTSTATUS status;
	struct smbd_smb2_request *req = NULL;

	DEBUG(10,("smbd_smb2_first_negprot: packet length %u\n",
		 (unsigned int)size));

	status = smbd_initialize_smb2(xconn);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return;
	}

	status = smbd_smb2_request_create(xconn, inpdu, size, &req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return;
	}

	status = smbd_smb2_request_validate(req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return;
	}

	status = smbd_smb2_request_setup_out(req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return;
	}

	status = smbd_smb2_request_dispatch(req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return;
	}

	status = smbd_smb2_request_next_incoming(xconn);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return;
	}

	sconn->num_requests++;
}

static int socket_error_from_errno(int ret,
				   int sys_errno,
				   bool *retry)
{
	*retry = false;

	if (ret >= 0) {
		return 0;
	}

	if (ret != -1) {
		return EIO;
	}

	if (sys_errno == 0) {
		return EIO;
	}

	if (sys_errno == EINTR) {
		*retry = true;
		return sys_errno;
	}

	if (sys_errno == EINPROGRESS) {
		*retry = true;
		return sys_errno;
	}

	if (sys_errno == EAGAIN) {
		*retry = true;
		return sys_errno;
	}

	/* ENOMEM is retryable on Solaris/illumos, and possibly other systems. */
	if (sys_errno == ENOMEM) {
		*retry = true;
		return sys_errno;
	}

#ifdef EWOULDBLOCK
#if EWOULDBLOCK != EAGAIN
	if (sys_errno == EWOULDBLOCK) {
		*retry = true;
		return sys_errno;
	}
#endif
#endif

	return sys_errno;
}

static NTSTATUS smbd_smb2_flush_send_queue(struct smbXsrv_connection *xconn)
{
	int ret;
	int err;
	bool retry;

	if (xconn->smb2.send_queue == NULL) {
		TEVENT_FD_NOT_WRITEABLE(xconn->transport.fde);
		return NT_STATUS_OK;
	}

	while (xconn->smb2.send_queue != NULL) {
		struct smbd_smb2_send_queue *e = xconn->smb2.send_queue;

		if (e->sendfile_header != NULL) {
			NTSTATUS status = NT_STATUS_INTERNAL_ERROR;
			size_t size = 0;
			size_t i = 0;
			uint8_t *buf;

			for (i=0; i < e->count; i++) {
				size += e->vector[i].iov_len;
			}

			if (size <= e->sendfile_header->length) {
				buf = e->sendfile_header->data;
			} else {
				buf = talloc_array(e->mem_ctx, uint8_t, size);
				if (buf == NULL) {
					return NT_STATUS_NO_MEMORY;
				}
			}

			size = 0;
			for (i=0; i < e->count; i++) {
				memcpy(buf+size,
				       e->vector[i].iov_base,
				       e->vector[i].iov_len);
				size += e->vector[i].iov_len;
			}

			e->sendfile_header->data = buf;
			e->sendfile_header->length = size;
			e->sendfile_status = &status;
			e->count = 0;

			xconn->smb2.send_queue_len--;
			DLIST_REMOVE(xconn->smb2.send_queue, e);
			/*
			 * This triggers the sendfile path via
			 * the destructor.
			 */
			talloc_free(e->mem_ctx);

			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			continue;
		}

		ret = writev(xconn->transport.sock, e->vector, e->count);
		if (ret == 0) {
			/* propagate end of file */
			return NT_STATUS_INTERNAL_ERROR;
		}
		err = socket_error_from_errno(ret, errno, &retry);
		if (retry) {
			/* retry later */
			TEVENT_FD_WRITEABLE(xconn->transport.fde);
			return NT_STATUS_OK;
		}
		if (err != 0) {
			return map_nt_error_from_unix_common(err);
		}
		while (ret > 0) {
			if (ret < e->vector[0].iov_len) {
				uint8_t *base;
				base = (uint8_t *)e->vector[0].iov_base;
				base += ret;
				e->vector[0].iov_base = (void *)base;
				e->vector[0].iov_len -= ret;
				break;
			}
			ret -= e->vector[0].iov_len;
			e->vector += 1;
			e->count -= 1;
		}

		/*
		 * there're maybe some empty vectors at the end
		 * which we need to skip, otherwise we would get
		 * ret == 0 from the readv() call and return EPIPE
		 */
		while (e->count > 0) {
			if (e->vector[0].iov_len > 0) {
				break;
			}
			e->vector += 1;
			e->count -= 1;
		}

		if (e->count > 0) {
			/* we have more to write */
			TEVENT_FD_WRITEABLE(xconn->transport.fde);
			return NT_STATUS_OK;
		}

		xconn->smb2.send_queue_len--;
		DLIST_REMOVE(xconn->smb2.send_queue, e);
		talloc_free(e->mem_ctx);
	}

	return NT_STATUS_OK;
}

static NTSTATUS smbd_smb2_io_handler(struct smbXsrv_connection *xconn,
				     uint16_t fde_flags)
{
	struct smbd_server_connection *sconn = xconn->client->sconn;
	struct smbd_smb2_request_read_state *state = &xconn->smb2.request_read_state;
	struct smbd_smb2_request *req = NULL;
	size_t min_recvfile_size = UINT32_MAX;
	int ret;
	int err;
	bool retry;
	NTSTATUS status;
	NTTIME now;

	if (!NT_STATUS_IS_OK(xconn->transport.status)) {
		/*
		 * we're not supposed to do any io
		 */
		TEVENT_FD_NOT_READABLE(xconn->transport.fde);
		TEVENT_FD_NOT_WRITEABLE(xconn->transport.fde);
		return NT_STATUS_OK;
	}

	if (fde_flags & TEVENT_FD_WRITE) {
		status = smbd_smb2_flush_send_queue(xconn);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (!(fde_flags & TEVENT_FD_READ)) {
		return NT_STATUS_OK;
	}

	if (state->req == NULL) {
		TEVENT_FD_NOT_READABLE(xconn->transport.fde);
		return NT_STATUS_OK;
	}

again:
	if (!state->hdr.done) {
		state->hdr.done = true;

		state->vector.iov_base = (void *)state->hdr.nbt;
		state->vector.iov_len = NBT_HDR_SIZE;
	}

	ret = readv(xconn->transport.sock, &state->vector, 1);
	if (ret == 0) {
		/* propagate end of file */
		return NT_STATUS_END_OF_FILE;
	}
	err = socket_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		TEVENT_FD_READABLE(xconn->transport.fde);
		return NT_STATUS_OK;
	}
	if (err != 0) {
		return map_nt_error_from_unix_common(err);
	}

	if (ret < state->vector.iov_len) {
		uint8_t *base;
		base = (uint8_t *)state->vector.iov_base;
		base += ret;
		state->vector.iov_base = (void *)base;
		state->vector.iov_len -= ret;
		/* we have more to read */
		TEVENT_FD_READABLE(xconn->transport.fde);
		return NT_STATUS_OK;
	}

	if (state->pktlen > 0) {
		if (state->doing_receivefile && !is_smb2_recvfile_write(state)) {
			/*
			 * Not a possible receivefile write.
			 * Read the rest of the data.
			 */
			state->doing_receivefile = false;

			state->pktbuf = talloc_realloc(state->req,
						       state->pktbuf,
						       uint8_t,
						       state->pktfull);
			if (state->pktbuf == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			state->vector.iov_base = (void *)(state->pktbuf +
				state->pktlen);
			state->vector.iov_len = (state->pktfull -
				state->pktlen);

			state->pktlen = state->pktfull;
			goto again;
		}

		/*
		 * Either this is a receivefile write so we've
		 * done a short read, or if not we have all the data.
		 */
		goto got_full;
	}

	/*
	 * Now we analyze the NBT header
	 */
	if (state->hdr.nbt[0] != 0x00) {
		state->min_recv_size = 0;
	}
	state->pktfull = smb2_len(state->hdr.nbt);
	if (state->pktfull == 0) {
		goto got_full;
	}

	if (state->min_recv_size != 0) {
		min_recvfile_size = SMBD_SMB2_SHORT_RECEIVEFILE_WRITE_LEN;
		min_recvfile_size += state->min_recv_size;
	}

	if (state->pktfull > min_recvfile_size) {
		/*
		 * Might be a receivefile write. Read the SMB2 HEADER +
		 * SMB2_WRITE header first. Set 'doing_receivefile'
		 * as we're *attempting* receivefile write. If this
		 * turns out not to be a SMB2_WRITE request or otherwise
		 * not suitable then we'll just read the rest of the data
		 * the next time this function is called.
		 */
		state->pktlen = SMBD_SMB2_SHORT_RECEIVEFILE_WRITE_LEN;
		state->doing_receivefile = true;
	} else {
		state->pktlen = state->pktfull;
	}

	state->pktbuf = talloc_array(state->req, uint8_t, state->pktlen);
	if (state->pktbuf == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->vector.iov_base = (void *)state->pktbuf;
	state->vector.iov_len = state->pktlen;

	goto again;

got_full:

	if (state->hdr.nbt[0] != 0x00) {
		DEBUG(1,("ignore NBT[0x%02X] msg\n",
			 state->hdr.nbt[0]));

		req = state->req;
		ZERO_STRUCTP(state);
		state->req = req;
		state->min_recv_size = lp_min_receive_file_size();
		req = NULL;
		goto again;
	}

	req = state->req;
	state->req = NULL;

	req->request_time = timeval_current();
	now = timeval_to_nttime(&req->request_time);

	status = smbd_smb2_inbuf_parse_compound(xconn,
						now,
						state->pktbuf,
						state->pktlen,
						req,
						&req->in.vector,
						&req->in.vector_count);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (state->doing_receivefile) {
		req->smb1req = talloc_zero(req, struct smb_request);
		if (req->smb1req == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		req->smb1req->unread_bytes = state->pktfull - state->pktlen;
	}

	ZERO_STRUCTP(state);

	req->current_idx = 1;

	DEBUG(10,("smbd_smb2_request idx[%d] of %d vectors\n",
		 req->current_idx, req->in.vector_count));

	status = smbd_smb2_request_validate(req);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = smbd_smb2_request_setup_out(req);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = smbd_smb2_request_dispatch(req);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	sconn->num_requests++;

	/* The timeout_processing function isn't run nearly
	   often enough to implement 'max log size' without
	   overrunning the size of the file by many megabytes.
	   This is especially true if we are running at debug
	   level 10.  Checking every 50 SMB2s is a nice
	   tradeoff of performance vs log file size overrun. */

	if ((sconn->num_requests % 50) == 0 &&
	    need_to_check_log_size()) {
		change_to_root_user();
		check_log_size();
	}

	status = smbd_smb2_request_next_incoming(xconn);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static void smbd_smb2_connection_handler(struct tevent_context *ev,
					 struct tevent_fd *fde,
					 uint16_t flags,
					 void *private_data)
{
	struct smbXsrv_connection *xconn =
		talloc_get_type_abort(private_data,
		struct smbXsrv_connection);
	NTSTATUS status;

	status = smbd_smb2_io_handler(xconn, flags);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return;
	}
}
