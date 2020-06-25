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
#include "system/network.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/smb/smb_common.h"
#include "../lib/tsocket/tsocket.h"
#include "../lib/util/tevent_ntstatus.h"
#include "smbprofile.h"
#include "../lib/util/bitmap.h"
#include "../librpc/gen_ndr/krb5pac.h"
#include "lib/util/iov_buf.h"
#include "auth.h"
#include "libcli/smb/smbXcli_base.h"

#if defined(LINUX)
/* SIOCOUTQ TIOCOUTQ are the same */
#define __IOCTL_SEND_QUEUE_SIZE_OPCODE TIOCOUTQ
#define __HAVE_TCP_INFO_RTO 1
#define __ALLOW_MULTI_CHANNEL_SUPPORT 1
#elif defined(FREEBSD)
#define __IOCTL_SEND_QUEUE_SIZE_OPCODE FIONWRITE
#define __HAVE_TCP_INFO_RTO 1
#define __ALLOW_MULTI_CHANNEL_SUPPORT 1
#endif

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SMB2

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
	bool modify;
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
		.modify = true,
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
		.modify = true,
	},{
		_OP(SMB2_OP_CANCEL),
		.as_root = true,
	},{
		_OP(SMB2_OP_KEEPALIVE),
		.as_root = true,
	},{
		_OP(SMB2_OP_QUERY_DIRECTORY),
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
		.modify = true,
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

bool smbd_smb2_is_compound(const struct smbd_smb2_request *req)
{
	return req->in.vector_count >= (2*SMBD_SMB2_NUM_IOV_PER_REQ);
}

static NTSTATUS smbd_initialize_smb2(struct smbXsrv_connection *xconn,
				     uint64_t expected_seq_low)
{
	xconn->smb2.credits.seq_low = expected_seq_low;
	xconn->smb2.credits.seq_range = 1;
	xconn->smb2.credits.granted = 1;
	xconn->smb2.credits.max = lp_smb2_max_credits();
	xconn->smb2.credits.bitmap = bitmap_talloc(xconn,
						   xconn->smb2.credits.max);
	if (xconn->smb2.credits.bitmap == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	tevent_fd_set_close_fn(xconn->transport.fde, NULL);
	TALLOC_FREE(xconn->transport.fde);

	xconn->transport.fde = tevent_add_fd(
					xconn->client->raw_ev_ctx,
					xconn,
					xconn->transport.sock,
					TEVENT_FD_READ,
					smbd_smb2_connection_handler,
					xconn);
	if (xconn->transport.fde == NULL) {
		close(xconn->transport.sock);
		xconn->transport.sock = -1;
		return NT_STATUS_NO_MEMORY;
	}
	tevent_fd_set_auto_close(xconn->transport.fde);

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

static bool smb2_setup_nbt_length(struct iovec *vector, int count)
{
	ssize_t len;

	if (count == 0) {
		return false;
	}

	len = iov_buflen(vector+1, count-1);

	if ((len == -1) || (len > 0xFFFFFF)) {
		return false;
	}

	_smb2_setlen(vector[0].iov_base, len);
	return true;
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

void smb2_request_set_async_internal(struct smbd_smb2_request *req,
				     bool async_internal)
{
	req->async_internal = async_internal;
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

			if (xconn->smb2.server.cipher == 0) {
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

			status = smb2srv_session_lookup_conn(xconn, uid, now,
							     &s);
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
							  xconn->smb2.server.cipher,
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

			if ((len == 5) &&
			    (IVAL(hdr, 0) == SMB_SUICIDE_PACKET) &&
			    lp_parm_bool(-1, "smbd", "suicide mode", false)) {
				uint8_t exitcode = CVAL(hdr, 4);
				DBG_WARNING("SUICIDE: Exiting immediately "
					    "with code %"PRIu8"\n",
					    exitcode);
				exit(exitcode);
			}

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
		DBGC_ERR(DBGC_SMB2_CREDITS,
			"smb2_validate_sequence_number: bad message_id "
			"%llu (sequence id %llu) "
			"(granted = %u, low = %llu, range = %u)\n",
			(unsigned long long)message_id,
			(unsigned long long)seq_id,
			(unsigned int)xconn->smb2.credits.granted,
			(unsigned long long)xconn->smb2.credits.seq_low,
			(unsigned int)xconn->smb2.credits.seq_range);
		return false;
	}

	seq_tmp += xconn->smb2.credits.seq_range;
	if (seq_id >= seq_tmp) {
		DBGC_ERR(DBGC_SMB2_CREDITS,
			"smb2_validate_sequence_number: bad message_id "
			"%llu (sequence id %llu) "
			"(granted = %u, low = %llu, range = %u)\n",
			(unsigned long long)message_id,
			(unsigned long long)seq_id,
			(unsigned int)xconn->smb2.credits.granted,
			(unsigned long long)xconn->smb2.credits.seq_low,
			(unsigned int)xconn->smb2.credits.seq_range);
		return false;
	}

	offset = seq_id % xconn->smb2.credits.max;

	if (bitmap_query(credits_bm, offset)) {
		DBGC_ERR(DBGC_SMB2_CREDITS,
			"smb2_validate_sequence_number: duplicate message_id "
			"%llu (sequence id %llu) "
			"(granted = %u, low = %llu, range = %u) "
			"(bm offset %u)\n",
			(unsigned long long)message_id,
			(unsigned long long)seq_id,
			(unsigned int)xconn->smb2.credits.granted,
			(unsigned long long)xconn->smb2.credits.seq_low,
			(unsigned int)xconn->smb2.credits.seq_range,
			offset);
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
		DBGC_DEBUG(DBGC_SMB2_CREDITS,
			  "smb2_validate_sequence_number: clearing "
			  "id %llu (position %u) from bitmap\n",
			  (unsigned long long)(xconn->smb2.credits.seq_low),
			  offset);
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

	DEBUGC(11,
		   DBGC_SMB2_CREDITS,
		   ("smb2_validate_message_id: mid %llu (charge %llu), "
		   "credits_granted %llu, "
		   "seqnum low/range: %llu/%llu\n",
		   (unsigned long long) message_id,
		   (unsigned long long) credit_charge,
		   (unsigned long long) xconn->smb2.credits.granted,
		   (unsigned long long) xconn->smb2.credits.seq_low,
		   (unsigned long long) xconn->smb2.credits.seq_range));

	if (xconn->smb2.credits.granted < credit_charge) {
		DBGC_ERR(DBGC_SMB2_CREDITS,
			  "smb2_validate_message_id: client used more "
			  "credits than granted, mid %llu, charge %llu, "
			  "credits_granted %llu, "
			  "seqnum low/range: %llu/%llu\n",
			  (unsigned long long) message_id,
			  (unsigned long long) credit_charge,
			  (unsigned long long) xconn->smb2.credits.granted,
			  (unsigned long long) xconn->smb2.credits.seq_low,
			  (unsigned long long) xconn->smb2.credits.seq_range);
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

		DEBUGC(11,
			   DBGC_SMB2_CREDITS,
			   ("Iterating mid %llu charge %u (sequence %llu)\n",
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
	 *
	 * The above is what Windows Server < 2016 is doing,
	 * but new servers use all credits (8192 by default).
	 */
	current_max_credits = xconn->smb2.credits.max;
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
				additional_max = xconn->smb2.credits.max;
			}
			break;
		default:
			/*
			 * Windows Server < 2016 and older Samba versions
			 * used to only grant additional credits in
			 * chunks of 32 credits.
			 *
			 * But we match Windows Server 2016 and grant
			 * all credits as requested.
			 */
			additional_max = xconn->smb2.credits.max;
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

	DBGC_DEBUG(DBGC_SMB2_CREDITS,
		"smb2_set_operation_credit: requested %u, charge %u, "
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
		(unsigned int)xconn->smb2.credits.seq_range);
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
	bool ok;

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
	ok = smb2_setup_nbt_length(req->out.vector, req->out.vector_count);
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	DLIST_ADD_END(xconn->smb2.requests, req);

	return NT_STATUS_OK;
}

bool smbXsrv_server_multi_channel_enabled(void)
{
	bool enabled = lp_server_multi_channel_support();
#ifndef __ALLOW_MULTI_CHANNEL_SUPPORT
	bool forced = false;
	/*
	 * If we don't have support from the kernel
	 * to ask for the un-acked number of bytes
	 * in the socket send queue, we better
	 * don't support multi-channel.
	 */
	forced = lp_parm_bool(-1, "force", "server multi channel support", false);
	if (enabled && !forced) {
		D_NOTICE("'server multi channel support' enabled "
			 "but not supported on %s (%s)\n",
			 SYSTEM_UNAME_SYSNAME, SYSTEM_UNAME_RELEASE);
		DEBUGADD(DBGLVL_NOTICE, ("Please report this on "
			"https://bugzilla.samba.org/show_bug.cgi?id=11897\n"));
		enabled = false;
	}
#endif /* ! __ALLOW_MULTI_CHANNEL_SUPPORT */
	return enabled;
}

static NTSTATUS smbXsrv_connection_get_rto_usecs(struct smbXsrv_connection *xconn,
						 uint32_t *_rto_usecs)
{
	/*
	 * Define an Retransmission Timeout
	 * of 1 second, if there's no way for the
	 * kernel to tell us the current value.
	 */
	uint32_t rto_usecs = 1000000;

#ifdef __HAVE_TCP_INFO_RTO
	{
		struct tcp_info info;
		socklen_t ilen = sizeof(info);
		int ret;

		ZERO_STRUCT(info);
		ret = getsockopt(xconn->transport.sock,
				 IPPROTO_TCP, TCP_INFO,
				 (void *)&info, &ilen);
		if (ret != 0) {
			int saved_errno = errno;
			NTSTATUS status = map_nt_error_from_unix(errno);
			DBG_ERR("getsockopt(TCP_INFO) errno[%d/%s] -s %s\n",
				saved_errno, strerror(saved_errno),
				nt_errstr(status));
			return status;
		}

		DBG_DEBUG("tcpi_rto[%u] tcpi_rtt[%u] tcpi_rttvar[%u]\n",
			  (unsigned)info.tcpi_rto,
			  (unsigned)info.tcpi_rtt,
			  (unsigned)info.tcpi_rttvar);
		rto_usecs = info.tcpi_rto;
	}
#endif /* __HAVE_TCP_INFO_RTO */

	rto_usecs = MAX(rto_usecs,  200000); /* at least 0.2s */
	rto_usecs = MIN(rto_usecs, 1000000); /* at max   1.0s */
	*_rto_usecs = rto_usecs;
	return NT_STATUS_OK;
}

static NTSTATUS smbXsrv_connection_get_acked_bytes(struct smbXsrv_connection *xconn,
						   uint64_t *_acked_bytes)
{
	/*
	 * Unless the kernel has an interface
	 * to reveal the number of un-acked bytes
	 * in the socket send queue, we'll assume
	 * everything is already acked.
	 *
	 * But that would mean that we better don't
	 * pretent to support multi-channel.
	 */
	uint64_t unacked_bytes = 0;

	*_acked_bytes = 0;

	if (xconn->ack.force_unacked_timeout) {
		/*
		 * Smbtorture tries to test channel failures...
		 * Just pretend nothing was acked...
		 */
		DBG_INFO("Simulating channel failure: "
			 "xconn->ack.unacked_bytes[%llu]\n",
			 (unsigned long long)xconn->ack.unacked_bytes);
		return NT_STATUS_OK;
	}

#ifdef __IOCTL_SEND_QUEUE_SIZE_OPCODE
	{
		int value = 0;
		int ret;

		/*
		 * If we have kernel support to get
		 * the number of bytes waiting in
		 * the socket's send queue, we
		 * use that in order to find out
		 * the number of unacked bytes.
		 */
		ret = ioctl(xconn->transport.sock,
			    __IOCTL_SEND_QUEUE_SIZE_OPCODE,
			    &value);
		if (ret != 0) {
			int saved_errno = errno;
			NTSTATUS status = map_nt_error_from_unix(saved_errno);
			DBG_ERR("Failed to get the SEND_QUEUE_SIZE - "
				"errno %d (%s) - %s\n",
				saved_errno, strerror(saved_errno),
				nt_errstr(status));
			return status;
		}

		if (value < 0) {
			DBG_ERR("xconn->ack.unacked_bytes[%llu] value[%d]\n",
				(unsigned long long)xconn->ack.unacked_bytes,
				value);
			return NT_STATUS_INTERNAL_ERROR;
		}
		unacked_bytes = value;
	}
#endif
	if (xconn->ack.unacked_bytes == 0) {
		xconn->ack.unacked_bytes = unacked_bytes;
		return NT_STATUS_OK;
	}

	if (xconn->ack.unacked_bytes < unacked_bytes) {
		DBG_ERR("xconn->ack.unacked_bytes[%llu] unacked_bytes[%llu]\n",
			(unsigned long long)xconn->ack.unacked_bytes,
			(unsigned long long)unacked_bytes);
		return NT_STATUS_INTERNAL_ERROR;
	}

	*_acked_bytes = xconn->ack.unacked_bytes - unacked_bytes;
	xconn->ack.unacked_bytes = unacked_bytes;
	return NT_STATUS_OK;
}

static void smbd_smb2_send_queue_ack_fail(struct smbd_smb2_send_queue **queue,
					  NTSTATUS status)
{
	struct smbd_smb2_send_queue *e = NULL;
	struct smbd_smb2_send_queue *n = NULL;

	for (e = *queue; e != NULL; e = n) {
		n = e->next;

		DLIST_REMOVE(*queue, e);
		if (e->ack.req != NULL) {
			tevent_req_nterror(e->ack.req, status);
		}
	}
}

static NTSTATUS smbd_smb2_send_queue_ack_bytes(struct smbd_smb2_send_queue **queue,
					       uint64_t acked_bytes)
{
	struct smbd_smb2_send_queue *e = NULL;
	struct smbd_smb2_send_queue *n = NULL;

	for (e = *queue; e != NULL; e = n) {
		bool expired;

		n = e->next;

		if (e->ack.req == NULL) {
			continue;
		}

		if (e->ack.required_acked_bytes <= acked_bytes) {
			e->ack.required_acked_bytes = 0;
			DLIST_REMOVE(*queue, e);
			tevent_req_done(e->ack.req);
			continue;
		}
		e->ack.required_acked_bytes -= acked_bytes;

		expired = timeval_expired(&e->ack.timeout);
		if (expired) {
			return NT_STATUS_IO_TIMEOUT;
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS smbd_smb2_check_ack_queue(struct smbXsrv_connection *xconn)
{
	uint64_t acked_bytes = 0;
	NTSTATUS status;

	status = smbXsrv_connection_get_acked_bytes(xconn, &acked_bytes);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = smbd_smb2_send_queue_ack_bytes(&xconn->ack.queue, acked_bytes);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = smbd_smb2_send_queue_ack_bytes(&xconn->smb2.send_queue, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static void smbXsrv_connection_ack_checker(struct tevent_req *subreq)
{
	struct smbXsrv_connection *xconn =
		tevent_req_callback_data(subreq,
		struct smbXsrv_connection);
	struct smbXsrv_client *client = xconn->client;
	struct timeval next_check;
	NTSTATUS status;
	bool ok;

	xconn->ack.checker_subreq = NULL;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		smbd_server_connection_terminate(xconn,
						 "tevent_wakeup_recv() failed");
		return;
	}

	status = smbd_smb2_check_ack_queue(xconn);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return;
	}

	next_check = timeval_current_ofs_usec(xconn->ack.rto_usecs);
	xconn->ack.checker_subreq = tevent_wakeup_send(xconn,
						       client->raw_ev_ctx,
						       next_check);
	if (xconn->ack.checker_subreq == NULL) {
		smbd_server_connection_terminate(xconn,
						 "tevent_wakeup_send() failed");
		return;
	}
	tevent_req_set_callback(xconn->ack.checker_subreq,
				smbXsrv_connection_ack_checker,
				xconn);
}

static NTSTATUS smbXsrv_client_pending_breaks_updated(struct smbXsrv_client *client)
{
	struct smbXsrv_connection *xconn = NULL;

	for (xconn = client->connections; xconn != NULL; xconn = xconn->next) {
		struct timeval next_check;
		uint64_t acked_bytes = 0;
		NTSTATUS status;

		/*
		 * A new 'pending break cycle' starts
		 * with a first pending break and lasts until
		 * all pending breaks are finished.
		 *
		 * This is typically a very short time,
		 * the value of one retransmission timeout.
		 */

		if (client->pending_breaks == NULL) {
			/*
			 * No more pending breaks, remove a pending
			 * checker timer
			 */
			TALLOC_FREE(xconn->ack.checker_subreq);
			continue;
		}

		if (xconn->ack.checker_subreq != NULL) {
			/*
			 * The cycle already started =>
			 * nothing todo
			 */
			continue;
		}

		/*
		 * Get the current retransmission timeout value.
		 *
		 * It may change over time, but fetching it once
		 * per 'pending break' cycled should be enough.
		 */
		status = smbXsrv_connection_get_rto_usecs(xconn,
							  &xconn->ack.rto_usecs);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/*
		 * At the start of the cycle we reset the
		 * unacked_bytes counter (first to 0 and
		 * within smbXsrv_connection_get_acked_bytes()
		 * to the current value in the kernel
		 * send queue.
		 */
		xconn->ack.unacked_bytes = 0;
		status = smbXsrv_connection_get_acked_bytes(xconn, &acked_bytes);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/*
		 * We setup a timer in order to check for
		 * acked bytes after one retransmission timeout.
		 *
		 * The code that sets up the send_queue.ack.timeout
		 * uses a multiple of the retransmission timeout.
		 */
		next_check = timeval_current_ofs_usec(xconn->ack.rto_usecs);
		xconn->ack.checker_subreq = tevent_wakeup_send(xconn,
							client->raw_ev_ctx,
							next_check);
		if (xconn->ack.checker_subreq == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		tevent_req_set_callback(xconn->ack.checker_subreq,
					smbXsrv_connection_ack_checker,
					xconn);
	}

	return NT_STATUS_OK;
}

void smbXsrv_connection_disconnect_transport(struct smbXsrv_connection *xconn,
					     NTSTATUS status)
{
	if (!NT_STATUS_IS_OK(xconn->transport.status)) {
		return;
	}

	xconn->transport.status = status;
	TALLOC_FREE(xconn->transport.fde);
	if (xconn->transport.sock != -1) {
		xconn->transport.sock = -1;
	}
	smbd_smb2_send_queue_ack_fail(&xconn->ack.queue, status);
	smbd_smb2_send_queue_ack_fail(&xconn->smb2.send_queue, status);
	xconn->smb2.send_queue_len = 0;
	DO_PROFILE_INC(disconnect);
}

size_t smbXsrv_client_valid_connections(struct smbXsrv_client *client)
{
	struct smbXsrv_connection *xconn = NULL;
	size_t num_ok = 0;

	for (xconn = client->connections; xconn != NULL; xconn = xconn->next) {
		if (NT_STATUS_IS_OK(xconn->transport.status)) {
			num_ok++;
		}
	}

	return num_ok;
}

struct smbXsrv_connection_shutdown_state {
	struct tevent_queue *wait_queue;
};

static void smbXsrv_connection_shutdown_wait_done(struct tevent_req *subreq);

static struct tevent_req *smbXsrv_connection_shutdown_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbXsrv_connection *xconn)
{
	struct tevent_req *req = NULL;
	struct smbXsrv_connection_shutdown_state *state = NULL;
	struct tevent_req *subreq = NULL;
	size_t len = 0;
	struct smbd_smb2_request *preq = NULL;
	NTSTATUS status;

	/*
	 * The caller should have called
	 * smbXsrv_connection_disconnect_transport() before.
	 */
	SMB_ASSERT(!NT_STATUS_IS_OK(xconn->transport.status));

	req = tevent_req_create(mem_ctx, &state,
				struct smbXsrv_connection_shutdown_state);
	if (req == NULL) {
		return NULL;
	}

	status = smbXsrv_session_disconnect_xconn(xconn);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	state->wait_queue = tevent_queue_create(state, "smbXsrv_connection_shutdown_queue");
	if (tevent_req_nomem(state->wait_queue, req)) {
		return tevent_req_post(req, ev);
	}

	for (preq = xconn->smb2.requests; preq != NULL; preq = preq->next) {
		/*
		 * The connection is gone so we
		 * don't need to take care of
		 * any crypto
		 */
		preq->session = NULL;
		preq->do_signing = false;
		preq->do_encryption = false;
		preq->preauth = NULL;

		if (preq->subreq != NULL) {
			tevent_req_cancel(preq->subreq);
		}

		/*
		 * Now wait until the request is finished.
		 *
		 * We don't set a callback, as we just want to block the
		 * wait queue and the talloc_free() of the request will
		 * remove the item from the wait queue.
		 */
		subreq = tevent_queue_wait_send(preq, ev, state->wait_queue);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
	}

	len = tevent_queue_length(state->wait_queue);
	if (len == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	/*
	 * Now we add our own waiter to the end of the queue,
	 * this way we get notified when all pending requests are finished
	 * and send to the socket.
	 */
	subreq = tevent_queue_wait_send(state, ev, state->wait_queue);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smbXsrv_connection_shutdown_wait_done, req);

	return req;
}

static void smbXsrv_connection_shutdown_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);

	tevent_queue_wait_recv(subreq);
	TALLOC_FREE(subreq);

	tevent_req_done(req);
}

static NTSTATUS smbXsrv_connection_shutdown_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static void smbd_server_connection_terminate_done(struct tevent_req *subreq)
{
	struct smbXsrv_connection *xconn =
		tevent_req_callback_data(subreq,
		struct smbXsrv_connection);
	struct smbXsrv_client *client = xconn->client;
	NTSTATUS status;

	status = smbXsrv_connection_shutdown_recv(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		exit_server("smbXsrv_connection_shutdown_recv failed");
	}

	DLIST_REMOVE(client->connections, xconn);
	TALLOC_FREE(xconn);
}

void smbd_server_connection_terminate_ex(struct smbXsrv_connection *xconn,
					 const char *reason,
					 const char *location)
{
	struct smbXsrv_client *client = xconn->client;
	size_t num_ok = 0;

	/*
	 * Make sure that no new request will be able to use this session.
	 *
	 * smbXsrv_connection_disconnect_transport() might be called already,
	 * but calling it again is a no-op.
	 */
	smbXsrv_connection_disconnect_transport(xconn,
					NT_STATUS_CONNECTION_DISCONNECTED);

	num_ok = smbXsrv_client_valid_connections(client);

	DBG_DEBUG("conn[%s] num_ok[%zu] reason[%s] at %s\n",
		  smbXsrv_connection_dbg(xconn), num_ok,
		  reason, location);

	if (xconn->has_ctdb_public_ip) {
		/*
		 * If the connection has a ctdb public address
		 * we disconnect all client connections,
		 * as the public address might be moved to
		 * a different node.
		 *
		 * In future we may recheck which node currently
		 * holds this address, but for now we keep it simple.
		 */
		smbd_server_disconnect_client_ex(xconn->client,
						 reason,
						 location);
		return;
	}

	if (num_ok != 0) {
		struct tevent_req *subreq = NULL;

		subreq = smbXsrv_connection_shutdown_send(client,
							  client->raw_ev_ctx,
							  xconn);
		if (subreq == NULL) {
			exit_server("smbXsrv_connection_shutdown_send failed");
		}
		tevent_req_set_callback(subreq,
					smbd_server_connection_terminate_done,
					xconn);
		return;
	}

	/*
	 * The last connection was disconnected
	 */
	exit_server_cleanly(reason);
}

void smbd_server_disconnect_client_ex(struct smbXsrv_client *client,
				      const char *reason,
				      const char *location)
{
	size_t num_ok = 0;

	num_ok = smbXsrv_client_valid_connections(client);

	DBG_WARNING("client[%s] num_ok[%zu] reason[%s] at %s\n",
		    client->global->remote_address, num_ok,
		    reason, location);

	/*
	 * Something bad happened we need to disconnect all connections.
	 */
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
	bool ok;

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

	ok = smb2_setup_nbt_length(newreq->out.vector,
				   newreq->out.vector_count);
	if (!ok) {
		TALLOC_FREE(newreq);
		return NULL;
	}

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
	bool ok;

	/* Create a new smb2 request we'll use
	   for the interim return. */
	nreq = dup_smb2_req(req);
	if (!nreq) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Lose the last X out vectors. They're the
	   ones we'll be using for the async reply. */
	nreq->out.vector_count -= SMBD_SMB2_NUM_IOV_PER_REQ;

	ok = smb2_setup_nbt_length(nreq->out.vector,
				   nreq->out.vector_count);
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

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
		struct smb2_signing_key key = {
			.blob = req->first_key,
		};
		status = smb2_signing_encrypt_pdu(&key,
					xconn->smb2.server.cipher,
					firsttf,
					nreq->out.vector_count - first_idx);
		smb2_signing_key_destructor(&key);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else if (req->last_key.length > 0) {
		struct smb2_signing_key key = {
			.blob = req->last_key,
		};

		status = smb2_signing_sign_pdu(&key,
					       xconn->protocol,
					       outhdr_v,
					       SMBD_SMB2_NUM_IOV_PER_REQ - 1);
		smb2_signing_key_destructor(&key);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	nreq->queue_entry.mem_ctx = nreq;
	nreq->queue_entry.vector = nreq->out.vector;
	nreq->queue_entry.count = nreq->out.vector_count;
	DLIST_ADD_END(xconn->smb2.send_queue, &nreq->queue_entry);
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

	if (req->async_internal || defer_time == 0) {
		/*
		 * An SMB2 request implementation wants to handle the request
		 * asynchronously "internally" while keeping synchronous
		 * behaviour for the SMB2 request. This means we don't send an
		 * interim response and we can allow processing of compound SMB2
		 * requests (cf the subsequent check) for all cases.
		 */
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

	/*
	 * smbd_smb2_request_pending_timer() just send a packet
	 * to the client and doesn't need any impersonation.
	 * So we use req->xconn->client->raw_ev_ctx instead
	 * of req->ev_ctx here.
	 */
	defer_endtime = timeval_current_ofs_usec(defer_time);
	req->async_te = tevent_add_timer(req->xconn->client->raw_ev_ctx,
					 req, defer_endtime,
					 smbd_smb2_request_pending_timer,
					 req);
	if (req->async_te == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static
struct smb2_signing_key *smbd_smb2_signing_key(struct smbXsrv_session *session,
					       struct smbXsrv_connection *xconn)
{
	struct smbXsrv_channel_global0 *c = NULL;
	NTSTATUS status;
	struct smb2_signing_key *key = NULL;

	status = smbXsrv_session_find_channel(session, xconn, &c);
	if (NT_STATUS_IS_OK(status)) {
		key = c->signing_key;
	}

	if (!smb2_signing_key_valid(key)) {
		key = session->global->signing_key;
	}

	return key;
}

static NTSTATUS smb2_get_new_nonce(struct smbXsrv_session *session,
				   uint64_t *new_nonce_high,
				   uint64_t *new_nonce_low)
{
	uint64_t nonce_high;
	uint64_t nonce_low;

	session->nonce_low += 1;
	if (session->nonce_low == 0) {
		session->nonce_low += 1;
		session->nonce_high += 1;
	}

	/*
	 * CCM and GCM algorithms must never have their
	 * nonce wrap, or the security of the whole
	 * communication and the keys is destroyed.
	 * We must drop the connection once we have
	 * transfered too much data.
	 *
	 * NOTE: We assume nonces greater than 8 bytes.
	 */
	if (session->nonce_high >= session->nonce_high_max) {
		return NT_STATUS_ENCRYPTION_FAILED;
	}

	nonce_high = session->nonce_high_random;
	nonce_high += session->nonce_high;
	nonce_low = session->nonce_low;

	*new_nonce_high = nonce_high;
	*new_nonce_low = nonce_low;
	return NT_STATUS_OK;
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
	uint8_t *hdr = NULL;
	uint8_t *body = NULL;
	uint8_t *dyn = NULL;
	uint32_t flags = 0;
	uint64_t message_id = 0;
	uint64_t async_id = 0;
	NTSTATUS status;
	bool ok;

	TALLOC_FREE(req->async_te);

	/* Ensure our final reply matches the interim one. */
	inhdr = SMBD_SMB2_IN_HDR_PTR(req);
	outhdr = SMBD_SMB2_OUT_HDR_PTR(req);
	flags = IVAL(outhdr, SMB2_HDR_FLAGS);
	message_id = BVAL(outhdr, SMB2_HDR_MESSAGE_ID);

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

	hdr = tf + SMB2_TF_HDR_SIZE;
	body = hdr + SMB2_HDR_BODY;
	dyn = body + 8;

	if (req->do_encryption) {
		uint64_t nonce_high = 0;
		uint64_t nonce_low = 0;
		uint64_t session_id = req->session->global->session_wire_id;

		status = smb2_get_new_nonce(req->session,
					    &nonce_high,
					    &nonce_low);
		if (!NT_STATUS_IS_OK(status)) {
			smbd_server_connection_terminate(xconn,
							 nt_errstr(status));
			return;
		}

		SIVAL(tf, SMB2_TF_PROTOCOL_ID, SMB2_TF_MAGIC);
		SBVAL(tf, SMB2_TF_NONCE+0, nonce_low);
		SBVAL(tf, SMB2_TF_NONCE+8, nonce_high);
		SBVAL(tf, SMB2_TF_SESSION_ID, session_id);
	}

	SIVAL(hdr, SMB2_HDR_PROTOCOL_ID, SMB2_MAGIC);
	SSVAL(hdr, SMB2_HDR_LENGTH, SMB2_HDR_BODY);
	SSVAL(hdr, SMB2_HDR_EPOCH, 0);
	SIVAL(hdr, SMB2_HDR_STATUS, NT_STATUS_V(NT_STATUS_PENDING));
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
		state->vector[1+SMBD_SMB2_TF_IOV_OFS].iov_len    =
							SMB2_TF_HDR_SIZE;
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

	ok = smb2_setup_nbt_length(state->vector,
				   1 + SMBD_SMB2_NUM_IOV_PER_REQ);
	if (!ok) {
		smbd_server_connection_terminate(
			xconn, nt_errstr(NT_STATUS_INTERNAL_ERROR));
		return;
	}

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
		struct smb2_signing_key *encryption_key = x->global->encryption_key;

		status = smb2_signing_encrypt_pdu(encryption_key,
					xconn->smb2.server.cipher,
					&state->vector[1+SMBD_SMB2_TF_IOV_OFS],
					SMBD_SMB2_NUM_IOV_PER_REQ);
		if (!NT_STATUS_IS_OK(status)) {
			smbd_server_connection_terminate(xconn,
						nt_errstr(status));
			return;
		}
	} else if (req->do_signing) {
		struct smbXsrv_session *x = req->session;
		struct smb2_signing_key *signing_key =
			smbd_smb2_signing_key(x, xconn);

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
	DLIST_ADD_END(xconn->smb2.send_queue, &state->queue_entry);
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
	 * We don't need the request anymore cancel requests never
	 * have a response.
	 *
	 * We defer the TALLOC_FREE(req) to the caller.
	 */
	DLIST_REMOVE(xconn->smb2.requests, req);

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

	if (!change_to_user_and_service(
		    tcon->compat,
		    req->session->global->session_wire_id))
	{
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

	/* look an existing session up */
	switch (in_opcode) {
	case SMB2_OP_SESSSETUP:
		/*
		 * For a session bind request, we don't have the
		 * channel set up at this point yet, so we defer
		 * the verification that the connection belongs
		 * to the session to the session setup code, which
		 * can look at the session binding flags.
		 */
		status = smb2srv_session_lookup_client(req->xconn->client,
						       in_session_id, now,
						       &session);
		break;
	default:
		status = smb2srv_session_lookup_conn(req->xconn,
						     in_session_id, now,
						     &session);
		break;
	}
	if (session) {
		req->session = session;
		req->last_session_id = in_session_id;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_SESSION_EXPIRED)) {
		switch (in_opcode) {
		case SMB2_OP_SESSSETUP:
			status = NT_STATUS_OK;
			break;
		case SMB2_OP_LOGOFF:
		case SMB2_OP_CLOSE:
		case SMB2_OP_LOCK:
		case SMB2_OP_CANCEL:
		case SMB2_OP_KEEPALIVE:
			/*
			 * [MS-SMB2] 3.3.5.2.9 Verifying the Session
			 * specifies that LOGOFF, CLOSE and (UN)LOCK
			 * should always be processed even on expired sessions.
			 *
			 * Also see the logic in
			 * smbd_smb2_request_process_lock().
			 *
			 * The smb2.session.expire2 test shows that
			 * CANCEL and KEEPALIVE/ECHO should also
			 * be processed.
			 */
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

	DBGC_DEBUG(DBGC_SMB2_CREDITS,
		   "mid %llu, CreditCharge: %d, NeededCharge: %d\n",
		   (unsigned long long) BVAL(inhdr, SMB2_HDR_MESSAGE_ID),
		   credit_charge, needed_charge);

	if (needed_charge > credit_charge) {
		DBGC_WARNING(DBGC_SMB2_CREDITS,
			  "CreditCharge too low, given %d, needed %d\n",
			  credit_charge, needed_charge);
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
	case SMB2_OP_WRITE:
		min_dyn_size = 0;
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

bool smbXsrv_is_encrypted(uint8_t encryption_flags)
{
	return (!(encryption_flags & SMBXSRV_PROCESSED_UNENCRYPTED_PACKET)
		&&
		(encryption_flags & (SMBXSRV_PROCESSED_ENCRYPTED_PACKET |
				     SMBXSRV_ENCRYPTION_DESIRED |
				     SMBXSRV_ENCRYPTION_REQUIRED)));
}

bool smbXsrv_is_partially_encrypted(uint8_t encryption_flags)
{
	return ((encryption_flags & SMBXSRV_PROCESSED_ENCRYPTED_PACKET) &&
		(encryption_flags & SMBXSRV_PROCESSED_UNENCRYPTED_PACKET));
}

/* Set a flag if not already set, return true if set */
bool smbXsrv_set_crypto_flag(uint8_t *flags, uint8_t flag)
{
	if ((flag == 0) || (*flags & flag)) {
		return false;
	}

	*flags |= flag;
	return true;
}

/*
 * Update encryption state tracking flags, this can be used to
 * determine whether whether the session or tcon is "encrypted".
 */
static void smb2srv_update_crypto_flags(struct smbd_smb2_request *req,
					uint16_t opcode,
					bool *update_session_globalp,
					bool *update_tcon_globalp)
{
	/* Default: assume unecrypted and unsigned */
	struct smbXsrv_session *session = req->session;
	struct smbXsrv_tcon *tcon = req->tcon;
	uint8_t encrypt_flag = SMBXSRV_PROCESSED_UNENCRYPTED_PACKET;
	uint8_t sign_flag = SMBXSRV_PROCESSED_UNSIGNED_PACKET;
	bool update_session = false;
	bool update_tcon = false;

	if (req->was_encrypted && req->do_encryption) {
		encrypt_flag = SMBXSRV_PROCESSED_ENCRYPTED_PACKET;
		sign_flag = SMBXSRV_PROCESSED_SIGNED_PACKET;
	} else {
		/* Unencrypted packet, can be signed */
		if (req->do_signing) {
			sign_flag = SMBXSRV_PROCESSED_SIGNED_PACKET;
		} else if (opcode == SMB2_OP_CANCEL) {
			/* Cancel requests are allowed to skip signing */
			sign_flag &= ~SMBXSRV_PROCESSED_UNSIGNED_PACKET;
		}
	}

	update_session |= smbXsrv_set_crypto_flag(
		&session->global->encryption_flags, encrypt_flag);
	update_session |= smbXsrv_set_crypto_flag(
		&session->global->signing_flags, sign_flag);

	if (tcon) {
		update_tcon |= smbXsrv_set_crypto_flag(
			&tcon->global->encryption_flags, encrypt_flag);
		update_tcon |= smbXsrv_set_crypto_flag(
			&tcon->global->signing_flags, sign_flag);
	}

	*update_session_globalp = update_session;
	*update_tcon_globalp = update_tcon;
	return;
}

bool smbXsrv_is_signed(uint8_t signing_flags)
{
	/*
	 * Signing is always enabled, so unless we got an unsigned
	 * packet and at least one signed packet that was not
	 * encrypted, the session or tcon is "signed".
	 */
	return (!(signing_flags & SMBXSRV_PROCESSED_UNSIGNED_PACKET) &&
		(signing_flags & SMBXSRV_PROCESSED_SIGNED_PACKET));
}

bool smbXsrv_is_partially_signed(uint8_t signing_flags)
{
	return ((signing_flags & SMBXSRV_PROCESSED_UNSIGNED_PACKET) &&
		(signing_flags & SMBXSRV_PROCESSED_SIGNED_PACKET));
}

static NTSTATUS smbd_smb2_request_dispatch_update_counts(
				struct smbd_smb2_request *req,
				bool modify_call)
{
	struct smbXsrv_connection *xconn = req->xconn;
	const uint8_t *inhdr;
	uint16_t channel_sequence;
	uint8_t generation_wrap = 0;
	uint32_t flags;
	int cmp;
	struct smbXsrv_open *op;
	bool update_open = false;
	NTSTATUS status = NT_STATUS_OK;

	SMB_ASSERT(!req->request_counters_updated);

	if (xconn->protocol < PROTOCOL_SMB2_22) {
		return NT_STATUS_OK;
	}

	if (req->compat_chain_fsp == NULL) {
		return NT_STATUS_OK;
	}

	op = req->compat_chain_fsp->op;
	if (op == NULL) {
		return NT_STATUS_OK;
	}

	inhdr = SMBD_SMB2_IN_HDR_PTR(req);
	flags = IVAL(inhdr, SMB2_HDR_FLAGS);
	channel_sequence = SVAL(inhdr, SMB2_HDR_CHANNEL_SEQUENCE);

	cmp = channel_sequence - op->global->channel_sequence;
	if (cmp < 0) {
		/*
		 * csn wrap. We need to watch out for long-running
		 * requests that are still sitting on a previously
		 * used csn. SMB2_OP_NOTIFY can take VERY long.
		 */
		generation_wrap += 1;
	}

	if (abs(cmp) > INT16_MAX) {
		/*
		 * [MS-SMB2] 3.3.5.2.10 - Verifying the Channel Sequence Number:
		 *
		 * If the channel sequence number of the request and the one
		 * known to the server are not equal, the channel sequence
		 * number and outstanding request counts are only updated
		 * "... if the unsigned difference using 16-bit arithmetic
		 * between ChannelSequence and Open.ChannelSequence is less than
		 * or equal to 0x7FFF ...".
		 * Otherwise, an error is returned for the modifying
		 * calls write, set_info, and ioctl.
		 *
		 * There are currently two issues with the description:
		 *
		 * * For the other calls, the document seems to imply
		 *   that processing continues without adapting the
		 *   counters (if the sequence numbers are not equal).
		 *
		 *   TODO: This needs clarification!
		 *
		 * * Also, the behaviour if the difference is larger
		 *   than 0x7FFF is not clear. The document seems to
		 *   imply that if such a difference is reached,
		 *   the server starts to ignore the counters or
		 *   in the case of the modifying calls, return errors.
		 *
		 *   TODO: This needs clarification!
		 *
		 * At this point Samba tries to be a little more
		 * clever than the description in the MS-SMB2 document
		 * by heuristically detecting and properly treating
		 * a 16 bit overflow of the client-submitted sequence
		 * number:
		 *
		 * If the stored channel sequence number is more than
		 * 0x7FFF larger than the one from the request, then
		 * the client-provided sequence number has likely
		 * overflown. We treat this case as valid instead
		 * of as failure.
		 *
		 * The MS-SMB2 behaviour would be setting cmp = -1.
		 */
		cmp *= -1;
	}

	if (flags & SMB2_HDR_FLAG_REPLAY_OPERATION) {
		if (cmp == 0 && op->pre_request_count == 0) {
			op->request_count += 1;
			req->request_counters_updated = true;
		} else if (cmp > 0 && op->pre_request_count == 0) {
			op->pre_request_count += op->request_count;
			op->request_count = 1;
			op->global->channel_sequence = channel_sequence;
			op->global->channel_generation += generation_wrap;
			update_open = true;
			req->request_counters_updated = true;
		} else if (modify_call) {
			return NT_STATUS_FILE_NOT_AVAILABLE;
		}
	} else {
		if (cmp == 0) {
			op->request_count += 1;
			req->request_counters_updated = true;
		} else if (cmp > 0) {
			op->pre_request_count += op->request_count;
			op->request_count = 1;
			op->global->channel_sequence = channel_sequence;
			op->global->channel_generation += generation_wrap;
			update_open = true;
			req->request_counters_updated = true;
		} else if (modify_call) {
			return NT_STATUS_FILE_NOT_AVAILABLE;
		}
	}
	req->channel_generation = op->global->channel_generation;

	if (update_open) {
		status = smbXsrv_open_update(op);
	}

	return status;
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
	bool encryption_desired = false;
	bool encryption_required = false;

	inhdr = SMBD_SMB2_IN_HDR_PTR(req);

	DO_PROFILE_INC(request);

	SMB_ASSERT(!req->request_counters_updated);

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
	 * Check if the client provided a valid session id.
	 *
	 * As some command don't require a valid session id
	 * we defer the check of the session_status
	 */
	session_status = smbd_smb2_request_check_session(req);
	x = req->session;
	if (x != NULL) {
		signing_required = x->global->signing_flags & SMBXSRV_SIGNING_REQUIRED;
		encryption_desired = x->global->encryption_flags & SMBXSRV_ENCRYPTION_DESIRED;
		encryption_required = x->global->encryption_flags & SMBXSRV_ENCRYPTION_REQUIRED;
	}

	req->async_internal = false;
	req->do_signing = false;
	if (opcode != SMB2_OP_SESSSETUP) {
		req->do_encryption = encryption_desired;
	} else {
		req->do_encryption = false;
	}
	req->was_encrypted = false;
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

		req->was_encrypted = true;
		req->do_encryption = true;
	}

	if (encryption_required && !req->was_encrypted) {
		req->do_encryption = true;
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
	if (xconn->protocol >= PROTOCOL_SMB3_11) {
		allowed_flags |= SMB2_HDR_FLAG_PRIORITY_MASK;
	}
	if (opcode == SMB2_OP_NEGPROT) {
		if (lp_server_max_protocol() >= PROTOCOL_SMB3_11) {
			allowed_flags |= SMB2_HDR_FLAG_PRIORITY_MASK;
		}
	}
	if (opcode == SMB2_OP_CANCEL) {
		allowed_flags |= SMB2_HDR_FLAG_ASYNC;
	}
	if (xconn->protocol >= PROTOCOL_SMB2_22) {
		allowed_flags |= SMB2_HDR_FLAG_REPLAY_OPERATION;
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

	if (req->was_encrypted) {
		signing_required = false;
	} else if (signing_required || (flags & SMB2_HDR_FLAG_SIGNED)) {
		struct smb2_signing_key *signing_key = NULL;

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
		if (smb2_signing_key_valid(signing_key)) {
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
	} else if (opcode == SMB2_OP_IOCTL) {
		/*
		 * Some special IOCTL calls don't require
		 * file, tcon nor session.
		 *
		 * They typically don't do any real action
		 * on behalf of the client.
		 *
		 * They are mainly used to alter the behavior
		 * of the connection for testing. So we can
		 * run as root and skip all file, tcon and session
		 * checks below.
		 */
		static const struct smbd_smb2_dispatch_table _root_ioctl_call = {
			_OP(SMB2_OP_IOCTL),
			.as_root = true,
		};
		const uint8_t *body = SMBD_SMB2_IN_BODY_PTR(req);
		size_t body_size = SMBD_SMB2_IN_BODY_LEN(req);
		uint32_t in_ctl_code;
		size_t needed = 4;

		if (needed > body_size) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}

		in_ctl_code = IVAL(body, 0x04);
		/*
		 * Only add trusted IOCTL codes here!
		 */
		switch (in_ctl_code) {
		case FSCTL_SMBTORTURE_FORCE_UNACKED_TIMEOUT:
			call = &_root_ioctl_call;
			break;
		}
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
		 * Which implies set_current_user_info()
		 * and chdir_current_service().
		 */
		status = smbd_smb2_request_check_tcon(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		if (req->tcon->global->encryption_flags & SMBXSRV_ENCRYPTION_DESIRED) {
			encryption_desired = true;
		}
		if (req->tcon->global->encryption_flags & SMBXSRV_ENCRYPTION_REQUIRED) {
			encryption_required = true;
		}
		if (encryption_required && !req->was_encrypted) {
			req->do_encryption = true;
			return smbd_smb2_request_error(req,
				NT_STATUS_ACCESS_DENIED);
		} else if (encryption_desired) {
			req->do_encryption = true;
		}
	} else if (call->need_session) {
		struct auth_session_info *session_info = NULL;

		/*
		 * Unless we also have need_tcon (see above),
		 * we still need to call set_current_user_info().
		 */

		session_info = req->session->global->auth_session_info;
		if (session_info == NULL) {
			return NT_STATUS_INVALID_HANDLE;
		}

		set_current_user_info(session_info->unix_info->sanitized_username,
				      session_info->unix_info->unix_name,
				      session_info->info->domain_name);
	}

	if (req->session) {
		bool update_session_global = false;
		bool update_tcon_global = false;

		smb2srv_update_crypto_flags(req, opcode,
					    &update_session_global,
					    &update_tcon_global);

		if (update_session_global) {
			status = smbXsrv_session_update(x);
			if (!NT_STATUS_IS_OK(status)) {
				return smbd_smb2_request_error(req, status);
			}
		}
		if (update_tcon_global) {
			status = smbXsrv_tcon_update(req->tcon);
			if (!NT_STATUS_IS_OK(status)) {
				return smbd_smb2_request_error(req, status);
			}
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

	status = smbd_smb2_request_dispatch_update_counts(req, call->modify);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	if (call->as_root) {
		SMB_ASSERT(call->fileid_ofs == 0);
		/* This call needs to be run as root */
		change_to_root_user();
	} else {
		SMB_ASSERT(call->need_tcon);
	}

#define _INBYTES(_r) \
	iov_buflen(SMBD_SMB2_IN_HDR_IOV(_r), SMBD_SMB2_NUM_IOV_PER_REQ-1)

	switch (opcode) {
	case SMB2_OP_NEGPROT:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_negprot, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_negprot(req);
		break;

	case SMB2_OP_SESSSETUP:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_sesssetup, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_sesssetup(req);
		break;

	case SMB2_OP_LOGOFF:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_logoff, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_logoff(req);
		break;

	case SMB2_OP_TCON:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_tcon, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_tcon(req);
		break;

	case SMB2_OP_TDIS:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_tdis, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_tdis(req);
		break;

	case SMB2_OP_CREATE:
		if (req->subreq == NULL) {
			SMBPROFILE_IOBYTES_ASYNC_START(smb2_create, profile_p,
						       req->profile, _INBYTES(req));
		} else {
			SMBPROFILE_IOBYTES_ASYNC_SET_BUSY(req->profile);
		}
		return_value = smbd_smb2_request_process_create(req);
		break;

	case SMB2_OP_CLOSE:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_close, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_close(req);
		break;

	case SMB2_OP_FLUSH:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_flush, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_flush(req);
		break;

	case SMB2_OP_READ:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_read, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_read(req);
		break;

	case SMB2_OP_WRITE:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_write, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_write(req);
		break;

	case SMB2_OP_LOCK:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_lock, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_lock(req);
		break;

	case SMB2_OP_IOCTL:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_ioctl, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_ioctl(req);
		break;

	case SMB2_OP_CANCEL:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_cancel, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_cancel(req);
		SMBPROFILE_IOBYTES_ASYNC_END(req->profile, 0);

		/*
		 * We don't need the request anymore cancel requests never
		 * have a response.
		 *
		 * smbd_smb2_request_process_cancel() already called
		 * DLIST_REMOVE(xconn->smb2.requests, req);
		 */
		TALLOC_FREE(req);

		break;

	case SMB2_OP_KEEPALIVE:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_keepalive, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_keepalive(req);
		break;

	case SMB2_OP_QUERY_DIRECTORY:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_find, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_query_directory(req);
		break;

	case SMB2_OP_NOTIFY:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_notify, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_notify(req);
		break;

	case SMB2_OP_GETINFO:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_getinfo, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_getinfo(req);
		break;

	case SMB2_OP_SETINFO:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_setinfo, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_setinfo(req);
		break;

	case SMB2_OP_BREAK:
		SMBPROFILE_IOBYTES_ASYNC_START(smb2_break, profile_p,
					       req->profile, _INBYTES(req));
		return_value = smbd_smb2_request_process_break(req);
		break;

	default:
		return_value = smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
		break;
	}
	return return_value;
}

static void smbd_smb2_request_reply_update_counts(struct smbd_smb2_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;
	const uint8_t *inhdr;
	uint16_t channel_sequence;
	struct smbXsrv_open *op;

	if (!req->request_counters_updated) {
		return;
	}

	req->request_counters_updated = false;

	if (xconn->protocol < PROTOCOL_SMB2_22) {
		return;
	}

	if (req->compat_chain_fsp == NULL) {
		return;
	}

	op = req->compat_chain_fsp->op;
	if (op == NULL) {
		return;
	}

	inhdr = SMBD_SMB2_IN_HDR_PTR(req);
	channel_sequence = SVAL(inhdr, SMB2_HDR_CHANNEL_SEQUENCE);

	if ((op->global->channel_sequence == channel_sequence) &&
	    (op->global->channel_generation == req->channel_generation)) {
		SMB_ASSERT(op->request_count > 0);
		op->request_count -= 1;
	} else {
		SMB_ASSERT(op->pre_request_count > 0);
		op->pre_request_count -= 1;
	}
}

static NTSTATUS smbd_smb2_request_reply(struct smbd_smb2_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;
	int first_idx = 1;
	struct iovec *firsttf = SMBD_SMB2_IDX_TF_IOV(req,out,first_idx);
	struct iovec *outhdr = SMBD_SMB2_OUT_HDR_IOV(req);
	struct iovec *outdyn = SMBD_SMB2_OUT_DYN_IOV(req);
	NTSTATUS status;
	bool ok;

	req->subreq = NULL;
	TALLOC_FREE(req->async_te);

	/* MS-SMB2: 3.3.4.1 Sending Any Outgoing Message */
	smbd_smb2_request_reply_update_counts(req);

	if (req->do_encryption &&
	    (firsttf->iov_len == 0) &&
	    (req->first_key.length == 0) &&
	    (req->session != NULL) &&
	    smb2_signing_key_valid(req->session->global->encryption_key))
	{
		struct smb2_signing_key *encryption_key =
			req->session->global->encryption_key;
		uint8_t *tf;
		uint64_t session_id = req->session->global->session_wire_id;
		uint64_t nonce_high;
		uint64_t nonce_low;

		status = smb2_get_new_nonce(req->session,
					    &nonce_high,
					    &nonce_low);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
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
		req->first_key = data_blob_dup_talloc(req,
						      encryption_key->blob);
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
		struct smb2_signing_key key = {
			.blob = req->last_key,
		};

		/*
		 * As we are sure the header of the last request in the
		 * compound chain will not change, we can to sign here
		 * with the last signing key we remembered.
		 */
		status = smb2_signing_sign_pdu(&key,
					       xconn->protocol,
					       lasthdr,
					       SMBD_SMB2_NUM_IOV_PER_REQ - 1);
		smb2_signing_key_destructor(&key);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	if (req->last_key.length > 0) {
		data_blob_clear_free(&req->last_key);
	}

	SMBPROFILE_IOBYTES_ASYNC_END(req->profile,
		iov_buflen(outhdr, SMBD_SMB2_NUM_IOV_PER_REQ-1));

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
			struct smb2_signing_key *signing_key =
				smbd_smb2_signing_key(x, xconn);

			/*
			 * we need to remember the signing key
			 * and defer the signing until
			 * we are sure that we do not change
			 * the header again.
			 */
			req->last_key = data_blob_dup_talloc(req,
							     signing_key->blob);
			if (req->last_key.data == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		}

		/*
		 * smbd_smb2_request_dispatch() will redo the impersonation.
		 * So we use req->xconn->client->raw_ev_ctx instead
		 * of req->ev_ctx here.
		 */
		tevent_schedule_immediate(im,
					req->xconn->client->raw_ev_ctx,
					smbd_smb2_request_dispatch_immediate,
					req);
		return NT_STATUS_OK;
	}

	if (req->compound_related) {
		req->compound_related = false;
	}

	ok = smb2_setup_nbt_length(req->out.vector, req->out.vector_count);
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	/* Set credit for these operations (zero credits if this
	   is a final reply for an async operation). */
	smb2_calculate_credits(req, req);

	/*
	 * now check if we need to sign the current response
	 */
	if (firsttf->iov_len == SMB2_TF_HDR_SIZE) {
		struct smb2_signing_key key = {
			.blob = req->first_key,
		};
		status = smb2_signing_encrypt_pdu(&key,
					xconn->smb2.server.cipher,
					firsttf,
					req->out.vector_count - first_idx);
		smb2_signing_key_destructor(&key);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else if (req->do_signing) {
		struct smbXsrv_session *x = req->session;
		struct smb2_signing_key *signing_key =
			smbd_smb2_signing_key(x, xconn);

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

	if (req->preauth != NULL) {
		gnutls_hash_hd_t hash_hnd = NULL;
		size_t i;
		int rc;

		rc = gnutls_hash_init(&hash_hnd, GNUTLS_DIG_SHA512);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
		}
		rc = gnutls_hash(hash_hnd,
			    req->preauth->sha512_value,
			    sizeof(req->preauth->sha512_value));
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
		}
		for (i = 1; i < req->in.vector_count; i++) {
			rc = gnutls_hash(hash_hnd,
					 req->in.vector[i].iov_base,
					 req->in.vector[i].iov_len);
			if (rc < 0) {
				gnutls_hash_deinit(hash_hnd, NULL);
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
			}
		}
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
		}
		gnutls_hash_output(hash_hnd, req->preauth->sha512_value);

		rc = gnutls_hash(hash_hnd,
				 req->preauth->sha512_value,
				 sizeof(req->preauth->sha512_value));
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
		}
		for (i = 1; i < req->out.vector_count; i++) {
			rc = gnutls_hash(hash_hnd,
					 req->out.vector[i].iov_base,
					 req->out.vector[i].iov_len);
			if (rc < 0) {
				gnutls_hash_deinit(hash_hnd, NULL);
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
			}
		}

		gnutls_hash_deinit(hash_hnd, req->preauth->sha512_value);

		req->preauth = NULL;
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
	DLIST_ADD_END(xconn->smb2.send_queue, &req->queue_entry);
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
	uint64_t mid;

	outhdr = SMBD_SMB2_OUT_HDR_PTR(req);
	mid = BVAL(outhdr, SMB2_HDR_MESSAGE_ID);

	DBG_DEBUG("mid [%"PRIu64"] idx[%d] status[%s] "
		  "body[%u] dyn[%s:%u] at %s\n",
		  mid,
		  req->current_idx,
		  nt_errstr(status),
		  (unsigned int)body.length,
		  dyn ? "yes" : "no",
		  (unsigned int)(dyn ? dyn->length : 0),
		  location);

	if (body.length < 2) {
		return smbd_smb2_request_error(req, NT_STATUS_INTERNAL_ERROR);
	}

	if ((body.length % 2) != 0) {
		return smbd_smb2_request_error(req, NT_STATUS_INTERNAL_ERROR);
	}

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

	DBG_NOTICE("smbd_smb2_request_error_ex: idx[%d] status[%s] |%s| "
		   "at %s\n", req->current_idx, nt_errstr(status),
		   info ? " +info" : "", location);

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

struct smbd_smb2_break_state {
	struct tevent_req *req;
	struct smbd_smb2_send_queue queue_entry;
	uint8_t nbt_hdr[NBT_HDR_SIZE];
	uint8_t hdr[SMB2_HDR_BODY];
	struct iovec vector[1+SMBD_SMB2_NUM_IOV_PER_REQ];
};

static struct tevent_req *smbd_smb2_break_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct smbXsrv_connection *xconn,
					       uint64_t session_id,
					       const uint8_t *body,
					       size_t body_len)
{
	struct tevent_req *req = NULL;
	struct smbd_smb2_break_state *state = NULL;
	NTSTATUS status;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_break_state);
	if (req == NULL) {
		return NULL;
	}

	state->req = req;
	tevent_req_defer_callback(req, ev);

	SIVAL(state->hdr, 0,				SMB2_MAGIC);
	SSVAL(state->hdr, SMB2_HDR_LENGTH,		SMB2_HDR_BODY);
	SSVAL(state->hdr, SMB2_HDR_EPOCH,		0);
	SIVAL(state->hdr, SMB2_HDR_STATUS,		0);
	SSVAL(state->hdr, SMB2_HDR_OPCODE,		SMB2_OP_BREAK);
	SSVAL(state->hdr, SMB2_HDR_CREDIT,		0);
	SIVAL(state->hdr, SMB2_HDR_FLAGS,		SMB2_HDR_FLAG_REDIRECT);
	SIVAL(state->hdr, SMB2_HDR_NEXT_COMMAND,	0);
	SBVAL(state->hdr, SMB2_HDR_MESSAGE_ID,		UINT64_MAX);
	SIVAL(state->hdr, SMB2_HDR_PID,			0);
	SIVAL(state->hdr, SMB2_HDR_TID,			0);
	SBVAL(state->hdr, SMB2_HDR_SESSION_ID,		session_id);
	memset(state->hdr+SMB2_HDR_SIGNATURE, 0, 16);

	state->vector[0] = (struct iovec) {
		.iov_base = state->nbt_hdr,
		.iov_len  = sizeof(state->nbt_hdr)
	};

	state->vector[1+SMBD_SMB2_TF_IOV_OFS] = (struct iovec) {
		.iov_base = NULL,
		.iov_len  = 0
	};

	state->vector[1+SMBD_SMB2_HDR_IOV_OFS] = (struct iovec) {
		.iov_base = state->hdr,
		.iov_len  = sizeof(state->hdr)
	};

	state->vector[1+SMBD_SMB2_BODY_IOV_OFS] = (struct iovec) {
		.iov_base = discard_const_p(uint8_t, body),
		.iov_len  = body_len,
	};

	/*
	 * state->vector[1+SMBD_SMB2_DYN_IOV_OFS] is NULL by talloc_zero above
	 */

	ok = smb2_setup_nbt_length(state->vector,
				   1 + SMBD_SMB2_NUM_IOV_PER_REQ);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	/*
	 * We require TCP acks for this PDU to the client!
	 * We want 5 retransmissions and timeout when the
	 * retransmission timeout (rto) passed 6 times.
	 *
	 * required_acked_bytes gets a dummy value of
	 * UINT64_MAX, as long it's in xconn->smb2.send_queue,
	 * it'll get the real value when it's moved to
	 * xconn->ack.queue.
	 *
	 * state->queue_entry.ack.req gets completed with
	 * 1.  tevent_req_done(), when all bytes are acked.
	 * 2a. tevent_req_nterror(NT_STATUS_IO_TIMEOUT), when
	 *     the timeout expired before all bytes were acked.
	 * 2b. tevent_req_nterror(transport_error), when the
	 *     connection got a disconnect from the kernel.
	 */
	state->queue_entry.ack.timeout =
		timeval_current_ofs_usec(xconn->ack.rto_usecs * 6);
	state->queue_entry.ack.required_acked_bytes = UINT64_MAX;
	state->queue_entry.ack.req = req;
	state->queue_entry.mem_ctx = state;
	state->queue_entry.vector = state->vector;
	state->queue_entry.count = ARRAY_SIZE(state->vector);
	DLIST_ADD_END(xconn->smb2.send_queue, &state->queue_entry);
	xconn->smb2.send_queue_len++;

	status = smbd_smb2_flush_send_queue(xconn);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static NTSTATUS smbd_smb2_break_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct smbXsrv_pending_break {
	struct smbXsrv_pending_break *prev, *next;
	struct smbXsrv_client *client;
	bool disable_oplock_break_retries;
	uint64_t session_id;
	uint64_t last_channel_id;
	union {
		uint8_t generic[1];
		uint8_t oplock[0x18];
		uint8_t lease[0x2c];
	} body;
	size_t body_len;
};

static void smbXsrv_pending_break_done(struct tevent_req *subreq);

static struct smbXsrv_pending_break *smbXsrv_pending_break_create(
		struct smbXsrv_client *client,
		uint64_t session_id)
{
	struct smbXsrv_pending_break *pb = NULL;

	pb = talloc_zero(client, struct smbXsrv_pending_break);
	if (pb == NULL) {
		return NULL;
	}
	pb->client = client;
	pb->session_id = session_id;
	pb->disable_oplock_break_retries = lp_smb2_disable_oplock_break_retry();

	return pb;
}

static NTSTATUS smbXsrv_pending_break_submit(struct smbXsrv_pending_break *pb);

static NTSTATUS smbXsrv_pending_break_schedule(struct smbXsrv_pending_break *pb)
{
	struct smbXsrv_client *client = pb->client;
	NTSTATUS status;

	DLIST_ADD_END(client->pending_breaks, pb);
	status = smbXsrv_client_pending_breaks_updated(client);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = smbXsrv_pending_break_submit(pb);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS smbXsrv_pending_break_submit(struct smbXsrv_pending_break *pb)
{
	struct smbXsrv_client *client = pb->client;
	struct smbXsrv_session *session = NULL;
	struct smbXsrv_connection *xconn = NULL;
	struct smbXsrv_connection *oplock_xconn = NULL;
	struct tevent_req *subreq = NULL;
	NTSTATUS status;

	if (pb->session_id != 0) {
		status = get_valid_smbXsrv_session(client,
						   pb->session_id,
						   &session);
		if (NT_STATUS_EQUAL(status, NT_STATUS_USER_SESSION_DELETED)) {
			return NT_STATUS_ABANDONED;
		}
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		if (pb->last_channel_id != 0) {
			/*
			 * This is what current Windows servers
			 * do, they don't retry on all available
			 * channels. They only use the last channel.
			 *
			 * But it doesn't match the specification in
			 * [MS-SMB2] "3.3.4.6 Object Store Indicates an
			 * Oplock Break"
			 *
			 * Per default disable_oplock_break_retries is false
			 * and we behave like the specification.
			 */
			if (pb->disable_oplock_break_retries) {
				return NT_STATUS_ABANDONED;
			}
		}
	}

	for (xconn = client->connections; xconn != NULL; xconn = xconn->next) {
		if (!NT_STATUS_IS_OK(xconn->transport.status)) {
			continue;
		}

		if (xconn->channel_id == 0) {
			/*
			 * non-multichannel case
			 */
			break;
		}

		if (session != NULL) {
			struct smbXsrv_channel_global0 *c = NULL;

			/*
			 * Having a session means we're handling
			 * an oplock break and we only need to
			 * use channels available on the
			 * session.
			 */
			status = smbXsrv_session_find_channel(session, xconn, &c);
			if (!NT_STATUS_IS_OK(status)) {
				continue;
			}

			/*
			 * This is what current Windows servers
			 * do, they don't retry on all available
			 * channels. They only use the last channel.
			 *
			 * But it doesn't match the specification
			 * in [MS-SMB2] "3.3.4.6 Object Store Indicates an
			 * Oplock Break"
			 *
			 * Per default disable_oplock_break_retries is false
			 * and we behave like the specification.
			 */
			if (pb->disable_oplock_break_retries) {
				oplock_xconn = xconn;
				continue;
			}
		}

		if (xconn->channel_id > pb->last_channel_id) {
			/*
			 * multichannel case
			 */
			break;
		}
	}

	if (xconn == NULL) {
		xconn = oplock_xconn;
	}

	if (xconn == NULL) {
		/*
		 * If there's no remaining connection available
		 * tell the caller to stop...
		 */
		return NT_STATUS_ABANDONED;
	}

	pb->last_channel_id = xconn->channel_id;

	subreq = smbd_smb2_break_send(pb,
				      client->raw_ev_ctx,
				      xconn,
				      pb->session_id,
				      pb->body.generic,
				      pb->body_len);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq,
				smbXsrv_pending_break_done,
				pb);

	return NT_STATUS_OK;
}

static void smbXsrv_pending_break_done(struct tevent_req *subreq)
{
	struct smbXsrv_pending_break *pb =
		tevent_req_callback_data(subreq,
		struct smbXsrv_pending_break);
	struct smbXsrv_client *client = pb->client;
	NTSTATUS status;

	status = smbd_smb2_break_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		status = smbXsrv_pending_break_submit(pb);
		if (NT_STATUS_EQUAL(status, NT_STATUS_ABANDONED)) {
			/*
			 * If there's no remaing connection
			 * there's no need to send a break again.
			 */
			goto remove;
		}
		if (!NT_STATUS_IS_OK(status)) {
			smbd_server_disconnect_client(client, nt_errstr(status));
			return;
		}
		return;
	}

remove:
	DLIST_REMOVE(client->pending_breaks, pb);
	TALLOC_FREE(pb);

	status = smbXsrv_client_pending_breaks_updated(client);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_disconnect_client(client, nt_errstr(status));
		return;
	}
}

NTSTATUS smbd_smb2_send_oplock_break(struct smbXsrv_client *client,
				     struct smbXsrv_open *op,
				     uint8_t oplock_level)
{
	struct smbXsrv_pending_break *pb = NULL;
	uint8_t *body = NULL;

	pb = smbXsrv_pending_break_create(client,
					  op->compat->vuid);
	if (pb == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	pb->body_len = sizeof(pb->body.oplock);
	body = pb->body.oplock;

	SSVAL(body, 0x00, pb->body_len);
	SCVAL(body, 0x02, oplock_level);
	SCVAL(body, 0x03, 0);		/* reserved */
	SIVAL(body, 0x04, 0);		/* reserved */
	SBVAL(body, 0x08, op->global->open_persistent_id);
	SBVAL(body, 0x10, op->global->open_volatile_id);

	return smbXsrv_pending_break_schedule(pb);
}

NTSTATUS smbd_smb2_send_lease_break(struct smbXsrv_client *client,
				    uint16_t new_epoch,
				    uint32_t lease_flags,
				    struct smb2_lease_key *lease_key,
				    uint32_t current_lease_state,
				    uint32_t new_lease_state)
{
	struct smbXsrv_pending_break *pb = NULL;
	uint8_t *body = NULL;

	pb = smbXsrv_pending_break_create(client,
					  0); /* no session_id */
	if (pb == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	pb->body_len = sizeof(pb->body.lease);
	body = pb->body.lease;

	SSVAL(body, 0x00, pb->body_len);
	SSVAL(body, 0x02, new_epoch);
	SIVAL(body, 0x04, lease_flags);
	SBVAL(body, 0x08, lease_key->data[0]);
	SBVAL(body, 0x10, lease_key->data[1]);
	SIVAL(body, 0x18, current_lease_state);
	SIVAL(body, 0x1c, new_lease_state);
	SIVAL(body, 0x20, 0);		/* BreakReason, MUST be 0 */
	SIVAL(body, 0x24, 0);		/* AccessMaskHint, MUST be 0 */
	SIVAL(body, 0x28, 0);		/* ShareMaskHint, MUST be 0 */

	return smbXsrv_pending_break_schedule(pb);
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
	if (fsp->base_fsp != NULL) {
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

NTSTATUS smbd_smb2_process_negprot(struct smbXsrv_connection *xconn,
			       uint64_t expected_seq_low,
			       const uint8_t *inpdu, size_t size)
{
	struct smbd_server_connection *sconn = xconn->client->sconn;
	NTSTATUS status;
	struct smbd_smb2_request *req = NULL;

	DEBUG(10,("smbd_smb2_first_negprot: packet length %u\n",
		 (unsigned int)size));

	status = smbd_initialize_smb2(xconn, expected_seq_low);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return status;
	}

	/*
	 * If a new connection joins the process, when we're
	 * already in a "pending break cycle", we need to
	 * turn on the ack checker on the new connection.
	 */
	status = smbXsrv_client_pending_breaks_updated(xconn->client);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * If there's a problem, we disconnect the whole
		 * client with all connections here!
		 *
		 * Instead of just the new connection.
		 */
		smbd_server_disconnect_client(xconn->client, nt_errstr(status));
		return status;
	}

	status = smbd_smb2_request_create(xconn, inpdu, size, &req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return status;
	}

	status = smbd_smb2_request_validate(req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return status;
	}

	status = smbd_smb2_request_setup_out(req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return status;
	}

#ifdef WITH_PROFILE
	/*
	 * this was already counted at the SMB1 layer =>
	 * smbd_smb2_request_dispatch() should not count it twice.
	 */
	if (profile_p->values.request_stats.count > 0) {
		profile_p->values.request_stats.count--;
	}
#endif
	status = smbd_smb2_request_dispatch(req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return status;
	}

	status = smbd_smb2_request_next_incoming(xconn);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn, nt_errstr(status));
		return status;
	}

	sconn->num_requests++;
	return NT_STATUS_OK;
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
	NTSTATUS status;

	if (xconn->smb2.send_queue == NULL) {
		TEVENT_FD_NOT_WRITEABLE(xconn->transport.fde);
		return NT_STATUS_OK;
	}

	while (xconn->smb2.send_queue != NULL) {
		struct smbd_smb2_send_queue *e = xconn->smb2.send_queue;
		bool ok;
		struct msghdr msg;

		if (e->sendfile_header != NULL) {
			size_t size = 0;
			size_t i = 0;
			uint8_t *buf;

			status = NT_STATUS_INTERNAL_ERROR;

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

			size += e->sendfile_body_size;

			/*
			 * This triggers the sendfile path via
			 * the destructor.
			 */
			talloc_free(e->mem_ctx);

			if (!NT_STATUS_IS_OK(status)) {
				smbXsrv_connection_disconnect_transport(xconn,
									status);
				return status;
			}
			xconn->ack.unacked_bytes += size;
			continue;
		}

		msg = (struct msghdr) {
			.msg_iov = e->vector,
			.msg_iovlen = e->count,
		};

		ret = sendmsg(xconn->transport.sock, &msg, 0);
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
			status = map_nt_error_from_unix_common(err);
			smbXsrv_connection_disconnect_transport(xconn,
								status);
			return status;
		}

		xconn->ack.unacked_bytes += ret;

		ok = iov_advance(&e->vector, &e->count, ret);
		if (!ok) {
			return NT_STATUS_INTERNAL_ERROR;
		}

		if (e->count > 0) {
			/* we have more to write */
			TEVENT_FD_WRITEABLE(xconn->transport.fde);
			return NT_STATUS_OK;
		}

		xconn->smb2.send_queue_len--;
		DLIST_REMOVE(xconn->smb2.send_queue, e);

		if (e->ack.req == NULL) {
			talloc_free(e->mem_ctx);
			continue;
		}

		e->ack.required_acked_bytes = xconn->ack.unacked_bytes;
		DLIST_ADD_END(xconn->ack.queue, e);
	}

	/*
	 * Restart reads if we were blocked on
	 * draining the send queue.
	 */

	status = smbd_smb2_request_next_incoming(xconn);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
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
	struct msghdr msg;

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

	msg = (struct msghdr) {
		.msg_iov = &state->vector,
		.msg_iovlen = 1,
	};

	ret = recvmsg(xconn->transport.sock, &msg, 0);
	if (ret == 0) {
		/* propagate end of file */
		status = NT_STATUS_END_OF_FILE;
		smbXsrv_connection_disconnect_transport(xconn,
							status);
		return status;
	}
	err = socket_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		TEVENT_FD_READABLE(xconn->transport.fde);
		return NT_STATUS_OK;
	}
	if (err != 0) {
		status = map_nt_error_from_unix_common(err);
		smbXsrv_connection_disconnect_transport(xconn,
							status);
		return status;
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
