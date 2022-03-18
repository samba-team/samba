/*
   Unix SMB/CIFS implementation.
   process incoming packets - main loop
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Volker Lendecke 2005-2007

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
#include "../lib/tsocket/tsocket.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "smbd/smbXsrv_open.h"
#include "librpc/gen_ndr/netlogon.h"
#include "../lib/async_req/async_sock.h"
#include "ctdbd_conn.h"
#include "../lib/util/select.h"
#include "printing/queue_process.h"
#include "system/select.h"
#include "passdb.h"
#include "auth.h"
#include "messages.h"
#include "lib/messages_ctdb.h"
#include "smbprofile.h"
#include "rpc_server/spoolss/srv_spoolss_nt.h"
#include "../lib/util/tevent_ntstatus.h"
#include "../libcli/security/dom_sid.h"
#include "../libcli/security/security_token.h"
#include "lib/id_cache.h"
#include "lib/util/sys_rw_data.h"
#include "system/threads.h"
#include "lib/pthreadpool/pthreadpool_tevent.h"
#include "util_event.h"
#include "libcli/smb/smbXcli_base.h"
#include "lib/util/time_basic.h"
#include "smb1_utils.h"
#include "source3/lib/substitute.h"

/* Internal message queue for deferred opens. */
struct pending_message_list {
	struct pending_message_list *next, *prev;
	struct timeval request_time; /* When was this first issued? */
	struct smbd_server_connection *sconn;
	struct smbXsrv_connection *xconn;
	struct tevent_timer *te;
	struct smb_perfcount_data pcd;
	uint32_t seqnum;
	bool encrypted;
	bool processed;
	DATA_BLOB buf;
	struct deferred_open_record *open_rec;
};

static struct pending_message_list *get_deferred_open_message_smb(
	struct smbd_server_connection *sconn, uint64_t mid);

#if !defined(WITH_SMB1SERVER)
static bool smb2_srv_send(struct smbXsrv_connection *xconn, char *buffer,
			  bool do_signing, uint32_t seqnum,
			  bool do_encrypt,
			  struct smb_perfcount_data *pcd)
{
	size_t len = 0;
	ssize_t ret;
	char *buf_out = buffer;

	if (!NT_STATUS_IS_OK(xconn->transport.status)) {
		/*
		 * we're not supposed to do any io
		 */
		return true;
	}

	len = smb_len_large(buf_out) + 4;

	ret = write_data(xconn->transport.sock, buf_out, len);
	if (ret <= 0) {
		int saved_errno = errno;
		/*
		 * Try and give an error message saying what
		 * client failed.
		 */
		DEBUG(1,("pid[%d] Error writing %d bytes to client %s. %d. (%s)\n",
			 (int)getpid(), (int)len,
			 smbXsrv_connection_dbg(xconn),
			 (int)ret, strerror(saved_errno)));
		errno = saved_errno;

		srv_free_enc_buffer(xconn, buf_out);
		goto out;
	}

	SMB_PERFCOUNT_SET_MSGLEN_OUT(pcd, len);
	srv_free_enc_buffer(xconn, buf_out);
out:
	SMB_PERFCOUNT_END(pcd);

	return (ret > 0);
}
#endif

bool srv_send_smb(struct smbXsrv_connection *xconn, char *buffer,
		  bool do_signing, uint32_t seqnum,
		  bool do_encrypt,
		  struct smb_perfcount_data *pcd)
{
#if !defined(WITH_SMB1SERVER)
	return smb2_srv_send(xconn, buffer, do_signing, seqnum,
			     do_encrypt, pcd);
#else
	return smb1_srv_send(xconn, buffer, do_signing, seqnum,
			     do_encrypt, pcd);
#endif
}

/*******************************************************************
 Setup the word count and byte count for a smb message.
********************************************************************/

size_t srv_set_message(char *buf,
		       size_t num_words,
		       size_t num_bytes,
		       bool zero)
{
	if (zero && (num_words || num_bytes)) {
		memset(buf + smb_size,'\0',num_words*2 + num_bytes);
	}
	SCVAL(buf,smb_wct,num_words);
	SSVAL(buf,smb_vwv + num_words*SIZEOFWORD,num_bytes);
	smb_setlen(buf,(smb_size + num_words*2 + num_bytes - 4));
	return (smb_size + num_words*2 + num_bytes);
}

NTSTATUS read_packet_remainder(int fd, char *buffer,
			       unsigned int timeout, ssize_t len)
{
	NTSTATUS status;

	if (len <= 0) {
		return NT_STATUS_OK;
	}

	status = read_fd_with_timeout(fd, buffer, len, len, timeout, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		char addr[INET6_ADDRSTRLEN];
		DEBUG(0, ("read_fd_with_timeout failed for client %s read "
			  "error = %s.\n",
			  get_peer_addr(fd, addr, sizeof(addr)),
			  nt_errstr(status)));
	}
	return status;
}

#if !defined(WITH_SMB1SERVER)
static NTSTATUS smb2_receive_raw_talloc(TALLOC_CTX *mem_ctx,
					struct smbXsrv_connection *xconn,
					int sock,
					char **buffer, unsigned int timeout,
					size_t *p_unread, size_t *plen)
{
	char lenbuf[4];
	size_t len;
	NTSTATUS status;

	*p_unread = 0;

	status = read_smb_length_return_keepalive(sock, lenbuf, timeout,
						  &len);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * The +4 here can't wrap, we've checked the length above already.
	 */

	*buffer = talloc_array(mem_ctx, char, len+4);

	if (*buffer == NULL) {
		DEBUG(0, ("Could not allocate inbuf of length %d\n",
			  (int)len+4));
		return NT_STATUS_NO_MEMORY;
	}

	memcpy(*buffer, lenbuf, sizeof(lenbuf));

	status = read_packet_remainder(sock, (*buffer)+4, timeout, len);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*plen = len + 4;
	return NT_STATUS_OK;
}

static NTSTATUS smb2_receive_talloc(TALLOC_CTX *mem_ctx,
				    struct smbXsrv_connection *xconn,
				    int sock,
				    char **buffer, unsigned int timeout,
				    size_t *p_unread, bool *p_encrypted,
				    size_t *p_len,
				    uint32_t *seqnum,
				    bool trusted_channel)
{
	size_t len = 0;
	NTSTATUS status;

	*p_encrypted = false;

	status = smb2_receive_raw_talloc(mem_ctx, xconn, sock, buffer, timeout,
					 p_unread, &len);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(NT_STATUS_EQUAL(status, NT_STATUS_END_OF_FILE)?5:1,
		      ("smb2_receive_raw_talloc failed for client %s "
		       "read error = %s.\n",
		       smbXsrv_connection_dbg(xconn),
		       nt_errstr(status)) );
		return status;
	}

	*p_len = len;
	return NT_STATUS_OK;
}
#endif

NTSTATUS receive_smb_talloc(TALLOC_CTX *mem_ctx,
			    struct smbXsrv_connection *xconn,
			    int sock,
			    char **buffer, unsigned int timeout,
			    size_t *p_unread, bool *p_encrypted,
			    size_t *p_len,
			    uint32_t *seqnum,
			    bool trusted_channel)
{
#if defined(WITH_SMB1SERVER)
	return smb1_receive_talloc(mem_ctx, xconn, sock, buffer, timeout,
				   p_unread, p_encrypted, p_len, seqnum,
				   trusted_channel);
#else
	return smb2_receive_talloc(mem_ctx, xconn, sock, buffer, timeout,
				   p_unread, p_encrypted, p_len, seqnum,
				   trusted_channel);
#endif
}

/****************************************************************************
 Function to delete a sharing violation open message by mid.
****************************************************************************/

void remove_deferred_open_message_smb(struct smbXsrv_connection *xconn,
				      uint64_t mid)
{
	struct smbd_server_connection *sconn = xconn->client->sconn;
	struct pending_message_list *pml;

	if (sconn->using_smb2) {
		remove_deferred_open_message_smb2(xconn, mid);
		return;
	}

	for (pml = sconn->deferred_open_queue; pml; pml = pml->next) {
		if (mid == (uint64_t)SVAL(pml->buf.data,smb_mid)) {
			DEBUG(10,("remove_deferred_open_message_smb: "
				  "deleting mid %llu len %u\n",
				  (unsigned long long)mid,
				  (unsigned int)pml->buf.length ));
			DLIST_REMOVE(sconn->deferred_open_queue, pml);
			TALLOC_FREE(pml);
			return;
		}
	}
}

static void smbd_deferred_open_timer(struct tevent_context *ev,
				     struct tevent_timer *te,
				     struct timeval _tval,
				     void *private_data)
{
	struct pending_message_list *msg = talloc_get_type(private_data,
					   struct pending_message_list);
	struct smbd_server_connection *sconn = msg->sconn;
	struct smbXsrv_connection *xconn = msg->xconn;
	TALLOC_CTX *mem_ctx = talloc_tos();
	uint64_t mid = (uint64_t)SVAL(msg->buf.data,smb_mid);
	uint8_t *inbuf;

	inbuf = (uint8_t *)talloc_memdup(mem_ctx, msg->buf.data,
					 msg->buf.length);
	if (inbuf == NULL) {
		exit_server("smbd_deferred_open_timer: talloc failed\n");
		return;
	}

	/* We leave this message on the queue so the open code can
	   know this is a retry. */
	DEBUG(5,("smbd_deferred_open_timer: trigger mid %llu.\n",
		(unsigned long long)mid ));

	/* Mark the message as processed so this is not
	 * re-processed in error. */
	msg->processed = true;

	process_smb(xconn, inbuf,
		    msg->buf.length, 0,
		    msg->seqnum, msg->encrypted, &msg->pcd);

	/* If it's still there and was processed, remove it. */
	msg = get_deferred_open_message_smb(sconn, mid);
	if (msg && msg->processed) {
		remove_deferred_open_message_smb(xconn, mid);
	}
}

/****************************************************************************
 Move a sharing violation open retry message to the front of the list and
 schedule it for immediate processing.
****************************************************************************/

bool schedule_deferred_open_message_smb(struct smbXsrv_connection *xconn,
					uint64_t mid)
{
	struct smbd_server_connection *sconn = xconn->client->sconn;
	struct pending_message_list *pml;
	int i = 0;

	if (sconn->using_smb2) {
		return schedule_deferred_open_message_smb2(xconn, mid);
	}

	for (pml = sconn->deferred_open_queue; pml; pml = pml->next) {
		uint64_t msg_mid = (uint64_t)SVAL(pml->buf.data,smb_mid);

		DEBUG(10,("schedule_deferred_open_message_smb: [%d] "
			"msg_mid = %llu\n",
			i++,
			(unsigned long long)msg_mid ));

		if (mid == msg_mid) {
			struct tevent_timer *te;

			if (pml->processed) {
				/* A processed message should not be
				 * rescheduled. */
				DEBUG(0,("schedule_deferred_open_message_smb: LOGIC ERROR "
					"message mid %llu was already processed\n",
					(unsigned long long)msg_mid ));
				continue;
			}

			DEBUG(10,("schedule_deferred_open_message_smb: "
				"scheduling mid %llu\n",
				(unsigned long long)mid ));

			/*
			 * smbd_deferred_open_timer() calls
			 * process_smb() to redispatch the request
			 * including the required impersonation.
			 *
			 * So we can just use the raw tevent_context.
			 */
			te = tevent_add_timer(xconn->client->raw_ev_ctx,
					      pml,
					      timeval_zero(),
					      smbd_deferred_open_timer,
					      pml);
			if (!te) {
				DEBUG(10,("schedule_deferred_open_message_smb: "
					"event_add_timed() failed, "
					"skipping mid %llu\n",
					(unsigned long long)msg_mid ));
			}

			TALLOC_FREE(pml->te);
			pml->te = te;
			DLIST_PROMOTE(sconn->deferred_open_queue, pml);
			return true;
		}
	}

	DEBUG(10,("schedule_deferred_open_message_smb: failed to "
		"find message mid %llu\n",
		(unsigned long long)mid ));

	return false;
}

/****************************************************************************
 Return true if this mid is on the deferred queue and was not yet processed.
****************************************************************************/

bool open_was_deferred(struct smbXsrv_connection *xconn, uint64_t mid)
{
	struct smbd_server_connection *sconn = xconn->client->sconn;
	struct pending_message_list *pml;

	if (sconn->using_smb2) {
		return open_was_deferred_smb2(xconn, mid);
	}

	for (pml = sconn->deferred_open_queue; pml; pml = pml->next) {
		if (((uint64_t)SVAL(pml->buf.data,smb_mid)) == mid && !pml->processed) {
			return True;
		}
	}
	return False;
}

/****************************************************************************
 Return the message queued by this mid.
****************************************************************************/

static struct pending_message_list *get_deferred_open_message_smb(
	struct smbd_server_connection *sconn, uint64_t mid)
{
	struct pending_message_list *pml;

	for (pml = sconn->deferred_open_queue; pml; pml = pml->next) {
		if (((uint64_t)SVAL(pml->buf.data,smb_mid)) == mid) {
			return pml;
		}
	}
	return NULL;
}

/****************************************************************************
 Get the state data queued by this mid.
****************************************************************************/

bool get_deferred_open_message_state(struct smb_request *smbreq,
				struct timeval *p_request_time,
				struct deferred_open_record **open_rec)
{
	struct pending_message_list *pml;

	if (smbreq->sconn->using_smb2) {
		return get_deferred_open_message_state_smb2(smbreq->smb2req,
					p_request_time,
					open_rec);
	}

	pml = get_deferred_open_message_smb(smbreq->sconn, smbreq->mid);
	if (!pml) {
		return false;
	}
	if (p_request_time) {
		*p_request_time = pml->request_time;
	}
	if (open_rec != NULL) {
		*open_rec = pml->open_rec;
	}
	return true;
}

bool push_deferred_open_message_smb(struct smb_request *req,
				    struct timeval timeout,
				    struct file_id id,
				    struct deferred_open_record *open_rec)
{
#if defined(WITH_SMB1SERVER)
	if (req->smb2req) {
#endif
		return push_deferred_open_message_smb2(req->smb2req,
						req->request_time,
						timeout,
						id,
						open_rec);
#if defined(WITH_SMB1SERVER)
	} else {
		return push_deferred_open_message_smb1(req, timeout,
						       id, open_rec);
	}
#endif
}

static void construct_reply_common(uint8_t cmd, const uint8_t *inbuf,
				   char *outbuf)
{
	uint16_t in_flags2 = SVAL(inbuf,smb_flg2);
	uint16_t out_flags2 = common_flags2;

	out_flags2 |= in_flags2 & FLAGS2_UNICODE_STRINGS;
	out_flags2 |= in_flags2 & FLAGS2_SMB_SECURITY_SIGNATURES;
	out_flags2 |= in_flags2 & FLAGS2_SMB_SECURITY_SIGNATURES_REQUIRED;

	srv_set_message(outbuf,0,0,false);

	SCVAL(outbuf, smb_com, cmd);
	SIVAL(outbuf,smb_rcls,0);
	SCVAL(outbuf,smb_flg, FLAG_REPLY | (CVAL(inbuf,smb_flg) & FLAG_CASELESS_PATHNAMES));
	SSVAL(outbuf,smb_flg2, out_flags2);
	memset(outbuf+smb_pidhigh,'\0',(smb_tid-smb_pidhigh));
	memcpy(outbuf+smb_ss_field, inbuf+smb_ss_field, 8);

	SSVAL(outbuf,smb_tid,SVAL(inbuf,smb_tid));
	SSVAL(outbuf,smb_pid,SVAL(inbuf,smb_pid));
	SSVAL(outbuf,smb_pidhigh,SVAL(inbuf,smb_pidhigh));
	SSVAL(outbuf,smb_uid,SVAL(inbuf,smb_uid));
	SSVAL(outbuf,smb_mid,SVAL(inbuf,smb_mid));
}

void construct_reply_common_req(struct smb_request *req, char *outbuf)
{
	construct_reply_common(req->cmd, req->inbuf, outbuf);
}

/*******************************************************************
 allocate and initialize a reply packet
********************************************************************/

bool create_outbuf(TALLOC_CTX *mem_ctx, struct smb_request *req,
		   const uint8_t *inbuf, char **outbuf,
		   uint8_t num_words, uint32_t num_bytes)
{
	size_t smb_len = MIN_SMB_SIZE + VWV(num_words) + num_bytes;

	/*
	 * Protect against integer wrap.
	 * The SMB layer reply can be up to 0xFFFFFF bytes.
	 */
	if ((num_bytes > 0xffffff) || (smb_len > 0xffffff)) {
		char *msg;
		if (asprintf(&msg, "num_bytes too large: %u",
			     (unsigned)num_bytes) == -1) {
			msg = discard_const_p(char, "num_bytes too large");
		}
		smb_panic(msg);
	}

	/*
	 * Here we include the NBT header for now.
	 */
	*outbuf = talloc_array(mem_ctx, char,
			       NBT_HDR_SIZE + smb_len);
	if (*outbuf == NULL) {
		return false;
	}

	construct_reply_common(req->cmd, inbuf, *outbuf);
	srv_set_message(*outbuf, num_words, num_bytes, false);
	/*
	 * Zero out the word area, the caller has to take care of the bcc area
	 * himself
	 */
	if (num_words != 0) {
		memset(*outbuf + (NBT_HDR_SIZE + HDR_VWV), 0, VWV(num_words));
	}

	return true;
}

void reply_outbuf(struct smb_request *req, uint8_t num_words, uint32_t num_bytes)
{
	char *outbuf;
	if (!create_outbuf(req, req, req->inbuf, &outbuf, num_words,
			   num_bytes)) {
		smb_panic("could not allocate output buffer\n");
	}
	req->outbuf = (uint8_t *)outbuf;
}

/****************************************************************************
 Process an smb from the client
****************************************************************************/

static void process_smb2(struct smbXsrv_connection *xconn,
			 uint8_t *inbuf, size_t nread, size_t unread_bytes,
			 uint32_t seqnum, bool encrypted,
			 struct smb_perfcount_data *deferred_pcd)
{
	const uint8_t *inpdu = inbuf + NBT_HDR_SIZE;
	size_t pdulen = nread - NBT_HDR_SIZE;
	NTSTATUS status = smbd_smb2_process_negprot(xconn, 0, inpdu, pdulen);
	if (!NT_STATUS_IS_OK(status)) {
		exit_server_cleanly("SMB2 negprot fail");
	}
}

void process_smb(struct smbXsrv_connection *xconn,
		 uint8_t *inbuf, size_t nread, size_t unread_bytes,
		 uint32_t seqnum, bool encrypted,
		 struct smb_perfcount_data *deferred_pcd)
{
	struct smbd_server_connection *sconn = xconn->client->sconn;
	int msg_type = CVAL(inbuf,0);

	DO_PROFILE_INC(request);

	DEBUG( 6, ( "got message type 0x%x of len 0x%x\n", msg_type,
		    smb_len(inbuf) ) );
	DEBUG(3, ("Transaction %d of length %d (%u toread)\n",
		  sconn->trans_num, (int)nread, (unsigned int)unread_bytes));

	if (msg_type != NBSSmessage) {
		/*
		 * NetBIOS session request, keepalive, etc.
		 */
		reply_special(xconn, (char *)inbuf, nread);
		goto done;
	}

#if defined(WITH_SMB1SERVER)
	if (sconn->using_smb2) {
		/* At this point we're not really using smb2,
		 * we make the decision here.. */
		if (smbd_is_smb2_header(inbuf, nread)) {
#endif
			process_smb2(xconn, inbuf, nread, unread_bytes, seqnum,
				     encrypted, deferred_pcd);
			return;
#if defined(WITH_SMB1SERVER)
		}
		if (nread >= smb_size && valid_smb_header(inbuf)
				&& CVAL(inbuf, smb_com) != 0x72) {
			/* This is a non-negprot SMB1 packet.
			   Disable SMB2 from now on. */
			sconn->using_smb2 = false;
		}
	}
	process_smb1(xconn, inbuf, nread, unread_bytes, seqnum, encrypted,
		     deferred_pcd);
#endif

done:
	sconn->num_requests++;

	/* The timeout_processing function isn't run nearly
	   often enough to implement 'max log size' without
	   overrunning the size of the file by many megabytes.
	   This is especially true if we are running at debug
	   level 10.  Checking every 50 SMBs is a nice
	   tradeoff of performance vs log file size overrun. */

	if ((sconn->num_requests % 50) == 0 &&
	    need_to_check_log_size()) {
		change_to_root_user();
		check_log_size();
	}
}

NTSTATUS smbXsrv_connection_init_tables(struct smbXsrv_connection *conn,
					enum protocol_types protocol)
{
	NTSTATUS status;

	conn->protocol = protocol;

	if (conn->client->session_table != NULL) {
		return NT_STATUS_OK;
	}

	if (protocol >= PROTOCOL_SMB2_02) {
		status = smb2srv_session_table_init(conn);
		if (!NT_STATUS_IS_OK(status)) {
			conn->protocol = PROTOCOL_NONE;
			return status;
		}

		status = smb2srv_open_table_init(conn);
		if (!NT_STATUS_IS_OK(status)) {
			conn->protocol = PROTOCOL_NONE;
			return status;
		}
	} else {
#if defined(WITH_SMB1SERVER)
		status = smb1srv_session_table_init(conn);
		if (!NT_STATUS_IS_OK(status)) {
			conn->protocol = PROTOCOL_NONE;
			return status;
		}

		status = smb1srv_tcon_table_init(conn);
		if (!NT_STATUS_IS_OK(status)) {
			conn->protocol = PROTOCOL_NONE;
			return status;
		}

		status = smb1srv_open_table_init(conn);
		if (!NT_STATUS_IS_OK(status)) {
			conn->protocol = PROTOCOL_NONE;
			return status;
		}
#else
		conn->protocol = PROTOCOL_NONE;
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
#endif
	}

	set_Protocol(protocol);
	return NT_STATUS_OK;
}

/**
 * Create a debug string for the connection
 *
 * This is allocated to talloc_tos() or a string constant
 * in certain corner cases. The returned string should
 * hence not be free'd directly but only via the talloc stack.
 */
const char *smbXsrv_connection_dbg(const struct smbXsrv_connection *xconn)
{
	const char *ret;
	char *addr;
	/*
	 * TODO: this can be improved later
	 * maybe including the client guid or more
	 */
	addr = tsocket_address_string(xconn->remote_address, talloc_tos());
	if (addr == NULL) {
		return "<tsocket_address_string() failed>";
	}

	ret = talloc_asprintf(talloc_tos(), "ptr=%p,id=%llu,addr=%s",
			      xconn, (unsigned long long)xconn->channel_id, addr);
	TALLOC_FREE(addr);
	if (ret == NULL) {
		return "<talloc_asprintf() failed>";
	}

	return ret;
}

static void smbd_server_connection_write_handler(
	struct smbXsrv_connection *xconn)
{
	/* TODO: make write nonblocking */
}

static void smbd_smb2_server_connection_read_handler(
			struct smbXsrv_connection *xconn, int fd)
{
	char lenbuf[NBT_HDR_SIZE];
	size_t len = 0;
	uint8_t *buffer = NULL;
	size_t bufferlen = 0;
	NTSTATUS status;
	uint8_t msg_type = 0;

	/* Read the first 4 bytes - contains length of remainder. */
	status = read_smb_length_return_keepalive(fd, lenbuf, 0, &len);
	if (!NT_STATUS_IS_OK(status)) {
		exit_server_cleanly("failed to receive request length");
		return;
	}

	/* Integer wrap check. */
	if (len + NBT_HDR_SIZE < len) {
		exit_server_cleanly("Invalid length on initial request");
		return;
	}

	/*
	 * The +4 here can't wrap, we've checked the length above already.
	 */
	bufferlen = len+NBT_HDR_SIZE;

	buffer = talloc_array(talloc_tos(), uint8_t, bufferlen);
	if (buffer == NULL) {
		DBG_ERR("Could not allocate request inbuf of length %zu\n",
			bufferlen);
                exit_server_cleanly("talloc fail");
		return;
	}

	/* Copy the NBT_HDR_SIZE length. */
	memcpy(buffer, lenbuf, sizeof(lenbuf));

	status = read_packet_remainder(fd, (char *)buffer+NBT_HDR_SIZE, 0, len);
	if (!NT_STATUS_IS_OK(status)) {
		exit_server_cleanly("Failed to read remainder of initial request");
		return;
	}

	/* Check the message type. */
	msg_type = PULL_LE_U8(buffer,0);
	if (msg_type == NBSSrequest) {
		/*
		 * clients can send this request before
		 * bootstrapping into SMB2. Cope with this
		 * message only, don't allow any other strange
		 * NBSS types.
		 */
		reply_special(xconn, (char *)buffer, bufferlen);
		xconn->client->sconn->num_requests++;
		return;
	}

	/* Only a 'normal' message type allowed now. */
	if (msg_type != NBSSmessage) {
		DBG_ERR("Invalid message type %d\n", msg_type);
		exit_server_cleanly("Invalid message type for initial request");
		return;
	}

	/* Could this be an SMB1 negprot bootstrap into SMB2 ? */
	if (bufferlen < smb_size) {
		exit_server_cleanly("Invalid initial SMB1 or SMB2 packet");
		return;
	}
#if defined(WITH_SMB1SERVER)
	if (valid_smb_header(buffer)) {
		/* Can *only* allow an SMB1 negprot here. */
		uint8_t cmd = PULL_LE_U8(buffer, smb_com);
		if (cmd != SMBnegprot) {
			DBG_ERR("Incorrect SMB1 command 0x%hhx, "
				"should be SMBnegprot (0x72)\n",
				cmd);
			exit_server_cleanly("Invalid initial SMB1 packet");
		}
		/* Minimal process_smb(). */
		show_msg((char *)buffer);
		construct_reply(xconn,
				(char *)buffer,
				bufferlen,
				0,
				0,
				false,
				NULL);
		xconn->client->sconn->trans_num++;
		xconn->client->sconn->num_requests++;
		return;

	} else
#endif
	if (!smbd_is_smb2_header(buffer, bufferlen)) {
		exit_server_cleanly("Invalid initial SMB2 packet");
		return;
	}

	/* Here we know we're a valid SMB2 packet. */

	/*
	 * Point at the start of the SMB2 PDU.
	 * len is the length of the SMB2 PDU.
	 */

	status = smbd_smb2_process_negprot(xconn,
					   0,
					   (const uint8_t *)buffer+NBT_HDR_SIZE,
					   len);
	if (!NT_STATUS_IS_OK(status)) {
		exit_server_cleanly("SMB2 negprot fail");
	}
	return;
}

static void smbd_server_connection_handler(struct tevent_context *ev,
					   struct tevent_fd *fde,
					   uint16_t flags,
					   void *private_data)
{
	struct smbXsrv_connection *xconn =
		talloc_get_type_abort(private_data,
		struct smbXsrv_connection);

	if (!NT_STATUS_IS_OK(xconn->transport.status)) {
		/*
		 * we're not supposed to do any io
		 */
		TEVENT_FD_NOT_READABLE(xconn->transport.fde);
		TEVENT_FD_NOT_WRITEABLE(xconn->transport.fde);
		return;
	}

	if (flags & TEVENT_FD_WRITE) {
		smbd_server_connection_write_handler(xconn);
		return;
	}
	if (flags & TEVENT_FD_READ) {
#if defined(WITH_SMB1SERVER)
		if (lp_server_min_protocol() > PROTOCOL_NT1) {
#endif
			smbd_smb2_server_connection_read_handler(xconn,
						xconn->transport.sock);
#if defined(WITH_SMB1SERVER)
		} else {
			smbd_smb1_server_connection_read_handler(xconn,
						xconn->transport.sock);
		}
#endif
		return;
	}
}

struct smbd_release_ip_state {
	struct smbXsrv_connection *xconn;
	struct tevent_immediate *im;
	char addr[INET6_ADDRSTRLEN];
};

static void smbd_release_ip_immediate(struct tevent_context *ctx,
				      struct tevent_immediate *im,
				      void *private_data)
{
	struct smbd_release_ip_state *state =
		talloc_get_type_abort(private_data,
		struct smbd_release_ip_state);
	struct smbXsrv_connection *xconn = state->xconn;

	if (!NT_STATUS_EQUAL(xconn->transport.status, NT_STATUS_ADDRESS_CLOSED)) {
		/*
		 * smbd_server_connection_terminate() already triggered ?
		 */
		return;
	}

	smbd_server_connection_terminate(xconn, "CTDB_SRVID_RELEASE_IP");
}

/****************************************************************************
received when we should release a specific IP
****************************************************************************/
static int release_ip(struct tevent_context *ev,
		      uint32_t src_vnn, uint32_t dst_vnn,
		      uint64_t dst_srvid,
		      const uint8_t *msg, size_t msglen,
		      void *private_data)
{
	struct smbd_release_ip_state *state =
		talloc_get_type_abort(private_data,
		struct smbd_release_ip_state);
	struct smbXsrv_connection *xconn = state->xconn;
	const char *ip;
	const char *addr = state->addr;
	const char *p = addr;

	if (msglen == 0) {
		return 0;
	}
	if (msg[msglen-1] != '\0') {
		return 0;
	}

	ip = (const char *)msg;

	if (!NT_STATUS_IS_OK(xconn->transport.status)) {
		/* avoid recursion */
		return 0;
	}

	if (strncmp("::ffff:", addr, 7) == 0) {
		p = addr + 7;
	}

	DEBUG(10, ("Got release IP message for %s, "
		   "our address is %s\n", ip, p));

	if ((strcmp(p, ip) == 0) || ((p != addr) && strcmp(addr, ip) == 0)) {
		DEBUG(0,("Got release IP message for our IP %s - exiting immediately\n",
			ip));
		/*
		 * With SMB2 we should do a clean disconnect,
		 * the previous_session_id in the session setup
		 * will cleanup the old session, tcons and opens.
		 *
		 * A clean disconnect is needed in order to support
		 * durable handles.
		 *
		 * Note: typically this is never triggered
		 *       as we got a TCP RST (triggered by ctdb event scripts)
		 *       before we get CTDB_SRVID_RELEASE_IP.
		 *
		 * We used to call _exit(1) here, but as this was mostly never
		 * triggered and has implication on our process model,
		 * we can just use smbd_server_connection_terminate()
		 * (also for SMB1).
		 *
		 * We don't call smbd_server_connection_terminate() directly
		 * as we might be called from within ctdbd_migrate(),
		 * we need to defer our action to the next event loop
		 */
		tevent_schedule_immediate(state->im,
					  xconn->client->raw_ev_ctx,
					  smbd_release_ip_immediate,
					  state);

		/*
		 * Make sure we don't get any io on the connection.
		 */
		xconn->transport.status = NT_STATUS_ADDRESS_CLOSED;
		return EADDRNOTAVAIL;
	}

	return 0;
}

static int match_cluster_movable_ip(uint32_t total_ip_count,
				    const struct sockaddr_storage *ip,
				    bool is_movable_ip,
				    void *private_data)
{
	const struct sockaddr_storage *srv = private_data;
	struct samba_sockaddr pub_ip = {
		.u = {
			.ss = *ip,
		},
	};
	struct samba_sockaddr srv_ip = {
		.u = {
			.ss = *srv,
		},
	};

	if (is_movable_ip && sockaddr_equal(&pub_ip.u.sa, &srv_ip.u.sa)) {
		return EADDRNOTAVAIL;
	}

	return 0;
}

static NTSTATUS smbd_register_ips(struct smbXsrv_connection *xconn,
				  struct sockaddr_storage *srv,
				  struct sockaddr_storage *clnt)
{
	struct smbd_release_ip_state *state;
	struct ctdbd_connection *cconn;
	int ret;

	cconn = messaging_ctdb_connection();
	if (cconn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state = talloc_zero(xconn, struct smbd_release_ip_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->xconn = xconn;
	state->im = tevent_create_immediate(state);
	if (state->im == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	if (print_sockaddr(state->addr, sizeof(state->addr), srv) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (xconn->client->server_multi_channel_enabled) {
		ret = ctdbd_public_ip_foreach(cconn,
					      match_cluster_movable_ip,
					      srv);
		if (ret == EADDRNOTAVAIL) {
			xconn->has_cluster_movable_ip = true;
			DBG_DEBUG("cluster movable IP on %s\n",
				  smbXsrv_connection_dbg(xconn));
		} else if (ret != 0) {
			DBG_ERR("failed to iterate cluster IPs: %s\n",
				strerror(ret));
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	ret = ctdbd_register_ips(cconn, srv, clnt, release_ip, state);
	if (ret != 0) {
		return map_nt_error_from_unix(ret);
	}
	return NT_STATUS_OK;
}

static int smbXsrv_connection_destructor(struct smbXsrv_connection *xconn)
{
	DBG_DEBUG("xconn[%s]\n", smbXsrv_connection_dbg(xconn));
	return 0;
}

NTSTATUS smbd_add_connection(struct smbXsrv_client *client, int sock_fd,
			     NTTIME now, struct smbXsrv_connection **_xconn)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct smbXsrv_connection *xconn;
	struct sockaddr_storage ss_srv;
	void *sp_srv = (void *)&ss_srv;
	struct sockaddr *sa_srv = (struct sockaddr *)sp_srv;
	struct sockaddr_storage ss_clnt;
	void *sp_clnt = (void *)&ss_clnt;
	struct sockaddr *sa_clnt = (struct sockaddr *)sp_clnt;
	socklen_t sa_socklen;
	struct tsocket_address *local_address = NULL;
	struct tsocket_address *remote_address = NULL;
	const char *remaddr = NULL;
	char *p;
	const char *rhost = NULL;
	int ret;
	int tmp;

	*_xconn = NULL;

	DO_PROFILE_INC(connect);

	xconn = talloc_zero(client, struct smbXsrv_connection);
	if (xconn == NULL) {
		DEBUG(0,("talloc_zero(struct smbXsrv_connection)\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(xconn, smbXsrv_connection_destructor);
	talloc_steal(frame, xconn);
	xconn->client = client;
	xconn->connect_time = now;
	if (client->next_channel_id != 0) {
		xconn->channel_id = client->next_channel_id++;
	}

	xconn->transport.sock = sock_fd;
#if defined(WITH_SMB1SERVER)
	smbd_echo_init(xconn);
#endif
	xconn->protocol = PROTOCOL_NONE;

	/* Ensure child is set to blocking mode */
	set_blocking(sock_fd,True);

	set_socket_options(sock_fd, "SO_KEEPALIVE");
	set_socket_options(sock_fd, lp_socket_options());

	sa_socklen = sizeof(ss_clnt);
	ret = getpeername(sock_fd, sa_clnt, &sa_socklen);
	if (ret != 0) {
		int saved_errno = errno;
		int level = (errno == ENOTCONN)?2:0;
		DEBUG(level,("getpeername() failed - %s\n",
		      strerror(saved_errno)));
		TALLOC_FREE(frame);
		return map_nt_error_from_unix_common(saved_errno);
	}
	ret = tsocket_address_bsd_from_sockaddr(xconn,
						sa_clnt, sa_socklen,
						&remote_address);
	if (ret != 0) {
		int saved_errno = errno;
		DEBUG(0,("%s: tsocket_address_bsd_from_sockaddr remote failed - %s\n",
			__location__, strerror(saved_errno)));
		TALLOC_FREE(frame);
		return map_nt_error_from_unix_common(saved_errno);
	}

	sa_socklen = sizeof(ss_srv);
	ret = getsockname(sock_fd, sa_srv, &sa_socklen);
	if (ret != 0) {
		int saved_errno = errno;
		int level = (errno == ENOTCONN)?2:0;
		DEBUG(level,("getsockname() failed - %s\n",
		      strerror(saved_errno)));
		TALLOC_FREE(frame);
		return map_nt_error_from_unix_common(saved_errno);
	}
	ret = tsocket_address_bsd_from_sockaddr(xconn,
						sa_srv, sa_socklen,
						&local_address);
	if (ret != 0) {
		int saved_errno = errno;
		DEBUG(0,("%s: tsocket_address_bsd_from_sockaddr remote failed - %s\n",
			__location__, strerror(saved_errno)));
		TALLOC_FREE(frame);
		return map_nt_error_from_unix_common(saved_errno);
	}

	if (tsocket_address_is_inet(remote_address, "ip")) {
		remaddr = tsocket_address_inet_addr_string(remote_address,
							   talloc_tos());
		if (remaddr == NULL) {
			DEBUG(0,("%s: tsocket_address_inet_addr_string remote failed - %s\n",
				 __location__, strerror(errno)));
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		remaddr = "0.0.0.0";
	}

	/*
	 * Before the first packet, check the global hosts allow/ hosts deny
	 * parameters before doing any parsing of packets passed to us by the
	 * client. This prevents attacks on our parsing code from hosts not in
	 * the hosts allow list.
	 */

	ret = get_remote_hostname(remote_address,
				  &p, talloc_tos());
	if (ret < 0) {
		int saved_errno = errno;
		DEBUG(0,("%s: get_remote_hostname failed - %s\n",
			__location__, strerror(saved_errno)));
		TALLOC_FREE(frame);
		return map_nt_error_from_unix_common(saved_errno);
	}
	rhost = p;
	if (strequal(rhost, "UNKNOWN")) {
		rhost = remaddr;
	}

	xconn->local_address = local_address;
	xconn->remote_address = remote_address;
	xconn->remote_hostname = talloc_strdup(xconn, rhost);
	if (xconn->remote_hostname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!srv_init_signing(xconn)) {
		DEBUG(0, ("Failed to init smb_signing\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (!allow_access(lp_hosts_deny(-1), lp_hosts_allow(-1),
			  xconn->remote_hostname,
			  remaddr)) {
		DEBUG( 1, ("Connection denied from %s to %s\n",
			   tsocket_address_string(remote_address, talloc_tos()),
			   tsocket_address_string(local_address, talloc_tos())));

		/*
		 * We return a valid xconn
		 * so that the caller can return an error message
		 * to the client
		 */
		DLIST_ADD_END(client->connections, xconn);
		talloc_steal(client, xconn);

		*_xconn = xconn;
		TALLOC_FREE(frame);
		return NT_STATUS_NETWORK_ACCESS_DENIED;
	}

	DEBUG(10, ("Connection allowed from %s to %s\n",
		   tsocket_address_string(remote_address, talloc_tos()),
		   tsocket_address_string(local_address, talloc_tos())));

	if (lp_clustering()) {
		/*
		 * We need to tell ctdb about our client's TCP
		 * connection, so that for failover ctdbd can send
		 * tickle acks, triggering a reconnection by the
		 * client.
		 */
		NTSTATUS status;

		status = smbd_register_ips(xconn, &ss_srv, &ss_clnt);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("ctdbd_register_ips failed: %s\n",
				  nt_errstr(status)));
		}
	}

	tmp = lp_max_xmit();
	tmp = MAX(tmp, SMB_BUFFER_SIZE_MIN);
	tmp = MIN(tmp, SMB_BUFFER_SIZE_MAX);

#if defined(WITH_SMB1SERVER)
	xconn->smb1.negprot.max_recv = tmp;

	xconn->smb1.sessions.done_sesssetup = false;
	xconn->smb1.sessions.max_send = SMB_BUFFER_SIZE_MAX;
#endif

	xconn->transport.fde = tevent_add_fd(client->raw_ev_ctx,
					     xconn,
					     sock_fd,
					     TEVENT_FD_READ,
					     smbd_server_connection_handler,
					     xconn);
	if (!xconn->transport.fde) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	tevent_fd_set_auto_close(xconn->transport.fde);

	/* for now we only have one connection */
	DLIST_ADD_END(client->connections, xconn);
	talloc_steal(client, xconn);

	*_xconn = xconn;
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}
