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
