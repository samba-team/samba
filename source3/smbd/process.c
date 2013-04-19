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
#include "librpc/gen_ndr/netlogon.h"
#include "../lib/async_req/async_sock.h"
#include "ctdbd_conn.h"
#include "../lib/util/select.h"
#include "printing/queue_process.h"
#include "system/select.h"
#include "passdb.h"
#include "auth.h"
#include "messages.h"
#include "smbprofile.h"
#include "rpc_server/spoolss/srv_spoolss_nt.h"
#include "libsmb/libsmb.h"
#include "../lib/util/tevent_ntstatus.h"
#include "../libcli/security/dom_sid.h"
#include "../libcli/security/security_token.h"
#include "lib/id_cache.h"
#include "serverid.h"

/* Internal message queue for deferred opens. */
struct pending_message_list {
	struct pending_message_list *next, *prev;
	struct timeval request_time; /* When was this first issued? */
	struct smbd_server_connection *sconn;
	struct timed_event *te;
	struct smb_perfcount_data pcd;
	uint32_t seqnum;
	bool encrypted;
	bool processed;
	DATA_BLOB buf;
	DATA_BLOB private_data;
};

static void construct_reply_common(struct smb_request *req, const char *inbuf,
				   char *outbuf);
static struct pending_message_list *get_deferred_open_message_smb(
	struct smbd_server_connection *sconn, uint64_t mid);
static bool smb_splice_chain(uint8_t **poutbuf, const uint8_t *andx_buf);

static bool smbd_lock_socket_internal(struct smbd_server_connection *sconn)
{
	bool ok;

	if (sconn->smb1.echo_handler.socket_lock_fd == -1) {
		return true;
	}

	sconn->smb1.echo_handler.ref_count++;

	if (sconn->smb1.echo_handler.ref_count > 1) {
		return true;
	}

	DEBUG(10,("pid[%d] wait for socket lock\n", (int)getpid()));

	do {
		ok = fcntl_lock(
			sconn->smb1.echo_handler.socket_lock_fd,
			F_SETLKW, 0, 0, F_WRLCK);
	} while (!ok && (errno == EINTR));

	if (!ok) {
		DEBUG(1, ("fcntl_lock failed: %s\n", strerror(errno)));
		return false;
	}

	DEBUG(10,("pid[%d] got for socket lock\n", (int)getpid()));

	return true;
}

void smbd_lock_socket(struct smbd_server_connection *sconn)
{
	if (!smbd_lock_socket_internal(sconn)) {
		exit_server_cleanly("failed to lock socket");
	}
}

static bool smbd_unlock_socket_internal(struct smbd_server_connection *sconn)
{
	bool ok;

	if (sconn->smb1.echo_handler.socket_lock_fd == -1) {
		return true;
	}

	sconn->smb1.echo_handler.ref_count--;

	if (sconn->smb1.echo_handler.ref_count > 0) {
		return true;
	}

	do {
		ok = fcntl_lock(
			sconn->smb1.echo_handler.socket_lock_fd,
			F_SETLKW, 0, 0, F_UNLCK);
	} while (!ok && (errno == EINTR));

	if (!ok) {
		DEBUG(1, ("fcntl_lock failed: %s\n", strerror(errno)));
		return false;
	}

	DEBUG(10,("pid[%d] unlocked socket\n", (int)getpid()));

	return true;
}

void smbd_unlock_socket(struct smbd_server_connection *sconn)
{
	if (!smbd_unlock_socket_internal(sconn)) {
		exit_server_cleanly("failed to unlock socket");
	}
}

/* Accessor function for smb_read_error for smbd functions. */

/****************************************************************************
 Send an smb to a fd.
****************************************************************************/

bool srv_send_smb(struct smbd_server_connection *sconn, char *buffer,
		  bool do_signing, uint32_t seqnum,
		  bool do_encrypt,
		  struct smb_perfcount_data *pcd)
{
	size_t len = 0;
	size_t nwritten=0;
	ssize_t ret;
	char *buf_out = buffer;

	smbd_lock_socket(sconn);

	if (do_signing) {
		/* Sign the outgoing packet if required. */
		srv_calculate_sign_mac(sconn, buf_out, seqnum);
	}

	if (do_encrypt) {
		NTSTATUS status = srv_encrypt_buffer(sconn, buffer, &buf_out);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("send_smb: SMB encryption failed "
				"on outgoing packet! Error %s\n",
				nt_errstr(status) ));
			goto out;
		}
	}

	len = smb_len_large(buf_out) + 4;

	ret = write_data(sconn->sock, buf_out+nwritten, len - nwritten);
	if (ret <= 0) {

		char addr[INET6_ADDRSTRLEN];
		/*
		 * Try and give an error message saying what
		 * client failed.
		 */
		DEBUG(1,("pid[%d] Error writing %d bytes to client %s. %d. (%s)\n",
			 (int)getpid(), (int)len,
			 get_peer_addr(sconn->sock, addr, sizeof(addr)),
			 (int)ret, strerror(errno) ));

		srv_free_enc_buffer(sconn, buf_out);
		goto out;
	}

	SMB_PERFCOUNT_SET_MSGLEN_OUT(pcd, len);
	srv_free_enc_buffer(sconn, buf_out);
out:
	SMB_PERFCOUNT_END(pcd);

	smbd_unlock_socket(sconn);
	return true;
}

/*******************************************************************
 Setup the word count and byte count for a smb message.
********************************************************************/

int srv_set_message(char *buf,
                        int num_words,
                        int num_bytes,
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

static bool valid_smb_header(struct smbd_server_connection *sconn,
			     const uint8_t *inbuf)
{
	if (is_encrypted_packet(sconn, inbuf)) {
		return true;
	}
	/*
	 * This used to be (strncmp(smb_base(inbuf),"\377SMB",4) == 0)
	 * but it just looks weird to call strncmp for this one.
	 */
	return (IVAL(smb_base(inbuf), 0) == 0x424D53FF);
}

/* Socket functions for smbd packet processing. */

static bool valid_packet_size(size_t len)
{
	/*
	 * A WRITEX with CAP_LARGE_WRITEX can be 64k worth of data plus 65 bytes
	 * of header. Don't print the error if this fits.... JRA.
	 */

	if (len > (BUFFER_SIZE + LARGE_WRITEX_HDR_SIZE)) {
		DEBUG(0,("Invalid packet length! (%lu bytes).\n",
					(unsigned long)len));
		return false;
	}
	return true;
}

static NTSTATUS read_packet_remainder(int fd, char *buffer,
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

/****************************************************************************
 Attempt a zerocopy writeX read. We know here that len > smb_size-4
****************************************************************************/

/*
 * Unfortunately, earlier versions of smbclient/libsmbclient
 * don't send this "standard" writeX header. I've fixed this
 * for 3.2 but we'll use the old method with earlier versions.
 * Windows and CIFSFS at least use this standard size. Not
 * sure about MacOSX.
 */

#define STANDARD_WRITE_AND_X_HEADER_SIZE (smb_size - 4 + /* basic header */ \
				(2*14) + /* word count (including bcc) */ \
				1 /* pad byte */)

static NTSTATUS receive_smb_raw_talloc_partial_read(TALLOC_CTX *mem_ctx,
						    const char lenbuf[4],
						    struct smbd_server_connection *sconn,
						    int sock,
						    char **buffer,
						    unsigned int timeout,
						    size_t *p_unread,
						    size_t *len_ret)
{
	/* Size of a WRITEX call (+4 byte len). */
	char writeX_header[4 + STANDARD_WRITE_AND_X_HEADER_SIZE];
	ssize_t len = smb_len_large(lenbuf); /* Could be a UNIX large writeX. */
	ssize_t toread;
	NTSTATUS status;

	memcpy(writeX_header, lenbuf, 4);

	status = read_fd_with_timeout(
		sock, writeX_header + 4,
		STANDARD_WRITE_AND_X_HEADER_SIZE,
		STANDARD_WRITE_AND_X_HEADER_SIZE,
		timeout, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("read_fd_with_timeout failed for client %s read "
			  "error = %s.\n",
			  tsocket_address_string(sconn->remote_address,
						 talloc_tos()),
			  nt_errstr(status)));
		return status;
	}

	/*
	 * Ok - now try and see if this is a possible
	 * valid writeX call.
	 */

	if (is_valid_writeX_buffer(sconn, (uint8_t *)writeX_header)) {
		/*
		 * If the data offset is beyond what
		 * we've read, drain the extra bytes.
		 */
		uint16_t doff = SVAL(writeX_header,smb_vwv11);
		ssize_t newlen;

		if (doff > STANDARD_WRITE_AND_X_HEADER_SIZE) {
			size_t drain = doff - STANDARD_WRITE_AND_X_HEADER_SIZE;
			if (drain_socket(sock, drain) != drain) {
	                        smb_panic("receive_smb_raw_talloc_partial_read:"
					" failed to drain pending bytes");
	                }
		} else {
			doff = STANDARD_WRITE_AND_X_HEADER_SIZE;
		}

		/* Spoof down the length and null out the bcc. */
		set_message_bcc(writeX_header, 0);
		newlen = smb_len(writeX_header);

		/* Copy the header we've written. */

		*buffer = (char *)talloc_memdup(mem_ctx,
				writeX_header,
				sizeof(writeX_header));

		if (*buffer == NULL) {
			DEBUG(0, ("Could not allocate inbuf of length %d\n",
				  (int)sizeof(writeX_header)));
			return NT_STATUS_NO_MEMORY;
		}

		/* Work out the remaining bytes. */
		*p_unread = len - STANDARD_WRITE_AND_X_HEADER_SIZE;
		*len_ret = newlen + 4;
		return NT_STATUS_OK;
	}

	if (!valid_packet_size(len)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/*
	 * Not a valid writeX call. Just do the standard
	 * talloc and return.
	 */

	*buffer = talloc_array(mem_ctx, char, len+4);

	if (*buffer == NULL) {
		DEBUG(0, ("Could not allocate inbuf of length %d\n",
			  (int)len+4));
		return NT_STATUS_NO_MEMORY;
	}

	/* Copy in what we already read. */
	memcpy(*buffer,
		writeX_header,
		4 + STANDARD_WRITE_AND_X_HEADER_SIZE);
	toread = len - STANDARD_WRITE_AND_X_HEADER_SIZE;

	if(toread > 0) {
		status = read_packet_remainder(
			sock,
			(*buffer) + 4 + STANDARD_WRITE_AND_X_HEADER_SIZE,
			timeout, toread);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("receive_smb_raw_talloc_partial_read: %s\n",
				   nt_errstr(status)));
			return status;
		}
	}

	*len_ret = len + 4;
	return NT_STATUS_OK;
}

static NTSTATUS receive_smb_raw_talloc(TALLOC_CTX *mem_ctx,
				       struct smbd_server_connection *sconn,
				       int sock,
				       char **buffer, unsigned int timeout,
				       size_t *p_unread, size_t *plen)
{
	char lenbuf[4];
	size_t len;
	int min_recv_size = lp_min_receive_file_size();
	NTSTATUS status;

	*p_unread = 0;

	status = read_smb_length_return_keepalive(sock, lenbuf, timeout,
						  &len);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (CVAL(lenbuf,0) == 0 && min_recv_size &&
	    (smb_len_large(lenbuf) > /* Could be a UNIX large writeX. */
		(min_recv_size + STANDARD_WRITE_AND_X_HEADER_SIZE)) &&
	    !srv_is_signing_active(sconn) &&
	    sconn->smb1.echo_handler.trusted_fde == NULL) {

		return receive_smb_raw_talloc_partial_read(
			mem_ctx, lenbuf, sconn, sock, buffer, timeout,
			p_unread, plen);
	}

	if (!valid_packet_size(len)) {
		return NT_STATUS_INVALID_PARAMETER;
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

static NTSTATUS receive_smb_talloc(TALLOC_CTX *mem_ctx,
				   struct smbd_server_connection *sconn,
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

	status = receive_smb_raw_talloc(mem_ctx, sconn, sock, buffer, timeout,
					p_unread, &len);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(NT_STATUS_EQUAL(status, NT_STATUS_END_OF_FILE)?5:1,
		      ("receive_smb_raw_talloc failed for client %s "
		       "read error = %s.\n",
		       tsocket_address_string(sconn->remote_address,
					      talloc_tos()),
		       nt_errstr(status)) );
		return status;
	}

	if (is_encrypted_packet(sconn, (uint8_t *)*buffer)) {
		status = srv_decrypt_buffer(sconn, *buffer);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("receive_smb_talloc: SMB decryption failed on "
				"incoming packet! Error %s\n",
				nt_errstr(status) ));
			return status;
		}
		*p_encrypted = true;
	}

	/* Check the incoming SMB signature. */
	if (!srv_check_sign_mac(sconn, *buffer, seqnum, trusted_channel)) {
		DEBUG(0, ("receive_smb: SMB Signature verification failed on "
			  "incoming packet!\n"));
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	*p_len = len;
	return NT_STATUS_OK;
}

/*
 * Initialize a struct smb_request from an inbuf
 */

static bool init_smb_request(struct smb_request *req,
			     struct smbd_server_connection *sconn,
			     const uint8 *inbuf,
			     size_t unread_bytes, bool encrypted,
			     uint32_t seqnum)
{
	struct smbXsrv_tcon *tcon;
	NTSTATUS status;
	NTTIME now;
	size_t req_size = smb_len(inbuf) + 4;

	/* Ensure we have at least smb_size bytes. */
	if (req_size < smb_size) {
		DEBUG(0,("init_smb_request: invalid request size %u\n",
			(unsigned int)req_size ));
		return false;
	}

	req->request_time = timeval_current();
	now = timeval_to_nttime(&req->request_time);

	req->cmd    = CVAL(inbuf, smb_com);
	req->flags2 = SVAL(inbuf, smb_flg2);
	req->smbpid = SVAL(inbuf, smb_pid);
	req->mid    = (uint64_t)SVAL(inbuf, smb_mid);
	req->seqnum = seqnum;
	req->vuid   = SVAL(inbuf, smb_uid);
	req->tid    = SVAL(inbuf, smb_tid);
	req->wct    = CVAL(inbuf, smb_wct);
	req->vwv    = (const uint16_t *)(inbuf+smb_vwv);
	req->buflen = smb_buflen(inbuf);
	req->buf    = (const uint8_t *)smb_buf_const(inbuf);
	req->unread_bytes = unread_bytes;
	req->encrypted = encrypted;
	req->sconn = sconn;
	status = smb1srv_tcon_lookup(sconn->conn, req->tid, now, &tcon);
	if (NT_STATUS_IS_OK(status)) {
		req->conn = tcon->compat;
	} else {
		req->conn = NULL;
	}
	req->chain_fsp = NULL;
	req->smb2req = NULL;
	req->priv_paths = NULL;
	req->chain = NULL;
	smb_init_perfcount_data(&req->pcd);

	/* Ensure we have at least wct words and 2 bytes of bcc. */
	if (smb_size + req->wct*2 > req_size) {
		DEBUG(0,("init_smb_request: invalid wct number %u (size %u)\n",
			(unsigned int)req->wct,
			(unsigned int)req_size));
		return false;
	}
	/* Ensure bcc is correct. */
	if (((const uint8_t *)smb_buf_const(inbuf)) + req->buflen > inbuf + req_size) {
		DEBUG(0,("init_smb_request: invalid bcc number %u "
			"(wct = %u, size %u)\n",
			(unsigned int)req->buflen,
			(unsigned int)req->wct,
			(unsigned int)req_size));
		return false;
	}

	req->outbuf = NULL;
	return true;
}

static void process_smb(struct smbd_server_connection *conn,
			uint8_t *inbuf, size_t nread, size_t unread_bytes,
			uint32_t seqnum, bool encrypted,
			struct smb_perfcount_data *deferred_pcd);

static void smbd_deferred_open_timer(struct event_context *ev,
				     struct timed_event *te,
				     struct timeval _tval,
				     void *private_data)
{
	struct pending_message_list *msg = talloc_get_type(private_data,
					   struct pending_message_list);
	struct smbd_server_connection *sconn = msg->sconn;
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

	process_smb(sconn, inbuf,
		    msg->buf.length, 0,
		    msg->seqnum, msg->encrypted, &msg->pcd);

	/* If it's still there and was processed, remove it. */
	msg = get_deferred_open_message_smb(sconn, mid);
	if (msg && msg->processed) {
		remove_deferred_open_message_smb(sconn, mid);
	}
}

/****************************************************************************
 Function to push a message onto the tail of a linked list of smb messages ready
 for processing.
****************************************************************************/

static bool push_queued_message(struct smb_request *req,
				struct timeval request_time,
				struct timeval end_time,
				char *private_data, size_t private_len)
{
	int msg_len = smb_len(req->inbuf) + 4;
	struct pending_message_list *msg;

	msg = talloc_zero(NULL, struct pending_message_list);

	if(msg == NULL) {
		DEBUG(0,("push_message: malloc fail (1)\n"));
		return False;
	}
	msg->sconn = req->sconn;

	msg->buf = data_blob_talloc(msg, req->inbuf, msg_len);
	if(msg->buf.data == NULL) {
		DEBUG(0,("push_message: malloc fail (2)\n"));
		TALLOC_FREE(msg);
		return False;
	}

	msg->request_time = request_time;
	msg->seqnum = req->seqnum;
	msg->encrypted = req->encrypted;
	msg->processed = false;
	SMB_PERFCOUNT_DEFER_OP(&req->pcd, &msg->pcd);

	if (private_data) {
		msg->private_data = data_blob_talloc(msg, private_data,
						     private_len);
		if (msg->private_data.data == NULL) {
			DEBUG(0,("push_message: malloc fail (3)\n"));
			TALLOC_FREE(msg);
			return False;
		}
	}

	msg->te = tevent_add_timer(msg->sconn->ev_ctx,
				   msg,
				   end_time,
				   smbd_deferred_open_timer,
				   msg);
	if (!msg->te) {
		DEBUG(0,("push_message: event_add_timed failed\n"));
		TALLOC_FREE(msg);
		return false;
	}

	DLIST_ADD_END(req->sconn->deferred_open_queue, msg,
		      struct pending_message_list *);

	DEBUG(10,("push_message: pushed message length %u on "
		  "deferred_open_queue\n", (unsigned int)msg_len));

	return True;
}

/****************************************************************************
 Function to delete a sharing violation open message by mid.
****************************************************************************/

void remove_deferred_open_message_smb(struct smbd_server_connection *sconn,
				      uint64_t mid)
{
	struct pending_message_list *pml;

	if (sconn->using_smb2) {
		remove_deferred_open_message_smb2(sconn, mid);
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

/****************************************************************************
 Move a sharing violation open retry message to the front of the list and
 schedule it for immediate processing.
****************************************************************************/

bool schedule_deferred_open_message_smb(struct smbd_server_connection *sconn,
					uint64_t mid)
{
	struct pending_message_list *pml;
	int i = 0;

	if (sconn->using_smb2) {
		return schedule_deferred_open_message_smb2(sconn, mid);
	}

	for (pml = sconn->deferred_open_queue; pml; pml = pml->next) {
		uint64_t msg_mid = (uint64_t)SVAL(pml->buf.data,smb_mid);

		DEBUG(10,("schedule_deferred_open_message_smb: [%d] "
			"msg_mid = %llu\n",
			i++,
			(unsigned long long)msg_mid ));

		if (mid == msg_mid) {
			struct timed_event *te;

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

			te = tevent_add_timer(pml->sconn->ev_ctx,
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

bool open_was_deferred(struct smbd_server_connection *sconn, uint64_t mid)
{
	struct pending_message_list *pml;

	if (sconn->using_smb2) {
		return open_was_deferred_smb2(sconn, mid);
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
				void **pp_state)
{
	struct pending_message_list *pml;

	if (smbreq->sconn->using_smb2) {
		return get_deferred_open_message_state_smb2(smbreq->smb2req,
					p_request_time,
					pp_state);
	}

	pml = get_deferred_open_message_smb(smbreq->sconn, smbreq->mid);
	if (!pml) {
		return false;
	}
	if (p_request_time) {
		*p_request_time = pml->request_time;
	}
	if (pp_state) {
		*pp_state = (void *)pml->private_data.data;
	}
	return true;
}

/****************************************************************************
 Function to push a deferred open smb message onto a linked list of local smb
 messages ready for processing.
****************************************************************************/

bool push_deferred_open_message_smb(struct smb_request *req,
			       struct timeval request_time,
			       struct timeval timeout,
			       struct file_id id,
			       char *private_data, size_t priv_len)
{
	struct timeval end_time;

	if (req->smb2req) {
		return push_deferred_open_message_smb2(req->smb2req,
						request_time,
						timeout,
						id,
						private_data,
						priv_len);
	}

	if (req->unread_bytes) {
		DEBUG(0,("push_deferred_open_message_smb: logic error ! "
			"unread_bytes = %u\n",
			(unsigned int)req->unread_bytes ));
		smb_panic("push_deferred_open_message_smb: "
			"logic error unread_bytes != 0" );
	}

	end_time = timeval_sum(&request_time, &timeout);

	DEBUG(10,("push_deferred_open_message_smb: pushing message "
		"len %u mid %llu timeout time [%u.%06u]\n",
		(unsigned int) smb_len(req->inbuf)+4,
		(unsigned long long)req->mid,
		(unsigned int)end_time.tv_sec,
		(unsigned int)end_time.tv_usec));

	return push_queued_message(req, request_time, end_time,
				   private_data, priv_len);
}

static void smbd_sig_term_handler(struct tevent_context *ev,
				  struct tevent_signal *se,
				  int signum,
				  int count,
				  void *siginfo,
				  void *private_data)
{
	exit_server_cleanly("termination signal");
}

void smbd_setup_sig_term_handler(struct smbd_server_connection *sconn)
{
	struct tevent_signal *se;

	se = tevent_add_signal(sconn->ev_ctx,
			       sconn,
			       SIGTERM, 0,
			       smbd_sig_term_handler,
			       sconn);
	if (!se) {
		exit_server("failed to setup SIGTERM handler");
	}
}

static void smbd_sig_hup_handler(struct tevent_context *ev,
				  struct tevent_signal *se,
				  int signum,
				  int count,
				  void *siginfo,
				  void *private_data)
{
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);

	change_to_root_user();
	DEBUG(1,("Reloading services after SIGHUP\n"));
	reload_services(sconn, conn_snum_used, false);
}

void smbd_setup_sig_hup_handler(struct smbd_server_connection *sconn)
{
	struct tevent_signal *se;

	se = tevent_add_signal(sconn->ev_ctx,
			       sconn,
			       SIGHUP, 0,
			       smbd_sig_hup_handler,
			       sconn);
	if (!se) {
		exit_server("failed to setup SIGHUP handler");
	}
}

static void smbd_conf_updated(struct messaging_context *msg,
			      void *private_data,
			      uint32_t msg_type,
			      struct server_id server_id,
			      DATA_BLOB *data)
{
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);

	DEBUG(10,("smbd_conf_updated: Got message saying smb.conf was "
		  "updated. Reloading.\n"));
	change_to_root_user();
	reload_services(sconn, conn_snum_used, false);
}

/*
 * Only allow 5 outstanding trans requests. We're allocating memory, so
 * prevent a DoS.
 */

NTSTATUS allow_new_trans(struct trans_state *list, uint64_t mid)
{
	int count = 0;
	for (; list != NULL; list = list->next) {

		if (list->mid == mid) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		count += 1;
	}
	if (count > 5) {
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	return NT_STATUS_OK;
}

/*
These flags determine some of the permissions required to do an operation 

Note that I don't set NEED_WRITE on some write operations because they
are used by some brain-dead clients when printing, and I don't want to
force write permissions on print services.
*/
#define AS_USER (1<<0)
#define NEED_WRITE (1<<1) /* Must be paired with AS_USER */
#define TIME_INIT (1<<2)
#define CAN_IPC (1<<3) /* Must be paired with AS_USER */
#define AS_GUEST (1<<5) /* Must *NOT* be paired with AS_USER */
#define DO_CHDIR (1<<6)

/* 
   define a list of possible SMB messages and their corresponding
   functions. Any message that has a NULL function is unimplemented -
   please feel free to contribute implementations!
*/
static const struct smb_message_struct {
	const char *name;
	void (*fn)(struct smb_request *req);
	int flags;
} smb_messages[256] = {

/* 0x00 */ { "SMBmkdir",reply_mkdir,AS_USER | NEED_WRITE},
/* 0x01 */ { "SMBrmdir",reply_rmdir,AS_USER | NEED_WRITE},
/* 0x02 */ { "SMBopen",reply_open,AS_USER },
/* 0x03 */ { "SMBcreate",reply_mknew,AS_USER},
/* 0x04 */ { "SMBclose",reply_close,AS_USER | CAN_IPC },
/* 0x05 */ { "SMBflush",reply_flush,AS_USER},
/* 0x06 */ { "SMBunlink",reply_unlink,AS_USER | NEED_WRITE },
/* 0x07 */ { "SMBmv",reply_mv,AS_USER | NEED_WRITE },
/* 0x08 */ { "SMBgetatr",reply_getatr,AS_USER},
/* 0x09 */ { "SMBsetatr",reply_setatr,AS_USER | NEED_WRITE},
/* 0x0a */ { "SMBread",reply_read,AS_USER},
/* 0x0b */ { "SMBwrite",reply_write,AS_USER | CAN_IPC },
/* 0x0c */ { "SMBlock",reply_lock,AS_USER},
/* 0x0d */ { "SMBunlock",reply_unlock,AS_USER},
/* 0x0e */ { "SMBctemp",reply_ctemp,AS_USER },
/* 0x0f */ { "SMBmknew",reply_mknew,AS_USER},
/* 0x10 */ { "SMBcheckpath",reply_checkpath,AS_USER},
/* 0x11 */ { "SMBexit",reply_exit,DO_CHDIR},
/* 0x12 */ { "SMBlseek",reply_lseek,AS_USER},
/* 0x13 */ { "SMBlockread",reply_lockread,AS_USER},
/* 0x14 */ { "SMBwriteunlock",reply_writeunlock,AS_USER},
/* 0x15 */ { NULL, NULL, 0 },
/* 0x16 */ { NULL, NULL, 0 },
/* 0x17 */ { NULL, NULL, 0 },
/* 0x18 */ { NULL, NULL, 0 },
/* 0x19 */ { NULL, NULL, 0 },
/* 0x1a */ { "SMBreadbraw",reply_readbraw,AS_USER},
/* 0x1b */ { "SMBreadBmpx",reply_readbmpx,AS_USER},
/* 0x1c */ { "SMBreadBs",reply_readbs,AS_USER },
/* 0x1d */ { "SMBwritebraw",reply_writebraw,AS_USER},
/* 0x1e */ { "SMBwriteBmpx",reply_writebmpx,AS_USER},
/* 0x1f */ { "SMBwriteBs",reply_writebs,AS_USER},
/* 0x20 */ { "SMBwritec", NULL,0},
/* 0x21 */ { NULL, NULL, 0 },
/* 0x22 */ { "SMBsetattrE",reply_setattrE,AS_USER | NEED_WRITE },
/* 0x23 */ { "SMBgetattrE",reply_getattrE,AS_USER },
/* 0x24 */ { "SMBlockingX",reply_lockingX,AS_USER },
/* 0x25 */ { "SMBtrans",reply_trans,AS_USER | CAN_IPC },
/* 0x26 */ { "SMBtranss",reply_transs,AS_USER | CAN_IPC},
/* 0x27 */ { "SMBioctl",reply_ioctl,0},
/* 0x28 */ { "SMBioctls", NULL,AS_USER},
/* 0x29 */ { "SMBcopy",reply_copy,AS_USER | NEED_WRITE },
/* 0x2a */ { "SMBmove", NULL,AS_USER | NEED_WRITE },
/* 0x2b */ { "SMBecho",reply_echo,0},
/* 0x2c */ { "SMBwriteclose",reply_writeclose,AS_USER},
/* 0x2d */ { "SMBopenX",reply_open_and_X,AS_USER | CAN_IPC },
/* 0x2e */ { "SMBreadX",reply_read_and_X,AS_USER | CAN_IPC },
/* 0x2f */ { "SMBwriteX",reply_write_and_X,AS_USER | CAN_IPC },
/* 0x30 */ { NULL, NULL, 0 },
/* 0x31 */ { NULL, NULL, 0 },
/* 0x32 */ { "SMBtrans2",reply_trans2, AS_USER | CAN_IPC },
/* 0x33 */ { "SMBtranss2",reply_transs2, AS_USER | CAN_IPC },
/* 0x34 */ { "SMBfindclose",reply_findclose,AS_USER},
/* 0x35 */ { "SMBfindnclose",reply_findnclose,AS_USER},
/* 0x36 */ { NULL, NULL, 0 },
/* 0x37 */ { NULL, NULL, 0 },
/* 0x38 */ { NULL, NULL, 0 },
/* 0x39 */ { NULL, NULL, 0 },
/* 0x3a */ { NULL, NULL, 0 },
/* 0x3b */ { NULL, NULL, 0 },
/* 0x3c */ { NULL, NULL, 0 },
/* 0x3d */ { NULL, NULL, 0 },
/* 0x3e */ { NULL, NULL, 0 },
/* 0x3f */ { NULL, NULL, 0 },
/* 0x40 */ { NULL, NULL, 0 },
/* 0x41 */ { NULL, NULL, 0 },
/* 0x42 */ { NULL, NULL, 0 },
/* 0x43 */ { NULL, NULL, 0 },
/* 0x44 */ { NULL, NULL, 0 },
/* 0x45 */ { NULL, NULL, 0 },
/* 0x46 */ { NULL, NULL, 0 },
/* 0x47 */ { NULL, NULL, 0 },
/* 0x48 */ { NULL, NULL, 0 },
/* 0x49 */ { NULL, NULL, 0 },
/* 0x4a */ { NULL, NULL, 0 },
/* 0x4b */ { NULL, NULL, 0 },
/* 0x4c */ { NULL, NULL, 0 },
/* 0x4d */ { NULL, NULL, 0 },
/* 0x4e */ { NULL, NULL, 0 },
/* 0x4f */ { NULL, NULL, 0 },
/* 0x50 */ { NULL, NULL, 0 },
/* 0x51 */ { NULL, NULL, 0 },
/* 0x52 */ { NULL, NULL, 0 },
/* 0x53 */ { NULL, NULL, 0 },
/* 0x54 */ { NULL, NULL, 0 },
/* 0x55 */ { NULL, NULL, 0 },
/* 0x56 */ { NULL, NULL, 0 },
/* 0x57 */ { NULL, NULL, 0 },
/* 0x58 */ { NULL, NULL, 0 },
/* 0x59 */ { NULL, NULL, 0 },
/* 0x5a */ { NULL, NULL, 0 },
/* 0x5b */ { NULL, NULL, 0 },
/* 0x5c */ { NULL, NULL, 0 },
/* 0x5d */ { NULL, NULL, 0 },
/* 0x5e */ { NULL, NULL, 0 },
/* 0x5f */ { NULL, NULL, 0 },
/* 0x60 */ { NULL, NULL, 0 },
/* 0x61 */ { NULL, NULL, 0 },
/* 0x62 */ { NULL, NULL, 0 },
/* 0x63 */ { NULL, NULL, 0 },
/* 0x64 */ { NULL, NULL, 0 },
/* 0x65 */ { NULL, NULL, 0 },
/* 0x66 */ { NULL, NULL, 0 },
/* 0x67 */ { NULL, NULL, 0 },
/* 0x68 */ { NULL, NULL, 0 },
/* 0x69 */ { NULL, NULL, 0 },
/* 0x6a */ { NULL, NULL, 0 },
/* 0x6b */ { NULL, NULL, 0 },
/* 0x6c */ { NULL, NULL, 0 },
/* 0x6d */ { NULL, NULL, 0 },
/* 0x6e */ { NULL, NULL, 0 },
/* 0x6f */ { NULL, NULL, 0 },
/* 0x70 */ { "SMBtcon",reply_tcon,0},
/* 0x71 */ { "SMBtdis",reply_tdis,DO_CHDIR},
/* 0x72 */ { "SMBnegprot",reply_negprot,0},
/* 0x73 */ { "SMBsesssetupX",reply_sesssetup_and_X,0},
/* 0x74 */ { "SMBulogoffX",reply_ulogoffX, 0}, /* ulogoff doesn't give a valid TID */
/* 0x75 */ { "SMBtconX",reply_tcon_and_X,0},
/* 0x76 */ { NULL, NULL, 0 },
/* 0x77 */ { NULL, NULL, 0 },
/* 0x78 */ { NULL, NULL, 0 },
/* 0x79 */ { NULL, NULL, 0 },
/* 0x7a */ { NULL, NULL, 0 },
/* 0x7b */ { NULL, NULL, 0 },
/* 0x7c */ { NULL, NULL, 0 },
/* 0x7d */ { NULL, NULL, 0 },
/* 0x7e */ { NULL, NULL, 0 },
/* 0x7f */ { NULL, NULL, 0 },
/* 0x80 */ { "SMBdskattr",reply_dskattr,AS_USER},
/* 0x81 */ { "SMBsearch",reply_search,AS_USER},
/* 0x82 */ { "SMBffirst",reply_search,AS_USER},
/* 0x83 */ { "SMBfunique",reply_search,AS_USER},
/* 0x84 */ { "SMBfclose",reply_fclose,AS_USER},
/* 0x85 */ { NULL, NULL, 0 },
/* 0x86 */ { NULL, NULL, 0 },
/* 0x87 */ { NULL, NULL, 0 },
/* 0x88 */ { NULL, NULL, 0 },
/* 0x89 */ { NULL, NULL, 0 },
/* 0x8a */ { NULL, NULL, 0 },
/* 0x8b */ { NULL, NULL, 0 },
/* 0x8c */ { NULL, NULL, 0 },
/* 0x8d */ { NULL, NULL, 0 },
/* 0x8e */ { NULL, NULL, 0 },
/* 0x8f */ { NULL, NULL, 0 },
/* 0x90 */ { NULL, NULL, 0 },
/* 0x91 */ { NULL, NULL, 0 },
/* 0x92 */ { NULL, NULL, 0 },
/* 0x93 */ { NULL, NULL, 0 },
/* 0x94 */ { NULL, NULL, 0 },
/* 0x95 */ { NULL, NULL, 0 },
/* 0x96 */ { NULL, NULL, 0 },
/* 0x97 */ { NULL, NULL, 0 },
/* 0x98 */ { NULL, NULL, 0 },
/* 0x99 */ { NULL, NULL, 0 },
/* 0x9a */ { NULL, NULL, 0 },
/* 0x9b */ { NULL, NULL, 0 },
/* 0x9c */ { NULL, NULL, 0 },
/* 0x9d */ { NULL, NULL, 0 },
/* 0x9e */ { NULL, NULL, 0 },
/* 0x9f */ { NULL, NULL, 0 },
/* 0xa0 */ { "SMBnttrans",reply_nttrans, AS_USER | CAN_IPC },
/* 0xa1 */ { "SMBnttranss",reply_nttranss, AS_USER | CAN_IPC },
/* 0xa2 */ { "SMBntcreateX",reply_ntcreate_and_X, AS_USER | CAN_IPC },
/* 0xa3 */ { NULL, NULL, 0 },
/* 0xa4 */ { "SMBntcancel",reply_ntcancel, 0 },
/* 0xa5 */ { "SMBntrename",reply_ntrename, AS_USER | NEED_WRITE },
/* 0xa6 */ { NULL, NULL, 0 },
/* 0xa7 */ { NULL, NULL, 0 },
/* 0xa8 */ { NULL, NULL, 0 },
/* 0xa9 */ { NULL, NULL, 0 },
/* 0xaa */ { NULL, NULL, 0 },
/* 0xab */ { NULL, NULL, 0 },
/* 0xac */ { NULL, NULL, 0 },
/* 0xad */ { NULL, NULL, 0 },
/* 0xae */ { NULL, NULL, 0 },
/* 0xaf */ { NULL, NULL, 0 },
/* 0xb0 */ { NULL, NULL, 0 },
/* 0xb1 */ { NULL, NULL, 0 },
/* 0xb2 */ { NULL, NULL, 0 },
/* 0xb3 */ { NULL, NULL, 0 },
/* 0xb4 */ { NULL, NULL, 0 },
/* 0xb5 */ { NULL, NULL, 0 },
/* 0xb6 */ { NULL, NULL, 0 },
/* 0xb7 */ { NULL, NULL, 0 },
/* 0xb8 */ { NULL, NULL, 0 },
/* 0xb9 */ { NULL, NULL, 0 },
/* 0xba */ { NULL, NULL, 0 },
/* 0xbb */ { NULL, NULL, 0 },
/* 0xbc */ { NULL, NULL, 0 },
/* 0xbd */ { NULL, NULL, 0 },
/* 0xbe */ { NULL, NULL, 0 },
/* 0xbf */ { NULL, NULL, 0 },
/* 0xc0 */ { "SMBsplopen",reply_printopen,AS_USER},
/* 0xc1 */ { "SMBsplwr",reply_printwrite,AS_USER},
/* 0xc2 */ { "SMBsplclose",reply_printclose,AS_USER},
/* 0xc3 */ { "SMBsplretq",reply_printqueue,AS_USER},
/* 0xc4 */ { NULL, NULL, 0 },
/* 0xc5 */ { NULL, NULL, 0 },
/* 0xc6 */ { NULL, NULL, 0 },
/* 0xc7 */ { NULL, NULL, 0 },
/* 0xc8 */ { NULL, NULL, 0 },
/* 0xc9 */ { NULL, NULL, 0 },
/* 0xca */ { NULL, NULL, 0 },
/* 0xcb */ { NULL, NULL, 0 },
/* 0xcc */ { NULL, NULL, 0 },
/* 0xcd */ { NULL, NULL, 0 },
/* 0xce */ { NULL, NULL, 0 },
/* 0xcf */ { NULL, NULL, 0 },
/* 0xd0 */ { "SMBsends",reply_sends,AS_GUEST},
/* 0xd1 */ { "SMBsendb", NULL,AS_GUEST},
/* 0xd2 */ { "SMBfwdname", NULL,AS_GUEST},
/* 0xd3 */ { "SMBcancelf", NULL,AS_GUEST},
/* 0xd4 */ { "SMBgetmac", NULL,AS_GUEST},
/* 0xd5 */ { "SMBsendstrt",reply_sendstrt,AS_GUEST},
/* 0xd6 */ { "SMBsendend",reply_sendend,AS_GUEST},
/* 0xd7 */ { "SMBsendtxt",reply_sendtxt,AS_GUEST},
/* 0xd8 */ { NULL, NULL, 0 },
/* 0xd9 */ { NULL, NULL, 0 },
/* 0xda */ { NULL, NULL, 0 },
/* 0xdb */ { NULL, NULL, 0 },
/* 0xdc */ { NULL, NULL, 0 },
/* 0xdd */ { NULL, NULL, 0 },
/* 0xde */ { NULL, NULL, 0 },
/* 0xdf */ { NULL, NULL, 0 },
/* 0xe0 */ { NULL, NULL, 0 },
/* 0xe1 */ { NULL, NULL, 0 },
/* 0xe2 */ { NULL, NULL, 0 },
/* 0xe3 */ { NULL, NULL, 0 },
/* 0xe4 */ { NULL, NULL, 0 },
/* 0xe5 */ { NULL, NULL, 0 },
/* 0xe6 */ { NULL, NULL, 0 },
/* 0xe7 */ { NULL, NULL, 0 },
/* 0xe8 */ { NULL, NULL, 0 },
/* 0xe9 */ { NULL, NULL, 0 },
/* 0xea */ { NULL, NULL, 0 },
/* 0xeb */ { NULL, NULL, 0 },
/* 0xec */ { NULL, NULL, 0 },
/* 0xed */ { NULL, NULL, 0 },
/* 0xee */ { NULL, NULL, 0 },
/* 0xef */ { NULL, NULL, 0 },
/* 0xf0 */ { NULL, NULL, 0 },
/* 0xf1 */ { NULL, NULL, 0 },
/* 0xf2 */ { NULL, NULL, 0 },
/* 0xf3 */ { NULL, NULL, 0 },
/* 0xf4 */ { NULL, NULL, 0 },
/* 0xf5 */ { NULL, NULL, 0 },
/* 0xf6 */ { NULL, NULL, 0 },
/* 0xf7 */ { NULL, NULL, 0 },
/* 0xf8 */ { NULL, NULL, 0 },
/* 0xf9 */ { NULL, NULL, 0 },
/* 0xfa */ { NULL, NULL, 0 },
/* 0xfb */ { NULL, NULL, 0 },
/* 0xfc */ { NULL, NULL, 0 },
/* 0xfd */ { NULL, NULL, 0 },
/* 0xfe */ { NULL, NULL, 0 },
/* 0xff */ { NULL, NULL, 0 }

};

/*******************************************************************
 allocate and initialize a reply packet
********************************************************************/

static bool create_outbuf(TALLOC_CTX *mem_ctx, struct smb_request *req,
			  const char *inbuf, char **outbuf, uint8_t num_words,
			  uint32_t num_bytes)
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

	construct_reply_common(req, inbuf, *outbuf);
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

void reply_outbuf(struct smb_request *req, uint8 num_words, uint32 num_bytes)
{
	char *outbuf;
	if (!create_outbuf(req, req, (const char *)req->inbuf, &outbuf, num_words,
			   num_bytes)) {
		smb_panic("could not allocate output buffer\n");
	}
	req->outbuf = (uint8_t *)outbuf;
}


/*******************************************************************
 Dump a packet to a file.
********************************************************************/

static void smb_dump(const char *name, int type, const char *data)
{
	size_t len;
	int fd, i;
	char *fname = NULL;
	if (DEBUGLEVEL < 50) {
		return;
	}

	len = smb_len_tcp(data)+4;
	for (i=1;i<100;i++) {
		fname = talloc_asprintf(talloc_tos(),
				"/tmp/%s.%d.%s",
				name,
				i,
				type ? "req" : "resp");
		if (fname == NULL) {
			return;
		}
		fd = open(fname, O_WRONLY|O_CREAT|O_EXCL, 0644);
		if (fd != -1 || errno != EEXIST) break;
		TALLOC_FREE(fname);
	}
	if (fd != -1) {
		ssize_t ret = write(fd, data, len);
		if (ret != len)
			DEBUG(0,("smb_dump: problem: write returned %d\n", (int)ret ));
		close(fd);
		DEBUG(0,("created %s len %lu\n", fname, (unsigned long)len));
	}
	TALLOC_FREE(fname);
}

/****************************************************************************
 Prepare everything for calling the actual request function, and potentially
 call the request function via the "new" interface.

 Return False if the "legacy" function needs to be called, everything is
 prepared.

 Return True if we're done.

 I know this API sucks, but it is the one with the least code change I could
 find.
****************************************************************************/

static connection_struct *switch_message(uint8 type, struct smb_request *req)
{
	int flags;
	uint64_t session_tag;
	connection_struct *conn = NULL;
	struct smbd_server_connection *sconn = req->sconn;
	NTTIME now = timeval_to_nttime(&req->request_time);
	struct smbXsrv_session *session = NULL;
	NTSTATUS status;

	errno = 0;

	if (smb_messages[type].fn == NULL) {
		DEBUG(0,("Unknown message type %d!\n",type));
		smb_dump("Unknown", 1, (const char *)req->inbuf);
		reply_unknown_new(req, type);
		return NULL;
	}

	flags = smb_messages[type].flags;

	/* In share mode security we must ignore the vuid. */
	session_tag = req->vuid;
	conn = req->conn;

	DEBUG(3,("switch message %s (pid %d) conn 0x%lx\n", smb_fn_name(type),
		 (int)getpid(), (unsigned long)conn));

	smb_dump(smb_fn_name(type), 1, (const char *)req->inbuf);

	/* Ensure this value is replaced in the incoming packet. */
	SSVAL(discard_const_p(uint8_t, req->inbuf),smb_uid,session_tag);

	/*
	 * Ensure the correct username is in current_user_info.  This is a
	 * really ugly bugfix for problems with multiple session_setup_and_X's
	 * being done and allowing %U and %G substitutions to work correctly.
	 * There is a reason this code is done here, don't move it unless you
	 * know what you're doing... :-).
	 * JRA.
	 */

	/*
	 * lookup an existing session
	 *
	 * Note: for now we only check for NT_STATUS_NETWORK_SESSION_EXPIRED
	 * here, the main check is still in change_to_user()
	 */
	status = smb1srv_session_lookup(sconn->conn,
					session_tag,
					now,
					&session);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_SESSION_EXPIRED)) {
		switch (type) {
		case SMBsesssetupX:
			status = NT_STATUS_OK;
			break;
		default:
			DEBUG(1,("Error: session %llu is expired, mid=%llu.\n",
				 (unsigned long long)session_tag,
				 (unsigned long long)req->mid));
			reply_nterror(req, NT_STATUS_NETWORK_SESSION_EXPIRED);
			return conn;
		}
	}

	if (session_tag != sconn->smb1.sessions.last_session_tag) {
		struct user_struct *vuser = NULL;

		sconn->smb1.sessions.last_session_tag = session_tag;
		if (session) {
			vuser = session->compat;
		}
		if (vuser) {
			set_current_user_info(
				vuser->session_info->unix_info->sanitized_username,
				vuser->session_info->unix_info->unix_name,
				vuser->session_info->info->domain_name);
		}
	}

	/* Does this call need to be run as the connected user? */
	if (flags & AS_USER) {

		/* Does this call need a valid tree connection? */
		if (!conn) {
			/*
			 * Amazingly, the error code depends on the command
			 * (from Samba4).
			 */
			if (type == SMBntcreateX) {
				reply_nterror(req, NT_STATUS_INVALID_HANDLE);
			} else {
				reply_nterror(req, NT_STATUS_NETWORK_NAME_DELETED);
			}
			return NULL;
		}

		if (!change_to_user(conn,session_tag)) {
			DEBUG(0, ("Error: Could not change to user. Removing "
				"deferred open, mid=%llu.\n",
				(unsigned long long)req->mid));
			reply_force_doserror(req, ERRSRV, ERRbaduid);
			return conn;
		}

		/* All NEED_WRITE and CAN_IPC flags must also have AS_USER. */

		/* Does it need write permission? */
		if ((flags & NEED_WRITE) && !CAN_WRITE(conn)) {
			reply_nterror(req, NT_STATUS_MEDIA_WRITE_PROTECTED);
			return conn;
		}

		/* IPC services are limited */
		if (IS_IPC(conn) && !(flags & CAN_IPC)) {
			reply_nterror(req, NT_STATUS_ACCESS_DENIED);
			return conn;
		}
	} else {
		/* This call needs to be run as root */
		change_to_root_user();
	}

	/* load service specific parameters */
	if (conn) {
		if (req->encrypted) {
			conn->encrypted_tid = true;
			/* encrypted required from now on. */
			conn->encrypt_level = SMB_SIGNING_REQUIRED;
		} else if (ENCRYPTION_REQUIRED(conn)) {
			if (req->cmd != SMBtrans2 && req->cmd != SMBtranss2) {
				DEBUG(1,("service[%s] requires encryption"
					"%s ACCESS_DENIED. mid=%llu\n",
					lp_servicename(talloc_tos(), SNUM(conn)),
					smb_fn_name(type),
					(unsigned long long)req->mid));
				reply_nterror(req, NT_STATUS_ACCESS_DENIED);
				return conn;
			}
		}

		if (!set_current_service(conn,SVAL(req->inbuf,smb_flg),
					 (flags & (AS_USER|DO_CHDIR)
					  ?True:False))) {
			reply_nterror(req, NT_STATUS_ACCESS_DENIED);
			return conn;
		}
		conn->num_smb_operations++;
	}

	/*
	 * Does this protocol need to be run as guest? (Only archane
	 * messenger service requests have this...)
	 */
	if (flags & AS_GUEST) {
		char *raddr;
		bool ok;

		if (!change_to_guest()) {
			reply_nterror(req, NT_STATUS_ACCESS_DENIED);
			return conn;
		}

		raddr = tsocket_address_inet_addr_string(sconn->remote_address,
							 talloc_tos());
		if (raddr == NULL) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			return conn;
		}

		/*
		 * Haven't we checked this in smbd_process already???
		 */

		ok = allow_access(lp_hostsdeny(-1), lp_hostsallow(-1),
				  sconn->remote_hostname, raddr);
		TALLOC_FREE(raddr);

		if (!ok) {
			reply_nterror(req, NT_STATUS_ACCESS_DENIED);
			return conn;
		}
	}

	smb_messages[type].fn(req);
	return req->conn;
}

/****************************************************************************
 Construct a reply to the incoming packet.
****************************************************************************/

static void construct_reply(struct smbd_server_connection *sconn,
			    char *inbuf, int size, size_t unread_bytes,
			    uint32_t seqnum, bool encrypted,
			    struct smb_perfcount_data *deferred_pcd)
{
	connection_struct *conn;
	struct smb_request *req;

	if (!(req = talloc(talloc_tos(), struct smb_request))) {
		smb_panic("could not allocate smb_request");
	}

	if (!init_smb_request(req, sconn, (uint8 *)inbuf, unread_bytes,
			      encrypted, seqnum)) {
		exit_server_cleanly("Invalid SMB request");
	}

	req->inbuf  = (uint8_t *)talloc_move(req, &inbuf);

	/* we popped this message off the queue - keep original perf data */
	if (deferred_pcd)
		req->pcd = *deferred_pcd;
	else {
		SMB_PERFCOUNT_START(&req->pcd);
		SMB_PERFCOUNT_SET_OP(&req->pcd, req->cmd);
		SMB_PERFCOUNT_SET_MSGLEN_IN(&req->pcd, size);
	}

	conn = switch_message(req->cmd, req);

	if (req->outbuf == NULL) {
		return;
	}

	if (CVAL(req->outbuf,0) == 0) {
		show_msg((char *)req->outbuf);
	}

	if (!srv_send_smb(req->sconn,
			(char *)req->outbuf,
			true, req->seqnum+1,
			IS_CONN_ENCRYPTED(conn)||req->encrypted,
			&req->pcd)) {
		exit_server_cleanly("construct_reply: srv_send_smb failed.");
	}

	TALLOC_FREE(req);

	return;
}

static void construct_reply_chain(struct smbd_server_connection *sconn,
				  char *inbuf, int size, uint32_t seqnum,
				  bool encrypted,
				  struct smb_perfcount_data *deferred_pcd)
{
	struct smb_request **reqs = NULL;
	struct smb_request *req;
	unsigned num_reqs;
	bool ok;

	ok = smb1_parse_chain(talloc_tos(), (uint8_t *)inbuf, sconn, encrypted,
			      seqnum, &reqs, &num_reqs);
	if (!ok) {
		char errbuf[smb_size];
		error_packet(errbuf, 0, 0, NT_STATUS_INVALID_PARAMETER,
			     __LINE__, __FILE__);
		if (!srv_send_smb(sconn, errbuf, true, seqnum, encrypted,
				  NULL)) {
			exit_server_cleanly("construct_reply_chain: "
					    "srv_send_smb failed.");
		}
		return;
	}

	req = reqs[0];
	req->inbuf = (uint8_t *)talloc_move(reqs, &inbuf);

	req->conn = switch_message(req->cmd, req);

	if (req->outbuf == NULL) {
		/*
		 * Request has suspended itself, will come
		 * back here.
		 */
		return;
	}
	smb_request_done(req);
}

/*
 * To be called from an async SMB handler that is potentially chained
 * when it is finished for shipping.
 */

void smb_request_done(struct smb_request *req)
{
	struct smb_request **reqs = NULL;
	struct smb_request *first_req;
	size_t i, num_reqs, next_index;
	NTSTATUS status;

	if (req->chain == NULL) {
		first_req = req;
		goto shipit;
	}

	reqs = req->chain;
	num_reqs = talloc_array_length(reqs);

	for (i=0; i<num_reqs; i++) {
		if (reqs[i] == req) {
			break;
		}
	}
	if (i == num_reqs) {
		/*
		 * Invalid chain, should not happen
		 */
		status = NT_STATUS_INTERNAL_ERROR;
		goto error;
	}
	next_index = i+1;

	while ((next_index < num_reqs) && (IVAL(req->outbuf, smb_rcls) == 0)) {
		struct smb_request *next = reqs[next_index];
		struct smbXsrv_tcon *tcon;
		NTTIME now = timeval_to_nttime(&req->request_time);

		next->vuid = SVAL(req->outbuf, smb_uid);
		next->tid  = SVAL(req->outbuf, smb_tid);
		status = smb1srv_tcon_lookup(req->sconn->conn, req->tid,
					     now, &tcon);
		if (NT_STATUS_IS_OK(status)) {
			req->conn = tcon->compat;
		} else {
			req->conn = NULL;
		}
		next->chain_fsp = req->chain_fsp;
		next->inbuf = (uint8_t *)req->inbuf;

		req = next;
		req->conn = switch_message(req->cmd, req);

		if (req->outbuf == NULL) {
			/*
			 * Request has suspended itself, will come
			 * back here.
			 */
			return;
		}
		next_index += 1;
	}

	first_req = reqs[0];

	for (i=1; i<next_index; i++) {
		bool ok;

		ok = smb_splice_chain(&first_req->outbuf, reqs[i]->outbuf);
		if (!ok) {
			status = NT_STATUS_INTERNAL_ERROR;
			goto error;
		}
	}

	SSVAL(first_req->outbuf, smb_uid, SVAL(req->outbuf, smb_uid));
	SSVAL(first_req->outbuf, smb_tid, SVAL(req->outbuf, smb_tid));

	/*
	 * This scary statement intends to set the
	 * FLAGS2_32_BIT_ERROR_CODES flg2 field in first_req->outbuf
	 * to the value last_req->outbuf carries
	 */
	SSVAL(first_req->outbuf, smb_flg2,
	      (SVAL(first_req->outbuf, smb_flg2) & ~FLAGS2_32_BIT_ERROR_CODES)
	      |(SVAL(req->outbuf, smb_flg2) & FLAGS2_32_BIT_ERROR_CODES));

	/*
	 * Transfer the error codes from the subrequest to the main one
	 */
	SSVAL(first_req->outbuf, smb_rcls, SVAL(req->outbuf, smb_rcls));
	SSVAL(first_req->outbuf, smb_err,  SVAL(req->outbuf, smb_err));

	_smb_setlen_large(
		first_req->outbuf, talloc_get_size(first_req->outbuf) - 4);

shipit:
	if (!srv_send_smb(first_req->sconn,
			  (char *)first_req->outbuf,
			  true, first_req->seqnum+1,
			  IS_CONN_ENCRYPTED(req->conn)||first_req->encrypted,
			  &first_req->pcd)) {
		exit_server_cleanly("construct_reply_chain: srv_send_smb "
				    "failed.");
	}
	TALLOC_FREE(req);	/* non-chained case */
	TALLOC_FREE(reqs);	/* chained case */
	return;

error:
	{
		char errbuf[smb_size];
		error_packet(errbuf, 0, 0, status, __LINE__, __FILE__);
		if (!srv_send_smb(req->sconn, errbuf, true,
				  req->seqnum+1, req->encrypted,
				  NULL)) {
			exit_server_cleanly("construct_reply_chain: "
					    "srv_send_smb failed.");
		}
	}
	TALLOC_FREE(req);	/* non-chained case */
	TALLOC_FREE(reqs);	/* chained case */
}

/****************************************************************************
 Process an smb from the client
****************************************************************************/
static void process_smb(struct smbd_server_connection *sconn,
			uint8_t *inbuf, size_t nread, size_t unread_bytes,
			uint32_t seqnum, bool encrypted,
			struct smb_perfcount_data *deferred_pcd)
{
	int msg_type = CVAL(inbuf,0);

	DO_PROFILE_INC(smb_count);

	DEBUG( 6, ( "got message type 0x%x of len 0x%x\n", msg_type,
		    smb_len(inbuf) ) );
	DEBUG(3, ("Transaction %d of length %d (%u toread)\n",
		  sconn->trans_num, (int)nread, (unsigned int)unread_bytes));

	if (msg_type != NBSSmessage) {
		/*
		 * NetBIOS session request, keepalive, etc.
		 */
		reply_special(sconn, (char *)inbuf, nread);
		goto done;
	}

	if (sconn->using_smb2) {
		/* At this point we're not really using smb2,
		 * we make the decision here.. */
		if (smbd_is_smb2_header(inbuf, nread)) {
			smbd_smb2_first_negprot(sconn, inbuf, nread);
			return;
		} else if (nread >= smb_size && valid_smb_header(sconn, inbuf)
				&& CVAL(inbuf, smb_com) != 0x72) {
			/* This is a non-negprot SMB1 packet.
			   Disable SMB2 from now on. */
			sconn->using_smb2 = false;
		}
	}

	/* Make sure this is an SMB packet. smb_size contains NetBIOS header
	 * so subtract 4 from it. */
	if ((nread < (smb_size - 4)) || !valid_smb_header(sconn, inbuf)) {
		DEBUG(2,("Non-SMB packet of length %d. Terminating server\n",
			 smb_len(inbuf)));

		/* special magic for immediate exit */
		if ((nread == 9) &&
		    (IVAL(inbuf, 4) == 0x74697865) &&
		    lp_parm_bool(-1, "smbd", "suicide mode", false)) {
			uint8_t exitcode = CVAL(inbuf, 8);
			DEBUG(1, ("Exiting immediately with code %d\n",
				  (int)exitcode));
			exit(exitcode);
		}

		exit_server_cleanly("Non-SMB packet");
	}

	show_msg((char *)inbuf);

	if ((unread_bytes == 0) && smb1_is_chain(inbuf)) {
		construct_reply_chain(sconn, (char *)inbuf, nread,
				      seqnum, encrypted, deferred_pcd);
	} else {
		construct_reply(sconn, (char *)inbuf, nread, unread_bytes,
				seqnum,	encrypted, deferred_pcd);
	}

	sconn->trans_num++;

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

/****************************************************************************
 Return a string containing the function name of a SMB command.
****************************************************************************/

const char *smb_fn_name(int type)
{
	const char *unknown_name = "SMBunknown";

	if (smb_messages[type].name == NULL)
		return(unknown_name);

	return(smb_messages[type].name);
}

/****************************************************************************
 Helper functions for contruct_reply.
****************************************************************************/

void add_to_common_flags2(uint32 v)
{
	common_flags2 |= v;
}

void remove_from_common_flags2(uint32 v)
{
	common_flags2 &= ~v;
}

static void construct_reply_common(struct smb_request *req, const char *inbuf,
				   char *outbuf)
{
	uint16_t in_flags2 = SVAL(inbuf,smb_flg2);
	uint16_t out_flags2 = common_flags2;

	out_flags2 |= in_flags2 & FLAGS2_UNICODE_STRINGS;
	out_flags2 |= in_flags2 & FLAGS2_SMB_SECURITY_SIGNATURES;
	out_flags2 |= in_flags2 & FLAGS2_SMB_SECURITY_SIGNATURES_REQUIRED;

	srv_set_message(outbuf,0,0,false);

	SCVAL(outbuf, smb_com, req->cmd);
	SIVAL(outbuf,smb_rcls,0);
	SCVAL(outbuf,smb_flg, FLAG_REPLY | (CVAL(inbuf,smb_flg) & FLAG_CASELESS_PATHNAMES)); 
	SSVAL(outbuf,smb_flg2, out_flags2);
	memset(outbuf+smb_pidhigh,'\0',(smb_tid-smb_pidhigh));
	memcpy(outbuf+smb_ss_field, inbuf+smb_ss_field, 8);

	SSVAL(outbuf,smb_tid,SVAL(inbuf,smb_tid));
	SSVAL(outbuf,smb_pid,SVAL(inbuf,smb_pid));
	SSVAL(outbuf,smb_uid,SVAL(inbuf,smb_uid));
	SSVAL(outbuf,smb_mid,SVAL(inbuf,smb_mid));
}

void construct_reply_common_req(struct smb_request *req, char *outbuf)
{
	construct_reply_common(req, (const char *)req->inbuf, outbuf);
}

/**
 * @brief Find the smb_cmd offset of the last command pushed
 * @param[in] buf	The buffer we're building up
 * @retval		Where can we put our next andx cmd?
 *
 * While chaining requests, the "next" request we're looking at needs to put
 * its SMB_Command before the data the previous request already built up added
 * to the chain. Find the offset to the place where we have to put our cmd.
 */

static bool find_andx_cmd_ofs(uint8_t *buf, size_t *pofs)
{
	uint8_t cmd;
	size_t ofs;

	cmd = CVAL(buf, smb_com);

	if (!is_andx_req(cmd)) {
		return false;
	}

	ofs = smb_vwv0;

	while (CVAL(buf, ofs) != 0xff) {

		if (!is_andx_req(CVAL(buf, ofs))) {
			return false;
		}

		/*
		 * ofs is from start of smb header, so add the 4 length
		 * bytes. The next cmd is right after the wct field.
		 */
		ofs = SVAL(buf, ofs+2) + 4 + 1;

		if (ofs+4 >= talloc_get_size(buf)) {
			return false;
		}
	}

	*pofs = ofs;
	return true;
}

/**
 * @brief Do the smb chaining at a buffer level
 * @param[in] poutbuf		Pointer to the talloc'ed buffer to be modified
 * @param[in] andx_buf		Buffer to be appended
 */

static bool smb_splice_chain(uint8_t **poutbuf, const uint8_t *andx_buf)
{
	uint8_t smb_command	= CVAL(andx_buf, smb_com);
	uint8_t wct		= CVAL(andx_buf, smb_wct);
	const uint16_t *vwv	= (const uint16_t *)(andx_buf + smb_vwv);
	uint32_t num_bytes	= smb_buflen(andx_buf);
	const uint8_t *bytes	= (const uint8_t *)smb_buf_const(andx_buf);

	uint8_t *outbuf;
	size_t old_size, new_size;
	size_t ofs;
	size_t chain_padding = 0;
	size_t andx_cmd_ofs;


	old_size = talloc_get_size(*poutbuf);

	if ((old_size % 4) != 0) {
		/*
		 * Align the wct field of subsequent requests to a 4-byte
		 * boundary
		 */
		chain_padding = 4 - (old_size % 4);
	}

	/*
	 * After the old request comes the new wct field (1 byte), the vwv's
	 * and the num_bytes field.
	 */

	new_size = old_size + chain_padding + 1 + wct * sizeof(uint16_t) + 2;
	new_size += num_bytes;

	if ((smb_command != SMBwriteX) && (new_size > 0xffff)) {
		DEBUG(1, ("smb_splice_chain: %u bytes won't fit\n",
			  (unsigned)new_size));
		return false;
	}

	outbuf = talloc_realloc(NULL, *poutbuf, uint8_t, new_size);
	if (outbuf == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return false;
	}
	*poutbuf = outbuf;

	if (!find_andx_cmd_ofs(outbuf, &andx_cmd_ofs)) {
		DEBUG(1, ("invalid command chain\n"));
		*poutbuf = talloc_realloc(NULL, *poutbuf, uint8_t, old_size);
		return false;
	}

	if (chain_padding != 0) {
		memset(outbuf + old_size, 0, chain_padding);
		old_size += chain_padding;
	}

	SCVAL(outbuf, andx_cmd_ofs, smb_command);
	SSVAL(outbuf, andx_cmd_ofs + 2, old_size - 4);

	ofs = old_size;

	/*
	 * Push the chained request:
	 *
	 * wct field
	 */

	SCVAL(outbuf, ofs, wct);
	ofs += 1;

	/*
	 * vwv array
	 */

	memcpy(outbuf + ofs, vwv, sizeof(uint16_t) * wct);

	/*
	 * HACK ALERT
	 *
	 * Read&X has an offset into its data buffer at
	 * vwv[6]. reply_read_andx has no idea anymore that it's
	 * running from within a chain, so we have to fix up the
	 * offset here.
	 *
	 * Although it looks disgusting at this place, I want to keep
	 * it here. The alternative would be to push knowledge about
	 * the andx chain down into read&x again.
	 */

	if (smb_command == SMBreadX) {
		uint8_t *bytes_addr;

		if (wct < 7) {
			/*
			 * Invalid read&x response
			 */
			return false;
		}

		bytes_addr = outbuf + ofs	 /* vwv start */
			+ sizeof(uint16_t) * wct /* vwv array */
			+ sizeof(uint16_t);	 /* bcc */

		SSVAL(outbuf + ofs, 6 * sizeof(uint16_t),
		      bytes_addr - outbuf - 4);
	}

	ofs += sizeof(uint16_t) * wct;

	/*
	 * bcc (byte count)
	 */

	SSVAL(outbuf, ofs, num_bytes);
	ofs += sizeof(uint16_t);

	/*
	 * The bytes field
	 */

	memcpy(outbuf + ofs, bytes, num_bytes);

	return true;
}

bool smb1_is_chain(const uint8_t *buf)
{
	uint8_t cmd, wct, andx_cmd;

	cmd = CVAL(buf, smb_com);
	if (!is_andx_req(cmd)) {
		return false;
	}
	wct = CVAL(buf, smb_wct);
	if (wct < 2) {
		return false;
	}
	andx_cmd = CVAL(buf, smb_vwv);
	return (andx_cmd != 0xFF);
}

bool smb1_walk_chain(const uint8_t *buf,
		     bool (*fn)(uint8_t cmd,
				uint8_t wct, const uint16_t *vwv,
				uint16_t num_bytes, const uint8_t *bytes,
				void *private_data),
		     void *private_data)
{
	size_t smblen = smb_len(buf);
	const char *smb_buf = smb_base(buf);
	uint8_t cmd, chain_cmd;
	uint8_t wct;
	const uint16_t *vwv;
	uint16_t num_bytes;
	const uint8_t *bytes;

	cmd = CVAL(buf, smb_com);
	wct = CVAL(buf, smb_wct);
	vwv = (const uint16_t *)(buf + smb_vwv);
	num_bytes = smb_buflen(buf);
	bytes = (uint8_t *)smb_buf_const(buf);

	if (!fn(cmd, wct, vwv, num_bytes, bytes, private_data)) {
		return false;
	}

	if (!is_andx_req(cmd)) {
		return true;
	}
	if (wct < 2) {
		return false;
	}

	chain_cmd = CVAL(vwv, 0);

	while (chain_cmd != 0xff) {
		uint32_t chain_offset;	/* uint32_t to avoid overflow */
		size_t length_needed;
		ptrdiff_t vwv_offset;

		chain_offset = SVAL(vwv+1, 0);

		/*
		 * Check if the client tries to fool us. The chain
		 * offset needs to point beyond the current request in
		 * the chain, it needs to strictly grow. Otherwise we
		 * might be tricked into an endless loop always
		 * processing the same request over and over again. We
		 * used to assume that vwv and the byte buffer array
		 * in a chain are always attached, but OS/2 the
		 * Write&X/Read&X chain puts the Read&X vwv array
		 * right behind the Write&X vwv chain. The Write&X bcc
		 * array is put behind the Read&X vwv array. So now we
		 * check whether the chain offset points strictly
		 * behind the previous vwv array. req->buf points
		 * right after the vwv array of the previous
		 * request. See
		 * https://bugzilla.samba.org/show_bug.cgi?id=8360 for
		 * more information.
		 */

		vwv_offset = ((const char *)vwv - smb_buf);
		if (chain_offset <= vwv_offset) {
			return false;
		}

		/*
		 * Next check: Make sure the chain offset does not
		 * point beyond the overall smb request length.
		 */

		length_needed = chain_offset+1;	/* wct */
		if (length_needed > smblen) {
			return false;
		}

		/*
		 * Now comes the pointer magic. Goal here is to set up
		 * vwv and buf correctly again. The chain offset (the
		 * former vwv[1]) points at the new wct field.
		 */

		wct = CVAL(smb_buf, chain_offset);

		if (is_andx_req(chain_cmd) && (wct < 2)) {
			return false;
		}

		/*
		 * Next consistency check: Make the new vwv array fits
		 * in the overall smb request.
		 */

		length_needed += (wct+1)*sizeof(uint16_t); /* vwv+buflen */
		if (length_needed > smblen) {
			return false;
		}
		vwv = (const uint16_t *)(smb_buf + chain_offset + 1);

		/*
		 * Now grab the new byte buffer....
		 */

		num_bytes = SVAL(vwv+wct, 0);

		/*
		 * .. and check that it fits.
		 */

		length_needed += num_bytes;
		if (length_needed > smblen) {
			return false;
		}
		bytes = (const uint8_t *)(vwv+wct+1);

		if (!fn(chain_cmd, wct, vwv, num_bytes, bytes, private_data)) {
			return false;
		}

		if (!is_andx_req(chain_cmd)) {
			return true;
		}
		chain_cmd = CVAL(vwv, 0);
	}
	return true;
}

static bool smb1_chain_length_cb(uint8_t cmd,
				 uint8_t wct, const uint16_t *vwv,
				 uint16_t num_bytes, const uint8_t *bytes,
				 void *private_data)
{
	unsigned *count = (unsigned *)private_data;
	*count += 1;
	return true;
}

unsigned smb1_chain_length(const uint8_t *buf)
{
	unsigned count = 0;

	if (!smb1_walk_chain(buf, smb1_chain_length_cb, &count)) {
		return 0;
	}
	return count;
}

struct smb1_parse_chain_state {
	TALLOC_CTX *mem_ctx;
	const uint8_t *buf;
	struct smbd_server_connection *sconn;
	bool encrypted;
	uint32_t seqnum;

	struct smb_request **reqs;
	unsigned num_reqs;
};

static bool smb1_parse_chain_cb(uint8_t cmd,
				uint8_t wct, const uint16_t *vwv,
				uint16_t num_bytes, const uint8_t *bytes,
				void *private_data)
{
	struct smb1_parse_chain_state *state =
		(struct smb1_parse_chain_state *)private_data;
	struct smb_request **reqs;
	struct smb_request *req;
	bool ok;

	reqs = talloc_realloc(state->mem_ctx, state->reqs,
			      struct smb_request *, state->num_reqs+1);
	if (reqs == NULL) {
		return false;
	}
	state->reqs = reqs;

	req = talloc(reqs, struct smb_request);
	if (req == NULL) {
		return false;
	}

	ok = init_smb_request(req, state->sconn, state->buf, 0,
			      state->encrypted, state->seqnum);
	if (!ok) {
		return false;
	}
	req->cmd = cmd;
	req->wct = wct;
	req->vwv = vwv;
	req->buflen = num_bytes;
	req->buf = bytes;

	reqs[state->num_reqs] = req;
	state->num_reqs += 1;
	return true;
}

bool smb1_parse_chain(TALLOC_CTX *mem_ctx, const uint8_t *buf,
		      struct smbd_server_connection *sconn,
		      bool encrypted, uint32_t seqnum,
		      struct smb_request ***reqs, unsigned *num_reqs)
{
	struct smb1_parse_chain_state state;
	unsigned i;

	state.mem_ctx = mem_ctx;
	state.buf = buf;
	state.sconn = sconn;
	state.encrypted = encrypted;
	state.seqnum = seqnum;
	state.reqs = NULL;
	state.num_reqs = 0;

	if (!smb1_walk_chain(buf, smb1_parse_chain_cb, &state)) {
		TALLOC_FREE(state.reqs);
		return false;
	}
	for (i=0; i<state.num_reqs; i++) {
		state.reqs[i]->chain = state.reqs;
	}
	*reqs = state.reqs;
	*num_reqs = state.num_reqs;
	return true;
}

/****************************************************************************
 Check if services need reloading.
****************************************************************************/

static void check_reload(struct smbd_server_connection *sconn, time_t t)
{

	if (last_smb_conf_reload_time == 0) {
		last_smb_conf_reload_time = t;
	}

	if (t >= last_smb_conf_reload_time+SMBD_RELOAD_CHECK) {
		reload_services(sconn, conn_snum_used, true);
		last_smb_conf_reload_time = t;
	}
}

static bool fd_is_readable(int fd)
{
	int ret, revents;

	ret = poll_one_fd(fd, POLLIN|POLLHUP, 0, &revents);

	return ((ret > 0) && ((revents & (POLLIN|POLLHUP|POLLERR)) != 0));

}

static void smbd_server_connection_write_handler(
	struct smbd_server_connection *sconn)
{
	/* TODO: make write nonblocking */
}

static void smbd_server_connection_read_handler(
	struct smbd_server_connection *sconn, int fd)
{
	uint8_t *inbuf = NULL;
	size_t inbuf_len = 0;
	size_t unread_bytes = 0;
	bool encrypted = false;
	TALLOC_CTX *mem_ctx = talloc_tos();
	NTSTATUS status;
	uint32_t seqnum;

	bool from_client;

	if (lp_async_smb_echo_handler()
	    && fd_is_readable(sconn->smb1.echo_handler.trusted_fd)) {
		/*
		 * This is the super-ugly hack to prefer the packets
		 * forwarded by the echo handler over the ones by the
		 * client directly
		 */
		fd = sconn->smb1.echo_handler.trusted_fd;
	}

	from_client = (sconn->sock == fd);

	if (from_client) {
		smbd_lock_socket(sconn);

		if (!fd_is_readable(fd)) {
			DEBUG(10,("the echo listener was faster\n"));
			smbd_unlock_socket(sconn);
			return;
		}
	}

	/* TODO: make this completely nonblocking */
	status = receive_smb_talloc(mem_ctx, sconn, fd,
				    (char **)(void *)&inbuf,
				    0, /* timeout */
				    &unread_bytes,
				    &encrypted,
				    &inbuf_len, &seqnum,
				    !from_client /* trusted channel */);

	if (from_client) {
		smbd_unlock_socket(sconn);
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_RETRY)) {
		goto process;
	}
	if (NT_STATUS_IS_ERR(status)) {
		exit_server_cleanly("failed to receive smb request");
	}
	if (!NT_STATUS_IS_OK(status)) {
		return;
	}

process:
	process_smb(sconn, inbuf, inbuf_len, unread_bytes,
		    seqnum, encrypted, NULL);
}

static void smbd_server_connection_handler(struct event_context *ev,
					   struct fd_event *fde,
					   uint16_t flags,
					   void *private_data)
{
	struct smbd_server_connection *conn = talloc_get_type(private_data,
					      struct smbd_server_connection);

	if (flags & EVENT_FD_WRITE) {
		smbd_server_connection_write_handler(conn);
		return;
	}
	if (flags & EVENT_FD_READ) {
		smbd_server_connection_read_handler(conn, conn->sock);
		return;
	}
}

static void smbd_server_echo_handler(struct event_context *ev,
				     struct fd_event *fde,
				     uint16_t flags,
				     void *private_data)
{
	struct smbd_server_connection *conn = talloc_get_type(private_data,
					      struct smbd_server_connection);

	if (flags & EVENT_FD_WRITE) {
		smbd_server_connection_write_handler(conn);
		return;
	}
	if (flags & EVENT_FD_READ) {
		smbd_server_connection_read_handler(
			conn, conn->smb1.echo_handler.trusted_fd);
		return;
	}
}

#ifdef CLUSTER_SUPPORT

struct smbd_release_ip_state {
	struct smbd_server_connection *sconn;
	char addr[INET6_ADDRSTRLEN];
};

/****************************************************************************
received when we should release a specific IP
****************************************************************************/
static void release_ip(const char *ip, void *priv)
{
	struct smbd_release_ip_state *state =
		talloc_get_type_abort(priv,
		struct smbd_release_ip_state);
	const char *addr = state->addr;
	const char *p = addr;

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
		 */
		smbd_server_connection_terminate(state->sconn,
						 "CTDB_SRVID_RELEASE_IP");
		return;
	}
}

static NTSTATUS smbd_register_ips(struct smbd_server_connection *sconn,
				  struct sockaddr_storage *srv,
				  struct sockaddr_storage *clnt)
{
	struct smbd_release_ip_state *state;
	struct ctdbd_connection *cconn;

	cconn = messaging_ctdbd_connection();
	if (cconn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state = talloc_zero(sconn, struct smbd_release_ip_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->sconn = sconn;
	if (print_sockaddr(state->addr, sizeof(state->addr), srv) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return ctdbd_register_ips(cconn, srv, clnt, release_ip, state);
}

static int client_get_tcp_info(int sock, struct sockaddr_storage *server,
			       struct sockaddr_storage *client)
{
	socklen_t length;
	length = sizeof(*server);
	if (getsockname(sock, (struct sockaddr *)server, &length) != 0) {
		return -1;
	}
	length = sizeof(*client);
	if (getpeername(sock, (struct sockaddr *)client, &length) != 0) {
		return -1;
	}
	return 0;
}
#endif

/*
 * Send keepalive packets to our client
 */
static bool keepalive_fn(const struct timeval *now, void *private_data)
{
	struct smbd_server_connection *sconn = talloc_get_type_abort(
		private_data, struct smbd_server_connection);
	bool ret;

	if (sconn->using_smb2) {
		/* Don't do keepalives on an SMB2 connection. */
		return false;
	}

	smbd_lock_socket(sconn);
	ret = send_keepalive(sconn->sock);
	smbd_unlock_socket(sconn);

	if (!ret) {
		char addr[INET6_ADDRSTRLEN];
		/*
		 * Try and give an error message saying what
		 * client failed.
		 */
		DEBUG(0, ("send_keepalive failed for client %s. "
			  "Error %s - exiting\n",
			  get_peer_addr(sconn->sock, addr, sizeof(addr)),
			  strerror(errno)));
		return False;
	}
	return True;
}

/*
 * Do the recurring check if we're idle
 */
static bool deadtime_fn(const struct timeval *now, void *private_data)
{
	struct smbd_server_connection *sconn =
		(struct smbd_server_connection *)private_data;

	if ((conn_num_open(sconn) == 0)
	    || (conn_idle_all(sconn, now->tv_sec))) {
		DEBUG( 2, ( "Closing idle connection\n" ) );
		messaging_send(sconn->msg_ctx,
			       messaging_server_id(sconn->msg_ctx),
			       MSG_SHUTDOWN, &data_blob_null);
		return False;
	}

	return True;
}

/*
 * Do the recurring log file and smb.conf reload checks.
 */

static bool housekeeping_fn(const struct timeval *now, void *private_data)
{
	struct smbd_server_connection *sconn = talloc_get_type_abort(
		private_data, struct smbd_server_connection);

	DEBUG(5, ("housekeeping\n"));

	change_to_root_user();

	/* update printer queue caches if necessary */
	update_monitored_printq_cache(sconn->msg_ctx);

	/* check if we need to reload services */
	check_reload(sconn, time_mono(NULL));

        /*
	 * Force a log file check.
	 */
	force_check_log_size();
	check_log_size();
	return true;
}

/*
 * Read an smb packet in the echo handler child, giving the parent
 * smbd one second to react once the socket becomes readable.
 */

struct smbd_echo_read_state {
	struct tevent_context *ev;
	struct smbd_server_connection *sconn;

	char *buf;
	size_t buflen;
	uint32_t seqnum;
};

static void smbd_echo_read_readable(struct tevent_req *subreq);
static void smbd_echo_read_waited(struct tevent_req *subreq);

static struct tevent_req *smbd_echo_read_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct smbd_server_connection *sconn)
{
	struct tevent_req *req, *subreq;
	struct smbd_echo_read_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_echo_read_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->sconn = sconn;

	subreq = wait_for_read_send(state, ev, sconn->sock);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smbd_echo_read_readable, req);
	return req;
}

static void smbd_echo_read_readable(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbd_echo_read_state *state = tevent_req_data(
		req, struct smbd_echo_read_state);
	bool ok;
	int err;

	ok = wait_for_read_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}

	/*
	 * Give the parent smbd one second to step in
	 */

	subreq = tevent_wakeup_send(
		state, state->ev, timeval_current_ofs(1, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, smbd_echo_read_waited, req);
}

static void smbd_echo_read_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbd_echo_read_state *state = tevent_req_data(
		req, struct smbd_echo_read_state);
	struct smbd_server_connection *sconn = state->sconn;
	bool ok;
	NTSTATUS status;
	size_t unread = 0;
	bool encrypted;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	ok = smbd_lock_socket_internal(sconn);
	if (!ok) {
		tevent_req_nterror(req, map_nt_error_from_unix(errno));
		DEBUG(0, ("%s: failed to lock socket\n", __location__));
		return;
	}

	if (!fd_is_readable(sconn->sock)) {
		DEBUG(10,("echo_handler[%d] the parent smbd was faster\n",
			  (int)getpid()));

		ok = smbd_unlock_socket_internal(sconn);
		if (!ok) {
			tevent_req_nterror(req, map_nt_error_from_unix(errno));
			DEBUG(1, ("%s: failed to unlock socket\n",
				__location__));
			return;
		}

		subreq = wait_for_read_send(state, state->ev, sconn->sock);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, smbd_echo_read_readable, req);
		return;
	}

	status = receive_smb_talloc(state, sconn, sconn->sock, &state->buf,
				    0 /* timeout */,
				    &unread,
				    &encrypted,
				    &state->buflen,
				    &state->seqnum,
				    false /* trusted_channel*/);

	if (tevent_req_nterror(req, status)) {
		tevent_req_nterror(req, status);
		DEBUG(1, ("echo_handler[%d]: receive_smb_raw_talloc failed: %s\n",
			  (int)getpid(), nt_errstr(status)));
		return;
	}

	ok = smbd_unlock_socket_internal(sconn);
	if (!ok) {
		tevent_req_nterror(req, map_nt_error_from_unix(errno));
		DEBUG(1, ("%s: failed to unlock socket\n", __location__));
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS smbd_echo_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				    char **pbuf, size_t *pbuflen, uint32_t *pseqnum)
{
	struct smbd_echo_read_state *state = tevent_req_data(
		req, struct smbd_echo_read_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*pbuf = talloc_move(mem_ctx, &state->buf);
	*pbuflen = state->buflen;
	*pseqnum = state->seqnum;
	return NT_STATUS_OK;
}

struct smbd_echo_state {
	struct tevent_context *ev;
	struct iovec *pending;
	struct smbd_server_connection *sconn;
	int parent_pipe;

	struct tevent_fd *parent_fde;

	struct tevent_req *write_req;
};

static void smbd_echo_writer_done(struct tevent_req *req);

static void smbd_echo_activate_writer(struct smbd_echo_state *state)
{
	int num_pending;

	if (state->write_req != NULL) {
		return;
	}

	num_pending = talloc_array_length(state->pending);
	if (num_pending == 0) {
		return;
	}

	state->write_req = writev_send(state, state->ev, NULL,
				       state->parent_pipe, false,
				       state->pending, num_pending);
	if (state->write_req == NULL) {
		DEBUG(1, ("writev_send failed\n"));
		exit(1);
	}

	talloc_steal(state->write_req, state->pending);
	state->pending = NULL;

	tevent_req_set_callback(state->write_req, smbd_echo_writer_done,
				state);
}

static void smbd_echo_writer_done(struct tevent_req *req)
{
	struct smbd_echo_state *state = tevent_req_callback_data(
		req, struct smbd_echo_state);
	ssize_t written;
	int err;

	written = writev_recv(req, &err);
	TALLOC_FREE(req);
	state->write_req = NULL;
	if (written == -1) {
		DEBUG(1, ("writev to parent failed: %s\n", strerror(err)));
		exit(1);
	}
	DEBUG(10,("echo_handler[%d]: forwarded pdu to main\n", (int)getpid()));
	smbd_echo_activate_writer(state);
}

static bool smbd_echo_reply(struct smbd_echo_state *state,
			    uint8_t *inbuf, size_t inbuf_len,
			    uint32_t seqnum)
{
	struct smb_request req;
	uint16_t num_replies;
	char *outbuf;
	bool ok;

	if ((inbuf_len == 4) && (CVAL(inbuf, 0) == NBSSkeepalive)) {
		DEBUG(10, ("Got netbios keepalive\n"));
		/*
		 * Just swallow it
		 */
		return true;
	}

	if (inbuf_len < smb_size) {
		DEBUG(10, ("Got short packet: %d bytes\n", (int)inbuf_len));
		return false;
	}
	if (!valid_smb_header(state->sconn, inbuf)) {
		DEBUG(10, ("Got invalid SMB header\n"));
		return false;
	}

	if (!init_smb_request(&req, state->sconn, inbuf, 0, false,
			      seqnum)) {
		return false;
	}
	req.inbuf = inbuf;

	DEBUG(10, ("smbecho handler got cmd %d (%s)\n", (int)req.cmd,
		   smb_messages[req.cmd].name
		   ? smb_messages[req.cmd].name : "unknown"));

	if (req.cmd != SMBecho) {
		return false;
	}
	if (req.wct < 1) {
		return false;
	}

	num_replies = SVAL(req.vwv+0, 0);
	if (num_replies != 1) {
		/* Not a Windows "Hey, you're still there?" request */
		return false;
	}

	if (!create_outbuf(talloc_tos(), &req, (const char *)req.inbuf, &outbuf,
			   1, req.buflen)) {
		DEBUG(10, ("create_outbuf failed\n"));
		return false;
	}
	req.outbuf = (uint8_t *)outbuf;

	SSVAL(req.outbuf, smb_vwv0, num_replies);

	if (req.buflen > 0) {
		memcpy(smb_buf(req.outbuf), req.buf, req.buflen);
	}

	ok = srv_send_smb(req.sconn,
			  (char *)outbuf,
			  true, seqnum+1,
			  false, &req.pcd);
	TALLOC_FREE(outbuf);
	if (!ok) {
		exit(1);
	}

	return true;
}

static void smbd_echo_exit(struct tevent_context *ev,
			   struct tevent_fd *fde, uint16_t flags,
			   void *private_data)
{
	DEBUG(2, ("smbd_echo_exit: lost connection to parent\n"));
	exit(0);
}

static void smbd_echo_got_packet(struct tevent_req *req);

static void smbd_echo_loop(struct smbd_server_connection *sconn,
			   int parent_pipe)
{
	struct smbd_echo_state *state;
	struct tevent_req *read_req;

	state = talloc_zero(sconn, struct smbd_echo_state);
	if (state == NULL) {
		DEBUG(1, ("talloc failed\n"));
		return;
	}
	state->sconn = sconn;
	state->parent_pipe = parent_pipe;
	state->ev = s3_tevent_context_init(state);
	if (state->ev == NULL) {
		DEBUG(1, ("tevent_context_init failed\n"));
		TALLOC_FREE(state);
		return;
	}
	state->parent_fde = tevent_add_fd(state->ev, state, parent_pipe,
					TEVENT_FD_READ, smbd_echo_exit,
					state);
	if (state->parent_fde == NULL) {
		DEBUG(1, ("tevent_add_fd failed\n"));
		TALLOC_FREE(state);
		return;
	}

	read_req = smbd_echo_read_send(state, state->ev, sconn);
	if (read_req == NULL) {
		DEBUG(1, ("smbd_echo_read_send failed\n"));
		TALLOC_FREE(state);
		return;
	}
	tevent_req_set_callback(read_req, smbd_echo_got_packet, state);

	while (true) {
		if (tevent_loop_once(state->ev) == -1) {
			DEBUG(1, ("tevent_loop_once failed: %s\n",
				  strerror(errno)));
			break;
		}
	}
	TALLOC_FREE(state);
}

static void smbd_echo_got_packet(struct tevent_req *req)
{
	struct smbd_echo_state *state = tevent_req_callback_data(
		req, struct smbd_echo_state);
	NTSTATUS status;
	char *buf = NULL;
	size_t buflen = 0;
	uint32_t seqnum = 0;
	bool reply;

	status = smbd_echo_read_recv(req, state, &buf, &buflen, &seqnum);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("smbd_echo_read_recv returned %s\n",
			  nt_errstr(status)));
		exit(1);
	}

	reply = smbd_echo_reply(state, (uint8_t *)buf, buflen, seqnum);
	if (!reply) {
		size_t num_pending;
		struct iovec *tmp;
		struct iovec *iov;

		num_pending = talloc_array_length(state->pending);
		tmp = talloc_realloc(state, state->pending, struct iovec,
				     num_pending+1);
		if (tmp == NULL) {
			DEBUG(1, ("talloc_realloc failed\n"));
			exit(1);
		}
		state->pending = tmp;

		if (buflen >= smb_size) {
			/*
			 * place the seqnum in the packet so that the main process
			 * can reply with signing
			 */
			SIVAL(buf, smb_ss_field, seqnum);
			SIVAL(buf, smb_ss_field+4, NT_STATUS_V(NT_STATUS_OK));
		}

		iov = &state->pending[num_pending];
		iov->iov_base = talloc_move(state->pending, &buf);
		iov->iov_len = buflen;

		DEBUG(10,("echo_handler[%d]: forward to main\n",
			  (int)getpid()));
		smbd_echo_activate_writer(state);
	}

	req = smbd_echo_read_send(state, state->ev, state->sconn);
	if (req == NULL) {
		DEBUG(1, ("smbd_echo_read_send failed\n"));
		exit(1);
	}
	tevent_req_set_callback(req, smbd_echo_got_packet, state);
}


/*
 * Handle SMBecho requests in a forked child process
 */
bool fork_echo_handler(struct smbd_server_connection *sconn)
{
	int listener_pipe[2];
	int res;
	pid_t child;

	res = pipe(listener_pipe);
	if (res == -1) {
		DEBUG(1, ("pipe() failed: %s\n", strerror(errno)));
		return false;
	}
	sconn->smb1.echo_handler.socket_lock_fd = create_unlink_tmp(lp_lockdir());
	if (sconn->smb1.echo_handler.socket_lock_fd == -1) {
		DEBUG(1, ("Could not create lock fd: %s\n", strerror(errno)));
		goto fail;
	}

	child = fork();
	if (child == 0) {
		NTSTATUS status;

		close(listener_pipe[0]);
		set_blocking(listener_pipe[1], false);

		status = reinit_after_fork(sconn->msg_ctx,
					   sconn->ev_ctx,
					   false);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("reinit_after_fork failed: %s\n",
				  nt_errstr(status)));
			exit(1);
		}
		smbd_echo_loop(sconn, listener_pipe[1]);
		exit(0);
	}
	close(listener_pipe[1]);
	listener_pipe[1] = -1;
	sconn->smb1.echo_handler.trusted_fd = listener_pipe[0];

	DEBUG(10,("fork_echo_handler: main[%d] echo_child[%d]\n", (int)getpid(), child));

	/*
	 * Without smb signing this is the same as the normal smbd
	 * listener. This needs to change once signing comes in.
	 */
	sconn->smb1.echo_handler.trusted_fde = tevent_add_fd(sconn->ev_ctx,
					sconn,
					sconn->smb1.echo_handler.trusted_fd,
					TEVENT_FD_READ,
					smbd_server_echo_handler,
					sconn);
	if (sconn->smb1.echo_handler.trusted_fde == NULL) {
		DEBUG(1, ("event_add_fd failed\n"));
		goto fail;
	}

	return true;

fail:
	if (listener_pipe[0] != -1) {
		close(listener_pipe[0]);
	}
	if (listener_pipe[1] != -1) {
		close(listener_pipe[1]);
	}
	sconn->smb1.echo_handler.trusted_fd = -1;
	if (sconn->smb1.echo_handler.socket_lock_fd != -1) {
		close(sconn->smb1.echo_handler.socket_lock_fd);
	}
	sconn->smb1.echo_handler.trusted_fd = -1;
	sconn->smb1.echo_handler.socket_lock_fd = -1;
	return false;
}

static bool uid_in_use(const struct user_struct *user, uid_t uid)
{
	while (user) {
		if (user->session_info &&
		    (user->session_info->unix_token->uid == uid)) {
			return true;
		}
		user = user->next;
	}
	return false;
}

static bool gid_in_use(const struct user_struct *user, gid_t gid)
{
	while (user) {
		if (user->session_info != NULL) {
			int i;
			struct security_unix_token *utok;

			utok = user->session_info->unix_token;
			if (utok->gid == gid) {
				return true;
			}
			for(i=0; i<utok->ngroups; i++) {
				if (utok->groups[i] == gid) {
					return true;
				}
			}
		}
		user = user->next;
	}
	return false;
}

static bool sid_in_use(const struct user_struct *user,
		       const struct dom_sid *psid)
{
	while (user) {
		struct security_token *tok;

		if (user->session_info == NULL) {
			continue;
		}
		tok = user->session_info->security_token;
		if (tok == NULL) {
			/*
			 * Not sure session_info->security_token can
			 * ever be NULL. This check might be not
			 * necessary.
			 */
			continue;
		}
		if (security_token_has_sid(tok, psid)) {
			return true;
		}
		user = user->next;
	}
	return false;
}

static bool id_in_use(const struct user_struct *user,
		      const struct id_cache_ref *id)
{
	switch(id->type) {
	case UID:
		return uid_in_use(user, id->id.uid);
	case GID:
		return gid_in_use(user, id->id.gid);
	case SID:
		return sid_in_use(user, &id->id.sid);
	default:
		break;
	}
	return false;
}

static void smbd_id_cache_kill(struct messaging_context *msg_ctx,
			       void *private_data,
			       uint32_t msg_type,
			       struct server_id server_id,
			       DATA_BLOB* data)
{
	const char *msg = (data && data->data)
		? (const char *)data->data : "<NULL>";
	struct id_cache_ref id;
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);

	if (!id_cache_ref_parse(msg, &id)) {
		DEBUG(0, ("Invalid ?ID: %s\n", msg));
		return;
	}

	if (id_in_use(sconn->users, &id)) {
		exit_server_cleanly(msg);
	}
	id_cache_delete_from_cache(&id);
}

NTSTATUS smbXsrv_connection_init_tables(struct smbXsrv_connection *conn,
					enum protocol_types protocol)
{
	NTSTATUS status;

	set_Protocol(protocol);
	conn->protocol = protocol;

	if (protocol >= PROTOCOL_SMB2_02) {
		status = smb2srv_session_table_init(conn);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = smb2srv_open_table_init(conn);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else {
		status = smb1srv_session_table_init(conn);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = smb1srv_tcon_table_init(conn);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = smb1srv_open_table_init(conn);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}

static void smbd_tevent_trace_callback(enum tevent_trace_point point,
				       void *private_data)
{
	struct smbXsrv_connection *conn =
		talloc_get_type_abort(private_data,
		struct smbXsrv_connection);

	switch (point) {
	case TEVENT_TRACE_BEFORE_WAIT:
		/*
		 * This just removes compiler warning
		 * without profile support
		 */
		conn->smbd_idle_profstamp = 0;
		START_PROFILE_STAMP(smbd_idle, conn->smbd_idle_profstamp);
		break;
	case TEVENT_TRACE_AFTER_WAIT:
		END_PROFILE_STAMP(smbd_idle, conn->smbd_idle_profstamp);
		break;
	}
}

/****************************************************************************
 Process commands from the client
****************************************************************************/

void smbd_process(struct tevent_context *ev_ctx,
		  struct messaging_context *msg_ctx,
		  int sock_fd,
		  bool interactive)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct smbXsrv_connection *conn;
	struct smbd_server_connection *sconn;
	struct sockaddr_storage ss;
	struct sockaddr *sa = NULL;
	socklen_t sa_socklen;
	struct tsocket_address *local_address = NULL;
	struct tsocket_address *remote_address = NULL;
	const char *locaddr = NULL;
	const char *remaddr = NULL;
	char *rhost;
	int ret;

	conn = talloc_zero(ev_ctx, struct smbXsrv_connection);
	if (conn == NULL) {
		DEBUG(0,("talloc_zero(struct smbXsrv_connection)\n"));
		exit_server_cleanly("talloc_zero(struct smbXsrv_connection).\n");
	}

	conn->ev_ctx = ev_ctx;
	conn->msg_ctx = msg_ctx;

	sconn = talloc_zero(conn, struct smbd_server_connection);
	if (!sconn) {
		exit_server("failed to create smbd_server_connection");
	}

	conn->sconn = sconn;
	sconn->conn = conn;

	/*
	 * TODO: remove this...:-)
	 */
	global_smbXsrv_connection = conn;

	sconn->ev_ctx = ev_ctx;
	sconn->msg_ctx = msg_ctx;
	sconn->sock = sock_fd;
	sconn->smb1.echo_handler.trusted_fd = -1;
	sconn->smb1.echo_handler.socket_lock_fd = -1;

	if (!interactive) {
		smbd_setup_sig_term_handler(sconn);
		smbd_setup_sig_hup_handler(sconn);

		if (!serverid_register(messaging_server_id(msg_ctx),
				       FLAG_MSG_GENERAL|FLAG_MSG_SMBD
				       |FLAG_MSG_DBWRAP
				       |FLAG_MSG_PRINT_GENERAL)) {
			exit_server_cleanly("Could not register myself in "
					    "serverid.tdb");
		}
	}

	if (lp_srv_maxprotocol() >= PROTOCOL_SMB2_02) {
		/*
		 * We're not making the decision here,
		 * we're just allowing the client
		 * to decide between SMB1 and SMB2
		 * with the first negprot
		 * packet.
		 */
		sconn->using_smb2 = true;
	}

	/* Ensure child is set to blocking mode */
	set_blocking(sconn->sock,True);

	set_socket_options(sconn->sock, "SO_KEEPALIVE");
	set_socket_options(sconn->sock, lp_socket_options());

	sa = (struct sockaddr *)(void *)&ss;
	sa_socklen = sizeof(ss);
	ret = getpeername(sconn->sock, sa, &sa_socklen);
	if (ret != 0) {
		int level = (errno == ENOTCONN)?2:0;
		DEBUG(level,("getpeername() failed - %s\n", strerror(errno)));
		exit_server_cleanly("getpeername() failed.\n");
	}
	ret = tsocket_address_bsd_from_sockaddr(sconn,
						sa, sa_socklen,
						&remote_address);
	if (ret != 0) {
		DEBUG(0,("%s: tsocket_address_bsd_from_sockaddr remote failed - %s\n",
			__location__, strerror(errno)));
		exit_server_cleanly("tsocket_address_bsd_from_sockaddr remote failed.\n");
	}

	sa = (struct sockaddr *)(void *)&ss;
	sa_socklen = sizeof(ss);
	ret = getsockname(sconn->sock, sa, &sa_socklen);
	if (ret != 0) {
		int level = (errno == ENOTCONN)?2:0;
		DEBUG(level,("getsockname() failed - %s\n", strerror(errno)));
		exit_server_cleanly("getsockname() failed.\n");
	}
	ret = tsocket_address_bsd_from_sockaddr(sconn,
						sa, sa_socklen,
						&local_address);
	if (ret != 0) {
		DEBUG(0,("%s: tsocket_address_bsd_from_sockaddr remote failed - %s\n",
			__location__, strerror(errno)));
		exit_server_cleanly("tsocket_address_bsd_from_sockaddr remote failed.\n");
	}

	sconn->local_address = local_address;
	sconn->remote_address = remote_address;

	if (tsocket_address_is_inet(local_address, "ip")) {
		locaddr = tsocket_address_inet_addr_string(
				sconn->local_address,
				talloc_tos());
		if (locaddr == NULL) {
			DEBUG(0,("%s: tsocket_address_inet_addr_string local failed - %s\n",
				 __location__, strerror(errno)));
			exit_server_cleanly("tsocket_address_inet_addr_string local failed.\n");
		}
	} else {
		locaddr = "0.0.0.0";
	}

	if (tsocket_address_is_inet(remote_address, "ip")) {
		remaddr = tsocket_address_inet_addr_string(
				sconn->remote_address,
				talloc_tos());
		if (remaddr == NULL) {
			DEBUG(0,("%s: tsocket_address_inet_addr_string remote failed - %s\n",
				 __location__, strerror(errno)));
			exit_server_cleanly("tsocket_address_inet_addr_string remote failed.\n");
		}
	} else {
		remaddr = "0.0.0.0";
	}

	/* this is needed so that we get decent entries
	   in smbstatus for port 445 connects */
	set_remote_machine_name(remaddr, false);
	reload_services(sconn, conn_snum_used, true);

	/*
	 * Before the first packet, check the global hosts allow/ hosts deny
	 * parameters before doing any parsing of packets passed to us by the
	 * client. This prevents attacks on our parsing code from hosts not in
	 * the hosts allow list.
	 */

	ret = get_remote_hostname(remote_address,
				  &rhost,
				  talloc_tos());
	if (ret < 0) {
		DEBUG(0,("%s: get_remote_hostname failed - %s\n",
			__location__, strerror(errno)));
		exit_server_cleanly("get_remote_hostname failed.\n");
	}
	if (strequal(rhost, "UNKNOWN")) {
		rhost = talloc_strdup(talloc_tos(), remaddr);
	}
	sconn->remote_hostname = talloc_move(sconn, &rhost);

	sub_set_socket_ids(remaddr,
			   sconn->remote_hostname,
			   locaddr);

	if (!allow_access(lp_hostsdeny(-1), lp_hostsallow(-1),
			  sconn->remote_hostname,
			  remaddr)) {
		/*
		 * send a negative session response "not listening on calling
		 * name"
		 */
		unsigned char buf[5] = {0x83, 0, 0, 1, 0x81};
		DEBUG( 1, ("Connection denied from %s to %s\n",
			   tsocket_address_string(remote_address, talloc_tos()),
			   tsocket_address_string(local_address, talloc_tos())));
		(void)srv_send_smb(sconn,(char *)buf, false,
				   0, false, NULL);
		exit_server_cleanly("connection denied");
	}

	DEBUG(10, ("Connection allowed from %s to %s\n",
		   tsocket_address_string(remote_address, talloc_tos()),
		   tsocket_address_string(local_address, talloc_tos())));

	if (lp_preload_modules()) {
		smb_load_modules(lp_preload_modules());
	}

	smb_perfcount_init();

	if (!init_account_policy()) {
		exit_server("Could not open account policy tdb.\n");
	}

	if (*lp_rootdir(talloc_tos())) {
		if (chroot(lp_rootdir(talloc_tos())) != 0) {
			DEBUG(0,("Failed to change root to %s\n",
				 lp_rootdir(talloc_tos())));
			exit_server("Failed to chroot()");
		}
		if (chdir("/") == -1) {
			DEBUG(0,("Failed to chdir to / on chroot to %s\n", lp_rootdir(talloc_tos())));
			exit_server("Failed to chroot()");
		}
		DEBUG(0,("Changed root to %s\n", lp_rootdir(talloc_tos())));
	}

	if (!srv_init_signing(sconn)) {
		exit_server("Failed to init smb_signing");
	}

	if (!file_init(sconn)) {
		exit_server("file_init() failed");
	}

	/* Setup oplocks */
	if (!init_oplocks(sconn))
		exit_server("Failed to init oplocks");

	/* register our message handlers */
	messaging_register(sconn->msg_ctx, sconn,
			   MSG_SMB_FORCE_TDIS, msg_force_tdis);
	messaging_register(sconn->msg_ctx, sconn,
			   MSG_SMB_CLOSE_FILE, msg_close_file);
	messaging_register(sconn->msg_ctx, sconn,
			   MSG_SMB_FILE_RENAME, msg_file_was_renamed);

	id_cache_register_msgs(sconn->msg_ctx);
	messaging_deregister(sconn->msg_ctx, ID_CACHE_KILL, NULL);
	messaging_register(sconn->msg_ctx, sconn,
			   ID_CACHE_KILL, smbd_id_cache_kill);

	messaging_deregister(sconn->msg_ctx,
			     MSG_SMB_CONF_UPDATED, sconn->ev_ctx);
	messaging_register(sconn->msg_ctx, sconn,
			   MSG_SMB_CONF_UPDATED, smbd_conf_updated);

	/*
	 * Use the default MSG_DEBUG handler to avoid rebroadcasting
	 * MSGs to all child processes
	 */
	messaging_deregister(sconn->msg_ctx,
			     MSG_DEBUG, NULL);
	messaging_register(sconn->msg_ctx, NULL,
			   MSG_DEBUG, debug_message);

	if ((lp_keepalive() != 0)
	    && !(event_add_idle(ev_ctx, NULL,
				timeval_set(lp_keepalive(), 0),
				"keepalive", keepalive_fn,
				sconn))) {
		DEBUG(0, ("Could not add keepalive event\n"));
		exit(1);
	}

	if (!(event_add_idle(ev_ctx, NULL,
			     timeval_set(IDLE_CLOSED_TIMEOUT, 0),
			     "deadtime", deadtime_fn, sconn))) {
		DEBUG(0, ("Could not add deadtime event\n"));
		exit(1);
	}

	if (!(event_add_idle(ev_ctx, NULL,
			     timeval_set(SMBD_HOUSEKEEPING_INTERVAL, 0),
			     "housekeeping", housekeeping_fn, sconn))) {
		DEBUG(0, ("Could not add housekeeping event\n"));
		exit(1);
	}

#ifdef CLUSTER_SUPPORT

	if (lp_clustering()) {
		/*
		 * We need to tell ctdb about our client's TCP
		 * connection, so that for failover ctdbd can send
		 * tickle acks, triggering a reconnection by the
		 * client.
		 */

		struct sockaddr_storage srv, clnt;

		if (client_get_tcp_info(sconn->sock, &srv, &clnt) == 0) {
			NTSTATUS status;
			status = smbd_register_ips(sconn, &srv, &clnt);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(0, ("ctdbd_register_ips failed: %s\n",
					  nt_errstr(status)));
			}
		} else
		{
			DEBUG(0,("Unable to get tcp info for "
				 "CTDB_CONTROL_TCP_CLIENT: %s\n",
				 strerror(errno)));
		}
	}

#endif

	sconn->nbt.got_session = false;

	sconn->smb1.negprot.max_recv = MIN(lp_max_xmit(),BUFFER_SIZE);

	sconn->smb1.sessions.done_sesssetup = false;
	sconn->smb1.sessions.max_send = BUFFER_SIZE;
	sconn->smb1.sessions.last_session_tag = UID_FIELD_INVALID;

	if (!init_dptrs(sconn)) {
		exit_server("init_dptrs() failed");
	}

	sconn->smb1.fde = event_add_fd(ev_ctx,
						  sconn,
						  sconn->sock,
						  EVENT_FD_READ,
						  smbd_server_connection_handler,
						  sconn);
	if (!sconn->smb1.fde) {
		exit_server("failed to create smbd_server_connection fde");
	}

	sconn->conn->local_address = sconn->local_address;
	sconn->conn->remote_address = sconn->remote_address;
	sconn->conn->remote_hostname = sconn->remote_hostname;
	sconn->conn->protocol = PROTOCOL_NONE;

	TALLOC_FREE(frame);

	tevent_set_trace_callback(ev_ctx, smbd_tevent_trace_callback, conn);

	while (True) {
		frame = talloc_stackframe_pool(8192);

		errno = 0;
		if (tevent_loop_once(ev_ctx) == -1) {
			if (errno != EINTR) {
				DEBUG(3, ("tevent_loop_once failed: %s,"
					  " exiting\n", strerror(errno) ));
				break;
			}
		}

		TALLOC_FREE(frame);
	}

	exit_server_cleanly(NULL);
}

bool req_is_in_chain(const struct smb_request *req)
{
	if (req->vwv != (const uint16_t *)(req->inbuf+smb_vwv)) {
		/*
		 * We're right now handling a subsequent request, so we must
		 * be in a chain
		 */
		return true;
	}

	if (!is_andx_req(req->cmd)) {
		return false;
	}

	if (req->wct < 2) {
		/*
		 * Okay, an illegal request, but definitely not chained :-)
		 */
		return false;
	}

	return (CVAL(req->vwv+0, 0) != 0xFF);
}
