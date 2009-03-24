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

extern int smb_echo_count;

/*
 * Size of data we can send to client. Set
 *  by the client for all protocols above CORE.
 *  Set by us for CORE protocol.
 */
int max_send = BUFFER_SIZE;
/*
 * Size of the data we can receive. Set by us.
 * Can be modified by the max xmit parameter.
 */
int max_recv = BUFFER_SIZE;

SIG_ATOMIC_T reload_after_sighup = 0;
SIG_ATOMIC_T got_sig_term = 0;
extern bool global_machine_password_needs_changing;
extern int max_send;

/* Accessor function for smb_read_error for smbd functions. */

/****************************************************************************
 Send an smb to a fd.
****************************************************************************/

bool srv_send_smb(int fd, char *buffer, bool do_encrypt)
{
	size_t len;
	size_t nwritten=0;
	ssize_t ret;
	char *buf_out = buffer;

	/* Sign the outgoing packet if required. */
	srv_calculate_sign_mac(buf_out);

	if (do_encrypt) {
		NTSTATUS status = srv_encrypt_buffer(buffer, &buf_out);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("send_smb: SMB encryption failed "
				"on outgoing packet! Error %s\n",
				nt_errstr(status) ));
			return false;
		}
	}

	len = smb_len(buf_out) + 4;

	while (nwritten < len) {
		ret = write_data(fd,buf_out+nwritten,len - nwritten);
		if (ret <= 0) {
			DEBUG(0,("Error writing %d bytes to client. %d. (%s)\n",
				(int)len,(int)ret, strerror(errno) ));
			srv_free_enc_buffer(buf_out);
			return false;
		}
		nwritten += ret;
	}

	srv_free_enc_buffer(buf_out);
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

static bool valid_smb_header(const uint8_t *inbuf)
{
	if (is_encrypted_packet(inbuf)) {
		return true;
	}
	return (strncmp(smb_base(inbuf),"\377SMB",4) == 0);
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
	if (len <= 0) {
		return NT_STATUS_OK;
	}

	return read_socket_with_timeout(fd, buffer, len, len, timeout, NULL);
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
						    int fd, char **buffer,
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

	status = read_socket_with_timeout(
		fd, writeX_header + 4,
		STANDARD_WRITE_AND_X_HEADER_SIZE,
		STANDARD_WRITE_AND_X_HEADER_SIZE,
		timeout, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * Ok - now try and see if this is a possible
	 * valid writeX call.
	 */

	if (is_valid_writeX_buffer((uint8_t *)writeX_header)) {
		/*
		 * If the data offset is beyond what
		 * we've read, drain the extra bytes.
		 */
		uint16_t doff = SVAL(writeX_header,smb_vwv11);
		ssize_t newlen;

		if (doff > STANDARD_WRITE_AND_X_HEADER_SIZE) {
			size_t drain = doff - STANDARD_WRITE_AND_X_HEADER_SIZE;
			if (drain_socket(smbd_server_fd(), drain) != drain) {
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

		*buffer = (char *)TALLOC_MEMDUP(mem_ctx,
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

	*buffer = TALLOC_ARRAY(mem_ctx, char, len+4);

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
			fd, (*buffer) + 4 + STANDARD_WRITE_AND_X_HEADER_SIZE,
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

static NTSTATUS receive_smb_raw_talloc(TALLOC_CTX *mem_ctx, int fd,
				       char **buffer, unsigned int timeout,
				       size_t *p_unread, size_t *plen)
{
	char lenbuf[4];
	size_t len;
	int min_recv_size = lp_min_receive_file_size();
	NTSTATUS status;

	*p_unread = 0;

	status = read_smb_length_return_keepalive(fd, lenbuf, timeout, &len);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("receive_smb_raw: %s\n", nt_errstr(status)));
		return status;
	}

	if (CVAL(lenbuf,0) == 0 &&
			min_recv_size &&
			smb_len_large(lenbuf) > (min_recv_size + STANDARD_WRITE_AND_X_HEADER_SIZE) && /* Could be a UNIX large writeX. */
			!srv_is_signing_active()) {

		return receive_smb_raw_talloc_partial_read(
			mem_ctx, lenbuf, fd, buffer, timeout, p_unread, plen);
	}

	if (!valid_packet_size(len)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/*
	 * The +4 here can't wrap, we've checked the length above already.
	 */

	*buffer = TALLOC_ARRAY(mem_ctx, char, len+4);

	if (*buffer == NULL) {
		DEBUG(0, ("Could not allocate inbuf of length %d\n",
			  (int)len+4));
		return NT_STATUS_NO_MEMORY;
	}

	memcpy(*buffer, lenbuf, sizeof(lenbuf));

	status = read_packet_remainder(fd, (*buffer)+4, timeout, len);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*plen = len + 4;
	return NT_STATUS_OK;
}

static NTSTATUS receive_smb_talloc(TALLOC_CTX *mem_ctx,	int fd,
				   char **buffer, unsigned int timeout,
				   size_t *p_unread, bool *p_encrypted,
				   size_t *p_len)
{
	size_t len = 0;
	NTSTATUS status;

	*p_encrypted = false;

	status = receive_smb_raw_talloc(mem_ctx, fd, buffer, timeout,
					p_unread, &len);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (is_encrypted_packet((uint8_t *)*buffer)) {
		status = srv_decrypt_buffer(*buffer);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("receive_smb_talloc: SMB decryption failed on "
				"incoming packet! Error %s\n",
				nt_errstr(status) ));
			return status;
		}
		*p_encrypted = true;
	}

	/* Check the incoming SMB signature. */
	if (!srv_check_sign_mac(*buffer, true)) {
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

void init_smb_request(struct smb_request *req,
			const uint8 *inbuf,
			size_t unread_bytes,
			bool encrypted)
{
	size_t req_size = smb_len(inbuf) + 4;
	/* Ensure we have at least smb_size bytes. */
	if (req_size < smb_size) {
		DEBUG(0,("init_smb_request: invalid request size %u\n",
			(unsigned int)req_size ));
		exit_server_cleanly("Invalid SMB request");
	}
	req->flags2 = SVAL(inbuf, smb_flg2);
	req->smbpid = SVAL(inbuf, smb_pid);
	req->mid    = SVAL(inbuf, smb_mid);
	req->vuid   = SVAL(inbuf, smb_uid);
	req->tid    = SVAL(inbuf, smb_tid);
	req->wct    = CVAL(inbuf, smb_wct);
	req->unread_bytes = unread_bytes;
	req->encrypted = encrypted;
	req->conn = conn_find(req->tid);

	/* Ensure we have at least wct words and 2 bytes of bcc. */
	if (smb_size + req->wct*2 > req_size) {
		DEBUG(0,("init_smb_request: invalid wct number %u (size %u)\n",
			(unsigned int)req->wct,
			(unsigned int)req_size));
		exit_server_cleanly("Invalid SMB request");
	}
	/* Ensure bcc is correct. */
	if (((uint8 *)smb_buf(inbuf)) + smb_buflen(inbuf) > inbuf + req_size) {
		DEBUG(0,("init_smb_request: invalid bcc number %u "
			"(wct = %u, size %u)\n",
			(unsigned int)smb_buflen(inbuf),
			(unsigned int)req->wct,
			(unsigned int)req_size));
		exit_server_cleanly("Invalid SMB request");
	}
	req->inbuf  = inbuf;
	req->outbuf = NULL;
}

/****************************************************************************
 structure to hold a linked list of queued messages.
 for processing.
****************************************************************************/

static struct pending_message_list *deferred_open_queue;

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

	msg = TALLOC_ZERO_P(NULL, struct pending_message_list);

	if(msg == NULL) {
		DEBUG(0,("push_message: malloc fail (1)\n"));
		return False;
	}

	msg->buf = data_blob_talloc(msg, req->inbuf, msg_len);
	if(msg->buf.data == NULL) {
		DEBUG(0,("push_message: malloc fail (2)\n"));
		TALLOC_FREE(msg);
		return False;
	}

	msg->request_time = request_time;
	msg->end_time = end_time;
	msg->encrypted = req->encrypted;

	if (private_data) {
		msg->private_data = data_blob_talloc(msg, private_data,
						     private_len);
		if (msg->private_data.data == NULL) {
			DEBUG(0,("push_message: malloc fail (3)\n"));
			TALLOC_FREE(msg);
			return False;
		}
	}

	DLIST_ADD_END(deferred_open_queue, msg, struct pending_message_list *);

	DEBUG(10,("push_message: pushed message length %u on "
		  "deferred_open_queue\n", (unsigned int)msg_len));

	return True;
}

/****************************************************************************
 Function to delete a sharing violation open message by mid.
****************************************************************************/

void remove_deferred_open_smb_message(uint16 mid)
{
	struct pending_message_list *pml;

	for (pml = deferred_open_queue; pml; pml = pml->next) {
		if (mid == SVAL(pml->buf.data,smb_mid)) {
			DEBUG(10,("remove_sharing_violation_open_smb_message: "
				  "deleting mid %u len %u\n",
				  (unsigned int)mid,
				  (unsigned int)pml->buf.length ));
			DLIST_REMOVE(deferred_open_queue, pml);
			TALLOC_FREE(pml);
			return;
		}
	}
}

/****************************************************************************
 Move a sharing violation open retry message to the front of the list and
 schedule it for immediate processing.
****************************************************************************/

void schedule_deferred_open_smb_message(uint16 mid)
{
	struct pending_message_list *pml;
	int i = 0;

	for (pml = deferred_open_queue; pml; pml = pml->next) {
		uint16 msg_mid = SVAL(pml->buf.data,smb_mid);
		DEBUG(10,("schedule_deferred_open_smb_message: [%d] msg_mid = %u\n", i++,
			(unsigned int)msg_mid ));
		if (mid == msg_mid) {
			DEBUG(10,("schedule_deferred_open_smb_message: scheduling mid %u\n",
				mid ));
			pml->end_time.tv_sec = 0;
			pml->end_time.tv_usec = 0;
			DLIST_PROMOTE(deferred_open_queue, pml);
			return;
		}
	}

	DEBUG(10,("schedule_deferred_open_smb_message: failed to find message mid %u\n",
		mid ));
}

/****************************************************************************
 Return true if this mid is on the deferred queue.
****************************************************************************/

bool open_was_deferred(uint16 mid)
{
	struct pending_message_list *pml;

	for (pml = deferred_open_queue; pml; pml = pml->next) {
		if (SVAL(pml->buf.data,smb_mid) == mid) {
			return True;
		}
	}
	return False;
}

/****************************************************************************
 Return the message queued by this mid.
****************************************************************************/

struct pending_message_list *get_open_deferred_message(uint16 mid)
{
	struct pending_message_list *pml;

	for (pml = deferred_open_queue; pml; pml = pml->next) {
		if (SVAL(pml->buf.data,smb_mid) == mid) {
			return pml;
		}
	}
	return NULL;
}

/****************************************************************************
 Function to push a deferred open smb message onto a linked list of local smb
 messages ready for processing.
****************************************************************************/

bool push_deferred_smb_message(struct smb_request *req,
			       struct timeval request_time,
			       struct timeval timeout,
			       char *private_data, size_t priv_len)
{
	struct timeval end_time;

	if (req->unread_bytes) {
		DEBUG(0,("push_deferred_smb_message: logic error ! "
			"unread_bytes = %u\n",
			(unsigned int)req->unread_bytes ));
		smb_panic("push_deferred_smb_message: "
			"logic error unread_bytes != 0" );
	}

	end_time = timeval_sum(&request_time, &timeout);

	DEBUG(10,("push_deferred_open_smb_message: pushing message len %u mid %u "
		  "timeout time [%u.%06u]\n",
		  (unsigned int) smb_len(req->inbuf)+4, (unsigned int)req->mid,
		  (unsigned int)end_time.tv_sec,
		  (unsigned int)end_time.tv_usec));

	return push_queued_message(req, request_time, end_time,
				   private_data, priv_len);
}

struct idle_event {
	struct timed_event *te;
	struct timeval interval;
	char *name;
	bool (*handler)(const struct timeval *now, void *private_data);
	void *private_data;
};

static void idle_event_handler(struct event_context *ctx,
			       struct timed_event *te,
			       const struct timeval *now,
			       void *private_data)
{
	struct idle_event *event =
		talloc_get_type_abort(private_data, struct idle_event);

	TALLOC_FREE(event->te);

	if (!event->handler(now, event->private_data)) {
		/* Don't repeat, delete ourselves */
		TALLOC_FREE(event);
		return;
	}

	event->te = event_add_timed(ctx, event,
				    timeval_sum(now, &event->interval),
				    event->name,
				    idle_event_handler, event);

	/* We can't do much but fail here. */
	SMB_ASSERT(event->te != NULL);
}

struct idle_event *event_add_idle(struct event_context *event_ctx,
				  TALLOC_CTX *mem_ctx,
				  struct timeval interval,
				  const char *name,
				  bool (*handler)(const struct timeval *now,
						  void *private_data),
				  void *private_data)
{
	struct idle_event *result;
	struct timeval now = timeval_current();

	result = TALLOC_P(mem_ctx, struct idle_event);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	result->interval = interval;
	result->handler = handler;
	result->private_data = private_data;

	if (!(result->name = talloc_asprintf(result, "idle_evt(%s)", name))) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	result->te = event_add_timed(event_ctx, result,
				     timeval_sum(&now, &interval),
				     result->name,
				     idle_event_handler, result);
	if (result->te == NULL) {
		DEBUG(0, ("event_add_timed failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	return result;
}

/****************************************************************************
 Do all async processing in here. This includes kernel oplock messages, change
 notify events etc.
****************************************************************************/

static void async_processing(fd_set *pfds)
{
	DEBUG(10,("async_processing: Doing async processing.\n"));

	process_aio_queue();

	process_kernel_oplocks(smbd_messaging_context(), pfds);

	/* Do the aio check again after receive_local_message as it does a
	   select and may have eaten our signal. */
	/* Is this till true? -- vl */
	process_aio_queue();

	if (got_sig_term) {
		exit_server_cleanly("termination signal");
	}

	/* check for sighup processing */
	if (reload_after_sighup) {
		change_to_root_user();
		DEBUG(1,("Reloading services after SIGHUP\n"));
		reload_services(False);
		reload_after_sighup = 0;
	}
}

/****************************************************************************
 Add a fd to the set we will be select(2)ing on.
****************************************************************************/

static int select_on_fd(int fd, int maxfd, fd_set *fds)
{
	if (fd != -1) {
		FD_SET(fd, fds);
		maxfd = MAX(maxfd, fd);
	}

	return maxfd;
}

/****************************************************************************
  Do a select on an two fd's - with timeout. 

  If a local udp message has been pushed onto the
  queue (this can only happen during oplock break
  processing) call async_processing()

  If a pending smb message has been pushed onto the
  queue (this can only happen during oplock break
  processing) return this next.

  If the first smbfd is ready then read an smb from it.
  if the second (loopback UDP) fd is ready then read a message
  from it and setup the buffer header to identify the length
  and from address.
  Returns False on timeout or error.
  Else returns True.

The timeout is in milliseconds
****************************************************************************/

static NTSTATUS receive_message_or_smb(TALLOC_CTX *mem_ctx, char **buffer,
				       size_t *buffer_len, int timeout,
				       size_t *p_unread, bool *p_encrypted)
{
	fd_set r_fds, w_fds;
	int selrtn;
	struct timeval to;
	int maxfd = 0;
	size_t len = 0;
	NTSTATUS status;

	*p_unread = 0;

 again:

	if (timeout >= 0) {
		to.tv_sec = timeout / 1000;
		to.tv_usec = (timeout % 1000) * 1000;
	} else {
		to.tv_sec = SMBD_SELECT_TIMEOUT;
		to.tv_usec = 0;
	}

	/*
	 * Note that this call must be before processing any SMB
	 * messages as we need to synchronously process any messages
	 * we may have sent to ourselves from the previous SMB.
	 */
	message_dispatch(smbd_messaging_context());

	/*
	 * Check to see if we already have a message on the deferred open queue
	 * and it's time to schedule.
	 */
  	if(deferred_open_queue != NULL) {
		bool pop_message = False;
		struct pending_message_list *msg = deferred_open_queue;

		if (timeval_is_zero(&msg->end_time)) {
			pop_message = True;
		} else {
			struct timeval tv;
			SMB_BIG_INT tdif;

			GetTimeOfDay(&tv);
			tdif = usec_time_diff(&msg->end_time, &tv);
			if (tdif <= 0) {
				/* Timed out. Schedule...*/
				pop_message = True;
				DEBUG(10,("receive_message_or_smb: queued message timed out.\n"));
			} else {
				/* Make a more accurate select timeout. */
				to.tv_sec = tdif / 1000000;
				to.tv_usec = tdif % 1000000;
				DEBUG(10,("receive_message_or_smb: select with timeout of [%u.%06u]\n",
					(unsigned int)to.tv_sec, (unsigned int)to.tv_usec ));
			}
		}

		if (pop_message) {

			*buffer = (char *)talloc_memdup(mem_ctx, msg->buf.data,
							msg->buf.length);
			if (*buffer == NULL) {
				DEBUG(0, ("talloc failed\n"));
				return NT_STATUS_NO_MEMORY;
			}
			*buffer_len = msg->buf.length;
			*p_encrypted = msg->encrypted;

			/* We leave this message on the queue so the open code can
			   know this is a retry. */
			DEBUG(5,("receive_message_or_smb: returning deferred open smb message.\n"));
			return NT_STATUS_OK;
		}
	}

	/*
	 * Setup the select fd sets.
	 */

	FD_ZERO(&r_fds);
	FD_ZERO(&w_fds);

	/*
	 * Ensure we process oplock break messages by preference.
	 * We have to do this before the select, after the select
	 * and if the select returns EINTR. This is due to the fact
	 * that the selects called from async_processing can eat an EINTR
	 * caused by a signal (we can't take the break message there).
	 * This is hideously complex - *MUST* be simplified for 3.0 ! JRA.
	 */

	if (oplock_message_waiting(&r_fds)) {
		DEBUG(10,("receive_message_or_smb: oplock_message is waiting.\n"));
		async_processing(&r_fds);
		/*
		 * After async processing we must go and do the select again, as
		 * the state of the flag in fds for the server file descriptor is
		 * indeterminate - we may have done I/O on it in the oplock processing. JRA.
		 */
		goto again;
	}

	/*
	 * Are there any timed events waiting ? If so, ensure we don't
	 * select for longer than it would take to wait for them.
	 */

	{
		struct timeval now;
		GetTimeOfDay(&now);

		event_add_to_select_args(smbd_event_context(), &now,
					 &r_fds, &w_fds, &to, &maxfd);
	}

	if (timeval_is_zero(&to)) {
		/* Process a timed event now... */
		if (run_events(smbd_event_context(), 0, NULL, NULL)) {
			goto again;
		}
	}
	
	{
		int sav;
		START_PROFILE(smbd_idle);

		maxfd = select_on_fd(smbd_server_fd(), maxfd, &r_fds);
		maxfd = select_on_fd(oplock_notify_fd(), maxfd, &r_fds);

		selrtn = sys_select(maxfd+1,&r_fds,&w_fds,NULL,&to);
		sav = errno;

		END_PROFILE(smbd_idle);
		errno = sav;
	}

	if (run_events(smbd_event_context(), selrtn, &r_fds, &w_fds)) {
		goto again;
	}

	/* if we get EINTR then maybe we have received an oplock
	   signal - treat this as select returning 1. This is ugly, but
	   is the best we can do until the oplock code knows more about
	   signals */
	if (selrtn == -1 && errno == EINTR) {
		async_processing(&r_fds);
		/*
		 * After async processing we must go and do the select again, as
		 * the state of the flag in fds for the server file descriptor is
		 * indeterminate - we may have done I/O on it in the oplock processing. JRA.
		 */
		goto again;
	}

	/* Check if error */
	if (selrtn == -1) {
		/* something is wrong. Maybe the socket is dead? */
		return map_nt_error_from_unix(errno);
	}

	/* Did we timeout ? */
	if (selrtn == 0) {
		return NT_STATUS_IO_TIMEOUT;
	}

	/*
	 * Ensure we process oplock break messages by preference.
	 * This is IMPORTANT ! Otherwise we can starve other processes
	 * sending us an oplock break message. JRA.
	 */

	if (oplock_message_waiting(&r_fds)) {
		async_processing(&r_fds);
		/*
		 * After async processing we must go and do the select again, as
		 * the state of the flag in fds for the server file descriptor is
		 * indeterminate - we may have done I/O on it in the oplock processing. JRA.
		 */
		goto again;
	}

	/*
	 * We've just woken up from a protentially long select sleep.
	 * Ensure we process local messages as we need to synchronously
	 * process any messages from other smbd's to avoid file rename race
	 * conditions. This call is cheap if there are no messages waiting.
	 * JRA.
	 */
	message_dispatch(smbd_messaging_context());

	status = receive_smb_talloc(mem_ctx, smbd_server_fd(), buffer, 0,
				    p_unread, p_encrypted, &len);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*buffer_len = len;

	return NT_STATUS_OK;
}

/*
 * Only allow 5 outstanding trans requests. We're allocating memory, so
 * prevent a DoS.
 */

NTSTATUS allow_new_trans(struct trans_state *list, int mid)
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

/****************************************************************************
 We're terminating and have closed all our files/connections etc.
 If there are any pending local messages we need to respond to them
 before termination so that other smbds don't think we just died whilst
 holding oplocks.
****************************************************************************/

void respond_to_all_remaining_local_messages(void)
{
	/*
	 * Assert we have no exclusive open oplocks.
	 */

	if(get_number_of_exclusive_open_oplocks()) {
		DEBUG(0,("respond_to_all_remaining_local_messages: PANIC : we have %d exclusive oplocks.\n",
			get_number_of_exclusive_open_oplocks() ));
		return;
	}

	process_kernel_oplocks(smbd_messaging_context(), NULL);

	return;
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
	void (*fn_new)(struct smb_request *req);
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
/* 0x33 */ { "SMBtranss2",reply_transs2, AS_USER | CAN_IPC},
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

void reply_outbuf(struct smb_request *req, uint8 num_words, uint32 num_bytes)
{
	/*
         * Protect against integer wrap
         */
	if ((num_bytes > 0xffffff)
	    || ((num_bytes + smb_size + num_words*2) > 0xffffff)) {
		char *msg;
		if (asprintf(&msg, "num_bytes too large: %u",
			     (unsigned)num_bytes) == -1) {
			msg = CONST_DISCARD(char *, "num_bytes too large");
		}
		smb_panic(msg);
	}

	if (!(req->outbuf = TALLOC_ARRAY(
		      req, uint8,
		      smb_size + num_words*2 + num_bytes))) {
		smb_panic("could not allocate output buffer\n");
	}

	construct_reply_common((char *)req->inbuf, (char *)req->outbuf);
	srv_set_message((char *)req->outbuf, num_words, num_bytes, false);
	/*
	 * Zero out the word area, the caller has to take care of the bcc area
	 * himself
	 */
	if (num_words != 0) {
		memset(req->outbuf + smb_vwv0, 0, num_words*2);
	}

	return;
}


/*******************************************************************
 Dump a packet to a file.
********************************************************************/

static void smb_dump(const char *name, int type, const char *data, ssize_t len)
{
	int fd, i;
	char *fname = NULL;
	if (DEBUGLEVEL < 50) {
		return;
	}

	if (len < 4) len = smb_len(data)+4;
	for (i=1;i<100;i++) {
		if (asprintf(&fname, "/tmp/%s.%d.%s", name, i,
			     type ? "req" : "resp") == -1) {
			return;
		}
		fd = open(fname, O_WRONLY|O_CREAT|O_EXCL, 0644);
		if (fd != -1 || errno != EEXIST) break;
	}
	if (fd != -1) {
		ssize_t ret = write(fd, data, len);
		if (ret != len)
			DEBUG(0,("smb_dump: problem: write returned %d\n", (int)ret ));
		close(fd);
		DEBUG(0,("created %s len %lu\n", fname, (unsigned long)len));
	}
	SAFE_FREE(fname);
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

static connection_struct *switch_message(uint8 type, struct smb_request *req, int size)
{
	int flags;
	uint16 session_tag;
	connection_struct *conn = NULL;

	static uint16 last_session_tag = UID_FIELD_INVALID;

	errno = 0;

	/* Make sure this is an SMB packet. smb_size contains NetBIOS header
	 * so subtract 4 from it. */
	if (!valid_smb_header(req->inbuf)
	    || (size < (smb_size - 4))) {
		DEBUG(2,("Non-SMB packet of length %d. Terminating server\n",
			 smb_len(req->inbuf)));
		exit_server_cleanly("Non-SMB packet");
	}

	if (smb_messages[type].fn_new == NULL) {
		DEBUG(0,("Unknown message type %d!\n",type));
		smb_dump("Unknown", 1, (char *)req->inbuf, size);
		reply_unknown_new(req, type);
		return NULL;
	}

	flags = smb_messages[type].flags;

	/* In share mode security we must ignore the vuid. */
	session_tag = (lp_security() == SEC_SHARE)
		? UID_FIELD_INVALID : req->vuid;
	conn = req->conn;

	DEBUG(3,("switch message %s (pid %d) conn 0x%lx\n", smb_fn_name(type),
		 (int)sys_getpid(), (unsigned long)conn));

	smb_dump(smb_fn_name(type), 1, (char *)req->inbuf, size);

	/* Ensure this value is replaced in the incoming packet. */
	SSVAL(req->inbuf,smb_uid,session_tag);

	/*
	 * Ensure the correct username is in current_user_info.  This is a
	 * really ugly bugfix for problems with multiple session_setup_and_X's
	 * being done and allowing %U and %G substitutions to work correctly.
	 * There is a reason this code is done here, don't move it unless you
	 * know what you're doing... :-).
	 * JRA.
	 */

	if (session_tag != last_session_tag) {
		user_struct *vuser = NULL;

		last_session_tag = session_tag;
		if(session_tag != UID_FIELD_INVALID) {
			vuser = get_valid_user_struct(session_tag);
			if (vuser) {
				set_current_user_info(&vuser->user);
			}
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
				reply_doserror(req, ERRSRV, ERRinvnid);
			}
			return NULL;
		}

		if (!change_to_user(conn,session_tag)) {
			reply_nterror(req, NT_STATUS_DOS(ERRSRV, ERRbaduid));
			remove_deferred_open_smb_message(req->mid);
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
			reply_doserror(req, ERRSRV,ERRaccess);
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
			conn->encrypt_level = Required;
		} else if (ENCRYPTION_REQUIRED(conn)) {
			uint8 com = CVAL(req->inbuf,smb_com);
			if (com != SMBtrans2 && com != SMBtranss2) {
				exit_server_cleanly("encryption required "
					"on connection");
				return conn;
			}
		}

		if (!set_current_service(conn,SVAL(req->inbuf,smb_flg),
					 (flags & (AS_USER|DO_CHDIR)
					  ?True:False))) {
			reply_doserror(req, ERRSRV, ERRaccess);
			return conn;
		}
		conn->num_smb_operations++;
	}

	/* does this protocol need to be run as guest? */
	if ((flags & AS_GUEST)
	    && (!change_to_guest() ||
		!check_access(smbd_server_fd(), lp_hostsallow(-1),
			      lp_hostsdeny(-1)))) {
		reply_doserror(req, ERRSRV, ERRaccess);
		return conn;
	}

	smb_messages[type].fn_new(req);
	return req->conn;
}

/****************************************************************************
 Construct a reply to the incoming packet.
****************************************************************************/

static void construct_reply(char *inbuf, int size, size_t unread_bytes, bool encrypted)
{
	uint8 type = CVAL(inbuf,smb_com);
	connection_struct *conn;
	struct smb_request *req;

	chain_size = 0;
	file_chain_reset();
	reset_chain_p();

	if (!(req = talloc(talloc_tos(), struct smb_request))) {
		smb_panic("could not allocate smb_request");
	}
	init_smb_request(req, (uint8 *)inbuf, unread_bytes, encrypted);

	conn = switch_message(type, req, size);

	if (req->unread_bytes) {
		/* writeX failed. drain socket. */
		if (drain_socket(smbd_server_fd(), req->unread_bytes) !=
				req->unread_bytes) {
			smb_panic("failed to drain pending bytes");
		}
		req->unread_bytes = 0;
	}

	if (req->outbuf == NULL) {
		return;
	}

	if (CVAL(req->outbuf,0) == 0) {
		show_msg((char *)req->outbuf);
	}

	if (!srv_send_smb(smbd_server_fd(),
			(char *)req->outbuf,
			IS_CONN_ENCRYPTED(conn)||req->encrypted)) {
		exit_server_cleanly("construct_reply: srv_send_smb failed.");
	}

	TALLOC_FREE(req);

	return;
}

/****************************************************************************
 Process an smb from the client
****************************************************************************/

static void process_smb(char *inbuf, size_t nread, size_t unread_bytes, bool encrypted)
{
	static int trans_num;
	int msg_type = CVAL(inbuf,0);

	DO_PROFILE_INC(smb_count);

	if (trans_num == 0) {
		char addr[INET6_ADDRSTRLEN];

		/* on the first packet, check the global hosts allow/ hosts
		deny parameters before doing any parsing of the packet
		passed to us by the client.  This prevents attacks on our
		parsing code from hosts not in the hosts allow list */

		if (!check_access(smbd_server_fd(), lp_hostsallow(-1),
				  lp_hostsdeny(-1))) {
			/* send a negative session response "not listening on calling name" */
			static unsigned char buf[5] = {0x83, 0, 0, 1, 0x81};
			DEBUG( 1, ( "Connection denied from %s\n",
				client_addr(get_client_fd(),addr,sizeof(addr)) ) );
			(void)srv_send_smb(smbd_server_fd(),(char *)buf,false);
			exit_server_cleanly("connection denied");
		}
	}

	DEBUG( 6, ( "got message type 0x%x of len 0x%x\n", msg_type,
		    smb_len(inbuf) ) );
	DEBUG( 3, ( "Transaction %d of length %d (%u toread)\n", trans_num,
				(int)nread,
				(unsigned int)unread_bytes ));

	if (msg_type != 0) {
		/*
		 * NetBIOS session request, keepalive, etc.
		 */
		reply_special(inbuf);
		return;
	}

	show_msg(inbuf);

	construct_reply(inbuf,nread,unread_bytes,encrypted);

	trans_num++;
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

static uint32 common_flags2 = FLAGS2_LONG_PATH_COMPONENTS|FLAGS2_32_BIT_ERROR_CODES;

void add_to_common_flags2(uint32 v)
{
	common_flags2 |= v;
}

void remove_from_common_flags2(uint32 v)
{
	common_flags2 &= ~v;
}

void construct_reply_common(const char *inbuf, char *outbuf)
{
	srv_set_message(outbuf,0,0,false);
	
	SCVAL(outbuf,smb_com,CVAL(inbuf,smb_com));
	SIVAL(outbuf,smb_rcls,0);
	SCVAL(outbuf,smb_flg, FLAG_REPLY | (CVAL(inbuf,smb_flg) & FLAG_CASELESS_PATHNAMES)); 
	SSVAL(outbuf,smb_flg2,
		(SVAL(inbuf,smb_flg2) & FLAGS2_UNICODE_STRINGS) |
		common_flags2);
	memset(outbuf+smb_pidhigh,'\0',(smb_tid-smb_pidhigh));

	SSVAL(outbuf,smb_tid,SVAL(inbuf,smb_tid));
	SSVAL(outbuf,smb_pid,SVAL(inbuf,smb_pid));
	SSVAL(outbuf,smb_uid,SVAL(inbuf,smb_uid));
	SSVAL(outbuf,smb_mid,SVAL(inbuf,smb_mid));
}

/****************************************************************************
 Construct a chained reply and add it to the already made reply
****************************************************************************/

void chain_reply(struct smb_request *req)
{
	static char *orig_inbuf;

	/*
	 * Dirty little const_discard: We mess with req->inbuf, which is
	 * declared as const. If maybe at some point this routine gets
	 * rewritten, this const_discard could go away.
	 */
	char *inbuf = CONST_DISCARD(char *, req->inbuf);
	int size = smb_len(req->inbuf)+4;

	int smb_com1, smb_com2 = CVAL(inbuf,smb_vwv0);
	unsigned smb_off2 = SVAL(inbuf,smb_vwv1);
	char *inbuf2;
	int outsize2;
	int new_size;
	char inbuf_saved[smb_wct];
	char *outbuf = (char *)req->outbuf;
	size_t outsize = smb_len(outbuf) + 4;
	size_t outsize_padded;
	size_t padding;
	size_t ofs, to_move;

	struct smb_request *req2;
	size_t caller_outputlen;
	char *caller_output;

	/* Maybe its not chained, or it's an error packet. */
	if (smb_com2 == 0xFF || SVAL(outbuf,smb_rcls) != 0) {
		SCVAL(outbuf,smb_vwv0,0xFF);
		return;
	}

	if (chain_size == 0) {
		/* this is the first part of the chain */
		orig_inbuf = inbuf;
	}

	/*
	 * We need to save the output the caller added to the chain so that we
	 * can splice it into the final output buffer later.
	 */

	caller_outputlen = outsize - smb_wct;

	caller_output = (char *)memdup(outbuf + smb_wct, caller_outputlen);

	if (caller_output == NULL) {
		/* TODO: NT_STATUS_NO_MEMORY */
		smb_panic("could not dup outbuf");
	}

	/*
	 * The original Win95 redirector dies on a reply to
	 * a lockingX and read chain unless the chain reply is
	 * 4 byte aligned. JRA.
	 */

	outsize_padded = (outsize + 3) & ~3;
	padding = outsize_padded - outsize;

	/*
	 * remember how much the caller added to the chain, only counting
	 * stuff after the parameter words
	 */
	chain_size += (outsize_padded - smb_wct);

	/*
	 * work out pointers into the original packets. The
	 * headers on these need to be filled in
	 */
	inbuf2 = orig_inbuf + smb_off2 + 4 - smb_wct;

	/* remember the original command type */
	smb_com1 = CVAL(orig_inbuf,smb_com);

	/* save the data which will be overwritten by the new headers */
	memcpy(inbuf_saved,inbuf2,smb_wct);

	/* give the new packet the same header as the last part of the SMB */
	memmove(inbuf2,inbuf,smb_wct);

	/* create the in buffer */
	SCVAL(inbuf2,smb_com,smb_com2);

	/* work out the new size for the in buffer. */
	new_size = size - (inbuf2 - inbuf);
	if (new_size < 0) {
		DEBUG(0,("chain_reply: chain packet size incorrect "
			 "(orig size = %d, offset = %d)\n",
			 size, (int)(inbuf2 - inbuf) ));
		exit_server_cleanly("Bad chained packet");
		return;
	}

	/* And set it in the header. */
	smb_setlen(inbuf2, new_size - 4);

	DEBUG(3,("Chained message\n"));
	show_msg(inbuf2);

	if (!(req2 = talloc(talloc_tos(), struct smb_request))) {
		smb_panic("could not allocate smb_request");
	}
	init_smb_request(req2, (uint8 *)inbuf2,0, req->encrypted);

	/* process the request */
	switch_message(smb_com2, req2, new_size);

	/*
	 * We don't accept deferred operations in chained requests.
	 */
	SMB_ASSERT(req2->outbuf != NULL);
	outsize2 = smb_len(req2->outbuf)+4;

	/*
	 * Move away the new command output so that caller_output fits in,
	 * copy in the caller_output saved above.
	 */

	SMB_ASSERT(outsize_padded >= smb_wct);

	/*
	 * "ofs" is the space we need for caller_output. Equal to
	 * caller_outputlen plus the padding.
	 */

	ofs = outsize_padded - smb_wct;

	/*
	 * "to_move" is the amount of bytes the secondary routine gave us
	 */

	to_move = outsize2 - smb_wct;

	if (to_move + ofs + smb_wct + chain_size > max_send) {
		smb_panic("replies too large -- would have to cut");
	}

	/*
	 * In the "new" API "outbuf" is allocated via reply_outbuf, just for
	 * the first request in the chain. So we have to re-allocate it. In
	 * the "old" API the only outbuf ever used is the global OutBuffer
	 * which is always large enough.
	 */

	outbuf = TALLOC_REALLOC_ARRAY(NULL, outbuf, char,
				      to_move + ofs + smb_wct);
	if (outbuf == NULL) {
		smb_panic("could not realloc outbuf");
	}

	req->outbuf = (uint8 *)outbuf;

	memmove(outbuf + smb_wct + ofs, req2->outbuf + smb_wct, to_move);
	memcpy(outbuf + smb_wct, caller_output, caller_outputlen);

	/*
	 * copy the new reply header over the old one but preserve the smb_com
	 * field
	 */
	memmove(outbuf, req2->outbuf, smb_wct);
	SCVAL(outbuf, smb_com, smb_com1);

	/*
	 * We've just copied in the whole "wct" area from the secondary
	 * function. Fix up the chaining: com2 and the offset need to be
	 * readjusted.
	 */

	SCVAL(outbuf, smb_vwv0, smb_com2);
	SSVAL(outbuf, smb_vwv1, chain_size + smb_wct - 4);

	if (padding != 0) {

		/*
		 * Due to padding we have some uninitialized bytes after the
		 * caller's output
		 */

		memset(outbuf + outsize, 0, padding);
	}

	smb_setlen(outbuf, outsize2 + caller_outputlen + padding - 4);

	/*
	 * restore the saved data, being careful not to overwrite any data
	 * from the reply header
	 */
	memcpy(inbuf2,inbuf_saved,smb_wct);

	SAFE_FREE(caller_output);
	TALLOC_FREE(req2);

	/*
	 * Reset the chain_size for our caller's offset calculations
	 */

	chain_size -= (outsize_padded - smb_wct);

	return;
}

/****************************************************************************
 Setup the needed select timeout in milliseconds.
****************************************************************************/

static int setup_select_timeout(void)
{
	int select_timeout;

	select_timeout = SMBD_SELECT_TIMEOUT*1000;

	if (print_notify_messages_pending()) {
		select_timeout = MIN(select_timeout, 1000);
	}

	return select_timeout;
}

/****************************************************************************
 Check if services need reloading.
****************************************************************************/

void check_reload(time_t t)
{
	static pid_t mypid = 0;
	static time_t last_smb_conf_reload_time = 0;
	static time_t last_printer_reload_time = 0;
	time_t printcap_cache_time = (time_t)lp_printcap_cache_time();

	if(last_smb_conf_reload_time == 0) {
		last_smb_conf_reload_time = t;
		/* Our printing subsystem might not be ready at smbd start up.
		   Then no printer is available till the first printers check
		   is performed.  A lower initial interval circumvents this. */
		if ( printcap_cache_time > 60 )
			last_printer_reload_time = t - printcap_cache_time + 60;
		else
			last_printer_reload_time = t;
	}

	if (mypid != getpid()) { /* First time or fork happened meanwhile */
		/* randomize over 60 second the printcap reload to avoid all
		 * process hitting cupsd at the same time */
		int time_range = 60;

		last_printer_reload_time += random() % time_range;
		mypid = getpid();
	}

	if (reload_after_sighup || (t >= last_smb_conf_reload_time+SMBD_RELOAD_CHECK)) {
		reload_services(True);
		reload_after_sighup = False;
		last_smb_conf_reload_time = t;
	}

	/* 'printcap cache time = 0' disable the feature */
	
	if ( printcap_cache_time != 0 )
	{ 
		/* see if it's time to reload or if the clock has been set back */
		
		if ( (t >= last_printer_reload_time+printcap_cache_time) 
			|| (t-last_printer_reload_time  < 0) ) 
		{
			DEBUG( 3,( "Printcap cache time expired.\n"));
			reload_printers();
			last_printer_reload_time = t;
		}
	}
}

/****************************************************************************
 Process any timeout housekeeping. Return False if the caller should exit.
****************************************************************************/

static void timeout_processing(int *select_timeout,
			       time_t *last_timeout_processing_time)
{
	time_t t;

	*last_timeout_processing_time = t = time(NULL);

	/* become root again if waiting */
	change_to_root_user();

	/* check if we need to reload services */
	check_reload(t);

	if(global_machine_password_needs_changing && 
			/* for ADS we need to do a regular ADS password change, not a domain
					password change */
			lp_security() == SEC_DOMAIN) {

		unsigned char trust_passwd_hash[16];
		time_t lct;
		void *lock;

		/*
		 * We're in domain level security, and the code that
		 * read the machine password flagged that the machine
		 * password needs changing.
		 */

		/*
		 * First, open the machine password file with an exclusive lock.
		 */

		lock = secrets_get_trust_account_lock(NULL, lp_workgroup());

		if (lock == NULL) {
			DEBUG(0,("process: unable to lock the machine account password for \
machine %s in domain %s.\n", global_myname(), lp_workgroup() ));
			return;
		}

		if(!secrets_fetch_trust_account_password(lp_workgroup(), trust_passwd_hash, &lct, NULL)) {
			DEBUG(0,("process: unable to read the machine account password for \
machine %s in domain %s.\n", global_myname(), lp_workgroup()));
			TALLOC_FREE(lock);
			return;
		}

		/*
		 * Make sure someone else hasn't already done this.
		 */

		if(t < lct + lp_machine_password_timeout()) {
			global_machine_password_needs_changing = False;
			TALLOC_FREE(lock);
			return;
		}

		/* always just contact the PDC here */
    
		change_trust_account_password( lp_workgroup(), NULL);
		global_machine_password_needs_changing = False;
		TALLOC_FREE(lock);
	}

	/* update printer queue caches if necessary */
  
	update_monitored_printq_cache();
  
	/*
	 * Now we are root, check if the log files need pruning.
	 * Force a log file check.
	 */
	force_check_log_size();
	check_log_size();

	/* Send any queued printer notify message to interested smbd's. */

	print_notify_send_messages(smbd_messaging_context(), 0);

	/*
	 * Modify the select timeout depending upon
	 * what we have remaining in our queues.
	 */

	*select_timeout = setup_select_timeout();

	return;
}

/****************************************************************************
 Process commands from the client
****************************************************************************/

void smbd_process(void)
{
	time_t last_timeout_processing_time = time(NULL);
	unsigned int num_smbs = 0;
	size_t unread_bytes = 0;

	max_recv = MIN(lp_maxxmit(),BUFFER_SIZE);

	while (True) {
		int select_timeout = setup_select_timeout();
		int num_echos;
		char *inbuf = NULL;
		size_t inbuf_len = 0;
		bool encrypted = false;
		TALLOC_CTX *frame = talloc_stackframe_pool(8192);

		errno = 0;

		/* Did someone ask for immediate checks on things like blocking locks ? */
		if (select_timeout == 0) {
			timeout_processing(&select_timeout,
					   &last_timeout_processing_time);
			num_smbs = 0; /* Reset smb counter. */
		}

		run_events(smbd_event_context(), 0, NULL, NULL);

		while (True) {
			NTSTATUS status;

			status = receive_message_or_smb(
				talloc_tos(), &inbuf, &inbuf_len,
				select_timeout,	&unread_bytes, &encrypted);

			if (NT_STATUS_IS_OK(status)) {
				break;
			}

			if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
				timeout_processing(
					&select_timeout,
					&last_timeout_processing_time);
				continue;
			}

			DEBUG(3, ("receive_message_or_smb failed: %s, "
				  "exiting\n", nt_errstr(status)));
			return;

			num_smbs = 0; /* Reset smb counter. */
		}


		/*
		 * Ensure we do timeout processing if the SMB we just got was
		 * only an echo request. This allows us to set the select
		 * timeout in 'receive_message_or_smb()' to any value we like
		 * without worrying that the client will send echo requests
		 * faster than the select timeout, thus starving out the
		 * essential processing (change notify, blocking locks) that
		 * the timeout code does. JRA.
		 */
		num_echos = smb_echo_count;

		process_smb(inbuf, inbuf_len, unread_bytes, encrypted);

		TALLOC_FREE(inbuf);

		if (smb_echo_count != num_echos) {
			timeout_processing(&select_timeout,
					   &last_timeout_processing_time);
			num_smbs = 0; /* Reset smb counter. */
		}

		num_smbs++;

		/*
		 * If we are getting smb requests in a constant stream
		 * with no echos, make sure we attempt timeout processing
		 * every select_timeout milliseconds - but only check for this
		 * every 200 smb requests.
		 */
		
		if ((num_smbs % 200) == 0) {
			time_t new_check_time = time(NULL);
			if(new_check_time - last_timeout_processing_time >= (select_timeout/1000)) {
				timeout_processing(
					&select_timeout,
					&last_timeout_processing_time);
				num_smbs = 0; /* Reset smb counter. */
				last_timeout_processing_time = new_check_time; /* Reset time. */
			}
		}

		/* The timeout_processing function isn't run nearly
		   often enough to implement 'max log size' without
		   overrunning the size of the file by many megabytes.
		   This is especially true if we are running at debug
		   level 10.  Checking every 50 SMBs is a nice
		   tradeoff of performance vs log file size overrun. */

		if ((num_smbs % 50) == 0 && need_to_check_log_size()) {
			change_to_root_user();
			check_log_size();
		}
		TALLOC_FREE(frame);
	}
}
