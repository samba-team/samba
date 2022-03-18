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
