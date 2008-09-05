/*
   Unix SMB/CIFS implementation.
   Infrastructure for async SMB client requests
   Copyright (C) Volker Lendecke 2008

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

/*
 * Fetch an error out of a NBT packet
 */

NTSTATUS cli_pull_error(char *buf)
{
	uint32_t flags2 = SVAL(buf, smb_flg2);

	if (flags2 & FLAGS2_32_BIT_ERROR_CODES) {
		return NT_STATUS(IVAL(buf, smb_rcls));
	}

	/* if the client uses dos errors, but there is no error,
	   we should return no error here, otherwise it looks
	   like an unknown bad NT_STATUS. jmcd */
	if (CVAL(buf, smb_rcls) == 0)
		return NT_STATUS_OK;

	return NT_STATUS_DOS(CVAL(buf, smb_rcls), SVAL(buf,smb_err));
}

/*
 * Compatibility helper for the sync APIs: Fake NTSTATUS in cli->inbuf
 */

void cli_set_error(struct cli_state *cli, NTSTATUS status)
{
	uint32_t flags2 = SVAL(cli->inbuf, smb_flg2);

	if (NT_STATUS_IS_DOS(status)) {
		SSVAL(cli->inbuf, smb_flg2,
		      flags2 & ~FLAGS2_32_BIT_ERROR_CODES);
		SCVAL(cli->inbuf, smb_rcls, NT_STATUS_DOS_CLASS(status));
		SSVAL(cli->inbuf, smb_err, NT_STATUS_DOS_CODE(status));
		return;
	}

	SSVAL(cli->inbuf, smb_flg2, flags2 | FLAGS2_32_BIT_ERROR_CODES);
	SIVAL(cli->inbuf, smb_rcls, NT_STATUS_V(status));
	return;
}

/*
 * Allocate a new mid
 */

static uint16_t cli_new_mid(struct cli_state *cli)
{
	uint16_t result;
	struct cli_request *req;

	while (true) {
		result = cli->mid++;
		if (result == 0) {
			continue;
		}

		for (req = cli->outstanding_requests; req; req = req->next) {
			if (result == req->mid) {
				break;
			}
		}

		if (req == NULL) {
			return result;
		}
	}
}

static char *cli_request_print(TALLOC_CTX *mem_ctx, struct async_req *req)
{
	char *result = async_req_print(mem_ctx, req);
	struct cli_request *cli_req = cli_request_get(req);

	if (result == NULL) {
		return NULL;
	}

	return talloc_asprintf_append_buffer(
		result, "mid=%d\n", cli_req->mid);
}

static int cli_request_destructor(struct cli_request *req)
{
	if (req->enc_state != NULL) {
		common_free_enc_buffer(req->enc_state, req->outbuf);
	}
	DLIST_REMOVE(req->cli->outstanding_requests, req);
	return 0;
}

/*
 * Create a fresh async smb request
 */

struct async_req *cli_request_new(TALLOC_CTX *mem_ctx,
				  struct event_context *ev,
				  struct cli_state *cli,
				  uint8_t num_words, size_t num_bytes,
				  struct cli_request **preq)
{
	struct async_req *result;
	struct cli_request *cli_req;
	size_t bufsize = smb_size + num_words * 2 + num_bytes;

	result = async_req_new(mem_ctx, ev);
	if (result == NULL) {
		return NULL;
	}

	cli_req = (struct cli_request *)talloc_size(
		result, sizeof(*cli_req) + bufsize);
	if (cli_req == NULL) {
		TALLOC_FREE(result);
		return NULL;
	}
	talloc_set_name_const(cli_req, "struct cli_request");
	result->private_data = cli_req;
	result->print = cli_request_print;

	cli_req->async = result;
	cli_req->cli = cli;
	cli_req->outbuf = ((char *)cli_req + sizeof(*cli_req));
	cli_req->sent = 0;
	cli_req->mid = cli_new_mid(cli);
	cli_req->inbuf = NULL;
	cli_req->enc_state = NULL;

	SCVAL(cli_req->outbuf, smb_wct, num_words);
	SSVAL(cli_req->outbuf, smb_vwv + num_words * 2, num_bytes);

	DLIST_ADD_END(cli->outstanding_requests, cli_req,
		      struct cli_request *);
	talloc_set_destructor(cli_req, cli_request_destructor);

	DEBUG(10, ("cli_request_new: mid=%d\n", cli_req->mid));

	*preq = cli_req;
	return result;
}

/*
 * Convenience function to get the SMB part out of an async_req
 */

struct cli_request *cli_request_get(struct async_req *req)
{
	if (req == NULL) {
		return NULL;
	}
	return talloc_get_type_abort(req->private_data, struct cli_request);
}

/*
 * A PDU has arrived on cli->evt_inbuf
 */

static void handle_incoming_pdu(struct cli_state *cli)
{
	struct cli_request *req;
	uint16_t mid;
	size_t raw_pdu_len, buf_len, pdu_len, rest_len;
	char *pdu;
	NTSTATUS status;

	/*
	 * The encrypted PDU len might differ from the unencrypted one
	 */
	raw_pdu_len = smb_len(cli->evt_inbuf) + 4;
	buf_len = talloc_get_size(cli->evt_inbuf);
	rest_len = buf_len - raw_pdu_len;

	if (buf_len == raw_pdu_len) {
		/*
		 * Optimal case: Exactly one PDU was in the socket buffer
		 */
		pdu = cli->evt_inbuf;
		cli->evt_inbuf = NULL;
	}
	else {
		DEBUG(11, ("buf_len = %d, raw_pdu_len = %d, splitting "
			   "buffer\n", (int)buf_len, (int)raw_pdu_len));

		if (raw_pdu_len < rest_len) {
			/*
			 * The PDU is shorter, talloc_memdup that one.
			 */
			pdu = (char *)talloc_memdup(
				cli, cli->evt_inbuf, raw_pdu_len);

			memmove(cli->evt_inbuf,	cli->evt_inbuf + raw_pdu_len,
				buf_len - raw_pdu_len);

			cli->evt_inbuf = TALLOC_REALLOC_ARRAY(
				NULL, cli->evt_inbuf, char, rest_len);

			if (pdu == NULL) {
				status = NT_STATUS_NO_MEMORY;
				goto invalidate_requests;
			}
		}
		else {
			/*
			 * The PDU is larger than the rest, talloc_memdup the
			 * rest
			 */
			pdu = cli->evt_inbuf;

			cli->evt_inbuf = (char *)talloc_memdup(
				cli, pdu + raw_pdu_len,	rest_len);

			if (cli->evt_inbuf == NULL) {
				status = NT_STATUS_NO_MEMORY;
				goto invalidate_requests;
			}
		}

	}

	/*
	 * TODO: Handle oplock break requests
	 */

	if (cli_encryption_on(cli) && CVAL(pdu, 0) == 0) {
		uint16_t enc_ctx_num;

		status = get_enc_ctx_num((uint8_t *)pdu, &enc_ctx_num);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("get_enc_ctx_num returned %s\n",
				   nt_errstr(status)));
			goto invalidate_requests;
		}

		if (enc_ctx_num != cli->trans_enc_state->enc_ctx_num) {
			DEBUG(10, ("wrong enc_ctx %d, expected %d\n",
				   enc_ctx_num,
				   cli->trans_enc_state->enc_ctx_num));
			status = NT_STATUS_INVALID_HANDLE;
			goto invalidate_requests;
		}

		status = common_decrypt_buffer(cli->trans_enc_state,
					       pdu);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("common_decrypt_buffer returned %s\n",
				   nt_errstr(status)));
			goto invalidate_requests;
		}
	}

	if (!cli_check_sign_mac(cli, pdu)) {
		DEBUG(10, ("cli_check_sign_mac failed\n"));
		status = NT_STATUS_ACCESS_DENIED;
		goto invalidate_requests;
	}

	mid = SVAL(pdu, smb_mid);

	DEBUG(10, ("handle_incoming_pdu: got mid %d\n", mid));

	for (req = cli->outstanding_requests; req; req = req->next) {
		if (req->mid == mid) {
			break;
		}
	}

	pdu_len = smb_len(pdu) + 4;

	if (req == NULL) {
		DEBUG(3, ("Request for mid %d not found, dumping PDU\n", mid));

		TALLOC_FREE(pdu);
		return;
	}

	req->inbuf = talloc_move(req, &pdu);

	async_req_done(req->async);
	return;

 invalidate_requests:

	DEBUG(10, ("handle_incoming_pdu: Aborting with %s\n",
		   nt_errstr(status)));

	for (req = cli->outstanding_requests; req; req = req->next) {
		async_req_error(req->async, status);
	}
	return;
}

/*
 * fd event callback. This is the basic connection to the socket
 */

static void cli_state_handler(struct event_context *event_ctx,
			      struct fd_event *event, uint16 flags, void *p)
{
	struct cli_state *cli = (struct cli_state *)p;
	struct cli_request *req;
	NTSTATUS status;

	DEBUG(11, ("cli_state_handler called with flags %d\n", flags));

	if (flags & EVENT_FD_READ) {
		int res, available;
		size_t old_size, new_size;
		char *tmp;

		res = ioctl(cli->fd, FIONREAD, &available);
		if (res == -1) {
			DEBUG(10, ("ioctl(FIONREAD) failed: %s\n",
				   strerror(errno)));
			status = map_nt_error_from_unix(errno);
			goto sock_error;
		}

		if (available == 0) {
			/* EOF */
			status = NT_STATUS_END_OF_FILE;
			goto sock_error;
		}

		old_size = talloc_get_size(cli->evt_inbuf);
		new_size = old_size + available;

		if (new_size < old_size) {
			/* wrap */
			status = NT_STATUS_UNEXPECTED_IO_ERROR;
			goto sock_error;
		}

		tmp = TALLOC_REALLOC_ARRAY(cli, cli->evt_inbuf, char,
					   new_size);
		if (tmp == NULL) {
			/* nomem */
			status = NT_STATUS_NO_MEMORY;
			goto sock_error;
		}
		cli->evt_inbuf = tmp;

		res = recv(cli->fd, cli->evt_inbuf + old_size, available, 0);
		if (res == -1) {
			DEBUG(10, ("recv failed: %s\n", strerror(errno)));
			status = map_nt_error_from_unix(errno);
			goto sock_error;
		}

		DEBUG(11, ("cli_state_handler: received %d bytes, "
			   "smb_len(evt_inbuf) = %d\n", (int)res,
			   smb_len(cli->evt_inbuf)));

		/* recv *might* have returned less than announced */
		new_size = old_size + res;

		/* shrink, so I don't expect errors here */
		cli->evt_inbuf = TALLOC_REALLOC_ARRAY(cli, cli->evt_inbuf,
						      char, new_size);

		while ((cli->evt_inbuf != NULL)
		       && ((smb_len(cli->evt_inbuf) + 4) <= new_size)) {
			/*
			 * we've got a complete NBT level PDU in evt_inbuf
			 */
			handle_incoming_pdu(cli);
			new_size = talloc_get_size(cli->evt_inbuf);
		}
	}

	if (flags & EVENT_FD_WRITE) {
		size_t to_send;
		ssize_t sent;

		for (req = cli->outstanding_requests; req; req = req->next) {
			to_send = smb_len(req->outbuf)+4;
			if (to_send > req->sent) {
				break;
			}
		}

		if (req == NULL) {
			event_fd_set_not_writeable(event);
			return;
		}

		sent = send(cli->fd, req->outbuf + req->sent,
			    to_send - req->sent, 0);

		if (sent < 0) {
			status = map_nt_error_from_unix(errno);
			goto sock_error;
		}

		req->sent += sent;

		if (req->sent == to_send) {
			return;
		}
	}
	return;

 sock_error:
	for (req = cli->outstanding_requests; req; req = req->next) {
		async_req_error(req->async, status);
	}
	TALLOC_FREE(cli->fd_event);
	close(cli->fd);
	cli->fd = -1;
}

/*
 * Holder for a talloc_destructor, we need to zero out the pointers in cli
 * when deleting
 */
struct cli_tmp_event {
	struct cli_state *cli;
};

static int cli_tmp_event_destructor(struct cli_tmp_event *e)
{
	TALLOC_FREE(e->cli->fd_event);
	TALLOC_FREE(e->cli->event_ctx);
	return 0;
}

/*
 * Create a temporary event context for use in the sync helper functions
 */

struct cli_tmp_event *cli_tmp_event_ctx(TALLOC_CTX *mem_ctx,
					struct cli_state *cli)
{
	struct cli_tmp_event *state;

	if (cli->event_ctx != NULL) {
		return NULL;
	}

	state = talloc(mem_ctx, struct cli_tmp_event);
	if (state == NULL) {
		return NULL;
	}
	state->cli = cli;
	talloc_set_destructor(state, cli_tmp_event_destructor);

	cli->event_ctx = event_context_init(state);
	if (cli->event_ctx == NULL) {
		TALLOC_FREE(state);
		return NULL;
	}

	cli->fd_event = event_add_fd(cli->event_ctx, state, cli->fd,
				     EVENT_FD_READ, cli_state_handler, cli);
	if (cli->fd_event == NULL) {
		TALLOC_FREE(state);
		return NULL;
	}
	return state;
}

/*
 * Attach an event context permanently to a cli_struct
 */

NTSTATUS cli_add_event_ctx(struct cli_state *cli,
			   struct event_context *event_ctx)
{
	cli->event_ctx = event_ctx;
	cli->fd_event = event_add_fd(event_ctx, cli, cli->fd, EVENT_FD_READ,
				     cli_state_handler, cli);
	if (cli->fd_event == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}
