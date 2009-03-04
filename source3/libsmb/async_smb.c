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

static void cli_state_handler(struct event_context *event_ctx,
			      struct fd_event *event, uint16 flags, void *p);

/**
 * Fetch an error out of a NBT packet
 * @param[in] buf	The SMB packet
 * @retval		The error, converted to NTSTATUS
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

/**
 * Compatibility helper for the sync APIs: Fake NTSTATUS in cli->inbuf
 * @param[in] cli	The client connection that just received an error
 * @param[in] status	The error to set on "cli"
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

/**
 * Allocate a new mid
 * @param[in] cli	The client connection
 * @retval		The new, unused mid
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

/**
 * Print an async req that happens to be a cli_request
 * @param[in] mem_ctx	The TALLOC_CTX to put the result on
 * @param[in] req	The request to print
 * @retval		The string representation of "req"
 */

static char *cli_request_print(TALLOC_CTX *mem_ctx, struct async_req *req)
{
	char *result = async_req_print(mem_ctx, req);
	struct cli_request *cli_req = talloc_get_type_abort(
		req->private_data, struct cli_request);

	if (result == NULL) {
		return NULL;
	}

	return talloc_asprintf_append_buffer(
		result, "mid=%d\n", cli_req->mid);
}

/**
 * Destroy a cli_request
 * @param[in] req	The cli_request to kill
 * @retval Can't fail
 */

static int cli_request_destructor(struct cli_request *req)
{
	if (req->enc_state != NULL) {
		common_free_enc_buffer(req->enc_state, (char *)req->outbuf);
	}
	DLIST_REMOVE(req->cli->outstanding_requests, req);
	if (req->cli->outstanding_requests == NULL) {
		TALLOC_FREE(req->cli->fd_event);
	}
	return 0;
}

/**
 * Are there already requests waiting in the chain_accumulator?
 * @param[in] cli	The cli_state we want to check
 * @retval reply :-)
 */

bool cli_in_chain(struct cli_state *cli)
{
	if (cli->chain_accumulator == NULL) {
		return false;
	}

	return (cli->chain_accumulator->num_async != 0);
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

	SMB_ASSERT(is_andx_req(cmd));

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

		SMB_ASSERT(ofs+4 < talloc_get_size(buf));
	}

	*pofs = ofs;
	return true;
}

/**
 * @brief Do the smb chaining at a buffer level
 * @param[in] poutbuf		Pointer to the talloc'ed buffer to be modified
 * @param[in] smb_command	The command that we want to issue
 * @param[in] wct		How many words?
 * @param[in] vwv		The words, already in network order
 * @param[in] bytes_alignment	How shall we align "bytes"?
 * @param[in] num_bytes		How many bytes?
 * @param[in] bytes		The data the request ships
 *
 * smb_splice_chain() adds the vwv and bytes to the request already present in
 * *poutbuf.
 */

bool smb_splice_chain(uint8_t **poutbuf, uint8_t smb_command,
		      uint8_t wct, const uint16_t *vwv,
		      size_t bytes_alignment,
		      uint32_t num_bytes, const uint8_t *bytes)
{
	uint8_t *outbuf;
	size_t old_size, new_size;
	size_t ofs;
	size_t chain_padding = 0;
	size_t bytes_padding = 0;
	bool first_request;

	old_size = talloc_get_size(*poutbuf);

	/*
	 * old_size == smb_wct means we're pushing the first request in for
	 * libsmb/
	 */

	first_request = (old_size == smb_wct);

	if (!first_request && ((old_size % 4) != 0)) {
		/*
		 * Align the wct field of subsequent requests to a 4-byte
		 * boundary
		 */
		chain_padding = 4 - (old_size % 4);
	}

	/*
	 * After the old request comes the new wct field (1 byte), the vwv's
	 * and the num_bytes field. After at we might need to align the bytes
	 * given to us to "bytes_alignment", increasing the num_bytes value.
	 */

	new_size = old_size + chain_padding + 1 + wct * sizeof(uint16_t) + 2;

	if ((bytes_alignment != 0) && ((new_size % bytes_alignment) != 0)) {
		bytes_padding = bytes_alignment - (new_size % bytes_alignment);
	}

	new_size += bytes_padding + num_bytes;

	if ((smb_command != SMBwriteX) && (new_size > 0xffff)) {
		DEBUG(1, ("splice_chain: %u bytes won't fit\n",
			  (unsigned)new_size));
		return false;
	}

	outbuf = TALLOC_REALLOC_ARRAY(NULL, *poutbuf, uint8_t, new_size);
	if (outbuf == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return false;
	}
	*poutbuf = outbuf;

	if (first_request) {
		SCVAL(outbuf, smb_com, smb_command);
	} else {
		size_t andx_cmd_ofs;

		if (!find_andx_cmd_ofs(outbuf, &andx_cmd_ofs)) {
			DEBUG(1, ("invalid command chain\n"));
			*poutbuf = TALLOC_REALLOC_ARRAY(
				NULL, *poutbuf, uint8_t, old_size);
			return false;
		}

		if (chain_padding != 0) {
			memset(outbuf + old_size, 0, chain_padding);
			old_size += chain_padding;
		}

		SCVAL(outbuf, andx_cmd_ofs, smb_command);
		SSVAL(outbuf, andx_cmd_ofs + 2, old_size - 4);
	}

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
	ofs += sizeof(uint16_t) * wct;

	/*
	 * bcc (byte count)
	 */

	SSVAL(outbuf, ofs, num_bytes + bytes_padding);
	ofs += sizeof(uint16_t);

	/*
	 * padding
	 */

	if (bytes_padding != 0) {
		memset(outbuf + ofs, 0, bytes_padding);
		ofs += bytes_padding;
	}

	/*
	 * The bytes field
	 */

	memcpy(outbuf + ofs, bytes, num_bytes);

	return true;
}

/**
 * @brief Destroy an async_req that is the visible part of a cli_request
 * @param[in] req	The request to kill
 * @retval Return 0 to make talloc happy
 *
 * This destructor is a bit tricky: Because a cli_request can host more than
 * one async_req for chained requests, we need to make sure that the
 * "cli_request" that we were part of is correctly destroyed at the right
 * time. This is done by NULLing out ourself from the "async" member of our
 * "cli_request". If there is none left, then also TALLOC_FREE() the
 * cli_request, which was a talloc child of the client connection cli_state.
 */

static int cli_async_req_destructor(struct async_req *req)
{
	struct cli_request *cli_req = talloc_get_type_abort(
		req->private_data, struct cli_request);
	int i, pending;
	bool found = false;

	pending = 0;

	for (i=0; i<cli_req->num_async; i++) {
		if (cli_req->async[i] == req) {
			cli_req->async[i] = NULL;
			found = true;
		}
		if (cli_req->async[i] != NULL) {
			pending += 1;
		}
	}

	SMB_ASSERT(found);

	if (pending == 0) {
		TALLOC_FREE(cli_req);
	}

	return 0;
}

/**
 * @brief Chain up a request
 * @param[in] mem_ctx		The TALLOC_CTX for the result
 * @param[in] ev		The event context that will call us back
 * @param[in] cli		The cli_state we queue the request up for
 * @param[in] smb_command	The command that we want to issue
 * @param[in] additional_flags	open_and_x wants to add oplock header flags
 * @param[in] wct		How many words?
 * @param[in] vwv		The words, already in network order
 * @param[in] bytes_alignment	How shall we align "bytes"?
 * @param[in] num_bytes		How many bytes?
 * @param[in] bytes		The data the request ships
 *
 * cli_request_chain() is the core of the SMB request marshalling routine. It
 * will create a new async_req structure in the cli->chain_accumulator->async
 * array and marshall the smb_cmd, the vwv array and the bytes into
 * cli->chain_accumulator->outbuf.
 */

static struct async_req *cli_request_chain(TALLOC_CTX *mem_ctx,
					   struct event_context *ev,
					   struct cli_state *cli,
					   uint8_t smb_command,
					   uint8_t additional_flags,
					   uint8_t wct, const uint16_t *vwv,
					   size_t bytes_alignment,
					   uint32_t num_bytes,
					   const uint8_t *bytes)
{
	struct async_req **tmp_reqs;
	struct cli_request *req;

	req = cli->chain_accumulator;

	tmp_reqs = TALLOC_REALLOC_ARRAY(req, req->async, struct async_req *,
					req->num_async + 1);
	if (tmp_reqs == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}
	req->async = tmp_reqs;
	req->num_async += 1;

	req->async[req->num_async-1] = async_req_new(mem_ctx);
	if (req->async[req->num_async-1] == NULL) {
		DEBUG(0, ("async_req_new failed\n"));
		req->num_async -= 1;
		return NULL;
	}
	req->async[req->num_async-1]->private_data = req;
	req->async[req->num_async-1]->print = cli_request_print;
	talloc_set_destructor(req->async[req->num_async-1],
			      cli_async_req_destructor);

	if (!smb_splice_chain(&req->outbuf, smb_command, wct, vwv,
			      bytes_alignment, num_bytes, bytes)) {
		goto fail;
	}

	return req->async[req->num_async-1];

 fail:
	TALLOC_FREE(req->async[req->num_async-1]);
	req->num_async -= 1;
	return NULL;
}

/**
 * @brief prepare a cli_state to accept a chain of requests
 * @param[in] cli	The cli_state we want to queue up in
 * @param[in] ev	The event_context that will call us back for the socket
 * @param[in] size_hint	How many bytes are expected, just an optimization
 * @retval Did we have enough memory?
 *
 * cli_chain_cork() sets up a new cli_request in cli->chain_accumulator. If
 * cli is used in an async fashion, i.e. if we have outstanding requests, then
 * we do not have to create a fd event. If cli is used only with the sync
 * helpers, we need to create the fd_event here.
 *
 * If you want to issue a chained request to the server, do a
 * cli_chain_cork(), then do you cli_open_send(), cli_read_and_x_send(),
 * cli_close_send() and so on. The async requests that come out of
 * cli_xxx_send() are normal async requests with the difference that they
 * won't be shipped individually. But the event_context will still trigger the
 * req->async.fn to be called on every single request.
 *
 * You have to take care yourself that you only issue chainable requests in
 * the middle of the chain.
 */

bool cli_chain_cork(struct cli_state *cli, struct event_context *ev,
		    size_t size_hint)
{
	struct cli_request *req = NULL;

	SMB_ASSERT(cli->chain_accumulator == NULL);

	if (cli->fd == -1) {
		DEBUG(10, ("cli->fd closed\n"));
		return false;
	}

	if (cli->fd_event == NULL) {
		SMB_ASSERT(cli->outstanding_requests == NULL);
		cli->fd_event = event_add_fd(ev, cli, cli->fd,
					     EVENT_FD_READ,
					     cli_state_handler, cli);
		if (cli->fd_event == NULL) {
			return false;
		}
	}

	req = talloc(cli, struct cli_request);
	if (req == NULL) {
		goto fail;
	}
	req->cli = cli;

	if (size_hint == 0) {
		size_hint = 100;
	}
	req->outbuf = talloc_array(req, uint8_t, smb_wct + size_hint);
	if (req->outbuf == NULL) {
		goto fail;
	}
	req->outbuf = TALLOC_REALLOC_ARRAY(NULL, req->outbuf, uint8_t,
					   smb_wct);

	req->num_async = 0;
	req->async = NULL;

	req->enc_state = NULL;
	req->recv_helper.fn = NULL;

	SSVAL(req->outbuf, smb_tid, cli->cnum);
	cli_setup_packet_buf(cli, (char *)req->outbuf);

	req->mid = cli_new_mid(cli);

	cli->chain_accumulator = req;

	DEBUG(10, ("cli_chain_cork: mid=%d\n", req->mid));

	return true;
 fail:
	TALLOC_FREE(req);
	if (cli->outstanding_requests == NULL) {
		TALLOC_FREE(cli->fd_event);
	}
	return false;
}

/**
 * Ship a request queued up via cli_request_chain()
 * @param[in] cl	The connection
 */

void cli_chain_uncork(struct cli_state *cli)
{
	struct cli_request *req = cli->chain_accumulator;
	size_t smblen;

	SMB_ASSERT(req != NULL);

	DLIST_ADD_END(cli->outstanding_requests, req, struct cli_request *);
	talloc_set_destructor(req, cli_request_destructor);

	cli->chain_accumulator = NULL;

	SSVAL(req->outbuf, smb_mid, req->mid);

	smblen = talloc_get_size(req->outbuf) - 4;

	smb_setlen((char *)req->outbuf, smblen);

	if (smblen > 0x1ffff) {
		/*
		 * This is a POSIX 14 word large write. Overwrite just the
		 * size field, the '0xFFSMB' has been set by smb_setlen which
		 * _smb_setlen_large does not do.
		 */
		_smb_setlen_large(((char *)req->outbuf), smblen);
	}

	cli_calculate_sign_mac(cli, (char *)req->outbuf);

	if (cli_encryption_on(cli)) {
		NTSTATUS status;
		char *enc_buf;

		status = cli_encrypt_message(cli, (char *)req->outbuf,
					     &enc_buf);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Error in encrypting client message. "
				  "Error %s\n",	nt_errstr(status)));
			TALLOC_FREE(req);
			return;
		}
		req->outbuf = (uint8_t *)enc_buf;
		req->enc_state = cli->trans_enc_state;
	}

	req->sent = 0;

	event_fd_set_writeable(cli->fd_event);
}

/**
 * @brief Send a request to the server
 * @param[in] mem_ctx		The TALLOC_CTX for the result
 * @param[in] ev		The event context that will call us back
 * @param[in] cli		The cli_state we queue the request up for
 * @param[in] smb_command	The command that we want to issue
 * @param[in] additional_flags	open_and_x wants to add oplock header flags
 * @param[in] wct		How many words?
 * @param[in] vwv		The words, already in network order
 * @param[in] bytes_alignment	How shall we align "bytes"?
 * @param[in] num_bytes		How many bytes?
 * @param[in] bytes		The data the request ships
 *
 * This is the generic routine to be used by the cli_xxx_send routines.
 */

struct async_req *cli_request_send(TALLOC_CTX *mem_ctx,
				   struct event_context *ev,
				   struct cli_state *cli,
				   uint8_t smb_command,
				   uint8_t additional_flags,
				   uint8_t wct, const uint16_t *vwv,
				   size_t bytes_alignment,
				   uint32_t num_bytes, const uint8_t *bytes)
{
	struct async_req *result;
	bool uncork = false;

	if (cli->chain_accumulator == NULL) {
		if (!cli_chain_cork(cli, ev,
				    wct * sizeof(uint16_t) + num_bytes + 3)) {
			DEBUG(1, ("cli_chain_cork failed\n"));
			return NULL;
		}
		uncork = true;
	}

	result = cli_request_chain(mem_ctx, ev, cli, smb_command,
				   additional_flags, wct, vwv, bytes_alignment,
				   num_bytes, bytes);

	if (result == NULL) {
		DEBUG(1, ("cli_request_chain failed\n"));
	}

	if (uncork) {
		cli_chain_uncork(cli);
	}

	return result;
}

/**
 * Calculate the current ofs to wct for requests like write&x
 * @param[in] req	The smb request we're currently building
 * @retval how many bytes offset have we accumulated?
 */

uint16_t cli_wct_ofs(const struct cli_state *cli)
{
	size_t buf_size;

	if (cli->chain_accumulator == NULL) {
		return smb_wct - 4;
	}

	buf_size = talloc_get_size(cli->chain_accumulator->outbuf);

	if (buf_size == smb_wct) {
		return smb_wct - 4;
	}

	/*
	 * Add alignment for subsequent requests
	 */

	if ((buf_size % 4) != 0) {
		buf_size += (4 - (buf_size % 4));
	}

	return buf_size - 4;
}

/**
 * Figure out if there is an andx command behind the current one
 * @param[in] buf	The smb buffer to look at
 * @param[in] ofs	The offset to the wct field that is followed by the cmd
 * @retval Is there a command following?
 */

static bool have_andx_command(const char *buf, uint16_t ofs)
{
	uint8_t wct;
	size_t buflen = talloc_get_size(buf);

	if ((ofs == buflen-1) || (ofs == buflen)) {
		return false;
	}

	wct = CVAL(buf, ofs);
	if (wct < 2) {
		/*
		 * Not enough space for the command and a following pointer
		 */
		return false;
	}
	return (CVAL(buf, ofs+1) != 0xff);
}

/**
 * @brief Pull reply data out of a request
 * @param[in] req		The request that we just received a reply for
 * @param[out] pwct		How many words did the server send?
 * @param[out] pvwv		The words themselves
 * @param[out] pnum_bytes	How many bytes did the server send?
 * @param[out] pbytes		The bytes themselves
 * @retval Was the reply formally correct?
 */

NTSTATUS cli_pull_reply(struct async_req *req,
			uint8_t *pwct, uint16_t **pvwv,
			uint16_t *pnum_bytes, uint8_t **pbytes)
{
	struct cli_request *cli_req = talloc_get_type_abort(
		req->private_data, struct cli_request);
	uint8_t wct, cmd;
	uint16_t num_bytes;
	size_t wct_ofs, bytes_offset;
	int i, j;
	NTSTATUS status;

	for (i = 0; i < cli_req->num_async; i++) {
		if (req == cli_req->async[i]) {
			break;
		}
	}

	if (i == cli_req->num_async) {
		cli_set_error(cli_req->cli, NT_STATUS_INVALID_PARAMETER);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/**
	 * The status we pull here is only relevant for the last reply in the
	 * chain.
	 */

	status = cli_pull_error(cli_req->inbuf);

	if (i == 0) {
		if (NT_STATUS_IS_ERR(status)
		    && !have_andx_command(cli_req->inbuf, smb_wct)) {
			cli_set_error(cli_req->cli, status);
			return status;
		}
		wct_ofs = smb_wct;
		goto done;
	}

	cmd = CVAL(cli_req->inbuf, smb_com);
	wct_ofs = smb_wct;

	for (j = 0; j < i; j++) {
		if (j < i-1) {
			if (cmd == 0xff) {
				return NT_STATUS_REQUEST_ABORTED;
			}
			if (!is_andx_req(cmd)) {
				return NT_STATUS_INVALID_NETWORK_RESPONSE;
			}
		}

		if (!have_andx_command(cli_req->inbuf, wct_ofs)) {
			/*
			 * This request was not completed because a previous
			 * request in the chain had received an error.
			 */
			return NT_STATUS_REQUEST_ABORTED;
		}

		wct_ofs = SVAL(cli_req->inbuf, wct_ofs + 3);

		/*
		 * Skip the all-present length field. No overflow, we've just
		 * put a 16-bit value into a size_t.
		 */
		wct_ofs += 4;

		if (wct_ofs+2 > talloc_get_size(cli_req->inbuf)) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}

		cmd = CVAL(cli_req->inbuf, wct_ofs + 1);
	}

	if (!have_andx_command(cli_req->inbuf, wct_ofs)
	    && NT_STATUS_IS_ERR(status)) {
		/*
		 * The last command takes the error code. All further commands
		 * down the requested chain will get a
		 * NT_STATUS_REQUEST_ABORTED.
		 */
		return status;
	}

 done:
	wct = CVAL(cli_req->inbuf, wct_ofs);

	bytes_offset = wct_ofs + 1 + wct * sizeof(uint16_t);
	num_bytes = SVAL(cli_req->inbuf, bytes_offset);

	/*
	 * wct_ofs is a 16-bit value plus 4, wct is a 8-bit value, num_bytes
	 * is a 16-bit value. So bytes_offset being size_t should be far from
	 * wrapping.
	 */

	if ((bytes_offset + 2 > talloc_get_size(cli_req->inbuf))
	    || (bytes_offset > 0xffff)) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	*pwct = wct;
	*pvwv = (uint16_t *)(cli_req->inbuf + wct_ofs + 1);
	*pnum_bytes = num_bytes;
	*pbytes = (uint8_t *)cli_req->inbuf + bytes_offset + 2;

	return NT_STATUS_OK;
}

/**
 * Decrypt a PDU, check the signature
 * @param[in] cli	The cli_state that received something
 * @param[in] pdu	The incoming bytes
 * @retval error code
 */


static NTSTATUS validate_smb_crypto(struct cli_state *cli, char *pdu)
{
	NTSTATUS status;

	if ((IVAL(pdu, 4) != 0x424d53ff) /* 0xFF"SMB" */
	    && (SVAL(pdu, 4) != 0x45ff)) /* 0xFF"E" */ {
		DEBUG(10, ("Got non-SMB PDU\n"));
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (cli_encryption_on(cli) && CVAL(pdu, 0) == 0) {
		uint16_t enc_ctx_num;

		status = get_enc_ctx_num((uint8_t *)pdu, &enc_ctx_num);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("get_enc_ctx_num returned %s\n",
				   nt_errstr(status)));
			return status;
		}

		if (enc_ctx_num != cli->trans_enc_state->enc_ctx_num) {
			DEBUG(10, ("wrong enc_ctx %d, expected %d\n",
				   enc_ctx_num,
				   cli->trans_enc_state->enc_ctx_num));
			return NT_STATUS_INVALID_HANDLE;
		}

		status = common_decrypt_buffer(cli->trans_enc_state, pdu);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("common_decrypt_buffer returned %s\n",
				   nt_errstr(status)));
			return status;
		}
	}

	if (!cli_check_sign_mac(cli, pdu)) {
		DEBUG(10, ("cli_check_sign_mac failed\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

/**
 * A PDU has arrived on cli->evt_inbuf
 * @param[in] cli	The cli_state that received something
 */

static void handle_incoming_pdu(struct cli_state *cli)
{
	struct cli_request *req, *next;
	uint16_t mid;
	size_t raw_pdu_len, buf_len, pdu_len, rest_len;
	char *pdu;
	int i;
	NTSTATUS status;

	int num_async;

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

	status = validate_smb_crypto(cli, pdu);
	if (!NT_STATUS_IS_OK(status)) {
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

	/*
	 * Freeing the last async_req will free the req (see
	 * cli_async_req_destructor). So make a copy of req->num_async, we
	 * can't reference it in the last round.
	 */

	num_async = req->num_async;

	for (i=0; i<num_async; i++) {
		/**
		 * A request might have been talloc_free()'ed before we arrive
		 * here. It will have removed itself from req->async via its
		 * destructor cli_async_req_destructor().
		 */
		if (req->async[i] != NULL) {
			if (req->recv_helper.fn != NULL) {
				req->recv_helper.fn(req->async[i]);
			} else {
				async_req_done(req->async[i]);
			}
		}
	}
	return;

 invalidate_requests:

	DEBUG(10, ("handle_incoming_pdu: Aborting with %s\n",
		   nt_errstr(status)));

	for (req = cli->outstanding_requests; req; req = next) {
		next = req->next;
		if (req->num_async) {
			async_req_nterror(req->async[0], status);
		}
	}
	return;
}

/**
 * fd event callback. This is the basic connection to the socket
 * @param[in] event_ctx	The event context that called us
 * @param[in] event	The event that fired
 * @param[in] flags	EVENT_FD_READ | EVENT_FD_WRITE
 * @param[in] p		private_data, in this case the cli_state
 */

static void cli_state_handler(struct event_context *event_ctx,
			      struct fd_event *event, uint16 flags, void *p)
{
	struct cli_state *cli = (struct cli_state *)p;
	struct cli_request *req, *next;
	NTSTATUS status;

	DEBUG(11, ("cli_state_handler called with flags %d\n", flags));

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
			if (cli->fd_event != NULL) {
				event_fd_set_not_writeable(cli->fd_event);
			}
			return;
		}

		sent = sys_send(cli->fd, req->outbuf + req->sent,
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

		res = sys_recv(cli->fd, cli->evt_inbuf + old_size, available, 0);
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

	return;

 sock_error:

	for (req = cli->outstanding_requests; req; req = next) {
		int i, num_async;

		next = req->next;
		num_async = req->num_async;

		for (i=0; i<num_async; i++) {
			async_req_nterror(req->async[i], status);
		}
	}
	TALLOC_FREE(cli->fd_event);
	close(cli->fd);
	cli->fd = -1;
}
