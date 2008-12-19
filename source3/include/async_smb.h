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

#ifndef __ASYNC_SMB_H__
#define __ASYNC_SMB_H__

#include "includes.h"

/**
 * struct cli_request is the state holder for an async client request we sent
 * to the server. It can consist of more than one struct async_req that we
 * have to server if the application did a cli_chain_cork() and
 * cli_chain_uncork()
 */

struct cli_request {
	/**
	 * "prev" and "next" form the doubly linked list in
	 * cli_state->outstanding_requests
	 */
	struct cli_request *prev, *next;

	/**
	 * num_async: How many chained requests do we serve?
	 */
	int num_async;

	/**
	 * async: This is the list of chained requests that were queued up by
	 * cli_request_chain before we sent out this request
	 */
	struct async_req **async;

	/**
	 * The client connection for this request
	 */
	struct cli_state *cli;

	/**
	 * The enc_state to decrypt the reply
	 */
	struct smb_trans_enc_state *enc_state;

	/**
	 * The mid we used for this request. Mainly used to demultiplex on
	 * receiving replies.
	 */
	uint16_t mid;

	/**
	 * The bytes we have to ship to the server
	 */
	uint8_t *outbuf;

	/**
	 * How much from "outbuf" did we already send
	 */
	size_t sent;

	/**
	 * The reply comes in here. Its intended size is implicit by
	 * smb_len(), its current size can be read via talloc_get_size()
	 */
	char *inbuf;

	/**
	 * Specific requests might add stuff here. Maybe convert this to a
	 * private_pointer at some point.
	 */
	union {
		struct {
			off_t ofs;
			size_t size;
			ssize_t received;
			uint8_t *rcvbuf;
		} read;
		struct {
			DATA_BLOB data;
			uint16_t num_echos;
		} echo;
	} data;

	/**
	 * For requests that don't follow the strict request/reply pattern
	 * such as the transaction request family and echo requests it is
	 * necessary to break the standard procedure in
	 * handle_incoming_pdu(). For a simple example look at
	 * cli_echo_recv_helper().
	 */
	struct {
		void (*fn)(struct async_req *req);
		void *priv;
	} recv_helper;
};

/*
 * Ship a new smb request to the server
 */

struct async_req *cli_request_send(TALLOC_CTX *mem_ctx,
				   struct event_context *ev,
				   struct cli_state *cli,
				   uint8_t smb_command,
				   uint8_t additional_flags,
				   uint8_t wct, const uint16_t *vwv,
				   size_t bytes_alignment,
				   uint32_t num_bytes, const uint8_t *bytes);

uint16_t cli_wct_ofs(const struct cli_state *cli);

bool cli_chain_cork(struct cli_state *cli, struct event_context *ev,
		    size_t size_hint);
void cli_chain_uncork(struct cli_state *cli);
bool cli_in_chain(struct cli_state *cli);
bool smb_splice_chain(uint8_t **poutbuf, uint8_t smb_command,
		      uint8_t wct, const uint16_t *vwv,
		      size_t bytes_alignment,
		      uint32_t num_bytes, const uint8_t *bytes);

NTSTATUS cli_pull_reply(struct async_req *req,
			uint8_t *pwct, uint16_t **pvwv,
			uint16_t *pnum_bytes, uint8_t **pbytes);

/*
 * Fetch an error out of a NBT packet
 */

NTSTATUS cli_pull_error(char *buf);

/*
 * Compatibility helper for the sync APIs: Fake NTSTATUS in cli->inbuf
 */

void cli_set_error(struct cli_state *cli, NTSTATUS status);

#endif
