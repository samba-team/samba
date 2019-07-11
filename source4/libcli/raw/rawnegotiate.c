/* 
   Unix SMB/CIFS implementation.

   SMB client negotiate context management functions

   Copyright (C) Andrew Tridgell 1994-2005
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   
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
#include <tevent.h>
#include "system/time.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "../libcli/smb/smbXcli_base.h"
#include "../lib/util/tevent_ntstatus.h"

NTSTATUS smb_raw_negotiate_fill_transport(struct smbcli_transport *transport)
{
	struct smbcli_negotiate *n = &transport->negotiate;
	struct smbXcli_conn *c = transport->conn;
	NTTIME ntt;

	n->protocol = smbXcli_conn_protocol(c);
	if (n->protocol > PROTOCOL_NT1) {
		return NT_STATUS_REVISION_MISMATCH;
	}

	n->sec_mode = smb1cli_conn_server_security_mode(c);
	n->max_mux  = smbXcli_conn_max_requests(c);
	n->max_xmit = smb1cli_conn_max_xmit(c);
	n->sesskey  = smb1cli_conn_server_session_key(c);
	n->capabilities = smb1cli_conn_capabilities(c);;

	/* this time arrives in real GMT */
	ntt = smbXcli_conn_server_system_time(c);
	n->server_time = nt_time_to_unix(ntt);
	n->server_zone = smb1cli_conn_server_time_zone(c);

	if (n->capabilities & CAP_EXTENDED_SECURITY) {
		const DATA_BLOB *b = smbXcli_conn_server_gss_blob(c);
		if (b) {
			n->secblob = *b;
		}
	} else {
		const uint8_t *p = smb1cli_conn_server_challenge(c);
		if (p) {
			n->secblob = data_blob_const(p, 8);
		}
	}

	n->readbraw_supported = smb1cli_conn_server_readbraw(c);
	n->readbraw_supported = smb1cli_conn_server_writebraw(c);
	n->lockread_supported = smb1cli_conn_server_lockread(c);

	return NT_STATUS_OK;
}

struct smb_raw_negotiate_state {
	struct smbcli_transport *transport;
};

static void smb_raw_negotiate_done(struct tevent_req *subreq);

struct tevent_req *smb_raw_negotiate_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct smbcli_transport *transport,
					  int minprotocol,
					  int maxprotocol)
{
	struct tevent_req *req;
	struct smb_raw_negotiate_state *state;
	struct tevent_req *subreq;
	uint32_t timeout_msec = transport->options.request_timeout * 1000;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_raw_negotiate_state);;
	if (req == NULL) {
		return NULL;
	}
	state->transport = transport;

	if (maxprotocol > PROTOCOL_NT1) {
		maxprotocol = PROTOCOL_NT1;
	}

	if (minprotocol > maxprotocol) {
		minprotocol = maxprotocol;
	}

	subreq = smbXcli_negprot_send(state, ev,
				      transport->conn,
				      timeout_msec,
				      minprotocol,
				      maxprotocol,
				      transport->options.max_credits);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb_raw_negotiate_done, req);

	return req;
}

static void smb_raw_negotiate_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb_raw_negotiate_state *state =
		tevent_req_data(req,
		struct smb_raw_negotiate_state);
	NTSTATUS status;

	status = smbXcli_negprot_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	status = smb_raw_negotiate_fill_transport(state->transport);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

/*
 Send a negprot command.
*/
NTSTATUS smb_raw_negotiate_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}


/*
 Send a negprot command (sync interface)
*/
NTSTATUS smb_raw_negotiate(struct smbcli_transport *transport, bool unicode,
			   int minprotocol, int maxprotocol)
{
	NTSTATUS status;
	struct tevent_req *subreq = NULL;
	bool ok;

	subreq = smb_raw_negotiate_send(transport,
					transport->ev,
					transport,
					minprotocol,
					maxprotocol);
	if (subreq == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	ok = tevent_req_poll(subreq, transport->ev);
	if (!ok) {
		status = map_nt_error_from_unix_common(errno);
		goto failed;
	}

	status = smb_raw_negotiate_recv(subreq);

failed:
	TALLOC_FREE(subreq);
	return status;
}
