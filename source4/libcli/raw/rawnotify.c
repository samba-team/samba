/* 
   Unix SMB/CIFS implementation.
   client change notify operations
   Copyright (C) Andrew Tridgell 2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/****************************************************************************
change notify (async send)
****************************************************************************/
struct cli_request *smb_raw_changenotify_send(struct cli_tree *tree, struct smb_notify *parms)
{
	struct smb_nttrans nt;
	uint16_t setup[4];

	nt.in.max_setup = 0;
	nt.in.max_param = parms->in.buffer_size;
	nt.in.max_data = 0;
	nt.in.setup_count = 4;
	nt.in.setup = setup;
	SIVAL(setup, 0, parms->in.completion_filter);
	SSVAL(setup, 4, parms->in.fnum);
	SSVAL(setup, 6, parms->in.recursive);	
	nt.in.function = NT_TRANSACT_NOTIFY_CHANGE;
	nt.in.params = data_blob(NULL, 0);
	nt.in.data = data_blob(NULL, 0);

	return smb_raw_nttrans_send(tree, &nt);
}

/****************************************************************************
change notify (async recv)
****************************************************************************/
NTSTATUS smb_raw_changenotify_recv(struct cli_request *req, 
				   TALLOC_CTX *mem_ctx, struct smb_notify *parms)
{
	struct smb_nttrans nt;
	NTSTATUS status;
	uint32_t ofs, i;
	struct cli_session *session = req?req->session:NULL;

	status = smb_raw_nttrans_recv(req, mem_ctx, &nt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	parms->out.changes = NULL;
	parms->out.num_changes = 0;
	
	/* count them */
	for (ofs=0; nt.out.params.length - ofs > 12; ) {
		uint32_t next = IVAL(nt.out.params.data, ofs);
		parms->out.num_changes++;
		if (next == 0 ||
		    ofs + next >= nt.out.params.length) break;
		ofs += next;
	}

	/* allocate array */
	parms->out.changes = talloc(mem_ctx, sizeof(parms->out.changes[0]) * 
				    parms->out.num_changes);
	if (!parms->out.changes) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=ofs=0; i<parms->out.num_changes; i++) {
		parms->out.changes[i].action = IVAL(nt.out.params.data, ofs+4);
		cli_blob_pull_string(session, mem_ctx, &nt.out.params, 
				     &parms->out.changes[i].name, 
				     ofs+8, ofs+12, STR_UNICODE);
		ofs += IVAL(nt.out.params.data, ofs);
	}

	return NT_STATUS_OK;
}


/****************************************************************************
 Send a NT Cancel request - used to hurry along a pending request. Usually
 used to cancel a pending change notify request
 note that this request does not expect a response!
****************************************************************************/
NTSTATUS smb_raw_ntcancel(struct cli_request *oldreq)
{
	struct cli_request *req;

	req = cli_request_setup_transport(oldreq->transport, SMBntcancel, 0, 0);

	SSVAL(req->out.hdr, HDR_MID, SVAL(oldreq->out.hdr, HDR_MID));	
	SSVAL(req->out.hdr, HDR_PID, SVAL(oldreq->out.hdr, HDR_PID));	
	SSVAL(req->out.hdr, HDR_TID, SVAL(oldreq->out.hdr, HDR_TID));	
	SSVAL(req->out.hdr, HDR_UID, SVAL(oldreq->out.hdr, HDR_UID));	

	/* this request does not expect a reply, so tell the signing
	   subsystem not to allocate an id for a reply */
	req->sign_single_increment = 1;
	req->one_way_request = 1;

	cli_request_send(req);

	return NT_STATUS_OK;
}
