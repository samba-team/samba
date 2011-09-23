/* 
   Unix SMB/CIFS implementation.
   client change notify operations
   Copyright (C) Andrew Tridgell 2003
   
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
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"

/****************************************************************************
change notify (async send)
****************************************************************************/
_PUBLIC_ struct smbcli_request *smb_raw_changenotify_send(struct smbcli_tree *tree, union smb_notify *parms)
{
	struct smb_nttrans nt;
	uint8_t setup[8];

	if (parms->nttrans.level != RAW_NOTIFY_NTTRANS) {
		return NULL;
	}

	nt.in.max_setup = 0;
	nt.in.max_param = parms->nttrans.in.buffer_size;
	nt.in.max_data = 0;
	nt.in.setup_count = 4;
	nt.in.setup = setup;
	SIVAL(setup, 0, parms->nttrans.in.completion_filter);
	SSVAL(setup, 4, parms->nttrans.in.file.fnum);
	SSVAL(setup, 6, parms->nttrans.in.recursive);	
	nt.in.function = NT_TRANSACT_NOTIFY_CHANGE;
	nt.in.params = data_blob(NULL, 0);
	nt.in.data = data_blob(NULL, 0);

	return smb_raw_nttrans_send(tree, &nt);
}

/****************************************************************************
change notify (async recv)
****************************************************************************/
_PUBLIC_ NTSTATUS smb_raw_changenotify_recv(struct smbcli_request *req, 
				   TALLOC_CTX *mem_ctx, union smb_notify *parms)
{
	struct smb_nttrans nt;
	NTSTATUS status;
	uint32_t ofs, i;
	struct smbcli_session *session = req?req->session:NULL;

	if (parms->nttrans.level != RAW_NOTIFY_NTTRANS) {
		return NT_STATUS_INVALID_LEVEL;
	}

	status = smb_raw_nttrans_recv(req, mem_ctx, &nt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	parms->nttrans.out.changes = NULL;
	parms->nttrans.out.num_changes = 0;

	/* count them */
	for (ofs=0; nt.out.params.length - ofs > 12; ) {
		uint32_t next = IVAL(nt.out.params.data, ofs);
		if (next % 4 != 0)
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		parms->nttrans.out.num_changes++;
		if (next == 0 ||
		    ofs + next >= nt.out.params.length) break;
		ofs += next;
	}

	/* allocate array */
	parms->nttrans.out.changes = talloc_array(mem_ctx, struct notify_changes, parms->nttrans.out.num_changes);
	if (!parms->nttrans.out.changes) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=ofs=0; i<parms->nttrans.out.num_changes; i++) {
		parms->nttrans.out.changes[i].action = IVAL(nt.out.params.data, ofs+4);
		smbcli_blob_pull_string(session, mem_ctx, &nt.out.params, 
					&parms->nttrans.out.changes[i].name, 
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
NTSTATUS smb_raw_ntcancel(struct smbcli_request *oldreq)
{
	bool ok;

	if (oldreq->subreqs[0] == NULL) {
		return NT_STATUS_OK;
	}

	ok = tevent_req_cancel(oldreq->subreqs[0]);
	if (!ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	return NT_STATUS_OK;
}
