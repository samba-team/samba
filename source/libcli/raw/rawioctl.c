/* 
   Unix SMB/CIFS implementation.
   client file operations
   Copyright (C) Andrew Tridgell 2003
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
   
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

#define SETUP_REQUEST(cmd, wct, buflen) do { \
	req = cli_request_setup(tree, cmd, wct, buflen); \
	if (!req) return NULL; \
} while (0)

/* 
   send a raw smb ioctl - async send
*/
static struct cli_request *smb_raw_smbioctl_send(struct cli_tree *tree, 
						 union smb_ioctl *parms)
{
	struct cli_request *req; 

	SETUP_REQUEST(SMBioctl, 3, 0);

	SSVAL(req->out.vwv, VWV(0), parms->ioctl.in.fnum);
	SIVAL(req->out.vwv, VWV(1), parms->ioctl.in.request);

	if (!cli_request_send(req)) {
		cli_request_destroy(req);
		return NULL;
	}

	return req;
}

/* 
   send a raw smb ioctl - async recv
*/
static NTSTATUS smb_raw_smbioctl_recv(struct cli_request *req, 
				      TALLOC_CTX *mem_ctx, 
				      union smb_ioctl *parms)
{
	if (!cli_request_receive(req) ||
	    cli_request_is_error(req)) {
		return cli_request_destroy(req);
	}

	parms->ioctl.out.blob = cli_req_pull_blob(req, mem_ctx, req->in.data, -1);
	return cli_request_destroy(req);
}



/****************************************************************************
NT ioctl (async send)
****************************************************************************/
static struct cli_request *smb_raw_ntioctl_send(struct cli_tree *tree, 
						union smb_ioctl *parms)
{
	struct smb_nttrans nt;
	uint16_t setup[4];

	nt.in.max_setup = 0;
	nt.in.max_param = 0;
	nt.in.max_data = 0;
	nt.in.setup_count = 4;
	nt.in.setup = setup;
	SIVAL(setup, 0, parms->ntioctl.in.function);
	SSVAL(setup, 4, parms->ntioctl.in.fnum);
	SCVAL(setup, 6, parms->ntioctl.in.fsctl);
	SCVAL(setup, 7, parms->ntioctl.in.filter);
	nt.in.function = NT_TRANSACT_IOCTL;
	nt.in.params = data_blob(NULL, 0);
	nt.in.data = data_blob(NULL, 0);

	return smb_raw_nttrans_send(tree, &nt);
}

/****************************************************************************
NT ioctl (async recv)
****************************************************************************/
static NTSTATUS smb_raw_ntioctl_recv(struct cli_request *req, 
				     TALLOC_CTX *mem_ctx,
				     union smb_ioctl *parms)
{
	if (!cli_request_receive(req) ||
	    cli_request_is_error(req)) {
		return cli_request_destroy(req);
	}

	parms->ntioctl.out.blob = cli_req_pull_blob(req, mem_ctx, req->in.data, -1);
	return cli_request_destroy(req);
}


/* 
   send a raw ioctl - async send
*/
struct cli_request *smb_raw_ioctl_send(struct cli_tree *tree, union smb_ioctl *parms)
{
	struct cli_request *req = NULL;
	
	switch (parms->generic.level) {
	case RAW_IOCTL_IOCTL:
		req = smb_raw_smbioctl_send(tree, parms);
		break;
		
	case RAW_IOCTL_NTIOCTL:
		req = smb_raw_ntioctl_send(tree, parms);
		break;
	}

	return req;
}

/* 
   recv a raw ioctl - async recv
*/
NTSTATUS smb_raw_ioctl_recv(struct cli_request *req,
			    TALLOC_CTX *mem_ctx, union smb_ioctl *parms)
{
	switch (parms->generic.level) {
	case RAW_IOCTL_IOCTL:
		return smb_raw_smbioctl_recv(req, mem_ctx, parms);
		
	case RAW_IOCTL_NTIOCTL:
		return smb_raw_ntioctl_recv(req, mem_ctx, parms);
	}
	return NT_STATUS_INVALID_LEVEL;
}

/* 
   send a raw ioctl - sync interface
*/
NTSTATUS smb_raw_ioctl(struct cli_tree *tree, 
		TALLOC_CTX *mem_ctx, union smb_ioctl *parms)
{
	struct cli_request *req;
	req = smb_raw_ioctl_send(tree, parms);
	return smb_raw_ioctl_recv(req, mem_ctx, parms);
}
