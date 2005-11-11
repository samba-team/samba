/* 
   Unix SMB/CIFS implementation.

   SMB2 client negprot handling

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/raw/libcliraw.h"
#include "libcli/smb2/smb2.h"

/*
  send a negprot request
*/
struct smb2_request *smb2_negprot_send(struct smb2_transport *transport)
{
	struct smb2_request *req;

	req = smb2_request_init(transport, SMB2_OP_NEGPROT, 0x26);
	if (req == NULL) return NULL;

	memset(req->out.body, 0, 0x26);
	SIVAL(req->out.body, 0, 0x00010024); /* unknown */

	smb2_transport_send(req);

	return req;
}

/*
  recv a negprot reply
*/
NTSTATUS smb2_negprot_recv(struct smb2_request *req)
{
	NTTIME t1, t2;
	DATA_BLOB secblob;
	struct GUID guid;
	NTSTATUS status;

	if (!smb2_request_receive(req) || 
	    smb2_request_is_error(req)) {
		return smb2_request_destroy(req);
	}

	t1 = smbcli_pull_nttime(req->in.body, 0x28);
	t2 = smbcli_pull_nttime(req->in.body, 0x30);

	secblob = smb2_pull_blob(req, req->in.body+0x40, req->in.body_size - 0x40);
	status  = smb2_pull_guid(req, req->in.body+0x08, &guid);
	NT_STATUS_NOT_OK_RETURN(status);

	printf("Negprot reply:\n");
	printf("t1  =%s\n", nt_time_string(req, t1));
	printf("t2  =%s\n", nt_time_string(req, t2));
	printf("guid=%s\n", GUID_string(req, &guid));

	return smb2_request_destroy(req);
}

/*
  sync negprot request
*/
NTSTATUS smb2_negprot(struct smb2_transport *transport)
{
	struct smb2_request *req = smb2_negprot_send(transport);
	return smb2_negprot_recv(req);
}
