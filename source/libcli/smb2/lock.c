/* 
   Unix SMB/CIFS implementation.

   SMB2 client lock handling

   Copyright (C) Stefan Metzmacher 2006
   
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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"

/*
  send a lock request
*/
struct smb2_request *smb2_lock_send(struct smb2_tree *tree, struct smb2_lock *io)
{
	struct smb2_request *req;

	req = smb2_request_init_tree(tree, SMB2_OP_LOCK, 0x30, False, 0);
	if (req == NULL) return NULL;

	SSVAL(req->out.body, 0x02, io->in.unknown1);
	SIVAL(req->out.body, 0x04, io->in.unknown2);
	smb2_push_handle(req->out.body+0x08, &io->in.file.handle);
	SBVAL(req->out.body, 0x18, io->in.offset);
	SBVAL(req->out.body, 0x20, io->in.count);
	SIVAL(req->out.body, 0x24, io->in.unknown5);
	SIVAL(req->out.body, 0x28, io->in.flags);

	smb2_transport_send(req);

	return req;
}


/*
  recv a lock reply
*/
NTSTATUS smb2_lock_recv(struct smb2_request *req, struct smb2_lock *io)
{
	if (!smb2_request_receive(req) || 
	    smb2_request_is_error(req)) {
		return smb2_request_destroy(req);
	}

	SMB2_CHECK_PACKET_RECV(req, 0x04, False);

	io->out.unknown1 = SVAL(req->in.body, 0x02);

	return smb2_request_destroy(req);
}

/*
  sync lock request
*/
NTSTATUS smb2_lock(struct smb2_tree *tree, struct smb2_lock *io)
{
	struct smb2_request *req = smb2_lock_send(tree, io);
	return smb2_lock_recv(req, io);
}
