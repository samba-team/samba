/* 
   Unix SMB2 implementation.
   
   Copyright (C) Stefan Metzmacher	2005
   
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
#include "libcli/smb2/smb2.h"
#include "smb_server/smb2/smb2_server.h"

void smb2srv_create_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_close_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_flush_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_read_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_write_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_lock_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_ioctl_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_cancel_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_find_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_notify_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_getinfo_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_setinfo_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}

void smb2srv_break_recv(struct smb2srv_request *req)
{
	smb2srv_send_error(req, NT_STATUS_NOT_IMPLEMENTED);
}
