/* 
   Unix SMB2 implementation.
   
   Copyright (C) Stefan Metzmacher            2005
   
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

/* the context for a single SMB2 request. This is passed to any request-context 
   functions */
struct smb2srv_request {
	/* the smbsrv_connection needs a list of requests queued for send */
	struct smb2srv_request *next, *prev;

	/* the server_context contains all context specific to this SMB socket */
	struct smbsrv_connection *smb_conn;

	/* the smbsrv_session for the request */
	struct smbsrv_session *session;

	/* the smbsrv_tcon for the request */
	struct smbsrv_tcon *tcon;

	/* the system time when the request arrived */
	struct timeval request_time;

	/* for matching request and reply */
	uint64_t seqnum;

	/* the status the backend returned */
	NTSTATUS status;

#define SMB2SRV_REQ_CTRL_FLAG_NOT_REPLY (1<<0)
	uint32_t control_flags;

	struct smb2_request_buffer in;
	struct smb2_request_buffer out;
};

#include "smb_server/smb2/smb2_proto.h"
