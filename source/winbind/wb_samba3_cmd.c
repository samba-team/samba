/* 
   Unix SMB/CIFS implementation.
   Main winbindd samba3 server routines

   Copyright (C) Stefan Metzmacher	2005
   Copyright (C) Volker Lendecke	2005

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
#include "smbd/service_stream.h"
#include "nsswitch/winbind_nss_config.h"
#include "nsswitch/winbindd_nss.h"
#include "winbind/wb_server.h"
#include "winbind/wb_samba3_protocol.h"

NTSTATUS wbsrv_samba3_interface_version(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	s3call->response.data.interface_version	= WINBIND_INTERFACE_VERSION;
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_priv_pipe_dir(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	s3call->response.extra_data		= smbd_tmp_path(s3call,
						  WINBINDD_SAMBA3_PRIVILEGED_SOCKET);
	NT_STATUS_HAVE_NO_MEMORY(s3call->response.extra_data);
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_ping(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	return NT_STATUS_OK;
}
