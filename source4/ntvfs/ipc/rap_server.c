/* 
   Unix SMB/CIFS implementation.
   RAP handlers

   Copyright (C) Volker Lendecke 2004

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

/* At this moment these are just dummy functions, but you might get the
 * idea. */

NTSTATUS rap_netshareenum(struct smbsrv_request *req,
			  struct rap_NetShareEnum *r)
{
	r->out.status = 0;
	r->out.available = 2;
	r->out.info = talloc_array_p(req,
				     union rap_shareenum_info, 2);

	strncpy(r->out.info[0].info1.name, "C$", sizeof(r->out.info[0].info1.name));
	r->out.info[0].info1.pad = 0;
	r->out.info[0].info1.type = 0;
	r->out.info[0].info1.comment = talloc_strdup(req, "Bla");
	
	strncpy(r->out.info[1].info1.name, "IPC$", sizeof(r->out.info[0].info1.name));
	r->out.info[1].info1.pad = 0;
	r->out.info[1].info1.type = 1;
	r->out.info[1].info1.comment = talloc_strdup(req, "Blub");
	
	return NT_STATUS_OK;
}

NTSTATUS rap_netserverenum2(struct smbsrv_request *req,
				   struct rap_NetServerEnum2 *r)
{
	r->out.status = 0;
	r->out.available = 0;
	return NT_STATUS_OK;
}
