/* 
   Unix SMB/CIFS implementation.
   LDAP server
   Copyright (C) Stefan Metzmacher 2004
   
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


NTSTATUS ldapsrv_BindRequest(struct ldapsrv_call *call)
{
	struct ldap_BindRequest *req = &call->request.r.BindRequest;
	struct ldapsrv_reply *reply;
	struct ldap_BindResponse *resp;

	DEBUG(10, ("BindRequest dn: %s\n",req->dn));

	reply = ldapsrv_init_reply(call, LDAP_TAG_BindResponse);
	if (!reply) {
		return NT_STATUS_NO_MEMORY;
	}

	resp = &reply->msg.r.BindResponse;
	resp->response.resultcode = 0;
	resp->response.dn = NULL;
	resp->response.errormessage = NULL;
	resp->response.referral = NULL;
	resp->SASL.secblob = data_blob(NULL, 0);

	return ldapsrv_queue_reply(call, reply);
}

NTSTATUS ldapsrv_UnbindRequest(struct ldapsrv_call *call)
{
/*	struct ldap_UnbindRequest *req = &call->request->r.UnbindRequest;*/
	DEBUG(10, ("UnbindRequest\n"));
	return NT_STATUS_OK;
}
