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


struct ldapsrv_reply *ldapsrv_init_reply(struct ldapsrv_call *call, enum ldap_request_tag type)
{
	struct ldapsrv_reply *reply;

	reply = talloc_p(call, struct ldapsrv_reply);
	if (!reply) {
		return NULL;
	}

	reply->prev = reply->next = NULL;
	reply->state = LDAPSRV_REPLY_STATE_NEW;
	reply->msg.messageid = call->request.messageid;
	reply->msg.type = type;
	reply->msg.mem_ctx = reply;

	return reply;
}

NTSTATUS ldapsrv_queue_reply(struct ldapsrv_call *call, struct ldapsrv_reply *reply)
{
	DLIST_ADD_END(call->replies, reply, struct ldapsrv_reply *);
	return NT_STATUS_OK;
}

struct ldapsrv_partition *ldapsrv_get_partition(struct ldapsrv_connection *conn, const char *dn)
{
	if (strcasecmp("", dn) == 0) {
		return conn->service->rootDSE;
	}

	return conn->service->default_partition;
}

NTSTATUS ldapsrv_unwilling(struct ldapsrv_call *call, int error)
{
	struct ldapsrv_reply *reply;
	struct ldap_ExtendedResponse *r;

	DEBUG(10,("Unwilling type[%d] id[%d]\n", call->request.type, call->request.messageid));

	reply = ldapsrv_init_reply(call, LDAP_TAG_ExtendedResponse);
	if (!reply) {
		return NT_STATUS_NO_MEMORY;
	}

	r = &reply->msg.r.ExtendedResponse;
	r->response.resultcode = error;
	r->response.dn = NULL;
	r->response.errormessage = NULL;
	r->response.referral = NULL;
	r->name = NULL;
	r->value.data = NULL;
	r->value.length = 0;

	return ldapsrv_queue_reply(call, reply);
}

static NTSTATUS ldapsrv_SearchRequest(struct ldapsrv_call *call)
{
	struct ldap_SearchRequest *req = &call->request.r.SearchRequest;
	struct ldapsrv_partition *part;

	DEBUG(10, ("SearchRequest"));
	DEBUGADD(10, (" basedn: %s", req->basedn));
	DEBUGADD(10, (" filter: %s\n", req->filter));

	part = ldapsrv_get_partition(call->conn, req->basedn);

	if (!part->ops->Search) {
		struct ldap_Result *done;
		struct ldapsrv_reply *done_r;

		done_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultDone);
		if (!done_r) {
			return NT_STATUS_NO_MEMORY;
		}

		done = &done_r->msg.r.SearchResultDone;
		done->resultcode = 53;
		done->dn = NULL;
		done->errormessage = NULL;
		done->referral = NULL;

		return ldapsrv_queue_reply(call, done_r);
	}

	return part->ops->Search(part, call, req);
}

static NTSTATUS ldapsrv_ModifyRequest(struct ldapsrv_call *call)
{
	struct ldap_ModifyRequest *req = &call->request.r.ModifyRequest;
	struct ldapsrv_partition *part;

	DEBUG(10, ("ModifyRequest"));
	DEBUGADD(10, (" dn: %s", req->dn));

	part = ldapsrv_get_partition(call->conn, req->dn);

	if (!part->ops->Modify) {
		return ldapsrv_unwilling(call, 53);
	}

	return part->ops->Modify(part, call, req);
}

static NTSTATUS ldapsrv_AddRequest(struct ldapsrv_call *call)
{
	struct ldap_AddRequest *req = &call->request.r.AddRequest;
	struct ldapsrv_partition *part;

	DEBUG(10, ("AddRequest"));
	DEBUGADD(10, (" dn: %s", req->dn));

	part = ldapsrv_get_partition(call->conn, req->dn);

	if (!part->ops->Add) {
		return ldapsrv_unwilling(call, 53);
	}

	return part->ops->Add(part, call, req);
}

static NTSTATUS ldapsrv_DelRequest(struct ldapsrv_call *call)
{
	struct ldap_DelRequest *req = &call->request.r.DelRequest;
	struct ldapsrv_partition *part;

	DEBUG(10, ("DelRequest"));
	DEBUGADD(10, (" dn: %s", req->dn));

	part = ldapsrv_get_partition(call->conn, req->dn);

	if (!part->ops->Del) {
		return ldapsrv_unwilling(call, 53);
	}

	return part->ops->Del(part, call, req);
}

static NTSTATUS ldapsrv_ModifyDNRequest(struct ldapsrv_call *call)
{
	struct ldap_ModifyDNRequest *req = &call->request.r.ModifyDNRequest;
	struct ldapsrv_partition *part;

	DEBUG(10, ("ModifyDNRequrest"));
	DEBUGADD(10, (" dn: %s", req->dn));
	DEBUGADD(10, (" newrdn: %s", req->newrdn));

	part = ldapsrv_get_partition(call->conn, req->dn);

	if (!part->ops->ModifyDN) {
		return ldapsrv_unwilling(call, 53);
	}

	return part->ops->ModifyDN(part, call, req);
}

static NTSTATUS ldapsrv_CompareRequest(struct ldapsrv_call *call)
{
	struct ldap_CompareRequest *req = &call->request.r.CompareRequest;
	struct ldapsrv_partition *part;

	DEBUG(10, ("CompareRequest"));
	DEBUGADD(10, (" dn: %s", req->dn));

	part = ldapsrv_get_partition(call->conn, req->dn);

	if (!part->ops->Compare) {
		return ldapsrv_unwilling(call, 53);
	}

	return part->ops->Compare(part, call, req);
}

static NTSTATUS ldapsrv_AbandonRequest(struct ldapsrv_call *call)
{
/*	struct ldap_AbandonRequest *req = &call->request.r.AbandonRequest;*/
	DEBUG(10, ("AbandonRequest\n"));
	return NT_STATUS_OK;
}

static NTSTATUS ldapsrv_ExtendedRequest(struct ldapsrv_call *call)
{
/*	struct ldap_ExtendedRequest *req = &call->request.r.ExtendedRequest;*/
	struct ldapsrv_reply *reply;

	DEBUG(10, ("Extended\n"));

	reply = ldapsrv_init_reply(call, LDAP_TAG_ExtendedResponse);
	if (!reply) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCT(reply->msg.r);

	return ldapsrv_queue_reply(call, reply);
}

NTSTATUS ldapsrv_do_call(struct ldapsrv_call *call)
{
	switch(call->request.type) {
	case LDAP_TAG_BindRequest:
		return ldapsrv_BindRequest(call);
	case LDAP_TAG_UnbindRequest:
		return ldapsrv_UnbindRequest(call);
	case LDAP_TAG_SearchRequest:
		return ldapsrv_SearchRequest(call);
	case LDAP_TAG_ModifyRequest:
		return ldapsrv_ModifyRequest(call);
	case LDAP_TAG_AddRequest:
		return ldapsrv_AddRequest(call);
	case LDAP_TAG_DelRequest:
		return ldapsrv_DelRequest(call);
	case LDAP_TAG_ModifyDNRequest:
		return ldapsrv_ModifyDNRequest(call);
	case LDAP_TAG_CompareRequest:
		return ldapsrv_CompareRequest(call);
	case LDAP_TAG_AbandonRequest:
		return ldapsrv_AbandonRequest(call);
	case LDAP_TAG_ExtendedRequest:
		return ldapsrv_ExtendedRequest(call);
	default:
		return ldapsrv_unwilling(call, 2);
	}
}
