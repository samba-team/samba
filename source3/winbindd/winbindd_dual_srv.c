/*
   Unix SMB/CIFS implementation.

   In-Child server implementation of the routines defined in wbint.idl

   Copyright (C) Volker Lendecke 2009

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
#include "winbindd/winbindd.h"
#include "winbindd/winbindd_proto.h"
#include "librpc/gen_ndr/srv_wbint.h"

void _wbint_Ping(pipes_struct *p, struct wbint_Ping *r)
{
	*r->out.out_data = r->in.in_data;
}

NTSTATUS _wbint_LookupSid(pipes_struct *p, struct wbint_LookupSid *r)
{
	struct winbindd_domain *domain = wb_child_domain();
	char *dom_name;
	char *name;
	enum lsa_SidType type;
	NTSTATUS status;

	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	status = domain->methods->sid_to_name(domain, p->mem_ctx, r->in.sid,
					      &dom_name, &name, &type);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*r->out.domain = dom_name;
	*r->out.name = name;
	*r->out.type = type;
	return NT_STATUS_OK;
}

NTSTATUS _wbint_LookupName(pipes_struct *p, struct wbint_LookupName *r)
{
	struct winbindd_domain *domain = wb_child_domain();

	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	return domain->methods->name_to_sid(
		domain, p->mem_ctx, r->in.domain, r->in.name, r->in.flags,
		r->out.sid, r->out.type);
}

NTSTATUS _wbint_Sid2Uid(pipes_struct *p, struct wbint_Sid2Uid *r)
{
	uid_t uid;
	NTSTATUS status;

	status = idmap_sid_to_uid(r->in.dom_name ? r->in.dom_name : "",
				  r->in.sid, &uid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	*r->out.uid = uid;
	return NT_STATUS_OK;
}

NTSTATUS _wbint_Sid2Gid(pipes_struct *p, struct wbint_Sid2Gid *r)
{
	gid_t gid;
	NTSTATUS status;

	status = idmap_sid_to_gid(r->in.dom_name ? r->in.dom_name : "",
				  r->in.sid, &gid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	*r->out.gid = gid;
	return NT_STATUS_OK;
}
