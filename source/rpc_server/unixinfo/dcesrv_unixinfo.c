/* 
   Unix SMB/CIFS implementation.

   endpoint server for the unixinfo pipe

   Copyright (C) Volker Lendecke 2005
   
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
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "librpc/gen_ndr/ndr_unixinfo.h"
#include "lib/events/events.h"
#include "dsdb/samdb/samdb.h"
#include "system/passwd.h"

static NTSTATUS dcesrv_unixinfo_SidToUid(struct dcesrv_call_state *dce_call,
				  TALLOC_CTX *mem_ctx,
				  struct unixinfo_SidToUid *r)
{
	NTSTATUS status;
	struct sidmap_context *sidmap;
	uid_t uid;

	sidmap = sidmap_open(mem_ctx);
	if (sidmap == NULL) {
		DEBUG(10, ("sidmap_open failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	status = sidmap_sid_to_unixuid(sidmap, &r->in.sid, &uid);
	NT_STATUS_NOT_OK_RETURN(status);

	*r->out.uid = uid;
	return NT_STATUS_OK;
}

static NTSTATUS dcesrv_unixinfo_UidToSid(struct dcesrv_call_state *dce_call,
				  TALLOC_CTX *mem_ctx,
				  struct unixinfo_UidToSid *r)
{
	struct sidmap_context *sidmap;
	uid_t uid;

	sidmap = sidmap_open(mem_ctx);
	if (sidmap == NULL) {
		DEBUG(10, ("sidmap_open failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	uid = r->in.uid; 	/* This cuts uid to (probably) 32 bit */

	if ((uint64_t)uid != r->in.uid) {
		DEBUG(10, ("uid out of range\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	return sidmap_uid_to_sid(sidmap, mem_ctx, uid, &r->out.sid);
}

static NTSTATUS dcesrv_unixinfo_SidToGid(struct dcesrv_call_state *dce_call,
				  TALLOC_CTX *mem_ctx,
				  struct unixinfo_SidToGid *r)
{
	NTSTATUS status;
	struct sidmap_context *sidmap;
	gid_t gid;

	sidmap = sidmap_open(mem_ctx);
	if (sidmap == NULL) {
		DEBUG(10, ("sidmap_open failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	status = sidmap_sid_to_unixgid(sidmap, &r->in.sid, &gid);
	NT_STATUS_NOT_OK_RETURN(status);

	*r->out.gid = gid;
	return NT_STATUS_OK;
}

static NTSTATUS dcesrv_unixinfo_GidToSid(struct dcesrv_call_state *dce_call,
				  TALLOC_CTX *mem_ctx,
				  struct unixinfo_GidToSid *r)
{
	struct sidmap_context *sidmap;
	gid_t gid;

	sidmap = sidmap_open(mem_ctx);
	if (sidmap == NULL) {
		DEBUG(10, ("sidmap_open failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	gid = r->in.gid; 	/* This cuts gid to (probably) 32 bit */

	if ((uint64_t)gid != r->in.gid) {
		DEBUG(10, ("gid out of range\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	return sidmap_gid_to_sid(sidmap, mem_ctx, gid, &r->out.sid);
}

static NTSTATUS dcesrv_unixinfo_GetPWUid(struct dcesrv_call_state *dce_call,
				  TALLOC_CTX *mem_ctx,
				  struct unixinfo_GetPWUid *r)
{
	int i;

	*r->out.count = 0;

	r->out.infos = talloc_zero_array(mem_ctx, struct unixinfo_GetPWUidInfo,
					 *r->in.count);
	NT_STATUS_HAVE_NO_MEMORY(r->out.infos);
	*r->out.count = *r->in.count;

	for (i=0; i < *r->in.count; i++) {
		uid_t uid;
		struct passwd *pwd;

		uid = r->in.uids[i];
		pwd = getpwuid(uid);
		if (pwd == NULL) {
			DEBUG(10, ("uid %d not found\n", uid));
			r->out.infos[i].homedir = "";
			r->out.infos[i].shell = "";
			r->out.infos[i].status = NT_STATUS_NO_SUCH_USER;
			continue;
		}

		r->out.infos[i].homedir = talloc_strdup(mem_ctx, pwd->pw_dir);
		r->out.infos[i].shell = talloc_strdup(mem_ctx, pwd->pw_shell);

		if ((r->out.infos[i].homedir == NULL) ||
		    (r->out.infos[i].shell == NULL)) {
			r->out.infos[i].homedir = "";
			r->out.infos[i].shell = "";
			r->out.infos[i].status = NT_STATUS_NO_MEMORY;
			continue;
		}

		r->out.infos[i].status = NT_STATUS_OK;
	}

	return NT_STATUS_OK;
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_unixinfo_s.c"
