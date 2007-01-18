/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines for unixinfo-pipe
 *  Copyright (C) Volker Lendecke 2005
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* This is the interface to the rpcunixinfo pipe. */

#include "includes.h"
#include "nterr.h"



#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/* Map a sid to a uid */

NTSTATUS _unixinfo_SidToUid(pipes_struct *p, struct unixinfo_SidToUid *r)
{
	uid_t real_uid;
	NTSTATUS status;
	*r->out.uid = 0;

	status = sid_to_uid(&r->in.sid, &real_uid) ? NT_STATUS_OK : NT_STATUS_NONE_MAPPED;
	if (NT_STATUS_IS_OK(status))
		*r->out.uid = real_uid;

	return status;
}

/* Map a uid to a sid */

NTSTATUS _unixinfo_UidToSid(pipes_struct *p, struct unixinfo_UidToSid *r)
{
	NTSTATUS status = NT_STATUS_NO_SUCH_USER;

	uid_to_sid(r->out.sid, (uid_t)r->in.uid);
	status = NT_STATUS_OK;

	return status;
}

/* Map a sid to a gid */

NTSTATUS _unixinfo_SidToGid(pipes_struct *p, struct unixinfo_SidToGid *r)
{
	gid_t real_gid;
	NTSTATUS status;

	*r->out.gid = 0;

	status = sid_to_gid(&r->in.sid, &real_gid) ? NT_STATUS_OK : NT_STATUS_NONE_MAPPED;
	if (NT_STATUS_IS_OK(status))
		*r->out.gid = real_gid;

	return status;
}

/* Map a gid to a sid */

NTSTATUS _unixinfo_GidToSid(pipes_struct *p, struct unixinfo_GidToSid *r)
{
	NTSTATUS status = NT_STATUS_NO_SUCH_GROUP;

	gid_to_sid(r->out.sid, (gid_t)r->in.gid);
	status = NT_STATUS_OK;

	return status;
}

/* Get unix struct passwd information */

NTSTATUS _unixinfo_GetPWUid(pipes_struct *p, struct unixinfo_GetPWUid *r)
{
	int i;
	NTSTATUS status;

	if (*r->in.count > 1023)
		return NT_STATUS_INVALID_PARAMETER;

	status = NT_STATUS_OK;

	for (i=0; i<*r->in.count; i++) {
		struct passwd *pw;
		char *homedir, *shell;
		ssize_t len1, len2;

		r->out.infos[i].status = NT_STATUS_NO_SUCH_USER;
		r->out.infos[i].homedir = "";
		r->out.infos[i].shell = "";

		pw = getpwuid(r->in.uids[i]);

		if (pw == NULL) {
			DEBUG(10, ("Did not find uid %lld\n",
				   (long long int)r->in.uids[i]));
			continue;
		}

		len1 = push_utf8_talloc(p->mem_ctx, &homedir, pw->pw_dir);
		len2 = push_utf8_talloc(p->mem_ctx, &shell, pw->pw_shell);

		if ((len1 < 0) || (len2 < 0) || (homedir == NULL) ||
		    (shell == NULL)) {
			DEBUG(3, ("push_utf8_talloc failed\n"));
			r->out.infos[i].status = NT_STATUS_NO_MEMORY;
			continue;
		}

		r->out.infos[i].status = NT_STATUS_OK;
		r->out.infos[i].homedir = homedir;
		r->out.infos[i].shell = shell;
	}

	return status;
}
