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

NTSTATUS _unixinfo_sid_to_uid(pipes_struct *p,
			      UNIXINFO_Q_SID_TO_UID *q_u,
			      UNIXINFO_R_SID_TO_UID *r_u)
{
	uid_t uid;

	r_u->uid.low = 0;
	r_u->uid.high = 0;

	r_u->status = sid_to_uid(&q_u->sid, &uid) ? NT_STATUS_OK : NT_STATUS_NONE_MAPPED;
	if (NT_STATUS_IS_OK(r_u->status))
		r_u->uid.low = uid;

	return r_u->status;
}

/* Map a uid to a sid */

NTSTATUS _unixinfo_uid_to_sid(pipes_struct *p,
			      UNIXINFO_Q_UID_TO_SID *q_u,
			      UNIXINFO_R_UID_TO_SID *r_u)
{
	DOM_SID sid;

	r_u->status = NT_STATUS_NO_SUCH_USER;

	if (q_u->uid.high == 0) {
		uid_to_sid(&sid, q_u->uid.low);
		r_u->status = NT_STATUS_OK;
	}

	init_r_unixinfo_uid_to_sid(r_u,
				NT_STATUS_IS_OK(r_u->status) ? &sid : NULL);

	return r_u->status;
}

/* Map a sid to a gid */

NTSTATUS _unixinfo_sid_to_gid(pipes_struct *p,
			      UNIXINFO_Q_SID_TO_GID *q_u,
			      UNIXINFO_R_SID_TO_GID *r_u)
{
	gid_t gid;

	r_u->gid.low = 0;
	r_u->gid.high = 0;

	r_u->status = sid_to_gid(&q_u->sid, &gid) ? NT_STATUS_OK : NT_STATUS_NONE_MAPPED;
	if (NT_STATUS_IS_OK(r_u->status))
		r_u->gid.low = gid;

	return r_u->status;
}

/* Map a gid to a sid */

NTSTATUS _unixinfo_gid_to_sid(pipes_struct *p,
			      UNIXINFO_Q_GID_TO_SID *q_u,
			      UNIXINFO_R_GID_TO_SID *r_u)
{
	DOM_SID sid;

	r_u->status = NT_STATUS_NO_SUCH_USER;

	if (q_u->gid.high == 0) {
		gid_to_sid(&sid, q_u->gid.low);
		r_u->status = NT_STATUS_OK;
	}

	init_r_unixinfo_gid_to_sid(r_u,
				NT_STATUS_IS_OK(r_u->status) ? &sid : NULL);

	return r_u->status;
}

/* Get unix struct passwd information */

NTSTATUS _unixinfo_getpwuid(pipes_struct *p,
			    UNIXINFO_Q_GETPWUID *q_u,
			    UNIXINFO_R_GETPWUID *r_u)
{
	int i;

	if (r_u->count > 1023) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	r_u->info = TALLOC_ARRAY(p->mem_ctx, struct unixinfo_getpwuid,
				 q_u->count);

	if ((r_u->count > 0) && (r_u->info == NULL)) {
		return NT_STATUS_NO_MEMORY;
	}

	r_u->status = NT_STATUS_OK;
	r_u->count = q_u->count;

	for (i=0; i<r_u->count; i++) {
		struct passwd *pw;
		char *homedir, *shell;
		ssize_t len1, len2;

		r_u->info[i].status = NT_STATUS_NO_SUCH_USER;
		r_u->info[i].homedir = "";
		r_u->info[i].shell = "";

		if (q_u->uid[i].high != 0) {
			DEBUG(10, ("64-bit uids not yet supported...\n"));
			continue;
		}

		pw = getpwuid(q_u->uid[i].low);

		if (pw == NULL) {
			DEBUG(10, ("Did not find uid %d\n", q_u->uid[i].low));
			continue;
		}

		len1 = push_utf8_talloc(p->mem_ctx, &homedir, pw->pw_dir);
		len2 = push_utf8_talloc(p->mem_ctx, &shell, pw->pw_shell);

		if ((len1 < 0) || (len2 < 0) || (homedir == NULL) ||
		    (shell == NULL)) {
			DEBUG(3, ("push_utf8_talloc failed\n"));
			r_u->info[i].status = NT_STATUS_NO_MEMORY;
			continue;
		}

		r_u->info[i].status = NT_STATUS_OK;
		r_u->info[i].homedir = homedir;
		r_u->info[i].shell = shell;
	}

	return r_u->status;
}
