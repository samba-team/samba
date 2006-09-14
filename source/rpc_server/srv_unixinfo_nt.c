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

NTSTATUS _unixinfo_SidToUid(pipes_struct *p, struct dom_sid sid, uint64_t *uid)
{
	uid_t real_uid;
	NTSTATUS status;
	*uid = 0;

	status = sid_to_uid(&sid, &real_uid) ? NT_STATUS_OK : NT_STATUS_NONE_MAPPED;
	if (NT_STATUS_IS_OK(status))
		*uid = real_uid;

	return status;
}

/* Map a uid to a sid */

NTSTATUS _unixinfo_UidToSid(pipes_struct *p, uint64_t uid, struct dom_sid *sid)
{
	NTSTATUS status = NT_STATUS_NO_SUCH_USER;

	uid_to_sid(sid, (uid_t)uid);
	status = NT_STATUS_OK;

	return status;
}

/* Map a sid to a gid */

NTSTATUS _unixinfo_SidToGid(pipes_struct *p, struct dom_sid sid, uint64_t *gid)
{
	gid_t real_gid;
	NTSTATUS status;

	*gid = 0;

	status = sid_to_gid(&sid, &real_gid) ? NT_STATUS_OK : NT_STATUS_NONE_MAPPED;
	if (NT_STATUS_IS_OK(status))
		*gid = real_gid;

	return status;
}

/* Map a gid to a sid */

NTSTATUS _unixinfo_GidToSid(pipes_struct *p, uint64_t gid, struct dom_sid *sid)
{
	NTSTATUS status = NT_STATUS_NO_SUCH_GROUP;

	gid_to_sid(sid, (gid_t)gid);
	status = NT_STATUS_OK;

	return status;
}

/* Get unix struct passwd information */

NTSTATUS _unixinfo_GetPWUid(pipes_struct *p, uint32_t *count, uint64_t *uids, 
							struct unixinfo_GetPWUidInfo *infos)
{
	int i;
	NTSTATUS status;

	if (*count > 1023)
		return NT_STATUS_INVALID_PARAMETER;

	status = NT_STATUS_OK;

	for (i=0; i<*count; i++) {
		struct passwd *pw;
		char *homedir, *shell;
		ssize_t len1, len2;

		infos[i].status = NT_STATUS_NO_SUCH_USER;
		infos[i].homedir = "";
		infos[i].shell = "";

		pw = getpwuid(uids[i]);

		if (pw == NULL) {
			DEBUG(10, ("Did not find uid %lld\n", uids[i]));
			continue;
		}

		len1 = push_utf8_talloc(p->mem_ctx, &homedir, pw->pw_dir);
		len2 = push_utf8_talloc(p->mem_ctx, &shell, pw->pw_shell);

		if ((len1 < 0) || (len2 < 0) || (homedir == NULL) ||
		    (shell == NULL)) {
			DEBUG(3, ("push_utf8_talloc failed\n"));
			infos[i].status = NT_STATUS_NO_MEMORY;
			continue;
		}

		infos[i].status = NT_STATUS_OK;
		infos[i].homedir = homedir;
		infos[i].shell = shell;
	}

	return status;
}
