/* 
 * Expand msdfs targets based on client IP
 *
 * Copyright (C) Volker Lendecke, 2004
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "smbd/globals.h"
#include "auth.h"
#include "../lib/tsocket/tsocket.h"
#include "msdfs.h"
#include "source3/lib/substitute.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

/**********************************************************
  Under mapfile we expect a table of the following format:

  IP-Prefix whitespace expansion

  For example:
  192.168.234 local.samba.org
  192.168     remote.samba.org
              default.samba.org

  This is to redirect a DFS client to a host close to it.
***********************************************************/

static char *read_target_host(TALLOC_CTX *ctx, const char *mapfile,
			      const char *clientaddr)
{
	FILE *f;
	char buf[1024];
	char *space = buf;
	bool found = false;

	f = fopen(mapfile, "r");

	if (f == NULL) {
		DEBUG(0,("can't open IP map %s. Error %s\n",
			 mapfile, strerror(errno) ));
		return NULL;
	}

	DEBUG(10, ("Scanning mapfile [%s]\n", mapfile));

	while (fgets(buf, sizeof(buf), f) != NULL) {

		if ((strlen(buf) > 0) && (buf[strlen(buf)-1] == '\n'))
			buf[strlen(buf)-1] = '\0';

		DEBUG(10, ("Scanning line [%s]\n", buf));

		space = strchr_m(buf, ' ');

		if (space == NULL) {
			DEBUG(0, ("Ignoring invalid line %s\n", buf));
			continue;
		}

		*space = '\0';

		if (strncmp(clientaddr, buf, strlen(buf)) == 0) {
			found = true;
			break;
		}
	}

	fclose(f);

	if (!found) {
		return NULL;
	}

	space += 1;

	while (isspace(*space))
		space += 1;

	return talloc_strdup(ctx, space);
}

/**********************************************************

  Expand the msdfs target host using read_target_host
  explained above. The syntax used in the msdfs link is

  msdfs:@table-filename@/share

  Everything between and including the two @-signs is
  replaced by the substitution string found in the table
  described above.

***********************************************************/

static char *expand_msdfs_target(TALLOC_CTX *ctx,
				connection_struct *conn,
				char *target)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *mapfilename = NULL;
	char *filename_start = strchr_m(target, '@');
	char *filename_end = NULL;
	int filename_len = 0;
	char *targethost = NULL;
	char *new_target = NULL;
	char *raddr;

	if (filename_start == NULL) {
		DEBUG(10, ("No filename start in %s\n", target));
		return NULL;
	}

	filename_end = strchr_m(filename_start+1, '@');

	if (filename_end == NULL) {
		DEBUG(10, ("No filename end in %s\n", target));
		return NULL;
	}

	filename_len = PTR_DIFF(filename_end, filename_start+1);
	mapfilename = talloc_strdup(ctx, filename_start+1);
	if (!mapfilename) {
		return NULL;
	}
	mapfilename[filename_len] = '\0';

	/*
	 * dfs links returned have had '/' characters replaced with '\'.
	 * Return them to '/' so we can have absolute path mapfilenames.
	 */
	string_replace(mapfilename, '\\', '/');

	DEBUG(10, ("Expanding from table [%s]\n", mapfilename));

	raddr = tsocket_address_inet_addr_string(conn->sconn->remote_address,
						 ctx);
	if (raddr == NULL) {
		return NULL;
	}

	targethost = read_target_host(ctx, mapfilename, raddr);
	if (targethost == NULL) {
		DEBUG(1, ("Could not expand target host from file %s\n",
			  mapfilename));
		return NULL;
	}

	targethost = talloc_sub_full(ctx,
				lp_servicename(talloc_tos(), lp_sub, SNUM(conn)),
				conn->session_info->unix_info->unix_name,
				conn->connectpath,
				conn->session_info->unix_token->gid,
				conn->session_info->unix_info->sanitized_username,
				conn->session_info->info->domain_name,
				targethost);

	DEBUG(10, ("Expanded targethost to %s\n", targethost));

	/* Replace the part between '@...@' */
	*filename_start = '\0';
	new_target = talloc_asprintf(ctx,
				"%s%s%s",
				target,
				targethost,
				filename_end+1);
	if (!new_target) {
		return NULL;
	}

	DEBUG(10, ("New DFS target: %s\n", new_target));
	return new_target;
}

static NTSTATUS expand_read_dfs_pathat(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct files_struct *dirfsp,
				struct smb_filename *smb_fname,
				struct referral **ppreflist,
				size_t *preferral_count)
{
	NTSTATUS status;
	size_t i;
	struct referral *reflist = NULL;
	size_t count = 0;
	TALLOC_CTX *frame = talloc_stackframe();

	/*
	 * Always call the NEXT function first, then
	 * modify the return if needed.
	 */
	status = SMB_VFS_NEXT_READ_DFS_PATHAT(handle,
				mem_ctx,
				dirfsp,
				smb_fname,
				ppreflist,
				preferral_count);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	/*
	 * This function can be called to check if a pathname
	 * is an MSDFS link, but not return the values of it.
	 * In this case ppreflist and preferral_count are NULL,
	 * so don't bother trying to look at any returns.
	 */
	if (ppreflist == NULL || preferral_count == NULL) {
		TALLOC_FREE(frame);
		return status;
	}

	/*
	 * We are always returning the values returned
	 * returned by the NEXT call, but we might mess
	 * with the reflist[i].alternate_path values,
	 * so use local pointers to minimise indirections.
	 */
	count = *preferral_count;
	reflist = *ppreflist;

	for (i = 0; i < count; i++) {
		if (strchr_m(reflist[i].alternate_path, '@') != NULL) {
			char *new_altpath = expand_msdfs_target(frame,
						handle->conn,
						reflist[i].alternate_path);
			if (new_altpath == NULL) {
				TALLOC_FREE(*ppreflist);
				*preferral_count = 0;
				TALLOC_FREE(frame);
				return NT_STATUS_NO_MEMORY;
			}
			reflist[i].alternate_path = talloc_move(reflist,
							&new_altpath);
		}
	}
	TALLOC_FREE(frame);
	return status;
}

static struct vfs_fn_pointers vfs_expand_msdfs_fns = {
	.read_dfs_pathat_fn = expand_read_dfs_pathat,
};

static_decl_vfs;
NTSTATUS vfs_expand_msdfs_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "expand_msdfs",
				&vfs_expand_msdfs_fns);
}
