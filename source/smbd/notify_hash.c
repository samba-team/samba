/*
   Unix SMB/CIFS implementation.
   change notify handling - hash based implementation
   Copyright (C) Jeremy Allison 1994-1998
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Volker Lendecke 2007

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

struct hash_change_data {
	time_t last_check_time; /* time we last checked this entry */
	struct timespec modify_time; /* Info from the directory we're
				      * monitoring. */
	struct timespec status_time; /* Info from the directory we're
				      * monitoring. */
	time_t total_time; /* Total time of all directory entries - don't care
			    * if it wraps. */
	unsigned int num_entries; /* Zero or the number of files in the
				   * directory. */
	unsigned int mode_sum;
	unsigned char name_hash[16];
};

struct hash_notify_ctx {
	struct hash_change_data *data;
	files_struct *fsp;
	char *path;
	uint32 filter;
};

/* Compare struct timespec. */
#define TIMESTAMP_NEQ(x, y) (((x).tv_sec != (y).tv_sec) || ((x).tv_nsec != (y).tv_nsec))

/****************************************************************************
 Create the hash we will use to determine if the contents changed.
*****************************************************************************/

static BOOL notify_hash(connection_struct *conn, char *path, uint32 flags, 
			struct hash_change_data *data,
			struct hash_change_data *old_data)
{
	SMB_STRUCT_STAT st;
	pstring full_name;
	char *p;
	const char *fname;
	size_t remaining_len;
	size_t fullname_len;
	struct smb_Dir *dp;
	long offset;

	ZERO_STRUCTP(data);

	if(SMB_VFS_STAT(conn,path, &st) == -1)
		return False;

	data->modify_time = get_mtimespec(&st);
	data->status_time = get_ctimespec(&st);

	if (old_data) {
		/*
		 * Shortcut to avoid directory scan if the time
		 * has changed - we always must return true then.
		 */
		if (TIMESTAMP_NEQ(old_data->modify_time, data->modify_time) ||
		    TIMESTAMP_NEQ(old_data->status_time, data->status_time) ) {
				return True;
		}
	}
 
        if (S_ISDIR(st.st_mode) && 
            (flags & ~(FILE_NOTIFY_CHANGE_FILE_NAME
		       | FILE_NOTIFY_CHANGE_DIR_NAME)) == 0)
        {
		/* This is the case of a client wanting to know only when
		 * the contents of a directory changes. Since any file
		 * creation, rename or deletion will update the directory
		 * timestamps, we don't need to create a hash.
		 */
                return True;
        }

	/*
	 * If we are to watch for changes that are only stored
	 * in inodes of files, not in the directory inode, we must
	 * scan the directory and produce a unique identifier with
	 * which we can determine if anything changed. We use the
	 * modify and change times from all the files in the
	 * directory, added together (ignoring wrapping if it's
	 * larger than the max time_t value).
	 */

	dp = OpenDir(conn, path, NULL, 0);
	if (dp == NULL)
		return False;

	data->num_entries = 0;
	
	pstrcpy(full_name, path);
	pstrcat(full_name, "/");
	
	fullname_len = strlen(full_name);
	remaining_len = sizeof(full_name) - fullname_len - 1;
	p = &full_name[fullname_len];
	
	offset = 0;
	while ((fname = ReadDirName(dp, &offset))) {
		SET_STAT_INVALID(st);
		if(strequal(fname, ".") || strequal(fname, ".."))
			continue;		

		if (!is_visible_file(conn, path, fname, &st, True))
			continue;

		data->num_entries++;
		safe_strcpy(p, fname, remaining_len);

		/*
		 * Do the stat - but ignore errors.
		 */		
		if (!VALID_STAT(st)) {
			SMB_VFS_STAT(conn,full_name, &st);
		}

		/*
		 * Always sum the times.
		 */

		data->total_time += (st.st_mtime + st.st_ctime);

		/*
		 * If requested hash the names.
		 */

		if (flags & (FILE_NOTIFY_CHANGE_DIR_NAME
			     |FILE_NOTIFY_CHANGE_FILE_NAME)) {
			int i;
			unsigned char tmp_hash[16];
			mdfour(tmp_hash, (const unsigned char *)fname,
			       strlen(fname));
			for (i=0;i<16;i++)
				data->name_hash[i] ^= tmp_hash[i];
		}

		/*
		 * If requested sum the mode_t's.
		 */

		if (flags & (FILE_NOTIFY_CHANGE_ATTRIBUTES
			     |FILE_NOTIFY_CHANGE_SECURITY))
			data->mode_sum += st.st_mode;
	}
	
	CloseDir(dp);
	
	return True;
}

static void hash_change_notify_handler(struct event_context *event_ctx,
				       struct timed_event *te,
				       const struct timeval *now,
				       void *private_data)
{
	struct hash_change_data *new_data;
	struct hash_notify_ctx *ctx =
		talloc_get_type_abort(private_data,
				      struct hash_notify_ctx);

	TALLOC_FREE(te);

	if (!(new_data = TALLOC_P(ctx, struct hash_change_data))) {
		DEBUG(0, ("talloc failed\n"));
		/*
		 * No new timed event;
		 */
		return;
	}

	if (!notify_hash(ctx->fsp->conn, ctx->fsp->fsp_name,
			 ctx->filter, new_data, ctx->data)
	    || TIMESTAMP_NEQ(new_data->modify_time, ctx->data->modify_time)
	    || TIMESTAMP_NEQ(new_data->status_time, ctx->data->status_time)
	    || new_data->total_time != ctx->data->total_time
	    || new_data->num_entries != ctx->data->num_entries
	    || new_data->mode_sum != ctx->data->mode_sum
	    || (memcmp(new_data->name_hash, ctx->data->name_hash,
		       sizeof(new_data->name_hash)))) {
		notify_fsp(ctx->fsp, 0, NULL);
	}

	TALLOC_FREE(ctx->data);
	ctx->data = new_data;

        event_add_timed(
		event_ctx, ctx,
		timeval_current_ofs(
			lp_change_notify_timeout(SNUM(ctx->fsp->conn)), 0),
		"hash_change_notify_handler",
		hash_change_notify_handler, ctx);
}



static void *hash_notify_add(TALLOC_CTX *mem_ctx,
			     struct event_context *event_ctx,
			     files_struct *fsp,
			     uint32 *filter)
{
	struct hash_notify_ctx *ctx;
	int timeout = lp_change_notify_timeout(SNUM(fsp->conn));

	if (timeout <= 0) {
		/* It change notify timeout has been disabled, never scan the
		 * directory. */
		return NULL;
	}

	if (!(ctx = TALLOC_P(mem_ctx, struct hash_notify_ctx))) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	if (!(ctx->path = talloc_asprintf(ctx, "%s/%s", fsp->conn->connectpath,
					  fsp->fsp_name))) {
		DEBUG(0, ("talloc_asprintf failed\n"));
		TALLOC_FREE(ctx);
		return NULL;
	}

	if (!(ctx->data = TALLOC_P(ctx, struct hash_change_data))) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(ctx);
		return NULL;
	}

	ctx->fsp = fsp;

	/*
	 * Don't change the Samba filter, hash can only be a very bad attempt
	 * anyway.
	 */
	ctx->filter = *filter;

	notify_hash(fsp->conn, ctx->path, ctx->filter, ctx->data, NULL);

	event_add_timed(event_ctx, ctx, timeval_current_ofs(timeout, 0),
			"hash_change_notify_handler",
			hash_change_notify_handler, ctx);

	return (void *)ctx;
}

/****************************************************************************
 Setup hash based change notify.
****************************************************************************/

struct cnotify_fns *hash_notify_init(void) 
{
	static struct cnotify_fns cnotify;

	cnotify.notify_add = hash_notify_add;

	return &cnotify;
}
