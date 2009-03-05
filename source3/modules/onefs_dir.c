/*
 * Unix SMB/CIFS implementation.
 *
 * Support for OneFS bulk directory enumeration API
 *
 * Copyright (C) Steven Danneman, 2009
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
#include "onefs.h"
#include "onefs_config.h"

#include <ifs/ifs_syscalls.h>

/* The OneFS filesystem provides a readdirplus() syscall, equivalent to the
 * NFSv3 PDU, which retrieves bulk directory listings with stat information
 * in a single syscall.
 *
 * This file hides this bulk interface underneath Samba's very POSIX like
 * opendir/readdir/telldir VFS interface.  This is done to provide a
 * significant performance improvement when listing the contents of large
 * directories, which also require file meta information. ie a typical
 * Windows Explorer request.
 */

#define RDP_RESUME_KEY_START 0x1

#define RDP_BATCH_SIZE 128
#define RDP_DIRENTRIES_SIZE ((size_t)(RDP_BATCH_SIZE * sizeof(struct dirent)))

static char *rdp_direntries = NULL;
static SMB_STRUCT_STAT *rdp_stats = NULL;
static uint64_t *rdp_cookies = NULL;

struct rdp_dir_state {
	struct rdp_dir_state *next, *prev;
	SMB_STRUCT_DIR *dirp;
	char *direntries_cursor; /* cursor to current direntry in the cache */
	size_t stat_count;	 /* number of entries stored in the cache */
	size_t stat_cursor;	 /* cursor to current stat in the cache */
	uint64_t resume_cookie;  /* last cookie returned from the cache */
	long location;		 /* absolute location of direnty in DIR */
};

static struct rdp_dir_state *dirstatelist = NULL;

SMB_STRUCT_DIR *rdp_last_dirp = NULL;

/**
 * Given a DIR pointer, return our internal state.
 *
 * This function also tells us whether the given DIR is the same as we saw
 * during the last call.  Because we use a single globally allocated buffer
 * for readdirplus entries we must check every call into this API to see if
 * it's for the same directory listing, or a new one. If it's the same we can
 * maintain our current cached entries, otherwise we must go to the kernel.
 *
 * @return 0 on success, 1 on failure
 */
static int
rdp_retrieve_dir_state(SMB_STRUCT_DIR *dirp, struct rdp_dir_state **dir_state,
		       bool *same_as_last)
{
	struct rdp_dir_state *dsp;

	/* Is this directory the same as the last call */
	*same_as_last = (dirp == rdp_last_dirp);

	for(dsp = dirstatelist; dsp; dsp = dsp->next)
		if (dsp->dirp == dirp) {
			*dir_state = dsp;
			return 0;
		}

	/* Couldn't find existing dir_state for the given directory
	 * pointer. */
	return 1;
}

/**
 * Initialize the global readdirplus buffers.
 *
 * These same buffers are used for all calls into readdirplus.
 *
 * @return 0 on success, errno value on failure
 */
static int
rdp_init(struct rdp_dir_state *dsp)
{
	/* Unfortunately, there is no good way to free these buffers.  If we
	 * allocated and freed for every DIR handle performance would be
	 * adversely affected.  For now these buffers will be leaked and only
	 * freed when the smbd process dies. */
	if (!rdp_direntries) {
		rdp_direntries = SMB_MALLOC(RDP_DIRENTRIES_SIZE);
		if (!rdp_direntries)
			return ENOMEM;
	}

	if (!rdp_stats) {
		rdp_stats =
		    SMB_MALLOC(RDP_BATCH_SIZE * sizeof(SMB_STRUCT_STAT));
		if (!rdp_stats)
			return ENOMEM;
	}

	if (!rdp_cookies) {
		rdp_cookies = SMB_MALLOC(RDP_BATCH_SIZE * sizeof(uint64_t));
		if (!rdp_cookies)
			return ENOMEM;
	}

	dsp->direntries_cursor = rdp_direntries + RDP_DIRENTRIES_SIZE;
	dsp->stat_count = RDP_BATCH_SIZE;
	dsp->stat_cursor = RDP_BATCH_SIZE;
	dsp->resume_cookie = RDP_RESUME_KEY_START;
	dsp->location = 0;

	return 0;
}

/**
 * Call into readdirplus() to refill our global dirent cache.
 *
 * This function also resets all cursors back to the beginning of the cache.
 * All stat buffers are retrieved by following symlinks.
 *
 * @return number of entries retrieved, -1 on error
 */
static int
rdp_fill_cache(struct rdp_dir_state *dsp)
{
	int nread, dirfd;

	dirfd = dirfd(dsp->dirp);
	if (dirfd < 0) {
		DEBUG(1, ("Could not retrieve fd for DIR\n"));
		return -1;
	}

	/* Resize the stat_count to grab as many entries as possible */
	dsp->stat_count = RDP_BATCH_SIZE;

	DEBUG(9, ("Calling readdirplus() with DIR %p, dirfd: %d, "
		 "resume_cookie 0x%llx, location %u, size_to_read: %zu, "
		 "direntries_size: %zu, stat_count: %u\n",
		 dsp->dirp, dirfd, dsp->resume_cookie, dsp->location,
		 RDP_BATCH_SIZE, RDP_DIRENTRIES_SIZE, dsp->stat_count));

	nread = readdirplus(dirfd,
			    RDP_FOLLOW,
			    &dsp->resume_cookie,
			    RDP_BATCH_SIZE,
			    rdp_direntries,
			    RDP_DIRENTRIES_SIZE,
			    &dsp->stat_count,
			    rdp_stats,
			    rdp_cookies);
	if (nread < 0) {
		DEBUG(1, ("Error calling readdirplus(): %s\n",
			 strerror(errno)));
		return -1;
	}

	DEBUG(9, ("readdirplus() returned %u entries from DIR %p\n",
		 dsp->stat_count, dsp->dirp));

	dsp->direntries_cursor = rdp_direntries;
	dsp->stat_cursor = 0;

	return nread;
}

/**
 * Create a dir_state to track an open directory that we're enumerating.
 *
 * This utility function is globally accessible for use by other parts of the
 * onefs.so module to initialize a dir_state when a directory is opened through
 * a path other than the VFS layer.
 *
 * @return 0 on success and errno on failure
 *
 * @note: Callers of this function MUST cleanup the dir_state through a proper
 * call to VFS_CLOSEDIR().
 */
int
onefs_rdp_add_dir_state(connection_struct *conn, SMB_STRUCT_DIR *dirp)
{
	int ret = 0;
	struct rdp_dir_state *dsp = NULL;

	/* No-op if readdirplus is disabled */
	if (!lp_parm_bool(SNUM(conn), PARM_ONEFS_TYPE,
	    PARM_USE_READDIRPLUS, PARM_USE_READDIRPLUS_DEFAULT))
	{
		return 0;
	}

	/* Create a struct dir_state */
	dsp = SMB_MALLOC_P(struct rdp_dir_state);
	if (!dsp) {
		DEBUG(0, ("Error allocating struct rdp_dir_state.\n"));
		return ENOMEM;
	}

	/* Initialize the dir_state structure and add it to the list */
	ret = rdp_init(dsp);
	if (ret) {
		DEBUG(0, ("Error initializing readdirplus() buffers: %s\n",
			 strerror(ret)));
		return ret;
	}

	/* Set the SMB_STRUCT_DIR in the dsp */
	dsp->dirp = dirp;

	DLIST_ADD(dirstatelist, dsp);

	return 0;
}

/**
 * Open a directory for enumeration.
 *
 * Create a state struct to track the state of this directory for the life
 * of this open.
 *
 * @param[in] handle vfs handle given in most VFS calls
 * @param[in] fname filename of the directory to open
 * @param[in] mask unused
 * @param[in] attr unused
 *
 * @return DIR pointer, NULL if directory does not exist, NULL on error
 */
SMB_STRUCT_DIR *
onefs_opendir(vfs_handle_struct *handle, const char *fname, const char *mask,
	      uint32 attr)
{
	int ret = 0;
	SMB_STRUCT_DIR *ret_dirp;

	/* Fallback to default system routines if readdirplus is disabled */
	if (!lp_parm_bool(SNUM(handle->conn), PARM_ONEFS_TYPE,
	    PARM_USE_READDIRPLUS, PARM_USE_READDIRPLUS_DEFAULT))
	{
		return SMB_VFS_NEXT_OPENDIR(handle, fname, mask, attr);
	}

	/* Open the directory */
	ret_dirp = SMB_VFS_NEXT_OPENDIR(handle, fname, mask, attr);
	if (!ret_dirp) {
		DEBUG(3, ("Unable to open directory: %s\n", fname));
		return NULL;
	}

	/* Create the dir_state struct and add it to the list */
	ret = onefs_rdp_add_dir_state(handle->conn, ret_dirp);
	if (ret) {
		DEBUG(0, ("Error adding dir_state to the list\n"));
		return NULL;
	}

	DEBUG(9, ("Opened handle on directory: \"%s\", DIR %p\n",
		 fname, ret_dirp));

	return ret_dirp;
}

/**
 * Retrieve one direntry and optional stat buffer from our readdir cache.
 *
 * Increment the internal resume cookie, and refresh the cache from the
 * kernel if necessary.
 *
 * @param[in] handle vfs handle given in most VFS calls
 * @param[in] dirp system DIR handle to retrieve direntries from
 * @param[in/out] sbuf optional stat buffer to fill, this can be NULL
 *
 * @return dirent structure, NULL if at the end of the directory, NULL on error
 */
SMB_STRUCT_DIRENT *
onefs_readdir(vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp,
	      SMB_STRUCT_STAT *sbuf)
{
	struct rdp_dir_state *dsp = NULL;
	SMB_STRUCT_DIRENT *ret_direntp;
	bool same_as_last;
	int ret = -1;

	/* Set stat invalid in-case we error out */
	if (sbuf)
		SET_STAT_INVALID(*sbuf);

	/* Fallback to default system routines if readdirplus is disabled */
	if (!lp_parm_bool(SNUM(handle->conn), PARM_ONEFS_TYPE,
	    PARM_USE_READDIRPLUS, PARM_USE_READDIRPLUS_DEFAULT))
	{
		return sys_readdir(dirp);
	}

	/* Retrieve state based off DIR handle */
	ret = rdp_retrieve_dir_state(dirp, &dsp, &same_as_last);
	if (ret) {
		DEBUG(1, ("Could not retrieve dir_state struct for "
			 "SMB_STRUCT_DIR pointer.\n"));
		ret_direntp = NULL;
		goto end;
	}

	/* DIR is the same, current buffer and cursors are valid.
	 * Grab the next direntry from our cache. */
	if (same_as_last) {
		if ((dsp->direntries_cursor >=
		    rdp_direntries + RDP_DIRENTRIES_SIZE) ||
		    (dsp->stat_cursor == dsp->stat_count))
		{
			/* Cache is empty, refill from kernel */
			ret = rdp_fill_cache(dsp);
			if (ret <= 0) {
				ret_direntp = NULL;
				goto end;
			}
		}
	} else {
		/* DIR is different from last call, reset all buffers and
		 * cursors, and refill the global cache from the new DIR */
		ret = rdp_fill_cache(dsp);
		if (ret <= 0) {
			ret_direntp = NULL;
			goto end;
		}
		DEBUG(8, ("Switched global rdp cache to new DIR entry.\n"));
	}

	/* Return next entry from cache */
	ret_direntp = ((SMB_STRUCT_DIRENT *)dsp->direntries_cursor);
	dsp->direntries_cursor +=
	    ((SMB_STRUCT_DIRENT *)dsp->direntries_cursor)->d_reclen;
	if (sbuf) {
		*sbuf = rdp_stats[dsp->stat_cursor];
		/* readdirplus() sets st_ino field to 0, if it was
		 * unable to retrieve stat information for that
		 * particular directory entry. */
		if (sbuf->st_ino == 0)
			SET_STAT_INVALID(*sbuf);
	}

	DEBUG(9, ("Read from DIR %p, direntry: \"%s\", location: %ld, "
		 "resume cookie: 0x%llx, cache cursor: %zu, cache count: %zu\n",
		 dsp->dirp, ret_direntp->d_name, dsp->location,
		 dsp->resume_cookie, dsp->stat_cursor, dsp->stat_count));

	dsp->resume_cookie = rdp_cookies[dsp->stat_cursor];
	dsp->stat_cursor++;
	dsp->location++;

	/* FALLTHROUGH */
end:
	/* Set rdp_last_dirp at the end of every VFS call where the cache was
	 * reloaded */
	rdp_last_dirp = dirp;
	return ret_direntp;
}

/**
 * Set the location of the next direntry to be read via onefs_readdir().
 *
 * This function should only pass in locations retrieved from onefs_telldir().
 *
 * Ideally the seek point will still be in the readdirplus cache, and we'll
 * just update our cursors.  If the seek location is outside of the current
 * cache we must do an expensive re-enumeration of the entire directory up
 * to the offset.
 *
 * @param[in] handle vfs handle given in most VFS calls
 * @param[in] dirp system DIR handle to set offset on
 * @param[in] offset from the start of the directory where the next read
 *	      will take place
 *
 * @return no return value
 */
void
onefs_seekdir(vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp, long offset)
{
	struct rdp_dir_state *dsp = NULL;
	bool same_as_last;
	bool outside_cache = false;
	int ret = -1, i;

	/* Fallback to default system routines if readdirplus is disabled */
	if (!lp_parm_bool(SNUM(handle->conn), PARM_ONEFS_TYPE,
	    PARM_USE_READDIRPLUS, PARM_USE_READDIRPLUS_DEFAULT))
	{
		return sys_seekdir(dirp, offset);
	}

	/* Validate inputs */
	if (offset < 0) {
		DEBUG(1, ("Invalid offset %ld passed.\n", offset));
		return;
	}

	/* Retrieve state based off DIR handle */
	ret = rdp_retrieve_dir_state(dirp, &dsp, &same_as_last);
	if (ret) {
		DEBUG(1, ("Could not retrieve dir_state struct for "
			 "SMB_STRUCT_DIR pointer.\n"));
		/* XXX: we can't return an error, should we ABORT rather than
		 * return without actually seeking? */
		return;
	}

	/* Short cut if no work needs to be done */
	if (offset == dsp->location)
		return;

	/* If DIR is different from last call, reset all buffers and cursors,
	 * and refill the global cache from the new DIR */
	if (!same_as_last) {
		ret = rdp_fill_cache(dsp);
		if (ret <= 0)
			goto out;
		DEBUG(8, ("Switched global rdp cache to new DIR entry.\n"));
	}

	/* Check if location is outside the currently cached entries */
	if (offset < dsp->location - dsp->stat_cursor) {
		/* offset is before the current cache */
		/* reset to the beginning of the directory */
		ret = rdp_init(dsp);
		if (ret) {
			DEBUG(0, ("Error initializing readdirplus() buffers: "
				 "%s\n", strerror(ret)));
			goto out;
		}
		outside_cache = true;
	} else if (offset >
	    dsp->location + (dsp->stat_count - 1 - dsp->stat_cursor))
	{
		/* offset is after the current cache
		 * advance the cookie to the end of the cache */
		dsp->resume_cookie = rdp_cookies[dsp->stat_count - 1];
		outside_cache = true;
	}

	if (outside_cache) {
		/* start reading from the directory, until we have the
		 * specified offset in our cache */
		do {
			dsp->location += dsp->stat_count - dsp->stat_cursor;
			ret = rdp_fill_cache(dsp);
			if (ret <= 0) {
				DEBUG(1, ("Error seeking to offset outside the "
					 "cached directory entries. Offset "
					 "%ld \n", dsp->location));
				goto out;
			}
			dsp->resume_cookie = rdp_cookies[dsp->stat_count - 1];
		} while (offset >= dsp->location + dsp->stat_count);
	}

	/* Location should be within the currently cached entries */
	if (offset < dsp->location &&
	    offset >= dsp->location - dsp->stat_cursor)
	{
		/* offset is within the current cache, before the cursor.
		 * update cursors to the new location */
		int new_cursor = dsp->stat_cursor - (dsp->location - offset);

		dsp->direntries_cursor = rdp_direntries;
		for (i=0; i < new_cursor; i++) {
			dsp->direntries_cursor +=
			    ((SMB_STRUCT_DIRENT *)
			     dsp->direntries_cursor)->d_reclen;
		}
		dsp->stat_cursor = new_cursor;
		dsp->resume_cookie = rdp_cookies[dsp->stat_cursor];
		dsp->location = offset;
	} else if (offset >= dsp->location &&
	   offset <= dsp->location + (dsp->stat_count - 1 - dsp->stat_cursor))
	{
		/* offset is within the current cache, at or after the cursor.
		 * update cursors to the new location */
		int add_to_cursor = offset - dsp->location - 1;

		for (i=0; i < add_to_cursor; i++) {
			dsp->direntries_cursor +=
			    ((SMB_STRUCT_DIRENT *)
			     dsp->direntries_cursor)->d_reclen;
		}
		dsp->stat_cursor += add_to_cursor;
		dsp->resume_cookie = rdp_cookies[dsp->stat_cursor];
		dsp->location = offset;
	}

	DEBUG(9, ("Seek DIR %p, location: %ld, cache cursor: %zu\n",
		 dsp->dirp, dsp->location, dsp->stat_cursor));

	/* FALLTHROUGH */
out:
	/* Set rdp_last_dirp at the end of every VFS call where the cache was
	 * reloaded */
	rdp_last_dirp = dirp;
	return;
}

/**
 * Returns the location of the next direntry to be read via onefs_readdir().
 *
 * This value can be passed into onefs_seekdir().
 *
 * @param[in] handle vfs handle given in most VFS calls
 * @param[in] dirp system DIR handle to set offset on
 *
 * @return offset from the start of the directory where the next read
 *	   will take place
 */
long
onefs_telldir(vfs_handle_struct *handle,  SMB_STRUCT_DIR *dirp)
{
	struct rdp_dir_state *dsp = NULL;
	bool same_as_last;
	int ret = -1;

	/* Fallback to default system routines if readdirplus is disabled */
	if (!lp_parm_bool(SNUM(handle->conn), PARM_ONEFS_TYPE,
	    PARM_USE_READDIRPLUS, PARM_USE_READDIRPLUS_DEFAULT))
	{
		return sys_telldir(dirp);
	}

	/* Retrieve state based off DIR handle */
	ret = rdp_retrieve_dir_state(dirp, &dsp, &same_as_last);
	if (ret) {
		DEBUG(1, ("Could not retrieve dir_state struct for "
			 "SMB_STRUCT_DIR pointer.\n"));
		return -1;
	}

	DEBUG(9, ("Tell DIR %p, location: %ld, cache cursor: %zu\n",
		 dsp->dirp, dsp->location, dsp->stat_cursor));

	return dsp->location;
}

/**
 * Set the next direntry to be read via onefs_readdir() to the beginning of the
 * directory.
 *
 * @param[in] handle vfs handle given in most VFS calls
 * @param[in] dirp system DIR handle to set offset on
 *
 * @return no return value
 */
void
onefs_rewinddir(vfs_handle_struct *handle,  SMB_STRUCT_DIR *dirp)
{
	struct rdp_dir_state *dsp = NULL;
	bool same_as_last;
	int ret = -1;

	/* Fallback to default system routines if readdirplus is disabled */
	if (!lp_parm_bool(SNUM(handle->conn), PARM_ONEFS_TYPE,
	    PARM_USE_READDIRPLUS, PARM_USE_READDIRPLUS_DEFAULT))
	{
		return sys_rewinddir(dirp);
	}

	/* Retrieve state based off DIR handle */
	ret = rdp_retrieve_dir_state(dirp, &dsp, &same_as_last);
	if (ret) {
		DEBUG(1, ("Could not retrieve dir_state struct for "
			 "SMB_STRUCT_DIR pointer.\n"));
		return;
	}

	/* Reset location and resume key to beginning */
	ret = rdp_init(dsp);
	if (ret) {
		DEBUG(0, ("Error re-initializing rdp cursors: %s\n",
		    strerror(ret)));
		return;
	}

	DEBUG(9, ("Rewind DIR: %p, to location: %ld\n", dsp->dirp,
		 dsp->location));

	return;
}

/**
 * Close DIR pointer and remove all state for that directory open.
 *
 * @param[in] handle vfs handle given in most VFS calls
 * @param[in] dirp system DIR handle to set offset on
 *
 * @return -1 on failure, setting errno
 */
int
onefs_closedir(vfs_handle_struct *handle,  SMB_STRUCT_DIR *dirp)
{
	struct rdp_dir_state *dsp = NULL;
	bool same_as_last;
	int ret_val = -1;
	int ret = -1;

	/* Fallback to default system routines if readdirplus is disabled */
	if (!lp_parm_bool(SNUM(handle->conn), PARM_ONEFS_TYPE,
	    PARM_USE_READDIRPLUS, PARM_USE_READDIRPLUS_DEFAULT))
	{
		return SMB_VFS_NEXT_CLOSEDIR(handle, dirp);
	}

	/* Retrieve state based off DIR handle */
	ret = rdp_retrieve_dir_state(dirp, &dsp, &same_as_last);
	if (ret) {
		DEBUG(1, ("Could not retrieve dir_state struct for "
			 "SMB_STRUCT_DIR pointer.\n"));
		errno = ENOENT;
		return -1;
	}

	/* Close DIR pointer */
	ret_val = SMB_VFS_NEXT_CLOSEDIR(handle, dsp->dirp);

	DEBUG(9, ("Closed handle on DIR %p\n", dsp->dirp));

	/* Tear down state struct */
	DLIST_REMOVE(dirstatelist, dsp);
	SAFE_FREE(dsp);

	/* Set lastp to NULL, as cache is no longer valid */
	rdp_last_dirp = NULL;

	return ret_val;
}

/**
 * Initialize cache data at the beginning of every SMB search operation
 *
 * Since filesystem operations, such as delete files or meta data
 * updates can occur to files in the directory we're searching
 * between FIND_FIRST and FIND_NEXT calls we must refresh the cache
 * from the kernel on every new search SMB.
 *
 * @param[in] handle vfs handle given in most VFS calls
 * @param[in] dirp system DIR handle for the current search
 *
 * @return nothing
 */
void
onefs_init_search_op(vfs_handle_struct *handle,  SMB_STRUCT_DIR *dirp)
{
	/* Setting the rdp_last_dirp to NULL will cause the next readdir operation
	 * to refill the cache. */
	rdp_last_dirp = NULL;

	return;
}
