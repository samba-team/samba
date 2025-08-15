/*
   Unix SMB/CIFS implementation.
   Directory handling routines
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2007

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
#include "system/filesys.h"
#include "locking/share_mode_lock.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "libcli/security/security.h"
#include "lib/util/bitmap.h"
#include "../lib/util/memcache.h"
#include "../librpc/gen_ndr/open_files.h"
#include "lib/util/string_wrappers.h"
#include "libcli/smb/reparse.h"
#include "source3/smbd/dir.h"

/*
   This module implements directory related functions for Samba.
*/

/* "Special" directory offsets. */
#define END_OF_DIRECTORY_OFFSET ((long)-1)
#define START_OF_DIRECTORY_OFFSET ((long)0)
#define DOT_DOT_DIRECTORY_OFFSET ((long)0x80000000)

/* Make directory handle internals available. */

struct smb_Dir {
	connection_struct *conn;
	DIR *dir;
	struct smb_filename *dir_smb_fname;
	unsigned int file_number;
	bool case_sensitive;
	files_struct *fsp; /* Back pointer to containing fsp, only
			      set from OpenDir_fsp(). */
};

struct dptr_struct {
	struct dptr_struct *next, *prev;
	int dnum;
	struct smb_Dir *dir_hnd;
	char *wcard;
	uint32_t attr;
	bool has_wild; /* Set to true if the wcard entry has MS wildcard characters in it. */
	bool did_stat; /* Optimisation for non-wcard searches. */
	bool priv;     /* Directory handle opened with privilege. */
	uint32_t counter;

	char *last_name_sent;	/* for name-based trans2 resume */

	struct {
		char *fname;
		struct smb_filename *smb_fname;
		uint32_t mode;
	} overflow;
};

static NTSTATUS OpenDir_fsp(
	TALLOC_CTX *mem_ctx,
	connection_struct *conn,
	files_struct *fsp,
	const char *mask,
	uint32_t attr,
	struct smb_Dir **_dir_hnd);

static int smb_Dir_destructor(struct smb_Dir *dir_hnd);

#define INVALID_DPTR_KEY (-3)

/****************************************************************************
 Initialise the dir bitmap.
****************************************************************************/

bool init_dptrs(struct smbd_server_connection *sconn)
{
	if (sconn->searches.dptr_bmap) {
		return true;
	}

	sconn->searches.dptr_bmap = bitmap_talloc(
		sconn, MAX_DIRECTORY_HANDLES);

	if (sconn->searches.dptr_bmap == NULL) {
		return false;
	}

	return true;
}

/****************************************************************************
 Get the struct dptr_struct for a dir index.
****************************************************************************/

static struct dptr_struct *dptr_get(struct smbd_server_connection *sconn,
				    int key)
{
	struct dptr_struct *dptr;

	for (dptr = sconn->searches.dirptrs; dptr != NULL; dptr = dptr->next) {
		if(dptr->dnum != key) {
			continue;
		}
		DLIST_PROMOTE(sconn->searches.dirptrs, dptr);
		return dptr;
	}
	return(NULL);
}

/****************************************************************************
 Get the dir path for a dir index.
****************************************************************************/

const char *dptr_path(struct smbd_server_connection *sconn, int key)
{
	struct dptr_struct *dptr = dptr_get(sconn, key);
	if (dptr)
		return(dptr->dir_hnd->dir_smb_fname->base_name);
	return(NULL);
}

/****************************************************************************
 Get the dir wcard for a dir index.
****************************************************************************/

const char *dptr_wcard(struct smbd_server_connection *sconn, int key)
{
	struct dptr_struct *dptr = dptr_get(sconn, key);
	if (dptr)
		return(dptr->wcard);
	return(NULL);
}

/****************************************************************************
 Get the dir attrib for a dir index.
****************************************************************************/

uint16_t dptr_attr(struct smbd_server_connection *sconn, int key)
{
	struct dptr_struct *dptr = dptr_get(sconn, key);
	if (dptr)
		return(dptr->attr);
	return(0);
}

/****************************************************************************
 Close all dptrs for a cnum.
****************************************************************************/

void dptr_closecnum(connection_struct *conn)
{
	struct dptr_struct *dptr, *next;
	struct smbd_server_connection *sconn = conn->sconn;

	if (sconn == NULL) {
		return;
	}

	for(dptr = sconn->searches.dirptrs; dptr; dptr = next) {
		next = dptr->next;
		if (dptr->dir_hnd->conn == conn) {
			/*
			 * Need to make a copy, "dptr" will be gone
			 * after close_file_free() returns
			 */
			struct files_struct *fsp = dptr->dir_hnd->fsp;
			close_file_free(NULL, &fsp, NORMAL_CLOSE);
		}
	}
}

/****************************************************************************
 Create a new dir ptr. If the flag old_handle is true then we must allocate
 from the bitmap range 0 - 255 as old SMBsearch directory handles are only
 one byte long. If old_handle is false we allocate from the range
 256 - MAX_DIRECTORY_HANDLES. We bias the number we return by 1 to ensure
 a directory handle is never zero.
 wcard must not be zero.
****************************************************************************/

NTSTATUS dptr_create(connection_struct *conn,
		struct smb_request *req,
		files_struct *fsp,
		bool old_handle,
		const char *wcard,
		uint32_t attr,
		struct dptr_struct **dptr_ret)
{
	struct smbd_server_connection *sconn = conn->sconn;
	struct dptr_struct *dptr = NULL;
	struct smb_Dir *dir_hnd = NULL;
	NTSTATUS status;

	DBG_INFO("dir=%s\n", fsp_str_dbg(fsp));

	if (sconn == NULL) {
		DEBUG(0,("dptr_create: called with fake connection_struct\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (!wcard) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = check_any_access_fsp(fsp, SEC_DIR_LIST);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_INFO("dptr_create: directory %s "
			"not open for LIST access\n",
			fsp_str_dbg(fsp));
		return status;
	}
	status = OpenDir_fsp(NULL, conn, fsp, wcard, attr, &dir_hnd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dptr = talloc_zero(NULL, struct dptr_struct);
	if(!dptr) {
		DEBUG(0,("talloc fail in dptr_create.\n"));
		TALLOC_FREE(dir_hnd);
		return NT_STATUS_NO_MEMORY;
	}

	dptr->dir_hnd = dir_hnd;
	dptr->wcard = talloc_strdup(dptr, wcard);
	if (!dptr->wcard) {
		TALLOC_FREE(dptr);
		TALLOC_FREE(dir_hnd);
		return NT_STATUS_NO_MEMORY;
	}
	if ((req != NULL && req->posix_pathnames) || ISDOT(wcard)) {
		dptr->has_wild = True;
	} else {
		dptr->has_wild = ms_has_wild(dptr->wcard);
	}

	dptr->attr = attr;

	if (conn_using_smb2(sconn)) {
		goto done;
	}

	if(old_handle) {

		/*
		 * This is an old-style SMBsearch request. Ensure the
		 * value we return will fit in the range 1-255.
		 */

		dptr->dnum = bitmap_find(sconn->searches.dptr_bmap, 0);

		if(dptr->dnum == -1 || dptr->dnum > 254) {
			DBG_ERR("returned %d: Error - all old "
				"dirptrs in use ?\n",
				dptr->dnum);
			TALLOC_FREE(dptr);
			TALLOC_FREE(dir_hnd);
			return NT_STATUS_TOO_MANY_OPENED_FILES;
		}
	} else {

		/*
		 * This is a new-style trans2 request. Allocate from
		 * a range that will return 256 - MAX_DIRECTORY_HANDLES.
		 */

		dptr->dnum = bitmap_find(sconn->searches.dptr_bmap, 255);

		if(dptr->dnum == -1 || dptr->dnum < 255) {
			DBG_ERR("returned %d: Error - all new "
				"dirptrs in use ?\n",
				dptr->dnum);
			TALLOC_FREE(dptr);
			TALLOC_FREE(dir_hnd);
			return NT_STATUS_TOO_MANY_OPENED_FILES;
		}
	}

	bitmap_set(sconn->searches.dptr_bmap, dptr->dnum);

	dptr->dnum += 1; /* Always bias the dnum by one - no zero dnums allowed. */

	DLIST_ADD(sconn->searches.dirptrs, dptr);

done:
	DBG_INFO("creating new dirptr [%d] for path [%s]\n",
		 dptr->dnum, fsp_str_dbg(fsp));

	*dptr_ret = dptr;

	return NT_STATUS_OK;
}


/****************************************************************************
 Wrapper functions to access the lower level directory handles.
****************************************************************************/

void dptr_CloseDir(files_struct *fsp)
{
	struct smbd_server_connection *sconn = NULL;

	if (fsp->dptr == NULL) {
		return;
	}
	sconn = fsp->conn->sconn;

	/*
	 * The destructor for the struct smb_Dir (fsp->dptr->dir_hnd)
	 * now handles all resource deallocation.
	 */

	DBG_INFO("closing dptr key %d\n", fsp->dptr->dnum);

	if (sconn != NULL && !conn_using_smb2(sconn)) {
		DLIST_REMOVE(sconn->searches.dirptrs, fsp->dptr);

		/*
		 * Free the dnum in the bitmap. Remember the dnum value is
		 * always biased by one with respect to the bitmap.
		 */

		if (!bitmap_query(sconn->searches.dptr_bmap,
				  fsp->dptr->dnum - 1))
		{
			DBG_ERR("closing dnum = %d and bitmap not set !\n",
				fsp->dptr->dnum);
		}

		bitmap_clear(sconn->searches.dptr_bmap, fsp->dptr->dnum - 1);
	}

	TALLOC_FREE(fsp->dptr->dir_hnd);
	TALLOC_FREE(fsp->dptr);
}

void dptr_RewindDir(struct dptr_struct *dptr)
{
	RewindDir(dptr->dir_hnd);
	dptr->did_stat = false;
	TALLOC_FREE(dptr->overflow.fname);
	TALLOC_FREE(dptr->overflow.smb_fname);
}

unsigned int dptr_FileNumber(struct dptr_struct *dptr)
{
	return dptr->dir_hnd->file_number;
}

bool dptr_has_wild(struct dptr_struct *dptr)
{
	return dptr->has_wild;
}

int dptr_dnum(struct dptr_struct *dptr)
{
	return dptr->dnum;
}

bool dptr_get_priv(struct dptr_struct *dptr)
{
	return dptr->priv;
}

void dptr_set_priv(struct dptr_struct *dptr)
{
	dptr->priv = true;
}

bool dptr_case_sensitive(struct dptr_struct *dptr)
{
	return dptr->dir_hnd->case_sensitive;
}

/****************************************************************************
 Return the next visible file name, skipping veto'd and invisible files.
****************************************************************************/

char *dptr_ReadDirName(TALLOC_CTX *ctx, struct dptr_struct *dptr)
{
	struct stat_ex st = {
		.st_ex_nlink = 0,
	};
	struct smb_Dir *dir_hnd = dptr->dir_hnd;
	struct files_struct *dir_fsp = dir_hnd->fsp;
	struct smb_filename *dir_name = dir_fsp->fsp_name;
	struct smb_filename smb_fname_base;
	bool retry_scanning = false;
	int ret;
	int flags = 0;

	if (dptr->has_wild) {
		const char *name_temp = NULL;
		char *talloced = NULL;
		name_temp = ReadDirName(dir_hnd, &talloced);
		if (name_temp == NULL) {
			return NULL;
		}
		if (talloced != NULL) {
			return talloc_move(ctx, &talloced);
		}
		return talloc_strdup(ctx, name_temp);
	}

	if (dptr->did_stat) {
		/*
		 * No wildcard, this is not a real directory traverse
		 * but a "stat" call behind a query_directory. We've
		 * been here, nothing else to look at.
		 */
		return NULL;
	}
	dptr->did_stat = true;

	/* Create an smb_filename with stream_name == NULL. */
	smb_fname_base = (struct smb_filename){
		.base_name = dptr->wcard,
		.flags = dir_name->flags,
		.twrp = dir_name->twrp,
	};

	if (dir_name->flags & SMB_FILENAME_POSIX_PATH) {
		flags |= AT_SYMLINK_NOFOLLOW;
	}

	ret = SMB_VFS_FSTATAT(
		dir_hnd->conn, dir_fsp, &smb_fname_base, &st, flags);
	if (ret == 0) {
		return talloc_strdup(ctx, dptr->wcard);
	}

	/*
	 * If we get any other error than ENOENT or ENOTDIR
	 * then the file exists, we just can't stat it.
	 */
	if (errno != ENOENT && errno != ENOTDIR) {
		return talloc_strdup(ctx, dptr->wcard);
	}

	/*
	 * A scan will find the long version of a mangled name as
	 * wildcard.
	 */
	retry_scanning |= mangle_is_mangled(dptr->wcard,
					    dir_hnd->conn->params);

	/*
	 * Also retry scanning if the client requested case
	 * insensitive semantics and the file system does not provide
	 * it.
	 */
	retry_scanning |= (!dir_hnd->case_sensitive &&
			   (dir_hnd->conn->fs_capabilities &
			    FILE_CASE_SENSITIVE_SEARCH));

	if (retry_scanning) {
		char *found_name = NULL;
		NTSTATUS status;

		status = get_real_filename_at(dir_fsp,
					      dptr->wcard,
					      ctx,
					      &found_name);
		if (NT_STATUS_IS_OK(status)) {
			return found_name;
		}
	}

	return NULL;
}

struct files_struct *dir_hnd_fetch_fsp(struct smb_Dir *dir_hnd)
{
	return dir_hnd->fsp;
}

/****************************************************************************
 Fetch the fsp associated with the dptr_num.
****************************************************************************/

files_struct *dptr_fetch_lanman2_fsp(struct smbd_server_connection *sconn,
				       int dptr_num)
{
	struct dptr_struct *dptr  = dptr_get(sconn, dptr_num);
	if (dptr == NULL) {
		return NULL;
	}
	DBG_NOTICE("fetching dirptr %d for path %s\n",
		   dptr_num,
		   dptr->dir_hnd->dir_smb_fname->base_name);
	return dptr->dir_hnd->fsp;
}

bool smbd_dirptr_get_entry(TALLOC_CTX *ctx,
			   struct dptr_struct *dirptr,
			   const char *mask,
			   uint32_t dirtype,
			   bool dont_descend,
			   bool ask_sharemode,
			   bool get_dosmode_in,
			   bool (*match_fn)(TALLOC_CTX *ctx,
					    void *private_data,
					    const char *dname,
					    const char *mask,
					    char **_fname),
			   void *private_data,
			   char **_fname,
			   struct smb_filename **_smb_fname,
			   uint32_t *_mode)
{
	struct smb_Dir *dir_hnd = dirptr->dir_hnd;
	connection_struct *conn = dir_hnd->conn;
	struct smb_filename *dir_fname = dir_hnd->dir_smb_fname;
	bool posix = (dir_fname->flags & SMB_FILENAME_POSIX_PATH);
	const bool toplevel = ISDOT(dir_fname->base_name);
	NTSTATUS status;

	*_smb_fname = NULL;
	*_mode = 0;

	if (dirptr->overflow.smb_fname != NULL) {
		*_fname = talloc_move(ctx, &dirptr->overflow.fname);
		*_smb_fname = talloc_move(ctx, &dirptr->overflow.smb_fname);
		*_mode = dirptr->overflow.mode;
		return true;
	}

	if (dont_descend && (dptr_FileNumber(dirptr) >= 2)) {
		/*
		 * . and .. were returned first, we're done showing
		 * the directory as empty.
		 */
		return false;
	}

	while (true) {
		char *dname = NULL;
		char *fname = NULL;
		struct smb_filename *smb_fname = NULL;
		uint32_t mode = 0;
		bool get_dosmode = get_dosmode_in;
		bool toplevel_dotdot;
		bool visible;
		bool ok;

		dname = dptr_ReadDirName(ctx, dirptr);

		DBG_DEBUG("dir [%s] dirptr [%p] offset [%u] => "
			  "dname [%s]\n",
			  smb_fname_str_dbg(dir_fname),
			  dirptr,
			  dir_hnd->file_number,
			  dname ? dname : "(finished)");

		if (dname == NULL) {
			return false;
		}

		if (IS_VETO_PATH(conn, dname)) {
			TALLOC_FREE(dname);
			continue;
		}

		/*
		 * fname may get mangled, dname is never mangled.
		 * Whenever we're accessing the filesystem we use
		 * pathreal which is composed from dname.
		 */

		ok = match_fn(ctx, private_data, dname, mask, &fname);
		if (!ok) {
			TALLOC_FREE(dname);
			continue;
		}

		toplevel_dotdot = toplevel && ISDOTDOT(dname);

		smb_fname = synthetic_smb_fname(talloc_tos(),
						toplevel_dotdot ? "." : dname,
						NULL,
						NULL,
						dir_fname->twrp,
						dir_fname->flags);
		if (smb_fname == NULL) {
			TALLOC_FREE(dname);
			return false;
		}

		/*
		 * UCF_POSIX_PATHNAMES to avoid the readdir fallback
		 * if we get raced between readdir and unlink.
		 */
		status = openat_pathref_fsp_lcomp(dir_hnd->fsp,
						  smb_fname,
						  UCF_POSIX_PATHNAMES);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("Could not open %s: %s\n",
				  dname,
				  nt_errstr(status));
			TALLOC_FREE(smb_fname);
			TALLOC_FREE(fname);
			TALLOC_FREE(dname);
			continue;
		}

		visible = is_visible_fsp(smb_fname->fsp);
		if (!visible) {
			TALLOC_FREE(smb_fname);
			TALLOC_FREE(fname);
			TALLOC_FREE(dname);
			continue;
		}

		if (!S_ISLNK(smb_fname->st.st_ex_mode)) {
			goto done;
		}

		if (lp_host_msdfs() && lp_msdfs_root(SNUM(conn)) &&
		    is_msdfs_link(dir_hnd->fsp, smb_fname))
		{
			DBG_INFO("Masquerading msdfs link %s as a directory\n",
				 smb_fname->base_name);

			smb_fname->st.st_ex_mode = (smb_fname->st.st_ex_mode &
						    ~S_IFMT) |
						   S_IFDIR;
			smb_fname->fsp->fsp_name->st.st_ex_mode =
				smb_fname->st.st_ex_mode;

			mode = dos_mode_msdfs(conn, dname, &smb_fname->st);
			get_dosmode = false;
			ask_sharemode = false;
			goto done;
		}

		if (posix) {
			/*
			 * Posix always wants to see symlinks.
			 */
			ask_sharemode = false;
			goto done;
		}

		if (!lp_follow_symlinks(SNUM(conn))) {
			/*
			 * Hide symlinks not followed
			 */
			TALLOC_FREE(smb_fname);
			TALLOC_FREE(fname);
			TALLOC_FREE(dname);
			continue;
		}

		/*
		 * We have to find out if it's a dangling
		 * symlink. Use the fat logic behind
		 * openat_pathref_fsp().
		 */

		{
			struct files_struct *fsp = smb_fname->fsp;
			smb_fname_fsp_unlink(smb_fname);
			fd_close(fsp);
			file_free(NULL, fsp);
		}

		status = openat_pathref_fsp(dir_hnd->fsp, smb_fname);

		if (!NT_STATUS_IS_OK(status)) {
			/*
			 * Dangling symlink. Hide.
			 */
			TALLOC_FREE(smb_fname);
			TALLOC_FREE(fname);
			TALLOC_FREE(dname);
			continue;
		}

done:
		if (get_dosmode) {
			mode = fdos_mode(smb_fname->fsp);
			smb_fname->st = smb_fname->fsp->fsp_name->st;
		}

		if (!dir_check_ftype(mode, dirtype)) {
			DBG_INFO("[%s] attribs 0x%" PRIx32 " didn't match "
				 "0x%" PRIx32 "\n",
				 fname,
				 mode,
				 dirtype);
			TALLOC_FREE(smb_fname);
			TALLOC_FREE(dname);
			TALLOC_FREE(fname);
			continue;
		}

		if (ask_sharemode && !S_ISDIR(smb_fname->st.st_ex_mode)) {
			struct timespec write_time_ts;
			struct file_id fileid;

			fileid = vfs_file_id_from_sbuf(conn,
						       &smb_fname->st);
			get_file_infos(fileid, 0, NULL, &write_time_ts);
			if (!is_omit_timespec(&write_time_ts)) {
				update_stat_ex_mtime(&smb_fname->st,
						     write_time_ts);
			}
		}

		if (toplevel_dotdot) {
			/*
			 * Ensure posix fileid and sids are hidden
			 */
			smb_fname->st.st_ex_ino = 0;
			smb_fname->st.st_ex_dev = 0;
			smb_fname->st.st_ex_uid = -1;
			smb_fname->st.st_ex_gid = -1;
		}

		DBG_NOTICE("mask=[%s] found %s fname=%s (%s)\n",
			   mask,
			   smb_fname_str_dbg(smb_fname),
			   dname,
			   fname);

		TALLOC_FREE(dname);

		*_smb_fname = talloc_move(ctx, &smb_fname);
		*_fname = fname;
		*_mode = mode;

		return true;
	}

	return false;
}

void smbd_dirptr_push_overflow(struct dptr_struct *dirptr,
			       char **_fname,
			       struct smb_filename **_smb_fname,
			       uint32_t mode)
{
	SMB_ASSERT(dirptr->overflow.fname == NULL);
	SMB_ASSERT(dirptr->overflow.smb_fname == NULL);

	dirptr->overflow.fname = talloc_move(dirptr, _fname);
	dirptr->overflow.smb_fname = talloc_move(dirptr, _smb_fname);
	dirptr->overflow.mode = mode;
}

void smbd_dirptr_set_last_name_sent(struct dptr_struct *dirptr,
				    char **_fname)
{
	TALLOC_FREE(dirptr->last_name_sent);
	dirptr->last_name_sent = talloc_move(dirptr, _fname);
}

char *smbd_dirptr_get_last_name_sent(struct dptr_struct *dirptr)
{
	return dirptr->last_name_sent;
}

/*******************************************************************
 Check to see if a user can read an fsp . This is only approximate,
 it is used as part of the "hide unreadable" option. Don't
 use it for anything security sensitive.
********************************************************************/

static bool user_can_read_fsp(struct files_struct *fsp)
{
	NTSTATUS status;
	uint32_t rejected_share_access = 0;
	uint32_t rejected_mask = 0;
	struct security_descriptor *sd = NULL;
	uint32_t access_mask = FILE_READ_DATA|
				FILE_READ_EA|
				FILE_READ_ATTRIBUTES|
				SEC_STD_READ_CONTROL;

	/*
	 * Never hide files from the root user.
	 * We use (uid_t)0 here not sec_initial_uid()
	 * as make test uses a single user context.
	 */

	if (get_current_uid(fsp->conn) == (uid_t)0) {
		return true;
	}

	/*
	 * We can't directly use smbd_check_access_rights_fsp()
	 * here, as this implicitly grants FILE_READ_ATTRIBUTES
	 * which the Windows access-based-enumeration code
	 * explicitly checks for on the file security descriptor.
	 * See bug:
	 *
	 * https://bugzilla.samba.org/show_bug.cgi?id=10252
	 *
	 * and the smb2.acl2.ACCESSBASED test for details.
	 */

	rejected_share_access = access_mask & ~(fsp->conn->share_access);
	if (rejected_share_access) {
		DBG_DEBUG("rejected share access 0x%x "
			"on %s (0x%x)\n",
			(unsigned int)access_mask,
			fsp_str_dbg(fsp),
			(unsigned int)rejected_share_access);
		return false;
        }

	status = SMB_VFS_FGET_NT_ACL(metadata_fsp(fsp),
			(SECINFO_OWNER |
			 SECINFO_GROUP |
			 SECINFO_DACL),
			talloc_tos(),
			&sd);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Could not get acl "
			"on %s: %s\n",
			fsp_str_dbg(fsp),
			nt_errstr(status));
		return false;
	}

	status = se_file_access_check(sd,
				get_current_nttok(fsp->conn),
				false,
				access_mask,
				&rejected_mask);

	TALLOC_FREE(sd);

	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		DBG_DEBUG("rejected bits 0x%x read access for %s\n",
			(unsigned int)rejected_mask,
			fsp_str_dbg(fsp));
		return false;
        }
	return true;
}

/*******************************************************************
 Check to see if a user can write to an fsp.
 Always return true for directories.
 This is only approximate,
 it is used as part of the "hide unwriteable" option. Don't
 use it for anything security sensitive.
********************************************************************/

static bool user_can_write_fsp(struct files_struct *fsp)
{
	/*
	 * Never hide files from the root user.
	 * We use (uid_t)0 here not sec_initial_uid()
	 * as make test uses a single user context.
	 */

	if (get_current_uid(fsp->conn) == (uid_t)0) {
		return true;
	}

	if (fsp->fsp_flags.is_directory) {
		return true;
	}

	return can_write_to_fsp(fsp);
}

/*******************************************************************
  Is a file a "special" type ?
********************************************************************/

static bool file_is_special(connection_struct *conn,
			    const struct smb_filename *smb_fname)
{
	/*
	 * Never hide files from the root user.
	 * We use (uid_t)0 here not sec_initial_uid()
	 * as make test uses a single user context.
	 */

	if (get_current_uid(conn) == (uid_t)0) {
		return False;
	}

	SMB_ASSERT(VALID_STAT(smb_fname->st));

	if (S_ISREG(smb_fname->st.st_ex_mode) ||
	    S_ISDIR(smb_fname->st.st_ex_mode) ||
	    S_ISLNK(smb_fname->st.st_ex_mode))
		return False;

	return True;
}

/*******************************************************************
 Should the file be seen by the client?
********************************************************************/

bool is_visible_fsp(struct files_struct *fsp)
{
	bool hide_unreadable = false;
	bool hide_unwriteable = false;
	bool hide_special = false;
	int hide_new_files_timeout = 0;
	const char *last_component = NULL;

	/*
	 * If the file does not exist, there's no point checking
	 * the configuration options. We succeed, on the basis that the
	 * checks *might* have passed if the file was present.
	 */
	if (fsp == NULL) {
		return true;
	}

	hide_unreadable = lp_hide_unreadable(SNUM(fsp->conn));
	hide_unwriteable = lp_hide_unwriteable_files(SNUM(fsp->conn));
	hide_special = lp_hide_special_files(SNUM(fsp->conn));
	hide_new_files_timeout = lp_hide_new_files_timeout(SNUM(fsp->conn));

	if (!hide_unreadable &&
	    !hide_unwriteable &&
	    !hide_special &&
	    (hide_new_files_timeout == 0))
	{
		return true;
	}

	fsp = metadata_fsp(fsp);

	/* Get the last component of the base name. */
	last_component = strrchr_m(fsp->fsp_name->base_name, '/');
	if (!last_component) {
		last_component = fsp->fsp_name->base_name;
	} else {
		last_component++; /* Go past '/' */
	}

	if (ISDOT(last_component) || ISDOTDOT(last_component)) {
		return true; /* . and .. are always visible. */
	}

	if (fsp_get_pathref_fd(fsp) == -1) {
		/*
		 * Symlink in POSIX mode or MS-DFS.
		 * We've checked veto files so the
		 * only thing we can check is the
		 * hide_new_files_timeout.
		 */
		if ((hide_new_files_timeout != 0) &&
		    !S_ISDIR(fsp->fsp_name->st.st_ex_mode)) {
			double age = timespec_elapsed(
				&fsp->fsp_name->st.st_ex_mtime);

			if (age < (double)hide_new_files_timeout) {
				return false;
			}
		}
		return true;
	}

	/* Honour _hide unreadable_ option */
	if (hide_unreadable && !user_can_read_fsp(fsp)) {
		DBG_DEBUG("file %s is unreadable.\n", fsp_str_dbg(fsp));
		return false;
	}

	/* Honour _hide unwriteable_ option */
	if (hide_unwriteable && !user_can_write_fsp(fsp)) {
		DBG_DEBUG("file %s is unwritable.\n", fsp_str_dbg(fsp));
		return false;
	}

	/* Honour _hide_special_ option */
	if (hide_special && file_is_special(fsp->conn, fsp->fsp_name)) {
		DBG_DEBUG("file %s is special.\n", fsp_str_dbg(fsp));
		return false;
	}

	if ((hide_new_files_timeout != 0) &&
	    !S_ISDIR(fsp->fsp_name->st.st_ex_mode)) {
		double age = timespec_elapsed(&fsp->fsp_name->st.st_ex_mtime);

		if (age < (double)hide_new_files_timeout) {
			return false;
		}
	}

	return true;
}

static int smb_Dir_destructor(struct smb_Dir *dir_hnd)
{
	files_struct *fsp = dir_hnd->fsp;

	SMB_VFS_CLOSEDIR(dir_hnd->conn, dir_hnd->dir);
	fsp_set_fd(fsp, -1);
	if (fsp->dptr != NULL) {
		SMB_ASSERT(fsp->dptr->dir_hnd == dir_hnd);
		fsp->dptr->dir_hnd = NULL;
	}
	dir_hnd->fsp = NULL;
	return 0;
}

/*******************************************************************
 Open a directory.
********************************************************************/

static int smb_Dir_OpenDir_destructor(struct smb_Dir *dir_hnd)
{
	files_struct *fsp = dir_hnd->fsp;

	smb_Dir_destructor(dir_hnd);
	file_free(NULL, fsp);
	return 0;
}

NTSTATUS OpenDir(TALLOC_CTX *mem_ctx,
		 connection_struct *conn,
		 const struct smb_filename *smb_dname,
		 const char *mask,
		 uint32_t attr,
		 struct smb_Dir **_dir_hnd)
{
	struct files_struct *fsp = NULL;
	struct smb_Dir *dir_hnd = NULL;
	NTSTATUS status;

	status = open_internal_dirfsp(conn,
				      smb_dname,
				      O_RDONLY,
				      &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = OpenDir_fsp(mem_ctx, conn, fsp, mask, attr, &dir_hnd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * This overwrites the destructor set by OpenDir_fsp() but
	 * smb_Dir_OpenDir_destructor() calls the OpenDir_fsp()
	 * destructor.
	 */
	talloc_set_destructor(dir_hnd, smb_Dir_OpenDir_destructor);

	*_dir_hnd = dir_hnd;
	return NT_STATUS_OK;
}

NTSTATUS OpenDir_from_pathref(TALLOC_CTX *mem_ctx,
			      struct files_struct *dirfsp,
			      const char *mask,
			      uint32_t attr,
			      struct smb_Dir **_dir_hnd)
{
	struct files_struct *fsp = NULL;
	struct smb_Dir *dir_hnd = NULL;
	NTSTATUS status;

	status = openat_internal_dir_from_pathref(dirfsp, O_RDONLY, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = OpenDir_fsp(mem_ctx, fsp->conn, fsp, mask, attr, &dir_hnd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * This overwrites the destructor set by OpenDir_fsp() but
	 * smb_Dir_OpenDir_destructor() calls the OpenDir_fsp()
	 * destructor.
	 */
	talloc_set_destructor(dir_hnd, smb_Dir_OpenDir_destructor);

	*_dir_hnd = dir_hnd;
	return NT_STATUS_OK;
}

/*******************************************************************
 Open a directory from an fsp.
********************************************************************/

static NTSTATUS OpenDir_fsp(
	TALLOC_CTX *mem_ctx,
	connection_struct *conn,
	files_struct *fsp,
	const char *mask,
	uint32_t attr,
	struct smb_Dir **_dir_hnd)
{
	struct smb_Dir *dir_hnd = talloc_zero(mem_ctx, struct smb_Dir);
	NTSTATUS status;

	if (!dir_hnd) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!fsp->fsp_flags.is_directory) {
		status = NT_STATUS_INVALID_HANDLE;
		goto fail;
	}

	if (fsp_get_io_fd(fsp) == -1) {
		status = NT_STATUS_INVALID_HANDLE;
		goto fail;
	}

	dir_hnd->conn = conn;

	dir_hnd->dir_smb_fname = cp_smb_filename(dir_hnd, fsp->fsp_name);
	if (!dir_hnd->dir_smb_fname) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	dir_hnd->dir = SMB_VFS_FDOPENDIR(fsp, mask, attr);
	if (dir_hnd->dir == NULL) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}
	dir_hnd->fsp = fsp;
	if (fsp->posix_flags & FSP_POSIX_FLAGS_OPEN) {
		dir_hnd->case_sensitive = true;
	} else {
		dir_hnd->case_sensitive = conn->case_sensitive;
	}

	talloc_set_destructor(dir_hnd, smb_Dir_destructor);

	*_dir_hnd = dir_hnd;
	return NT_STATUS_OK;

  fail:
	TALLOC_FREE(dir_hnd);
	return status;
}


/*******************************************************************
 Read from a directory.
 Return directory entry, current offset, and optional stat information.
 Don't check for veto or invisible files.
********************************************************************/

const char *ReadDirName(struct smb_Dir *dir_hnd, char **ptalloced)
{
	const char *n;
	char *talloced = NULL;
	connection_struct *conn = dir_hnd->conn;

	if (dir_hnd->file_number < 2) {
		if (dir_hnd->file_number == 0) {
			n = ".";
		} else {
			n = "..";
		}
		dir_hnd->file_number++;
		*ptalloced = NULL;
		return n;
	}

	while ((n = vfs_readdirname(conn,
				    dir_hnd->fsp,
				    dir_hnd->dir,
				    &talloced))) {
		/* Ignore . and .. - we've already returned them. */
		if (ISDOT(n) || ISDOTDOT(n)) {
			TALLOC_FREE(talloced);
			continue;
		}
		*ptalloced = talloced;
		dir_hnd->file_number++;
		return n;
	}
	*ptalloced = NULL;
	return NULL;
}

/*******************************************************************
 Rewind to the start.
********************************************************************/

void RewindDir(struct smb_Dir *dir_hnd)
{
	SMB_VFS_REWINDDIR(dir_hnd->conn, dir_hnd->dir);
	dir_hnd->file_number = 0;
}

struct files_below_forall_state {
	char *dirpath;
	ssize_t dirpath_len;
	int (*fn)(struct file_id fid, const struct share_mode_data *data,
		  void *private_data);
	void *private_data;
};

static int files_below_forall_fn(struct file_id fid,
				 const struct share_mode_data *data,
				 void *private_data)
{
	struct files_below_forall_state *state = private_data;
	char tmpbuf[PATH_MAX];
	char *fullpath, *to_free;
	ssize_t len;

	len = full_path_tos(data->servicepath, data->base_name,
			    tmpbuf, sizeof(tmpbuf),
			    &fullpath, &to_free);
	if (len == -1) {
		return 0;
	}
	if (state->dirpath_len >= len) {
		/*
		 * Filter files above dirpath
		 */
		goto out;
	}
	if (fullpath[state->dirpath_len] != '/') {
		/*
		 * Filter file that don't have a path separator at the end of
		 * dirpath's length
		 */
		goto out;
	}

	if (memcmp(state->dirpath, fullpath, state->dirpath_len) != 0) {
		/*
		 * Not a parent
		 */
		goto out;
	}

	TALLOC_FREE(to_free);
	return state->fn(fid, data, state->private_data);

out:
	TALLOC_FREE(to_free);
	return 0;
}

static int files_below_forall(connection_struct *conn,
			      const struct smb_filename *dir_name,
			      int (*fn)(struct file_id fid,
					const struct share_mode_data *data,
					void *private_data),
			      void *private_data)
{
	struct files_below_forall_state state = {
			.fn = fn,
			.private_data = private_data,
	};
	int ret;
	char tmpbuf[PATH_MAX];
	char *to_free;

	state.dirpath_len = full_path_tos(conn->connectpath,
					  dir_name->base_name,
					  tmpbuf, sizeof(tmpbuf),
					  &state.dirpath, &to_free);
	if (state.dirpath_len == -1) {
		return -1;
	}

	ret = share_mode_forall(files_below_forall_fn, &state);
	TALLOC_FREE(to_free);
	return ret;
}

struct have_file_open_below_state {
	bool found_one;
};

static int have_file_open_below_fn(struct file_id fid,
				   const struct share_mode_data *data,
				   void *private_data)
{
	struct have_file_open_below_state *state = private_data;
	state->found_one = true;
	return 1;
}

bool have_file_open_below(connection_struct *conn,
				 const struct smb_filename *name)
{
	struct have_file_open_below_state state = {
		.found_one = false,
	};
	int ret;

	if (!VALID_STAT(name->st)) {
		return false;
	}
	if (!S_ISDIR(name->st.st_ex_mode)) {
		return false;
	}

	ret = files_below_forall(conn, name, have_file_open_below_fn, &state);
	if (ret == -1) {
		return false;
	}

	return state.found_one;
}

/*****************************************************************
 Is this directory empty ?
*****************************************************************/

NTSTATUS can_delete_directory_fsp(files_struct *fsp)
{
	NTSTATUS status = NT_STATUS_OK;
	const char *dname = NULL;
	char *talloced = NULL;
	struct connection_struct *conn = fsp->conn;
	struct smb_Dir *dir_hnd = NULL;

	status = OpenDir(
		talloc_tos(), conn, fsp->fsp_name, NULL, 0, &dir_hnd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	while ((dname = ReadDirName(dir_hnd, &talloced))) {
		struct smb_filename *smb_dname_full = NULL;
		struct smb_filename *direntry_fname = NULL;
		char *fullname = NULL;
		int ret;

		if (ISDOT(dname) || (ISDOTDOT(dname))) {
			TALLOC_FREE(talloced);
			continue;
		}
		if (IS_VETO_PATH(conn, dname)) {
			TALLOC_FREE(talloced);
			continue;
		}

		fullname = talloc_asprintf(talloc_tos(),
					   "%s/%s",
					   fsp->fsp_name->base_name,
					   dname);
		if (fullname == NULL) {
			status = NT_STATUS_NO_MEMORY;
                        break;
		}

		smb_dname_full = synthetic_smb_fname(talloc_tos(),
						     fullname,
						     NULL,
						     NULL,
						     fsp->fsp_name->twrp,
						     fsp->fsp_name->flags);
		if (smb_dname_full == NULL) {
			TALLOC_FREE(talloced);
			TALLOC_FREE(fullname);
			status = NT_STATUS_NO_MEMORY;
			break;
		}

		ret = SMB_VFS_LSTAT(conn, smb_dname_full);
		if (ret != 0) {
			status = map_nt_error_from_unix(errno);
			TALLOC_FREE(talloced);
			TALLOC_FREE(fullname);
			TALLOC_FREE(smb_dname_full);
			break;
		}

		if (S_ISLNK(smb_dname_full->st.st_ex_mode)) {
			/* Could it be an msdfs link ? */
			if (lp_host_msdfs() &&
			    lp_msdfs_root(SNUM(conn))) {
				struct smb_filename *smb_dname;
				smb_dname = synthetic_smb_fname(talloc_tos(),
							dname,
							NULL,
							&smb_dname_full->st,
							fsp->fsp_name->twrp,
							fsp->fsp_name->flags);
				if (smb_dname == NULL) {
					TALLOC_FREE(talloced);
					TALLOC_FREE(fullname);
					TALLOC_FREE(smb_dname_full);
					status = NT_STATUS_NO_MEMORY;
					break;
				}
				if (is_msdfs_link(fsp, smb_dname)) {
					TALLOC_FREE(talloced);
					TALLOC_FREE(fullname);
					TALLOC_FREE(smb_dname_full);
					TALLOC_FREE(smb_dname);
					DBG_DEBUG("got msdfs link name %s "
						"- can't delete directory %s\n",
						dname,
						fsp_str_dbg(fsp));
					status = NT_STATUS_DIRECTORY_NOT_EMPTY;
					break;
				}
				TALLOC_FREE(smb_dname);
			}
			/* Not a DFS link - could it be a dangling symlink ? */
			ret = SMB_VFS_STAT(conn, smb_dname_full);
			if (ret == -1 && (errno == ENOENT || errno == ELOOP)) {
				/*
				 * Dangling symlink.
				 * Allow if "delete veto files = yes"
				 */
				if (lp_delete_veto_files(SNUM(conn))) {
					TALLOC_FREE(talloced);
					TALLOC_FREE(fullname);
					TALLOC_FREE(smb_dname_full);
					continue;
				}
			}
			DBG_DEBUG("got symlink name %s - "
				"can't delete directory %s\n",
				dname,
				fsp_str_dbg(fsp));
			TALLOC_FREE(talloced);
			TALLOC_FREE(fullname);
			TALLOC_FREE(smb_dname_full);
			status = NT_STATUS_DIRECTORY_NOT_EMPTY;
			break;
		}

		/* Not a symlink, get a pathref. */
		status = synthetic_pathref(talloc_tos(),
					   fsp,
					   dname,
					   NULL,
					   &smb_dname_full->st,
					   fsp->fsp_name->twrp,
					   fsp->fsp_name->flags,
					   &direntry_fname);
		if (!NT_STATUS_IS_OK(status)) {
			status = map_nt_error_from_unix(errno);
			TALLOC_FREE(talloced);
			TALLOC_FREE(fullname);
			TALLOC_FREE(smb_dname_full);
			break;
		}

		if (!is_visible_fsp(direntry_fname->fsp)) {
			/*
			 * Hidden file.
			 * Allow if "delete veto files = yes"
			 */
			if (lp_delete_veto_files(SNUM(conn))) {
				TALLOC_FREE(talloced);
				TALLOC_FREE(fullname);
				TALLOC_FREE(smb_dname_full);
				TALLOC_FREE(direntry_fname);
				continue;
			}
		}

		TALLOC_FREE(talloced);
		TALLOC_FREE(fullname);
		TALLOC_FREE(smb_dname_full);
		TALLOC_FREE(direntry_fname);

		DBG_DEBUG("got name %s - can't delete\n", dname);
		status = NT_STATUS_DIRECTORY_NOT_EMPTY;
		break;
	}
	TALLOC_FREE(talloced);
	TALLOC_FREE(dir_hnd);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!(fsp->posix_flags & FSP_POSIX_FLAGS_RENAME) &&
	    lp_strict_rename(SNUM(conn)) &&
	    have_file_open_below(fsp->conn, fsp->fsp_name))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}
