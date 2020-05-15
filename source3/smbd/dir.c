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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "libcli/security/security.h"
#include "lib/util/bitmap.h"
#include "../lib/util/memcache.h"
#include "../librpc/gen_ndr/open_files.h"

/*
   This module implements directory related functions for Samba.
*/

/* "Special" directory offsets. */
#define END_OF_DIRECTORY_OFFSET ((long)-1)
#define START_OF_DIRECTORY_OFFSET ((long)0)
#define DOT_DOT_DIRECTORY_OFFSET ((long)0x80000000)

/* "Special" directory offsets in 32-bit wire format. */
#define WIRE_END_OF_DIRECTORY_OFFSET ((uint32_t)0xFFFFFFFF)
#define WIRE_START_OF_DIRECTORY_OFFSET ((uint32_t)0)
#define WIRE_DOT_DOT_DIRECTORY_OFFSET ((uint32_t)0x80000000)

/* Make directory handle internals available. */

struct name_cache_entry {
	char *name;
	long offset;
};

struct smb_Dir {
	connection_struct *conn;
	DIR *dir;
	long offset;
	struct smb_filename *dir_smb_fname;
	size_t name_cache_size;
	struct name_cache_entry *name_cache;
	unsigned int name_cache_index;
	unsigned int file_number;
	files_struct *fsp; /* Back pointer to containing fsp, only
			      set from OpenDir_fsp(). */
};

struct dptr_struct {
	struct dptr_struct *next, *prev;
	int dnum;
	uint16_t spid;
	struct connection_struct *conn;
	struct smb_Dir *dir_hnd;
	bool expect_close;
	char *wcard;
	uint32_t attr;
	struct smb_filename *smb_dname;
	bool has_wild; /* Set to true if the wcard entry has MS wildcard characters in it. */
	bool did_stat; /* Optimisation for non-wcard searches. */
	bool priv;     /* Directory handle opened with privilege. */
	uint32_t counter;
	struct memcache *dptr_cache;
};

static struct smb_Dir *OpenDir_fsp(TALLOC_CTX *mem_ctx, connection_struct *conn,
			files_struct *fsp,
			const char *mask,
			uint32_t attr);

static void DirCacheAdd(struct smb_Dir *dir_hnd, const char *name, long offset);

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
		return(dptr->smb_dname->base_name);
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
		if (dptr->conn == conn) {
			files_struct *fsp = dptr->dir_hnd->fsp;
			close_file(NULL, fsp, NORMAL_CLOSE);
			fsp = NULL;
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
		bool expect_close,
		uint16_t spid,
		const char *wcard,
		bool wcard_has_wild,
		uint32_t attr,
		struct dptr_struct **dptr_ret)
{
	struct smbd_server_connection *sconn = conn->sconn;
	struct dptr_struct *dptr = NULL;
	struct smb_Dir *dir_hnd;

	DBG_INFO("dir=%s\n", fsp_str_dbg(fsp));

	if (sconn == NULL) {
		DEBUG(0,("dptr_create: called with fake connection_struct\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (!wcard) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!(fsp->access_mask & SEC_DIR_LIST)) {
		DBG_INFO("dptr_create: directory %s "
			"not open for LIST access\n",
			fsp_str_dbg(fsp));
		return NT_STATUS_ACCESS_DENIED;
	}
	dir_hnd = OpenDir_fsp(NULL, conn, fsp, wcard, attr);
	if (!dir_hnd) {
		return map_nt_error_from_unix(errno);
	}

	dptr = talloc_zero(NULL, struct dptr_struct);
	if(!dptr) {
		DEBUG(0,("talloc fail in dptr_create.\n"));
		TALLOC_FREE(dir_hnd);
		return NT_STATUS_NO_MEMORY;
	}

	dptr->smb_dname = cp_smb_filename(dptr, fsp->fsp_name);
	if (dptr->smb_dname == NULL) {
		TALLOC_FREE(dptr);
		TALLOC_FREE(dir_hnd);
		return NT_STATUS_NO_MEMORY;
	}
	dptr->conn = conn;
	dptr->dir_hnd = dir_hnd;
	dptr->spid = spid;
	dptr->expect_close = expect_close;
	dptr->wcard = talloc_strdup(dptr, wcard);
	if (!dptr->wcard) {
		TALLOC_FREE(dptr);
		TALLOC_FREE(dir_hnd);
		return NT_STATUS_NO_MEMORY;
	}
	if ((req != NULL && req->posix_pathnames) ||
			(wcard[0] == '.' && wcard[1] == 0)) {
		dptr->has_wild = True;
	} else {
		dptr->has_wild = wcard_has_wild;
	}

	dptr->attr = attr;

	if (sconn->using_smb2) {
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
	DBG_INFO("creating new dirptr [%d] for path [%s], expect_close = %d\n",
		 dptr->dnum, fsp_str_dbg(fsp), expect_close);

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
	sconn = fsp->dptr->conn->sconn;

	/*
	 * The destructor for the struct smb_Dir (fsp->dptr->dir_hnd)
	 * now handles all resource deallocation.
	 */

	DBG_INFO("closing dptr key %d\n", fsp->dptr->dnum);

	if (sconn != NULL && !sconn->using_smb2) {
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

void dptr_SeekDir(struct dptr_struct *dptr, long offset)
{
	SeekDir(dptr->dir_hnd, offset);
}

long dptr_TellDir(struct dptr_struct *dptr)
{
	return TellDir(dptr->dir_hnd);
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

/****************************************************************************
 Return the next visible file name, skipping veto'd and invisible files.
****************************************************************************/

static const char *dptr_normal_ReadDirName(struct dptr_struct *dptr,
					   long *poffset, SMB_STRUCT_STAT *pst,
					   char **ptalloced)
{
	/* Normal search for the next file. */
	const char *name;
	char *talloced = NULL;

	while ((name = ReadDirName(dptr->dir_hnd, poffset, pst, &talloced))
	       != NULL) {
		if (is_visible_file(dptr->conn,
				dptr->dir_hnd,
				name,
				pst,
				true)) {
			*ptalloced = talloced;
			return name;
		}
		TALLOC_FREE(talloced);
	}
	return NULL;
}

/****************************************************************************
 Return the next visible file name, skipping veto'd and invisible files.
****************************************************************************/

static char *dptr_ReadDirName(TALLOC_CTX *ctx,
			      struct dptr_struct *dptr,
			      long *poffset,
			      SMB_STRUCT_STAT *pst)
{
	struct smb_filename smb_fname_base;
	char *name = NULL;
	const char *name_temp = NULL;
	char *talloced = NULL;
	char *pathreal = NULL;
	char *found_name = NULL;
	int ret;

	SET_STAT_INVALID(*pst);

	if (dptr->has_wild || dptr->did_stat) {
		name_temp = dptr_normal_ReadDirName(dptr, poffset, pst,
						    &talloced);
		if (name_temp == NULL) {
			return NULL;
		}
		if (talloced != NULL) {
			return talloc_move(ctx, &talloced);
		}
		return talloc_strdup(ctx, name_temp);
	}

	/* If poffset is -1 then we know we returned this name before and we
	 * have no wildcards. We're at the end of the directory. */
	if (*poffset == END_OF_DIRECTORY_OFFSET) {
		return NULL;
	}

	/* We know the stored wcard contains no wildcard characters.
	 * See if we can match with a stat call. If we can't, then set
	 * did_stat to true to ensure we only do this once and keep
	 * searching. */

	dptr->did_stat = true;

	/* First check if it should be visible. */
	if (!is_visible_file(dptr->conn,
			dptr->dir_hnd,
			dptr->wcard,
			pst,
			true)) {
		/* This only returns false if the file was found, but
		   is explicitly not visible. Set us to end of
		   directory, but return NULL as we know we can't ever
		   find it. */
		goto ret;
	}

	if (VALID_STAT(*pst)) {
		name = talloc_strdup(ctx, dptr->wcard);
		goto ret;
	}

	pathreal = talloc_asprintf(ctx,
				"%s/%s",
				dptr->smb_dname->base_name,
				dptr->wcard);
	if (!pathreal)
		return NULL;

	/* Create an smb_filename with stream_name == NULL. */
	smb_fname_base = (struct smb_filename) {
		.base_name = pathreal,
		.twrp = dptr->smb_dname->twrp,
	};

	if (SMB_VFS_STAT(dptr->conn, &smb_fname_base) == 0) {
		*pst = smb_fname_base.st;
		name = talloc_strdup(ctx, dptr->wcard);
		goto clean;
	} else {
		/* If we get any other error than ENOENT or ENOTDIR
		   then the file exists we just can't stat it. */
		if (errno != ENOENT && errno != ENOTDIR) {
			name = talloc_strdup(ctx, dptr->wcard);
			goto clean;
		}
	}

	/* Stat failed. We know this is authoratiative if we are
	 * providing case sensitive semantics or the underlying
	 * filesystem is case sensitive.
	 */
	if (dptr->conn->case_sensitive ||
	    !(dptr->conn->fs_capabilities & FILE_CASE_SENSITIVE_SEARCH))
	{
		goto clean;
	}

	/*
	 * Try case-insensitive stat if the fs has the ability. This avoids
	 * scanning the whole directory.
	 */
	ret = SMB_VFS_GET_REAL_FILENAME(dptr->conn,
					dptr->smb_dname,
					dptr->wcard,
					ctx,
					&found_name);
	if (ret == 0) {
		name = found_name;
		goto clean;
	} else if (errno == ENOENT) {
		/* The case-insensitive lookup was authoritative. */
		goto clean;
	}

	TALLOC_FREE(pathreal);

	name_temp = dptr_normal_ReadDirName(dptr, poffset, pst, &talloced);
	if (name_temp == NULL) {
		return NULL;
	}
	if (talloced != NULL) {
		return talloc_move(ctx, &talloced);
	}
	return talloc_strdup(ctx, name_temp);

clean:
	TALLOC_FREE(pathreal);
ret:
	/* We need to set the underlying dir_hnd offset to -1
	 * also as this function is usually called with the
	 * output from TellDir. */
	dptr->dir_hnd->offset = *poffset = END_OF_DIRECTORY_OFFSET;
	return name;
}

/****************************************************************************
 Search for a file by name, skipping veto'ed and not visible files.
****************************************************************************/

bool dptr_SearchDir(struct dptr_struct *dptr, const char *name, long *poffset, SMB_STRUCT_STAT *pst)
{
	SET_STAT_INVALID(*pst);

	if (!dptr->has_wild && (dptr->dir_hnd->offset == END_OF_DIRECTORY_OFFSET)) {
		/* This is a singleton directory and we're already at the end. */
		*poffset = END_OF_DIRECTORY_OFFSET;
		return False;
	}

	return SearchDir(dptr->dir_hnd, name, poffset);
}

/****************************************************************************
 Map a native directory offset to a 32-bit cookie.
****************************************************************************/

static uint32_t map_dir_offset_to_wire(struct dptr_struct *dptr, long offset)
{
	DATA_BLOB key;
	DATA_BLOB val;

	if (offset == END_OF_DIRECTORY_OFFSET) {
		return WIRE_END_OF_DIRECTORY_OFFSET;
	} else if(offset == START_OF_DIRECTORY_OFFSET) {
		return WIRE_START_OF_DIRECTORY_OFFSET;
	} else if (offset == DOT_DOT_DIRECTORY_OFFSET) {
		return WIRE_DOT_DOT_DIRECTORY_OFFSET;
	}
	if (sizeof(long) == 4) {
		/* 32-bit machine. We can cheat... */
		return (uint32_t)offset;
	}
	if (dptr->dptr_cache == NULL) {
		/* Lazy initialize cache. */
		dptr->dptr_cache = memcache_init(dptr, 0);
		if (dptr->dptr_cache == NULL) {
			return WIRE_END_OF_DIRECTORY_OFFSET;
		}
	} else {
		/* Have we seen this offset before ? */
		key.data = (void *)&offset;
		key.length = sizeof(offset);
		if (memcache_lookup(dptr->dptr_cache,
					SMB1_SEARCH_OFFSET_MAP,
					key,
					&val)) {
			uint32_t wire_offset;
			SMB_ASSERT(val.length == sizeof(wire_offset));
			memcpy(&wire_offset, val.data, sizeof(wire_offset));
			DEBUG(10,("found wire %u <-> offset %ld\n",
				(unsigned int)wire_offset,
				(long)offset));
			return wire_offset;
		}
	}
	/* Allocate a new wire cookie. */
	do {
		dptr->counter++;
	} while (dptr->counter == WIRE_START_OF_DIRECTORY_OFFSET ||
		 dptr->counter == WIRE_END_OF_DIRECTORY_OFFSET ||
		 dptr->counter == WIRE_DOT_DOT_DIRECTORY_OFFSET);
	/* Store it in the cache. */
	key.data = (void *)&offset;
	key.length = sizeof(offset);
	val.data = (void *)&dptr->counter;
	val.length = sizeof(dptr->counter); /* MUST BE uint32_t ! */
	memcache_add(dptr->dptr_cache,
			SMB1_SEARCH_OFFSET_MAP,
			key,
			val);
	/* And the reverse mapping for lookup from
	   map_wire_to_dir_offset(). */
	memcache_add(dptr->dptr_cache,
			SMB1_SEARCH_OFFSET_MAP,
			val,
			key);
	DEBUG(10,("stored wire %u <-> offset %ld\n",
		(unsigned int)dptr->counter,
		(long)offset));
	return dptr->counter;
}

/****************************************************************************
 Fill the 5 byte server reserved dptr field.
****************************************************************************/

bool dptr_fill(struct smbd_server_connection *sconn,
	       char *buf1,unsigned int key)
{
	unsigned char *buf = (unsigned char *)buf1;
	struct dptr_struct *dptr = dptr_get(sconn, key);
	uint32_t wire_offset;
	if (!dptr) {
		DEBUG(1,("filling null dirptr %d\n",key));
		return(False);
	}
	wire_offset = map_dir_offset_to_wire(dptr,TellDir(dptr->dir_hnd));
	DEBUG(6,("fill on key %u dirptr 0x%lx now at %d\n",key,
		(long)dptr->dir_hnd,(int)wire_offset));
	buf[0] = key;
	SIVAL(buf,1,wire_offset);
	return(True);
}

/****************************************************************************
 Map a 32-bit wire cookie to a native directory offset.
****************************************************************************/

static long map_wire_to_dir_offset(struct dptr_struct *dptr, uint32_t wire_offset)
{
	DATA_BLOB key;
	DATA_BLOB val;

	if (wire_offset == WIRE_END_OF_DIRECTORY_OFFSET) {
		return END_OF_DIRECTORY_OFFSET;
	} else if(wire_offset == WIRE_START_OF_DIRECTORY_OFFSET) {
		return START_OF_DIRECTORY_OFFSET;
	} else if (wire_offset == WIRE_DOT_DOT_DIRECTORY_OFFSET) {
		return DOT_DOT_DIRECTORY_OFFSET;
	}
	if (sizeof(long) == 4) {
		/* 32-bit machine. We can cheat... */
		return (long)wire_offset;
	}
	if (dptr->dptr_cache == NULL) {
		/* Logic error, cache should be initialized. */
		return END_OF_DIRECTORY_OFFSET;
	}
	key.data = (void *)&wire_offset;
	key.length = sizeof(wire_offset);
	if (memcache_lookup(dptr->dptr_cache,
				SMB1_SEARCH_OFFSET_MAP,
				key,
				&val)) {
		/* Found mapping. */
		long offset;
		SMB_ASSERT(val.length == sizeof(offset));
		memcpy(&offset, val.data, sizeof(offset));
		DEBUG(10,("lookup wire %u <-> offset %ld\n",
			(unsigned int)wire_offset,
			(long)offset));
		return offset;
	}
	return END_OF_DIRECTORY_OFFSET;
}

/****************************************************************************
 Return the associated fsp and seek the dir_hnd on it it given the 5 byte
 server field.
****************************************************************************/

files_struct *dptr_fetch_fsp(struct smbd_server_connection *sconn,
			       char *buf, int *num)
{
	unsigned int key = *(unsigned char *)buf;
	struct dptr_struct *dptr = dptr_get(sconn, key);
	uint32_t wire_offset;
	long seekoff;

	if (dptr == NULL) {
		DEBUG(3,("fetched null dirptr %d\n",key));
		return(NULL);
	}
	*num = key;
	wire_offset = IVAL(buf,1);
	seekoff = map_wire_to_dir_offset(dptr, wire_offset);
	SeekDir(dptr->dir_hnd,seekoff);
	DEBUG(3,("fetching dirptr %d for path %s at offset %d\n",
		key, dptr->smb_dname->base_name, (int)seekoff));
	return dptr->dir_hnd->fsp;
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
		dptr->smb_dname->base_name);
	return dptr->dir_hnd->fsp;
}

static bool mangle_mask_match(connection_struct *conn,
		const char *filename,
		const char *mask)
{
	char mname[13];

	if (!name_to_8_3(filename,mname,False,conn->params)) {
		return False;
	}
	return mask_match_search(mname,mask,False);
}

bool smbd_dirptr_get_entry(TALLOC_CTX *ctx,
			   struct dptr_struct *dirptr,
			   const char *mask,
			   uint32_t dirtype,
			   bool dont_descend,
			   bool ask_sharemode,
			   bool get_dosmode,
			   bool (*match_fn)(TALLOC_CTX *ctx,
					    void *private_data,
					    const char *dname,
					    const char *mask,
					    char **_fname),
			   bool (*mode_fn)(TALLOC_CTX *ctx,
					   void *private_data,
					   struct smb_filename *smb_fname,
					   bool get_dosmode,
					   uint32_t *_mode),
			   void *private_data,
			   char **_fname,
			   struct smb_filename **_smb_fname,
			   uint32_t *_mode,
			   long *_prev_offset)
{
	connection_struct *conn = dirptr->conn;
	size_t slashlen;
	size_t pathlen;
	const char *dpath = dirptr->smb_dname->base_name;
	bool dirptr_path_is_dot = ISDOT(dpath);

	*_smb_fname = NULL;
	*_mode = 0;

	pathlen = strlen(dpath);
	slashlen = ( dpath[pathlen-1] != '/') ? 1 : 0;

	while (true) {
		long cur_offset;
		long prev_offset;
		SMB_STRUCT_STAT sbuf = { 0 };
		char *dname = NULL;
		bool isdots;
		char *fname = NULL;
		char *pathreal = NULL;
		struct smb_filename smb_fname;
		uint32_t mode = 0;
		bool ok;

		cur_offset = dptr_TellDir(dirptr);
		prev_offset = cur_offset;
		dname = dptr_ReadDirName(ctx, dirptr, &cur_offset, &sbuf);

		DEBUG(6,("smbd_dirptr_get_entry: dirptr 0x%lx now at offset %ld\n",
			(long)dirptr, cur_offset));

		if (dname == NULL) {
			return false;
		}

		isdots = (ISDOT(dname) || ISDOTDOT(dname));
		if (dont_descend && !isdots) {
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

		/*
		 * This used to be
		 * pathreal = talloc_asprintf(ctx, "%s%s%s", dirptr->path,
		 *			      needslash?"/":"", dname);
		 * but this was measurably slower than doing the memcpy.
		 */

		pathreal = talloc_array(
			ctx, char,
			pathlen + slashlen + talloc_get_size(dname));
		if (!pathreal) {
			TALLOC_FREE(dname);
			TALLOC_FREE(fname);
			return false;
		}

		/*
		 * We don't want to pass ./xxx to modules below us so don't
		 * add the path if it is just . by itself.
		 */
		if (dirptr_path_is_dot) {
			memcpy(pathreal, dname, talloc_get_size(dname));
		} else {
			memcpy(pathreal, dpath, pathlen);
			pathreal[pathlen] = '/';
			memcpy(pathreal + slashlen + pathlen, dname,
			       talloc_get_size(dname));
		}

		/* Create smb_fname with NULL stream_name. */
		smb_fname = (struct smb_filename) {
			.base_name = pathreal,
			.st = sbuf,
			.twrp = dirptr->smb_dname->twrp,
		};

		ok = mode_fn(ctx, private_data, &smb_fname, get_dosmode, &mode);
		if (!ok) {
			TALLOC_FREE(dname);
			TALLOC_FREE(fname);
			TALLOC_FREE(pathreal);
			continue;
		}

		if (!dir_check_ftype(mode, dirtype)) {
			DEBUG(5,("[%s] attribs 0x%x didn't match 0x%x\n",
				fname, (unsigned int)mode, (unsigned int)dirtype));
			TALLOC_FREE(dname);
			TALLOC_FREE(fname);
			TALLOC_FREE(pathreal);
			continue;
		}

		if (ask_sharemode && !S_ISDIR(smb_fname.st.st_ex_mode)) {
			struct timespec write_time_ts;
			struct file_id fileid;

			fileid = vfs_file_id_from_sbuf(conn,
						       &smb_fname.st);
			get_file_infos(fileid, 0, NULL, &write_time_ts);
			if (!is_omit_timespec(&write_time_ts)) {
				update_stat_ex_mtime(&smb_fname.st,
						     write_time_ts);
			}
		}

		DEBUG(3,("smbd_dirptr_get_entry mask=[%s] found %s "
			"fname=%s (%s)\n",
			mask, smb_fname_str_dbg(&smb_fname),
			dname, fname));

		if (!conn->sconn->using_smb2) {
			/*
			 * The dircache is only needed for SMB1 because SMB1
			 * uses a name for the resume wheras SMB2 always
			 * continues from the next position (unless it's told to
			 * restart or close-and-reopen the listing).
			 */
			DirCacheAdd(dirptr->dir_hnd, dname, cur_offset);
		}

		TALLOC_FREE(dname);

		*_smb_fname = cp_smb_filename(ctx, &smb_fname);
		TALLOC_FREE(pathreal);
		if (*_smb_fname == NULL) {
			return false;
		}
		*_fname = fname;
		*_mode = mode;
		*_prev_offset = prev_offset;

		return true;
	}

	return false;
}

/****************************************************************************
 Get an 8.3 directory entry.
****************************************************************************/

static bool smbd_dirptr_8_3_match_fn(TALLOC_CTX *ctx,
				     void *private_data,
				     const char *dname,
				     const char *mask,
				     char **_fname)
{
	connection_struct *conn = (connection_struct *)private_data;

	if ((strcmp(mask,"*.*") == 0) ||
	    mask_match_search(dname, mask, false) ||
	    mangle_mask_match(conn, dname, mask)) {
		char mname[13];
		const char *fname;
		/*
		 * Ensure we can push the original name as UCS2. If
		 * not, then just don't return this name.
		 */
		NTSTATUS status;
		size_t ret_len = 0;
		size_t len = (strlen(dname) + 2) * 4; /* Allow enough space. */
		uint8_t *tmp = talloc_array(talloc_tos(),
					uint8_t,
					len);

		status = srvstr_push(NULL,
			FLAGS2_UNICODE_STRINGS,
			tmp,
			dname,
			len,
			STR_TERMINATE,
			&ret_len);

		TALLOC_FREE(tmp);

		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		if (!mangle_is_8_3(dname, false, conn->params)) {
			bool ok = name_to_8_3(dname, mname, false,
					      conn->params);
			if (!ok) {
				return false;
			}
			fname = mname;
		} else {
			fname = dname;
		}

		*_fname = talloc_strdup(ctx, fname);
		if (*_fname == NULL) {
			return false;
		}

		return true;
	}

	return false;
}

static bool smbd_dirptr_8_3_mode_fn(TALLOC_CTX *ctx,
				    void *private_data,
				    struct smb_filename *smb_fname,
				    bool get_dosmode,
				    uint32_t *_mode)
{
	connection_struct *conn = (connection_struct *)private_data;

	if (!VALID_STAT(smb_fname->st)) {
		if ((SMB_VFS_STAT(conn, smb_fname)) != 0) {
			DEBUG(5,("smbd_dirptr_8_3_mode_fn: "
				 "Couldn't stat [%s]. Error "
			         "= %s\n",
			         smb_fname_str_dbg(smb_fname),
			         strerror(errno)));
			return false;
		}
	}

	*_mode = dos_mode(conn, smb_fname);
	return true;
}

bool get_dir_entry(TALLOC_CTX *ctx,
		struct dptr_struct *dirptr,
		const char *mask,
		uint32_t dirtype,
		char **_fname,
		off_t *_size,
		uint32_t *_mode,
		struct timespec *_date,
		bool check_descend,
		bool ask_sharemode)
{
	connection_struct *conn = dirptr->conn;
	char *fname = NULL;
	struct smb_filename *smb_fname = NULL;
	uint32_t mode = 0;
	long prev_offset;
	bool ok;

	ok = smbd_dirptr_get_entry(ctx,
				   dirptr,
				   mask,
				   dirtype,
				   check_descend,
				   ask_sharemode,
				   true,
				   smbd_dirptr_8_3_match_fn,
				   smbd_dirptr_8_3_mode_fn,
				   conn,
				   &fname,
				   &smb_fname,
				   &mode,
				   &prev_offset);
	if (!ok) {
		return false;
	}

	*_fname = talloc_move(ctx, &fname);
	*_size = smb_fname->st.st_ex_size;
	*_mode = mode;
	*_date = smb_fname->st.st_ex_mtime;
	TALLOC_FREE(smb_fname);
	return true;
}

/*******************************************************************
 Check to see if a user can read a file. This is only approximate,
 it is used as part of the "hide unreadable" option. Don't
 use it for anything security sensitive.
********************************************************************/

static bool user_can_read_file(connection_struct *conn,
				struct files_struct *dirfsp,
				struct smb_filename *smb_fname)
{
	NTSTATUS status;
	uint32_t rejected_share_access = 0;
	uint32_t rejected_mask = 0;
	struct security_descriptor *sd = NULL;
	uint32_t access_mask = FILE_READ_DATA|
				FILE_READ_EA|
				FILE_READ_ATTRIBUTES|
				SEC_STD_READ_CONTROL;

	SMB_ASSERT(dirfsp == conn->cwd_fsp);

	/*
	 * Never hide files from the root user.
	 * We use (uid_t)0 here not sec_initial_uid()
	 * as make test uses a single user context.
	 */

	if (get_current_uid(conn) == (uid_t)0) {
		return True;
	}

	/*
	 * We can't directly use smbd_check_access_rights()
	 * here, as this implicitly grants FILE_READ_ATTRIBUTES
	 * which the Windows access-based-enumeration code
	 * explicitly checks for on the file security descriptor.
	 * See bug:
	 *
	 * https://bugzilla.samba.org/show_bug.cgi?id=10252
	 *
	 * and the smb2.acl2.ACCESSBASED test for details.
	 */

	rejected_share_access = access_mask & ~(conn->share_access);
	if (rejected_share_access) {
		DEBUG(10, ("rejected share access 0x%x "
			"on %s (0x%x)\n",
			(unsigned int)access_mask,
			smb_fname_str_dbg(smb_fname),
			(unsigned int)rejected_share_access ));
		return false;
        }

	status = SMB_VFS_GET_NT_ACL_AT(conn,
			dirfsp,
			smb_fname,
			(SECINFO_OWNER |
			 SECINFO_GROUP |
			 SECINFO_DACL),
			talloc_tos(),
			&sd);

	if (!NT_STATUS_IS_OK(status)) {
                DEBUG(10, ("Could not get acl "
			"on %s: %s\n",
			smb_fname_str_dbg(smb_fname),
			nt_errstr(status)));
		return false;
        }

	status = se_file_access_check(sd,
				get_current_nttok(conn),
				false,
				access_mask,
				&rejected_mask);

        TALLOC_FREE(sd);

	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		DEBUG(10,("rejected bits 0x%x read access for %s\n",
			(unsigned int)rejected_mask,
			smb_fname_str_dbg(smb_fname) ));
		return false;
        }
	return true;
}

/*******************************************************************
 Check to see if a user can write a file (and only files, we do not
 check dirs on this one). This is only approximate,
 it is used as part of the "hide unwriteable" option. Don't
 use it for anything security sensitive.
********************************************************************/

static bool user_can_write_file(connection_struct *conn,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname)
{
	SMB_ASSERT(dirfsp == conn->cwd_fsp);

	/*
	 * Never hide files from the root user.
	 * We use (uid_t)0 here not sec_initial_uid()
	 * as make test uses a single user context.
	 */

	if (get_current_uid(conn) == (uid_t)0) {
		return True;
	}

	SMB_ASSERT(VALID_STAT(smb_fname->st));

	/* Pseudo-open the file */

	if(S_ISDIR(smb_fname->st.st_ex_mode)) {
		return True;
	}

	return can_write_to_file(conn, dirfsp, smb_fname);
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
 NOTE: A successful return is no guarantee of the file's existence.
********************************************************************/

bool is_visible_file(connection_struct *conn,
		struct smb_Dir *dir_hnd,
		const char *name,
		SMB_STRUCT_STAT *pst,
		bool use_veto)
{
	bool hide_unreadable = lp_hide_unreadable(SNUM(conn));
	bool hide_unwriteable = lp_hide_unwriteable_files(SNUM(conn));
	bool hide_special = lp_hide_special_files(SNUM(conn));
	int hide_new_files_timeout = lp_hide_new_files_timeout(SNUM(conn));
	char *entry = NULL;
	struct smb_filename *dir_path = dir_hnd->fsp->fsp_name;
	struct smb_filename *smb_fname_base = NULL;
	bool ret = false;

	if ((strcmp(".",name) == 0) || (strcmp("..",name) == 0)) {
		return True; /* . and .. are always visible. */
	}

	/* If it's a vetoed file, pretend it doesn't even exist */
	if (use_veto && IS_VETO_PATH(conn, name)) {
		DEBUG(10,("is_visible_file: file %s is vetoed.\n", name ));
		return False;
	}

	if (hide_unreadable ||
	    hide_unwriteable ||
	    hide_special ||
	    (hide_new_files_timeout != 0))
	{
		entry = talloc_asprintf(talloc_tos(),
					"%s/%s",
					dir_path->base_name,
					name);
		if (!entry) {
			ret = false;
			goto out;
		}

		/* Create an smb_filename with stream_name == NULL. */
		smb_fname_base = synthetic_smb_fname(talloc_tos(),
						entry,
						NULL,
						pst,
						dir_path->twrp,
						0);
		if (smb_fname_base == NULL) {
			ret = false;
			goto out;
		}

		/* If the file name does not exist, there's no point checking
		 * the configuration options. We succeed, on the basis that the
		 * checks *might* have passed if the file was present.
		 */
		if (!VALID_STAT(*pst)) {
			if (SMB_VFS_STAT(conn, smb_fname_base) != 0) {
				ret = true;
				goto out;
			}
			*pst = smb_fname_base->st;
		}

		/* Honour _hide unreadable_ option */
		if (hide_unreadable &&
		    !user_can_read_file(conn,
				conn->cwd_fsp,
				smb_fname_base))
		{
			DEBUG(10,("is_visible_file: file %s is unreadable.\n",
				 entry ));
			ret = false;
			goto out;
		}
		/* Honour _hide unwriteable_ option */
		if (hide_unwriteable &&
		    !user_can_write_file(conn,
				conn->cwd_fsp,
				smb_fname_base))
		{
			DEBUG(10,("is_visible_file: file %s is unwritable.\n",
				 entry ));
			ret = false;
			goto out;
		}
		/* Honour _hide_special_ option */
		if (hide_special && file_is_special(conn, smb_fname_base)) {
			DEBUG(10,("is_visible_file: file %s is special.\n",
				 entry ));
			ret = false;
			goto out;
		}

		if (hide_new_files_timeout != 0) {

			double age = timespec_elapsed(
				&smb_fname_base->st.st_ex_mtime);

			if (age < (double)hide_new_files_timeout) {
				ret = false;
				goto out;
			}
		}
	}

	ret = true;
 out:
	TALLOC_FREE(smb_fname_base);
	TALLOC_FREE(entry);
	return ret;
}

static int smb_Dir_destructor(struct smb_Dir *dir_hnd)
{
	files_struct *fsp = dir_hnd->fsp;

	SMB_VFS_CLOSEDIR(dir_hnd->conn, dir_hnd->dir);
	fsp->fh->fd = -1;
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

struct smb_Dir *OpenDir(TALLOC_CTX *mem_ctx,
			connection_struct *conn,
			const struct smb_filename *smb_dname,
			const char *mask,
			uint32_t attr)
{
	struct files_struct *fsp = NULL;
	struct smb_Dir *dir_hnd = NULL;
	NTSTATUS status;

	status = open_internal_dirfsp(conn,
				      smb_dname,
				      O_RDONLY,
				      &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	dir_hnd = OpenDir_fsp(mem_ctx, conn, fsp, mask, attr);
	if (dir_hnd == NULL) {
		return NULL;
	}

	/*
	 * This overwrites the destructor set by smb_Dir_OpenDir_destructor(),
	 * but smb_Dir_OpenDir_destructor() calls the OpenDir_fsp() destructor.
	 */
	talloc_set_destructor(dir_hnd, smb_Dir_OpenDir_destructor);
	return dir_hnd;
}

/*******************************************************************
 Open a directory from an fsp.
********************************************************************/

static struct smb_Dir *OpenDir_fsp(TALLOC_CTX *mem_ctx, connection_struct *conn,
			files_struct *fsp,
			const char *mask,
			uint32_t attr)
{
	struct smb_Dir *dir_hnd = talloc_zero(mem_ctx, struct smb_Dir);

	if (!dir_hnd) {
		goto fail;
	}

	if (!fsp->fsp_flags.is_directory) {
		errno = EBADF;
		goto fail;
	}

	if (fsp->fh->fd == -1) {
		errno = EBADF;
		goto fail;
	}

	dir_hnd->conn = conn;

	if (!conn->sconn->using_smb2) {
		/*
		 * The dircache is only needed for SMB1 because SMB1 uses a name
		 * for the resume wheras SMB2 always continues from the next
		 * position (unless it's told to restart or close-and-reopen the
		 * listing).
		 */
		dir_hnd->name_cache_size =
			lp_directory_name_cache_size(SNUM(conn));
	}

	dir_hnd->dir_smb_fname = cp_smb_filename(dir_hnd, fsp->fsp_name);
	if (!dir_hnd->dir_smb_fname) {
		errno = ENOMEM;
		goto fail;
	}

	dir_hnd->dir = SMB_VFS_FDOPENDIR(fsp, mask, attr);
	if (dir_hnd->dir == NULL) {
		goto fail;
	}
	dir_hnd->fsp = fsp;

	talloc_set_destructor(dir_hnd, smb_Dir_destructor);

	return dir_hnd;

  fail:
	TALLOC_FREE(dir_hnd);
	return NULL;
}


/*******************************************************************
 Read from a directory.
 Return directory entry, current offset, and optional stat information.
 Don't check for veto or invisible files.
********************************************************************/

const char *ReadDirName(struct smb_Dir *dir_hnd, long *poffset,
			SMB_STRUCT_STAT *sbuf, char **ptalloced)
{
	const char *n;
	char *talloced = NULL;
	connection_struct *conn = dir_hnd->conn;

	/* Cheat to allow . and .. to be the first entries returned. */
	if (((*poffset == START_OF_DIRECTORY_OFFSET) ||
	     (*poffset == DOT_DOT_DIRECTORY_OFFSET)) && (dir_hnd->file_number < 2))
	{
		if (dir_hnd->file_number == 0) {
			n = ".";
			*poffset = dir_hnd->offset = START_OF_DIRECTORY_OFFSET;
		} else {
			n = "..";
			*poffset = dir_hnd->offset = DOT_DOT_DIRECTORY_OFFSET;
		}
		dir_hnd->file_number++;
		*ptalloced = NULL;
		return n;
	}

	if (*poffset == END_OF_DIRECTORY_OFFSET) {
		*poffset = dir_hnd->offset = END_OF_DIRECTORY_OFFSET;
		return NULL;
	}

	/* A real offset, seek to it. */
	SeekDir(dir_hnd, *poffset);

	while ((n = vfs_readdirname(conn, dir_hnd->dir, sbuf, &talloced))) {
		/* Ignore . and .. - we've already returned them. */
		if (*n == '.') {
			if ((n[1] == '\0') || (n[1] == '.' && n[2] == '\0')) {
				TALLOC_FREE(talloced);
				continue;
			}
		}
		*poffset = dir_hnd->offset = SMB_VFS_TELLDIR(conn, dir_hnd->dir);
		*ptalloced = talloced;
		dir_hnd->file_number++;
		return n;
	}
	*poffset = dir_hnd->offset = END_OF_DIRECTORY_OFFSET;
	*ptalloced = NULL;
	return NULL;
}

/*******************************************************************
 Rewind to the start.
********************************************************************/

void RewindDir(struct smb_Dir *dir_hnd, long *poffset)
{
	SMB_VFS_REWINDDIR(dir_hnd->conn, dir_hnd->dir);
	dir_hnd->file_number = 0;
	dir_hnd->offset = START_OF_DIRECTORY_OFFSET;
	*poffset = START_OF_DIRECTORY_OFFSET;
}

/*******************************************************************
 Seek a dir.
********************************************************************/

void SeekDir(struct smb_Dir *dirp, long offset)
{
	if (offset != dirp->offset) {
		if (offset == START_OF_DIRECTORY_OFFSET) {
			RewindDir(dirp, &offset);
			/*
			 * Ok we should really set the file number here
			 * to 1 to enable ".." to be returned next. Trouble
			 * is I'm worried about callers using SeekDir(dirp,0)
			 * as equivalent to RewindDir(). So leave this alone
			 * for now.
			 */
		} else if  (offset == DOT_DOT_DIRECTORY_OFFSET) {
			RewindDir(dirp, &offset);
			/*
			 * Set the file number to 2 - we want to get the first
			 * real file entry (the one we return after "..")
			 * on the next ReadDir.
			 */
			dirp->file_number = 2;
		} else if (offset == END_OF_DIRECTORY_OFFSET) {
			; /* Don't seek in this case. */
		} else {
			SMB_VFS_SEEKDIR(dirp->conn, dirp->dir, offset);
		}
		dirp->offset = offset;
	}
}

/*******************************************************************
 Tell a dir position.
********************************************************************/

long TellDir(struct smb_Dir *dir_hnd)
{
	return(dir_hnd->offset);
}

/*******************************************************************
 Add an entry into the dcache.
********************************************************************/

static void DirCacheAdd(struct smb_Dir *dir_hnd, const char *name, long offset)
{
	struct name_cache_entry *e;

	if (dir_hnd->name_cache_size == 0) {
		return;
	}

	if (dir_hnd->name_cache == NULL) {
		dir_hnd->name_cache = talloc_zero_array(dir_hnd,
						struct name_cache_entry,
						dir_hnd->name_cache_size);

		if (dir_hnd->name_cache == NULL) {
			return;
		}
	}

	dir_hnd->name_cache_index = (dir_hnd->name_cache_index+1) %
					dir_hnd->name_cache_size;
	e = &dir_hnd->name_cache[dir_hnd->name_cache_index];
	TALLOC_FREE(e->name);
	e->name = talloc_strdup(dir_hnd, name);
	e->offset = offset;
}

/*******************************************************************
 Find an entry by name. Leave us at the offset after it.
 Don't check for veto or invisible files.
********************************************************************/

bool SearchDir(struct smb_Dir *dir_hnd, const char *name, long *poffset)
{
	int i;
	const char *entry = NULL;
	char *talloced = NULL;
	connection_struct *conn = dir_hnd->conn;

	/* Search back in the name cache. */
	if (dir_hnd->name_cache_size && dir_hnd->name_cache) {
		for (i = dir_hnd->name_cache_index; i >= 0; i--) {
			struct name_cache_entry *e = &dir_hnd->name_cache[i];
			if (e->name && (conn->case_sensitive ? (strcmp(e->name, name) == 0) : strequal(e->name, name))) {
				*poffset = e->offset;
				SeekDir(dir_hnd, e->offset);
				return True;
			}
		}
		for (i = dir_hnd->name_cache_size - 1;
				i > dir_hnd->name_cache_index; i--) {
			struct name_cache_entry *e = &dir_hnd->name_cache[i];
			if (e->name && (conn->case_sensitive ? (strcmp(e->name, name) == 0) : strequal(e->name, name))) {
				*poffset = e->offset;
				SeekDir(dir_hnd, e->offset);
				return True;
			}
		}
	}

	/* Not found in the name cache. Rewind directory and start from scratch. */
	SMB_VFS_REWINDDIR(conn, dir_hnd->dir);
	dir_hnd->file_number = 0;
	*poffset = START_OF_DIRECTORY_OFFSET;
	while ((entry = ReadDirName(dir_hnd, poffset, NULL, &talloced))) {
		if (conn->case_sensitive ? (strcmp(entry, name) == 0) : strequal(entry, name)) {
			TALLOC_FREE(talloced);
			return True;
		}
		TALLOC_FREE(talloced);
	}
	return False;
}

struct files_below_forall_state {
	char *dirpath;
	size_t dirpath_len;
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
	size_t len;

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
	long dirpos = 0;
	const char *dname = NULL;
	char *talloced = NULL;
	SMB_STRUCT_STAT st;
	struct connection_struct *conn = fsp->conn;
	struct smb_Dir *dir_hnd = OpenDir(talloc_tos(),
					conn,
					fsp->fsp_name,
					NULL,
					0);

	if (!dir_hnd) {
		return map_nt_error_from_unix(errno);
	}

	while ((dname = ReadDirName(dir_hnd, &dirpos, &st, &talloced))) {
		/* Quick check for "." and ".." */
		if (dname[0] == '.') {
			if (!dname[1] || (dname[1] == '.' && !dname[2])) {
				TALLOC_FREE(talloced);
				continue;
			}
		}

		if (!is_visible_file(conn,
				dir_hnd,
				dname,
				&st,
				True)) {
			TALLOC_FREE(talloced);
			continue;
		}

		DEBUG(10,("got name %s - can't delete\n",
			 dname ));
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
