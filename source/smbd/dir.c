/* 
   Unix SMB/CIFS implementation.
   Directory handling routines
   Copyright (C) Andrew Tridgell 1992-1998
   
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

/*
   This module implements directory related functions for Samba.
*/

/* Make directory handle internals available. */

#define NAME_CACHE_SIZE 100

struct name_cache_entry {
	char *name;
	long offset;
};

struct smb_Dir {
	connection_struct *conn;
	DIR *dir;
	long offset;
	char *dir_path;
	struct name_cache_entry *name_cache;
	unsigned int name_cache_index;
};

struct dptr_struct {
	struct dptr_struct *next, *prev;
	int dnum;
	uint16 spid;
	struct connection_struct *conn;
	struct smb_Dir *dir_hnd;
	BOOL expect_close;
	char *wcard;
	uint16 attr;
	char *path;
	BOOL has_wild; /* Set to true if the wcard entry has MS wildcard characters in it. */
};

static struct bitmap *dptr_bmap;
static struct dptr_struct *dirptrs;
static int dirhandles_open = 0;

#define INVALID_DPTR_KEY (-3)

/****************************************************************************
 Initialise the dir bitmap.
****************************************************************************/

void init_dptrs(void)
{
	static BOOL dptrs_init=False;

	if (dptrs_init)
		return;

	dptr_bmap = bitmap_allocate(MAX_DIRECTORY_HANDLES);

	if (!dptr_bmap)
		exit_server("out of memory in init_dptrs");

	dptrs_init = True;
}

/****************************************************************************
 Idle a dptr - the directory is closed but the control info is kept.
****************************************************************************/

static void dptr_idle(struct dptr_struct *dptr)
{
	if (dptr->dir_hnd) {
		DEBUG(4,("Idling dptr dnum %d\n",dptr->dnum));
		CloseDir(dptr->dir_hnd);
		dptr->dir_hnd = NULL;
	}
}

/****************************************************************************
 Idle the oldest dptr.
****************************************************************************/

static void dptr_idleoldest(void)
{
	struct dptr_struct *dptr;

	/*
	 * Go to the end of the list.
	 */
	for(dptr = dirptrs; dptr && dptr->next; dptr = dptr->next)
		;

	if(!dptr) {
		DEBUG(0,("No dptrs available to idle ?\n"));
		return;
	}

	/*
	 * Idle the oldest pointer.
	 */

	for(; dptr; dptr = dptr->prev) {
		if (dptr->dir_hnd) {
			dptr_idle(dptr);
			return;
		}
	}
}

/****************************************************************************
 Get the struct dptr_struct for a dir index.
****************************************************************************/

static struct dptr_struct *dptr_get(int key, BOOL forclose)
{
	struct dptr_struct *dptr;

	for(dptr = dirptrs; dptr; dptr = dptr->next) {
		if(dptr->dnum == key) {
			if (!forclose && !dptr->dir_hnd) {
				if (dirhandles_open >= MAX_OPEN_DIRECTORIES)
					dptr_idleoldest();
				DEBUG(4,("dptr_get: Reopening dptr key %d\n",key));
				if (!(dptr->dir_hnd = OpenDir(dptr->conn, dptr->path))) {
					DEBUG(4,("dptr_get: Failed to open %s (%s)\n",dptr->path,
						strerror(errno)));
					return False;
				}
			}
			DLIST_PROMOTE(dirptrs,dptr);
			return dptr;
		}
	}
	return(NULL);
}

/****************************************************************************
 Get the dir path for a dir index.
****************************************************************************/

char *dptr_path(int key)
{
	struct dptr_struct *dptr = dptr_get(key, False);
	if (dptr)
		return(dptr->path);
	return(NULL);
}

/****************************************************************************
 Get the dir wcard for a dir index.
****************************************************************************/

char *dptr_wcard(int key)
{
	struct dptr_struct *dptr = dptr_get(key, False);
	if (dptr)
		return(dptr->wcard);
	return(NULL);
}

/****************************************************************************
 Get the dir attrib for a dir index.
****************************************************************************/

uint16 dptr_attr(int key)
{
	struct dptr_struct *dptr = dptr_get(key, False);
	if (dptr)
		return(dptr->attr);
	return(0);
}

/****************************************************************************
 Set the dir wcard for a dir index.
 Returns 0 on ok, 1 on fail.
****************************************************************************/

BOOL dptr_set_wcard_and_attributes(int key, const char *wcard, uint16 attr)
{
	struct dptr_struct *dptr = dptr_get(key, False);

	if (dptr) {
		dptr->attr = attr;
		dptr->wcard = SMB_STRDUP(wcard);
		if (!dptr->wcard)
			return False;
		if (wcard[0] == '.' && wcard[1] == 0) {
			dptr->has_wild = True;
		} else {
			dptr->has_wild = ms_has_wild(wcard);
		}
		return True;
	}
	return False;
}

/****************************************************************************
 Close a dptr (internal func).
****************************************************************************/

static void dptr_close_internal(struct dptr_struct *dptr)
{
	DEBUG(4,("closing dptr key %d\n",dptr->dnum));

	DLIST_REMOVE(dirptrs, dptr);

	/* 
	 * Free the dnum in the bitmap. Remember the dnum value is always 
	 * biased by one with respect to the bitmap.
	 */

	if(bitmap_query( dptr_bmap, dptr->dnum - 1) != True) {
		DEBUG(0,("dptr_close_internal : Error - closing dnum = %d and bitmap not set !\n",
			dptr->dnum ));
	}

	bitmap_clear(dptr_bmap, dptr->dnum - 1);

	if (dptr->dir_hnd) {
		CloseDir(dptr->dir_hnd);
	}

	/* Lanman 2 specific code */
	SAFE_FREE(dptr->wcard);
	string_set(&dptr->path,"");
	SAFE_FREE(dptr);
}

/****************************************************************************
 Close a dptr given a key.
****************************************************************************/

void dptr_close(int *key)
{
	struct dptr_struct *dptr;

	if(*key == INVALID_DPTR_KEY)
		return;

	/* OS/2 seems to use -1 to indicate "close all directories" */
	if (*key == -1) {
		struct dptr_struct *next;
		for(dptr = dirptrs; dptr; dptr = next) {
			next = dptr->next;
			dptr_close_internal(dptr);
		}
		*key = INVALID_DPTR_KEY;
		return;
	}

	dptr = dptr_get(*key, True);

	if (!dptr) {
		DEBUG(0,("Invalid key %d given to dptr_close\n", *key));
		return;
	}

	dptr_close_internal(dptr);

	*key = INVALID_DPTR_KEY;
}

/****************************************************************************
 Close all dptrs for a cnum.
****************************************************************************/

void dptr_closecnum(connection_struct *conn)
{
	struct dptr_struct *dptr, *next;
	for(dptr = dirptrs; dptr; dptr = next) {
		next = dptr->next;
		if (dptr->conn == conn)
			dptr_close_internal(dptr);
	}
}

/****************************************************************************
 Idle all dptrs for a cnum.
****************************************************************************/

void dptr_idlecnum(connection_struct *conn)
{
	struct dptr_struct *dptr;
	for(dptr = dirptrs; dptr; dptr = dptr->next) {
		if (dptr->conn == conn && dptr->dir_hnd)
			dptr_idle(dptr);
	}
}

/****************************************************************************
 Close a dptr that matches a given path, only if it matches the spid also.
****************************************************************************/

void dptr_closepath(char *path,uint16 spid)
{
	struct dptr_struct *dptr, *next;
	for(dptr = dirptrs; dptr; dptr = next) {
		next = dptr->next;
		if (spid == dptr->spid && strequal(dptr->path,path))
			dptr_close_internal(dptr);
	}
}

/****************************************************************************
 Try and close the oldest handle not marked for
 expect close in the hope that the client has
 finished with that one.
****************************************************************************/

static void dptr_close_oldest(BOOL old)
{
	struct dptr_struct *dptr;

	/*
	 * Go to the end of the list.
	 */
	for(dptr = dirptrs; dptr && dptr->next; dptr = dptr->next)
		;

	if(!dptr) {
		DEBUG(0,("No old dptrs available to close oldest ?\n"));
		return;
	}

	/*
	 * If 'old' is true, close the oldest oldhandle dnum (ie. 1 < dnum < 256) that
	 * does not have expect_close set. If 'old' is false, close
	 * one of the new dnum handles.
	 */

	for(; dptr; dptr = dptr->prev) {
		if ((old && (dptr->dnum < 256) && !dptr->expect_close) ||
			(!old && (dptr->dnum > 255))) {
				dptr_close_internal(dptr);
				return;
		}
	}
}

/****************************************************************************
 Create a new dir ptr. If the flag old_handle is true then we must allocate
 from the bitmap range 0 - 255 as old SMBsearch directory handles are only
 one byte long. If old_handle is false we allocate from the range
 256 - MAX_DIRECTORY_HANDLES. We bias the number we return by 1 to ensure
 a directory handle is never zero.
****************************************************************************/

int dptr_create(connection_struct *conn, pstring path, BOOL old_handle, BOOL expect_close,uint16 spid)
{
	struct dptr_struct *dptr = NULL;
	struct smb_Dir *dir_hnd;
        const char *dir2;

	DEBUG(5,("dptr_create dir=%s\n", path));

	if (!check_name(path,conn))
		return(-2); /* Code to say use a unix error return code. */

	/* use a const pointer from here on */
	dir2 = path;
	if (!*dir2)
		dir2 = ".";

	dir_hnd = OpenDir(conn, dir2);
	if (!dir_hnd) {
		return (-2);
	}

	string_set(&conn->dirpath,dir2);

	if (dirhandles_open >= MAX_OPEN_DIRECTORIES)
		dptr_idleoldest();

	dptr = SMB_MALLOC_P(struct dptr_struct);
	if(!dptr) {
		DEBUG(0,("malloc fail in dptr_create.\n"));
		CloseDir(dir_hnd);
		return -1;
	}

	ZERO_STRUCTP(dptr);

	if(old_handle) {

		/*
		 * This is an old-style SMBsearch request. Ensure the
		 * value we return will fit in the range 1-255.
		 */

		dptr->dnum = bitmap_find(dptr_bmap, 0);

		if(dptr->dnum == -1 || dptr->dnum > 254) {

			/*
			 * Try and close the oldest handle not marked for
			 * expect close in the hope that the client has
			 * finished with that one.
			 */

			dptr_close_oldest(True);

			/* Now try again... */
			dptr->dnum = bitmap_find(dptr_bmap, 0);
			if(dptr->dnum == -1 || dptr->dnum > 254) {
				DEBUG(0,("dptr_create: returned %d: Error - all old dirptrs in use ?\n", dptr->dnum));
				SAFE_FREE(dptr);
				CloseDir(dir_hnd);
				return -1;
			}
		}
	} else {

		/*
		 * This is a new-style trans2 request. Allocate from
		 * a range that will return 256 - MAX_DIRECTORY_HANDLES.
		 */

		dptr->dnum = bitmap_find(dptr_bmap, 255);

		if(dptr->dnum == -1 || dptr->dnum < 255) {

			/*
			 * Try and close the oldest handle close in the hope that
			 * the client has finished with that one. This will only
			 * happen in the case of the Win98 client bug where it leaks
			 * directory handles.
			 */

			dptr_close_oldest(False);

			/* Now try again... */
			dptr->dnum = bitmap_find(dptr_bmap, 255);

			if(dptr->dnum == -1 || dptr->dnum < 255) {
				DEBUG(0,("dptr_create: returned %d: Error - all new dirptrs in use ?\n", dptr->dnum));
				SAFE_FREE(dptr);
				CloseDir(dir_hnd);
				return -1;
			}
		}
	}

	bitmap_set(dptr_bmap, dptr->dnum);

	dptr->dnum += 1; /* Always bias the dnum by one - no zero dnums allowed. */

	string_set(&dptr->path,dir2);
	dptr->conn = conn;
	dptr->dir_hnd = dir_hnd;
	dptr->spid = spid;
	dptr->expect_close = expect_close;
	dptr->wcard = NULL; /* Only used in lanman2 searches */
	dptr->attr = 0; /* Only used in lanman2 searches */
	dptr->has_wild = True; /* Only used in lanman2 searches */

	DLIST_ADD(dirptrs, dptr);

	DEBUG(3,("creating new dirptr %d for path %s, expect_close = %d\n",
		dptr->dnum,path,expect_close));  

	conn->dirptr = dptr;

	return(dptr->dnum);
}


/****************************************************************************
 Wrapper functions to access the lower level directory handles.
****************************************************************************/

int dptr_CloseDir(struct dptr_struct *dptr)
{
	return CloseDir(dptr->dir_hnd);
}

void dptr_SeekDir(struct dptr_struct *dptr, long offset)
{
	SeekDir(dptr->dir_hnd, offset);
}

long dptr_TellDir(struct dptr_struct *dptr)
{
	return TellDir(dptr->dir_hnd);
}

/****************************************************************************
 Return the next visible file name, skipping veto'd and invisible files.
****************************************************************************/

static const char *dptr_normal_ReadDirName(struct dptr_struct *dptr, long *poffset, SMB_STRUCT_STAT *pst)
{
	/* Normal search for the next file. */
	const char *name;
	while ((name = ReadDirName(dptr->dir_hnd, poffset)) != NULL) {
		if (is_visible_file(dptr->conn, dptr->path, name, pst, True)) {
			return name;
		}
	}
	return NULL;
}

/****************************************************************************
 Return the next visible file name, skipping veto'd and invisible files.
****************************************************************************/

const char *dptr_ReadDirName(struct dptr_struct *dptr, long *poffset, SMB_STRUCT_STAT *pst)
{
	pstring pathreal;

	ZERO_STRUCTP(pst);

	if (dptr->has_wild) {
		return dptr_normal_ReadDirName(dptr, poffset, pst);
	}

	/* If poffset is -1 then we know we returned this name before and we have
	   no wildcards. We're at the end of the directory. */
	if (*poffset == -1) {
		return NULL;
	}

	/* We know the stored wcard contains no wildcard characters. See if we can match
	   with a stat call. If we can't, then set has_wild to true to
	   prevent us from doing this on every call. */

	/* First check if it should be visible. */
	if (!is_visible_file(dptr->conn, dptr->path, dptr->wcard, pst, True)) {
		dptr->has_wild = True;
		return dptr_normal_ReadDirName(dptr, poffset, pst);
	}

	if (VALID_STAT(*pst)) {
		/* We need to set the underlying dir_hdn offset to -1 also as
		   this function is usually called with the output from TellDir. */
		dptr->dir_hnd->offset = *poffset = -1;
		return dptr->wcard;
	}

	pstrcpy(pathreal,dptr->path);
	pstrcat(pathreal,"/");
	pstrcat(pathreal,dptr->wcard);

	if (SMB_VFS_STAT(dptr->conn,pathreal,pst) == 0) {
		/* We need to set the underlying dir_hdn offset to -1 also as
		   this function is usually called with the output from TellDir. */
		dptr->dir_hnd->offset = *poffset = -1;
		return dptr->wcard;
	} else {
		/* If we get any other error than ENOENT or ENOTDIR
		   then the file exists we just can't stat it. */
		if (errno != ENOENT && errno != ENOTDIR) {
			/* We need to set the underlying dir_hdn offset to -1 also as
			   this function is usually called with the output from TellDir. */
			dptr->dir_hnd->offset = *poffset = -1;
			return dptr->wcard;
		}
	}

	/* In case sensitive mode we don't search - we know if it doesn't exist 
	   with a stat we will fail. */

	if (dptr->conn->case_sensitive) {
		/* We need to set the underlying dir_hdn offset to -1 also as
		   this function is usually called with the output from TellDir. */
		dptr->dir_hnd->offset = *poffset = -1;
		return NULL;
	} else {
		dptr->has_wild = True;
		return dptr_normal_ReadDirName(dptr, poffset, pst);
	}
}

/****************************************************************************
 Search for a file by name, skipping veto'ed and not visible files.
****************************************************************************/

BOOL dptr_SearchDir(struct dptr_struct *dptr, const char *name, long *poffset, SMB_STRUCT_STAT *pst)
{
	ZERO_STRUCTP(pst);

	if (!dptr->has_wild && (dptr->dir_hnd->offset == -1)) {
		/* This is a singleton directory and we're already at the end. */
		*poffset = -1;
		return False;
	}

	if (SearchDir(dptr->dir_hnd, name, poffset)) {
		if (is_visible_file(dptr->conn, dptr->path, name, pst, True)) {
			return True;
		}
	}
	return False;
}

/****************************************************************************
 Fill the 5 byte server reserved dptr field.
****************************************************************************/

BOOL dptr_fill(char *buf1,unsigned int key)
{
	unsigned char *buf = (unsigned char *)buf1;
	struct dptr_struct *dptr = dptr_get(key, False);
	uint32 offset;
	if (!dptr) {
		DEBUG(1,("filling null dirptr %d\n",key));
		return(False);
	}
	offset = TellDir(dptr->dir_hnd);
	DEBUG(6,("fill on key %u dirptr 0x%lx now at %d\n",key,
		(long)dptr->dir_hnd,(int)offset));
	buf[0] = key;
	SIVAL(buf,1,offset | DPTR_MASK);
	return(True);
}

/****************************************************************************
 Fetch the dir ptr and seek it given the 5 byte server field.
****************************************************************************/

struct dptr_struct *dptr_fetch(char *buf,int *num)
{
	unsigned int key = *(unsigned char *)buf;
	struct dptr_struct *dptr = dptr_get(key, False);
	uint32 offset;

	if (!dptr) {
		DEBUG(3,("fetched null dirptr %d\n",key));
		return(NULL);
	}
	*num = key;
	offset = IVAL(buf,1)&~DPTR_MASK;
	SeekDir(dptr->dir_hnd,(long)offset);
	DEBUG(3,("fetching dirptr %d for path %s at offset %d\n",
		key,dptr_path(key),offset));
	return(dptr);
}

/****************************************************************************
 Fetch the dir ptr.
****************************************************************************/

struct dptr_struct *dptr_fetch_lanman2(int dptr_num)
{
	struct dptr_struct *dptr  = dptr_get(dptr_num, False);

	if (!dptr) {
		DEBUG(3,("fetched null dirptr %d\n",dptr_num));
		return(NULL);
	}
	DEBUG(3,("fetching dirptr %d for path %s\n",dptr_num,dptr_path(dptr_num)));
	return(dptr);
}

/****************************************************************************
 Check a filetype for being valid.
****************************************************************************/

BOOL dir_check_ftype(connection_struct *conn,int mode,int dirtype)
{
	int mask;

	/* Check the "may have" search bits. */
	if (((mode & ~dirtype) & (aHIDDEN | aSYSTEM | aDIR)) != 0)
		return False;

	/* Check the "must have" bits, which are the may have bits shifted eight */
	/* If must have bit is set, the file/dir can not be returned in search unless the matching
		file attribute is set */
	mask = ((dirtype >> 8) & (aDIR|aARCH|aRONLY|aHIDDEN|aSYSTEM)); /* & 0x37 */
	if(mask) {
		if((mask & (mode & (aDIR|aARCH|aRONLY|aHIDDEN|aSYSTEM))) == mask)   /* check if matching attribute present */
			return True;
		else
			return False;
	}

	return True;
}

static BOOL mangle_mask_match(connection_struct *conn, fstring filename, char *mask)
{
	mangle_map(filename,True,False,SNUM(conn));
	return mask_match(filename,mask,False);
}

/****************************************************************************
 Get an 8.3 directory entry.
****************************************************************************/

BOOL get_dir_entry(connection_struct *conn,char *mask,int dirtype, pstring fname,
                   SMB_OFF_T *size,int *mode,time_t *date,BOOL check_descend)
{
	const char *dname;
	BOOL found = False;
	SMB_STRUCT_STAT sbuf;
	pstring path;
	pstring pathreal;
	BOOL isrootdir;
	pstring filename;
	BOOL needslash;

	*path = *pathreal = *filename = 0;

	isrootdir = (strequal(conn->dirpath,"./") ||
			strequal(conn->dirpath,".") ||
			strequal(conn->dirpath,"/"));
  
	needslash = ( conn->dirpath[strlen(conn->dirpath) -1] != '/');

	if (!conn->dirptr)
		return(False);

	while (!found) {
		long curoff = dptr_TellDir(conn->dirptr);
		dname = dptr_ReadDirName(conn->dirptr, &curoff, &sbuf);

		DEBUG(6,("readdir on dirptr 0x%lx now at offset %ld\n",
			(long)conn->dirptr,TellDir(conn->dirptr->dir_hnd)));
      
		if (dname == NULL) 
			return(False);
      
		pstrcpy(filename,dname);      

		/* notice the special *.* handling. This appears to be the only difference
			between the wildcard handling in this routine and in the trans2 routines.
			see masktest for a demo
		*/
		if ((strcmp(mask,"*.*") == 0) ||
		    mask_match(filename,mask,False) ||
		    mangle_mask_match(conn,filename,mask)) {
			if (isrootdir && (strequal(filename,"..") || strequal(filename,".")))
				continue;

			if (!mangle_is_8_3(filename, False))
				mangle_map(filename,True,False,SNUM(conn));

			pstrcpy(fname,filename);
			*path = 0;
			pstrcpy(path,conn->dirpath);
			if(needslash)
				pstrcat(path,"/");
			pstrcpy(pathreal,path);
			pstrcat(path,fname);
			pstrcat(pathreal,dname);
			if (!VALID_STAT(sbuf) && (SMB_VFS_STAT(conn, pathreal, &sbuf)) != 0) {
				DEBUG(5,("Couldn't stat 1 [%s]. Error = %s\n",path, strerror(errno) ));
				continue;
			}
	  
			*mode = dos_mode(conn,pathreal,&sbuf);

			if (!dir_check_ftype(conn,*mode,dirtype)) {
				DEBUG(5,("[%s] attribs didn't match %x\n",filename,dirtype));
				continue;
			}

			*size = sbuf.st_size;
			*date = sbuf.st_mtime;

			DEBUG(3,("get_dir_entry mask=[%s] found %s fname=%s\n",mask, pathreal,fname));

			found = True;
		}
	}

	return(found);
}

/*******************************************************************
 Check to see if a user can read a file. This is only approximate,
 it is used as part of the "hide unreadable" option. Don't
 use it for anything security sensitive.
********************************************************************/

static BOOL user_can_read_file(connection_struct *conn, char *name, SMB_STRUCT_STAT *pst)
{
	extern struct current_user current_user;
	SEC_DESC *psd = NULL;
	size_t sd_size;
	files_struct *fsp;
	int smb_action;
	NTSTATUS status;
	uint32 access_granted;

	/*
	 * If user is a member of the Admin group
	 * we never hide files from them.
	 */

	if (conn->admin_user)
		return True;

	/* If we can't stat it does not show it */
	if (!VALID_STAT(*pst) && (SMB_VFS_STAT(conn, name, pst) != 0))
		return False;

	/* Pseudo-open the file (note - no fd's created). */

	if(S_ISDIR(pst->st_mode))	
		 fsp = open_directory(conn, name, pst, 0, SET_DENY_MODE(DENY_NONE), (FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN),
			&smb_action);
	else
		fsp = open_file_stat(conn, name, pst);

	if (!fsp)
		return False;

	/* Get NT ACL -allocated in main loop talloc context. No free needed here. */
	sd_size = SMB_VFS_FGET_NT_ACL(fsp, fsp->fd,
			(OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION), &psd);
	close_file(fsp, True);

	/* No access if SD get failed. */
	if (!sd_size)
		return False;

	return se_access_check(psd, current_user.nt_user_token, FILE_READ_DATA,
                                 &access_granted, &status);
}

/*******************************************************************
 Check to see if a user can write a file (and only files, we do not
 check dirs on this one). This is only approximate,
 it is used as part of the "hide unwriteable" option. Don't
 use it for anything security sensitive.
********************************************************************/

static BOOL user_can_write_file(connection_struct *conn, char *name, SMB_STRUCT_STAT *pst)
{
	extern struct current_user current_user;
	SEC_DESC *psd = NULL;
	size_t sd_size;
	files_struct *fsp;
	int smb_action;
	int access_mode;
	NTSTATUS status;
	uint32 access_granted;

	/*
	 * If user is a member of the Admin group
	 * we never hide files from them.
	 */

	if (conn->admin_user)
		return True;

	/* If we can't stat it does not show it */
	if (!VALID_STAT(*pst) && (SMB_VFS_STAT(conn, name, pst) != 0))
		return False;

	/* Pseudo-open the file (note - no fd's created). */

	if(S_ISDIR(pst->st_mode))	
		return True;
	else
		fsp = open_file_shared1(conn, name, pst, FILE_WRITE_ATTRIBUTES, SET_DENY_MODE(DENY_NONE),
			(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN), FILE_ATTRIBUTE_NORMAL, INTERNAL_OPEN_ONLY,
			&access_mode, &smb_action);

	if (!fsp)
		return False;

	/* Get NT ACL -allocated in main loop talloc context. No free needed here. */
	sd_size = SMB_VFS_FGET_NT_ACL(fsp, fsp->fd,
			(OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION), &psd);
	close_file(fsp, False);

	/* No access if SD get failed. */
	if (!sd_size)
		return False;

	return se_access_check(psd, current_user.nt_user_token, FILE_WRITE_DATA,
                                 &access_granted, &status);
}

/*******************************************************************
  Is a file a "special" type ?
********************************************************************/

static BOOL file_is_special(connection_struct *conn, char *name, SMB_STRUCT_STAT *pst)
{
	/*
	 * If user is a member of the Admin group
	 * we never hide files from them.
	 */

	if (conn->admin_user)
		return False;

	/* If we can't stat it does not show it */
	if (!VALID_STAT(*pst) && (SMB_VFS_STAT(conn, name, pst) != 0))
		return True;

	if (S_ISREG(pst->st_mode) || S_ISDIR(pst->st_mode) || S_ISLNK(pst->st_mode))
		return False;

	return True;
}

/*******************************************************************
 Should the file be seen by the client ?
********************************************************************/

BOOL is_visible_file(connection_struct *conn, const char *dir_path, const char *name, SMB_STRUCT_STAT *pst, BOOL use_veto)
{
	BOOL hide_unreadable = lp_hideunreadable(SNUM(conn));
	BOOL hide_unwriteable = lp_hideunwriteable_files(SNUM(conn));
	BOOL hide_special = lp_hide_special_files(SNUM(conn));

	ZERO_STRUCTP(pst);

	if ((strcmp(".",name) == 0) || (strcmp("..",name) == 0)) {
		return True; /* . and .. are always visible. */
	}

	/* If it's a vetoed file, pretend it doesn't even exist */
	if (use_veto && IS_VETO_PATH(conn, name)) {
		return False;
	}

	if (hide_unreadable || hide_unwriteable || hide_special) {
		char *entry = NULL;

		if (asprintf(&entry, "%s/%s", dir_path, name) == -1) {
			return False;
		}
		/* Honour _hide unreadable_ option */
		if (hide_unreadable && !user_can_read_file(conn, entry, pst)) {
			SAFE_FREE(entry);
			return False;
		}
		/* Honour _hide unwriteable_ option */
		if (hide_unwriteable && !user_can_write_file(conn, entry, pst)) {
			SAFE_FREE(entry);
			return False;
		}
		/* Honour _hide_special_ option */
		if (hide_special && !file_is_special(conn, entry, pst)) {
			SAFE_FREE(entry);
			return False;
		}
		SAFE_FREE(entry);
	}
	return True;
}

/*******************************************************************
 Open a directory.
********************************************************************/

struct smb_Dir *OpenDir(connection_struct *conn, const char *name)
{
	struct smb_Dir *dirp = SMB_MALLOC_P(struct smb_Dir);
	if (!dirp) {
		return NULL;
	}
	ZERO_STRUCTP(dirp);

	dirp->conn = conn;

	dirp->dir_path = SMB_STRDUP(name);
	if (!dirp->dir_path) {
		goto fail;
	}
	dirp->dir = SMB_VFS_OPENDIR(conn, dirp->dir_path);
	if (!dirp->dir) {
		DEBUG(5,("OpenDir: Can't open %s. %s\n", dirp->dir_path, strerror(errno) ));
		goto fail;
	}

	dirp->name_cache = SMB_CALLOC_ARRAY(struct name_cache_entry, NAME_CACHE_SIZE);
	if (!dirp->name_cache) {
		goto fail;
	}

	dirhandles_open++;
	return dirp;

  fail:

	if (dirp) {
		if (dirp->dir) {
			SMB_VFS_CLOSEDIR(conn,dirp->dir);
		}
		SAFE_FREE(dirp->dir_path);
		SAFE_FREE(dirp->name_cache);
		SAFE_FREE(dirp);
	}
	return NULL;
}


/*******************************************************************
 Close a directory.
********************************************************************/

int CloseDir(struct smb_Dir *dirp)
{
	int i, ret = 0;

	if (dirp->dir) {
		ret = SMB_VFS_CLOSEDIR(dirp->conn,dirp->dir);
	}
	SAFE_FREE(dirp->dir_path);
	if (dirp->name_cache) {
		for (i = 0; i < NAME_CACHE_SIZE; i++) {
			SAFE_FREE(dirp->name_cache[i].name);
		}
	}
	SAFE_FREE(dirp->name_cache);
	SAFE_FREE(dirp);
	dirhandles_open--;
	return ret;
}

/*******************************************************************
 Read from a directory. Also return current offset.
 Don't check for veto or invisible files.
********************************************************************/

const char *ReadDirName(struct smb_Dir *dirp, long *poffset)
{
	const char *n;
	connection_struct *conn = dirp->conn;

	SeekDir(dirp, *poffset);
	while ((n = vfs_readdirname(conn, dirp->dir))) {
		struct name_cache_entry *e;
		dirp->offset = SMB_VFS_TELLDIR(conn, dirp->dir);
		if (dirp->offset == -1) {
			return NULL;
		}
		dirp->name_cache_index = (dirp->name_cache_index+1) % NAME_CACHE_SIZE;

		e = &dirp->name_cache[dirp->name_cache_index];
		SAFE_FREE(e->name);
		e->name = SMB_STRDUP(n);
		*poffset = e->offset= dirp->offset;
		return e->name;
	}
	dirp->offset = -1;
	return NULL;
}

/*******************************************************************
 Seek a dir.
********************************************************************/

void SeekDir(struct smb_Dir *dirp, long offset)
{
	if (offset != dirp->offset) {
		SMB_VFS_SEEKDIR(dirp->conn, dirp->dir, offset);
		dirp->offset = offset;
	}
}

/*******************************************************************
 Tell a dir position.
********************************************************************/

long TellDir(struct smb_Dir *dirp)
{
	return(dirp->offset);
}

/*******************************************************************
 Find an entry by name. Leave us at the offset after it.
 Don't check for veto or invisible files.
********************************************************************/

BOOL SearchDir(struct smb_Dir *dirp, const char *name, long *poffset)
{
	int i;
	const char *entry;
	connection_struct *conn = dirp->conn;

	/* Search back in the name cache. */
	for (i = dirp->name_cache_index; i >= 0; i--) {
		struct name_cache_entry *e = &dirp->name_cache[i];
		if (e->name && (conn->case_sensitive ? (strcmp(e->name, name) == 0) : strequal(e->name, name))) {
			*poffset = e->offset;
			SeekDir(dirp, e->offset);
			return True;
		}
	}
	for (i = NAME_CACHE_SIZE-1; i > dirp->name_cache_index; i--) {
		struct name_cache_entry *e = &dirp->name_cache[i];
		if (e->name && (conn->case_sensitive ? (strcmp(e->name, name) == 0) : strequal(e->name, name))) {
			*poffset = e->offset;
			SeekDir(dirp, e->offset);
			return True;
		}
	}

	/* Not found in the name cache. Rewind directory and start from scratch. */
	SMB_VFS_REWINDDIR(conn, dirp->dir);
	*poffset = 0;
	while ((entry = ReadDirName(dirp, poffset))) {
		if (conn->case_sensitive ? (strcmp(entry, name) == 0) : strequal(entry, name)) {
			return True;
		}
	}
	return False;
}
