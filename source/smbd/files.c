/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Files[] structure handling
   Copyright (C) Andrew Tridgell 1998
   
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

static int real_max_open_files;

#define VALID_FNUM(fnum)   (((fnum) >= 0) && ((fnum) < real_max_open_files))

#define FILE_HANDLE_OFFSET 0x1000

static struct bitmap *file_bmap;

static files_struct *Files;
 
/* a fsp to use when chaining */
static files_struct *chain_fsp = NULL;
/* a fsp to use to save when breaking an oplock. */
static files_struct *oplock_save_chain_fsp = NULL;

static int files_used;

/****************************************************************************
 Return a unique number identifying this fsp over the life of this pid.
****************************************************************************/

static unsigned long get_gen_count(void)
{
	static unsigned long file_gen_counter;

	if ((++file_gen_counter) == 0)
		return ++file_gen_counter;
	return file_gen_counter;
}

/****************************************************************************
 Find first available file slot.
****************************************************************************/

files_struct *file_new(connection_struct *conn)
{
	int i;
	static int first_file;
	files_struct *fsp, *next;

	/* we want to give out file handles differently on each new
	   connection because of a common bug in MS clients where they try to
	   reuse a file descriptor from an earlier smb connection. This code
	   increases the chance that the errant client will get an error rather
	   than causing corruption */
	if (first_file == 0) {
		first_file = (sys_getpid() ^ (int)time(NULL)) % real_max_open_files;
	}

	i = bitmap_find(file_bmap, first_file);
	if (i == -1) {
		/* 
		 * Before we give up, go through the open files 
		 * and see if there are any files opened with a
		 * batch oplock. If so break the oplock and then
		 * re-use that entry (if it becomes closed).
		 * This may help as NT/95 clients tend to keep
		 * files batch oplocked for quite a long time
		 * after they have finished with them.
		 */
		for (fsp=Files;fsp;fsp=next) {
			next=fsp->next;
			if (attempt_close_oplocked_file(fsp)) {
				return file_new(conn);
			}
		}

		DEBUG(0,("ERROR! Out of file structures\n"));
		unix_ERR_class = ERRSRV;
		unix_ERR_code = ERRnofids;
		return NULL;
	}

	fsp = (files_struct *)malloc(sizeof(*fsp));
	if (!fsp) {
		unix_ERR_class = ERRSRV;
		unix_ERR_code = ERRnofids;
		return NULL;
	}

	ZERO_STRUCTP(fsp);
	fsp->fd = -1;
	fsp->conn = conn;
	fsp->file_id = get_gen_count();
	GetTimeOfDay(&fsp->open_time);

	first_file = (i+1) % real_max_open_files;

	bitmap_set(file_bmap, i);
	files_used++;

	fsp->fnum = i + FILE_HANDLE_OFFSET;
	SMB_ASSERT(fsp->fnum < 65536);

	string_set(&fsp->fsp_name,"");
	
	DLIST_ADD(Files, fsp);

	DEBUG(5,("allocated file structure %d, fnum = %d (%d used)\n",
		 i, fsp->fnum, files_used));

	chain_fsp = fsp;
	
	return fsp;
}

/****************************************************************************
 Close all open files for a connection.
****************************************************************************/

void file_close_conn(connection_struct *conn)
{
	files_struct *fsp, *next;
	
	for (fsp=Files;fsp;fsp=next) {
		next = fsp->next;
		if (fsp->conn == conn) {
			close_file(fsp,False); 
		}
	}
}

/****************************************************************************
 Initialise file structures.
****************************************************************************/

#define MAX_OPEN_FUDGEFACTOR 20

void file_init(void)
{
	int request_max_open_files = lp_max_open_files();
	int real_lim;

	/*
	 * Set the max_open files to be the requested
	 * max plus a fudgefactor to allow for the extra
	 * fd's we need such as log files etc...
	 */
	real_lim = set_maxfiles(request_max_open_files + MAX_OPEN_FUDGEFACTOR);

	real_max_open_files = real_lim - MAX_OPEN_FUDGEFACTOR;

	if (real_max_open_files + FILE_HANDLE_OFFSET + MAX_OPEN_PIPES > 65536)
		real_max_open_files = 65536 - FILE_HANDLE_OFFSET - MAX_OPEN_PIPES;

	if(real_max_open_files != request_max_open_files) {
		DEBUG(1,("file_init: Information only: requested %d \
open files, %d are available.\n", request_max_open_files, real_max_open_files));
	}

	SMB_ASSERT(real_max_open_files > 100);

	file_bmap = bitmap_allocate(real_max_open_files);
	
	if (!file_bmap) {
		exit_server("out of memory in file_init");
	}
	
	/*
	 * Ensure that pipe_handle_oppset is set correctly.
	 */
	set_pipe_handle_offset(real_max_open_files);
}

/****************************************************************************
 Close files open by a specified vuid.
****************************************************************************/

void file_close_user(int vuid)
{
	files_struct *fsp, *next;

	for (fsp=Files;fsp;fsp=next) {
		next=fsp->next;
		if (fsp->vuid == vuid) {
			close_file(fsp,False);
		}
	}
}

/****************************************************************************
 Find a fsp given a file descriptor.
****************************************************************************/

files_struct *file_find_fd(int fd)
{
	int count=0;
	files_struct *fsp;

	for (fsp=Files;fsp;fsp=fsp->next,count++) {
		if (fsp->fd == fd) {
			if (count > 10) {
				DLIST_PROMOTE(Files, fsp);
			}
			return fsp;
		}
	}

	return NULL;
}

/****************************************************************************
 Find a fsp given a device, inode and file_id.
****************************************************************************/

files_struct *file_find_dif(SMB_DEV_T dev, SMB_INO_T inode, unsigned long file_id)
{
	int count=0;
	files_struct *fsp;

	for (fsp=Files;fsp;fsp=fsp->next,count++) {
		if (fsp->fd != -1 &&
		    fsp->dev == dev && 
		    fsp->inode == inode &&
		    fsp->file_id == file_id ) {
			if (count > 10) {
				DLIST_PROMOTE(Files, fsp);
			}
			return fsp;
		}
	}

	return NULL;
}

/****************************************************************************
 Check if an fsp still exists.
****************************************************************************/

files_struct *file_find_fsp(files_struct *orig_fsp)
{
	files_struct *fsp;

    for (fsp=Files;fsp;fsp=fsp->next) {
        if (fsp == orig_fsp)
            return fsp;
    }

    return NULL;
}

/****************************************************************************
 Find the first fsp given a device and inode.
****************************************************************************/

files_struct *file_find_di_first(SMB_DEV_T dev, SMB_INO_T inode)
{
    files_struct *fsp;

    for (fsp=Files;fsp;fsp=fsp->next) {
        if ( fsp->fd != -1 &&
            fsp->dev == dev &&
            fsp->inode == inode )
            return fsp;
    }

    return NULL;
}

/****************************************************************************
 Find the next fsp having the same device and inode.
****************************************************************************/

files_struct *file_find_di_next(files_struct *start_fsp)
{
    files_struct *fsp;

    for (fsp = start_fsp->next;fsp;fsp=fsp->next) {
        if ( fsp->fd != -1 &&
            fsp->dev == start_fsp->dev &&
            fsp->inode == start_fsp->inode )
            return fsp;
    }

    return NULL;
}

/****************************************************************************
 Find a fsp that is open for printing.
****************************************************************************/

files_struct *file_find_print(void)
{
	files_struct *fsp;

	for (fsp=Files;fsp;fsp=fsp->next) {
		if (fsp->print_file) return fsp;
	} 

	return NULL;
}

/****************************************************************************
 Sync open files on a connection.
****************************************************************************/

void file_sync_all(connection_struct *conn)
{
	files_struct *fsp, *next;

	for (fsp=Files;fsp;fsp=next) {
		next=fsp->next;
		if ((conn == fsp->conn) && (fsp->fd != -1)) {
			sync_file(conn,fsp);
		}
	}
}

/****************************************************************************
 Free up a fsp.
****************************************************************************/

void file_free(files_struct *fsp)
{
	DLIST_REMOVE(Files, fsp);

	string_free(&fsp->fsp_name);

	bitmap_clear(file_bmap, fsp->fnum - FILE_HANDLE_OFFSET);
	files_used--;

	DEBUG(5,("freed files structure %d (%d used)\n",
		 fsp->fnum, files_used));

	/* this is paranoia, just in case someone tries to reuse the 
	   information */
	ZERO_STRUCTP(fsp);

	if (fsp == chain_fsp) chain_fsp = NULL;

	SAFE_FREE(fsp);
}

/****************************************************************************
 Get a fsp from a packet given the offset of a 16 bit fnum.
****************************************************************************/

files_struct *file_fsp(char *buf, int where)
{
	int fnum, count=0;
	files_struct *fsp;

	if (chain_fsp)
		return chain_fsp;

	fnum = SVAL(buf, where);

	for (fsp=Files;fsp;fsp=fsp->next, count++) {
		if (fsp->fnum == fnum) {
			chain_fsp = fsp;
			if (count > 10) {
				DLIST_PROMOTE(Files, fsp);
			}
			return fsp;
		}
	}
	return NULL;
}

/****************************************************************************
 Reset the chained fsp - done at the start of a packet reply.
****************************************************************************/

void file_chain_reset(void)
{
	chain_fsp = NULL;
}

/****************************************************************************
Save the chained fsp - done when about to do an oplock break.
****************************************************************************/

void file_chain_save(void)
{
	oplock_save_chain_fsp = chain_fsp;
}

/****************************************************************************
Restore the chained fsp - done after an oplock break.
****************************************************************************/

void file_chain_restore(void)
{
	chain_fsp = oplock_save_chain_fsp;
}
