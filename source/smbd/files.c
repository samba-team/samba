/* 
   Unix SMB/CIFS implementation.
   Files[] structure handling
   Copyright (C) Andrew Tridgell 1998
   
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

static int real_max_open_files;

#define VALID_FNUM(fnum)   (((fnum) >= 0) && ((fnum) < real_max_open_files))

#define FILE_HANDLE_OFFSET 0x1000

static struct bitmap *file_bmap;

static files_struct *Files;
 
/* a fsp to use when chaining */
static files_struct *chain_fsp = NULL;

static int files_used;

/* A singleton cache to speed up searching by dev/inode. */
static struct fsp_singleton_cache {
	files_struct *fsp;
	struct file_id id;
} fsp_fi_cache;

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

NTSTATUS file_new(connection_struct *conn, files_struct **result)
{
	int i;
	static int first_file;
	files_struct *fsp;

	/* we want to give out file handles differently on each new
	   connection because of a common bug in MS clients where they try to
	   reuse a file descriptor from an earlier smb connection. This code
	   increases the chance that the errant client will get an error rather
	   than causing corruption */
	if (first_file == 0) {
		first_file = (sys_getpid() ^ (int)time(NULL)) % real_max_open_files;
	}

	/* TODO: Port the id-tree implementation from Samba4 */

	i = bitmap_find(file_bmap, first_file);
	if (i == -1) {
		DEBUG(0,("ERROR! Out of file structures\n"));
		/* TODO: We have to unconditionally return a DOS error here,
		 * W2k3 even returns ERRDOS/ERRnofids for ntcreate&x with
		 * NTSTATUS negotiated */
		return NT_STATUS_TOO_MANY_OPENED_FILES;
	}

	fsp = SMB_MALLOC_P(files_struct);
	if (!fsp) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(fsp);

	fsp->fh = SMB_MALLOC_P(struct fd_handle);
	if (!fsp->fh) {
		SAFE_FREE(fsp);
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(fsp->fh);

	fsp->fh->ref_count = 1;
	fsp->fh->fd = -1;

	fsp->conn = conn;
	fsp->fh->gen_id = get_gen_count();
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

	/* A new fsp invalidates the positive and
	  negative fsp_fi_cache as the new fsp is pushed
	  at the start of the list and we search from
	  a cache hit to the *end* of the list. */

	ZERO_STRUCT(fsp_fi_cache);

	conn->num_files_open++;

	*result = fsp;
	return NT_STATUS_OK;
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
			close_file(fsp,SHUTDOWN_CLOSE); 
		}
	}
}

/****************************************************************************
 Close all open files for a pid and a vuid.
****************************************************************************/

void file_close_pid(uint16 smbpid, int vuid)
{
	files_struct *fsp, *next;
	
	for (fsp=Files;fsp;fsp=next) {
		next = fsp->next;
		if ((fsp->file_pid == smbpid) && (fsp->vuid == vuid)) {
			close_file(fsp,SHUTDOWN_CLOSE); 
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
			close_file(fsp,SHUTDOWN_CLOSE);
		}
	}
}

/****************************************************************************
 Debug to enumerate all open files in the smbd.
****************************************************************************/

void file_dump_open_table(void)
{
	int count=0;
	files_struct *fsp;

	for (fsp=Files;fsp;fsp=fsp->next,count++) {
		DEBUG(10,("Files[%d], fnum = %d, name %s, fd = %d, gen = %lu, fileid=%s\n",
			count, fsp->fnum, fsp->fsp_name, fsp->fh->fd, (unsigned long)fsp->fh->gen_id,
			  file_id_string_tos(&fsp->file_id)));
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
		if (fsp->fh->fd == fd) {
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

files_struct *file_find_dif(struct file_id id, unsigned long gen_id)
{
	int count=0;
	files_struct *fsp;

	for (fsp=Files;fsp;fsp=fsp->next,count++) {
		/* We can have a fsp->fh->fd == -1 here as it could be a stat open. */
		if (file_id_equal(&fsp->file_id, &id) &&
		    fsp->fh->gen_id == gen_id ) {
			if (count > 10) {
				DLIST_PROMOTE(Files, fsp);
			}
			/* Paranoia check. */
			if ((fsp->fh->fd == -1) &&
			    (fsp->oplock_type != NO_OPLOCK) &&
			    (fsp->oplock_type != FAKE_LEVEL_II_OPLOCK)) {
				DEBUG(0,("file_find_dif: file %s file_id = %s, gen = %u \
oplock_type = %u is a stat open with oplock type !\n", fsp->fsp_name, 
					 file_id_string_tos(&fsp->file_id),
					 (unsigned int)fsp->fh->gen_id,
					 (unsigned int)fsp->oplock_type ));
				smb_panic("file_find_dif");
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
 We use a singleton cache here to speed up searching from getfilepathinfo
 calls.
****************************************************************************/

files_struct *file_find_di_first(struct file_id id)
{
	files_struct *fsp;

	if (file_id_equal(&fsp_fi_cache.id, &id)) {
		/* Positive or negative cache hit. */
		return fsp_fi_cache.fsp;
	}

	fsp_fi_cache.id = id;

	for (fsp=Files;fsp;fsp=fsp->next) {
		if (file_id_equal(&fsp->file_id, &id)) {
			/* Setup positive cache. */
			fsp_fi_cache.fsp = fsp;
			return fsp;
		}
	}

	/* Setup negative cache. */
	fsp_fi_cache.fsp = NULL;
	return NULL;
}

/****************************************************************************
 Find the next fsp having the same device and inode.
****************************************************************************/

files_struct *file_find_di_next(files_struct *start_fsp)
{
	files_struct *fsp;

	for (fsp = start_fsp->next;fsp;fsp=fsp->next) {
		if (file_id_equal(&fsp->file_id, &start_fsp->file_id)) {
			return fsp;
		}
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
		if (fsp->print_file) {
			return fsp;
		}
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
		if ((conn == fsp->conn) && (fsp->fh->fd != -1)) {
			sync_file(conn, fsp, True /* write through */);
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

	TALLOC_FREE(fsp->fake_file_handle);

	if (fsp->fh->ref_count == 1) {
		SAFE_FREE(fsp->fh);
	} else {
		fsp->fh->ref_count--;
	}

	if (fsp->notify) {
		notify_remove(fsp->conn->notify_ctx, fsp);
		TALLOC_FREE(fsp->notify);
	}

	/* Ensure this event will never fire. */
	TALLOC_FREE(fsp->oplock_timeout);

	/* Ensure this event will never fire. */
	TALLOC_FREE(fsp->update_write_time_event);

	bitmap_clear(file_bmap, fsp->fnum - FILE_HANDLE_OFFSET);
	files_used--;

	DEBUG(5,("freed files structure %d (%d used)\n",
		 fsp->fnum, files_used));

	fsp->conn->num_files_open--;

	if (fsp == chain_fsp) {
		chain_fsp = NULL;
	}

	/* Closing a file can invalidate the positive cache. */
	if (fsp == fsp_fi_cache.fsp) {
		ZERO_STRUCT(fsp_fi_cache);
	}

	/* Drop all remaining extensions. */
	while (fsp->vfs_extension) {
		vfs_remove_fsp_extension(fsp->vfs_extension->owner, fsp);
	}

	/* this is paranoia, just in case someone tries to reuse the
	   information */
	ZERO_STRUCTP(fsp);

	SAFE_FREE(fsp);
}

/****************************************************************************
 Get an fsp from a 16 bit fnum.
****************************************************************************/

files_struct *file_fnum(uint16 fnum)
{
	files_struct *fsp;
	int count=0;

	for (fsp=Files;fsp;fsp=fsp->next, count++) {
		if (fsp->fnum == fnum) {
			if (count > 10) {
				DLIST_PROMOTE(Files, fsp);
			}
			return fsp;
		}
	}
	return NULL;
}

/****************************************************************************
 Get an fsp from a packet given the offset of a 16 bit fnum.
****************************************************************************/

files_struct *file_fsp(uint16 fid)
{
	files_struct *fsp;

	if (chain_fsp) {
		return chain_fsp;
	}

	fsp = file_fnum(fid);
	if (fsp) {
		chain_fsp = fsp;
	}
	return fsp;
}

/****************************************************************************
 Reset the chained fsp - done at the start of a packet reply.
****************************************************************************/

void file_chain_reset(void)
{
	chain_fsp = NULL;
}

/****************************************************************************
 Duplicate the file handle part for a DOS or FCB open.
****************************************************************************/

void dup_file_fsp(files_struct *from,
				uint32 access_mask,
				uint32 share_access,
				uint32 create_options,
		      		files_struct *to)
{
	SAFE_FREE(to->fh);

	to->fh = from->fh;
	to->fh->ref_count++;

	to->file_id = from->file_id;
	to->initial_allocation_size = from->initial_allocation_size;
	to->mode = from->mode;
	to->file_pid = from->file_pid;
	to->vuid = from->vuid;
	to->open_time = from->open_time;
	to->access_mask = access_mask;
	to->share_access = share_access;
	to->oplock_type = from->oplock_type;
	to->can_lock = from->can_lock;
	to->can_read = (access_mask & (FILE_READ_DATA)) ? True : False;
	if (!CAN_WRITE(from->conn)) {
		to->can_write = False;
	} else {
		to->can_write = (access_mask & (FILE_WRITE_DATA | FILE_APPEND_DATA)) ? True : False;
	}
	to->print_file = from->print_file;
	to->modified = from->modified;
	to->is_directory = from->is_directory;
	to->aio_write_behind = from->aio_write_behind;
        string_set(&to->fsp_name,from->fsp_name);
}
