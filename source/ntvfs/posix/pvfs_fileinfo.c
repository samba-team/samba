/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - 

   Copyright (C) Andrew Tridgell 2004

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

#include "include/includes.h"
#include "vfs_posix.h"


/* UNIX filetype mappings. */
#define UNIX_TYPE_FILE 0
#define UNIX_TYPE_DIR 1
#define UNIX_TYPE_SYMLINK 2
#define UNIX_TYPE_CHARDEV 3
#define UNIX_TYPE_BLKDEV 4
#define UNIX_TYPE_FIFO 5
#define UNIX_TYPE_SOCKET 6
#define UNIX_TYPE_UNKNOWN 0xFFFFFFFF


/*
 Return the major devicenumber for UNIX extensions.
*/
static uint32_t unix_dev_major(dev_t dev)
{
#if defined(HAVE_DEVICE_MAJOR_FN)
	return (uint32)major(dev);
#else
	return (uint32)(dev >> 8);
#endif
}

/*
 Return the minor devicenumber for UNIX extensions.
*/
static uint32_t unix_dev_minor(dev_t dev)
{
#if defined(HAVE_DEVICE_MINOR_FN)
	return (uint32)minor(dev);
#else
	return (uint32)(dev & 0xff);
#endif
}

/*
 Return the filetype for UNIX extensions
*/
static uint32_t unix_filetype(mode_t mode)
{
	if (S_ISREG(mode)) return UNIX_TYPE_FILE;
	if (S_ISDIR(mode)) return UNIX_TYPE_DIR;
#ifdef S_ISLNK
	if (S_ISLNK(mode)) return UNIX_TYPE_SYMLINK;
#endif
#ifdef S_ISCHR
	if (S_ISCHR(mode)) return UNIX_TYPE_CHARDEV;
#endif
#ifdef S_ISBLK
	if (S_ISBLK(mode)) return UNIX_TYPE_BLKDEV;
#endif
#ifdef S_ISFIFO
	if (S_ISFIFO(mode)) return UNIX_TYPE_FIFO;
#endif
#ifdef S_ISSOCK
	if (S_ISSOCK(mode)) return UNIX_TYPE_SOCKET;
#endif

	DEBUG(0,("unix_filetype: unknown filetype %u", (unsigned)mode));
	return UNIX_TYPE_UNKNOWN;
}


/*
  return all basic information about a file. This call is case-sensitive (it assumes that the 
  pathnames given have already had case conversion)
*/
NTSTATUS pvfs_relative_file_info_cs(struct pvfs_state *pvfs, const char *dir_path, 
				    const char *name, struct pvfs_file_info *finfo)
{
	char *full_name = NULL;
	struct stat st;

	asprintf(&full_name, "%s/%s", dir_path, name);
	if (full_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (stat(full_name, &st) == -1) {
		free(full_name);
		return pvfs_map_errno(pvfs, errno);
	}

	unix_to_nt_time(&finfo->create_time, st.st_ctime);
	unix_to_nt_time(&finfo->access_time, st.st_atime);
	unix_to_nt_time(&finfo->write_time, st.st_mtime);
	unix_to_nt_time(&finfo->change_time, st.st_mtime);
	finfo->attrib      = 0;
	finfo->alloc_size  = st.st_size;
	finfo->size        = st.st_size;
	finfo->nlink       = st.st_nlink;
	finfo->ea_size     = 0;
	finfo->file_id     = st.st_ino;
	finfo->unix_uid    = st.st_uid;
	finfo->unix_gid    = st.st_gid;
	finfo->unix_file_type = unix_filetype(st.st_mode);
	finfo->unix_dev_major = unix_dev_major(st.st_rdev);
	finfo->unix_dev_minor = unix_dev_minor(st.st_rdev);
	finfo->unix_permissions = unix_perms_to_wire(st.st_mode);

	return NT_STATUS_OK;
}
