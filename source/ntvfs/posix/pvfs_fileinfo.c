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


/****************************************************************************
 Change a unix mode to a dos mode.
****************************************************************************/
static uint32_t dos_mode_from_stat(struct pvfs_state *pvfs, struct stat *st)
{
	int result = 0;

	if ((st->st_mode & S_IWUSR) == 0)
		result |= FILE_ATTRIBUTE_READONLY;
	
	if ((pvfs->flags & PVFS_FLAG_MAP_ARCHIVE) && ((st->st_mode & S_IXUSR) != 0))
		result |= FILE_ATTRIBUTE_ARCHIVE;

	if ((pvfs->flags & PVFS_FLAG_MAP_SYSTEM) && ((st->st_mode & S_IXGRP) != 0))
		result |= FILE_ATTRIBUTE_SYSTEM;
	
	if ((pvfs->flags & PVFS_FLAG_MAP_HIDDEN) && ((st->st_mode & S_IXOTH) != 0))
		result |= FILE_ATTRIBUTE_HIDDEN;
  
	if (S_ISDIR(st->st_mode))
		result = FILE_ATTRIBUTE_DIRECTORY | (result & FILE_ATTRIBUTE_READONLY);

#if defined (HAVE_STAT_ST_BLOCKS) && defined (HAVE_STAT_ST_BLKSIZE)
	if (st->st_size > st->st_blocks * (off_t)st->st_blksize) {
		result |= FILE_ATTRIBUTE_SPARSE;
	}
#endif

	if (!(result & 
	      (FILE_ATTRIBUTE_READONLY|
	       FILE_ATTRIBUTE_ARCHIVE|
	       FILE_ATTRIBUTE_SYSTEM|
	       FILE_ATTRIBUTE_HIDDEN|
	       FILE_ATTRIBUTE_DIRECTORY))) {
		result |= FILE_ATTRIBUTE_NORMAL;
	}
 
	return result;
}



/*
  fill in the dos file attributes for a file
*/
NTSTATUS pvfs_fill_dos_info(struct pvfs_state *pvfs, struct pvfs_filename *name)
{
	/* for now just use the simple samba mapping */
	unix_to_nt_time(&name->dos.create_time, name->st.st_ctime);
	unix_to_nt_time(&name->dos.access_time, name->st.st_atime);
	unix_to_nt_time(&name->dos.write_time, name->st.st_mtime);
	unix_to_nt_time(&name->dos.change_time, name->st.st_mtime);
#ifdef HAVE_STAT_TV_NSEC
	name->dos.create_time += name->st.st_ctim.tv_nsec / 100;
	name->dos.access_time += name->st.st_atim.tv_nsec / 100;
	name->dos.write_time  += name->st.st_mtim.tv_nsec / 100;
	name->dos.change_time += name->st.st_mtim.tv_nsec / 100;
#endif
	name->dos.attrib = dos_mode_from_stat(pvfs, &name->st);
	name->dos.alloc_size = name->st.st_size;
	name->dos.nlink = name->st.st_nlink;
	name->dos.ea_size = 0;
	name->dos.file_id = (((uint64_t)name->st.st_dev)<<32) | name->st.st_ino;

	return NT_STATUS_OK;
}
