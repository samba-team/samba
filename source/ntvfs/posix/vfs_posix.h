/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - structure definitions

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

#ifndef _VFS_POSIX_H_
#define _VFS_POSIX_H_

/* this is the private structure for the posix vfs backend. It is used
   to hold per-connection (per tree connect) state information */
struct pvfs_state {
	struct smbsrv_tcon *tcon;
	const char *base_directory;

	const char *share_name;
	uint_t flags;

	struct {
		/* a linked list of open searches */
		struct pvfs_search_state *open_searches;

		/* search handles are returned to the clients so they
		   can continue searches */
		uint16_t next_search_handle;

		/* count of active searches */
		uint_t num_active_searches;

		/* during trans2 search continuations we need to use
		   the initial search attributes */
		uint16_t search_attrib;
	} search;

	struct pvfs_file *open_files;
};


/* this is the basic information needed about a file from the filesystem */
struct pvfs_dos_fileinfo {
	NTTIME create_time;
	NTTIME access_time;
	NTTIME write_time;
	NTTIME change_time;
	uint32_t attrib;
	uint64_t alloc_size;
	uint32_t nlink;
	uint32_t ea_size;
	uint64_t file_id;
};

/*
  this is the structure returned by pvfs_resolve_name(). It holds the posix details of
  a filename passed by the client to any function
*/
struct pvfs_filename {
	const char *original_name;
	char *full_name;
	const char *stream_name;
	BOOL has_wildcard;
	BOOL exists;
	struct stat st;
	struct pvfs_dos_fileinfo dos;
};


/* this holds a list of file names for a search. We deliberately do
   not hold the file stat information here to minimise the memory
   overhead of idle searches */
struct pvfs_dir {
	uint_t count;
	const char *unix_path;
	const char **names;
};

/* the state of a search started with pvfs_search_first() */
struct pvfs_search_state {
	struct pvfs_search_state *next, *prev;
	uint16_t handle;
	uint_t current_index;
	uint16_t search_attrib;
	struct pvfs_dir *dir;
};

/* open file state - this is a temporary implementation
   to allow some tests to work */
struct pvfs_file {
	struct pvfs_file *next, *prev;
	int fd;
	uint16_t fnum;
	struct pvfs_filename *name;

	/* we need to remember the session it was opened on,
	   as it is illegal to operate on someone elses fnum */
	struct smbsrv_session *session;

	/* we need to remember the client pid that 
	   opened the file so SMBexit works */
	uint16_t smbpid;
};


/* flags to pvfs_resolve_name() */
#define PVFS_RESOLVE_NO_WILDCARD (1<<0)
#define PVFS_RESOLVE_STREAMS     (1<<1)

/* flags in pvfs->flags */
#define PVFS_FLAG_CI_FILESYSTEM (1<<0) /* the filesystem is case insensitive */
#define PVFS_FLAG_MAP_ARCHIVE   (1<<1)
#define PVFS_FLAG_MAP_SYSTEM    (1<<2)
#define PVFS_FLAG_MAP_HIDDEN    (1<<3)
#define PVFS_FLAG_READONLY      (1<<4)

#endif /* _VFS_POSIX_H_ */
