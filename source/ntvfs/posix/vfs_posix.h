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

#include "smb_server/smb_server.h"

/* this is the private structure for the posix vfs backend. It is used
   to hold per-connection (per tree connect) state information */
struct pvfs_state {
	struct smbsrv_tcon *tcon;
	const char *base_directory;

	const char *share_name;
	uint_t flags;

	struct pvfs_file *open_files;

	struct pvfs_mangle_context *mangle_ctx;

	struct brl_context *brl_context;
	struct odb_context *odb_context;
	struct sidmap_context *sidmap;

	/* an id tree mapping open search ID to a pvfs_search_state structure */
	struct idr_context *idtree_search;

	/* an id tree mapping open file handle -> struct pvfs_file */
	struct idr_context *idtree_fnum;

	/* a list of pending async requests. Needed to support
	   ntcancel */
	struct pvfs_wait *wait_list;

	/* the sharing violation timeout */
	uint_t sharing_violation_delay;

	/* filesystem attributes (see FS_ATTR_*) */
	uint32_t fs_attribs;

	/* if posix:eadb is set, then this gets setup */
	struct tdb_wrap *ea_db;

	/* used to accelerate acl mapping */
	struct {
		const struct dom_sid *creator_owner;
		const struct dom_sid *creator_group;		
	} sid_cache;
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
	uint32_t flags;
};

/*
  this is the structure returned by pvfs_resolve_name(). It holds the posix details of
  a filename passed by the client to any function
*/
struct pvfs_filename {
	const char *original_name;
	char *full_name;
	const char *stream_name; /* does not include :$DATA suffix */
	uint32_t stream_id;      /* this uses a hash, so is probabilistic */
	BOOL has_wildcard;
	BOOL exists;          /* true if the base filename exists */
	BOOL stream_exists;   /* true if the stream exists */
	struct stat st;
	struct pvfs_dos_fileinfo dos;
};


/* open file handle state - encapsulates the posix fd

   Note that this is separated from the pvfs_file structure in order
   to cope with the openx DENY_DOS semantics where a 2nd DENY_DOS open
   on the same connection gets the same low level filesystem handle,
   rather than a new handle
*/
struct pvfs_file_handle {
	int fd;

	struct pvfs_filename *name;

	/* a unique file key to be used for open file locking */
	DATA_BLOB odb_locking_key;

	/* a unique file key to be used for byte range locking */
	DATA_BLOB brl_locking_key;

	uint32_t create_options;

	/* this is set by the mode_information level. What does it do? */
	uint32_t mode;

	/* yes, we need 2 independent positions ... */
	uint64_t seek_offset;
	uint64_t position;

	BOOL have_opendb_entry;

	/* we need this hook back to our parent for lock destruction */
	struct pvfs_state *pvfs;

	/* have we set a sticky write time that we should remove on close */
	BOOL sticky_write_time;
};

/* open file state */
struct pvfs_file {
	struct pvfs_file *next, *prev;
	struct pvfs_file_handle *handle;
	uint16_t fnum;

	struct pvfs_state *pvfs;

	uint32_t impersonation;
	uint32_t share_access;
	uint32_t access_mask;

	/* we need to remember the session it was opened on,
	   as it is illegal to operate on someone elses fnum */
	struct smbsrv_session *session;

	/* we need to remember the client pid that 
	   opened the file so SMBexit works */
	uint16_t smbpid;

	/* a list of pending locks - used for locking cancel operations */
	struct pvfs_pending_lock *pending_list;

	/* a count of active locks - used to avoid calling brl_close on
	   file close */
	uint64_t lock_count;
};


struct pvfs_mangle_context {
	uint8_t char_flags[256];
	/*
	  this determines how many characters are used from the original
	  filename in the 8.3 mangled name. A larger value leads to a weaker
	  hash and more collisions.  The largest possible value is 6.
	*/
	int mangle_prefix;
	uint32_t mangle_modulus;

	/* we will use a very simple direct mapped prefix cache. The big
	   advantage of this cache structure is speed and low memory usage 

	   The cache is indexed by the low-order bits of the hash, and confirmed by
	   hashing the resulting cache entry to match the known hash
	*/
	char **prefix_cache;
	uint32_t *prefix_cache_hashes;

	/* this is used to reverse the base 36 mapping */
	unsigned char base_reverse[256];
};



/* flags to pvfs_resolve_name() */
#define PVFS_RESOLVE_WILDCARD    (1<<0)
#define PVFS_RESOLVE_STREAMS     (1<<1)

/* flags in pvfs->flags */
#define PVFS_FLAG_CI_FILESYSTEM  (1<<0) /* the filesystem is case insensitive */
#define PVFS_FLAG_MAP_ARCHIVE    (1<<1)
#define PVFS_FLAG_MAP_SYSTEM     (1<<2)
#define PVFS_FLAG_MAP_HIDDEN     (1<<3)
#define PVFS_FLAG_READONLY       (1<<4)
#define PVFS_FLAG_STRICT_SYNC    (1<<5)
#define PVFS_FLAG_STRICT_LOCKING (1<<6)
#define PVFS_FLAG_XATTR_ENABLE   (1<<7)
#define PVFS_FLAG_FAKE_OPLOCKS   (1<<8)

/* forward declare some anonymous structures */
struct pvfs_dir;

/* types of notification for pvfs wait events */
enum pvfs_wait_notice {PVFS_WAIT_EVENT, PVFS_WAIT_TIMEOUT, PVFS_WAIT_CANCEL};


/* putting this prototype here avoids us having to expose this whole header in the
   rest of Samba */
void *pvfs_wait_message(struct pvfs_state *pvfs, 
			 struct smbsrv_request *req, 
			 int msg_type, 
			 struct timeval end_time,
			 void (*fn)(void *, enum pvfs_wait_notice),
			 void *private);

#endif /* _VFS_POSIX_H_ */
