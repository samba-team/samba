/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   VFS structures and parameters
   Copyright (C) Tim Potter 1999
   
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

#ifndef _VFS_H
#define _VFS_H

/* Types used in the definition of VFS operations.  These are included
   here so the vfs.h file can be included by VFS modules without
   having to pull in unnecessary amounts of other stuff.  Note to VFS
   writers: you must include config.h before including this file.
   The following type definitions reference the HAVE_* symbols which
   are defined in config.h */

#ifndef SMB_OFF_T
#  ifdef HAVE_OFF64_T
#    define SMB_OFF_T off64_t
#  else
#    define SMB_OFF_T off_t
#  endif
#endif

#ifndef SMB_STRUCT_STAT
#  if defined(HAVE_STAT64) && defined(HAVE_OFF64_T)
#    define SMB_STRUCT_STAT struct stat64
#  else
#    define SMB_STRUCT_STAT struct stat
#  endif
#endif

#ifndef _BOOL
typedef int BOOL;
#endif

#ifndef _PSTRING
#define PSTRING_LEN 1024
#define FSTRING_LEN 128

typedef char pstring[PSTRING_LEN];
typedef char fstring[FSTRING_LEN];
#define _PSTRING
#endif

#if defined(HAVE_LONGLONG)
#define SMB_BIG_UINT unsigned long long
#else
#define SMB_BIG_UINT unsigned long
#endif

#ifndef MAXSUBAUTHS
#define MAXSUBAUTHS 15 /* max sub authorities in a SID */
#endif

#ifndef uint8
#define uint8 unsigned char
#endif 

#if !defined(uint32) && !defined(HAVE_UINT32_FROM_RPC_RPC_H)
#if (SIZEOF_INT == 4)
#define uint32 unsigned int
#elif (SIZEOF_LONG == 4)
#define uint32 unsigned long
#elif (SIZEOF_SHORT == 4)
#define uint32 unsigned short
#endif
#endif

#ifndef _DOM_SID
/* DOM_SID - security id */
typedef struct sid_info
{
  uint8  sid_rev_num;             /* SID revision number */
  uint8  num_auths;               /* number of sub-authorities */
  uint8  id_auth[6];              /* Identifier Authority */
  /*
   * Note that the values in these uint32's are in *native* byteorder,
   * not neccessarily little-endian...... JRA.
   */
  uint32 sub_auths[MAXSUBAUTHS];  /* pointer to sub-authorities. */

} DOM_SID;
#define _DOM_SID
#endif

/*
 * The complete list of SIDS belonging to this user.
 * Created when a vuid is registered.
 */

#ifndef _NT_USER_TOKEN
typedef struct _nt_user_token {
    size_t num_sids;
    DOM_SID *user_sids;
} NT_USER_TOKEN;
#define _NT_USER_TOKEN
#endif

/* Information from the connection_struct passed to the vfs layer */

struct vfs_connection_struct {

    /* Connection information */

    BOOL printer;
    BOOL ipc;
    BOOL read_only;
    BOOL admin_user;

    /* Handle on dlopen() call */

    void *dl_handle;

    /* Paths */

    pstring dirpath;
    pstring connectpath;
    pstring origpath;
    pstring service;
    
    /* Information on user who *opened* this connection */

    pstring user;
    uid_t uid;
    gid_t gid;
    int ngroups;
    gid_t *groups;
	NT_USER_TOKEN *nt_user_token;
};

/* Avoid conflict with an AIX include file */

#ifdef vfs_ops
#undef vfs_ops
#endif

/* VFS operations structure */

struct vfs_ops {

    /* Disk operations */
    
    int (*connect)(struct vfs_connection_struct *conn, char *service, 
		   char *user);
    void (*disconnect)(void);
    SMB_BIG_UINT (*disk_free)(char *path, BOOL small_query, SMB_BIG_UINT *bsize, 
			      SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize);
    
    /* Directory operations */

    DIR *(*opendir)(char *fname);
    struct dirent *(*readdir)(DIR *dirp);
    int (*mkdir)(char *path, mode_t mode);
    int (*rmdir)(char *path);
    int (*closedir)(DIR *dir);
    
    /* File operations */
    
    int (*open)(char *fname, int flags, mode_t mode);
    int (*close)(int fd);
    ssize_t (*read)(int fd, char *data, size_t n);
    ssize_t (*write)(int fd, char *data, size_t n);
    SMB_OFF_T (*lseek)(int filedes, SMB_OFF_T offset, int whence);
    int (*rename)(char *old, char *new);
    int (*fsync)(int fd);
    int (*stat)(char *fname, SMB_STRUCT_STAT *sbuf);
    int (*fstat)(int fd, SMB_STRUCT_STAT *sbuf);
    int (*lstat)(char *path, SMB_STRUCT_STAT *sbuf);
    int (*unlink)(char *path);
    int (*chmod)(char *path, mode_t mode);
	int (*chown)(char *path, uid_t uid, gid_t gid);
	int (*chdir)(char *path);
	char *(*getwd)(char *buf);
    int (*utime)(char *path, struct utimbuf *times);
	int (*ftruncate)(int fd, SMB_OFF_T offset);
	BOOL (*lock)(int fd, int op, SMB_OFF_T offset, SMB_OFF_T count, int type);
#if 0
	size_t (*fget_nt_acl)(int fd, SEC_DESC **ppdesc);
	size_t (*get_nt_acl)(char *name, SEC_DESC **ppdesc);
	BOOL (*fset_nt_acl)(int fd, uint32 security_info_sent, SEC_DESC *psd);
	BOOL (*set_nt_acl)(char *name, uint32 security_info_sent, SEC_DESC *psd);
#endif
};

struct vfs_options {
    struct vfs_options *prev, *next;
    char *name;
    char *value;
};

#endif /* _VFS_H */
