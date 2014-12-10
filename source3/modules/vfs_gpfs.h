/*
   Unix SMB/CIFS implementation.
   Wrap gpfs calls in vfs functions.

   Copyright (C) Christian Ambach <cambach1@de.ibm.com> 2006

   Major code contributions by Chetan Shringarpure <chetan.sh@in.ibm.com>
                            and Gomati Mohanan <gomati.mohanan@in.ibm.com>

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

#ifndef GPFS_GETACL_NATIVE
#define GPFS_GETACL_NATIVE 0x00000004
#endif

int gpfswrap_init(void);
int gpfswrap_set_share(int fd, unsigned int allow, unsigned int deny);
int gpfswrap_set_lease(int fd, unsigned int type);
int gpfswrap_getacl(char *pathname, int flags, void *acl);
int gpfswrap_putacl(char *pathname, int flags, void *acl);
int gpfswrap_get_realfilename_path(char *pathname, char *filenamep, int *len);
int gpfswrap_set_winattrs_path(char *pathname, int flags,
			       struct gpfs_winattr *attrs);
int gpfswrap_get_winattrs_path(char *pathname, struct gpfs_winattr *attrs);
int gpfswrap_get_winattrs(int fd, struct gpfs_winattr *attrs);
int gpfswrap_prealloc(int fd, gpfs_off64_t start, gpfs_off64_t bytes);
int gpfswrap_ftruncate(int fd, gpfs_off64_t length);
int gpfswrap_lib_init(int flags);
int gpfswrap_set_times_path(char *pathname, int flags,
			    gpfs_timestruc_t times[4]);
int gpfswrap_quotactl(char *pathname, int cmd, int id, void *bufp);
int gpfswrap_fcntl(int fd, void *argp);
int gpfswrap_getfilesetid(char *pathname, char *name, int *idp);
int get_gpfs_quota(const char *pathname, int type, int id,
		   struct gpfs_quotaInfo *qi);
int get_gpfs_fset_id(const char *pathname, int *fset_id);
int smbd_gpfs_set_times_path(char *path, struct smb_file_time *ft);
