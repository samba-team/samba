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

bool set_gpfs_sharemode(files_struct *fsp, uint32 access_mask,
			uint32 share_access);
int set_gpfs_lease(int fd, int leasetype);
int smbd_gpfs_getacl(char *pathname, int flags, void *acl);
int smbd_gpfs_putacl(char *pathname, int flags, void *acl);
int smbd_gpfs_get_realfilename_path(char *pathname, char *filenamep,
				    int *buflen);
int smbd_fget_gpfs_winattrs(int fd, struct gpfs_winattr *attrs);
int get_gpfs_winattrs(char * pathname,struct gpfs_winattr *attrs);
int set_gpfs_winattrs(char * pathname,int flags,struct gpfs_winattr *attrs);
int smbd_gpfs_prealloc(int fd, gpfs_off64_t start, gpfs_off64_t bytes);
int smbd_gpfs_ftruncate(int fd, gpfs_off64_t length);
int get_gpfs_quota(const char *pathname, int type, int id,
		   struct gpfs_quotaInfo *qi);
int get_gpfs_fset_id(const char *pathname, int *fset_id);
int smbd_gpfs_set_times_path(char *path, struct smb_file_time *ft);

void init_gpfs(void);
void smbd_gpfs_lib_init(void);
