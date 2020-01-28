/*
 *  Unix SMB/CIFS implementation.
 *  Wrapper for GPFS library
 *  Copyright (C) Christian Ambach <cambach1@de.ibm.com> 2006
 *  Copyright (C) Christof Schmitt 2015
 *
 *  Major code contributions by Chetan Shringarpure <chetan.sh@in.ibm.com>
 *                           and Gomati Mohanan <gomati.mohanan@in.ibm.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __GPFSWRAP_H__
#define __GPFSWRAP_H__

#include <gpfs.h>

int gpfswrap_init(void);
int gpfswrap_set_share(int fd, unsigned int allow, unsigned int deny);
int gpfswrap_set_lease(int fd, unsigned int type);
int gpfswrap_getacl(const char *pathname, int flags, void *acl);
int gpfswrap_putacl(const char *pathname, int flags, void *acl);
int gpfswrap_get_realfilename_path(const char *pathname,
				   char *filenamep,
				   int *len);
int gpfswrap_set_winattrs_path(const char *pathname,
			       int flags,
			       struct gpfs_winattr *attrs);
int gpfswrap_set_winattrs(int fd, int flags, struct gpfs_winattr *attrs);
int gpfswrap_get_winattrs_path(const char *pathname,
			       struct gpfs_winattr *attrs);
int gpfswrap_get_winattrs(int fd, struct gpfs_winattr *attrs);
int gpfswrap_ftruncate(int fd, gpfs_off64_t length);
int gpfswrap_lib_init(int flags);
int gpfswrap_set_times_path(char *pathname, int flags,
			    gpfs_timestruc_t times[4]);
int gpfswrap_quotactl(const char *pathname, int cmd, int id, void *bufp);
int gpfswrap_init_trace(void);
int gpfswrap_query_trace(void);
void gpfswrap_add_trace(int level, const char *msg);
void gpfswrap_fini_trace(void);
int gpfswrap_fstat_x(int fd, unsigned int *litemask,
		     struct gpfs_iattr64 *iattr, size_t len);
int gpfswrap_stat_x(const char *pathname, unsigned int *litemask,
		    struct gpfs_iattr64 *iattr, size_t len);

#endif
