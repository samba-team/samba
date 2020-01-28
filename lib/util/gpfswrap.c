/*
 *  Unix SMB/CIFS implementation.
 *  Wrapper for GPFS library
 *  Copyright (C) Volker Lendecke 2005
 *  Copyright (C) Christof Schmitt 2015
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

#include "replace.h"
#include "gpfswrap.h"

static int (*gpfs_set_share_fn)(int fd, unsigned int allow, unsigned int deny);
static int (*gpfs_set_lease_fn)(int fd, unsigned int type);
static int (*gpfs_getacl_fn)(const char *pathname, int flags, void *acl);
static int (*gpfs_putacl_fn)(const char *pathname, int flags, void *acl);
static int (*gpfs_get_realfilename_path_fn)(const char *pathname,
					    char *filenamep,
					    int *len);
static int (*gpfs_set_winattrs_path_fn)(const char *pathname,
					int flags,
					struct gpfs_winattr *attrs);
static int (*gpfs_set_winattrs_fn)(int fd, int flags,
				   struct gpfs_winattr *attrs);
static int (*gpfs_get_winattrs_path_fn)(const char *pathname,
					struct gpfs_winattr *attrs);
static int (*gpfs_get_winattrs_fn)(int fd, struct gpfs_winattr *attrs);
static int (*gpfs_ftruncate_fn)(int fd, gpfs_off64_t length);
static int (*gpfs_lib_init_fn)(int flags);
static int (*gpfs_set_times_path_fn)(char *pathname, int flags,
				     gpfs_timestruc_t times[4]);
static int (*gpfs_quotactl_fn)(const char *pathname,
			       int cmd,
			       int id,
			       void *bufp);
static int (*gpfs_init_trace_fn)(void);
static int (*gpfs_query_trace_fn)(void);
static void (*gpfs_add_trace_fn)(int level, const char *msg);
static void (*gpfs_fini_trace_fn)(void);
static int (*gpfs_fstat_x_fn)(int fd, unsigned int *litemask,
			      struct gpfs_iattr64 *iattr, size_t len);
static int (*gpfs_stat_x_fn)(const char *pathname, unsigned int *litemask,
			     struct gpfs_iattr64 *iattr, size_t len);

int gpfswrap_init(void)
{
	static void *l;

	if (l != NULL) {
		return 0;
	}

	l = dlopen("libgpfs.so", RTLD_LAZY);
	if (l == NULL) {
		return -1;
	}

	gpfs_set_share_fn	      = dlsym(l, "gpfs_set_share");
	gpfs_set_lease_fn	      = dlsym(l, "gpfs_set_lease");
	gpfs_getacl_fn		      = dlsym(l, "gpfs_getacl");
	gpfs_putacl_fn		      = dlsym(l, "gpfs_putacl");
	gpfs_get_realfilename_path_fn = dlsym(l, "gpfs_get_realfilename_path");
	gpfs_set_winattrs_path_fn     = dlsym(l, "gpfs_set_winattrs_path");
	gpfs_set_winattrs_fn	      = dlsym(l, "gpfs_set_winattrs");
	gpfs_get_winattrs_path_fn     = dlsym(l, "gpfs_get_winattrs_path");
	gpfs_get_winattrs_fn	      = dlsym(l, "gpfs_get_winattrs");
	gpfs_ftruncate_fn	      = dlsym(l, "gpfs_ftruncate");
	gpfs_lib_init_fn	      = dlsym(l, "gpfs_lib_init");
	gpfs_set_times_path_fn	      = dlsym(l, "gpfs_set_times_path");
	gpfs_quotactl_fn	      = dlsym(l, "gpfs_quotactl");
	gpfs_init_trace_fn	      = dlsym(l, "gpfs_init_trace");
	gpfs_query_trace_fn	      = dlsym(l, "gpfs_query_trace");
	gpfs_add_trace_fn	      = dlsym(l, "gpfs_add_trace");
	gpfs_fini_trace_fn	      = dlsym(l, "gpfs_fini_trace");
	gpfs_fstat_x_fn	      = dlsym(l, "gpfs_fstat_x");
	gpfs_stat_x_fn		      = dlsym(l, "gpfs_stat_x");

	return 0;
}

int gpfswrap_set_share(int fd, unsigned int allow, unsigned int deny)
{
	if (gpfs_set_share_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_set_share_fn(fd, allow, deny);
}

int gpfswrap_set_lease(int fd, unsigned int type)
{
	if (gpfs_set_lease_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_set_lease_fn(fd, type);
}

int gpfswrap_getacl(const char *pathname, int flags, void *acl)
{
	if (gpfs_getacl_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_getacl_fn(pathname, flags, acl);
}

int gpfswrap_putacl(const char *pathname, int flags, void *acl)
{
	if (gpfs_putacl_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_putacl_fn(pathname, flags, acl);
}

int gpfswrap_get_realfilename_path(const char *pathname,
				   char *filenamep,
				   int *len)
{
	if (gpfs_get_realfilename_path_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_get_realfilename_path_fn(pathname, filenamep, len);
}

int gpfswrap_set_winattrs_path(const char *pathname,
			       int flags,
			       struct gpfs_winattr *attrs)
{
	if (gpfs_set_winattrs_path_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_set_winattrs_path_fn(pathname, flags, attrs);
}

int gpfswrap_set_winattrs(int fd, int flags, struct gpfs_winattr *attrs)
{
	if (gpfs_set_winattrs_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_set_winattrs_fn(fd, flags, attrs);
}

int gpfswrap_get_winattrs_path(const char *pathname,
			       struct gpfs_winattr *attrs)
{
	if (gpfs_get_winattrs_path_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_get_winattrs_path_fn(pathname, attrs);
}

int gpfswrap_get_winattrs(int fd, struct gpfs_winattr *attrs)
{
	if (gpfs_get_winattrs_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_get_winattrs_fn(fd, attrs);
}

int gpfswrap_ftruncate(int fd, gpfs_off64_t length)
{
	if (gpfs_ftruncate_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_ftruncate_fn(fd, length);
}

int gpfswrap_lib_init(int flags)
{
	if (gpfs_lib_init_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_lib_init_fn(flags);
}

int gpfswrap_set_times_path(char *pathname, int flags,
			    gpfs_timestruc_t times[4])
{
	if (gpfs_set_times_path_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_set_times_path_fn(pathname, flags, times);
}

int gpfswrap_quotactl(const char *pathname, int cmd, int id, void *bufp)
{
	if (gpfs_quotactl_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_quotactl_fn(pathname, cmd, id, bufp);
}

int gpfswrap_init_trace(void)
{
	if (gpfs_init_trace_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_init_trace_fn();
}

int gpfswrap_query_trace(void)
{
	if (gpfs_query_trace_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_query_trace_fn();
}

void gpfswrap_add_trace(int level, const char *msg)
{
	if (gpfs_add_trace_fn == NULL) {
		return;
	}

	gpfs_add_trace_fn(level, msg);
}

void gpfswrap_fini_trace(void)
{
	if (gpfs_fini_trace_fn == NULL) {
		return;
	}

	gpfs_fini_trace_fn();
}

int gpfswrap_fstat_x(int fd, unsigned int *litemask,
		     struct gpfs_iattr64 *iattr, size_t len)
{
	if (gpfs_fstat_x_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_fstat_x_fn(fd, litemask, iattr, len);
}

int gpfswrap_stat_x(const char *pathname, unsigned int *litemask,
		    struct gpfs_iattr64 *iattr, size_t len)
{
	if (gpfs_stat_x_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_stat_x_fn(pathname, litemask, iattr, len);
}
