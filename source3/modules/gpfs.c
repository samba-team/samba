/*
 *  Unix SMB/CIFS implementation.
 *  Provide a connection to GPFS specific features
 *  Copyright (C) Volker Lendecke 2005
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

#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"

#include <fcntl.h>
#include <gpfs_fcntl.h>
#include "vfs_gpfs.h"

static int (*gpfs_set_share_fn)(int fd, unsigned int allow, unsigned int deny);
static int (*gpfs_set_lease_fn)(int fd, unsigned int type);
static int (*gpfs_getacl_fn)(char *pathname, int flags, void *acl);
static int (*gpfs_putacl_fn)(char *pathname, int flags, void *acl);
static int (*gpfs_get_realfilename_path_fn)(char *pathname, char *filenamep,
					    int *len);
static int (*gpfs_set_winattrs_path_fn)(char *pathname, int flags,
					struct gpfs_winattr *attrs);
static int (*gpfs_get_winattrs_path_fn)(char *pathname,
					struct gpfs_winattr *attrs);
static int (*gpfs_get_winattrs_fn)(int fd, struct gpfs_winattr *attrs);
static int (*gpfs_prealloc_fn)(int fd, gpfs_off64_t start, gpfs_off64_t bytes);
static int (*gpfs_ftruncate_fn)(int fd, gpfs_off64_t length);
static int (*gpfs_lib_init_fn)(int flags);
static int (*gpfs_set_times_path_fn)(char *pathname, int flags,
				     gpfs_timestruc_t times[4]);
static int (*gpfs_quotactl_fn)(char *pathname, int cmd, int id, void *bufp);
static int (*gpfs_fcntl_fn)(int fd, void *argp);
static int (*gpfs_getfilesetid_fn)(char *pathname, char *name, int *idp);

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
	gpfs_get_winattrs_path_fn     = dlsym(l, "gpfs_get_winattrs_path");
	gpfs_get_winattrs_fn	      = dlsym(l, "gpfs_get_winattrs");
	gpfs_prealloc_fn	      = dlsym(l, "gpfs_prealloc");
	gpfs_ftruncate_fn	      = dlsym(l, "gpfs_ftruncate");
	gpfs_lib_init_fn	      = dlsym(l, "gpfs_lib_init");
	gpfs_set_times_path_fn	      = dlsym(l, "gpfs_set_times_path");
	gpfs_quotactl_fn	      = dlsym(l, "gpfs_quotactl");
	gpfs_fcntl_fn		      = dlsym(l, "gpfs_fcntl");
	gpfs_getfilesetid_fn	      = dlsym(l, "gpfs_getfilesetid");

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

int gpfswrap_getacl(char *pathname, int flags, void *acl)
{
	if (gpfs_getacl_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_getacl_fn(pathname, flags, acl);
}

int gpfswrap_putacl(char *pathname, int flags, void *acl)
{
	if (gpfs_putacl_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_putacl_fn(pathname, flags, acl);
}

int gpfswrap_get_realfilename_path(char *pathname, char *filenamep, int *len)
{
	if (gpfs_get_realfilename_path_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_get_realfilename_path_fn(pathname, filenamep, len);
}

int gpfswrap_set_winattrs_path(char *pathname, int flags,
			       struct gpfs_winattr *attrs)
{
	if (gpfs_set_winattrs_path_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_set_winattrs_path_fn(pathname, flags, attrs);
}

int gpfswrap_get_winattrs_path(char *pathname, struct gpfs_winattr *attrs)
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

int gpfswrap_prealloc(int fd, gpfs_off64_t start, gpfs_off64_t bytes)
{
	if (gpfs_prealloc_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_prealloc_fn(fd, start, bytes);
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

int gpfswrap_quotactl(char *pathname, int cmd, int id, void *bufp)
{
	if (gpfs_quotactl_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_quotactl_fn(pathname, cmd, id, bufp);
}

int gpfswrap_fcntl(int fd, void *argp)
{
	if (gpfs_fcntl_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_fcntl_fn(fd, argp);
}

int gpfswrap_getfilesetid(char *pathname, char *name, int *idp)
{
	if (gpfs_getfilesetid_fn == NULL) {
		errno = ENOSYS;
		return -1;
	}

	return gpfs_getfilesetid_fn(pathname, name, idp);
}

static void timespec_to_gpfs_time(struct timespec ts, gpfs_timestruc_t *gt,
				  int idx, int *flags)
{
	if (!null_timespec(ts)) {
		*flags |= 1 << idx;
		gt[idx].tv_sec = ts.tv_sec;
		gt[idx].tv_nsec = ts.tv_nsec;
		DEBUG(10, ("Setting GPFS time %d, flags 0x%x\n", idx, *flags));
	}
}

int smbd_gpfs_set_times_path(char *path, struct smb_file_time *ft)
{
	gpfs_timestruc_t gpfs_times[4];
	int flags = 0;
	int rc;

	ZERO_ARRAY(gpfs_times);
	timespec_to_gpfs_time(ft->atime, gpfs_times, 0, &flags);
	timespec_to_gpfs_time(ft->mtime, gpfs_times, 1, &flags);
	/* No good mapping from LastChangeTime to ctime, not storing */
	timespec_to_gpfs_time(ft->create_time, gpfs_times, 3, &flags);

	if (!flags) {
		DEBUG(10, ("nothing to do, return to avoid EINVAL\n"));
		return 0;
	}

	rc = gpfswrap_set_times_path(path, flags, gpfs_times);

	if (rc != 0 && errno != ENOSYS) {
		DEBUG(1,("gpfs_set_times() returned with error %s\n",
			strerror(errno)));
	}

	return rc;
}
