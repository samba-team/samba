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
#include "libcli/security/security.h"
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
static int (*gpfs_quotactl_fn)(char *pathname, int cmd, int id, void *bufferP);
static int (*gpfs_fcntl_fn)(gpfs_file_t fileDesc, void *fcntlArgP);
static int (*gpfs_getfilesetid_fn)(char *pathname, char *name, int *idP);

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

bool set_gpfs_sharemode(files_struct *fsp, uint32 access_mask,
			uint32 share_access)
{
	unsigned int allow = GPFS_SHARE_NONE;
	unsigned int deny = GPFS_DENY_NONE;
	int result;

	if ((fsp == NULL) || (fsp->fh == NULL) || (fsp->fh->fd < 0)) {
		/* No real file, don't disturb */
		return True;
	}

	allow |= (access_mask & (FILE_WRITE_DATA|FILE_APPEND_DATA|
				 DELETE_ACCESS)) ? GPFS_SHARE_WRITE : 0;
	allow |= (access_mask & (FILE_READ_DATA|FILE_EXECUTE)) ?
		GPFS_SHARE_READ : 0;

	if (allow == GPFS_SHARE_NONE) {
		DEBUG(10, ("special case am=no_access:%x\n",access_mask));
	}
	else {	
		deny |= (share_access & FILE_SHARE_WRITE) ?
			0 : GPFS_DENY_WRITE;
		deny |= (share_access & (FILE_SHARE_READ)) ?
			0 : GPFS_DENY_READ;
	}
	DEBUG(10, ("am=%x, allow=%d, sa=%x, deny=%d\n",
		   access_mask, allow, share_access, deny));

	result = gpfswrap_set_share(fsp->fh->fd, allow, deny);
	if (result != 0) {
		if (errno == ENOSYS) {
			DEBUG(5, ("VFS module vfs_gpfs loaded, but gpfs "
				  "set_share function support not available. "
				  "Allowing access\n"));
			return True;
		} else {
			DEBUG(10, ("gpfs_set_share failed: %s\n",
				   strerror(errno)));
		}
	}

	return (result == 0);
}

int set_gpfs_lease(int fd, int leasetype)
{
	int gpfs_type = GPFS_LEASE_NONE;

	if (leasetype == F_RDLCK) {
		gpfs_type = GPFS_LEASE_READ;
	}
	if (leasetype == F_WRLCK) {
		gpfs_type = GPFS_LEASE_WRITE;
	}

	/* we unconditionally set CAP_LEASE, rather than looking for
	   -1/EACCES as there is a bug in some versions of
	   libgpfs_gpl.so which results in a leaked fd on /dev/ss0
	   each time we try this with the wrong capabilities set
	*/
	linux_set_lease_capability();
	return gpfswrap_set_lease(fd, gpfs_type);
}

int get_gpfs_quota(const char *pathname, int type, int id,
		   struct gpfs_quotaInfo *qi)
{
	int ret;

	if (!gpfs_quotactl_fn) {
		errno = ENOSYS;
		return -1;
	}

	ZERO_STRUCTP(qi);
	ret = gpfs_quotactl_fn(discard_const_p(char, pathname),
			       GPFS_QCMD(Q_GETQUOTA, type), id, qi);

	if (ret) {
		if (errno == GPFS_E_NO_QUOTA_INST) {
			DEBUG(10, ("Quotas disabled on GPFS filesystem.\n"));
		} else {
			DEBUG(0, ("Get quota failed, type %d, id, %d, "
				  "errno %d.\n", type, id, errno));
		}

		return ret;
	}

	DEBUG(10, ("quota type %d, id %d, blk u:%lld h:%lld s:%lld gt:%u\n",
		   type, id, qi->blockUsage, qi->blockHardLimit,
		   qi->blockSoftLimit, qi->blockGraceTime));

	return ret;
}

int get_gpfs_fset_id(const char *pathname, int *fset_id)
{
	int err, fd, errno_fcntl;

	struct {
		gpfsFcntlHeader_t hdr;
		gpfsGetFilesetName_t fsn;
	} arg;

	if (!gpfs_fcntl_fn || !gpfs_getfilesetid_fn) {
		errno = ENOSYS;
		return -1;
	}

	arg.hdr.totalLength = sizeof(arg);
	arg.hdr.fcntlVersion = GPFS_FCNTL_CURRENT_VERSION;
	arg.hdr.fcntlReserved = 0;
	arg.fsn.structLen = sizeof(arg.fsn);
	arg.fsn.structType = GPFS_FCNTL_GET_FILESETNAME;

	fd = open(pathname, O_RDONLY);
	if (fd == -1) {
		DEBUG(1, ("Could not open %s: %s\n",
			  pathname, strerror(errno)));
		return fd;
	}

	err = gpfs_fcntl_fn(fd, &arg);
	errno_fcntl = errno;
	close(fd);

	if (err) {
		errno = errno_fcntl;
		DEBUG(1, ("GPFS_FCNTL_GET_FILESETNAME for %s failed: %s\n",
			  pathname, strerror(errno)));
		return err;
	}

	err = gpfs_getfilesetid_fn(discard_const_p(char, pathname),
				   arg.fsn.buffer, fset_id);
	if (err) {
		DEBUG(1, ("gpfs_getfilesetid for %s failed: %s\n",
			  pathname, strerror(errno)));
	}
	return err;
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

	if (!gpfs_set_times_path_fn) {
		errno = ENOSYS;
		return -1;
	}

	ZERO_ARRAY(gpfs_times);
	timespec_to_gpfs_time(ft->atime, gpfs_times, 0, &flags);
	timespec_to_gpfs_time(ft->mtime, gpfs_times, 1, &flags);
	/* No good mapping from LastChangeTime to ctime, not storing */
	timespec_to_gpfs_time(ft->create_time, gpfs_times, 3, &flags);

	if (!flags) {
		DEBUG(10, ("nothing to do, return to avoid EINVAL\n"));
		return 0;
	}

	rc = gpfs_set_times_path_fn(path, flags, gpfs_times);

	if (rc != 0) {
		DEBUG(1,("gpfs_set_times() returned with error %s\n",
			strerror(errno)));
	}

	return rc;
}
