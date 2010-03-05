/*
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - pvfs_sys wrappers

   Copyright (C) Andrew Tridgell 2010
   Copyright (C) Andrew Bartlett 2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "vfs_posix.h"
#include "../lib/util/unix_privs.h"

/*
  these wrapper functions must only be called when the appropriate ACL
  has already been checked. The wrappers will override a EACCES result
  by gaining root privileges if the 'pvfs:perm override' is set on the
  share (it is enabled by default)
 */


/*
  chown a file that we created with a root privileges override
 */
static int pvfs_sys_fchown(struct pvfs_state *pvfs, void *privs, int fd)
{
	return fchown(fd, root_privileges_original_uid(privs), -1);
}

/*
  chown a directory that we created with a root privileges override
 */
static int pvfs_sys_chown(struct pvfs_state *pvfs, void *privs, const char *name)
{
	return chown(name, root_privileges_original_uid(privs), -1);
}


/*
  wrap open for system override
*/
int pvfs_sys_open(struct pvfs_state *pvfs, const char *filename, int flags, mode_t mode)
{
	int fd, ret;
	void *privs;
	int saved_errno, orig_errno;
	int retries = 5;

	orig_errno = errno;

	fd = open(filename, flags, mode);
	if (fd != -1 ||
	    !(pvfs->flags & PVFS_FLAG_PERM_OVERRIDE) ||
	    errno != EACCES) {
		return fd;
	}

	saved_errno = errno;
	privs = root_privileges();

	/* don't allow permission overrides to follow links */
#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif

	/*
	   if O_CREAT was specified and O_EXCL was not specified
	   then initially do the open without O_CREAT, as in that case
	   we know that we did not create the file, so we don't have
	   to fchown it
	 */
	if ((flags & O_CREAT) && !(flags & O_EXCL)) {
	try_again:
		fd = open(filename, flags & ~O_CREAT, mode);
		/* if this open succeeded, or if it failed
		   with anything other than ENOENT, then we return the
		   open result, with the original errno */
		if (fd == -1 && errno != ENOENT) {
			talloc_free(privs);
			errno = saved_errno;
			return -1;
		}
		if (fd != -1) {
			/* the file already existed and we opened it */
			talloc_free(privs);
			errno = orig_errno;
			return fd;
		}

		fd = open(filename, flags | O_EXCL, mode);
		if (fd == -1 && errno != EEXIST) {
			talloc_free(privs);
			errno = saved_errno;
			return -1;
		}
		if (fd != -1) {
			/* we created the file, we need to set the
			   right ownership on it */
			ret = pvfs_sys_fchown(pvfs, privs, fd);
			if (ret == -1) {
				close(fd);
				unlink(filename);
				talloc_free(privs);
				errno = saved_errno;
				return -1;
			}
			talloc_free(privs);
			errno = orig_errno;
			return fd;
		}

		/* the file got created between the two times
		   we tried to open it! Try again */
		if (retries-- > 0) {
			goto try_again;
		}

		talloc_free(privs);
		errno = saved_errno;
		return -1;
	}

	fd = open(filename, flags, mode);
	if (fd == -1) {
		talloc_free(privs);
		errno = saved_errno;
		return -1;
	}

	/* if we have created a file then fchown it */
	if (flags & O_CREAT) {
		ret = pvfs_sys_fchown(pvfs, privs, fd);
		if (ret == -1) {
			close(fd);
			unlink(filename);
			talloc_free(privs);
			errno = saved_errno;
			return -1;
		}
	}

	talloc_free(privs);
	return fd;
}


/*
  wrap unlink for system override
*/
int pvfs_sys_unlink(struct pvfs_state *pvfs, const char *filename)
{
	int ret;
	void *privs;
	int saved_errno, orig_errno;

	orig_errno = errno;

	ret = unlink(filename);
	if (ret != -1 ||
	    !(pvfs->flags & PVFS_FLAG_PERM_OVERRIDE) ||
	    errno != EACCES) {
		return ret;
	}

	saved_errno = errno;

	privs = root_privileges();
	ret = unlink(filename);
	if (ret == -1) {
		errno = saved_errno;
		talloc_free(privs);
		return -1;
	}

	errno = orig_errno;
	talloc_free(privs);
	return ret;
}


/*
  wrap rename for system override
*/
int pvfs_sys_rename(struct pvfs_state *pvfs, const char *name1, const char *name2)
{
	int ret;
	void *privs;
	int saved_errno, orig_errno;

	orig_errno = errno;

	ret = rename(name1, name2);
	if (ret != -1 ||
	    !(pvfs->flags & PVFS_FLAG_PERM_OVERRIDE) ||
	    errno != EACCES) {
		return ret;
	}

	saved_errno = errno;

	privs = root_privileges();
	ret = rename(name1, name2);
	if (ret == -1) {
		errno = saved_errno;
		talloc_free(privs);
		return -1;
	}

	errno = orig_errno;
	talloc_free(privs);
	return ret;
}


/*
  wrap mkdir for system override
*/
int pvfs_sys_mkdir(struct pvfs_state *pvfs, const char *dirname, mode_t mode)
{
	int ret;
	void *privs;
	int saved_errno, orig_errno;

	orig_errno = errno;

	ret = mkdir(dirname, mode);
	if (ret != -1 ||
	    !(pvfs->flags & PVFS_FLAG_PERM_OVERRIDE) ||
	    errno != EACCES) {
		return ret;
	}

	saved_errno = errno;
	privs = root_privileges();

	ret = mkdir(dirname, mode);
	if (ret == -1) {
		talloc_free(privs);
		errno = saved_errno;
		return -1;
	}

	ret = pvfs_sys_chown(pvfs, privs, dirname);
	if (ret == -1) {
		rmdir(dirname);
		talloc_free(privs);
		errno = saved_errno;
		return -1;
	}

	talloc_free(privs);
	return ret;
}


/*
  wrap rmdir for system override
*/
int pvfs_sys_rmdir(struct pvfs_state *pvfs, const char *dirname)
{
	int ret;
	void *privs;
	int saved_errno, orig_errno;

	orig_errno = errno;

	ret = rmdir(dirname);
	if (ret != -1 ||
	    !(pvfs->flags & PVFS_FLAG_PERM_OVERRIDE) ||
	    errno != EACCES) {
		return ret;
	}

	saved_errno = errno;

	privs = root_privileges();
	ret = rmdir(dirname);
	if (ret == -1) {
		errno = saved_errno;
		talloc_free(privs);
		return -1;
	}

	errno = orig_errno;
	talloc_free(privs);
	return ret;
}
