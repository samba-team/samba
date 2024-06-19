/*
   Unix SMB/CIFS implementation.
   Wrap disk only vfs functions to sidestep dodgy compilers.
   Copyright (C) Tim Potter 1998
   Copyright (C) Jeremy Allison 2007
   Copyright (C) Brian Chrisman 2011 <bchrisman@gmail.com>
   Copyright (C) Richard Sharpe 2011 <realrichardsharpe@gmail.com>

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

/*
 * This VFS only works with the libcephfs.so user-space client. It is not needed
 * if you are using the kernel client or the FUSE client.
 *
 * Add the following smb.conf parameter to each share that will be hosted on
 * Ceph:
 *
 *   vfs objects = [any others you need go here] ceph_new
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include <dirent.h>
#include <sys/statvfs.h>
#include "cephfs/libcephfs.h"
#include "smbprofile.h"
#include "modules/posixacl_xattr.h"
#include "lib/util/tevent_unix.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#ifndef LIBCEPHFS_VERSION
#define LIBCEPHFS_VERSION(maj, min, extra) ((maj << 16) + (min << 8) + extra)
#define LIBCEPHFS_VERSION_CODE LIBCEPHFS_VERSION(0, 0, 0)
#endif

/*
 * Use %llu whenever we have a 64bit unsigned int, and cast to (long long
 * unsigned)
 */
#define llu(_var) ((long long unsigned)_var)

/*
 * Note, libcephfs's return code model is to return -errno. Thus we have to
 * convert to what Samba expects: set errno to non-negative value and return -1.
 *
 * Using convenience helper functions to avoid non-hygienic macro.
 */
static int status_code(int ret)
{
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	errno = 0;
	return ret;
}

static ssize_t lstatus_code(intmax_t ret)
{
	if (ret < 0) {
		errno = -((int)ret);
		return -1;
	}
	errno = 0;
	return (ssize_t)ret;
}

/*
 * Track unique connections, as virtual mounts, to cephfs file systems.
 * Individual mount-entries will be set on the handle->data attribute, but
 * the mounts themselves will be shared so as not to spawn extra mounts
 * to the same cephfs.
 *
 * Individual mounts are IDed by a 'cookie' value that is a string built
 * from identifying parameters found in smb.conf.
 */

static struct cephmount_cached {
	char *cookie;
	uint32_t count;
	struct ceph_mount_info *mount;
	struct cephmount_cached *next, *prev;
	uint64_t fd_index;
} *cephmount_cached;

static int cephmount_cache_add(const char *cookie,
			       struct ceph_mount_info *mount,
			       struct cephmount_cached **out_entry)
{
	struct cephmount_cached *entry = NULL;

	entry = talloc_zero(NULL, struct cephmount_cached);
	if (entry == NULL) {
		errno = ENOMEM;
		return -1;
	}

	entry->cookie = talloc_strdup(entry, cookie);
	if (entry->cookie == NULL) {
		talloc_free(entry);
		errno = ENOMEM;
		return -1;
	}

	entry->mount = mount;
	entry->count = 1;

	DBG_DEBUG("adding mount cache entry for %s\n", entry->cookie);
	DLIST_ADD(cephmount_cached, entry);

	*out_entry = entry;
	return 0;
}

static struct cephmount_cached *cephmount_cache_update(const char *cookie)
{
	struct cephmount_cached *entry = NULL;

	for (entry = cephmount_cached; entry; entry = entry->next) {
		if (strcmp(entry->cookie, cookie) == 0) {
			entry->count++;
			DBG_DEBUG("updated mount cache: count is [%"
				  PRIu32 "]\n", entry->count);
			return entry;
		}
	}

	errno = ENOENT;
	return NULL;
}

static int cephmount_cache_remove(struct cephmount_cached *entry)
{
	if (--entry->count) {
		DBG_DEBUG("updated mount cache: count is [%" PRIu32 "]\n",
			  entry->count);
		return entry->count;
	}

	DBG_DEBUG("removing mount cache entry for %s\n", entry->cookie);
	DLIST_REMOVE(cephmount_cached, entry);
	talloc_free(entry);
	return 0;
}

static char *cephmount_get_cookie(TALLOC_CTX * mem_ctx, const int snum)
{
	const char *conf_file =
	    lp_parm_const_string(snum, "ceph", "config_file", ".");
	const char *user_id = lp_parm_const_string(snum, "ceph", "user_id", "");
	const char *fsname =
	    lp_parm_const_string(snum, "ceph", "filesystem", "");
	return talloc_asprintf(mem_ctx, "(%s/%s/%s)", conf_file, user_id,
			       fsname);
}

static int cephmount_select_fs(struct ceph_mount_info *mnt, const char *fsname)
{
	/*
	 * ceph_select_filesystem was added in ceph 'nautilus' (v14).
	 * Earlier versions of libcephfs will lack that API function.
	 * At the time of this writing (Feb 2023) all versions of ceph
	 * supported by ceph upstream have this function.
	 */
#if defined(HAVE_CEPH_SELECT_FILESYSTEM)
	DBG_DEBUG("[CEPH] calling: ceph_select_filesystem with %s\n", fsname);
	return ceph_select_filesystem(mnt, fsname);
#else
	DBG_ERR("[CEPH] ceph_select_filesystem not available\n");
	return -ENOTSUP;
#endif
}

static struct ceph_mount_info *cephmount_mount_fs(const int snum)
{
	int ret;
	char buf[256];
	struct ceph_mount_info *mnt = NULL;
	/* if config_file and/or user_id are NULL, ceph will use defaults */
	const char *conf_file =
	    lp_parm_const_string(snum, "ceph", "config_file", NULL);
	const char *user_id =
	    lp_parm_const_string(snum, "ceph", "user_id", NULL);
	const char *fsname =
	    lp_parm_const_string(snum, "ceph", "filesystem", NULL);

	DBG_DEBUG("[CEPH] calling: ceph_create\n");
	ret = ceph_create(&mnt, user_id);
	if (ret) {
		errno = -ret;
		return NULL;
	}

	DBG_DEBUG("[CEPH] calling: ceph_conf_read_file with %s\n",
		  (conf_file == NULL ? "default path" : conf_file));
	ret = ceph_conf_read_file(mnt, conf_file);
	if (ret) {
		goto err_cm_release;
	}

	DBG_DEBUG("[CEPH] calling: ceph_conf_get\n");
	ret = ceph_conf_get(mnt, "log file", buf, sizeof(buf));
	if (ret < 0) {
		goto err_cm_release;
	}

	/* libcephfs disables POSIX ACL support by default, enable it... */
	ret = ceph_conf_set(mnt, "client_acl_type", "posix_acl");
	if (ret < 0) {
		goto err_cm_release;
	}
	/* tell libcephfs to perform local permission checks */
	ret = ceph_conf_set(mnt, "fuse_default_permissions", "false");
	if (ret < 0) {
		goto err_cm_release;
	}
	/*
	 * select a cephfs file system to use:
	 * In ceph, multiple file system support has been stable since
	 * 'pacific'. Permit different shares to access different file systems.
	 */
	if (fsname != NULL) {
		ret = cephmount_select_fs(mnt, fsname);
		if (ret < 0) {
			goto err_cm_release;
		}
	}

	DBG_DEBUG("[CEPH] calling: ceph_mount\n");
	ret = ceph_mount(mnt, NULL);
	if (ret >= 0) {
		goto cm_done;
	}

      err_cm_release:
	ceph_release(mnt);
	mnt = NULL;
	DBG_DEBUG("[CEPH] Error mounting fs: %s\n", strerror(-ret));
      cm_done:
	/*
	 * Handle the error correctly. Ceph returns -errno.
	 */
	if (ret) {
		errno = -ret;
	}
	return mnt;
}

/* Check for NULL pointer parameters in vfs_ceph_* functions */

/* We don't want to have NULL function pointers lying around.  Someone
   is sure to try and execute them.  These stubs are used to prevent
   this possibility. */

static int vfs_ceph_connect(struct vfs_handle_struct *handle,
			    const char *service, const char *user)
{
	int ret = 0;
	struct cephmount_cached *entry = NULL;
	struct ceph_mount_info *cmount = NULL;
	int snum = SNUM(handle->conn);
	char *cookie = cephmount_get_cookie(handle, snum);
	if (cookie == NULL) {
		return -1;
	}

	entry = cephmount_cache_update(cookie);
	if (entry != NULL) {
		goto connect_ok;
	}

	cmount = cephmount_mount_fs(snum);
	if (cmount == NULL) {
		ret = -1;
		goto connect_fail;
	}
	ret = cephmount_cache_add(cookie, cmount, &entry);
	if (ret != 0) {
		goto connect_fail;
	}

connect_ok:
	handle->data = entry;
	DBG_WARNING("Connection established with the server: %s\n", cookie);

	/*
	 * Unless we have an async implementation of getxattrat turn this off.
	 */
	lp_do_parameter(SNUM(handle->conn), "smbd async dosmode", "false");
connect_fail:
	talloc_free(cookie);
	return ret;
}

static struct ceph_mount_info *cmount_of(const struct vfs_handle_struct *handle)
{
	const struct cephmount_cached *entry = handle->data;

	return entry->mount;
}

static void vfs_ceph_disconnect(struct vfs_handle_struct *handle)
{
	struct ceph_mount_info *cmount = cmount_of(handle);
	int ret = 0;

	ret = cephmount_cache_remove(handle->data);
	if (ret > 0) {
		DBG_DEBUG("mount cache entry still in use\n");
		return;
	}

	ret = ceph_unmount(cmount);
	if (ret < 0) {
		DBG_ERR("[CEPH] failed to unmount: %s\n", strerror(-ret));
	}

	ret = ceph_release(cmount);
	if (ret < 0) {
		DBG_ERR("[CEPH] failed to release: %s\n", strerror(-ret));
	}
	handle->data = NULL;
}

/* Ceph user-credentials */
static struct UserPerm *vfs_ceph_userperm_new(
	const struct vfs_handle_struct *handle)
{
	const struct security_unix_token *unix_token = NULL;

	unix_token = get_current_utok(handle->conn);
	return ceph_userperm_new(unix_token->uid,
				 unix_token->gid,
				 unix_token->ngroups,
				 unix_token->groups);
}

static void vfs_ceph_userperm_del(struct UserPerm *uperm)
{
	if (uperm != NULL) {
		ceph_userperm_destroy(uperm);
	}
}

/* Ceph's statx to Samba's stat_ex */
#define SAMBA_STATX_ATTR_MASK (CEPH_STATX_BASIC_STATS | CEPH_STATX_BTIME)

static void smb_stat_from_ceph_statx(SMB_STRUCT_STAT *st,
				     const struct ceph_statx *stx)
{
	ZERO_STRUCTP(st);

	st->st_ex_dev = stx->stx_dev;
	st->st_ex_rdev = stx->stx_rdev;
	st->st_ex_ino = stx->stx_ino;
	st->st_ex_mode = stx->stx_mode;
	st->st_ex_uid = stx->stx_uid;
	st->st_ex_gid = stx->stx_gid;
	st->st_ex_size = stx->stx_size;
	st->st_ex_nlink = stx->stx_nlink;
	st->st_ex_atime = stx->stx_atime;
	st->st_ex_btime = stx->stx_btime;
	st->st_ex_ctime = stx->stx_ctime;
	st->st_ex_mtime = stx->stx_mtime;
	st->st_ex_blksize = stx->stx_blksize;
	st->st_ex_blocks = stx->stx_blocks;
}

/* Ceph's inode + ino-number */
struct vfs_ceph_iref {
	struct Inode *inode;
	uint64_t ino; /* for debug printing */
	bool owner;   /* indicate when actual owner of Inode ref */
};

/* Ceph DIR pointer wrapper */
struct vfs_ceph_dirp {
	struct ceph_dir_result *cdr;
};

/* Ceph file-handles via fsp-extension */
struct vfs_ceph_fh {
	struct vfs_ceph_dirp dirp; /* keep first for up-casting */
	struct cephmount_cached *cme;
	struct UserPerm *uperm;
	struct files_struct *fsp;
	struct vfs_ceph_iref iref;
	struct Fh *fh;
	int fd;
};

static int cephmount_next_fd(struct cephmount_cached *cme)
{
	/*
	 * Those file-descriptor numbers are reported back to VFS layer
	 * (debug-hints only). Using numbers within a large range of
	 * [1000, 1001000], thus the chances of (annoying but harmless)
	 * collision are low.
	 */
	uint64_t next;

	next = (cme->fd_index++ % 1000000) + 1000;
	return (int)next;
}

static int vfs_ceph_release_fh(struct vfs_ceph_fh *cfh)
{
	int ret = 0;

	if (cfh->fh != NULL) {
		ret = ceph_ll_close(cfh->cme->mount, cfh->fh);
		cfh->fh = NULL;
	}
	if (cfh->iref.inode != NULL) {
		ceph_ll_put(cfh->cme->mount, cfh->iref.inode);
		cfh->iref.inode = NULL;
	}
	if (cfh->uperm != NULL) {
		vfs_ceph_userperm_del(cfh->uperm);
		cfh->uperm = NULL;
	}
	cfh->fd = -1;

	return ret;
}

static void vfs_ceph_fsp_ext_destroy_cb(void *p_data)
{
	vfs_ceph_release_fh((struct vfs_ceph_fh *)p_data);
}

static int vfs_ceph_add_fh(struct vfs_handle_struct *handle,
			   files_struct *fsp,
			   struct vfs_ceph_fh **out_cfh)
{
	struct cephmount_cached *cme = handle->data;
	struct UserPerm *uperm = NULL;

	uperm = vfs_ceph_userperm_new(handle);
	if (uperm == NULL) {
		return -ENOMEM;
	}

	*out_cfh = VFS_ADD_FSP_EXTENSION(handle,
					 fsp,
					 struct vfs_ceph_fh,
					 vfs_ceph_fsp_ext_destroy_cb);
	if (*out_cfh == NULL) {
		vfs_ceph_userperm_del(uperm);
		return -ENOMEM;
	}
	(*out_cfh)->cme = cme;
	(*out_cfh)->uperm = uperm;
	(*out_cfh)->fsp = fsp;
	(*out_cfh)->fd = -1;
	return 0;
}

static void vfs_ceph_remove_fh(struct vfs_handle_struct *handle,
			       struct files_struct *fsp)
{
	VFS_REMOVE_FSP_EXTENSION(handle, fsp);
}

static int vfs_ceph_fetch_fh(struct vfs_handle_struct *handle,
			     const struct files_struct *fsp,
			     struct vfs_ceph_fh **out_cfh)
{
	*out_cfh = VFS_FETCH_FSP_EXTENSION(handle, fsp);
	return (*out_cfh == NULL) ? -EBADF : 0;
}

static int vfs_ceph_fetch_io_fh(struct vfs_handle_struct *handle,
				const struct files_struct *fsp,
				struct vfs_ceph_fh **out_cfh)
{
	*out_cfh = VFS_FETCH_FSP_EXTENSION(handle, fsp);
	return (*out_cfh == NULL) || ((*out_cfh)->fh == NULL) ? -EBADF : 0;
}

static void vfs_ceph_assign_fh_fd(struct vfs_ceph_fh *cfh)
{
	cfh->fd = cephmount_next_fd(cfh->cme); /* debug only */
}

/* Ceph low-level wrappers */

static int vfs_ceph_ll_lookup_inode(const struct vfs_handle_struct *handle,
				    uint64_t inoval,
				    Inode **pout)
{
	struct inodeno_t ino = {.val = inoval};

	return ceph_ll_lookup_inode(cmount_of(handle), ino, pout);
}

static int vfs_ceph_ll_walk(const struct vfs_handle_struct *handle,
			    const char *name,
			    struct Inode **pin,
			    struct ceph_statx *stx,
			    unsigned int want,
			    unsigned int flags)
{
	struct UserPerm *uperm = NULL;
	int ret = -1;

	uperm = vfs_ceph_userperm_new(handle);
	if (uperm == NULL) {
		return -ENOMEM;
	}

	ret = ceph_ll_walk(cmount_of(handle),
			   name,
			   pin,
			   stx,
			   want,
			   flags,
			   uperm);

	vfs_ceph_userperm_del(uperm);
	return ret;
}

static int vfs_ceph_ll_statfs(const struct vfs_handle_struct *handle,
			      const struct vfs_ceph_iref *iref,
			      struct statvfs *stbuf)
{
	return ceph_ll_statfs(cmount_of(handle), iref->inode, stbuf);
}

static int vfs_ceph_ll_getattr2(const struct vfs_handle_struct *handle,
				const struct vfs_ceph_iref *iref,
				struct UserPerm *uperm,
				SMB_STRUCT_STAT *st)
{
	struct ceph_statx stx = {0};
	int ret = -1;

	ret = ceph_ll_getattr(cmount_of(handle),
			      iref->inode,
			      &stx,
			      SAMBA_STATX_ATTR_MASK,
			      0,
			      uperm);
	if (ret == 0) {
		smb_stat_from_ceph_statx(st, &stx);
	}
	return ret;
}

static int vfs_ceph_ll_getattr(const struct vfs_handle_struct *handle,
			       const struct vfs_ceph_iref *iref,
			       SMB_STRUCT_STAT *st)
{
	struct UserPerm *uperm = NULL;
	int ret = -1;

	uperm = vfs_ceph_userperm_new(handle);
	if (uperm == NULL) {
		return -ENOMEM;
	}
	ret = vfs_ceph_ll_getattr2(handle, iref, uperm, st);
	vfs_ceph_userperm_del(uperm);
	return ret;
}

static int vfs_ceph_ll_chown(struct vfs_handle_struct *handle,
			     const struct vfs_ceph_iref *iref,
			     uid_t uid,
			     gid_t gid)
{
	struct ceph_statx stx = {.stx_uid = uid, .stx_gid = gid};
	struct UserPerm *uperm = NULL;
	int ret = -1;

	uperm = vfs_ceph_userperm_new(handle);
	if (uperm == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_setattr(cmount_of(handle),
			      iref->inode,
			      &stx,
			      CEPH_STATX_UID | CEPH_STATX_GID,
			      uperm);
	vfs_ceph_userperm_del(uperm);
	return ret;
}

static int vfs_ceph_ll_fchown(struct vfs_handle_struct *handle,
			      const struct vfs_ceph_fh *cfh,
			      uid_t uid,
			      gid_t gid)
{
	struct ceph_statx stx = {.stx_uid = uid, .stx_gid = gid};

	return ceph_ll_setattr(cmount_of(handle),
			       cfh->iref.inode,
			       &stx,
			       CEPH_STATX_UID | CEPH_STATX_GID,
			       cfh->uperm);
}

static int vfs_ceph_ll_fchmod(struct vfs_handle_struct *handle,
			      const struct vfs_ceph_fh *cfh,
			      mode_t mode)
{
	struct ceph_statx stx = {.stx_mode = mode};

	return ceph_ll_setattr(cmount_of(handle),
			       cfh->iref.inode,
			       &stx,
			       CEPH_STATX_MODE,
			       cfh->uperm);
}

static int vfs_ceph_ll_futimes(struct vfs_handle_struct *handle,
			       const struct vfs_ceph_fh *cfh,
			       const struct smb_file_time *ft)
{
	struct ceph_statx stx = {0};
	int mask = 0;

	if (!is_omit_timespec(&ft->atime)) {
		stx.stx_atime = ft->atime;
		mask |= CEPH_SETATTR_ATIME;
	}
	if (!is_omit_timespec(&ft->mtime)) {
		stx.stx_mtime = ft->mtime;
		mask |= CEPH_SETATTR_MTIME;
	}
	if (!is_omit_timespec(&ft->ctime)) {
		stx.stx_ctime = ft->ctime;
		mask |= CEPH_SETATTR_CTIME;
	}
	if (!is_omit_timespec(&ft->create_time)) {
		stx.stx_btime = ft->create_time;
		mask |= CEPH_SETATTR_BTIME;
	}
	if (!mask) {
		return 0;
	}
	return ceph_ll_setattr(cmount_of(handle),
			       cfh->iref.inode,
			       &stx,
			       mask,
			       cfh->uperm);
}

static int vfs_ceph_ll_releasedir(const struct vfs_handle_struct *handle,
				  const struct vfs_ceph_fh *dircfh)
{
	return ceph_ll_releasedir(cmount_of(handle), dircfh->dirp.cdr);
}

static int vfs_ceph_ll_create(const struct vfs_handle_struct *handle,
			      const struct vfs_ceph_iref *parent,
			      const char *name,
			      mode_t mode,
			      int oflags,
			      struct vfs_ceph_fh *cfh)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct Inode *inode = NULL;
	struct Fh *fh = NULL;
	int ret = -1;

	ret = ceph_ll_create(cmount_of(handle),
			     parent->inode,
			     name,
			     mode,
			     oflags,
			     &inode,
			     &fh,
			     &stx,
			     CEPH_STATX_INO,
			     0,
			     cfh->uperm);
	if (ret != 0) {
		return ret;
	}

	cfh->iref.inode = inode;
	cfh->iref.ino = (long)stx.stx_ino;
	cfh->iref.owner = true;
	cfh->fh = fh;
	vfs_ceph_assign_fh_fd(cfh);

	return 0;
}

static int vfs_ceph_ll_lookup(const struct vfs_handle_struct *handle,
			      const struct vfs_ceph_iref *parent,
			      const char *name,
			      struct vfs_ceph_iref *iref)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct Inode *inode = NULL;
	struct UserPerm *uperm = NULL;
	int ret = -1;

	uperm = vfs_ceph_userperm_new(handle);
	if (uperm == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_lookup(cmount_of(handle),
			     parent->inode,
			     name,
			     &inode,
			     &stx,
			     CEPH_STATX_INO,
			     0,
			     uperm);

	vfs_ceph_userperm_del(uperm);
	if (ret != 0) {
		return ret;
	}

	iref->inode = inode;
	iref->ino = stx.stx_ino;
	iref->owner = true;
	return 0;
}

static int vfs_ceph_ll_lookupat(const struct vfs_handle_struct *handle,
				const struct vfs_ceph_fh *parent_fh,
				const char *name,
				struct vfs_ceph_iref *iref)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct Inode *inode = NULL;
	int ret = -1;

	ret = ceph_ll_lookup(cmount_of(handle),
			     parent_fh->iref.inode,
			     name,
			     &inode,
			     &stx,
			     CEPH_STATX_INO,
			     0,
			     parent_fh->uperm);
	if (ret != 0) {
		return ret;
	}
	iref->inode = inode;
	iref->ino = stx.stx_ino;
	iref->owner = true;
	return 0;
}

static int vfs_ceph_ll_open(const struct vfs_handle_struct *handle,
			    struct vfs_ceph_fh *cfh,
			    int flags)
{
	struct Inode *in = cfh->iref.inode;
	struct Fh *fh = NULL;
	int ret = -1;

	ret = ceph_ll_open(cmount_of(handle), in, flags, &fh, cfh->uperm);
	if (ret == 0) {
		cfh->fh = fh;
		vfs_ceph_assign_fh_fd(cfh);
	}
	return ret;
}

static int vfs_ceph_ll_opendir(const struct vfs_handle_struct *handle,
			       struct vfs_ceph_fh *cfh)
{
	return ceph_ll_opendir(cmount_of(handle),
			       cfh->iref.inode,
			       &cfh->dirp.cdr,
			       cfh->uperm);
}

static struct dirent *vfs_ceph_ll_readdir(const struct vfs_handle_struct *hndl,
					  const struct vfs_ceph_fh *dircfh)
{
	return ceph_readdir(cmount_of(hndl), dircfh->dirp.cdr);
}

static void vfs_ceph_ll_rewinddir(const struct vfs_handle_struct *handle,
				  const struct vfs_ceph_fh *dircfh)
{
	ceph_rewinddir(cmount_of(handle), dircfh->dirp.cdr);
}

static int vfs_ceph_ll_mkdirat(const struct vfs_handle_struct *handle,
			       const struct vfs_ceph_fh *dircfh,
			       const char *name,
			       mode_t mode,
			       struct vfs_ceph_iref *iref)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct Inode *inode = NULL;
	int ret = -1;

	ret = ceph_ll_mkdir(cmount_of(handle),
			    dircfh->iref.inode,
			    name,
			    mode,
			    &inode,
			    &stx,
			    CEPH_STATX_INO,
			    0,
			    dircfh->uperm);
	if (ret != 0) {
		return ret;
	}
	iref->inode = inode;
	iref->ino = stx.stx_ino;
	iref->owner = true;
	return false;
}

/* Ceph Inode-refernce get/put wrappers */
static int vfs_ceph_iget(const struct vfs_handle_struct *handle,
			 uint64_t ino,
			 const char *name,
			 unsigned int flags,
			 struct vfs_ceph_iref *iref)
{
	struct Inode *inode = NULL;
	int ret = -1;

	if (ino > CEPH_INO_ROOT) {
		/* get-by-ino */
		ret = vfs_ceph_ll_lookup_inode(handle, ino, &inode);
		if (ret != 0) {
			return ret;
		}
	} else {
		/* get-by-path */
		struct ceph_statx stx = {.stx_ino = 0};

		ret = vfs_ceph_ll_walk(handle,
				       name,
				       &inode,
				       &stx,
				       CEPH_STATX_INO,
				       flags);
		if (ret != 0) {
			return ret;
		}
		ino = stx.stx_ino;
	}
	iref->inode = inode;
	iref->ino = ino;
	iref->owner = true;
	DBG_DEBUG("[CEPH] get-inode: %s ino=%" PRIu64 "\n", name, iref->ino);
	return 0;
}

static int vfs_ceph_iget_by_fname(const struct vfs_handle_struct *handle,
				  const struct smb_filename *smb_fname,
				  struct vfs_ceph_iref *iref)
{
	const char *name = smb_fname->base_name;
	const char *cwd = ceph_getcwd(cmount_of(handle));
	int ret = -1;

	if (!strcmp(name, cwd)) {
		ret = vfs_ceph_iget(handle, 0, "./", 0, iref);
	} else {
		ret = vfs_ceph_iget(handle, 0, name, 0, iref);
	}
	return ret;
}

static int vfs_ceph_igetl(const struct vfs_handle_struct *handle,
			  const struct smb_filename *smb_fname,
			  struct vfs_ceph_iref *iref)
{
	return vfs_ceph_iget(handle,
			     0,
			     smb_fname->base_name,
			     AT_SYMLINK_NOFOLLOW,
			     iref);
}

static int vfs_ceph_igetd(struct vfs_handle_struct *handle,
			  const struct files_struct *dirfsp,
			  struct vfs_ceph_iref *iref)
{
	struct vfs_ceph_fh *dircfh = NULL;
	int ret = -1;

	/* case-1: already have reference to open directory; re-ref */
	ret = vfs_ceph_fetch_fh(handle, dirfsp, &dircfh);
	if (ret == 0) {
		iref->inode = dircfh->iref.inode;
		iref->ino = dircfh->iref.ino;
		iref->owner = false;
		return 0;
	}

	/* case-2: resolve by current work-dir */
	if (fsp_get_pathref_fd(dirfsp) == AT_FDCWD) {
		return vfs_ceph_iget(handle, 0, ".", 0, iref);
	}

	/* case-3: resolve by parent dir and name */
	return vfs_ceph_iget(handle,
			     dirfsp->file_id.inode,
			     dirfsp->fsp_name->base_name,
			     AT_SYMLINK_NOFOLLOW,
			     iref);
}

static void vfs_ceph_iput(const struct vfs_handle_struct *handle,
			  struct vfs_ceph_iref *iref)
{
	if ((iref != NULL) && (iref->inode != NULL) && iref->owner) {
		DBG_DEBUG("[CEPH] put-inode: ino=%" PRIu64 "\n", iref->ino);

		ceph_ll_put(cmount_of(handle), iref->inode);
		iref->inode = NULL;
	}
}

/* Disk operations */

static uint64_t vfs_ceph_disk_free(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	struct statvfs statvfs_buf = { 0 };
	struct Inode *inode = NULL;
	int ret;

	ret = ceph_ll_lookup_root(cmount_of(handle), &inode);
	if (ret != 0) {
		DBG_DEBUG("[CEPH] ceph_ll_lookup_root returned %d\n", ret);
		errno = -ret;
		return (uint64_t)(-1);
	}
	ret = ceph_ll_statfs(cmount_of(handle), inode, &statvfs_buf);
	ceph_ll_put(cmount_of(handle), inode);
	if (ret != 0) {
		DBG_DEBUG("[CEPH] ceph_ll_statfs returned %d\n", ret);
		errno = -ret;
		return (uint64_t)(-1);
	}
	*bsize = (uint64_t)statvfs_buf.f_bsize;
	*dfree = (uint64_t)statvfs_buf.f_bavail;
	*dsize = (uint64_t)statvfs_buf.f_blocks;

	DBG_DEBUG("[CEPH] bsize: %llu, dfree: %llu, dsize: %llu\n",
		  llu(*bsize),
		  llu(*dfree),
		  llu(*dsize));
	return *dfree;
}

static int vfs_ceph_statvfs(struct vfs_handle_struct *handle,
			    const struct smb_filename *smb_fname,
			    struct vfs_statvfs_struct *statbuf)
{
	struct statvfs statvfs_buf = { 0 };
	struct vfs_ceph_iref iref = {0};
	int ret;

	ret = vfs_ceph_iget_by_fname(handle, smb_fname, &iref);
	if (ret != 0) {
		goto out;
	}

	ret = vfs_ceph_ll_statfs(handle, &iref, &statvfs_buf);
	if (ret != 0) {
		goto out;
	}

	statbuf->OptimalTransferSize = statvfs_buf.f_frsize;
	statbuf->BlockSize = statvfs_buf.f_bsize;
	statbuf->TotalBlocks = statvfs_buf.f_blocks;
	statbuf->BlocksAvail = statvfs_buf.f_bfree;
	statbuf->UserBlocksAvail = statvfs_buf.f_bavail;
	statbuf->TotalFileNodes = statvfs_buf.f_files;
	statbuf->FreeFileNodes = statvfs_buf.f_ffree;
	statbuf->FsIdentifier = statvfs_buf.f_fsid;
	DBG_DEBUG("[CEPH] f_bsize: %ld, f_blocks: %ld, f_bfree: %ld, "
		  "f_bavail: %ld\n",
		  (long int)statvfs_buf.f_bsize,
		  (long int)statvfs_buf.f_blocks,
		  (long int)statvfs_buf.f_bfree,
		  (long int)statvfs_buf.f_bavail);
out:
	vfs_ceph_iput(handle, &iref);
	return status_code(ret);
}

static uint32_t vfs_ceph_fs_capabilities(
	struct vfs_handle_struct *handle,
	enum timestamp_set_resolution *p_ts_res)
{
	uint32_t caps = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES;

	*p_ts_res = TIMESTAMP_SET_NT_OR_BETTER;

	return caps;
}

/* Directory operations */

static DIR *vfs_ceph_fdopendir(struct vfs_handle_struct *handle,
			       struct files_struct *fsp,
			       const char *mask,
			       uint32_t attributes)
{
	int ret = 0;
	void *result = NULL;
	struct vfs_ceph_fh *cfh = NULL;

	DBG_DEBUG("[CEPH] fdopendir(%p, %p)\n", handle, fsp);
	ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
	if (ret != 0) {
		goto out;
	}

	ret = vfs_ceph_ll_opendir(handle, cfh);
	if (ret != 0) {
		goto out;
	}
	result = &cfh->dirp;
out:
	DBG_DEBUG("[CEPH] fdopendir(...) = %d\n", ret);
	if (ret != 0) {
		errno = -ret;
	}
	return (DIR *)result;
}

static struct dirent *vfs_ceph_readdir(struct vfs_handle_struct *handle,
				       struct files_struct *dirfsp,
				       DIR *dirp)
{
	const struct vfs_ceph_fh *dircfh = (const struct vfs_ceph_fh *)dirp;
	struct dirent *result = NULL;
	int errval = 0;

	DBG_DEBUG("[CEPH] readdir(%p, %p)\n", handle, dirp);
	errno = 0;
	result = vfs_ceph_ll_readdir(handle, dircfh);
	errval = errno;
	if ((result == NULL) && (errval != 0)) {
		DBG_DEBUG("[CEPH] readdir(...) = %d\n", errval);
	} else {
		DBG_DEBUG("[CEPH] readdir(...) = %p\n", result);
	}
	/* re-assign errno to avoid possible over-write by DBG_DEBUG */
	errno = errval;
	return result;
}

static void vfs_ceph_rewinddir(struct vfs_handle_struct *handle, DIR *dirp)
{
	const struct vfs_ceph_fh *dircfh = (const struct vfs_ceph_fh *)dirp;

	DBG_DEBUG("[CEPH] rewinddir(%p, %p)\n", handle, dirp);
	vfs_ceph_ll_rewinddir(handle, dircfh);
}

static int vfs_ceph_mkdirat(struct vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	int result = -1;
	const char *name = smb_fname->base_name;
	struct vfs_ceph_fh *dircfh = NULL;
	struct vfs_ceph_iref iref = {0};

	DBG_DEBUG("[CEPH] mkdirat(%p, %s)\n", handle, name);
	result = vfs_ceph_fetch_fh(handle, dirfsp, &dircfh);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_ll_mkdirat(handle, dircfh, name, mode, &iref);
	vfs_ceph_iput(handle, &iref);
out:
	DBG_DEBUG("[CEPH] mkdirat(...) = %d\n", result);
	return status_code(result);
}

static int vfs_ceph_closedir(struct vfs_handle_struct *handle, DIR *dirp)
{
	int result;
	struct vfs_ceph_fh *cfh = (struct vfs_ceph_fh *)dirp;

	DBG_DEBUG("[CEPH] closedir(%p, %p)\n", handle, dirp);
	result = vfs_ceph_ll_releasedir(handle, cfh);
	vfs_ceph_release_fh(cfh);
	vfs_ceph_remove_fh(handle, cfh->fsp);
	DBG_DEBUG("[CEPH] closedir(...) = %d\n", result);
	return status_code(result);
}

/* File operations */

static int vfs_ceph_openat(struct vfs_handle_struct *handle,
			   const struct files_struct *dirfsp,
			   const struct smb_filename *smb_fname,
			   files_struct *fsp,
			   const struct vfs_open_how *how)
{
	struct vfs_ceph_iref diref = {0};
	struct vfs_ceph_fh *cfh = NULL;
	int flags = how->flags;
	mode_t mode = how->mode;
	int result = -ENOENT;

	if (how->resolve != 0) {
		errno = ENOSYS;
		return -1;
	}

	if (smb_fname->stream_name) {
		errno = ENOENT;
		return -1;
	}

#ifdef O_PATH
	if (fsp->fsp_flags.is_pathref) {
		flags |= O_PATH;
	}
#endif

	DBG_DEBUG("[CEPH] openat(%p, %p, %d, %d)\n", handle, fsp, flags, mode);

	result = vfs_ceph_igetd(handle, dirfsp, &diref);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_add_fh(handle, fsp, &cfh);
	if (result != 0) {
		goto out;
	}

	if (flags & O_CREAT) {
		result = vfs_ceph_ll_create(handle,
					    &diref,
					    smb_fname->base_name,
					    mode,
					    flags,
					    cfh);
		if (result != 0) {
			vfs_ceph_remove_fh(handle, fsp);
			goto out;
		}
	} else {
		result = vfs_ceph_ll_lookup(handle,
					    &diref,
					    smb_fname->base_name,
					    &cfh->iref);
		if (result != 0) {
			vfs_ceph_remove_fh(handle, fsp);
			goto out;
		}
#ifdef O_PATH
		if (flags & O_PATH) {
			/*
			 * Special case: open with O_PATH: we already have
			 * Cephfs' Inode* from the above lookup so there is no
			 * need to go via expensive ceph_ll_open for Fh*.
			 */
			vfs_ceph_assign_fh_fd(cfh);
			result = cfh->fd;
			goto out;
		}
#endif
		result = vfs_ceph_ll_open(handle, cfh, flags);
		if (result != 0) {
			vfs_ceph_remove_fh(handle, fsp);
			goto out;
		}
	}

	result = cfh->fd;
out:
	vfs_ceph_iput(handle, &diref);
	fsp->fsp_flags.have_proc_fds = false;
	DBG_DEBUG("[CEPH] open(...) = %d\n", result);
	return status_code(result);
}

static int vfs_ceph_close(struct vfs_handle_struct *handle, files_struct *fsp)
{
	int result;
	struct vfs_ceph_fh *cfh = NULL;

	DBG_DEBUG("[CEPH] close(%p, %p)\n", handle, fsp);
	result = vfs_ceph_fetch_fh(handle, fsp, &cfh);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_release_fh(cfh);
	vfs_ceph_remove_fh(handle, fsp);
out:
	DBG_DEBUG("[CEPH] close(...) = %d\n", result);
	return status_code(result);
}

static ssize_t vfs_ceph_pread(struct vfs_handle_struct *handle,
			      files_struct *fsp,
			      void *data,
			      size_t n,
			      off_t offset)
{
	ssize_t result;

	DBG_DEBUG("[CEPH] pread(%p, %p, %p, %llu, %llu)\n",
		  handle,
		  fsp,
		  data,
		  llu(n),
		  llu(offset));

	result = ceph_read(cmount_of(handle),
			   fsp_get_io_fd(fsp),
			   data,
			   n,
			   offset);

	DBG_DEBUG("[CEPH] pread(...) = %llu\n", llu(result));
	return lstatus_code(result);
}

struct vfs_ceph_pread_state {
	ssize_t bytes_read;
	struct vfs_aio_state vfs_aio_state;
};

/*
 * Fake up an async ceph read by calling the synchronous API.
 */
static struct tevent_req *vfs_ceph_pread_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct files_struct *fsp,
					      void *data,
					      size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct vfs_ceph_pread_state *state = NULL;
	int ret = -1;

	DBG_DEBUG("[CEPH] %s\n", __func__);
	req = tevent_req_create(mem_ctx, &state, struct vfs_ceph_pread_state);
	if (req == NULL) {
		return NULL;
	}

	ret = ceph_read(cmount_of(handle), fsp_get_io_fd(fsp), data, n, offset);
	if (ret < 0) {
		/* ceph returns -errno on error. */
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}

	state->bytes_read = ret;
	tevent_req_done(req);
	/* Return and schedule the completion of the call. */
	return tevent_req_post(req, ev);
}

static ssize_t vfs_ceph_pread_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_ceph_pread_state *state =
		tevent_req_data(req, struct vfs_ceph_pread_state);

	DBG_DEBUG("[CEPH] %s\n", __func__);
	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->bytes_read;
}

static ssize_t vfs_ceph_pwrite(struct vfs_handle_struct *handle,
			       files_struct *fsp,
			       const void *data,
			       size_t n,
			       off_t offset)
{
	ssize_t result;

	DBG_DEBUG("[CEPH] pwrite(%p, %p, %p, %llu, %llu)\n",
		  handle,
		  fsp,
		  data,
		  llu(n),
		  llu(offset));

	result = ceph_write(cmount_of(handle),
			    fsp_get_io_fd(fsp),
			    data,
			    n,
			    offset);

	DBG_DEBUG("[CEPH] pwrite(...) = %llu\n", llu(result));
	return lstatus_code(result);
}

struct vfs_ceph_pwrite_state {
	ssize_t bytes_written;
	struct vfs_aio_state vfs_aio_state;
};

/*
 * Fake up an async ceph write by calling the synchronous API.
 */
static struct tevent_req *vfs_ceph_pwrite_send(struct vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct files_struct *fsp,
					       const void *data,
					       size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct vfs_ceph_pwrite_state *state = NULL;
	int ret = -1;

	DBG_DEBUG("[CEPH] %s\n", __func__);
	req = tevent_req_create(mem_ctx, &state, struct vfs_ceph_pwrite_state);
	if (req == NULL) {
		return NULL;
	}

	ret = ceph_write(
		cmount_of(handle), fsp_get_io_fd(fsp), data, n, offset);
	if (ret < 0) {
		/* ceph returns -errno on error. */
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}

	state->bytes_written = ret;
	tevent_req_done(req);
	/* Return and schedule the completion of the call. */
	return tevent_req_post(req, ev);
}

static ssize_t vfs_ceph_pwrite_recv(struct tevent_req *req,
				    struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_ceph_pwrite_state *state =
		tevent_req_data(req, struct vfs_ceph_pwrite_state);

	DBG_DEBUG("[CEPH] %s\n", __func__);
	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->bytes_written;
}

static off_t vfs_ceph_lseek(struct vfs_handle_struct *handle,
			    files_struct *fsp,
			    off_t offset,
			    int whence)
{
	off_t result = 0;

	DBG_DEBUG("[CEPH] vfs_ceph_lseek\n");
	result = ceph_lseek(cmount_of(handle),
			    fsp_get_io_fd(fsp),
			    offset,
			    whence);
	return lstatus_code(result);
}

static ssize_t vfs_ceph_sendfile(struct vfs_handle_struct *handle,
				 int tofd,
				 files_struct *fromfsp,
				 const DATA_BLOB *hdr,
				 off_t offset,
				 size_t n)
{
	/*
	 * We cannot support sendfile because libcephfs is in user space.
	 */
	DBG_DEBUG("[CEPH] vfs_ceph_sendfile\n");
	errno = ENOTSUP;
	return -1;
}

static ssize_t vfs_ceph_recvfile(struct vfs_handle_struct *handle,
			int fromfd,
			files_struct *tofsp,
			off_t offset,
			size_t n)
{
	/*
	 * We cannot support recvfile because libcephfs is in user space.
	 */
	DBG_DEBUG("[CEPH] vfs_ceph_recvfile\n");
	errno = ENOTSUP;
	return -1;
}

static int vfs_ceph_renameat(struct vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *smb_fname_src,
			files_struct *dstfsp,
			const struct smb_filename *smb_fname_dst)
{
	struct smb_filename *full_fname_src = NULL;
	struct smb_filename *full_fname_dst = NULL;
	int result = -1;

	DBG_DEBUG("[CEPH] vfs_ceph_renameat\n");
	if (smb_fname_src->stream_name || smb_fname_dst->stream_name) {
		errno = ENOENT;
		return result;
	}

	full_fname_src = full_path_from_dirfsp_atname(talloc_tos(),
						  srcfsp,
						  smb_fname_src);
	if (full_fname_src == NULL) {
		errno = ENOMEM;
		return -1;
	}
	full_fname_dst = full_path_from_dirfsp_atname(talloc_tos(),
						  dstfsp,
						  smb_fname_dst);
	if (full_fname_dst == NULL) {
		TALLOC_FREE(full_fname_src);
		errno = ENOMEM;
		return -1;
	}

	result = ceph_rename(cmount_of(handle),
			     full_fname_src->base_name,
			     full_fname_dst->base_name);

	TALLOC_FREE(full_fname_src);
	TALLOC_FREE(full_fname_dst);

	return status_code(result);
}

/*
 * Fake up an async ceph fsync by calling the synchronous API.
 */

static struct tevent_req *vfs_ceph_fsync_send(struct vfs_handle_struct *handle,
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					files_struct *fsp)
{
	struct tevent_req *req = NULL;
	struct vfs_aio_state *state = NULL;
	int ret = -1;

	DBG_DEBUG("[CEPH] vfs_ceph_fsync_send\n");

	req = tevent_req_create(mem_ctx, &state, struct vfs_aio_state);
	if (req == NULL) {
		return NULL;
	}

	/* Make sync call. */
	ret = ceph_fsync(cmount_of(handle), fsp_get_io_fd(fsp), false);

	if (ret != 0) {
		/* ceph_fsync returns -errno on error. */
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}

	/* Mark it as done. */
	tevent_req_done(req);
	/* Return and schedule the completion of the call. */
	return tevent_req_post(req, ev);
}

static int vfs_ceph_fsync_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_aio_state *state =
		tevent_req_data(req, struct vfs_aio_state);

	DBG_DEBUG("[CEPH] vfs_ceph_fsync_recv\n");

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = *state;
	return 0;
}

static void init_stat_ex_from_ceph_statx(struct stat_ex *dst,
					 const struct ceph_statx *stx)
{
	DBG_DEBUG("[CEPH]\tstx = {dev = %llx, ino = %llu, mode = 0x%x, "
		  "nlink = %llu, uid = %d, gid = %d, rdev = %llx, size = %llu, "
		  "blksize = %llu, blocks = %llu, atime = %llu, mtime = %llu, "
		  "ctime = %llu, btime = %llu}\n",
		  llu(stx->stx_dev), llu(stx->stx_ino), stx->stx_mode,
		  llu(stx->stx_nlink), stx->stx_uid, stx->stx_gid,
		  llu(stx->stx_rdev), llu(stx->stx_size), llu(stx->stx_blksize),
		  llu(stx->stx_blocks), llu(stx->stx_atime.tv_sec),
		  llu(stx->stx_mtime.tv_sec), llu(stx->stx_ctime.tv_sec),
		  llu(stx->stx_btime.tv_sec));

	if ((stx->stx_mask & SAMBA_STATX_ATTR_MASK) != SAMBA_STATX_ATTR_MASK) {
		DBG_WARNING("%s: stx->stx_mask is incorrect "
			    "(wanted %x, got %x)\n",
			    __func__,
			    SAMBA_STATX_ATTR_MASK,
			    stx->stx_mask);
	}

	dst->st_ex_dev = stx->stx_dev;
	dst->st_ex_rdev = stx->stx_rdev;
	dst->st_ex_ino = stx->stx_ino;
	dst->st_ex_mode = stx->stx_mode;
	dst->st_ex_uid = stx->stx_uid;
	dst->st_ex_gid = stx->stx_gid;
	dst->st_ex_size = stx->stx_size;
	dst->st_ex_nlink = stx->stx_nlink;
	dst->st_ex_atime = stx->stx_atime;
	dst->st_ex_btime = stx->stx_btime;
	dst->st_ex_ctime = stx->stx_ctime;
	dst->st_ex_mtime = stx->stx_mtime;
	dst->st_ex_blksize = stx->stx_blksize;
	dst->st_ex_blocks = stx->stx_blocks;
}

static int vfs_ceph_stat(struct vfs_handle_struct *handle,
			struct smb_filename *smb_fname)
{
	int result = -1;
	struct vfs_ceph_iref iref = {0};

	DBG_DEBUG("[CEPH] stat(%p, %s)\n",
		  handle,
		  smb_fname_str_dbg(smb_fname));

	if (smb_fname->stream_name) {
		errno = ENOENT;
		return result;
	}

	result = vfs_ceph_iget_by_fname(handle, smb_fname, &iref);
	if (result != 0) {
		goto out;
	}

	DBG_DEBUG("[CEPH] stat: ino=%" PRIu64 "\n", iref.ino);
	result = vfs_ceph_ll_getattr(handle, &iref, &smb_fname->st);
	if (result != 0) {
		goto out;
	}
	DBG_DEBUG("[CEPH] mode = 0x%x\n", smb_fname->st.st_ex_mode);
out:
	vfs_ceph_iput(handle, &iref);
	return status_code(result);
}

static int vfs_ceph_fstat(struct vfs_handle_struct *handle,
			  files_struct *fsp,
			  SMB_STRUCT_STAT *sbuf)
{
	int result = -1;
	struct vfs_ceph_fh *cfh = NULL;

	DBG_DEBUG("[CEPH] fstat(%p)\n", handle);

	result = vfs_ceph_fetch_fh(handle, fsp, &cfh);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_ll_getattr2(handle, &cfh->iref, cfh->uperm, sbuf);
	if (result != 0) {
		goto out;
	}
	DBG_DEBUG("[CEPH] mode = 0x%x\n", sbuf->st_ex_mode);
out:
	DBG_DEBUG("[CEPH] fstat(...) = %d\n", result);
	return status_code(result);
}

static int vfs_ceph_fstatat(struct vfs_handle_struct *handle,
			    const struct files_struct *dirfsp,
			    const struct smb_filename *smb_fname,
			    SMB_STRUCT_STAT *sbuf,
			    int flags)
{
	int result = -1;
	struct vfs_ceph_iref iref = {0};
	struct vfs_ceph_fh *dircfh = NULL;

	DBG_DEBUG("[CEPH] fstatat(%p, %s)\n", handle, smb_fname->base_name);

	result = vfs_ceph_fetch_fh(handle, dirfsp, &dircfh);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_ll_lookupat(handle,
				      dircfh,
				      smb_fname->base_name,
				      &iref);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_ll_getattr2(handle, &iref, dircfh->uperm, sbuf);
	if (result != 0) {
		goto out;
	}
out:
	vfs_ceph_iput(handle, &iref);
	DBG_DEBUG("[CEPH] fstatat(...) = %d\n", result);
	return status_code(result);
}

static int vfs_ceph_lstat(struct vfs_handle_struct *handle,
			  struct smb_filename *smb_fname)
{
	int result = -1;
	struct vfs_ceph_iref iref = {0};

	DBG_DEBUG("[CEPH] lstat(%p, %s)\n",
		  handle,
		  smb_fname_str_dbg(smb_fname));

	if (smb_fname->stream_name) {
		errno = ENOENT;
		return result;
	}

	result = vfs_ceph_igetl(handle, smb_fname, &iref);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_ll_getattr(handle, &iref, &smb_fname->st);
	if (result != 0) {
		goto out;
	}
out:
	vfs_ceph_iput(handle, &iref);
	DBG_DEBUG("[CEPH] lstat(...) = %d\n", result);
	return status_code(result);
}

static int vfs_ceph_fntimes(struct vfs_handle_struct *handle,
			    files_struct *fsp,
			    struct smb_file_time *ft)
{
	struct vfs_ceph_fh *cfh = NULL;
	int result;

	result = vfs_ceph_fetch_fh(handle, fsp, &cfh);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_ll_futimes(handle, cfh, ft);
	if (result != 0) {
		goto out;
	}

	if (!is_omit_timespec(&ft->create_time)) {
		set_create_timespec_ea(fsp, ft->create_time);
	}

	DBG_DEBUG("[CEPH] ntimes(%p, %s, {%ld, %ld, %ld, %ld}) = %d\n",
		  handle, fsp_str_dbg(fsp), ft->mtime.tv_sec, ft->atime.tv_sec,
		  ft->ctime.tv_sec, ft->create_time.tv_sec, result);
out:
	return status_code(result);
}

static int vfs_ceph_unlinkat(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	int result = -1;
#ifdef HAVE_CEPH_UNLINKAT
	int dirfd = fsp_get_pathref_fd(dirfsp);

	DBG_DEBUG("[CEPH] unlinkat(%p, %d, %s)\n",
		  handle,
		  dirfd,
		  smb_fname_str_dbg(smb_fname));

	if (smb_fname->stream_name) {
		errno = ENOENT;
		return result;
	}

	result = ceph_unlinkat(cmount_of(handle),
			       dirfd,
			       smb_fname->base_name,
			       flags);
	DBG_DEBUG("[CEPH] unlinkat(...) = %d\n", result);
	return status_code(result);
#else
	struct smb_filename *full_fname = NULL;

	DBG_DEBUG("[CEPH] unlink(%p, %s)\n",
		handle,
		smb_fname_str_dbg(smb_fname));

	if (smb_fname->stream_name) {
		errno = ENOENT;
		return result;
	}

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						  dirfsp,
						  smb_fname);
	if (full_fname == NULL) {
		return -1;
	}

	if (flags & AT_REMOVEDIR) {
		result = ceph_rmdir(cmount_of(handle), full_fname->base_name);
	} else {
		result = ceph_unlink(cmount_of(handle), full_fname->base_name);
	}
	TALLOC_FREE(full_fname);
	DBG_DEBUG("[CEPH] unlink(...) = %d\n", result);
	return status_code(result);
#endif
}

static int vfs_ceph_fchmod(struct vfs_handle_struct *handle,
			   files_struct *fsp,
			   mode_t mode)
{
	int result;
	struct vfs_ceph_fh *cfh = NULL;

	DBG_DEBUG("[CEPH] fchmod(%p, %p, %d)\n", handle, fsp, mode);
	result = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_ll_fchmod(handle, cfh, mode);
out:
	DBG_DEBUG("[CEPH] fchmod(...) = %d\n", result);
	return status_code(result);
}

static int vfs_ceph_fchown(struct vfs_handle_struct *handle,
			   files_struct *fsp,
			   uid_t uid,
			   gid_t gid)
{
	int result;
	struct vfs_ceph_fh *cfh = NULL;

	DBG_DEBUG("[CEPH] fchown(%p, %p, %d, %d)\n", handle, fsp, uid, gid);
	result = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
	if (result != 0) {
		goto out;
	}
	result = vfs_ceph_ll_fchown(handle, cfh, uid, gid);
out:
	DBG_DEBUG("[CEPH] fchown(...) = %d\n", result);
	return status_code(result);
}

static int vfs_ceph_lchown(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	int result;
	struct vfs_ceph_iref iref = {0};

	DBG_DEBUG("[CEPH] lchown(%p, %s, %d, %d)\n",
		  handle,
		  smb_fname->base_name,
		  uid,
		  gid);

	result = vfs_ceph_igetl(handle, smb_fname, &iref);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_ll_chown(handle, &iref, uid, gid);
	vfs_ceph_iput(handle, &iref);
out:
	DBG_DEBUG("[CEPH] lchown(...) = %d\n", result);
	return status_code(result);
}

static int vfs_ceph_chdir(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	int result = -1;
	DBG_DEBUG("[CEPH] chdir(%p, %s)\n", handle, smb_fname->base_name);
	result = ceph_chdir(cmount_of(handle), smb_fname->base_name);
	DBG_DEBUG("[CEPH] chdir(...) = %d\n", result);
	return status_code(result);
}

static struct smb_filename *vfs_ceph_getwd(struct vfs_handle_struct *handle,
			TALLOC_CTX *ctx)
{
	const char *cwd = ceph_getcwd(cmount_of(handle));
	DBG_DEBUG("[CEPH] getwd(%p) = %s\n", handle, cwd);
	return synthetic_smb_fname(ctx, cwd, NULL, NULL, 0, 0);
}

static int strict_allocate_ftruncate(struct vfs_handle_struct *handle,
				     files_struct *fsp,
				     off_t len)
{
	off_t space_to_write;
	int result;
	NTSTATUS status;
	SMB_STRUCT_STAT *pst;

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}
	pst = &fsp->fsp_name->st;

#ifdef S_ISFIFO
	if (S_ISFIFO(pst->st_ex_mode))
		return 0;
#endif

	if (pst->st_ex_size == len)
		return 0;

	/* Shrink - just ftruncate. */
	if (pst->st_ex_size > len) {
		result = ceph_ftruncate(cmount_of(handle),
					fsp_get_io_fd(fsp),
					len);
		return status_code(result);
	}

	space_to_write = len - pst->st_ex_size;
	result = ceph_fallocate(cmount_of(handle),
				fsp_get_io_fd(fsp),
				0,
				pst->st_ex_size,
				space_to_write);
	return status_code(result);
}

static int vfs_ceph_ftruncate(struct vfs_handle_struct *handle,
			      files_struct *fsp,
			      off_t len)
{
	int result = -1;

	DBG_DEBUG("[CEPH] ftruncate(%p, %p, %llu\n", handle, fsp, llu(len));

	if (lp_strict_allocate(SNUM(fsp->conn))) {
		return strict_allocate_ftruncate(handle, fsp, len);
	}

	result = ceph_ftruncate(cmount_of(handle), fsp_get_io_fd(fsp), len);
	return status_code(result);
}

static int vfs_ceph_fallocate(struct vfs_handle_struct *handle,
			      struct files_struct *fsp,
			      uint32_t mode,
			      off_t offset,
			      off_t len)
{
	int result;

	DBG_DEBUG("[CEPH] fallocate(%p, %p, %u, %llu, %llu\n",
		  handle, fsp, mode, llu(offset), llu(len));
	/* unsupported mode flags are rejected by libcephfs */
	result = ceph_fallocate(cmount_of(handle),
			        fsp_get_io_fd(fsp),
				mode,
				offset,
				len);
	DBG_DEBUG("[CEPH] fallocate(...) = %d\n", result);
	return status_code(result);
}

static bool vfs_ceph_lock(struct vfs_handle_struct *handle,
			  files_struct *fsp,
			  int op,
			  off_t offset,
			  off_t count,
			  int type)
{
	DBG_DEBUG("[CEPH] lock\n");
	return true;
}

static int vfs_ceph_filesystem_sharemode(struct vfs_handle_struct *handle,
					 files_struct *fsp,
					 uint32_t share_access,
					 uint32_t access_mask)
{
	DBG_ERR("[CEPH] filesystem sharemodes unsupported! Consider setting "
		"\"kernel share modes = no\"\n");

	return vfs_not_implemented_filesystem_sharemode(handle,
							fsp,
							share_access,
							access_mask);
}

static int vfs_ceph_fcntl(vfs_handle_struct *handle,
			  files_struct *fsp, int cmd, va_list cmd_arg)
{
	/*
	 * SMB_VFS_FCNTL() is currently only called by vfs_set_blocking() to
	 * clear O_NONBLOCK, etc for LOCK_MAND and FIFOs. Ignore it.
	 */
	if (cmd == F_GETFL) {
		return 0;
	} else if (cmd == F_SETFL) {
		va_list dup_cmd_arg;
		int opt;

		va_copy(dup_cmd_arg, cmd_arg);
		opt = va_arg(dup_cmd_arg, int);
		va_end(dup_cmd_arg);
		if (opt == 0) {
			return 0;
		}
		DBG_ERR("unexpected fcntl SETFL(%d)\n", opt);
		goto err_out;
	}
	DBG_ERR("unexpected fcntl: %d\n", cmd);
err_out:
	errno = EINVAL;
	return -1;
}

static bool vfs_ceph_getlock(struct vfs_handle_struct *handle,
			     files_struct *fsp,
			     off_t *poffset,
			     off_t *pcount,
			     int *ptype,
			     pid_t *ppid)
{
	DBG_DEBUG("[CEPH] getlock returning false and errno=0\n");

	errno = 0;
	return false;
}

static int vfs_ceph_symlinkat(struct vfs_handle_struct *handle,
		const struct smb_filename *link_target,
		struct files_struct *dirfsp,
		const struct smb_filename *new_smb_fname)
{
	int result = -1;
#ifdef HAVE_CEPH_SYMLINKAT
	int dirfd = fsp_get_pathref_fd(dirfsp);

	DBG_DEBUG("[CEPH] symlinkat(%p, %s, %d, %s)\n",
		  handle,
		  link_target->base_name,
		  dirfd,
		  new_smb_fname->base_name);

	result = ceph_symlinkat(cmount_of(handle),
				link_target->base_name,
				dirfd,
				new_smb_fname->base_name);
	DBG_DEBUG("[CEPH] symlinkat(...) = %d\n", result);
	return status_code(result);
#else
	struct smb_filename *full_fname = NULL;

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						dirfsp,
						new_smb_fname);
	if (full_fname == NULL) {
		return -1;
	}

	DBG_DEBUG("[CEPH] symlink(%p, %s, %s)\n", handle,
			link_target->base_name,
			full_fname->base_name);

	result = ceph_symlink(cmount_of(handle),
			      link_target->base_name,
			      full_fname->base_name);
	TALLOC_FREE(full_fname);
	DBG_DEBUG("[CEPH] symlink(...) = %d\n", result);
	return status_code(result);
#endif
}

static int vfs_ceph_readlinkat(struct vfs_handle_struct *handle,
		const struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		char *buf,
		size_t bufsiz)
{
	int result = -1;
#ifdef HAVE_CEPH_READLINKAT
	int dirfd = fsp_get_pathref_fd(dirfsp);

	DBG_DEBUG("[CEPH] readlinkat(%p, %d, %s, %p, %llu)\n",
		  handle,
		  dirfd,
		  smb_fname->base_name,
		  buf,
		  llu(bufsiz));

	result = ceph_readlinkat(cmount_of(handle),
				 dirfd,
				 smb_fname->base_name,
				 buf,
				 bufsiz);

	DBG_DEBUG("[CEPH] readlinkat(...) = %d\n", result);
	return status_code(result);
#else
	struct smb_filename *full_fname = NULL;

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						dirfsp,
						smb_fname);
	if (full_fname == NULL) {
		return -1;
	}

	DBG_DEBUG("[CEPH] readlink(%p, %s, %p, %llu)\n", handle,
			full_fname->base_name, buf, llu(bufsiz));

	result = ceph_readlink(cmount_of(handle),
			       full_fname->base_name,
			       buf,
			       bufsiz);
	TALLOC_FREE(full_fname);
	DBG_DEBUG("[CEPH] readlink(...) = %d\n", result);
	return status_code(result);
#endif
}

static int vfs_ceph_linkat(struct vfs_handle_struct *handle,
		files_struct *srcfsp,
		const struct smb_filename *old_smb_fname,
		files_struct *dstfsp,
		const struct smb_filename *new_smb_fname,
		int flags)
{
	struct smb_filename *full_fname_old = NULL;
	struct smb_filename *full_fname_new = NULL;
	int result = -1;

	full_fname_old = full_path_from_dirfsp_atname(talloc_tos(),
					srcfsp,
					old_smb_fname);
	if (full_fname_old == NULL) {
		return -1;
	}
	full_fname_new = full_path_from_dirfsp_atname(talloc_tos(),
					dstfsp,
					new_smb_fname);
	if (full_fname_new == NULL) {
		TALLOC_FREE(full_fname_old);
		return -1;
	}

	DBG_DEBUG("[CEPH] link(%p, %s, %s)\n", handle,
			full_fname_old->base_name,
			full_fname_new->base_name);

	result = ceph_link(cmount_of(handle),
			   full_fname_old->base_name,
			   full_fname_new->base_name);
	DBG_DEBUG("[CEPH] link(...) = %d\n", result);
	TALLOC_FREE(full_fname_old);
	TALLOC_FREE(full_fname_new);
	return status_code(result);
}

static int vfs_ceph_mknodat(struct vfs_handle_struct *handle,
		files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode,
		SMB_DEV_T dev)
{
	struct smb_filename *full_fname = NULL;
	int result = -1;

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						dirfsp,
						smb_fname);
	if (full_fname == NULL) {
		return -1;
	}

	DBG_DEBUG("[CEPH] mknodat(%p, %s)\n", handle, full_fname->base_name);
	result = ceph_mknod(cmount_of(handle),
			    full_fname->base_name,
			    mode,
			    dev);
	DBG_DEBUG("[CEPH] mknodat(...) = %d\n", result);

	TALLOC_FREE(full_fname);

	return status_code(result);
}

/*
 * This is a simple version of real-path ... a better version is needed to
 * ask libcephfs about symbolic links.
 */
static struct smb_filename *vfs_ceph_realpath(struct vfs_handle_struct *handle,
				TALLOC_CTX *ctx,
				const struct smb_filename *smb_fname)
{
	char *result = NULL;
	const char *cwd = handle->conn->cwd_fsp->fsp_name->base_name;
	const char *path = smb_fname->base_name;
	size_t len = strlen(path);
	struct smb_filename *result_fname = NULL;

	if (path[0] == '/') {
		result = talloc_strdup(ctx, path);
	} else if ((len >= 2) && (path[0] == '.') && (path[1] == '/')) {
		if (len == 2) {
			result = talloc_strdup(ctx, cwd);
		} else {
			result = talloc_asprintf(ctx, "%s/%s", cwd, &path[2]);
		}
	} else {
		result = talloc_asprintf(ctx, "%s/%s", cwd, path);
	}

	if (result == NULL) {
		return NULL;
	}

	DBG_DEBUG("[CEPH] realpath(%p, %s) = %s\n", handle, path, result);
	result_fname = synthetic_smb_fname(ctx, result, NULL, NULL, 0, 0);
	TALLOC_FREE(result);
	return result_fname;
}

static NTSTATUS vfs_ceph_get_real_filename_at(
	struct vfs_handle_struct *handle,
	struct files_struct *dirfsp,
	const char *name,
	TALLOC_CTX *mem_ctx,
	char **found_name)
{
	/*
	 * Don't fall back to get_real_filename so callers can differentiate
	 * between a full directory scan and an actual case-insensitive stat.
	 */
	return NT_STATUS_NOT_SUPPORTED;
}

static const char *vfs_ceph_connectpath(
	struct vfs_handle_struct *handle,
	const struct files_struct *dirfsp,
	const struct smb_filename *smb_fname)
{
	return handle->conn->connectpath;
}

static NTSTATUS vfs_ceph_fget_dos_attributes(struct vfs_handle_struct *handle,
					     struct files_struct *fsp,
					     uint32_t *dosmode)
{
	struct timespec saved_btime = fsp->fsp_name->st.st_ex_btime;
	NTSTATUS status;

	status = fget_ea_dos_attribute(fsp, dosmode);

	/*
	 * Restore previously stored btime from statx timestamps as it should be
	 * the only source of truth. create_time from dos attribute, if any, may
	 * have older values which isn't trustworthy to be looked at for other
	 * open file handle operations.
	 */
	fsp->fsp_name->st.st_ex_btime = saved_btime;

	return status;
}

static NTSTATUS vfs_ceph_fset_dos_attributes(struct vfs_handle_struct *handle,
					     struct files_struct *fsp,
					     uint32_t dosmode)
{
	struct timespec saved_btime = fsp->fsp_name->st.st_ex_btime;
	NTSTATUS status;

	status = set_ea_dos_attribute(handle->conn, fsp->fsp_name, dosmode);

	/*
	 * Restore previously stored btime from statx timestamps. This is done
	 * to ensure that we have the exact btime in fsp stat information while
	 * the file handle is still open since the create_time stored as part of
	 * dos attributes can loose its precision when converted back to btime.
	 */
	fsp->fsp_name->st.st_ex_btime = saved_btime;

	return status;
}

/****************************************************************
 Extended attribute operations.
*****************************************************************/

static ssize_t vfs_ceph_fgetxattr(struct vfs_handle_struct *handle,
				  struct files_struct *fsp,
				  const char *name,
				  void *value,
				  size_t size)
{
	int ret;
	DBG_DEBUG("[CEPH] fgetxattr(%p, %p, %s, %p, %llu)\n",
		  handle,
		  fsp,
		  name,
		  value,
		  llu(size));
	if (!fsp->fsp_flags.is_pathref) {
		ret = ceph_fgetxattr(cmount_of(handle),
				     fsp_get_io_fd(fsp),
				     name,
				     value,
				     size);
	} else {
		ret = ceph_getxattr(cmount_of(handle),
				    fsp->fsp_name->base_name,
				    name,
				    value,
				    size);
	}
	DBG_DEBUG("[CEPH] fgetxattr(...) = %d\n", ret);
	return lstatus_code(ret);
}

static ssize_t vfs_ceph_flistxattr(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   char *list,
				   size_t size)
{
	int ret;
	DBG_DEBUG("[CEPH] flistxattr(%p, %p, %p, %llu)\n",
		  handle, fsp, list, llu(size));
	if (!fsp->fsp_flags.is_pathref) {
		/*
		 * We can use an io_fd to list xattrs.
		 */
		ret = ceph_flistxattr(cmount_of(handle),
				      fsp_get_io_fd(fsp),
				      list,
				      size);
	} else {
		/*
		 * This is no longer a handle based call.
		 */
		ret = ceph_listxattr(cmount_of(handle),
				     fsp->fsp_name->base_name,
				     list,
				     size);
	}
	DBG_DEBUG("[CEPH] flistxattr(...) = %d\n", ret);
	return lstatus_code(ret);
}

static int vfs_ceph_fremovexattr(struct vfs_handle_struct *handle,
				 struct files_struct *fsp,
				 const char *name)
{
	int ret;
	DBG_DEBUG("[CEPH] fremovexattr(%p, %p, %s)\n", handle, fsp, name);
	if (!fsp->fsp_flags.is_pathref) {
		/*
		 * We can use an io_fd to remove xattrs.
		 */
		ret = ceph_fremovexattr(cmount_of(handle),
					fsp_get_io_fd(fsp),
					name);
	} else {
		/*
		 * This is no longer a handle based call.
		 */
		ret = ceph_removexattr(cmount_of(handle),
				       fsp->fsp_name->base_name,
				       name);
	}
	DBG_DEBUG("[CEPH] fremovexattr(...) = %d\n", ret);
	return status_code(ret);
}

static int vfs_ceph_fsetxattr(struct vfs_handle_struct *handle,
			      struct files_struct *fsp,
			      const char *name,
			      const void *value,
			      size_t size,
			      int flags)
{
	int ret;
	DBG_DEBUG("[CEPH] fsetxattr(%p, %p, %s, %p, %llu, %d)\n",
		  handle,
		  fsp,
		  name,
		  value,
		  llu(size),
		  flags);
	if (!fsp->fsp_flags.is_pathref) {
		/*
		 * We can use an io_fd to set xattrs.
		 */
		ret = ceph_fsetxattr(cmount_of(handle),
				     fsp_get_io_fd(fsp),
				     name,
				     value,
				     size,
				     flags);
	} else {
		/*
		 * This is no longer a handle based call.
		 */
		ret = ceph_setxattr(cmount_of(handle),
				    fsp->fsp_name->base_name,
				    name,
				    value,
				    size,
				    flags);
	}
	DBG_DEBUG("[CEPH] fsetxattr(...) = %d\n", ret);
	return status_code(ret);
}

static NTSTATUS vfs_ceph_create_dfs_pathat(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				const struct referral *reflist,
				size_t referral_count)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	int ret;
	char *msdfs_link = NULL;
	struct smb_filename *full_fname = NULL;

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						dirfsp,
						smb_fname);
	if (full_fname == NULL) {
		goto out;
	}

	/* Form the msdfs_link contents */
	msdfs_link = msdfs_link_string(frame,
					reflist,
					referral_count);
	if (msdfs_link == NULL) {
		goto out;
	}

	ret = ceph_symlink(cmount_of(handle),
			   msdfs_link,
			   full_fname->base_name);
	if (ret == 0) {
		status = NT_STATUS_OK;
	} else {
		status = map_nt_error_from_unix(-ret);
        }

  out:

	DBG_DEBUG("[CEPH] create_dfs_pathat(%s) = %s\n",
			full_fname != NULL ? full_fname->base_name : "",
			nt_errstr(status));

	TALLOC_FREE(frame);
	return status;
}

/*
 * Read and return the contents of a DFS redirect given a
 * pathname. A caller can pass in NULL for ppreflist and
 * preferral_count but still determine if this was a
 * DFS redirect point by getting NT_STATUS_OK back
 * without incurring the overhead of reading and parsing
 * the referral contents.
 */

static NTSTATUS vfs_ceph_read_dfs_pathat(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct files_struct *dirfsp,
				struct smb_filename *smb_fname,
				struct referral **ppreflist,
				size_t *preferral_count)
{
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	size_t bufsize;
	char *link_target = NULL;
	int referral_len;
	bool ok;
#if defined(HAVE_BROKEN_READLINK)
	char link_target_buf[PATH_MAX];
#else
	char link_target_buf[7];
#endif
	struct ceph_statx stx = { 0 };
	struct smb_filename *full_fname = NULL;
	int ret;

	if (is_named_stream(smb_fname)) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto err;
	}

	if (ppreflist == NULL && preferral_count == NULL) {
		/*
		 * We're only checking if this is a DFS
		 * redirect. We don't need to return data.
		 */
		bufsize = sizeof(link_target_buf);
		link_target = link_target_buf;
	} else {
		bufsize = PATH_MAX;
		link_target = talloc_array(mem_ctx, char, bufsize);
		if (!link_target) {
			goto err;
		}
	}

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						  dirfsp,
						  smb_fname);
	if (full_fname == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err;
	}

	ret = ceph_statx(cmount_of(handle),
			 full_fname->base_name,
			 &stx,
			 SAMBA_STATX_ATTR_MASK,
			 AT_SYMLINK_NOFOLLOW);
	if (ret < 0) {
		status = map_nt_error_from_unix(-ret);
		goto err;
	}

	referral_len = ceph_readlink(cmount_of(handle),
				     full_fname->base_name,
				     link_target,
				     bufsize - 1);
	if (referral_len < 0) {
		/* ceph errors are -errno. */
		if (-referral_len == EINVAL) {
			DBG_INFO("%s is not a link.\n",
				full_fname->base_name);
			status = NT_STATUS_OBJECT_TYPE_MISMATCH;
		} else {
	                status = map_nt_error_from_unix(-referral_len);
			DBG_ERR("Error reading "
				"msdfs link %s: %s\n",
				full_fname->base_name,
			strerror(errno));
		}
                goto err;
	}
	link_target[referral_len] = '\0';

        DBG_INFO("%s -> %s\n",
                        full_fname->base_name,
                        link_target);

        if (!strnequal(link_target, "msdfs:", 6)) {
                status = NT_STATUS_OBJECT_TYPE_MISMATCH;
                goto err;
        }

        if (ppreflist == NULL && preferral_count == NULL) {
                /* Early return for checking if this is a DFS link. */
		TALLOC_FREE(full_fname);
		init_stat_ex_from_ceph_statx(&smb_fname->st, &stx);
                return NT_STATUS_OK;
        }

        ok = parse_msdfs_symlink(mem_ctx,
                        lp_msdfs_shuffle_referrals(SNUM(handle->conn)),
                        link_target,
                        ppreflist,
                        preferral_count);

        if (ok) {
		init_stat_ex_from_ceph_statx(&smb_fname->st, &stx);
                status = NT_STATUS_OK;
        } else {
                status = NT_STATUS_NO_MEMORY;
        }

  err:

        if (link_target != link_target_buf) {
                TALLOC_FREE(link_target);
        }
	TALLOC_FREE(full_fname);
        return status;
}

static struct vfs_fn_pointers ceph_new_fns = {
	/* Disk operations */

	.connect_fn = vfs_ceph_connect,
	.disconnect_fn = vfs_ceph_disconnect,
	.disk_free_fn = vfs_ceph_disk_free,
	.get_quota_fn = vfs_not_implemented_get_quota,
	.set_quota_fn = vfs_not_implemented_set_quota,
	.statvfs_fn = vfs_ceph_statvfs,
	.fs_capabilities_fn = vfs_ceph_fs_capabilities,

	/* Directory operations */

	.fdopendir_fn = vfs_ceph_fdopendir,
	.readdir_fn = vfs_ceph_readdir,
	.rewind_dir_fn = vfs_ceph_rewinddir,
	.mkdirat_fn = vfs_ceph_mkdirat,
	.closedir_fn = vfs_ceph_closedir,

	/* File operations */

	.create_dfs_pathat_fn = vfs_ceph_create_dfs_pathat,
	.read_dfs_pathat_fn = vfs_ceph_read_dfs_pathat,
	.openat_fn = vfs_ceph_openat,
	.close_fn = vfs_ceph_close,
	.pread_fn = vfs_ceph_pread,
	.pread_send_fn = vfs_ceph_pread_send,
	.pread_recv_fn = vfs_ceph_pread_recv,
	.pwrite_fn = vfs_ceph_pwrite,
	.pwrite_send_fn = vfs_ceph_pwrite_send,
	.pwrite_recv_fn = vfs_ceph_pwrite_recv,
	.lseek_fn = vfs_ceph_lseek,
	.sendfile_fn = vfs_ceph_sendfile,
	.recvfile_fn = vfs_ceph_recvfile,
	.renameat_fn = vfs_ceph_renameat,
	.fsync_send_fn = vfs_ceph_fsync_send,
	.fsync_recv_fn = vfs_ceph_fsync_recv,
	.stat_fn = vfs_ceph_stat,
	.fstat_fn = vfs_ceph_fstat,
	.lstat_fn = vfs_ceph_lstat,
	.fstatat_fn = vfs_ceph_fstatat,
	.unlinkat_fn = vfs_ceph_unlinkat,
	.fchmod_fn = vfs_ceph_fchmod,
	.fchown_fn = vfs_ceph_fchown,
	.lchown_fn = vfs_ceph_lchown,
	.chdir_fn = vfs_ceph_chdir,
	.getwd_fn = vfs_ceph_getwd,
	.fntimes_fn = vfs_ceph_fntimes,
	.ftruncate_fn = vfs_ceph_ftruncate,
	.fallocate_fn = vfs_ceph_fallocate,
	.lock_fn = vfs_ceph_lock,
	.filesystem_sharemode_fn = vfs_ceph_filesystem_sharemode,
	.fcntl_fn = vfs_ceph_fcntl,
	.linux_setlease_fn = vfs_not_implemented_linux_setlease,
	.getlock_fn = vfs_ceph_getlock,
	.symlinkat_fn = vfs_ceph_symlinkat,
	.readlinkat_fn = vfs_ceph_readlinkat,
	.linkat_fn = vfs_ceph_linkat,
	.mknodat_fn = vfs_ceph_mknodat,
	.realpath_fn = vfs_ceph_realpath,
	.fchflags_fn = vfs_not_implemented_fchflags,
	.get_real_filename_at_fn = vfs_ceph_get_real_filename_at,
	.connectpath_fn = vfs_ceph_connectpath,
	.fget_dos_attributes_fn = vfs_ceph_fget_dos_attributes,
	.fset_dos_attributes_fn = vfs_ceph_fset_dos_attributes,

	/* EA operations. */
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,
	.fgetxattr_fn = vfs_ceph_fgetxattr,
	.flistxattr_fn = vfs_ceph_flistxattr,
	.fremovexattr_fn = vfs_ceph_fremovexattr,
	.fsetxattr_fn = vfs_ceph_fsetxattr,

	/* Posix ACL Operations */
	.sys_acl_get_fd_fn = posixacl_xattr_acl_get_fd,
	.sys_acl_blob_get_fd_fn = posix_sys_acl_blob_get_fd,
	.sys_acl_set_fd_fn = posixacl_xattr_acl_set_fd,
	.sys_acl_delete_def_fd_fn = posixacl_xattr_acl_delete_def_fd,

	/* aio operations */
	.aio_force_fn = vfs_not_implemented_aio_force,
};

static_decl_vfs;
NTSTATUS vfs_ceph_new_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"ceph_new", &ceph_new_fns);
}
