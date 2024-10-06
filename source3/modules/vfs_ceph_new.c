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
	return ret;
}

static ssize_t lstatus_code(intmax_t ret)
{
	if (ret < 0) {
		errno = -((int)ret);
		return -1;
	}
	return (ssize_t)ret;
}

enum vfs_cephfs_proxy_mode {
	VFS_CEPHFS_PROXY_NO = 0,
	VFS_CEPHFS_PROXY_YES,
	VFS_CEPHFS_PROXY_AUTO
};

static const struct enum_list enum_vfs_cephfs_proxy_vals[] = {
	{VFS_CEPHFS_PROXY_NO, "No"},
	{VFS_CEPHFS_PROXY_NO, "False"},
	{VFS_CEPHFS_PROXY_NO, "0"},
	{VFS_CEPHFS_PROXY_NO, "Off"},
	{VFS_CEPHFS_PROXY_NO, "disable"},
	{VFS_CEPHFS_PROXY_YES, "Yes"},
	{VFS_CEPHFS_PROXY_YES, "True"},
	{VFS_CEPHFS_PROXY_YES, "1"},
	{VFS_CEPHFS_PROXY_YES, "On"},
	{VFS_CEPHFS_PROXY_YES, "enable"},
	{VFS_CEPHFS_PROXY_AUTO, "auto"},
	{-1, NULL}
};

#define CEPH_FN(_name) typeof(_name) *_name ## _fn

struct vfs_ceph_config {
	const char *conf_file;
	const char *user_id;
	const char *fsname;
	struct cephmount_cached *mount_entry;
	struct ceph_mount_info *mount;
	enum vfs_cephfs_proxy_mode proxy;
	void *libhandle;

	CEPH_FN(ceph_ll_lookup_inode);
	CEPH_FN(ceph_ll_walk);
	CEPH_FN(ceph_ll_getattr);
	CEPH_FN(ceph_ll_setattr);
	CEPH_FN(ceph_ll_releasedir);
	CEPH_FN(ceph_ll_create);
	CEPH_FN(ceph_ll_lookup);
	CEPH_FN(ceph_ll_open);
	CEPH_FN(ceph_ll_opendir);
	CEPH_FN(ceph_ll_mkdir);
	CEPH_FN(ceph_ll_rmdir);
	CEPH_FN(ceph_ll_unlink);
	CEPH_FN(ceph_ll_symlink);
	CEPH_FN(ceph_ll_readlink);
	CEPH_FN(ceph_ll_put);
	CEPH_FN(ceph_ll_read);
	CEPH_FN(ceph_ll_write);
	CEPH_FN(ceph_ll_lseek);
	CEPH_FN(ceph_ll_fsync);
	CEPH_FN(ceph_ll_fallocate);
	CEPH_FN(ceph_ll_link);
	CEPH_FN(ceph_ll_rename);
	CEPH_FN(ceph_ll_mknod);
	CEPH_FN(ceph_ll_getxattr);
	CEPH_FN(ceph_ll_setxattr);
	CEPH_FN(ceph_ll_listxattr);
	CEPH_FN(ceph_ll_removexattr);
	CEPH_FN(ceph_ll_lookup_root);
	CEPH_FN(ceph_ll_statfs);
	CEPH_FN(ceph_ll_close);

	CEPH_FN(ceph_chdir);
	CEPH_FN(ceph_conf_get);
	CEPH_FN(ceph_conf_read_file);
	CEPH_FN(ceph_conf_set);
	CEPH_FN(ceph_create);
	CEPH_FN(ceph_getcwd);
	CEPH_FN(ceph_init);
	CEPH_FN(ceph_mount);
	CEPH_FN(ceph_release);
	CEPH_FN(ceph_select_filesystem);
	CEPH_FN(ceph_unmount);
	CEPH_FN(ceph_userperm_destroy);
	CEPH_FN(ceph_userperm_new);
	CEPH_FN(ceph_version);
	CEPH_FN(ceph_readdir);
	CEPH_FN(ceph_rewinddir);
	CEPH_FN(ceph_readdir_r);
};

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
	int32_t count;
	struct ceph_mount_info *mount;
	struct cephmount_cached *next, *prev;
	uint64_t fd_index;
} *cephmount_cached;

static bool cephmount_cache_add(const char *cookie,
				struct ceph_mount_info *mount,
				struct cephmount_cached **out_entry)
{
	struct cephmount_cached *entry = NULL;

	entry = talloc_zero(NULL, struct cephmount_cached);
	if (entry == NULL) {
		errno = ENOMEM;
		return false;
	}

	entry->cookie = talloc_strdup(entry, cookie);
	if (entry->cookie == NULL) {
		talloc_free(entry);
		errno = ENOMEM;
		return false;
	}

	entry->mount = mount;
	entry->count = 1;

	DBG_DEBUG("[CEPH] adding mount cache entry: cookie='%s'\n",
		  entry->cookie);
	DLIST_ADD(cephmount_cached, entry);

	*out_entry = entry;
	return true;
}

static bool cephmount_cache_change_ref(struct cephmount_cached *entry, int n)
{
	entry->count += n;

	DBG_DEBUG("[CEPH] updated mount cache entry: count=%" PRId32
		  "change=%+d cookie='%s'\n", entry->count, n, entry->cookie);

	if (entry->count && (n < 0)) {
		DBG_DEBUG("[CEPH] mount cache entry still in use: "
			  "count=%" PRId32 " cookie='%s'\n",
			  entry->count, entry->cookie);
	}
	return (entry->count == 0);
}

static struct cephmount_cached *cephmount_cache_update(const char *cookie)
{
	struct cephmount_cached *entry = NULL;

	for (entry = cephmount_cached; entry; entry = entry->next) {
		if (strcmp(entry->cookie, cookie) == 0) {
			cephmount_cache_change_ref(entry, 1);
			return entry;
		}
	}

	return NULL;
}

static bool cephmount_cache_remove(struct cephmount_cached *entry)
{
	if (!cephmount_cache_change_ref(entry, -1)) {
		return false;
	}

	DBG_DEBUG("[CEPH] removing mount cache entry: cookie='%s'\n",
		  entry->cookie);
	DLIST_REMOVE(cephmount_cached, entry);
	talloc_free(entry);
	return true;
}

static char *cephmount_get_cookie(TALLOC_CTX * mem_ctx,
				  struct vfs_ceph_config *config)
{
	return talloc_asprintf(mem_ctx, "(%s/%s/%s)",
			       config->conf_file,
			       config->user_id,
			       config->fsname);
}

static int cephmount_update_conf(struct vfs_ceph_config *config,
				 struct ceph_mount_info *mnt,
				 const char *option,
				 const char *value)
{
	DBG_DEBUG("[CEPH] calling ceph_conf_set: option='%s' value='%s'\n",
		  option,
		  value);

	return config->ceph_conf_set_fn(mnt, option, value);
}

static struct ceph_mount_info *cephmount_mount_fs(
	struct vfs_ceph_config *config)
{
	int ret;
	char buf[256];
	struct ceph_mount_info *mnt = NULL;
	/* if config_file and/or user_id are NULL, ceph will use defaults */

	DBG_DEBUG("[CEPH] calling ceph_create: user_id='%s'\n",
		  (config->user_id != NULL) ? config->user_id : "");
	ret = config->ceph_create_fn(&mnt, config->user_id);
	if (ret) {
		errno = -ret;
		return NULL;
	}

	DBG_DEBUG("[CEPH] calling ceph_conf_read_file: conf_file='%s'\n",
		  (config->conf_file == NULL) ? "default path"
					      : config->conf_file);
	ret = config->ceph_conf_read_file_fn(mnt, config->conf_file);
	if (ret) {
		goto out;
	}

	DBG_DEBUG("[CEPH] calling ceph_conf_get: option='%s'\n", "log_file");
	ret = config->ceph_conf_get_fn(mnt, "log_file", buf, sizeof(buf));
	if (ret < 0) {
		goto out;
	}

	/* libcephfs disables POSIX ACL support by default, enable it... */
	ret = cephmount_update_conf(config,
				    mnt,
				    "client_acl_type",
				    "posix_acl");
	if (ret < 0) {
		goto out;
	}
	/* tell libcephfs to perform local permission checks */
	ret = cephmount_update_conf(config,
				    mnt,
				    "fuse_default_permissions",
				    "false");
	if (ret < 0) {
		goto out;
	}
	/*
	 * select a cephfs file system to use:
	 * In ceph, multiple file system support has been stable since
	 * 'pacific'. Permit different shares to access different file systems.
	 */
	if (config->fsname != NULL) {
		DBG_DEBUG("[CEPH] calling ceph_select_filesystem: "
			  "fsname='%s'\n", config->fsname);
		ret = config->ceph_select_filesystem_fn(mnt, config->fsname);
		if (ret < 0) {
			goto out;
		}
	}

	DBG_DEBUG("[CEPH] calling ceph_mount: mnt=%p\n", mnt);
	ret = config->ceph_mount_fn(mnt, NULL);
	if (ret < 0) {
		goto out;
	}
	ret = 0;

out:
	if (ret != 0) {
		config->ceph_release_fn(mnt);
		mnt = NULL;
		DBG_ERR("[CEPH] mount failed: user_id='%s' fsname='%s' %s",
			(config->user_id != NULL) ? config->user_id : "",
			(config->fsname != NULL) ? config->fsname : "",
			strerror(-ret));
		errno = -ret;
	} else {
		DBG_DEBUG("[CEPH] mount done: user_id='%s' fsname='%s'",
			  (config->user_id != NULL) ? config->user_id : "",
			  (config->fsname != NULL) ? config->fsname : "");
	}
	return mnt;
}

#define CHECK_CEPH_FN(hnd, func) \
	do { \
		config->func ## _fn = dlsym(hnd, #func); \
		if (config->func ## _fn == NULL) { \
			if (dlclose(hnd)) { \
				DBG_ERR("%s\n", dlerror()); \
			} \
			errno = ENOSYS; \
			return false; \
		} \
	} while(0);

static bool vfs_cephfs_load_lib(struct vfs_ceph_config *config)
{
	void *libhandle = NULL;
	const char *libname = "libcephfs.so.2";
	const char *libname_proxy = "libcephfs_proxy.so.2";

	switch (config->proxy) {
	case VFS_CEPHFS_PROXY_YES:
	case VFS_CEPHFS_PROXY_AUTO:
		libhandle = dlopen(libname_proxy, RTLD_NOW);
		if (libhandle == NULL) {
			if (config->proxy == VFS_CEPHFS_PROXY_YES) {
				DBG_ERR("%s\n", dlerror());
				return false;
			}
			DBG_DEBUG("%s, trying %s\n", dlerror(), libname);
			FALL_THROUGH;
		} else {
			break;
		}
	case VFS_CEPHFS_PROXY_NO:
	default:
		libhandle = dlopen(libname, RTLD_LAZY);
		if (libhandle == NULL) {
			DBG_ERR("%s\n", dlerror());
			return false;
		}
		break;
	}

	CHECK_CEPH_FN(libhandle, ceph_ll_lookup_inode);
	CHECK_CEPH_FN(libhandle, ceph_ll_walk);
	CHECK_CEPH_FN(libhandle, ceph_ll_getattr);
	CHECK_CEPH_FN(libhandle, ceph_ll_setattr);
	CHECK_CEPH_FN(libhandle, ceph_ll_releasedir);
	CHECK_CEPH_FN(libhandle, ceph_ll_create);
	CHECK_CEPH_FN(libhandle, ceph_ll_open);
	CHECK_CEPH_FN(libhandle, ceph_ll_opendir);
	CHECK_CEPH_FN(libhandle, ceph_ll_mkdir);
	CHECK_CEPH_FN(libhandle, ceph_ll_rmdir);
	CHECK_CEPH_FN(libhandle, ceph_ll_unlink);
	CHECK_CEPH_FN(libhandle, ceph_ll_symlink);
	CHECK_CEPH_FN(libhandle, ceph_ll_readlink);
	CHECK_CEPH_FN(libhandle, ceph_ll_put);
	CHECK_CEPH_FN(libhandle, ceph_ll_read);
	CHECK_CEPH_FN(libhandle, ceph_ll_write);
	CHECK_CEPH_FN(libhandle, ceph_ll_lseek);
	CHECK_CEPH_FN(libhandle, ceph_ll_fsync);
	CHECK_CEPH_FN(libhandle, ceph_ll_fallocate);
	CHECK_CEPH_FN(libhandle, ceph_ll_link);
	CHECK_CEPH_FN(libhandle, ceph_ll_rename);
	CHECK_CEPH_FN(libhandle, ceph_ll_mknod);
	CHECK_CEPH_FN(libhandle, ceph_ll_getxattr);
	CHECK_CEPH_FN(libhandle, ceph_ll_setxattr);
	CHECK_CEPH_FN(libhandle, ceph_ll_listxattr);
	CHECK_CEPH_FN(libhandle, ceph_ll_removexattr);
	CHECK_CEPH_FN(libhandle, ceph_ll_lookup);
	CHECK_CEPH_FN(libhandle, ceph_ll_lookup_root);
	CHECK_CEPH_FN(libhandle, ceph_ll_statfs);
	CHECK_CEPH_FN(libhandle, ceph_ll_close);

	CHECK_CEPH_FN(libhandle, ceph_chdir);
	CHECK_CEPH_FN(libhandle, ceph_conf_get);
	CHECK_CEPH_FN(libhandle, ceph_conf_read_file);
	CHECK_CEPH_FN(libhandle, ceph_conf_set);
	CHECK_CEPH_FN(libhandle, ceph_create);
	CHECK_CEPH_FN(libhandle, ceph_getcwd);
	CHECK_CEPH_FN(libhandle, ceph_init);
	CHECK_CEPH_FN(libhandle, ceph_mount);
	CHECK_CEPH_FN(libhandle, ceph_release);
	CHECK_CEPH_FN(libhandle, ceph_select_filesystem);
	CHECK_CEPH_FN(libhandle, ceph_unmount);
	CHECK_CEPH_FN(libhandle, ceph_userperm_destroy);
	CHECK_CEPH_FN(libhandle, ceph_userperm_new);
	CHECK_CEPH_FN(libhandle, ceph_version);
	CHECK_CEPH_FN(libhandle, ceph_readdir);
	CHECK_CEPH_FN(libhandle, ceph_rewinddir);
	CHECK_CEPH_FN(libhandle, ceph_readdir_r);

	config->libhandle = libhandle;

	return true;
}

static int vfs_ceph_config_destructor(struct vfs_ceph_config *config)
{
	if (config->libhandle) {
		if (dlclose(config->libhandle)) {
			DBG_ERR("%s\n", dlerror());
		}
	}

	return 0;
}

static bool vfs_ceph_load_config(struct vfs_handle_struct *handle,
				 struct vfs_ceph_config **config)
{
	struct vfs_ceph_config *config_tmp = NULL;
	int snum = SNUM(handle->conn);
	const char *module_name = "ceph_new";
	bool ok;

	if (SMB_VFS_HANDLE_TEST_DATA(handle)) {
		SMB_VFS_HANDLE_GET_DATA(handle, config_tmp,
					struct vfs_ceph_config,
					return false);
		goto done;
	}

	config_tmp = talloc_zero(handle->conn, struct vfs_ceph_config);
	if (config_tmp == NULL) {
		errno = ENOMEM;
		return false;
	}
	talloc_set_destructor(config_tmp, vfs_ceph_config_destructor);

	config_tmp->conf_file	= lp_parm_const_string(snum, module_name,
						       "config_file", ".");
	config_tmp->user_id	= lp_parm_const_string(snum, module_name,
						       "user_id", "");
	config_tmp->fsname	= lp_parm_const_string(snum, module_name,
						       "filesystem", "");
	config_tmp->proxy	= lp_parm_enum(snum, module_name, "proxy",
					       enum_vfs_cephfs_proxy_vals,
					       VFS_CEPHFS_PROXY_NO);
	if (config_tmp->proxy == -1) {
		DBG_ERR("value for proxy: mode unknown\n");
		return false;
	}

	ok = vfs_cephfs_load_lib(config_tmp);
	if (!ok) {
		return false;
	}

	SMB_VFS_HANDLE_SET_DATA(handle, config_tmp, NULL,
				struct vfs_ceph_config, return false);

done:
	*config = config_tmp;

	return true;
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
	struct ceph_mount_info *mount = NULL;
	char *cookie;
	struct vfs_ceph_config *config = NULL;
	bool ok;

	ok = vfs_ceph_load_config(handle, &config);
	if (!ok) {
		return -1;
	}

	cookie = cephmount_get_cookie(handle, config);
	if (cookie == NULL) {
		return -1;
	}

	entry = cephmount_cache_update(cookie);
	if (entry != NULL) {
		goto connect_ok;
	}

	mount = cephmount_mount_fs(config);
	if (mount == NULL) {
		ret = -1;
		goto connect_fail;
	}

	ok = cephmount_cache_add(cookie, mount, &entry);
	if (!ok) {
		ret = -1;
		goto connect_fail;
	}

connect_ok:
	config->mount = entry->mount;
	config->mount_entry = entry;
	DBG_INFO("[CEPH] connection established with the server: "
		 "snum=%d cookie='%s'\n",
		 SNUM(handle->conn),
		 cookie);

	/*
	 * Unless we have an async implementation of getxattrat turn this off.
	 */
	lp_do_parameter(SNUM(handle->conn), "smbd async dosmode", "false");
connect_fail:
	talloc_free(cookie);
	return ret;
}

static void vfs_ceph_disconnect(struct vfs_handle_struct *handle)
{
	struct ceph_mount_info *mount = NULL;
	int ret = 0;
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config, return);

	mount = config->mount;

	if (!cephmount_cache_remove(config->mount_entry)) {
		return;
	}

	ret = config->ceph_unmount_fn(mount);
	if (ret < 0) {
		DBG_ERR("[CEPH] failed to unmount: snum=%d %s\n",
			SNUM(handle->conn),
			strerror(-ret));
	}

	ret = config->ceph_release_fn(mount);
	if (ret < 0) {
		DBG_ERR("[CEPH] failed to release: snum=%d %s\n",
			SNUM(handle->conn),
			strerror(-ret));
	}

	config->mount_entry = NULL;

	TALLOC_FREE(config);
}

/* Ceph user-credentials */
static struct UserPerm *vfs_ceph_userperm_new(struct vfs_ceph_config *config,
	struct connection_struct *conn)
{
	const struct security_unix_token *unix_token = NULL;

	unix_token = get_current_utok(conn);
	return config->ceph_userperm_new_fn(unix_token->uid,
					    unix_token->gid,
					    unix_token->ngroups,
					    unix_token->groups);
}

static void vfs_ceph_userperm_del(struct vfs_ceph_config *config,
				  struct UserPerm *uperm)
{
	if (uperm != NULL) {
		config->ceph_userperm_destroy_fn(uperm);
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
	struct vfs_ceph_config *config;
	struct vfs_ceph_iref iref;
	struct Fh *fh;
	struct dirent *de;
	int fd;
	int o_flags;
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

static struct dirent *vfs_ceph_get_fh_dirent(struct vfs_ceph_fh *cfh)
{
	if (cfh->de == NULL) {
		cfh->de = talloc_zero_size(cfh->fsp, sizeof(*(cfh->de)));
	}
	return cfh->de;
}

static void vfs_ceph_put_fh_dirent(struct vfs_ceph_fh *cfh)
{
	if (cfh->de != NULL) {
		TALLOC_FREE(cfh->de);
		cfh->de = NULL;
	}
}

static int vfs_ceph_release_fh(struct vfs_ceph_fh *cfh)
{
	int ret = 0;

	if (cfh->fh != NULL) {
		DBG_DEBUG("[ceph] ceph_ll_close: fd=%d o_flags=0x%x\n",
			  cfh->fd, cfh->o_flags);
		ret = cfh->config->ceph_ll_close_fn(cfh->cme->mount, cfh->fh);
		cfh->fh = NULL;
	}
	if (cfh->iref.inode != NULL) {
		DBG_DEBUG("[ceph] ceph_ll_put: ino=%" PRIu64 "\n",
			  cfh->iref.ino);
		cfh->config->ceph_ll_put_fn(cfh->cme->mount, cfh->iref.inode);
		cfh->iref.inode = NULL;
	}
	if (cfh->uperm != NULL) {
		vfs_ceph_userperm_del(cfh->config, cfh->uperm);
		cfh->uperm = NULL;
	}
	vfs_ceph_put_fh_dirent(cfh);
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
	struct cephmount_cached *cme = NULL;
	struct UserPerm *uperm = NULL;
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	cme = config->mount_entry;

	uperm = vfs_ceph_userperm_new(config, handle->conn);
	if (uperm == NULL) {
		return -ENOMEM;
	}

	*out_cfh = VFS_ADD_FSP_EXTENSION(handle,
					 fsp,
					 struct vfs_ceph_fh,
					 vfs_ceph_fsp_ext_destroy_cb);
	if (*out_cfh == NULL) {
		vfs_ceph_userperm_del(config, uperm);
		return -ENOMEM;
	}
	(*out_cfh)->cme = cme;
	(*out_cfh)->uperm = uperm;
	(*out_cfh)->fsp = fsp;
	(*out_cfh)->config = config;
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
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_lookup_inode: ino=%" PRIu64 "\n", inoval);

	return config->ceph_ll_lookup_inode_fn(config->mount, ino, pout);
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
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_walk: name=%s\n", name);

	uperm = vfs_ceph_userperm_new(config, handle->conn);
	if (uperm == NULL) {
		return -ENOMEM;
	}

	ret = config->ceph_ll_walk_fn(config->mount,
				      name,
				      pin,
				      stx,
				      want,
				      flags,
				      uperm);

	vfs_ceph_userperm_del(config, uperm);
	return ret;
}

static int vfs_ceph_ll_statfs(const struct vfs_handle_struct *handle,
			      const struct vfs_ceph_iref *iref,
			      struct statvfs *stbuf)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_statfs: ino=%" PRIu64 "\n", iref->ino);

	return config->ceph_ll_statfs_fn(config->mount, iref->inode, stbuf);
}

static int vfs_ceph_ll_getattr2(const struct vfs_handle_struct *handle,
				const struct vfs_ceph_iref *iref,
				struct UserPerm *uperm,
				SMB_STRUCT_STAT *st)
{
	struct ceph_statx stx = {0};
	int ret = -1;
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_getattr: ino=%" PRIu64 "\n", iref->ino);

	ret = config->ceph_ll_getattr_fn(config->mount,
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
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct vfs_ceph_config,
				return -ENOMEM);

	uperm = vfs_ceph_userperm_new(config, handle->conn);
	if (uperm == NULL) {
		return -ENOMEM;
	}
	ret = vfs_ceph_ll_getattr2(handle, iref, uperm, st);
	vfs_ceph_userperm_del(config, uperm);
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
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_setattr: ino=%" PRIu64 " uid=%u gid=%u\n",
		  iref->ino, uid, gid);

	uperm = vfs_ceph_userperm_new(config, handle->conn);
	if (uperm == NULL) {
		return -ENOMEM;
	}
	ret = config->ceph_ll_setattr_fn(config->mount,
					 iref->inode,
					 &stx,
					 CEPH_STATX_UID | CEPH_STATX_GID,
					 uperm);
	vfs_ceph_userperm_del(config, uperm);
	return ret;
}

static int vfs_ceph_ll_fchown(struct vfs_handle_struct *handle,
			      const struct vfs_ceph_fh *cfh,
			      uid_t uid,
			      gid_t gid)
{
	struct ceph_statx stx = {.stx_uid = uid, .stx_gid = gid};
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_setattr: ino=%" PRIu64 " uid=%u gid=%u\n",
		  cfh->iref.ino, uid, gid);

	return config->ceph_ll_setattr_fn(config->mount,
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
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_setattr: ino=%" PRIu64 " mode=%o\n",
		  cfh->iref.ino, mode);

	return config->ceph_ll_setattr_fn(config->mount,
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
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

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

	DBG_DEBUG("[ceph] ceph_ll_setattr: ino=%" PRIu64 " mtime=%" PRIu64
		  " atime=%" PRIu64 " ctime=%" PRIu64 " btime=%" PRIu64 "\n",
		  cfh->iref.ino,
		  full_timespec_to_nt_time(&stx.stx_mtime),
		  full_timespec_to_nt_time(&stx.stx_atime),
		  full_timespec_to_nt_time(&stx.stx_ctime),
		  full_timespec_to_nt_time(&stx.stx_btime));

	return config->ceph_ll_setattr_fn(config->mount,
					  cfh->iref.inode,
					  &stx,
					  mask,
					  cfh->uperm);
}

static int vfs_ceph_ll_releasedir(const struct vfs_handle_struct *handle,
				  const struct vfs_ceph_fh *dircfh)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_releasedir: ino=%" PRIu64 " fd=%d\n",
		  dircfh->iref.ino, dircfh->fd);

	return config->ceph_ll_releasedir_fn(config->mount, dircfh->dirp.cdr);
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
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_create: parent-ino=%" PRIu64 " name=%s "
		  "mode=%o\n", parent->ino, name, mode);

	ret = config->ceph_ll_create_fn(config->mount,
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
	cfh->o_flags = oflags;
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
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_lookup: parent-ino=%" PRIu64 " name=%s\n",
		  parent->ino, name);

	uperm = vfs_ceph_userperm_new(config, handle->conn);
	if (uperm == NULL) {
		return -ENOMEM;
	}
	ret = config->ceph_ll_lookup_fn(config->mount,
					parent->inode,
					name,
					&inode,
					&stx,
					CEPH_STATX_INO,
					0,
					uperm);

	vfs_ceph_userperm_del(config, uperm);
	if (ret != 0) {
		return ret;
	}

	iref->inode = inode;
	iref->ino = stx.stx_ino;
	iref->owner = true;
	return 0;
}

static int vfs_ceph_ll_lookup2(const struct vfs_handle_struct *handle,
			       const struct vfs_ceph_fh *parent_fh,
			       const char *name,
			       unsigned want,
			       struct vfs_ceph_iref *iref,
			       struct ceph_statx *stx)
{
	struct Inode *inode = NULL;
	int ret = -1;
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_lookup: parent-ino=%" PRIu64 " name=%s\n",
		  parent_fh->iref.ino, name);

	ret = config->ceph_ll_lookup_fn(config->mount,
					parent_fh->iref.inode,
					name,
					&inode,
					stx,
					want | CEPH_STATX_INO,
					0,
					parent_fh->uperm);
	if (ret != 0) {
		return ret;
	}
	iref->inode = inode;
	iref->ino = stx->stx_ino;
	iref->owner = true;
	return 0;
}

static int vfs_ceph_ll_lookupat(const struct vfs_handle_struct *handle,
				const struct vfs_ceph_fh *parent_fh,
				const char *name,
				struct vfs_ceph_iref *iref)
{
	struct ceph_statx stx = {.stx_ino = 0};

	return vfs_ceph_ll_lookup2(handle,
				   parent_fh,
				   name,
				   CEPH_STATX_INO,
				   iref,
				   &stx);
}

static int vfs_ceph_ll_lookupat2(const struct vfs_handle_struct *handle,
				 const struct vfs_ceph_fh *parent_fh,
				 const char *name,
				 struct vfs_ceph_iref *iref,
				 SMB_STRUCT_STAT *st)
{
	struct ceph_statx stx = {.stx_ino = 0};
	int ret;

	ret = vfs_ceph_ll_lookup2(handle,
				  parent_fh,
				  name,
				  CEPH_STATX_ALL_STATS,
				  iref,
				  &stx);
	if (ret == 0) {
		smb_stat_from_ceph_statx(st, &stx);
	}
	return ret;
}

static int vfs_ceph_ll_open(const struct vfs_handle_struct *handle,
			    struct vfs_ceph_fh *cfh,
			    int flags)
{
	struct Inode *in = cfh->iref.inode;
	struct Fh *fh = NULL;
	int ret = -1;
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_open: ino=%" PRIu64 " flags=0x%x\n",
		  cfh->iref.ino, flags);

	ret = config->ceph_ll_open_fn(config->mount, in, flags, &fh,
				      cfh->uperm);
	if (ret == 0) {
		cfh->fh = fh;
		cfh->o_flags = flags;
		vfs_ceph_assign_fh_fd(cfh);
	}
	return ret;
}

static int vfs_ceph_ll_opendir(const struct vfs_handle_struct *handle,
			       struct vfs_ceph_fh *cfh)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_opendir: ino=%" PRIu64 "\n", cfh->iref.ino);

	return config->ceph_ll_opendir_fn(config->mount,
					  cfh->iref.inode,
					  &cfh->dirp.cdr,
					  cfh->uperm);
}

static int vfs_ceph_ll_readdir(const struct vfs_handle_struct *hndl,
			       const struct vfs_ceph_fh *dircfh)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(hndl, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_readdir: ino=%" PRIu64 " fd=%d\n",
		  dircfh->iref.ino, dircfh->fd);

	return config->ceph_readdir_r_fn(config->mount,
					 dircfh->dirp.cdr,
					 dircfh->de);
}

static void vfs_ceph_ll_rewinddir(const struct vfs_handle_struct *handle,
				  const struct vfs_ceph_fh *dircfh)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config, return);

	DBG_DEBUG("[ceph] ceph_rewinddir: ino=%" PRIu64 " fd=%d\n",
		  dircfh->iref.ino, dircfh->fd);

	config->ceph_rewinddir_fn(config->mount, dircfh->dirp.cdr);
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
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_mkdir: parent-ino=%" PRIu64 " name=%s "
		  "mode=%o\n", dircfh->iref.ino, name, mode);

	ret = config->ceph_ll_mkdir_fn(config->mount,
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

static int vfs_ceph_ll_rmdir(const struct vfs_handle_struct *handle,
			     const struct vfs_ceph_fh *dircfh,
			     const char *name)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_rmdir: parent-ino=%" PRIu64 " name=%s\n",
		  dircfh->iref.ino, name);

	return config->ceph_ll_rmdir_fn(config->mount,
					dircfh->iref.inode,
					name,
					dircfh->uperm);
}

static int vfs_ceph_ll_unlinkat(const struct vfs_handle_struct *handle,
				const struct vfs_ceph_fh *dircfh,
				const char *name)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_unlink: parent-ino=%" PRIu64 " name=%s\n",
		  dircfh->iref.ino, name);

	return config->ceph_ll_unlink_fn(config->mount,
					 dircfh->iref.inode,
					 name,
					 dircfh->uperm);
}

static int vfs_ceph_ll_symlinkat(const struct vfs_handle_struct *handle,
				 const struct vfs_ceph_fh *dircfh,
				 const char *name,
				 const char *value,
				 struct vfs_ceph_iref *out_iref)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct Inode *inode = NULL;
	int ret = -1;
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_symlink: parent-ino=%" PRIu64 " name=%s\n",
		  dircfh->iref.ino, name);

	ret = config->ceph_ll_symlink_fn(config->mount,
					 dircfh->iref.inode,
					 name,
					 value,
					 &inode,
					 &stx,
					 CEPH_STATX_INO,
					 0,
					 dircfh->uperm);
	if (ret != 0) {
		return ret;
	}
	out_iref->inode = inode;
	out_iref->ino = stx.stx_ino;
	out_iref->owner = true;
	return 0;
}

static int vfs_ceph_ll_readlinkat(const struct vfs_handle_struct *handle,
				  const struct vfs_ceph_fh *dircfh,
				  const struct vfs_ceph_iref *iref,
				  char *buf,
				  size_t bsz)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_readlink: ino=%" PRIu64 "\n", iref->ino);

	return config->ceph_ll_readlink_fn(config->mount,
					   iref->inode,
					   buf,
					   bsz,
					   dircfh->uperm);
}

static int vfs_ceph_ll_read(const struct vfs_handle_struct *handle,
			    const struct vfs_ceph_fh *cfh,
			    int64_t off,
			    uint64_t len,
			    char *buf)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_read: ino=%" PRIu64 " fd=%d off=%jd "
		  "len=%ju\n", cfh->iref.ino, cfh->fd, off, len);

	return config->ceph_ll_read_fn(config->mount, cfh->fh, off, len, buf);
}

static int vfs_ceph_ll_write(const struct vfs_handle_struct *handle,
			     const struct vfs_ceph_fh *cfh,
			     int64_t off,
			     uint64_t len,
			     const char *data)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_write: ino=%" PRIu64 " fd=%d off=%jd "
		  "len=%ju\n", cfh->iref.ino, cfh->fd, off, len);

	return config->ceph_ll_write_fn(config->mount, cfh->fh, off, len, data);
}

static off_t vfs_ceph_ll_lseek(const struct vfs_handle_struct *handle,
			       const struct vfs_ceph_fh *cfh,
			       off_t offset,
			       int whence)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_lseek: ino=%" PRIu64 " fd=%d offset=%jd "
		  "whence=%d\n", cfh->iref.ino, cfh->fd, offset, whence);

	return config->ceph_ll_lseek_fn(config->mount, cfh->fh, offset, whence);
}

static int vfs_ceph_ll_fsync(const struct vfs_handle_struct *handle,
			     const struct vfs_ceph_fh *cfh,
			     int syncdataonly)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_fsync: ino=%" PRIu64 " fd=%d "
		  "syncdataonly=%d\n", cfh->iref.ino, cfh->fd, syncdataonly);

	return config->ceph_ll_fsync_fn(config->mount, cfh->fh, syncdataonly);
}

static int vfs_ceph_ll_ftruncate(struct vfs_handle_struct *handle,
				 const struct vfs_ceph_fh *cfh,
				 int64_t size)
{
	struct ceph_statx stx = {.stx_size = (uint64_t)size};
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_setattr: ino=%" PRIu64 " fd=%d size=%jd\n",
		  cfh->iref.ino, cfh->fd, size);

	return config->ceph_ll_setattr_fn(config->mount,
					  cfh->iref.inode,
					  &stx,
					  CEPH_SETATTR_SIZE,
					  cfh->uperm);
}

static int vfs_ceph_ll_fallocate(const struct vfs_handle_struct *handle,
				 const struct vfs_ceph_fh *cfh,
				 int mode,
				 int64_t off,
				 int64_t len)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_fallocate: ino=%" PRIu64 " fd=%d off=%jd "
		  "len=%jd\n", cfh->iref.ino, cfh->fd, off, len);

	return config->ceph_ll_fallocate_fn(config->mount, cfh->fh,
					    mode, off, len);
}

static int vfs_ceph_ll_link(const struct vfs_handle_struct *handle,
			    const struct vfs_ceph_fh *dircfh,
			    const char *name,
			    const struct vfs_ceph_iref *iref)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_link: parent-ino=%" PRIu64 " name=%s\n",
		  dircfh->iref.ino, name);

	return config->ceph_ll_link_fn(config->mount,
				       iref->inode,
				       dircfh->iref.inode,
				       name,
				       dircfh->uperm);
}

static int vfs_ceph_ll_rename(const struct vfs_handle_struct *handle,
			      const struct vfs_ceph_fh *parent,
			      const char *name,
			      const struct vfs_ceph_fh *newparent,
			      const char *newname)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_rename: parent-ino=%" PRIu64
		  " name=%s newparent-ino=%" PRIu64 " newname=%s\n",
		  parent->iref.ino, name, newparent->iref.ino, newname);

	return config->ceph_ll_rename_fn(config->mount,
					 parent->iref.inode,
					 name,
					 newparent->iref.inode,
					 newname,
					 newparent->uperm);
}

static int vfs_ceph_ll_mknod(const struct vfs_handle_struct *handle,
			     const struct vfs_ceph_fh *parent,
			     const char *name,
			     mode_t mode,
			     dev_t rdev,
			     struct vfs_ceph_iref *iref)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct Inode *inode = NULL;
	int ret = -1;
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_mknod: parent-ino=%" PRIu64 " name=%s "
		  "mode=%o\n", parent->iref.ino, name, mode);

	ret = config->ceph_ll_mknod_fn(config->mount,
				       parent->iref.inode,
				       name,
				       mode,
				       rdev,
				       &inode,
				       &stx,
				       CEPH_STATX_INO,
				       0,
				       parent->uperm);
	if (ret == 0) {
		iref->inode = inode;
		iref->ino = stx.stx_ino;
		iref->owner = true;
	}
	return ret;
}

static int vfs_ceph_ll_getxattr(const struct vfs_handle_struct *handle,
				const struct vfs_ceph_iref *iref,
				const char *name,
				void *value,
				size_t size)
{
	struct UserPerm *uperm = NULL;
	int ret = -1;
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_getxattr: ino=%" PRIu64 " name=%s\n",
		  iref->ino, name);

	uperm = vfs_ceph_userperm_new(config, handle->conn);
	if (uperm == NULL) {
		return -ENOMEM;
	}

	ret = config->ceph_ll_getxattr_fn(config->mount,
					  iref->inode,
					  name,
					  value,
					  size,
					  uperm);

	vfs_ceph_userperm_del(config, uperm);

	return ret;
}

static int vfs_ceph_ll_fgetxattr(const struct vfs_handle_struct *handle,
				 const struct vfs_ceph_fh *cfh,
				 const char *name,
				 void *value,
				 size_t size)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_getxattr: ino=%" PRIu64 " name=%s\n",
		  cfh->iref.ino, name);

	return config->ceph_ll_getxattr_fn(config->mount,
					   cfh->iref.inode,
					   name,
					   value,
					   size,
					   cfh->uperm);
}

static int vfs_ceph_ll_setxattr(const struct vfs_handle_struct *handle,
				const struct vfs_ceph_iref *iref,
				const char *name,
				const void *value,
				size_t size,
				int flags)
{
	struct UserPerm *uperm = NULL;
	int ret = -1;
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_setxattr: ino=%" PRIu64 " name=%s "
		  "size=%zu\n", iref->ino, name, size);

	uperm = vfs_ceph_userperm_new(config, handle->conn);
	if (uperm == NULL) {
		return -ENOMEM;
	}

	ret = config->ceph_ll_setxattr_fn(config->mount,
					  iref->inode,
					  name,
					  value,
					  size,
					  flags,
					  uperm);

	vfs_ceph_userperm_del(config, uperm);

	return ret;
}

static int vfs_ceph_ll_fsetxattr(const struct vfs_handle_struct *handle,
				 const struct vfs_ceph_fh *cfh,
				 const char *name,
				 const void *value,
				 size_t size,
				 int flags)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_setxattr: ino=%" PRIu64 " name=%s "
		  "size=%zu\n", cfh->iref.ino, name, size);

	return config->ceph_ll_setxattr_fn(config->mount,
					   cfh->iref.inode,
					   name,
					   value,
					   size,
					   flags,
					   cfh->uperm);
}

static int vfs_ceph_ll_listxattr(const struct vfs_handle_struct *handle,
				 const struct vfs_ceph_iref *iref,
				 char *list,
				 size_t buf_size,
				 size_t *list_size)
{
	struct UserPerm *uperm = NULL;
	int ret = -1;
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_listxattr: ino=%" PRIu64 "\n", iref->ino);

	uperm = vfs_ceph_userperm_new(config, handle->conn);
	if (uperm == NULL) {
		return -ENOMEM;
	}

	ret = config->ceph_ll_listxattr_fn(config->mount,
					   iref->inode,
					   list,
					   buf_size,
					   list_size,
					   uperm);

	vfs_ceph_userperm_del(config, uperm);

	return ret;
}

static int vfs_ceph_ll_flistxattr(const struct vfs_handle_struct *handle,
				  const struct vfs_ceph_fh *cfh,
				  char *list,
				  size_t buf_size,
				  size_t *list_size)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_listxattr: ino=%" PRIu64 "\n", cfh->iref.ino);

	return config->ceph_ll_listxattr_fn(config->mount,
					    cfh->iref.inode,
					    list,
					    buf_size,
					    list_size,
					    cfh->uperm);
}

static int vfs_ceph_ll_removexattr(const struct vfs_handle_struct *handle,
				   const struct vfs_ceph_iref *iref,
				   const char *name)
{
	struct UserPerm *uperm = NULL;
	int ret = -1;
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_removexattr: ino=%" PRIu64 " name=%s\n",
		  iref->ino, name);

	uperm = vfs_ceph_userperm_new(config, handle->conn);
	if (uperm == NULL) {
		return -ENOMEM;
	}

	ret = config->ceph_ll_removexattr_fn(config->mount, iref->inode,
					     name, uperm);

	vfs_ceph_userperm_del(config, uperm);

	return ret;
}

static int vfs_ceph_ll_fremovexattr(const struct vfs_handle_struct *handle,
				    const struct vfs_ceph_fh *cfh,
				    const char *name)
{
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[ceph] ceph_ll_removexattr: ino=%" PRIu64 " name=%s\n",
		  cfh->iref.ino, name);

	return config->ceph_ll_removexattr_fn(config->mount,
					      cfh->iref.inode,
					      name,
					      cfh->uperm);
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
	DBG_DEBUG("[CEPH] iget: %s ino=%" PRIu64 "\n", name, iref->ino);
	return 0;
}

static int vfs_ceph_iget_by_fname(const struct vfs_handle_struct *handle,
				  const struct smb_filename *smb_fname,
				  struct vfs_ceph_iref *iref)
{
	const char *name = smb_fname->base_name;
	const char *cwd = NULL;
	int ret = -1;
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	cwd = config->ceph_getcwd_fn(config->mount);
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

static int vfs_ceph_igetf(struct vfs_handle_struct *handle,
			  const struct files_struct *fsp,
			  struct vfs_ceph_iref *iref)
{
	return vfs_ceph_iget(
		handle, fsp->file_id.inode, fsp->fsp_name->base_name, 0, iref);
}

static void vfs_ceph_iput(const struct vfs_handle_struct *handle,
			  struct vfs_ceph_iref *iref)
{
	if ((iref != NULL) && (iref->inode != NULL) && iref->owner) {
		struct vfs_ceph_config *config = NULL;

		SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
					return);

		DBG_DEBUG("[ceph] ceph_ll_put: ino=%" PRIu64 "\n", iref->ino);

		config->ceph_ll_put_fn(config->mount, iref->inode);
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
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	ret = config->ceph_ll_lookup_root_fn(config->mount, &inode);
	if (ret != 0) {
		DBG_DEBUG("[CEPH] ceph_ll_lookup_root returned %d\n", ret);
		errno = -ret;
		return (uint64_t)(-1);
	}
	ret = config->ceph_ll_statfs_fn(config->mount, inode, &statvfs_buf);
	config->ceph_ll_put_fn(config->mount, inode);
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
	struct vfs_ceph_fh *dircfh = (struct vfs_ceph_fh *)dirp;
	struct dirent *result = NULL;
	int saved_errno = errno;
	int ret = -1;

	DBG_DEBUG("[CEPH] readdir(%p, %p)\n", handle, dirp);

	result = vfs_ceph_get_fh_dirent(dircfh);
	if (result == NULL) {
		/* Memory allocation failure */
		return NULL;
	}

	/* The low-level call uses 'dircfh->de' which is now 'result' */
	ret = vfs_ceph_ll_readdir(handle, dircfh);
	if (ret < 0) {
		/* Error case */
		DBG_DEBUG("[CEPH] readdir(...) = %d\n", ret);
		vfs_ceph_put_fh_dirent(dircfh);
		result = NULL;
		saved_errno = ret;
	} else if (ret == 0) {
		/* End of directory stream */
		vfs_ceph_put_fh_dirent(dircfh);
		result = NULL;
	} else {
		/* Normal case */
		DBG_DEBUG("[CEPH] readdir(...) = %p\n", result);
	}
	errno = saved_errno;
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
			cfh->o_flags = flags;
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
	struct vfs_ceph_fh *cfh = NULL;
	ssize_t result;

	DBG_DEBUG("[CEPH] pread(%p, %p, %p, %llu, %llu)\n",
		  handle,
		  fsp,
		  data,
		  llu(n),
		  llu(offset));

	result = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_ll_read(handle, cfh, offset, n, data);
out:
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
	struct vfs_ceph_fh *cfh = NULL;
	struct tevent_req *req = NULL;
	struct vfs_ceph_pread_state *state = NULL;
	int ret = -1;

	DBG_DEBUG("[CEPH] pread_send(%p, %p, %p, %zu, %zd)\n",
		  handle,
		  fsp,
		  data,
		  n,
		  offset);
	req = tevent_req_create(mem_ctx, &state, struct vfs_ceph_pread_state);
	if (req == NULL) {
		return NULL;
	}

	ret = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
	if (ret != 0) {
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}

	ret = vfs_ceph_ll_read(handle, cfh, offset, n, data);
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

	DBG_DEBUG("[CEPH] pread_recv: bytes_read=%zd\n", state->bytes_read);
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
	struct vfs_ceph_fh *cfh = NULL;
	ssize_t result;

	DBG_DEBUG("[CEPH] pwrite(%p, %p, %p, %llu, %llu)\n",
		  handle,
		  fsp,
		  data,
		  llu(n),
		  llu(offset));

	result = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
	if (result != 0) {
		goto out;
	}
	result = vfs_ceph_ll_write(handle, cfh, offset, n, data);
out:
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
	struct vfs_ceph_fh *cfh = NULL;
	struct tevent_req *req = NULL;
	struct vfs_ceph_pwrite_state *state = NULL;
	int ret = -1;

	DBG_DEBUG("[CEPH] pwrite_send(%p, %p, %p, %zu, %zd)\n",
		  handle,
		  fsp,
		  data,
		  n,
		  offset);
	req = tevent_req_create(mem_ctx, &state, struct vfs_ceph_pwrite_state);
	if (req == NULL) {
		return NULL;
	}

	ret = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
	if (ret != 0) {
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}

	ret = vfs_ceph_ll_write(handle, cfh, offset, n, data);
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

	DBG_DEBUG("[CEPH] pwrite_recv: bytes_written=%zd\n",
		  state->bytes_written);
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
	struct vfs_ceph_fh *cfh = NULL;
	intmax_t result = 0;

	DBG_DEBUG(
		"[CEPH] lseek(%p, %p, %zd, %d)\n", handle, fsp, offset, whence);
	result = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_ll_lseek(handle, cfh, offset, whence);
out:
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
	DBG_DEBUG("[CEPH] sendfile(%p, %d, %p, %p, %zd, %zu)\n",
		  handle,
		  tofd,
		  fromfsp,
		  hdr,
		  offset,
		  n);
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
	DBG_DEBUG("[CEPH] recvfile(%p, %d, %p, %zd, %zu)\n",
		  handle,
		  fromfd,
		  tofsp,
		  offset,
		  n);
	errno = ENOTSUP;
	return -1;
}

static int vfs_ceph_renameat(struct vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *smb_fname_src,
			files_struct *dstfsp,
			const struct smb_filename *smb_fname_dst)
{
	struct vfs_ceph_fh *src_dircfh = NULL;
	struct vfs_ceph_fh *dst_dircfh = NULL;
	int result = -1;

	DBG_DEBUG("[CEPH] renameat(%p, %p, %s, %p, %s)\n",
		  handle,
		  srcfsp,
		  smb_fname_src->base_name,
		  dst_dircfh,
		  smb_fname_dst->base_name);

	if (smb_fname_src->stream_name || smb_fname_dst->stream_name) {
		errno = ENOENT;
		return result;
	}

	result = vfs_ceph_fetch_fh(handle, srcfsp, &src_dircfh);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_fetch_fh(handle, dstfsp, &dst_dircfh);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_ll_rename(handle,
				    src_dircfh,
				    smb_fname_src->base_name,
				    dst_dircfh,
				    smb_fname_dst->base_name);
out:
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
	struct vfs_ceph_fh *cfh = NULL;
	struct tevent_req *req = NULL;
	struct vfs_aio_state *state = NULL;
	int ret = -1;

	DBG_DEBUG("[CEPH] fsync_send(%p, %p)\n", handle, fsp);

	req = tevent_req_create(mem_ctx, &state, struct vfs_aio_state);
	if (req == NULL) {
		return NULL;
	}

	ret = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
	if (ret != 0) {
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}

	/* Make sync call. */
	ret = vfs_ceph_ll_fsync(handle, cfh, false);
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

	DBG_DEBUG("[CEPH] fsync_recv: error=%d duration=%" PRIu64 "\n",
		  state->error,
		  state->duration);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = *state;
	return 0;
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
	struct vfs_ceph_fh *dircfh = NULL;
	const char *name = smb_fname->base_name;
	int result = -1;

	DBG_DEBUG("[CEPH] unlinkat(%p, %s)\n",
		  handle,
		  smb_fname_str_dbg(smb_fname));

	if (smb_fname->stream_name) {
		errno = ENOENT;
		return result;
	}

	result = vfs_ceph_fetch_fh(handle, dirfsp, &dircfh);
	if (result != 0) {
		goto out;
	}

	if (flags & AT_REMOVEDIR) {
		result = vfs_ceph_ll_rmdir(handle, dircfh, name);
	} else {
		result = vfs_ceph_ll_unlinkat(handle, dircfh, name);
	}
out:
	DBG_DEBUG("[CEPH] unlinkat(...) = %d\n", result);
	return status_code(result);
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
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return -ENOMEM);

	DBG_DEBUG("[CEPH] chdir(%p, %s)\n", handle, smb_fname->base_name);
	result = config->ceph_chdir_fn(config->mount, smb_fname->base_name);
	DBG_DEBUG("[CEPH] chdir(...) = %d\n", result);
	return status_code(result);
}

static struct smb_filename *vfs_ceph_getwd(struct vfs_handle_struct *handle,
			TALLOC_CTX *ctx)
{
	const char *cwd = NULL;
	struct vfs_ceph_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_config,
				return NULL);

	cwd = config->ceph_getcwd_fn(config->mount);
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
	struct vfs_ceph_fh *cfh = NULL;

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

	result = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
	if (result != 0) {
		return status_code(result);
	}

	/* Shrink - just ftruncate. */
	if (pst->st_ex_size > len) {
		result = vfs_ceph_ll_ftruncate(handle, cfh, len);
		return status_code(result);
	}

	space_to_write = len - pst->st_ex_size;
	result = vfs_ceph_ll_fallocate(
		handle, cfh, 0, pst->st_ex_size, space_to_write);

	return status_code(result);
}

static int vfs_ceph_ftruncate(struct vfs_handle_struct *handle,
			      files_struct *fsp,
			      off_t len)
{
	struct vfs_ceph_fh *cfh = NULL;
	int result = -1;

	DBG_DEBUG("[CEPH] ftruncate(%p, %p, %llu\n", handle, fsp, llu(len));

	if (lp_strict_allocate(SNUM(fsp->conn))) {
		return strict_allocate_ftruncate(handle, fsp, len);
	}

	result = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
	if (result != 0) {
		goto out;
	}
	result = vfs_ceph_ll_ftruncate(handle, cfh, len);
out:
	return status_code(result);
}

static int vfs_ceph_fallocate(struct vfs_handle_struct *handle,
			      struct files_struct *fsp,
			      uint32_t mode,
			      off_t offset,
			      off_t len)
{
	struct vfs_ceph_fh *cfh = NULL;
	int result;

	DBG_DEBUG("[CEPH] fallocate(%p, %p, %u, %llu, %llu\n",
		  handle, fsp, mode, llu(offset), llu(len));
	result = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
	if (result != 0) {
		goto out;
	}

	/* unsupported mode flags are rejected by libcephfs */
	result = vfs_ceph_ll_fallocate(handle, cfh, mode, offset, len);
out:
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
	DBG_DEBUG("[CEPH] lock(%p, %p, %d, %zd, %zd, %d)\n",
		  handle,
		  fsp,
		  op,
		  offset,
		  count,
		  type);
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
	struct vfs_ceph_iref iref = {0};
	struct vfs_ceph_fh *dircfh = NULL;
	int result = -1;

	DBG_DEBUG("[CEPH] symlinkat(%p, %s, %s)\n",
		  handle,
		  link_target->base_name,
		  new_smb_fname->base_name);

	result = vfs_ceph_fetch_fh(handle, dirfsp, &dircfh);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_ll_symlinkat(handle,
				       dircfh,
				       new_smb_fname->base_name,
				       link_target->base_name,
				       &iref);
	if (result != 0) {
		goto out;
	}
	vfs_ceph_iput(handle, &iref);
out:
	DBG_DEBUG("[CEPH] symlinkat(...) = %d\n", result);
	return status_code(result);
}

static int vfs_ceph_readlinkat(struct vfs_handle_struct *handle,
		const struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		char *buf,
		size_t bufsiz)
{
	int result = -1;
	struct vfs_ceph_fh *dircfh = NULL;

	DBG_DEBUG("[CEPH] readlinkat(%p, %s, %p, %llu)\n",
		  handle,
		  smb_fname->base_name,
		  buf,
		  llu(bufsiz));

	result = vfs_ceph_fetch_fh(handle, dirfsp, &dircfh);
	if (result != 0) {
		goto out;
	}
	if (strcmp(smb_fname->base_name, "") != 0) {
		struct vfs_ceph_iref iref = {0};

		result = vfs_ceph_ll_lookupat(handle,
					      dircfh,
					      smb_fname->base_name,
					      &iref);
		if (result != 0) {
			goto out;
		}
		result = vfs_ceph_ll_readlinkat(handle,
						dircfh,
						&iref,
						buf,
						bufsiz);
		vfs_ceph_iput(handle, &iref);
	} else {
		result = vfs_ceph_ll_readlinkat(handle,
						dircfh,
						&dircfh->iref,
						buf,
						bufsiz);
	}
out:
	DBG_DEBUG("[CEPH] readlinkat(...) = %d\n", result);
	return status_code(result);
}

static int vfs_ceph_linkat(struct vfs_handle_struct *handle,
			   files_struct *srcfsp,
			   const struct smb_filename *old_smb_fname,
			   files_struct *dstfsp,
			   const struct smb_filename *new_smb_fname,
			   int flags)
{
	struct vfs_ceph_fh *src_dircfh = NULL;
	struct vfs_ceph_fh *dst_dircfh = NULL;
	struct vfs_ceph_iref iref = {0};
	const char *name = old_smb_fname->base_name;
	const char *newname = new_smb_fname->base_name;
	int result = -1;

	/* Prevent special linkat modes until it is required by VFS layer */
	if (flags & (AT_EMPTY_PATH | AT_SYMLINK_FOLLOW)) {
		errno = ENOTSUP;
		return -1;
	}

	DBG_DEBUG("[CEPH] link(%p, %s, %s)\n", handle, name, newname);

	result = vfs_ceph_fetch_fh(handle, srcfsp, &src_dircfh);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_fetch_fh(handle, dstfsp, &dst_dircfh);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_ll_lookupat(handle, src_dircfh, name, &iref);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_ll_link(handle, dst_dircfh, newname, &iref);
	if (result != 0) {
		goto out;
	}

	vfs_ceph_iput(handle, &iref);
out:
	DBG_DEBUG("[CEPH] link(...) = %d\n", result);
	return status_code(result);
}

static int vfs_ceph_mknodat(struct vfs_handle_struct *handle,
		files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode,
		SMB_DEV_T dev)
{
	struct vfs_ceph_iref iref = {0};
	struct vfs_ceph_fh *dircfh = NULL;
	const char *name = smb_fname->base_name;
	int result = -1;

	result = vfs_ceph_fetch_fh(handle, dirfsp, &dircfh);
	if (result != 0) {
		goto out;
	}

	DBG_DEBUG("[CEPH] mknodat(%p, %s)\n", handle, name);

	result = vfs_ceph_ll_mknod(handle, dircfh, name, mode, dev, &iref);
	if (result != 0) {
		goto out;
	}

	vfs_ceph_iput(handle, &iref);
out:
	DBG_DEBUG("[CEPH] mknodat(...) = %d\n", result);
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
		struct vfs_ceph_fh *cfh = NULL;

		ret = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
		if (ret != 0) {
			goto out;
		}

		ret = vfs_ceph_ll_fgetxattr(handle, cfh, name, value, size);
	} else {
		struct vfs_ceph_iref iref = {0};

		ret = vfs_ceph_igetf(handle, fsp, &iref);
		if (ret != 0) {
			goto out;
		}

		ret = vfs_ceph_ll_getxattr(handle, &iref, name, value, size);
		vfs_ceph_iput(handle, &iref);
	}
out:
	DBG_DEBUG("[CEPH] fgetxattr(...) = %d\n", ret);
	return lstatus_code(ret);
}

static ssize_t vfs_ceph_flistxattr(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   char *list,
				   size_t size)
{
	size_t list_size = 0;
	int ret;

	DBG_DEBUG("[CEPH] flistxattr(%p, %p, %p, %llu)\n",
		  handle, fsp, list, llu(size));

	if (!fsp->fsp_flags.is_pathref) {
		struct vfs_ceph_fh *cfh = NULL;

		ret = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
		if (ret != 0) {
			goto out;
		}

		ret = vfs_ceph_ll_flistxattr(handle,
					     cfh,
					     list,
					     size,
					     &list_size);
		if (ret != 0) {
			goto out;
		}
	} else {
		struct vfs_ceph_iref iref = {0};

		ret = vfs_ceph_igetf(handle, fsp, &iref);
		if (ret != 0) {
			goto out;
		}
		ret = vfs_ceph_ll_listxattr(handle,
					    &iref,
					    list,
					    size,
					    &list_size);
		if (ret != 0) {
			goto out;
		}
		vfs_ceph_iput(handle, &iref);
	}
	ret = (int)list_size;
out:
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
		struct vfs_ceph_fh *cfh = NULL;

		ret = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
		if (ret != 0) {
			goto out;
		}

		ret = vfs_ceph_ll_fremovexattr(handle, cfh, name);
	} else {
		struct vfs_ceph_iref iref = {0};

		ret = vfs_ceph_igetf(handle, fsp, &iref);
		if (ret != 0) {
			goto out;
		}

		ret = vfs_ceph_ll_removexattr(handle, &iref, name);
		vfs_ceph_iput(handle, &iref);
	}
out:
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
		struct vfs_ceph_fh *cfh = NULL;

		ret = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
		if (ret != 0) {
			goto out;
		}
		ret = vfs_ceph_ll_fsetxattr(handle,
					    cfh,
					    name,
					    value,
					    size,
					    flags);
	} else {
		struct vfs_ceph_iref iref = {0};

		ret = vfs_ceph_igetf(handle, fsp, &iref);
		if (ret != 0) {
			goto out;
		}
		ret = vfs_ceph_ll_setxattr(handle,
					   &iref,
					   name,
					   value,
					   size,
					   flags);
		vfs_ceph_iput(handle, &iref);
	}
out:
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
	struct vfs_ceph_fh *dircfh = NULL;
	struct vfs_ceph_iref iref = {0};

	ret = vfs_ceph_fetch_fh(handle, dirfsp, &dircfh);
	if (ret != 0) {
		status = map_nt_error_from_unix(-ret);
		goto out;
	}

	/* Form the msdfs_link contents */
	msdfs_link = msdfs_link_string(frame,
					reflist,
					referral_count);
	if (msdfs_link == NULL) {
		goto out;
	}

	ret = vfs_ceph_ll_symlinkat(handle,
				    dircfh,
				    smb_fname->base_name,
				    msdfs_link,
				    &iref);
	if (ret == 0) {
		vfs_ceph_iput(handle, &iref);
		status = NT_STATUS_OK;
	} else {
		status = map_nt_error_from_unix(-ret);
	}

out:
	DBG_DEBUG("[CEPH] create_dfs_pathat(...) = %s\n", nt_errstr(status));

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
	size_t bufsize = 0;
	char *link_target = NULL;
	int referral_len = 0;
	bool ok;
#if defined(HAVE_BROKEN_READLINK)
	char link_target_buf[PATH_MAX];
#else
	char link_target_buf[7];
#endif
	SMB_STRUCT_STAT st = {0};
	struct vfs_ceph_fh *dircfh = NULL;
	struct vfs_ceph_iref iref = {0};
	int ret;

	if (is_named_stream(smb_fname)) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto out;
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
			goto out;
		}
	}

	ret = vfs_ceph_fetch_fh(handle, dirfsp, &dircfh);
	if (ret != 0) {
		status = map_nt_error_from_unix(-ret);
		goto out;
	}

	ret = vfs_ceph_ll_lookupat2(handle,
				    dircfh,
				    smb_fname->base_name,
				    &iref,
				    &st);
	if (ret != 0) {
		status = map_nt_error_from_unix(-ret);
		goto out;
	}

	if (!S_ISLNK(st.st_ex_mode)) {
		DBG_INFO("%s is not a link.\n", smb_fname->base_name);
		status = NT_STATUS_OBJECT_TYPE_MISMATCH;
		goto out;
	}

	ret = vfs_ceph_ll_readlinkat(handle,
				     dircfh,
				     &iref,
				     link_target,
				     bufsize - 1);
	if (ret < 0) {
		DBG_ERR("Error reading msdfs link %s: %d\n",
			smb_fname->base_name, ret);
		status = map_nt_error_from_unix(-ret);
		goto out;
	}

	referral_len = ret;
	link_target[referral_len] = '\0';
	DBG_INFO("%s -> %s\n", smb_fname->base_name, link_target);

	if (!strnequal(link_target, "msdfs:", 6)) {
		status = NT_STATUS_OBJECT_TYPE_MISMATCH;
		goto out;
	}

	status = NT_STATUS_OK;
	if (ppreflist == NULL && preferral_count == NULL) {
		/* Early return for checking if this is a DFS link. */
		goto out;
	}

	ok = parse_msdfs_symlink(mem_ctx,
			lp_msdfs_shuffle_referrals(SNUM(handle->conn)),
			link_target,
			ppreflist,
			preferral_count);

	if (!ok) {
		status = NT_STATUS_NO_MEMORY;
	}

out:
	DBG_DEBUG("[CEPH] read_dfs_pathat(...) = %s\n", nt_errstr(status));

	vfs_ceph_iput(handle, &iref);
	if ((link_target != NULL) && (link_target != link_target_buf)) {
		TALLOC_FREE(link_target);
	}
	if (NT_STATUS_IS_OK(status)) {
		memcpy(&smb_fname->st, &st, sizeof(smb_fname->st));
	}
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
