/*
 * VFS module to alter the algorithm to calculate
 * the struct file_id used as key for the share mode
 * and byte range locking db's.
 *
 * Copyright (C) 2007, Stefan Metzmacher
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"

static int vfs_fileid_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_fileid_debug_level

struct fileid_mount_entry {
	SMB_DEV_T device;
	const char *mnt_fsname;
	fsid_t fsid;
	uint64_t devid;
};

struct fileid_nolock_inode {
	dev_t dev;
	ino_t ino;
};

struct fileid_handle_data {
	struct vfs_handle_struct *handle;
	struct file_id (*mapping_fn)(struct fileid_handle_data *data,
				     const SMB_STRUCT_STAT *sbuf);
	char **fstype_deny_list;
	char **fstype_allow_list;
	char **mntdir_deny_list;
	char **mntdir_allow_list;
	unsigned num_mount_entries;
	struct fileid_mount_entry *mount_entries;
	struct {
		bool force_all_inodes;
		bool force_all_dirs;
		uint64_t extid;
		size_t num_inodes;
		struct fileid_nolock_inode *inodes;
	} nolock;
};

/* check if a mount entry is allowed based on fstype and mount directory */
static bool fileid_mount_entry_allowed(struct fileid_handle_data *data,
				       struct mntent *m)
{
	int i;
	char **fstype_deny = data->fstype_deny_list;
	char **fstype_allow = data->fstype_allow_list;
	char **mntdir_deny = data->mntdir_deny_list;
	char **mntdir_allow = data->mntdir_allow_list;

	if (fstype_deny != NULL) {
		for (i = 0; fstype_deny[i] != NULL; i++) {
			if (strcmp(m->mnt_type, fstype_deny[i]) == 0) {
				return false;
			}
		}
	}
	if (fstype_allow != NULL) {
		for (i = 0; fstype_allow[i] != NULL; i++) {
			if (strcmp(m->mnt_type, fstype_allow[i]) == 0) {
				break;
			}
		}
		if (fstype_allow[i] == NULL) {
			return false;
		}
	}
	if (mntdir_deny != NULL) {
		for (i=0; mntdir_deny[i] != NULL; i++) {
			if (strcmp(m->mnt_dir, mntdir_deny[i]) == 0) {
				return false;
			}
		}
	}
	if (mntdir_allow != NULL) {
		for (i=0; mntdir_allow[i] != NULL; i++) {
			if (strcmp(m->mnt_dir, mntdir_allow[i]) == 0) {
				break;
			}
		}
		if (mntdir_allow[i] == NULL) {
			return false;
		}
	}
	return true;
}


/* load all the mount entries from the mtab */
static void fileid_load_mount_entries(struct fileid_handle_data *data)
{
	FILE *f;
	struct mntent *m;

	data->num_mount_entries = 0;
	TALLOC_FREE(data->mount_entries);

	f = setmntent("/etc/mtab", "r");
	if (!f) return;

	while ((m = getmntent(f))) {
		struct stat st;
		struct statfs sfs;
		struct fileid_mount_entry *cur;
		bool allowed;

		allowed = fileid_mount_entry_allowed(data, m);
		if (!allowed) {
			DBG_DEBUG("skipping mount entry %s\n", m->mnt_dir);
			continue;
		}
		if (stat(m->mnt_dir, &st) != 0) continue;
		if (statfs(m->mnt_dir, &sfs) != 0) continue;

		if (strncmp(m->mnt_fsname, "/dev/", 5) == 0) {
			m->mnt_fsname += 5;
		}

		data->mount_entries = talloc_realloc(data,
							   data->mount_entries,
							   struct fileid_mount_entry,
							   data->num_mount_entries+1);
		if (data->mount_entries == NULL) {
			goto nomem;
		}

		cur = &data->mount_entries[data->num_mount_entries];
		cur->device	= st.st_dev;
		cur->mnt_fsname = talloc_strdup(data->mount_entries,
						m->mnt_fsname);
		if (!cur->mnt_fsname) goto nomem;
		cur->fsid	= sfs.f_fsid;
		cur->devid	= (uint64_t)-1;

		data->num_mount_entries++;
	}
	endmntent(f);
	return;

nomem:
	if (f) endmntent(f);

	data->num_mount_entries = 0;
	TALLOC_FREE(data->mount_entries);

	return;
}

/* find a mount entry given a dev_t */
static struct fileid_mount_entry *fileid_find_mount_entry(struct fileid_handle_data *data,
							  SMB_DEV_T dev)
{
	unsigned i;

	if (data->num_mount_entries == 0) {
		fileid_load_mount_entries(data);
	}
	for (i=0;i<data->num_mount_entries;i++) {
		if (data->mount_entries[i].device == dev) {
			return &data->mount_entries[i];
		}
	}
	/* 2nd pass after reloading */
	fileid_load_mount_entries(data);
	for (i=0;i<data->num_mount_entries;i++) {
		if (data->mount_entries[i].device == dev) {
			return &data->mount_entries[i];
		}
	}
	return NULL;
}


/* a 64 bit hash, based on the one in tdb */
static uint64_t fileid_uint64_hash(const uint8_t *s, size_t len)
{
	uint64_t value;	/* Used to compute the hash value.  */
	uint32_t i;	/* Used to cycle through random values. */

	/* Set the initial value from the key size. */
	for (value = 0x238F13AFLL * len, i=0; i < len; i++)
		value = (value + (((uint64_t)s[i]) << (i*5 % 24)));

	return (1103515243LL * value + 12345LL);
}

/* a device mapping using a fsname */
static uint64_t fileid_device_mapping_fsname(struct fileid_handle_data *data,
					     const SMB_STRUCT_STAT *sbuf)
{
	struct fileid_mount_entry *m;

	m = fileid_find_mount_entry(data, sbuf->st_ex_dev);
	if (!m) return sbuf->st_ex_dev;

	if (m->devid == (uint64_t)-1) {
		m->devid = fileid_uint64_hash((const uint8_t *)m->mnt_fsname,
					      strlen(m->mnt_fsname));
	}

	return m->devid;
}

static struct file_id fileid_mapping_fsname(struct fileid_handle_data *data,
					    const SMB_STRUCT_STAT *sbuf)
{
	struct file_id id = { .inode = sbuf->st_ex_ino, };

	id.devid = fileid_device_mapping_fsname(data, sbuf);

	return id;
}

/* a device mapping using a hostname */
static uint64_t fileid_device_mapping_hostname(struct fileid_handle_data *data,
					       const SMB_STRUCT_STAT *sbuf)
{
	char hostname[HOST_NAME_MAX+1];
	char *devname = NULL;
	uint64_t id;
	size_t devname_len;
	int rc;

	rc = gethostname(hostname, HOST_NAME_MAX+1);
	if (rc != 0) {
		DBG_ERR("gethostname failed\n");
		return UINT64_MAX;
	}

	devname = talloc_asprintf(talloc_tos(), "%s%ju",
				  hostname, (uintmax_t)sbuf->st_ex_dev);
	if (devname == NULL) {
		DBG_ERR("talloc_asprintf failed\n");
		return UINT64_MAX;
	}
	devname_len = talloc_array_length(devname) - 1;

	id = fileid_uint64_hash((uint8_t *)devname, devname_len);

	TALLOC_FREE(devname);

	return id;
}

static struct file_id fileid_mapping_hostname(struct fileid_handle_data *data,
					      const SMB_STRUCT_STAT *sbuf)
{
	struct file_id id = { .inode = sbuf->st_ex_ino, };

	id.devid = fileid_device_mapping_hostname(data, sbuf);

	return id;
}

static bool fileid_is_nolock_inode(struct fileid_handle_data *data,
				   const SMB_STRUCT_STAT *sbuf)
{
	size_t i;

	if (data->nolock.force_all_inodes) {
		return true;
	}

	if (S_ISDIR(sbuf->st_ex_mode) && data->nolock.force_all_dirs) {
		return true;
	}

	/*
	 * We could make this a binary search over an sorted array,
	 * but for now we keep things simple.
	 */

	for (i=0; i < data->nolock.num_inodes; i++) {
		if (data->nolock.inodes[i].ino != sbuf->st_ex_ino) {
			continue;
		}

		if (data->nolock.inodes[i].dev == 0) {
			/*
			 * legacy "fileid:nolockinode"
			 * handling ignoring dev
			 */
			return true;
		}

		if (data->nolock.inodes[i].dev != sbuf->st_ex_dev) {
			continue;
		}

		return true;
	}

	return false;
}

static int fileid_add_nolock_inode(struct fileid_handle_data *data,
				   const SMB_STRUCT_STAT *sbuf)
{
	bool exists = fileid_is_nolock_inode(data, sbuf);
	struct fileid_nolock_inode *inodes = NULL;

	if (exists) {
		return 0;
	}

	inodes = talloc_realloc(data, data->nolock.inodes,
				struct fileid_nolock_inode,
				data->nolock.num_inodes + 1);
	if (inodes == NULL) {
		return -1;
	}

	inodes[data->nolock.num_inodes] = (struct fileid_nolock_inode) {
		.dev = sbuf->st_ex_dev,
		.ino = sbuf->st_ex_ino,
	};
	data->nolock.inodes = inodes;
	data->nolock.num_inodes += 1;

	return 0;
}

static uint64_t fileid_mapping_nolock_extid(uint64_t max_slots)
{
	char buf[8+4+HOST_NAME_MAX+1] = { 0, };
	uint64_t slot = 0;
	uint64_t id;
	int rc;

	if (max_slots > 1) {
		slot = getpid() % max_slots;
	}

	PUSH_LE_U64(buf, 0, slot);
	PUSH_LE_U32(buf, 8, get_my_vnn());

	rc = gethostname(&buf[12], HOST_NAME_MAX+1);
	if (rc != 0) {
		DBG_ERR("gethostname failed\n");
		return UINT64_MAX;
	}

	id = fileid_uint64_hash((uint8_t *)buf, ARRAY_SIZE(buf));

	return id;
}

/* device mapping functions using a fsid */
static uint64_t fileid_device_mapping_fsid(struct fileid_handle_data *data,
					   const SMB_STRUCT_STAT *sbuf)
{
	struct fileid_mount_entry *m;

	m = fileid_find_mount_entry(data, sbuf->st_ex_dev);
	if (!m) return sbuf->st_ex_dev;

	if (m->devid == (uint64_t)-1) {
		if (sizeof(fsid_t) > sizeof(uint64_t)) {
			m->devid = fileid_uint64_hash((uint8_t *)&m->fsid,
						      sizeof(m->fsid));
		} else {
			union {
				uint64_t ret;
				fsid_t fsid;
			} u;
			ZERO_STRUCT(u);
			u.fsid = m->fsid;
			m->devid = u.ret;
		}
	}

	return m->devid;
}

static struct file_id fileid_mapping_fsid(struct fileid_handle_data *data,
					  const SMB_STRUCT_STAT *sbuf)
{
	struct file_id id = { .inode = sbuf->st_ex_ino, };

	id.devid = fileid_device_mapping_fsid(data, sbuf);

	return id;
}

static struct file_id fileid_mapping_next_module(struct fileid_handle_data *data,
						 const SMB_STRUCT_STAT *sbuf)
{
	return SMB_VFS_NEXT_FILE_ID_CREATE(data->handle, sbuf);
}

static int get_connectpath_ino(struct vfs_handle_struct *handle,
			       const char *path,
			       SMB_STRUCT_STAT *psbuf)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct smb_filename *fname = NULL;
	const char *fullpath = NULL;
	int ret;

	if (path[0] == '/') {
		fullpath = path;
	} else {
		fullpath = talloc_asprintf(frame,
					   "%s/%s",
					   handle->conn->connectpath,
					   path);
		if (fullpath == NULL) {
			DBG_ERR("talloc_asprintf() failed\n");
			TALLOC_FREE(frame);
			return -1;
		}
	}

	fname = synthetic_smb_fname(frame,
				    fullpath,
				    NULL,
				    NULL,
				    0,
				    0);
	if (fname == NULL) {
		DBG_ERR("synthetic_smb_fname(%s) failed - %s\n",
			fullpath, strerror(errno));
		TALLOC_FREE(frame);
		return -1;
	}

	ret = SMB_VFS_NEXT_STAT(handle, fname);
	if (ret != 0) {
		DBG_ERR("stat failed for %s with %s\n",
			fullpath, strerror(errno));
		TALLOC_FREE(frame);
		return -1;
	}
	*psbuf = fname->st;

	TALLOC_FREE(frame);

	return 0;
}

static int fileid_connect(struct vfs_handle_struct *handle,
			  const char *service, const char *user)
{
	struct fileid_handle_data *data;
	const char *algorithm;
	const char **fstype_deny_list = NULL;
	const char **fstype_allow_list = NULL;
	const char **mntdir_deny_list = NULL;
	const char **mntdir_allow_list = NULL;
	ino_t nolockinode;
	uint64_t max_slots = 0;
	bool rootdir_nolock = false;
	const char **nolock_paths = NULL;
	size_t i;
	int saved_errno;
	int ret = SMB_VFS_NEXT_CONNECT(handle, service, user);

	if (ret < 0) {
		return ret;
	}

	data = talloc_zero(handle, struct fileid_handle_data);
	if (!data) {
		saved_errno = errno;
		SMB_VFS_NEXT_DISCONNECT(handle);
		DEBUG(0, ("talloc_zero() failed\n"));
		errno = saved_errno;
		return -1;
	}
	data->handle = handle;

	/*
	 * "fileid:mapping" is only here as fallback for old setups
	 * "fileid:algorithm" is the option new setups should use
	 */
	algorithm = lp_parm_const_string(SNUM(handle->conn),
					 "fileid", "mapping",
					 "fsname");
	algorithm = lp_parm_const_string(SNUM(handle->conn),
					 "fileid", "algorithm",
					 algorithm);
	if (strcmp("fsname", algorithm) == 0) {
		data->mapping_fn = fileid_mapping_fsname;
	} else if (strcmp("fsname_nodirs", algorithm) == 0) {
		data->mapping_fn = fileid_mapping_fsname;
		data->nolock.force_all_dirs = true;
	} else if (strcmp("fsid", algorithm) == 0) {
		data->mapping_fn = fileid_mapping_fsid;
	} else if (strcmp("hostname", algorithm) == 0) {
		data->mapping_fn = fileid_mapping_hostname;
		data->nolock.force_all_inodes = true;
	} else if (strcmp("fsname_norootdir", algorithm) == 0) {
		data->mapping_fn = fileid_mapping_fsname;
		rootdir_nolock = true;
	} else if (strcmp("fsname_norootdir_ext", algorithm) == 0) {
		data->mapping_fn = fileid_mapping_fsname;
		rootdir_nolock = true;
		max_slots = UINT64_MAX;
	} else if (strcmp("next_module", algorithm) == 0) {
		data->mapping_fn	= fileid_mapping_next_module;
	} else {
		SMB_VFS_NEXT_DISCONNECT(handle);
		DEBUG(0,("fileid_connect(): unknown algorithm[%s]\n", algorithm));
		return -1;
	}

	fstype_deny_list = lp_parm_string_list(SNUM(handle->conn), "fileid",
					       "fstype deny", NULL);
	if (fstype_deny_list != NULL) {
		data->fstype_deny_list = str_list_copy(data, fstype_deny_list);
		if (data->fstype_deny_list == NULL) {
			saved_errno = errno;
			DBG_ERR("str_list_copy failed\n");
			SMB_VFS_NEXT_DISCONNECT(handle);
			errno = saved_errno;
			return -1;
		}
	}

	fstype_allow_list = lp_parm_string_list(SNUM(handle->conn), "fileid",
						"fstype allow", NULL);
	if (fstype_allow_list != NULL) {
		data->fstype_allow_list = str_list_copy(data, fstype_allow_list);
		if (data->fstype_allow_list == NULL) {
			saved_errno = errno;
			DBG_ERR("str_list_copy failed\n");
			SMB_VFS_NEXT_DISCONNECT(handle);
			errno = saved_errno;
			return -1;
		}
	}

	mntdir_deny_list = lp_parm_string_list(SNUM(handle->conn), "fileid",
					       "mntdir deny", NULL);
	if (mntdir_deny_list != NULL) {
		data->mntdir_deny_list = str_list_copy(data, mntdir_deny_list);
		if (data->mntdir_deny_list == NULL) {
			saved_errno = errno;
			DBG_ERR("str_list_copy failed\n");
			SMB_VFS_NEXT_DISCONNECT(handle);
			errno = saved_errno;
			return -1;
		}
	}

	mntdir_allow_list = lp_parm_string_list(SNUM(handle->conn), "fileid",
						"mntdir allow", NULL);
	if (mntdir_allow_list != NULL) {
		data->mntdir_allow_list = str_list_copy(data, mntdir_allow_list);
		if (data->mntdir_allow_list == NULL) {
			saved_errno = errno;
			DBG_ERR("str_list_copy failed\n");
			SMB_VFS_NEXT_DISCONNECT(handle);
			errno = saved_errno;
			return -1;
		}
	}

	data->nolock.force_all_inodes = lp_parm_bool(SNUM(handle->conn),
						     "fileid", "nolock_all_inodes",
						     data->nolock.force_all_inodes);
	data->nolock.force_all_dirs = lp_parm_bool(SNUM(handle->conn),
						   "fileid", "nolock_all_dirs",
						   data->nolock.force_all_dirs);

	max_slots = lp_parm_ulonglong(SNUM(handle->conn),
				      "fileid", "nolock_max_slots",
				      max_slots);
	max_slots = MAX(max_slots, 1);

	data->nolock.extid = fileid_mapping_nolock_extid(max_slots);

	nolockinode = lp_parm_ulong(SNUM(handle->conn), "fileid", "nolockinode", 0);
	if (nolockinode != 0) {
		SMB_STRUCT_STAT tmpsbuf = { .st_ex_ino = nolockinode, };

		ret = fileid_add_nolock_inode(data, &tmpsbuf);
		if (ret != 0) {
			saved_errno = errno;
			SMB_VFS_NEXT_DISCONNECT(handle);
			errno = saved_errno;
			return -1;
		}
	}

	if (rootdir_nolock) {
		SMB_STRUCT_STAT rootdirsbuf;

		ret = get_connectpath_ino(handle, ".", &rootdirsbuf);
		if (ret != 0) {
			saved_errno = errno;
			SMB_VFS_NEXT_DISCONNECT(handle);
			errno = saved_errno;
			return -1;
		}

		ret = fileid_add_nolock_inode(data, &rootdirsbuf);
		if (ret != 0) {
			saved_errno = errno;
			SMB_VFS_NEXT_DISCONNECT(handle);
			errno = saved_errno;
			return -1;
		}
	}

	nolock_paths = lp_parm_string_list(SNUM(handle->conn), "fileid", "nolock_paths", NULL);
	for (i = 0; nolock_paths != NULL && nolock_paths[i] != NULL; i++) {
		SMB_STRUCT_STAT tmpsbuf;

		ret = get_connectpath_ino(handle, nolock_paths[i], &tmpsbuf);
		if (ret == -1 && errno == ENOENT) {
			DBG_ERR("ignoring non existing nolock_paths[%zu]='%s'\n",
				i, nolock_paths[i]);
			continue;
		}
		if (ret != 0) {
			saved_errno = errno;
			SMB_VFS_NEXT_DISCONNECT(handle);
			errno = saved_errno;
			return -1;
		}

		ret = fileid_add_nolock_inode(data, &tmpsbuf);
		if (ret != 0) {
			saved_errno = errno;
			SMB_VFS_NEXT_DISCONNECT(handle);
			errno = saved_errno;
			return -1;
		}
		DBG_DEBUG("Adding nolock_paths[%zu]='%s'\n",
			  i, nolock_paths[i]);
	}

	SMB_VFS_HANDLE_SET_DATA(handle, data, NULL,
				struct fileid_handle_data,
				return -1);

	DBG_DEBUG("connect to service[%s] with algorithm[%s] nolock.inodes %zu\n",
		  service, algorithm, data->nolock.num_inodes);

	return 0;
}

static void fileid_disconnect(struct vfs_handle_struct *handle)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();

	DEBUG(10,("fileid_disconnect() connect to service[%s].\n",
		  lp_servicename(talloc_tos(), lp_sub, SNUM(handle->conn))));

	SMB_VFS_NEXT_DISCONNECT(handle);
}

static struct file_id fileid_file_id_create(struct vfs_handle_struct *handle,
					    const SMB_STRUCT_STAT *sbuf)
{
	struct fileid_handle_data *data;
	struct file_id id = { .inode = 0, };

	SMB_VFS_HANDLE_GET_DATA(handle, data,
				struct fileid_handle_data,
				return id);

	id = data->mapping_fn(data, sbuf);
	if (id.extid == 0 && fileid_is_nolock_inode(data, sbuf)) {
		id.extid = data->nolock.extid;
	}

	DBG_DEBUG("Returning dev [%jx] inode [%jx] extid [%jx]\n",
		  (uintmax_t)id.devid, (uintmax_t)id.inode, (uintmax_t)id.extid);

	return id;
}

static struct vfs_fn_pointers vfs_fileid_fns = {
	.connect_fn = fileid_connect,
	.disconnect_fn = fileid_disconnect,
	.file_id_create_fn = fileid_file_id_create
};

static_decl_vfs;
NTSTATUS vfs_fileid_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;

	ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "fileid",
			       &vfs_fileid_fns);
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	vfs_fileid_debug_level = debug_add_class("fileid");
	if (vfs_fileid_debug_level == -1) {
		vfs_fileid_debug_level = DBGC_VFS;
		DEBUG(0, ("vfs_fileid: Couldn't register custom debugging class!\n"));
	} else {
		DEBUG(10, ("vfs_fileid: Debug class number of 'fileid': %d\n", vfs_fileid_debug_level));
	}

	return ret;
}
