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

struct fileid_handle_data {
	uint64_t (*device_mapping_fn)(struct fileid_handle_data *data,
				      const SMB_STRUCT_STAT *sbuf);
	uint64_t (*extid_mapping_fn)(struct fileid_handle_data *data,
				      const SMB_STRUCT_STAT *sbuf);
	char **fstype_deny_list;
	char **fstype_allow_list;
	char **mntdir_deny_list;
	char **mntdir_allow_list;
	unsigned num_mount_entries;
	struct fileid_mount_entry *mount_entries;
	ino_t nolockinode;
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

/* a device mapping using a fsname for files and hostname for dirs */
static uint64_t fileid_device_mapping_fsname_nodirs(
	struct fileid_handle_data *data,
	const SMB_STRUCT_STAT *sbuf)
{
	if (S_ISDIR(sbuf->st_ex_mode)) {
		return fileid_device_mapping_hostname(data, sbuf);
	}

	return fileid_device_mapping_fsname(data, sbuf);
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

static uint64_t fileid_extid_mapping_zero(struct fileid_handle_data *data,
					  const SMB_STRUCT_STAT *sbuf)
{
	return 0;
}

static uint64_t fileid_extid_mapping_pid(struct fileid_handle_data *data,
					 const SMB_STRUCT_STAT *sbuf)
{
	return getpid();
}

static int get_connectpath_ino(struct vfs_handle_struct *handle,
			       ino_t *ino)
{
	struct smb_filename *fname = NULL;
	int ret;

	fname = synthetic_smb_fname(talloc_tos(),
				    handle->conn->connectpath,
				    NULL,
				    NULL,
				    0,
				    0);
	if (fname == NULL) {
		DBG_ERR("synthetic_smb_fname failed\n");
		return -1;
	}

	ret = SMB_VFS_NEXT_STAT(handle, fname);
	if (ret != 0) {
		DBG_ERR("stat failed for %s with %s\n",
			handle->conn->connectpath, strerror(errno));
		TALLOC_FREE(fname);
		return -1;
	}
	*ino = fname->st.st_ex_ino;
	TALLOC_FREE(fname);

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
	int saved_errno;
	int ret = SMB_VFS_NEXT_CONNECT(handle, service, user);

	if (ret < 0) {
		return ret;
	}

	data = talloc_zero(handle->conn, struct fileid_handle_data);
	if (!data) {
		saved_errno = errno;
		SMB_VFS_NEXT_DISCONNECT(handle);
		DEBUG(0, ("talloc_zero() failed\n"));
		errno = saved_errno;
		return -1;
	}

	data->nolockinode = 0;

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
		data->device_mapping_fn	= fileid_device_mapping_fsname;
		data->extid_mapping_fn = fileid_extid_mapping_zero;
	} else if (strcmp("fsname_nodirs", algorithm) == 0) {
		data->device_mapping_fn = fileid_device_mapping_fsname_nodirs;
		data->extid_mapping_fn = fileid_extid_mapping_zero;
	} else if (strcmp("fsid", algorithm) == 0) {
		data->device_mapping_fn	= fileid_device_mapping_fsid;
		data->extid_mapping_fn = fileid_extid_mapping_zero;
	} else if (strcmp("hostname", algorithm) == 0) {
		data->device_mapping_fn = fileid_device_mapping_hostname;
		data->extid_mapping_fn = fileid_extid_mapping_zero;
	} else if (strcmp("fsname_norootdir", algorithm) == 0) {
		data->device_mapping_fn	= fileid_device_mapping_fsname;
		data->extid_mapping_fn = fileid_extid_mapping_zero;

		ret = get_connectpath_ino(handle, &data->nolockinode);
		if (ret != 0) {
			saved_errno = errno;
			SMB_VFS_NEXT_DISCONNECT(handle);
			errno = saved_errno;
			return -1;
		}
	} else if (strcmp("fsname_norootdir_ext", algorithm) == 0) {
		data->device_mapping_fn	= fileid_device_mapping_fsname;
		data->extid_mapping_fn = fileid_extid_mapping_pid;

		ret = get_connectpath_ino(handle, &data->nolockinode);
		if (ret != 0) {
			saved_errno = errno;
			SMB_VFS_NEXT_DISCONNECT(handle);
			errno = saved_errno;
			return -1;
		}
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

	data->nolockinode = lp_parm_ulong(SNUM(handle->conn), "fileid",
					  "nolockinode", data->nolockinode);

	SMB_VFS_HANDLE_SET_DATA(handle, data, NULL,
				struct fileid_handle_data,
				return -1);

	DBG_DEBUG("connect to service[%s] with algorithm[%s] nolockinode %lli\n",
		  service, algorithm, (long long) data->nolockinode);

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
	struct file_id id;
	uint64_t devid;

	ZERO_STRUCT(id);

	SMB_VFS_HANDLE_GET_DATA(handle, data,
				struct fileid_handle_data,
				return id);

	if ((data->nolockinode != 0) &&
	    (sbuf->st_ex_ino == data->nolockinode)) {
		devid = fileid_device_mapping_hostname(data, sbuf);
		id.extid = data->extid_mapping_fn(data, sbuf);
	} else {
		devid = data->device_mapping_fn(data, sbuf);
	}

	id.inode	= sbuf->st_ex_ino;
	id.devid        = devid;

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
