/*
   Unix SMB/CIFS implementation.

   Copyright (c) 2019 Guenther Deschner <gd@samba.org>

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
#include "smbd/smbd.h"
#include "system/filesys.h"

#define GLUSTER_NAME_MAX 255

static int vfs_gluster_fuse_get_real_filename(struct vfs_handle_struct *handle,
					      const struct smb_filename *path,
					      const char *name,
					      TALLOC_CTX *mem_ctx,
					      char **_found_name)
{
	int ret;
	char key_buf[GLUSTER_NAME_MAX + 64];
	char val_buf[GLUSTER_NAME_MAX + 1];
	char *found_name = NULL;

	if (strlen(name) >= GLUSTER_NAME_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}

	snprintf(key_buf, GLUSTER_NAME_MAX + 64,
		 "glusterfs.get_real_filename:%s", name);

	ret = getxattr(path->base_name, key_buf, val_buf, GLUSTER_NAME_MAX + 1);
	if (ret == -1) {
		if (errno == ENOATTR) {
			errno = ENOENT;
		}
		return -1;
	}

	found_name = talloc_strdup(mem_ctx, val_buf);
	if (found_name == NULL) {
		errno = ENOMEM;
		return -1;
	}
	*_found_name = found_name;
	return 0;
}

struct device_mapping_entry {
	SMB_DEV_T device;       /* the local device, for reference */
	uint64_t mapped_device; /* the mapped device */
};

struct vfs_glusterfs_fuse_handle_data {
	unsigned num_mapped_devices;
	struct device_mapping_entry *mapped_devices;
};

/* a 64 bit hash, based on the one in tdb, copied from vfs_fileied */
static uint64_t vfs_glusterfs_fuse_uint64_hash(const uint8_t *s, size_t len)
{
	uint64_t value; /* Used to compute the hash value.  */
	uint32_t i;     /* Used to cycle through random values. */

	/* Set the initial value from the key size. */
	for (value = 0x238F13AFLL * len, i=0; i < len; i++)
		value = (value + (((uint64_t)s[i]) << (i*5 % 24)));

	return (1103515243LL * value + 12345LL);
}

static void vfs_glusterfs_fuse_load_devices(
		struct vfs_glusterfs_fuse_handle_data *data)
{
	FILE *f;
	struct mntent *m;

	data->num_mapped_devices = 0;
	TALLOC_FREE(data->mapped_devices);

	f = setmntent("/etc/mtab", "r");
	if (!f) {
		return;
	}

	while ((m = getmntent(f))) {
		struct stat st;
		char *p;
		uint64_t mapped_device;

		if (stat(m->mnt_dir, &st) != 0) {
			/* TODO: log? */
			continue;
		}

		/* strip the host part off of the fsname */
		p = strrchr(m->mnt_fsname, ':');
		if (p == NULL) {
			p = m->mnt_fsname;
		} else {
			/* TODO: consider the case of '' ? */
			p++;
		}

		mapped_device = vfs_glusterfs_fuse_uint64_hash(
						(const uint8_t *)p,
						strlen(p));

		data->mapped_devices = talloc_realloc(data,
						data->mapped_devices,
						struct device_mapping_entry,
						data->num_mapped_devices + 1);
		if (data->mapped_devices == NULL) {
			goto nomem;
		}

		data->mapped_devices[data->num_mapped_devices].device =
								st.st_dev;
		data->mapped_devices[data->num_mapped_devices].mapped_device =
								mapped_device;

		data->num_mapped_devices++;
	}

	endmntent(f);
	return;

nomem:
	data->num_mapped_devices = 0;
	TALLOC_FREE(data->mapped_devices);

	endmntent(f);
	return;
}

static int vfs_glusterfs_fuse_map_device_cached(
				struct vfs_glusterfs_fuse_handle_data *data,
				SMB_DEV_T device,
				uint64_t *mapped_device)
{
	unsigned i;

	for (i = 0; i < data->num_mapped_devices; i++) {
		if (data->mapped_devices[i].device == device) {
			*mapped_device = data->mapped_devices[i].mapped_device;
			return 0;
		}
	}

	return -1;
}

static int vfs_glusterfs_fuse_map_device(
				struct vfs_glusterfs_fuse_handle_data *data,
				SMB_DEV_T device,
				uint64_t *mapped_device)
{
	int ret;

	ret = vfs_glusterfs_fuse_map_device_cached(data, device, mapped_device);
	if (ret == 0) {
		return 0;
	}

	vfs_glusterfs_fuse_load_devices(data);

	ret = vfs_glusterfs_fuse_map_device_cached(data, device, mapped_device);

	return ret;
}

static struct file_id vfs_glusterfs_fuse_file_id_create(
			struct vfs_handle_struct *handle,
			const SMB_STRUCT_STAT *sbuf)
{
	struct vfs_glusterfs_fuse_handle_data *data;
	struct file_id id;
	uint64_t mapped_device;
	int ret;

	ZERO_STRUCT(id);

	id = SMB_VFS_NEXT_FILE_ID_CREATE(handle, sbuf);

	SMB_VFS_HANDLE_GET_DATA(handle, data,
				struct vfs_glusterfs_fuse_handle_data,
				return id);

	ret = vfs_glusterfs_fuse_map_device(data, sbuf->st_ex_dev,
					    &mapped_device);
	if (ret == 0) {
		id.devid = mapped_device;
	} else {
		DBG_WARNING("Failed to map device [%jx], falling back to "
			    "standard file_id [%jx]",
			    (uintmax_t)sbuf->st_ex_dev,
			    (uintmax_t)id.devid);
	}

	DBG_DEBUG("Returning dev [%jx] inode [%jx]\n",
		  (uintmax_t)id.devid, (uintmax_t)id.inode);

	return id;
}

static int vfs_glusterfs_fuse_connect(struct vfs_handle_struct *handle,
				      const char *service, const char *user)
{
	struct vfs_glusterfs_fuse_handle_data *data;
	int ret = SMB_VFS_NEXT_CONNECT(handle, service, user);

	if (ret < 0) {
		return ret;
	}

	data = talloc_zero(handle->conn, struct vfs_glusterfs_fuse_handle_data);
	if (data == NULL) {
		DBG_ERR("talloc_zero() failed.\n");
		SMB_VFS_NEXT_DISCONNECT(handle);
		return -1;
	}

	/*
	 * Fill the cache in the tree connect, so that the first file/dir access
	 * has chances of being fast...
	 */
	vfs_glusterfs_fuse_load_devices(data);

	SMB_VFS_HANDLE_SET_DATA(handle, data, NULL,
				struct vfs_glusterfs_fuse_handle_data,
				return -1);

	DBG_DEBUG("vfs_glusterfs_fuse_connect(): connected to service[%s]\n",
		  service);

	return 0;
}

struct vfs_fn_pointers glusterfs_fuse_fns = {

	.connect_fn = vfs_glusterfs_fuse_connect,
	.get_real_filename_fn = vfs_gluster_fuse_get_real_filename,
	.file_id_create_fn = vfs_glusterfs_fuse_file_id_create,
};

static_decl_vfs;
NTSTATUS vfs_glusterfs_fuse_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"glusterfs_fuse", &glusterfs_fuse_fns);
}
