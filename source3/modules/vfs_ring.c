/*
 * VFS module implementing get_real_filename for Scality SOFS
 *
 * Copyright (C) 2016, Jean-Marc Saffroy <jm@scality.com>
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

#define DBG 10

#define GRFN_PREFIX "scal.grfn."
#define GRFN_PREFIX_LEN (sizeof(GRFN_PREFIX)-1)

static int vfs_ring_get_real_filename(struct vfs_handle_struct *handle,
				      const struct smb_filename *dirpath,
				      const char *name,
				      TALLOC_CTX *mem_ctx,
				      char **found_name)
{
	const char *path = dirpath->base_name;
	bool mangled;
	char attr_name [NAME_MAX+1];
	char attr_value[NAME_MAX+1];
	int rc;
	const struct smb_filename *smb_fname = NULL;

	if (!strcmp(path, ""))
		path = ".";

	smb_fname = synthetic_smb_fname(talloc_tos(),
		path,
		NULL,
		NULL,
		dirpath->twrp,
		0);
	if (smb_fname == NULL) {
		errno = ENOMEM;
		return -1;
	}

	DEBUG(DBG, ("vfs_ring_get_real_filename: under \"%s\" lookup \"%s\"\n",
		    path, name));

	mangled = mangle_is_mangled(name, handle->conn->params);
	if (mangled) {
		return SMB_VFS_NEXT_GET_REAL_FILENAME(
			handle, dirpath, name, mem_ctx, found_name);
	}

	if (strlen(name) > NAME_MAX - GRFN_PREFIX_LEN) {
		errno = ENAMETOOLONG;
		return -1;
	}

	strncpy(attr_name, GRFN_PREFIX, sizeof(attr_name));
	strncpy(attr_name + GRFN_PREFIX_LEN, name,
		sizeof(attr_name) - GRFN_PREFIX_LEN);

	rc = SMB_VFS_NEXT_GETXATTR(handle, smb_fname, attr_name,
				   attr_value, sizeof(attr_value));
	if (rc < 0) {
		DEBUG(DBG, ("vfs_ring_get_real_filename: getxattr(\"%s\",\"%s\") -> %s\n",
			    path, name, strerror(errno)));
		if (errno == EOPNOTSUPP)
			return SMB_VFS_NEXT_GET_REAL_FILENAME(
				handle, dirpath, name, mem_ctx, found_name);
		if (errno == ENOATTR)
			errno = ENOENT;
		return -1;
	}

	attr_value[rc] = 0;
	*found_name = talloc_strdup(mem_ctx, attr_value);
	if (*found_name == NULL) {
		errno = ENOMEM;
		return -1;
	}

	DEBUG(DBG, ("vfs_ring_get_real_filename: under \"%s\" found \"%s\" as \"%s\"\n",
		    path, name, *found_name));

	return 0;
}

static struct vfs_fn_pointers vfs_ring_fns = {
	.get_real_filename_fn = vfs_ring_get_real_filename,
};

NTSTATUS vfs_ring_init(TALLOC_CTX *);
NTSTATUS vfs_ring_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;

	ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "ring",
			       &vfs_ring_fns);
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	return ret;
}
