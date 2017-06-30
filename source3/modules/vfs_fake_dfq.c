/*
 * Fake Disk-Free and Quota VFS module.  Implements passthrough operation
 * of all VFS calls, except for "disk free" and "get quota" which
 * are handled by reading a text file named ".dfq" in the current directory.
 *
 * This module is intended for testing purposes.
 *
 * Copyright (C) Uri Simchoni, 2016
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

static int dfq_get_quota(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			enum SMB_QUOTA_TYPE qtype,
			unid_t id,
			SMB_DISK_QUOTA *qt);

static uint64_t dfq_load_param(int snum, const char *path, const char *section,
			       const char *param, uint64_t def_val)
{
	uint64_t ret;

	char *option =
	    talloc_asprintf(talloc_tos(), "%s/%s/%s", section, param, path);
	if (option == NULL) {
		return def_val;
	}

	ret = (uint64_t)lp_parm_ulonglong(snum, "fake_dfq", option,
					  (unsigned long long)def_val);

	TALLOC_FREE(option);

	return ret;
}

static uint64_t dfq_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	uint64_t free_1k;
	int snum = SNUM(handle->conn);
	uint64_t dfq_bsize = 0;
	struct smb_filename *rpath_fname = NULL;

	/* look up the params based on real path to be resilient
	 * to refactoring of path<->realpath
	 */
	rpath_fname = SMB_VFS_NEXT_REALPATH(handle, talloc_tos(), smb_fname);
	if (rpath_fname != NULL) {
		dfq_bsize = dfq_load_param(snum, rpath_fname->base_name,
				"df", "block size", 0);
	}
	if (dfq_bsize == 0) {
		TALLOC_FREE(rpath_fname);
		return SMB_VFS_NEXT_DISK_FREE(handle, smb_fname, bsize, dfree,
					      dsize);
	}

	*bsize = dfq_bsize;
	*dfree = dfq_load_param(snum, rpath_fname->base_name,
				"df", "disk free", 0);
	*dsize = dfq_load_param(snum, rpath_fname->base_name,
				"df", "disk size", 0);

	if ((*bsize) < 1024) {
		free_1k = (*dfree) / (1024 / (*bsize));
	} else {
		free_1k = ((*bsize) / 1024) * (*dfree);
	}

	TALLOC_FREE(rpath_fname);
	return free_1k;
}

static int dfq_get_quota(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			enum SMB_QUOTA_TYPE qtype,
			unid_t id,
			SMB_DISK_QUOTA *qt)
{
	int rc = 0;
	int save_errno;
	char *section = NULL;
	int snum = SNUM(handle->conn);
	uint64_t bsize = 0;
	struct smb_filename *rpath_fname = NULL;

	rpath_fname = SMB_VFS_NEXT_REALPATH(handle, talloc_tos(), smb_fname);
	if (rpath_fname == NULL) {
		goto dflt;
	}

	switch (qtype) {
	case SMB_USER_QUOTA_TYPE:
		section = talloc_asprintf(talloc_tos(), "u%llu",
					  (unsigned long long)id.uid);
		break;
	case SMB_GROUP_QUOTA_TYPE:
		section = talloc_asprintf(talloc_tos(), "g%llu",
					  (unsigned long long)id.gid);
		break;
	case SMB_USER_FS_QUOTA_TYPE:
		section = talloc_strdup(talloc_tos(), "udflt");
		break;
	case SMB_GROUP_FS_QUOTA_TYPE:
		section = talloc_strdup(talloc_tos(), "gdflt");
		break;
	default:
		break;
	}

	if (section == NULL) {
		goto dflt;
	}

	bsize = dfq_load_param(snum, rpath_fname->base_name,
				section, "block size", 4096);
	if (bsize == 0) {
		goto dflt;
	}

	if (dfq_load_param(snum, rpath_fname->base_name,
				section, "err", 0) != 0) {
		errno = ENOTSUP;
		rc = -1;
		goto out;
	}

	if (dfq_load_param(snum, rpath_fname->base_name,
				section, "nosys", 0) != 0) {
		errno = ENOSYS;
		rc = -1;
		goto out;
	}

	ZERO_STRUCTP(qt);

	qt->bsize = bsize;
	qt->hardlimit = dfq_load_param(snum, rpath_fname->base_name,
				section, "hard limit", 0);
	qt->softlimit = dfq_load_param(snum, rpath_fname->base_name,
				section, "soft limit", 0);
	qt->curblocks = dfq_load_param(snum, rpath_fname->base_name,
				section, "cur blocks", 0);
	qt->ihardlimit =
	    dfq_load_param(snum, rpath_fname->base_name,
				section, "inode hard limit", 0);
	qt->isoftlimit =
	    dfq_load_param(snum, rpath_fname->base_name,
				section, "inode soft limit", 0);
	qt->curinodes = dfq_load_param(snum, rpath_fname->base_name,
				section, "cur inodes", 0);
	qt->qflags = dfq_load_param(snum, rpath_fname->base_name,
				section, "qflags", QUOTAS_DENY_DISK);

	goto out;

dflt:
	rc = SMB_VFS_NEXT_GET_QUOTA(handle, smb_fname, qtype, id, qt);

out:
	save_errno = errno;
	TALLOC_FREE(section);
	TALLOC_FREE(rpath_fname);
	errno = save_errno;
	return rc;
}

struct vfs_fn_pointers vfs_fake_dfq_fns = {
    /* Disk operations */

    .disk_free_fn = dfq_disk_free,
    .get_quota_fn = dfq_get_quota,
};

static_decl_vfs;
NTSTATUS vfs_fake_dfq_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "fake_dfq",
				&vfs_fake_dfq_fns);
}
