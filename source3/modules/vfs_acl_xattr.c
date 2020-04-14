/*
 * Store Windows ACLs in xattrs.
 *
 * Copyright (C) Volker Lendecke, 2008
 * Copyright (C) Jeremy Allison, 2008
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
#include "librpc/gen_ndr/xattr.h"
#include "auth.h"
#include "vfs_acl_common.h"

/* Pull in the common functions. */
#define ACL_MODULE_NAME "acl_xattr"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

/*******************************************************************
 Pull a security descriptor into a DATA_BLOB from a xattr.
*******************************************************************/

static ssize_t getxattr_do(vfs_handle_struct *handle,
			   files_struct *fsp,
			   const struct smb_filename *smb_fname,
			   const char *xattr_name,
			   uint8_t *val,
			   size_t size)
{
	ssize_t sizeret;
	int saved_errno = 0;

	become_root();
	if (fsp && fsp->fh->fd != -1) {
		sizeret = SMB_VFS_FGETXATTR(fsp, xattr_name, val, size);
	} else {
		sizeret = SMB_VFS_GETXATTR(handle->conn, smb_fname,
					   XATTR_NTACL_NAME, val, size);
	}
	if (sizeret == -1) {
		saved_errno = errno;
	}
	unbecome_root();

	if (saved_errno != 0) {
		errno = saved_errno;
	}

	return sizeret;
}

static NTSTATUS fget_acl_blob(TALLOC_CTX *ctx,
			vfs_handle_struct *handle,
			files_struct *fsp,
			DATA_BLOB *pblob)
{
	size_t size = 4096;
	uint8_t *val = NULL;
	uint8_t *tmp;
	ssize_t sizeret;

	ZERO_STRUCTP(pblob);

  again:

	tmp = talloc_realloc(ctx, val, uint8_t, size);
	if (tmp == NULL) {
		TALLOC_FREE(val);
		return NT_STATUS_NO_MEMORY;
	}
	val = tmp;

	sizeret =
	    getxattr_do(handle, fsp, NULL, XATTR_NTACL_NAME, val, size);

	if (sizeret >= 0) {
		pblob->data = val;
		pblob->length = sizeret;
		return NT_STATUS_OK;
	}

	if (errno != ERANGE) {
		goto err;
	}

	/* Too small, try again. */
	sizeret =
	    getxattr_do(handle, fsp, NULL, XATTR_NTACL_NAME, NULL, 0);
	if (sizeret < 0) {
		goto err;
	}

	if (size < sizeret) {
		size = sizeret;
	}

	if (size > 65536) {
		/* Max ACL size is 65536 bytes. */
		errno = ERANGE;
		goto err;
	}

	goto again;
  err:
	/* Real error - exit here. */
	TALLOC_FREE(val);
	return map_nt_error_from_unix(errno);
}

static NTSTATUS get_acl_blob_at(TALLOC_CTX *ctx,
			vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			DATA_BLOB *pblob)
{
	size_t size = 4096;
	uint8_t *val = NULL;
	uint8_t *tmp;
	ssize_t sizeret;

	ZERO_STRUCTP(pblob);

  again:

	tmp = talloc_realloc(ctx, val, uint8_t, size);
	if (tmp == NULL) {
		TALLOC_FREE(val);
		return NT_STATUS_NO_MEMORY;
	}
	val = tmp;

	sizeret =
	    getxattr_do(handle, NULL, smb_fname, XATTR_NTACL_NAME, val, size);

	if (sizeret >= 0) {
		pblob->data = val;
		pblob->length = sizeret;
		return NT_STATUS_OK;
	}

	if (errno != ERANGE) {
		goto err;
	}

	/* Too small, try again. */
	sizeret =
	    getxattr_do(handle, NULL, smb_fname, XATTR_NTACL_NAME, NULL, 0);
	if (sizeret < 0) {
		goto err;
	}

	if (size < sizeret) {
		size = sizeret;
	}

	if (size > 65536) {
		/* Max ACL size is 65536 bytes. */
		errno = ERANGE;
		goto err;
	}

	goto again;
  err:
	/* Real error - exit here. */
	TALLOC_FREE(val);
	return map_nt_error_from_unix(errno);
}

/*******************************************************************
 Store a DATA_BLOB into an xattr given an fsp pointer.
*******************************************************************/

static NTSTATUS store_acl_blob_fsp(vfs_handle_struct *handle,
				files_struct *fsp,
				DATA_BLOB *pblob)
{
	int ret;
	int saved_errno = 0;

	DEBUG(10,("store_acl_blob_fsp: storing blob length %u on file %s\n",
		  (unsigned int)pblob->length, fsp_str_dbg(fsp)));

	become_root();
	if (fsp->fh->fd != -1) {
		ret = SMB_VFS_FSETXATTR(fsp, XATTR_NTACL_NAME,
			pblob->data, pblob->length, 0);
	} else {
		ret = SMB_VFS_SETXATTR(fsp->conn, fsp->fsp_name,
				XATTR_NTACL_NAME,
				pblob->data, pblob->length, 0);
	}
	if (ret) {
		saved_errno = errno;
	}
	unbecome_root();
	if (ret) {
		DEBUG(5, ("store_acl_blob_fsp: setting attr failed for file %s"
			"with error %s\n",
			fsp_str_dbg(fsp),
			strerror(saved_errno) ));
		errno = saved_errno;
		return map_nt_error_from_unix(saved_errno);
	}
	return NT_STATUS_OK;
}

/*********************************************************************
 Remove a Windows ACL - we're setting the underlying POSIX ACL.
*********************************************************************/

static int sys_acl_set_file_xattr(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T type,
				SMB_ACL_T theacl)
{
	int ret = SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle,
						smb_fname,
						type,
						theacl);
	if (ret == -1) {
		return -1;
	}

	become_root();
	SMB_VFS_REMOVEXATTR(handle->conn, smb_fname,
			XATTR_NTACL_NAME);
	unbecome_root();

	return ret;
}

/*********************************************************************
 Remove a Windows ACL - we're setting the underlying POSIX ACL.
*********************************************************************/

static int sys_acl_set_fd_xattr(vfs_handle_struct *handle,
                            files_struct *fsp,
                            SMB_ACL_T theacl)
{
	int ret = SMB_VFS_NEXT_SYS_ACL_SET_FD(handle,
						fsp,
						theacl);
	if (ret == -1) {
		return -1;
	}

	become_root();
	SMB_VFS_FREMOVEXATTR(fsp, XATTR_NTACL_NAME);
	unbecome_root();

	return ret;
}

static int connect_acl_xattr(struct vfs_handle_struct *handle,
				const char *service,
				const char *user)
{
	int ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	bool ok;
	struct acl_common_config *config = NULL;

	if (ret < 0) {
		return ret;
	}

	ok = init_acl_common_config(handle, ACL_MODULE_NAME);
	if (!ok) {
		DBG_ERR("init_acl_common_config failed\n");
		return -1;
	}

	/* Ensure we have the parameters correct if we're
	 * using this module. */
	DEBUG(2,("connect_acl_xattr: setting 'inherit acls = true' "
		"'dos filemode = true' and "
		"'force unknown acl user = true' for service %s\n",
		service ));

        lp_do_parameter(SNUM(handle->conn), "inherit acls", "true");
        lp_do_parameter(SNUM(handle->conn), "dos filemode", "true");
        lp_do_parameter(SNUM(handle->conn), "force unknown acl user", "true");

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct acl_common_config,
				return -1);

	if (config->ignore_system_acls) {
		mode_t create_mask = lp_create_mask(SNUM(handle->conn));
		char *create_mask_str = NULL;

		if ((create_mask & 0666) != 0666) {
			create_mask |= 0666;
			create_mask_str = talloc_asprintf(handle, "0%o",
							  create_mask);
			if (create_mask_str == NULL) {
				DBG_ERR("talloc_asprintf failed\n");
				return -1;
			}

			DBG_NOTICE("setting 'create mask = %s'\n", create_mask_str);

			lp_do_parameter (SNUM(handle->conn),
					"create mask", create_mask_str);

			TALLOC_FREE(create_mask_str);
		}

		DBG_NOTICE("setting 'directory mask = 0777', "
			   "'store dos attributes = yes' and all "
			   "'map ...' options to 'no'\n");

		lp_do_parameter(SNUM(handle->conn), "directory mask", "0777");
		lp_do_parameter(SNUM(handle->conn), "map archive", "no");
		lp_do_parameter(SNUM(handle->conn), "map hidden", "no");
		lp_do_parameter(SNUM(handle->conn), "map readonly", "no");
		lp_do_parameter(SNUM(handle->conn), "map system", "no");
		lp_do_parameter(SNUM(handle->conn), "store dos attributes",
				"yes");
	}

	return 0;
}

static int acl_xattr_unlinkat(vfs_handle_struct *handle,
                        struct files_struct *dirfsp,
                        const struct smb_filename *smb_fname,
                        int flags)
{
	int ret;

	if (flags & AT_REMOVEDIR) {
		ret = rmdir_acl_common(handle,
				dirfsp,
				smb_fname);
	} else {
		ret = unlink_acl_common(handle,
				dirfsp,
				smb_fname,
				flags);
	}
	return ret;
}

static NTSTATUS acl_xattr_fget_nt_acl(vfs_handle_struct *handle,
				      files_struct *fsp,
				      uint32_t security_info,
				      TALLOC_CTX *mem_ctx,
				      struct security_descriptor **ppdesc)
{
	NTSTATUS status;
	status = fget_nt_acl_common(fget_acl_blob, handle, fsp,
				   security_info, mem_ctx, ppdesc);
	return status;
}

static NTSTATUS acl_xattr_get_nt_acl_at(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc)
{
	NTSTATUS status;
	status = get_nt_acl_common_at(get_acl_blob_at,
				handle,
				dirfsp,
				smb_fname,
				security_info,
				mem_ctx,
				ppdesc);
	return status;
}

static NTSTATUS acl_xattr_fset_nt_acl(vfs_handle_struct *handle,
				      files_struct *fsp,
				      uint32_t security_info_sent,
				      const struct security_descriptor *psd)
{
	NTSTATUS status;
	status = fset_nt_acl_common(fget_acl_blob, store_acl_blob_fsp,
				    ACL_MODULE_NAME,
				    handle, fsp, security_info_sent, psd);
	return status;
}

static struct vfs_fn_pointers vfs_acl_xattr_fns = {
	.connect_fn = connect_acl_xattr,
	.unlinkat_fn = acl_xattr_unlinkat,
	.chmod_fn = chmod_acl_module_common,
	.fchmod_fn = fchmod_acl_module_common,
	.fget_nt_acl_fn = acl_xattr_fget_nt_acl,
	.get_nt_acl_at_fn = acl_xattr_get_nt_acl_at,
	.fset_nt_acl_fn = acl_xattr_fset_nt_acl,
	.sys_acl_set_file_fn = sys_acl_set_file_xattr,
	.sys_acl_set_fd_fn = sys_acl_set_fd_xattr
};

static_decl_vfs;
NTSTATUS vfs_acl_xattr_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "acl_xattr",
				&vfs_acl_xattr_fns);
}
