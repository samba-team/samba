/*
 * Module for snapshot management using shell callouts
 *
 * Copyright (C) David Disseldorp 2013-2015
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
#include "include/ntioctl.h"
#include "system/filesys.h"
#include "smbd/smbd.h"

/*
 * Check whether a path can be shadow copied. Return the base volume, allowing
 * the caller to determine if multiple paths lie on the same base volume.
 */
static NTSTATUS shell_snap_check_path(struct vfs_handle_struct *handle,
				      TALLOC_CTX *mem_ctx,
				      const char *service_path,
				      char **base_volume)
{
	NTSTATUS status;
	const char *cmd;
	char *cmd_run;
	int ret;
	TALLOC_CTX *tmp_ctx;

	cmd = lp_parm_const_string(handle->conn->params->service,
				   "shell_snap", "check path command", "");
	if ((cmd == NULL) || (strlen(cmd) == 0)) {
		DEBUG(0,
		      ("\"shell_snap:check path command\" not configured\n"));
		status = NT_STATUS_NOT_SUPPORTED;
		goto err_out;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_out;
	}

	/* add service path argument */
	cmd_run = talloc_asprintf(tmp_ctx, "%s %s", cmd, service_path);
	if (cmd_run == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_tmp_free;
	}

	ret = smbrun(cmd_run, NULL, NULL);
	if (ret != 0) {
		DEBUG(0, ("%s failed with %d\n", cmd_run, ret));
		status = NT_STATUS_NOT_SUPPORTED;
		goto err_tmp_free;
	}

	/* assume the service path is the base volume */
	*base_volume = talloc_strdup(mem_ctx, service_path);
	if (*base_volume == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_tmp_free;
	}
	status = NT_STATUS_OK;
err_tmp_free:
	talloc_free(tmp_ctx);
err_out:
	return status;
}

static NTSTATUS shell_snap_create(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  const char *base_volume,
				  time_t *tstamp,
				  bool rw,
				  char **base_path,
				  char **snap_path)
{
	const char *cmd;
	char *cmd_run;
	char **qlines;
	int numlines, ret;
	int fd = -1;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;

	cmd = lp_parm_const_string(handle->conn->params->service,
				   "shell_snap", "create command", "");
	if ((cmd == NULL) || (strlen(cmd) == 0)) {
		DEBUG(1, ("\"shell_snap:create command\" not configured\n"));
		status = NT_STATUS_NOT_SUPPORTED;
		goto err_out;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_out;
	}

	/* add base vol argument */
	cmd_run = talloc_asprintf(tmp_ctx, "%s %s", cmd, base_volume);
	if (cmd_run == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_tmp_free;
	}

	ret = smbrun(cmd_run, &fd, NULL);
	talloc_free(cmd_run);
	if (ret != 0) {
		if (fd != -1) {
			close(fd);
		}
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_tmp_free;
	}

	numlines = 0;
	qlines = fd_lines_load(fd, &numlines, PATH_MAX + 1, tmp_ctx);
	close(fd);

	/* script must return the snapshot path as a single line */
	if ((numlines == 0) || (qlines == NULL) || (qlines[0] == NULL)) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_tmp_free;
	}

	*base_path = talloc_strdup(mem_ctx, base_volume);
	if (*base_path == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_tmp_free;
	}
	*snap_path = talloc_strdup(mem_ctx, qlines[0]);
	if (*snap_path == NULL) {
		status = NT_STATUS_NO_MEMORY;
		talloc_free(*base_path);
		goto err_tmp_free;
	}

	status = NT_STATUS_OK;
err_tmp_free:
	talloc_free(tmp_ctx);
err_out:
	return status;
}

static NTSTATUS shell_snap_delete(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  char *base_path,
				  char *snap_path)
{
	const char *cmd;
	char *cmd_run;
	int ret;

	cmd = lp_parm_const_string(handle->conn->params->service,
				   "shell_snap", "delete command", "");
	if ((cmd == NULL) || (strlen(cmd) == 0)) {
		DEBUG(1, ("\"shell_snap:delete command\" not configured\n"));
		return NT_STATUS_NOT_SUPPORTED;
	}

	/* add base path and snap path arguments */
	cmd_run = talloc_asprintf(mem_ctx, "%s %s %s",
				  cmd, base_path, snap_path);
	if (cmd_run == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = smbrun(cmd_run, NULL, NULL);
	talloc_free(cmd_run);
	if (ret != 0) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

static struct vfs_fn_pointers shell_snap_fns = {
	.snap_check_path_fn = shell_snap_check_path,
	.snap_create_fn = shell_snap_create,
	.snap_delete_fn = shell_snap_delete,
};

static_decl_vfs;
NTSTATUS vfs_shell_snap_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"shell_snap", &shell_snap_fns);
}
