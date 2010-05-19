/*
 *  Unix SMB/CIFS implementation.
 *  Group Policy Object Support
 *  Copyright (C) Wilco Baan Hofman 2008-2010
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "includes.h"
#include "lib/policy/policy.h"
#include "libcli/raw/smb.h"
#include "libcli/libcli.h"
#include "param/param.h"
#include "libcli/resolve/resolve.h"
#include "libcli/raw/libcliraw.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#define GP_MAX_DEPTH 25

struct gp_list_state {
	struct gp_context *gp_ctx;
	uint8_t depth;
	const char *cur_rel_path;
	const char *share_path;
	const char *local_path;
};

static NTSTATUS gp_do_list(const char *, struct gp_list_state *);

/* Create a temporary policy directory */
static const char *gp_tmpdir(TALLOC_CTX *mem_ctx)
{
	const char *gp_dir = talloc_asprintf(mem_ctx, "%s/policy", tmpdir());
	struct stat st;

	if (stat(gp_dir, &st) != 0) {
		mkdir(gp_dir, 0755);
	}

	return gp_dir;
}

/* This function is called by the smbcli_list function */
static void gp_list_helper (struct clilist_file_info *info, const char *mask, void *list_state_ptr)
{
	struct gp_list_state *state = list_state_ptr;
	const char *rel_path, *full_remote_path;
	char *local_rel_path, *full_local_path;
	unsigned int i;
	int fh_remote, fh_local;
	uint8_t *buf;
	size_t nread = 0;
	size_t buf_size = 1024;

	/* Get local path by replacing backslashes with slashes */
	local_rel_path = talloc_strdup(state, state->cur_rel_path);
	for (i = 0; local_rel_path[i] != '\0'; i++) {
		if (local_rel_path[i] == '\\') {
			local_rel_path[i] = '/';
		}
	}
	full_local_path = talloc_asprintf(state, "%s%s/%s", state->local_path, local_rel_path, info->name);

	/* Directory */
	if (info->attrib & FILE_ATTRIBUTE_DIRECTORY) {
		if (state->depth >= GP_MAX_DEPTH)
			return;
		if (strcmp(info->name, ".") == 0 || strcmp(info->name, "..") == 0)
			return;

		mkdir(full_local_path, 0755);

		rel_path = talloc_asprintf(state, "%s\\%s", state->cur_rel_path, info->name);

		/* Recurse into this directory */
		gp_do_list(rel_path, state);
		return;
	}

	full_remote_path = talloc_asprintf(state, "%s%s\\%s", state->share_path, state->cur_rel_path, info->name);

	/* Open the remote file */
	fh_remote = smbcli_open(state->gp_ctx->cli->tree, full_remote_path, O_RDONLY, DENY_NONE);
	if (fh_remote == -1) {
		DEBUG(0, ("Failed to open remote file: %s\n", full_remote_path));
		return;
	}

	/* Open the local file */
	fh_local = open(full_local_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fh_local == -1) {
		DEBUG(0, ("Failed to open local file: %s\n", full_local_path));
		return;
	}

	/* Copy the contents of the file */
	buf = talloc_zero_array(state, uint8_t, buf_size);
	while (1) {
		int n = smbcli_read(state->gp_ctx->cli->tree, fh_remote, buf, nread, buf_size);
		if (n <= 0) {
			break;
		}
		if (write(fh_local, buf, n) != n) {
			DEBUG(0, ("Short write while copying file.\n"));
			return;
		}
		nread += n;
	}
	/* Close the files */
	smbcli_close(state->gp_ctx->cli->tree, fh_remote);
	close(fh_local);

	return;
}

static NTSTATUS gp_do_list (const char *rel_path, struct gp_list_state *state)
{
	uint16_t attributes;
	int success;
	char *mask;
	const char *old_rel_path;

	attributes = FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_DIRECTORY;

	/* Update the relative paths, while buffering the parent */
	old_rel_path = state->cur_rel_path;
	state->cur_rel_path = rel_path;
	state->depth++;

	/* Get the current mask */
	mask = talloc_asprintf(state, "%s%s\\*", state->share_path, rel_path);
	success = smbcli_list(state->gp_ctx->cli->tree, mask, attributes, gp_list_helper, state);
	talloc_free(mask);

	/* Go back to the state of the parent */
	state->cur_rel_path = old_rel_path;
	state->depth--;

	if (!success)
		return NT_STATUS_UNSUCCESSFUL;

	return NT_STATUS_OK;
}

static NTSTATUS gp_cli_connect(struct gp_context *gp_ctx)
{
	struct smbcli_options options;
        struct smbcli_session_options session_options;

	if (gp_ctx->cli != NULL)
		return NT_STATUS_OK;

	gp_ctx->cli = smbcli_state_init(gp_ctx);

	lp_smbcli_options(gp_ctx->lp_ctx, &options);
	lp_smbcli_session_options(gp_ctx->lp_ctx, &session_options);


	return smbcli_full_connection(gp_ctx,
			&gp_ctx->cli,
			gp_ctx->active_dc.name,
			lp_smb_ports(gp_ctx->lp_ctx),
			"sysvol",
			NULL,
			lp_socket_options(gp_ctx->lp_ctx),
			gp_ctx->credentials,
			lp_resolve_context(gp_ctx->lp_ctx),
			gp_ctx->ev_ctx,
			&options,
			&session_options,
			lp_iconv_convenience(gp_ctx->lp_ctx),
			lp_gensec_settings(gp_ctx, gp_ctx->lp_ctx));

	return NT_STATUS_OK;
}

static char * gp_get_share_path(TALLOC_CTX *mem_ctx, const char *file_sys_path)
{
	unsigned int i, bkslash_cnt;

	/* Get the path from the share down (\\..\..\(this\stuff) */
	for (i = 0, bkslash_cnt = 0; file_sys_path[i] != '\0'; i++) {
		if (file_sys_path[i] == '\\')
			bkslash_cnt++;

		if (bkslash_cnt == 4) {
			return talloc_strdup(mem_ctx, &file_sys_path[i]);
		}
	}

	return NULL;
}


NTSTATUS gp_fetch_gpt (struct gp_context *gp_ctx, struct gp_object *gpo, const char **ret_local_path)
{
	TALLOC_CTX *mem_ctx;
	struct gp_list_state *state;
	NTSTATUS status;
	struct stat st;
	int rv;

	/* Create a forked memory context, as a base for everything here */
	mem_ctx = talloc_new(gp_ctx);


	if (gp_ctx->cli == NULL) {
		status = gp_cli_connect(gp_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Failed to create cli connection to DC\n"));
			talloc_free(mem_ctx);
			return status;
		}
	}

	/* Prepare the state structure */
	state = talloc_zero(mem_ctx, struct gp_list_state);
	state->gp_ctx = gp_ctx;
	state->local_path = talloc_asprintf(mem_ctx, "%s/%s", gp_tmpdir(mem_ctx), gpo->name);
	state->share_path = gp_get_share_path(mem_ctx, gpo->file_sys_path);


	/* Create the GPO dir if it does not exist */
	if (stat(state->local_path, &st) != 0) {
		rv = mkdir(state->local_path, 0755);
		if (rv < 0) {
			DEBUG(0, ("Could not create local path\n"));
			talloc_free(mem_ctx);
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	/* Copy the files */
	status = gp_do_list("", state);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Could not list GPO files on remote server\n"));
		talloc_free(mem_ctx);
		return status;
	}

	/* Return the local path to the gpo */
	*ret_local_path = state->local_path;

	talloc_free(mem_ctx);
	return NT_STATUS_OK;
}

static NTSTATUS push_recursive (struct gp_context *gp_ctx, const char *local_path, const char *remote_path, int depth)
{
	DIR *dir;
	struct dirent *dirent;
	char *entry_local_path;
	char *entry_remote_path;
	int local_fd, remote_fd;
	int buf[1024];
	int nread, total_read;

	dir = opendir(local_path);
	while ((dirent = readdir(dir)) != NULL) {
		if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) {
			continue;
		}

		entry_local_path = talloc_asprintf(gp_ctx, "%s/%s", local_path, dirent->d_name);
		entry_remote_path = talloc_asprintf(gp_ctx, "%s\\%s", remote_path, dirent->d_name);
		if (dirent->d_type == DT_DIR) {
			DEBUG(6, ("Pushing directory %s to %s on sysvol\n", entry_local_path, entry_remote_path));
			smbcli_mkdir(gp_ctx->cli->tree, entry_remote_path);
			if (depth < GP_MAX_DEPTH)
				push_recursive(gp_ctx, entry_local_path, entry_remote_path, depth+1);
		} else {
			DEBUG(6, ("Pushing file %s to %s on sysvol\n", entry_local_path, entry_remote_path));
			remote_fd = smbcli_open(gp_ctx->cli->tree, entry_remote_path, O_WRONLY | O_CREAT, 0);
			if (remote_fd < 0) {
				talloc_free(entry_local_path);
				talloc_free(entry_remote_path);
				DEBUG(0, ("Failed to create remote file: %s\n", entry_remote_path));
				return NT_STATUS_UNSUCCESSFUL;
			}
			local_fd = open(entry_local_path, O_RDONLY);
			if (local_fd < 0) {
				talloc_free(entry_local_path);
				talloc_free(entry_remote_path);
				DEBUG(0, ("Failed to open local file: %s\n", entry_local_path));
				return NT_STATUS_UNSUCCESSFUL;
			}
			total_read = 0;
			while ((nread = read(local_fd, &buf, sizeof(buf)))) {
				smbcli_write(gp_ctx->cli->tree, remote_fd, 0, &buf, total_read, nread);
				total_read += nread;
			}

			close(local_fd);
			smbcli_close(gp_ctx->cli->tree, remote_fd);
		}
		talloc_free(entry_local_path);
		talloc_free(entry_remote_path);
	}
	closedir(dir);

	return NT_STATUS_OK;
}



NTSTATUS gp_push_gpt(struct gp_context *gp_ctx, const char *local_path, const char *file_sys_path)
{
	NTSTATUS status;
	char *share_path;

	if (gp_ctx->cli == NULL) {
		status = gp_cli_connect(gp_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Failed to create cli connection to DC\n"));
			return status;
		}
	}
	share_path = gp_get_share_path(gp_ctx, file_sys_path);

	DEBUG(5, ("Copying %s to %s on sysvol\n", local_path, share_path));

	smbcli_mkdir(gp_ctx->cli->tree, share_path);

	status = push_recursive(gp_ctx, local_path, share_path, 0);

	talloc_free(share_path);
	return status;
}

NTSTATUS gp_create_gpt(struct gp_context *gp_ctx, const char *name, const char *file_sys_path)
{
	TALLOC_CTX *mem_ctx;
	const char *tmp_dir, *policy_dir, *tmp_str;
	int rv;
	int fd;
	NTSTATUS status;

	/* Create a forked memory context, as a base for everything here */
	mem_ctx = talloc_new(gp_ctx);

	tmp_dir = gp_tmpdir(mem_ctx);
	policy_dir = talloc_asprintf(mem_ctx, "%s/%s", tmp_dir, name);

	/* Create the directories */

	rv = mkdir(policy_dir, 0755);
	if (rv < 0) {
		DEBUG(0, ("Could not create the policy dir: %s\n", policy_dir));
		talloc_free(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	tmp_str = talloc_asprintf(mem_ctx, "%s/User", policy_dir);
	rv = mkdir(tmp_str, 0755);
	if (rv < 0) {
		DEBUG(0, ("Could not create the User dir: %s\n", tmp_str));
		talloc_free(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	tmp_str = talloc_asprintf(mem_ctx, "%s/Machine", policy_dir);
	rv = mkdir(tmp_str, 0755);
	if (rv < 0) {
		DEBUG(0, ("Could not create the Machine dir: %s\n", tmp_str));
		talloc_free(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Create a GPT.INI with version 0 */

	tmp_str = talloc_asprintf(mem_ctx, "%s/GPT.INI", policy_dir);
	fd = open(tmp_str, O_CREAT | O_WRONLY, 0644);
	if (fd < 0) {
		DEBUG(0, ("Could not create the GPT.INI: %s\n", tmp_str));
		talloc_free(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	rv = write(fd, "[General]\r\nVersion=0\r\n", 23);
	if (rv != 23) {
		DEBUG(0, ("Short write in GPT.INI\n"));
		talloc_free(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	close(fd);

	/* Upload the GPT to the sysvol share on a DC */
	status = gp_push_gpt(gp_ctx, policy_dir, file_sys_path);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return status;
	}

	talloc_free(mem_ctx);
	return NT_STATUS_OK;
}

NTSTATUS gp_set_gpt_security_descriptor(struct gp_context *gp_ctx, struct gp_object *gpo, struct security_descriptor *sd)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	union smb_setfileinfo fileinfo;
	union smb_open io;
	union smb_close io_close;

	/* Create a connection to sysvol if it is not already there */
	if (gp_ctx->cli == NULL) {
		status = gp_cli_connect(gp_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Failed to create cli connection to DC\n"));
			return status;
		}
	}

	/* Create a forked memory context which can be freed easily */
	mem_ctx = talloc_new(gp_ctx);

	/* Open the directory with NTCreate AndX call */
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = gp_get_share_path(mem_ctx, gpo->file_sys_path);
	status = smb_raw_open(gp_ctx->cli->tree, mem_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Can't open GPT directory\n"));
		talloc_free(mem_ctx);
		return status;
	}

	/* Set the security descriptor on the directory */
	fileinfo.generic.level = RAW_FILEINFO_SEC_DESC;
	fileinfo.set_secdesc.in.file.fnum = io.ntcreatex.out.file.fnum;
	fileinfo.set_secdesc.in.secinfo_flags = SECINFO_PROTECTED_DACL | SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL;
	fileinfo.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(gp_ctx->cli->tree, &fileinfo);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to set security descriptor on the GPT\n"));
		talloc_free(mem_ctx);
		return status;
	}

	/* Close the directory */
	io_close.close.level = RAW_CLOSE_CLOSE;
	io_close.close.in.file.fnum = io.ntcreatex.out.file.fnum;
	io_close.close.in.write_time = 0;
	status = smb_raw_close(gp_ctx->cli->tree, &io_close);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to close directory\n"));
		talloc_free(mem_ctx);
		return status;
	}

	talloc_free(mem_ctx);
	return NT_STATUS_OK;
}
