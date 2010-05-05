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
#include <sys/stat.h>
#include <fcntl.h>

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

NTSTATUS gp_fetch_gpo (struct gp_context *gp_ctx, struct gp_object *gpo, const char **ret_local_path)
{
	TALLOC_CTX *mem_ctx;
	struct gp_list_state *state;
	NTSTATUS status;
	unsigned int i, bkslash_cnt;
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
	state->local_path = talloc_asprintf(gp_ctx, "%s/%s", gp_tmpdir(mem_ctx), gpo->name);

	/* Get the path from the share down (\\..\..\(this\stuff) */
	for (i = 0, bkslash_cnt = 0; gpo->file_sys_path[i] != '\0'; i++) {
		if (gpo->file_sys_path[i] == '\\')
			bkslash_cnt++;

		if (bkslash_cnt == 4) {
			state->share_path = talloc_strdup(mem_ctx, &gpo->file_sys_path[i]);
			break;
		}
	}

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
