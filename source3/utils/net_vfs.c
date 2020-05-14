/*
 * Samba Unix/Linux SMB client library
 * Distributed SMB/CIFS Server Management Utility
 * Copyright (C) 2019 Ralph Boehme <slow@samba.org>
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include <talloc.h>
#include <tevent.h>
#include <ftw.h>
#include "system/filesys.h"
#include "system/passwd.h"
#include "popt_common.h"
#include "lib/param/loadparm.h"
#include "lib/param/param.h"
#include "libcli/security/security.h"
#include "smbd/proto.h"
#include "locking/proto.h"
#include "auth.h"
#include "client.h"
#include "util_sd.h"
#include "lib/adouble.h"
#include "lib/string_replace.h"
#include "utils/net.h"

#define NET_VFS_CMD_STREAM_TO_ADOUBLE "stream2adouble"

static struct net_vfs_state {
	TALLOC_CTX *mem_ctx;
	struct net_context *c;
	struct auth_session_info *session_info;
	struct conn_struct_tos *conn_tos;
} state;

static void net_vfs_usage(void)
{
	fprintf(stderr,
		"Usage:\n"
		"net vfs [OPTIONS] <share> ....\n");
}

static void net_vfs_getntacl_usage(void)
{
	fprintf(stderr,
		"Usage:\n"
		"net vfs getntacl <share> <path>\n");
}

static void net_vfs_stream_to_appledouble_usage(void)
{
	fprintf(stderr,
		"Usage:\n"
		"net vfs " NET_VFS_CMD_STREAM_TO_ADOUBLE
		" [OPTIONS] <share> <path> [<path> ...]\n"
		"Options:\n"
		"  --verbose             verbose output\n"
		"  --continue            continue on error\n"
		"  --recursive           traverse directory hierarchy\n"
		"  --follow-symlinks     follow symlinks\n");
}

static bool net_vfs_make_session_info(struct auth_session_info **session_info)
{
	NTSTATUS status;

	if (non_root_mode()) {
		struct passwd *p = NULL;

		p = getpwuid(geteuid());
		if (p == NULL) {
			fprintf(stderr, "getpwuid(%d) failed\n", geteuid());
			return false;
		}

		status = make_session_info_from_username(state.mem_ctx,
							 p->pw_name,
							 false,
							 session_info);
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr, "session_info from username failed\n");
			return false;
		}

		return true;
	}

	status = init_system_session_info(state.mem_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "init_system_session_info failed\n");
		return false;
	}

	status = make_session_info_system(state.mem_ctx, session_info);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "make_session_info_system failed\n");
		return false;
	}

	return true;
}

static int net_vfs_init(struct net_context *c, int argc, const char **argv)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	const char *service = NULL;
	char *share_root = NULL;
	int snum;
	NTSTATUS status;
	bool ok;
	int rc = 1;

	state = (struct net_vfs_state) {
		.c = c,
		.mem_ctx = c,
	};

	if (argc < 1) {
		net_vfs_usage();
		goto done;
	}

	if (geteuid() != 0 && !uid_wrapper_enabled()) {
		fprintf(stderr, "'net vfs' must be run as root.\n");
		goto done;
	}

	smb_init_locale();
	umask(0);
	sec_init();
	setup_logging("net", DEBUG_STDOUT);
	lp_set_cmdline("log level", "0");

	ok = lp_load_with_registry_shares(get_dyn_CONFIGFILE());
	if (!ok) {
		fprintf(stderr, "lp_load_with_registry_shares failed\n");
		goto done;
	}

	ok = locking_init();
	if (!ok) {
		fprintf(stderr, "locking init failed\n");
		goto done;
	}

	ok = net_vfs_make_session_info(&state.session_info);
	if (!ok) {
		goto done;
	}

	service = argv[0];
	snum = lp_servicenumber(service);
	if (snum == -1) {
		fprintf(stderr, "unknown service: %s\n", service);
		goto done;
	}

	share_root = lp_path(state.mem_ctx, lp_sub, snum);
	if (share_root == NULL) {
		fprintf(stderr, "Failed to find share root for service: %s\n",
			service);
		goto done;
	}

	status = create_conn_struct_tos_cwd(global_messaging_context(),
					    snum,
					    share_root,
					    state.session_info,
					    &state.conn_tos);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	state.conn_tos->conn->share_access = FILE_GENERIC_ALL;
	state.conn_tos->conn->read_only = false;
	file_init(state.conn_tos->conn->sconn);

	ok = become_user_without_service_by_session(state.conn_tos->conn,
						    state.session_info);
	if (!ok) {
		fprintf(stderr,
			"become_user_without_service_by_session failed\n");
		goto done;
	}

	rc = 0;
done:
	return rc;
}

static int net_vfs_get_ntacl(struct net_context *net,
			     int argc,
			     const char **argv)
{
	const char *path = NULL;
	struct smb_filename *smb_fname = NULL;
	files_struct *fsp = NULL;
	struct security_descriptor *sd = NULL;
	NTSTATUS status;
	int ret;
	int rc = 1;

	if (argc < 2 || net->display_usage) {
		net_vfs_getntacl_usage();
		goto done;
	}

	ret = net_vfs_init(net, argc, argv);
	if (ret != 0) {
		goto done;
	}

	path = argv[1];
	smb_fname = synthetic_smb_fname(state.mem_ctx,
					path,
					NULL,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		goto done;
	}

	ret = SMB_VFS_STAT(state.conn_tos->conn, smb_fname);
	if (ret != 0) {
		fprintf(stderr, "stat [%s] failed: %s\n",
			smb_fname_str_dbg(smb_fname), strerror(errno));
		goto done;
	}

	status = SMB_VFS_CREATE_FILE(
		state.conn_tos->conn,
		NULL,				/* req */
		&state.conn_tos->conn->cwd_fsp,
		smb_fname,
		FILE_READ_ATTRIBUTES|READ_CONTROL_ACCESS,
		FILE_SHARE_READ|FILE_SHARE_WRITE,
		FILE_OPEN,
		0,				/* create_options */
		0,				/* file_attributes */
		INTERNAL_OPEN_ONLY,		/* oplock_request */
		NULL,				/* lease */
		0,				/* allocation_size */
		0,				/* private_flags */
		NULL,				/* sd */
		NULL,				/* ea_list */
		&fsp,
		NULL,				/* info */
		NULL, NULL);			/* create context */
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("SMB_VFS_CREATE_FILE [%s] failed: %s\n",
			smb_fname_str_dbg(smb_fname), nt_errstr(status));
		goto done;
	}

	status = SMB_VFS_FGET_NT_ACL(fsp,
				     SECINFO_OWNER|SECINFO_GROUP|SECINFO_DACL,
				     fsp,
				     &sd);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("SMB_VFS_FGET_NT_ACL [%s] failed: %s\n",
			smb_fname_str_dbg(smb_fname), nt_errstr(status));
		goto done;
	}

	status = close_file(NULL, fsp, NORMAL_CLOSE);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("close_file [%s] failed: %s\n",
			smb_fname_str_dbg(smb_fname),
			nt_errstr(status));
		goto done;
	}
	fsp = NULL;

	sec_desc_print(NULL, stdout, sd, true);

	rc = 0;
done:
	if (fsp != NULL) {
		status = close_file(NULL, fsp, NORMAL_CLOSE);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("close_file [%s] failed: %s\n",
				smb_fname_str_dbg(smb_fname),
				nt_errstr(status));
			rc = 1;
		}
	}
	return rc;
}

static bool do_unfruit(const char *path)
{
	struct smb_filename *smb_fname = NULL;
	char *p = NULL;
	bool converted;
	int ret;
	bool ok;

	p = strrchr_m(path, '/');
	if (p != NULL) {
		if (p[1] == '.' && p[2] == '_') {
			return true;
		}
	}

	smb_fname = synthetic_smb_fname(state.mem_ctx,
					path,
					NULL,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		return false;
	}

	ret = SMB_VFS_STAT(state.conn_tos->conn, smb_fname);
	if (ret != 0) {
		fprintf(stderr, "%s: %s\n", path, strerror(errno));
		if (state.c->opt_continue_on_error) {
			return true;
		}
		return false;
	}

	ok = ad_unconvert(state.mem_ctx,
			  state.conn_tos->conn->vfs_handles,
			  macos_string_replace_map,
			  smb_fname,
			  &converted);
	if (!ok) {
		fprintf(stderr, "Converting failed: %s\n", path);
		if (state.c->opt_continue_on_error) {
			return true;
		}
		return false;
	}

	if (converted) {
		fprintf(stdout, "Converted: %s\n", path);
	} else if (state.c->opt_verbose) {
		fprintf(stdout, "%s\n", path);
	}
	return true;
}

static int nftw_cb(const char *path,
		   const struct stat *sb,
		   int typeflag,
		   struct FTW *ftwbuf)
{
	bool ok;

	if (typeflag == FTW_SL) {
		if (state.c->opt_verbose) {
			fprintf(stdout, "Ignoring symlink: %s\n", path);
		}
		return 0;
	}

	ok = do_unfruit(path);
	if (!ok) {
		return -1;
	}

	return 0;
}

static int net_vfs_stream_to_appledouble(struct net_context *net,
					 int argc,
					 const char **argv)
{
	int i;
	int ret;
	bool ok;
	int rc = 1;

	if (argc < 2 || net->display_usage) {
		net_vfs_stream_to_appledouble_usage();
		goto done;
	}

	ret = net_vfs_init(net, argc, argv);
	if (ret != 0) {
		goto done;
	}

	for (i = 1; i < argc; i++) {
		const char *path = argv[i];

		if (path[0] == '/') {
			fprintf(stderr, "ignoring absolute path: %s\n", path);
			if (state.c->opt_continue_on_error) {
				continue;
			}
			goto done;
		}

		if (!state.c->opt_recursive) {
			ok = do_unfruit(path);
			if (!ok) {
				if (!state.c->opt_continue_on_error) {
					goto done;
				}
			}
			continue;
		}

		ret = nftw(path,
			   nftw_cb,
			   256,
			   state.c->opt_follow_symlink ? 0 : FTW_PHYS);
		if (ret != 0) {
			fprintf(stderr, "%s: %s\n", path, strerror(errno));
			if (!state.c->opt_continue_on_error) {
				goto done;
			}
		}
	}

	rc = 0;

done:
	return rc;
}

static struct functable func[] = {
	{
		"getntacl",
		net_vfs_get_ntacl,
		NET_TRANSPORT_LOCAL,
		N_("Display security descriptor of a file or directory"),
		N_("net vfs getntacl <share> <path> [<path> ...]")
	},
	{
		NET_VFS_CMD_STREAM_TO_ADOUBLE,
		net_vfs_stream_to_appledouble,
		NET_TRANSPORT_LOCAL,
		N_("Convert streams to AppleDouble files"),
		N_("net vfs " NET_VFS_CMD_STREAM_TO_ADOUBLE " [OPTIONS] <share> <path> [<path> ...]")
	},
	{NULL, NULL, 0, NULL, NULL}
};

int net_vfs(struct net_context *c, int argc, const char **argv)
{
	return net_run_function(c, argc, argv, "net vfs", func);
}
