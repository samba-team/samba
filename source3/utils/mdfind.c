/*
 * Copyright (C) 2019, Ralph Boehme <slow@samba.org.>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

#include "includes.h"
#include "lib/util/debug.h"
#include "popt_common.h"
#include "popt_common_cmdline.h"
#include "lib/cmdline_contexts.h"
#include "param.h"
#include "auth_info.h"
#include "client.h"
#include "libsmb/proto.h"
#include "librpc/rpc/rpc_common.h"
#include "rpc_client/cli_pipe.h"
#include "rpc_client/cli_mdssvc.h"
#include "librpc/gen_ndr/ndr_mdssvc_c.h"

static char *opt_path;
static int opt_live;

static struct poptOption long_options[] = {
	POPT_AUTOHELP
	{
		.longName  = "path",
		.shortName = 'p',
		.argInfo   = POPT_ARG_STRING,
		.arg       = &opt_path,
		.descrip   = "Server-relative search path",
	},
	{
		.longName  = "live",
		.shortName = 'L',
		.argInfo   = POPT_ARG_NONE,
		.arg       = &opt_live,
		.descrip   = "live query",
	},
	POPT_COMMON_SAMBA
	POPT_COMMON_CREDENTIALS
	POPT_TABLEEND
};

int main(int argc, char **argv)
{
	const char **const_argv = discard_const_p(const char *, argv);
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = NULL;
	struct user_auth_info *auth = NULL;
	struct cli_credentials *creds = NULL;
	struct rpc_pipe_client *rpccli = NULL;
	struct mdscli_ctx *mdscli_ctx = NULL;
	struct mdscli_search_ctx *search = NULL;
	const char *server = NULL;
	const char *share = NULL;
	const char *mds_query = NULL;
	struct cli_state *cli = NULL;
	char *basepath = NULL;
	uint32_t flags = 0;
	int signing_state = SMB_SIGNING_IPC_DEFAULT;
	uint64_t *cnids = NULL;
	size_t ncnids;
	size_t i;
	int opt;
	poptContext pc;
	NTSTATUS status;
	bool ok;

	setup_logging(argv[0], DEBUG_STDERR);
	smb_init_locale();
	lp_set_cmdline("log level", "1");

	pc = poptGetContext(argv[0],
			    argc,
			    const_argv,
			    long_options,
			    POPT_CONTEXT_KEEP_FIRST);

	poptSetOtherOptionHelp(pc, "mdfind [OPTIONS] <server> <share> <query>\n");

	while ((opt = poptGetNextOpt(pc)) != -1) {
		DBG_ERR("Invalid option %s: %s\n",
			poptBadOption(pc, 0),
			poptStrerror(opt));
		poptPrintHelp(pc, stderr, 0);
		goto fail;
	}

	poptGetArg(pc); /* Drop argv[0], the program name */
	server = poptGetArg(pc);
	share = poptGetArg(pc);
	mds_query = poptGetArg(pc);

	if (server == NULL || mds_query == NULL) {
		poptPrintHelp(pc, stderr, 0);
		goto fail;
	}

	popt_burn_cmdline_password(argc, argv);

	if ((server[0] == '/' && server[1] == '/') ||
	    (server[0] == '\\' && server[1] ==  '\\'))
	{
		server += 2;
	}

	auth = popt_get_cmdline_auth_info();
	creds = get_cmdline_auth_info_creds(auth);

	signing_state = get_cmdline_auth_info_signing_state(auth);
	switch (signing_state) {
	case SMB_SIGNING_OFF:
		lp_set_cmdline("client ipc signing", "no");
		break;
	case SMB_SIGNING_REQUIRED:
		lp_set_cmdline("client ipc signing", "required");
		break;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}

	cmdline_messaging_context(get_dyn_CONFIGFILE());

	ok = lp_load_client(get_dyn_CONFIGFILE());
	if (!ok) {
		fprintf(stderr, "ERROR: Can't load %s\n",
			get_dyn_CONFIGFILE());
		exit(1);
	}

	status = cli_full_connection_creds(&cli,
					   lp_netbios_name(),
					   server,
					   NULL,
					   0,
					   "IPC$",
					   "IPC",
					   creds,
					   flags,
					   SMB_SIGNING_IPC_DEFAULT);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Cannot connect to server: %s\n", nt_errstr(status));
		goto fail;
	}

	if (get_cmdline_auth_info_smb_encrypt(auth)) {
		status = cli_cm_force_encryption_creds(cli, creds, "IPC$");
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	status = cli_rpc_pipe_open_noauth_transport(cli,
						    NCACN_NP,
						    &ndr_table_mdssvc,
						    &rpccli);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = mdscli_connect(frame,
				rpccli->binding_handle,
				share,
				"/foo/bar",
				&mdscli_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect mdssvc\n");
		goto fail;
	}

	if (opt_path == NULL) {
		basepath = mdscli_get_basepath(frame, mdscli_ctx);
	} else {
		basepath = talloc_strdup(frame, opt_path);
	}
	if (basepath == NULL) {
		goto fail;
	}

	status = mdscli_search(frame,
			       mdscli_ctx,
			       mds_query,
			       basepath,
			       opt_live == 1 ? true : false,
			       &search);
	if (!NT_STATUS_IS_OK(status)) {
		printf("mdscli_search failed\n");
		goto fail;
	}

	if (!opt_live) {
		sleep(1);
	}

	while (true) {
		status = mdscli_get_results(frame,
					    search,
					    &cnids);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_MATCHES)) {
			if (opt_live) {
				sleep(1);
				continue;
			}
			break;
		}
		if (!NT_STATUS_IS_OK(status)) {
			printf("mdscli_get_results failed\n");
			goto fail;
		}

		ncnids = talloc_array_length(cnids);
		if (ncnids == 0) {
			break;
		}

		for (i = 0; i < ncnids; i++) {
			char *path = NULL;

			status = mdscli_get_path(frame,
						 mdscli_ctx,
						 cnids[i],
						 &path);
			if (!NT_STATUS_IS_OK(status)) {
				printf("Get path for CNID 0x%"PRIx64" failed\n",
				       cnids[i]);
				goto fail;
			}
			printf("%s\n", path);
			TALLOC_FREE(path);
		}
	}

	status = mdscli_close_search(&search);
	if (!NT_STATUS_IS_OK(status)) {
		printf("mdscli_close_search failed\n");
		goto fail;
	}

	status = mdscli_disconnect(mdscli_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		printf("mdscli_disconnect failed\n");
		goto fail;
	}

	TALLOC_FREE(frame);
	poptFreeContext(pc);
	return 0;

fail:
	TALLOC_FREE(frame);
	return 1;
}
