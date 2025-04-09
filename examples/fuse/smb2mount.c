/*
 * Unix SMB/CIFS implementation.
 * fusermount smb2 client
 *
 * Copyright (C) Volker Lendecke 2016
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

#include "source3/include/includes.h"
#include "popt.h"
#include "lib/cmdline/cmdline.h"
#include "lib/param/param.h"
#include "client.h"
#include "libsmb/proto.h"
#include "libsmb/smbsock_connect.h"
#include "clifuse.h"

static struct cli_state *connect_one(struct cli_credentials *creds,
				     const char *server,
				     const struct smb_transports *transports,
				     const char *share)
{
	struct cli_state *c = NULL;
	NTSTATUS nt_status;
	uint32_t flags = 0;

	nt_status = cli_full_connection_creds(talloc_tos(),
					      &c,
					      lp_netbios_name(),
					      server,
					      NULL,
					      transports,
					      share,
					      "?????",
					      creds,
					      flags);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_ERR("cli_full_connection failed! (%s)\n",
			nt_errstr(nt_status));
		return NULL;
	}

	return c;
}

int main(int argc, char *argv[])
{
	const char **argv_const = discard_const_p(const char *, argv);
	TALLOC_CTX *frame = talloc_stackframe();
	struct loadparm_context *lp_ctx = NULL;
	poptContext pc;
	int opt, ret;
	int port = 0;
	char *unc, *mountpoint, *server, *share;
	struct cli_state *cli;
	struct cli_credentials *creds = NULL;
	struct smb_transports ts = { .num_transports = 0, };
	bool ok;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		POPT_COMMON_SAMBA
		POPT_COMMON_CREDENTIALS
		{ "port", 'p', POPT_ARG_INT, &port, 'p', "Port to connect to",
		  "PORT" },
		POPT_TABLEEND
	};

	smb_init_locale();

	ok = samba_cmdline_init(frame,
				SAMBA_CMDLINE_CONFIG_CLIENT,
				false /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
		TALLOC_FREE(frame);
		exit(1);
	}
	lp_ctx = samba_cmdline_get_lp_ctx();
	lpcfg_set_cmdline(lp_ctx, "client min protocol", "SMB2");
	lpcfg_set_cmdline(lp_ctx, "client max protocol", "SMB3_11");

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    argv_const,
				    long_options,
				    0);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	poptSetOtherOptionHelp(pc, "//server1/share1 mountpoint");

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch(opt) {
		    case 'p':
			    break;
		    default:
			    fprintf(stderr, "Unknown Option: %c\n", opt);
			    exit(1);
		}
	}

	if (!poptPeekArg(pc)) {
		poptPrintUsage(pc, stderr, 0);
		return -1;
	}
	unc = talloc_strdup(frame, poptGetArg(pc));
	if (unc == NULL) {
		return -1;
	}
	string_replace(unc,'/','\\');

	if (!poptPeekArg(pc)) {
		poptPrintUsage(pc, stderr, 0);
		return -1;
	}
	mountpoint = talloc_strdup(frame, poptGetArg(pc));
	if (mountpoint == NULL) {
		return -1;
	}

	poptFreeContext(pc);
	samba_cmdline_burn(argc, argv);

	server = talloc_strdup(frame, unc+2);
	if (!server) {
		return -1;
	}
	share = strchr_m(server,'\\');
	if (!share) {
		fprintf(stderr, "Invalid argument: %s\n", server);
		return -1;
	}

	*share = 0;
	share++;

	creds = samba_cmdline_get_creds();

	ts = smbsock_transports_from_port(port);

	cli = connect_one(creds, server, &ts, share);
	if (cli == NULL) {
		return -1;
	}

	ret = do_mount(cli, mountpoint);
	if (ret != 0) {
		fprintf(stderr, "mount failed\n");
		return -1;
	}

	TALLOC_FREE(frame);
	return 0;
}
