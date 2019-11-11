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
#include "popt_common_cmdline.h"
#include "client.h"
#include "libsmb/proto.h"
#include "clifuse.h"

static struct cli_state *connect_one(const struct user_auth_info *auth_info,
				     const char *server, int port,
				     const char *share)
{
	struct cli_state *c = NULL;
	NTSTATUS nt_status;
	uint32_t flags = 0;

	nt_status = cli_full_connection_creds(&c, lp_netbios_name(), server,
				NULL, port,
				share, "?????",
				get_cmdline_auth_info_creds(auth_info),
				flags,
				get_cmdline_auth_info_signing_state(auth_info));
	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_ERR("cli_full_connection failed! (%s)\n",
			nt_errstr(nt_status));
		return NULL;
	}

	if (get_cmdline_auth_info_smb_encrypt(auth_info)) {
		nt_status = cli_cm_force_encryption_creds(
			c,
			get_cmdline_auth_info_creds(auth_info),
			share);
                if (!NT_STATUS_IS_OK(nt_status)) {
			cli_shutdown(c);
			c = NULL;
                }
	}

	return c;
}

int main(int argc, char *argv[])
{
	const char **argv_const = discard_const_p(const char *, argv);
	TALLOC_CTX *frame = talloc_stackframe();
	poptContext pc;
	int opt, ret;
	int port = 0;
	char *unc, *mountpoint, *server, *share;
	struct cli_state *cli;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		POPT_COMMON_SAMBA
		POPT_COMMON_CREDENTIALS
		{ "port", 'p', POPT_ARG_INT, &port, 'p', "Port to connect to",
		  "PORT" },
		POPT_TABLEEND
	};

	smb_init_locale();
	setup_logging(argv[0], DEBUG_STDERR);
	lp_set_cmdline("client min protocol", "SMB2");
	lp_set_cmdline("client max protocol", "SMB3_11");

	lp_load_global(get_dyn_CONFIGFILE());
	load_interfaces();

	pc = poptGetContext("smb2mount", argc, argv_const, long_options, 0);
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
	popt_burn_cmdline_password(argc, argv);

	server = talloc_strdup(frame, unc+2);
	if (!server) {
		return -1;
	}
	share = strchr_m(server,'\\');
	if (!share) {
		fprintf(stderr, "Invalid argument: %s\n", share);
		return -1;
	}

	*share = 0;
	share++;

	cli = connect_one(popt_get_cmdline_auth_info(), server, port, share);
	if (cli == NULL) {
		return -1;
	}

	ret = do_mount(cli, mountpoint);
	if (ret != 0) {
		fprintf(stderr, "mount failed\n");
		return -1;
	}

	popt_free_cmdline_auth_info();
	TALLOC_FREE(frame);
	return 0;
}
