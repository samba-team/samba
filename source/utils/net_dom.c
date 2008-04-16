/*
   Samba Unix/Linux SMB client library
   net dom commands for remote join/unjoin
   Copyright (C) 2007 Günther Deschner

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "utils/net.h"

static int net_dom_usage(int argc, const char **argv)
{
	d_printf("usage: net dom join "
		 "<domain=DOMAIN> <ou=OU> <account=ACCOUNT> <password=PASSWORD> <reboot>\n");
	d_printf("usage: net dom unjoin "
		 "<account=ACCOUNT> <password=PASSWORD> <reboot>\n");

	return -1;
}

int net_help_dom(int argc, const char **argv)
{
	d_printf("net dom join"\
		"\n  Join a remote machine\n");
	d_printf("net dom unjoin"\
		"\n  Unjoin a remote machine\n");

	return -1;
}

static int net_dom_unjoin(int argc, const char **argv)
{
	struct libnetapi_ctx *ctx = NULL;
	const char *server_name = NULL;
	const char *account = NULL;
	const char *password = NULL;
	uint32_t unjoin_flags = WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE |
				WKSSVC_JOIN_FLAGS_JOIN_TYPE;
	struct cli_state *cli = NULL;
	bool reboot = false;
	NTSTATUS ntstatus;
	NET_API_STATUS status;
	int ret = -1;
	int i;

	if (argc < 1) {
		return net_dom_usage(argc, argv);
	}

	if (opt_host) {
		server_name = opt_host;
	}

	for (i=0; i<argc; i++) {
		if (strnequal(argv[i], "account", strlen("account"))) {
			account = get_string_param(argv[i]);
			if (!account) {
				return -1;
			}
		}
		if (strnequal(argv[i], "password", strlen("password"))) {
			password = get_string_param(argv[i]);
			if (!password) {
				return -1;
			}
		}
		if (strequal(argv[i], "reboot")) {
			reboot = true;
		}
	}

	if (reboot) {
		ntstatus = net_make_ipc_connection_ex(opt_workgroup, server_name,
						      NULL, 0, &cli);
		if (!NT_STATUS_IS_OK(ntstatus)) {
			return -1;
		}
	}

	status = libnetapi_init(&ctx);
	if (status != 0) {
		return -1;
	}

	libnetapi_set_username(ctx, opt_user_name);
	libnetapi_set_password(ctx, opt_password);

	status = NetUnjoinDomain(server_name, account, password, unjoin_flags);
	if (status != 0) {
		printf("Failed to unjoin domain: %s\n",
			libnetapi_get_error_string(ctx, status));
		goto done;
	}

	if (reboot) {
		opt_comment = "Shutting down due to a domain membership change";
		opt_reboot = true;
		opt_timeout = 30;

		ret = run_rpc_command(cli, PI_INITSHUTDOWN, 0,
				      rpc_init_shutdown_internals,
				      argc, argv);
		if (ret == 0) {
			goto done;
		}

		ret = run_rpc_command(cli, PI_WINREG, 0,
				      rpc_reg_shutdown_internals,
				      argc, argv);
		goto done;
	}

	ret = 0;

 done:
	if (cli) {
		cli_shutdown(cli);
	}

	return ret;
}

static int net_dom_join(int argc, const char **argv)
{
	struct libnetapi_ctx *ctx = NULL;
	const char *server_name = NULL;
	const char *domain_name = NULL;
	const char *account_ou = NULL;
	const char *Account = NULL;
	const char *password = NULL;
	uint32_t join_flags = WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE |
			      WKSSVC_JOIN_FLAGS_JOIN_TYPE;
	struct cli_state *cli = NULL;
	bool reboot = false;
	NTSTATUS ntstatus;
	NET_API_STATUS status;
	int ret = -1;
	int i;

	if (argc < 1) {
		return net_dom_usage(argc, argv);
	}

	if (opt_host) {
		server_name = opt_host;
	}

	if (opt_force) {
		join_flags |= WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED;
	}

	for (i=0; i<argc; i++) {
		if (strnequal(argv[i], "ou", strlen("ou"))) {
			account_ou = get_string_param(argv[i]);
			if (!account_ou) {
				return -1;
			}
		}
		if (strnequal(argv[i], "domain", strlen("domain"))) {
			domain_name = get_string_param(argv[i]);
			if (!domain_name) {
				return -1;
			}
		}
		if (strnequal(argv[i], "account", strlen("account"))) {
			Account = get_string_param(argv[i]);
			if (!Account) {
				return -1;
			}
		}
		if (strnequal(argv[i], "password", strlen("password"))) {
			password = get_string_param(argv[i]);
			if (!password) {
				return -1;
			}
		}
		if (strequal(argv[i], "reboot")) {
			reboot = true;
		}
	}

	if (reboot) {
		ntstatus = net_make_ipc_connection_ex(opt_workgroup, server_name,
						      NULL, 0, &cli);
		if (!NT_STATUS_IS_OK(ntstatus)) {
			return -1;
		}
	}

	/* check if domain is a domain or a workgroup */

	status = libnetapi_init(&ctx);
	if (status != 0) {
		return -1;
	}

	libnetapi_set_username(ctx, opt_user_name);
	libnetapi_set_password(ctx, opt_password);

	status = NetJoinDomain(server_name, domain_name, account_ou,
			       Account, password, join_flags);
	if (status != 0) {
		printf("Failed to join domain: %s\n",
			libnetapi_get_error_string(ctx, status));
		goto done;
	}

	if (reboot) {
		opt_comment = "Shutting down due to a domain membership change";
		opt_reboot = true;
		opt_timeout = 30;

		ret = run_rpc_command(cli, PI_INITSHUTDOWN, 0,
				      rpc_init_shutdown_internals,
				      argc, argv);
		if (ret == 0) {
			goto done;
		}

		ret = run_rpc_command(cli, PI_WINREG, 0,
				      rpc_reg_shutdown_internals,
				      argc, argv);
		goto done;
	}

	ret = 0;

 done:
	if (cli) {
		cli_shutdown(cli);
	}

	return ret;
}

int net_dom(int argc, const char **argv)
{
	struct functable func[] = {
		{"JOIN", net_dom_join},
		{"UNJOIN", net_dom_unjoin},
		{"HELP", net_help_dom},
		{NULL, NULL}
	};

	return net_run_function(argc, argv, func, net_dom_usage);
}
