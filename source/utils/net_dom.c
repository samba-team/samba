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
#include "lib/netapi/joindomain.h"

static int net_dom_usage(int argc, const char **argv)
{
	d_printf("usage: net dom join "
		 "<domain=DOMAIN> <ou=OU> <account=ACCOUNT> <password=PASSWORD> <reboot>\n");

	return -1;
}

int net_help_dom(int argc, const char **argv)
{
	d_printf("net dom join"\
		"\n  Join a remote machine\n");

	return -1;
}

static int net_dom_join(int argc, const char **argv)
{
	const char *server_name = NULL;
	const char *domain_name = NULL;
	const char *account_ou = NULL;
	const char *Account = NULL;
	const char *password = NULL;
	uint32_t join_flags = WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE |
			      WKSSVC_JOIN_FLAGS_JOIN_TYPE;
	bool reboot = false;
	WERROR werr;
	int i;

	if (argc < 1) {
		return net_dom_usage(argc, argv);
	}

	server_name = opt_host;

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

	/* check if domain is a domain or a workgroup */

	werr = NetJoinDomain(server_name, domain_name, account_ou,
			     Account, password, join_flags);
	if (!W_ERROR_IS_OK(werr)) {
		printf("Failed to join domain: %s\n",
			get_friendly_nt_error_msg(werror_to_ntstatus(werr)));
			return -1;
	}

	/* reboot then */

	return 0;
}

int net_dom(int argc, const char **argv)
{
	struct functable func[] = {
		{"JOIN", net_dom_join},
		{NULL, NULL}
	};

	return net_run_function(argc, argv, func, net_dom_usage);
}
