/*
 *  Unix SMB/CIFS implementation.
 *  Join Support (cmdline + netapi)
 *  Copyright (C) Guenther Deschner 2008
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

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include <netapi.h>

char *get_string_param(const char *param)
{
	char *p;

	p = strchr(param, '=');
	if (!p) {
		return NULL;
	}

	return (p+1);
}

int main(int argc, char **argv)
{
	NET_API_STATUS status;
	const char *server_name = NULL;
	const char *domain_name = NULL;
	const char *account = NULL;
	const char *password = NULL;
	const char **ous = NULL;
	uint32_t num_ous = 0;
	struct libnetapi_ctx *ctx = NULL;
	int i;

	status = libnetapi_init(&ctx);
	if (status != 0) {
		return status;
	}

	if (argc < 2) {
		printf("usage: getjoinableous\n");
		printf("\t<hostname> [domain=DOMAIN] <user=USER> <password=PASSWORD>\n");
		return 0;
	}

	if (argc > 2) {
		server_name = argv[1];
	}

	for (i=0; i<argc; i++) {
		if (strncasecmp(argv[i], "domain", strlen("domain"))== 0) {
			domain_name = get_string_param(argv[i]);
		}
		if (strncasecmp(argv[i], "user", strlen("user"))== 0) {
			account = get_string_param(argv[i]);
			libnetapi_set_username(ctx, account);
		}
		if (strncasecmp(argv[i], "password", strlen("password"))== 0) {
			password = get_string_param(argv[i]);
			libnetapi_set_password(ctx, password);
		}
		if (strncasecmp(argv[i], "debug", strlen("debug"))== 0) {
			const char *str = NULL;
			str = get_string_param(argv[i]);
			libnetapi_set_debuglevel(ctx, str);
		}
	}

	status = NetGetJoinableOUs(server_name,
				   domain_name,
				   account,
				   password,
				   &num_ous,
				   &ous);
	if (status != 0) {
		printf("failed with: %s\n",
			libnetapi_get_error_string(ctx, status));
	} else {
		printf("Successfully queried joinable ous:\n");
		for (i=0; i<num_ous; i++) {
			printf("ou: %s\n", ous[i]);
		}
	}

	NetApiBufferFree(ous);

	libnetapi_free(ctx);

	return status;
}
