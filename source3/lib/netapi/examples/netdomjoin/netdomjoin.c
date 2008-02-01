/*
 *  Unix SMB/CIFS implementation.
 *  Join Support (cmdline + netapi)
 *  Copyright (C) Guenther Deschner 2007-2008
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

#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
	const char *account_ou = NULL;
	const char *Account = NULL;
	const char *password = NULL;
	uint32_t join_flags = 3;
	struct libnetapi_ctx *ctx = NULL;
	int i;

	status = libnetapi_init(&ctx);
	if (status != 0) {
		return status;
	}

	if (argc < 2) {
		printf("usage: netdomjoin\n");
		printf("\t[hostname] [domain=DOMAIN] <ou=OU> "
		       "<usero=USERO> <passwordo=PASSWORDO> "
		       "<userd=USERD> <passwordd=PASSWORDD> "
		       "<debug=DEBUGLEVEL>\n");
		return 0;
	}

	if (argc > 2) {
		server_name = argv[1];
	}

	for (i=0; i<argc; i++) {
		if (strncasecmp(argv[i], "ou", strlen("ou")) == 0) {
			account_ou = get_string_param(argv[i]);
		}
		if (strncasecmp(argv[i], "domain", strlen("domain"))== 0) {
			domain_name = get_string_param(argv[i]);
		}
		if (strncasecmp(argv[i], "userd", strlen("userd"))== 0) {
			Account = get_string_param(argv[i]);
		}
		if (strncasecmp(argv[i], "passwordd", strlen("passwordd"))== 0) {
			password = get_string_param(argv[i]);
		}
		if (strncasecmp(argv[i], "usero", strlen("usero"))== 0) {
			const char *str = NULL;
			str = get_string_param(argv[i]);
			libnetapi_set_username(ctx, str);
		}
		if (strncasecmp(argv[i], "passwordo", strlen("passwordo"))== 0) {
			const char *str = NULL;
			str = get_string_param(argv[i]);
			libnetapi_set_password(ctx, str);
		}
		if (strncasecmp(argv[i], "debug", strlen("debug"))== 0) {
			const char *str = NULL;
			str = get_string_param(argv[i]);
			libnetapi_set_debuglevel(ctx, str);
		}
	}

	status = NetJoinDomain(server_name,
			       domain_name,
			       account_ou,
			       Account,
			       password,
			       join_flags);
	if (status != 0) {
		const char *errstr = NULL;
		errstr = libnetapi_get_error_string(ctx, status);
		if (!errstr) {
			errstr = libnetapi_errstr(status);
		}
		printf("Join failed with: %s\n", errstr);
	} else {
		printf("Successfully joined\n");
	}

	libnetapi_free(ctx);

	return status;
}
