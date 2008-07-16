/*
 *  Unix SMB/CIFS implementation.
 *  NetUserGetInfo query
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

#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netapi.h>

#include "common.h"

int main(int argc, const char **argv)
{
	NET_API_STATUS status;
	struct libnetapi_ctx *ctx = NULL;
	const char *hostname = NULL;
	const char *username = NULL;
	uint8_t *buffer = NULL;
	uint32_t level = 0;
	char *sid_str = NULL;

	struct USER_INFO_0 *u0;
	struct USER_INFO_1 *u1;
	struct USER_INFO_10 *u10;
	struct USER_INFO_20 *u20;
	struct USER_INFO_23 *u23;

	poptContext pc;
	int opt;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		POPT_COMMON_LIBNETAPI_EXAMPLES
		POPT_TABLEEND
	};

	status = libnetapi_init(&ctx);
	if (status != 0) {
		return status;
	}

	pc = poptGetContext("user_getinfo", argc, argv, long_options, 0);

	poptSetOtherOptionHelp(pc, "hostname username level");
	while((opt = poptGetNextOpt(pc)) != -1) {
	}

	if (!poptPeekArg(pc)) {
		poptPrintHelp(pc, stderr, 0);
		goto out;
	}
	hostname = poptGetArg(pc);

	if (!poptPeekArg(pc)) {
		poptPrintHelp(pc, stderr, 0);
		goto out;
	}
	username = poptGetArg(pc);

	if (poptPeekArg(pc)) {
		level = atoi(poptGetArg(pc));
	}

	/* NetUserGetInfo */

	status = NetUserGetInfo(hostname,
				username,
				level,
				&buffer);
	if (status != 0) {
		printf("NetUserGetInfo failed with: %s\n",
			libnetapi_get_error_string(ctx, status));
		goto out;
	}

	switch (level) {
		case 0:
			u0 = (struct USER_INFO_0 *)buffer;
			printf("name: %s\n", u0->usri0_name);
			break;
		case 1:
			u1 = (struct USER_INFO_1 *)buffer;
			printf("name: %s\n", u1->usri1_name);
			printf("password: %s\n", u1->usri1_password);
			printf("password_age: %d\n", u1->usri1_password_age);
			printf("priv: %d\n", u1->usri1_priv);
			printf("homedir: %s\n", u1->usri1_home_dir);
			printf("comment: %s\n", u1->usri1_comment);
			printf("flags: 0x%08x\n", u1->usri1_flags);
			printf("script: %s\n", u1->usri1_script_path);
			break;
		case 10:
			u10 = (struct USER_INFO_10 *)buffer;
			printf("name: %s\n", u10->usri10_name);
			printf("comment: %s\n", u10->usri10_comment);
			printf("usr_comment: %s\n", u10->usri10_usr_comment);
			printf("full_name: %s\n", u10->usri10_full_name);
			break;
		case 20:
			u20 = (struct USER_INFO_20 *)buffer;
			printf("name: %s\n", u20->usri20_name);
			printf("comment: %s\n", u20->usri20_comment);
			printf("flags: 0x%08x\n", u20->usri20_flags);
			printf("rid: %d\n", u20->usri20_user_id);
			break;
		case 23:
			u23 = (struct USER_INFO_23 *)buffer;
			printf("name: %s\n", u23->usri23_name);
			printf("comment: %s\n", u23->usri23_comment);
			printf("flags: 0x%08x\n", u23->usri23_flags);
			if (ConvertSidToStringSid(u23->usri23_user_sid,
						  &sid_str)) {
				printf("user_sid: %s\n", sid_str);
				free(sid_str);
			}
			break;
		default:
			break;
	}

 out:
	libnetapi_free(ctx);
	poptFreeContext(pc);

	return status;
}
