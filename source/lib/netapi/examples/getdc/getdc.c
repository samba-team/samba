/*
 *  Unix SMB/CIFS implementation.
 *  GetDCName query
 *  Copyright (C) Guenther Deschner 2007
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

int main(int argc, char **argv)
{
	NET_API_STATUS status;
	struct libnetapi_ctx *ctx = NULL;
	uint8_t *buffer = NULL;

	if (argc < 3) {
		printf("usage: getdc <hostname> <domain>\n");
		return -1;
	}

	status = libnetapi_init(&ctx);
	if (status != 0) {
		return status;
	}

	libnetapi_set_username(ctx, "");
	libnetapi_set_password(ctx, "");

	status = NetGetDCName(argv[1], argv[2], &buffer);
	if (status != 0) {
		printf("GetDcName failed with: %s\n", libnetapi_errstr(status));
	} else {
		printf("%s\n", (char *)buffer);
	}
	NetApiBufferFree(buffer);
	libnetapi_free(ctx);

	return status;
}
