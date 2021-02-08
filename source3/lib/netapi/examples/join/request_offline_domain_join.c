/*
 *  Unix SMB/CIFS implementation.
 *  NetRequestOfflineDomainJoin
 *  Copyright (C) Guenther Deschner 2021
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
#include <sys/types.h>
#include <inttypes.h>
#include <stdlib.h>

#include <netapi.h>

#include "common.h"

int main(int argc, const char **argv)
{
	NET_API_STATUS status;
	const char *windows_path = NULL;
	uint32_t options = 0;
	uint8_t *provision_bin_data = NULL;
	uint32_t provision_bin_data_size = 0;
	const char *loadfile = NULL;
	struct libnetapi_ctx *ctx = NULL;
	int localos = 0;

	poptContext pc;
	int opt;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{ "loadfile", 0, POPT_ARG_STRING, &loadfile, 'D', "Load file from previous provision", "FILENAME" },
		{ "localos", 0, POPT_ARG_NONE, &localos, 'D', "Request local OS to load offline join information", "" },
		POPT_COMMON_LIBNETAPI_EXAMPLES
		POPT_TABLEEND
	};

	status = libnetapi_init(&ctx);
	if (status != 0) {
		return status;
	}

	pc = poptGetContext("request_offline_domain_join", argc, argv, long_options, 0);

	poptSetOtherOptionHelp(pc, "");
	while((opt = poptGetNextOpt(pc)) != -1) {
	}

	if (loadfile == NULL) {
		printf("--loadfile <FILENAME> is required\n");
		goto out;
	}
	provision_bin_data = (uint8_t *)netapi_read_file(loadfile,
					&provision_bin_data_size);
	if (provision_bin_data == NULL) {
		printf("failed to read loadfile: %s\n", loadfile);
		goto out;
	}

	if (localos) {
		options |= NETSETUP_PROVISION_ONLINE_CALLER;
	}

	/* NetRequestOfflineDomainJoin */

	status = NetRequestOfflineDomainJoin(provision_bin_data,
					     provision_bin_data_size,
					     options,
					     windows_path);
	free(provision_bin_data);
	if (status != 0 && status != 0x00000a99) {
		/* NERR_JoinPerformedMustRestart */
		printf("failed with: %s\n",
			libnetapi_get_error_string(ctx, status));
		goto out;
	}

 out:
	libnetapi_free(ctx);
	poptFreeContext(pc);

	return status;
}
