/*
 *  Unix SMB/CIFS implementation.
 *  Offline Domain Join utility
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
	const char *domain = NULL;
	const char *machine_name = NULL;
	const char *windows_path = NULL;
	const char *dcname = NULL;
	const char *loadfile = NULL;
	const char *savefile = NULL;
	const char *machine_account_ou = NULL;
	uint32_t options = 0;
	uint8_t *provision_bin_data = NULL;
	uint32_t provision_bin_data_size = 0;
	const char *provision_text_data = NULL;
	int provision = 0;
	int requestodj = 0;
	int default_password = 0;
	int print_blob = 0;
	int localos = 0;
	int reuse = 0;

	struct libnetapi_ctx *ctx = NULL;
	poptContext pc;
	int opt;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{ "provision", 0, POPT_ARG_NONE, &provision, 'D', "Create computer account in AD", NULL },
		{ "dcname", 0, POPT_ARG_STRING, &dcname, 'D', "Domain Controller Name", "DCNAME" },
		{ "machine_account_ou", 0, POPT_ARG_STRING, &machine_account_ou, 'D', "LDAP DN for Machine Account OU", "MACHINE_ACCOUNT_OU" },
		{ "domain", 0, POPT_ARG_STRING, &domain, 'D', "Domain name", "DOMAIN" },
		{ "machine_name", 0, POPT_ARG_STRING, &machine_name, 'D', "Computer Account Name", "MACHINENAME" },
		{ "defpwd", 0, POPT_ARG_NONE, &default_password, 'D', "Use default password for machine account (not recommended)", "" },
		{ "printblob", 0, POPT_ARG_NONE, &print_blob, 'D', "Print base64 encoded ODJ blob (for Windows answer files)", "" },
		{ "savefile", 0, POPT_ARG_STRING, &savefile, 'D', "Save ODJ blob to file (for Windows answer files)", "FILENAME" },
		{ "reuse", 0, POPT_ARG_NONE, &reuse, 'D', "Reuse machine account", "" },
		{ "requestodj", 0, POPT_ARG_NONE, &requestodj, 'D', "Load offline join data", NULL },
		{ "loadfile", 0, POPT_ARG_STRING, &loadfile, 'D', "Load file from previous provision", "FILENAME" },
		{ "localos", 0, POPT_ARG_NONE, &localos, 'D', "Request local OS to load offline join information", "" },
		POPT_COMMON_LIBNETAPI_EXAMPLES
		POPT_TABLEEND
	};

	status = libnetapi_init(&ctx);
	if (status != 0) {
		return status;
	}

	pc = poptGetContext("djoin", argc, argv, long_options, 0);

	poptSetOtherOptionHelp(pc, "[provision|requestodj]");
	while((opt = poptGetNextOpt(pc)) != -1) {
	}

	if (provision) {

		if (domain == NULL) {
			printf("domain must be defined\n");
			goto out;
		}

		if (machine_name == NULL) {
			printf("machine_name must be defined\n");
			goto out;
		}

		if (default_password) {
			options |= NETSETUP_PROVISION_USE_DEFAULT_PASSWORD;
		}

		if (reuse) {
			options |= NETSETUP_PROVISION_REUSE_ACCOUNT;
		}

		status = NetProvisionComputerAccount(domain,
						     machine_name,
						     machine_account_ou,
						     dcname,
						     options,
						     NULL,
						     0,
						     &provision_text_data);
		if (status != 0) {
			printf("failed with: %s\n",
				libnetapi_get_error_string(ctx, status));
			goto out;
		}

		if (print_blob) {
			printf("Provision Text Data: %s\n", provision_text_data);
		}

		if (savefile != NULL) {
			status = netapi_save_file_ucs2(savefile, provision_text_data);
			if (status != 0) {
				goto out;
			}
		}
	}

	if (requestodj) {

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
	}

 out:
	libnetapi_free(ctx);
	poptFreeContext(pc);

	return status;
}
