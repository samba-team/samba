/*
 *  Unix SMB/CIFS implementation.
 *  NetProvisionComputerAccount query
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

#include <netapi.h>

#include "common.h"

int main(int argc, const char **argv)
{
	NET_API_STATUS status;
	const char *domain = NULL;
	const char *machine_name = NULL;
	const char *machine_account_ou = NULL;
	const char *dcname = NULL;
	uint32_t options = 0;
	const char *provision_text_data = NULL;
	int default_password = 0;
	int print_blob = 0;
	const char *savefile = NULL;
	int reuse = 0;

	struct libnetapi_ctx *ctx = NULL;

	poptContext pc;
	int opt;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{ "dcname", 0, POPT_ARG_STRING, &dcname, 'D', "Domain Controller Name", "DCNAME" },
		{ "machine_account_ou", 0, POPT_ARG_STRING, &machine_account_ou, 'D', "LDAP DN for Machine Account OU", "MACHINE_ACCOUNT_OU" },
		{ "defpwd", 0, POPT_ARG_NONE, &default_password, 'D', "Use default password for machine account (not recommended)", "" },
		{ "printblob", 0, POPT_ARG_NONE, &print_blob, 'D', "Print base64 encoded ODJ blob (for Windows answer files)", "" },
		{ "savefile", 0, POPT_ARG_STRING, &savefile, 'D', "Save ODJ blob to file (for Windows answer files)", "FILENAME" },
		{ "reuse", 0, POPT_ARG_NONE, &reuse, 'D', "Reuse machine account", "" },
		POPT_COMMON_LIBNETAPI_EXAMPLES
		POPT_TABLEEND
	};

	status = libnetapi_init(&ctx);
	if (status != 0) {
		return status;
	}

	pc = poptGetContext("provision_computer_account", argc, argv, long_options, 0);

	poptSetOtherOptionHelp(pc, "domain machine_name");
	while((opt = poptGetNextOpt(pc)) != -1) {
	}

	if (!poptPeekArg(pc)) {
		poptPrintHelp(pc, stderr, 0);
		goto out;
	}
	domain = poptGetArg(pc);

	if (!poptPeekArg(pc)) {
		poptPrintHelp(pc, stderr, 0);
		goto out;
	}
	machine_name = poptGetArg(pc);

	if (default_password) {
		options |= NETSETUP_PROVISION_USE_DEFAULT_PASSWORD;
	}
	if (reuse) {
		options |= NETSETUP_PROVISION_REUSE_ACCOUNT;
	}

	/* NetProvisionComputerAccount */

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
		printf("Provision data: %s\n", provision_text_data);
	}

	if (savefile != NULL) {
		status = netapi_save_file_ucs2(savefile, provision_text_data);
		if (status != 0) {
			goto out;
		}
	}

 out:
	libnetapi_free(ctx);
	poptFreeContext(pc);

	return status;
}
