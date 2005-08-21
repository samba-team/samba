/* 
   Unix SMB/CIFS implementation.
   Samba3 database dump utility

    Copyright (C) Jelmer Vernooij	2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "lib/samba3/policy.h"
#include "lib/samba3/sam.h"
#include "lib/cmdline/popt_common.h"

static const char *libdir = "/var/lib/samba";

static NTSTATUS print_policy(void)
{
	struct samba3_policy *ret;
	char *policy_file;
	TALLOC_CTX *mem_ctx = talloc_init(NULL);

	policy_file = talloc_asprintf(mem_ctx, "%s/account_policy.tdb", libdir);

	printf("Opening policy file %s\n", policy_file);

	ret = samba3_read_account_policy(mem_ctx, policy_file);

	if (ret == NULL) 
		return NT_STATUS_UNSUCCESSFUL;
	
	printf("Min password length: %d\n", ret->min_password_length);

	talloc_free(mem_ctx);

	return NT_STATUS_OK;
}

static NTSTATUS print_sam(void)
{
	struct samba3_samaccount *accounts;
	uint32_t count, i;
	char *tdbsam_file;
	NTSTATUS status;
	
	asprintf(&tdbsam_file, "%s/passdb.tdb", libdir);

	printf("Opening TDB sam %s\n", tdbsam_file);

	status = samba3_read_tdbsam(NULL, tdbsam_file, &accounts, &count);
	if (NT_STATUS_IS_ERR(status)) {
		fprintf(stderr, "Error reading tdbsam database %s\n", tdbsam_file);
		SAFE_FREE(tdbsam_file);
		return status;
	}
	SAFE_FREE(tdbsam_file);

	for (i = 0; i < count; i++) {
		printf("%d: %s\n", accounts[i].user_rid, accounts[i].username);
	}

	return NT_STATUS_OK;
}
 
int main(int argc, char **argv)
{
	int opt;
	poptContext pc;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{ "libdir", 0, POPT_ARG_STRING, &libdir, 'l', "Set libdir [/var/lib/samba]", "LIBDIR" },
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};

	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,0);

	poptSetOtherOptionHelp(pc, "<smb.conf>");

	while((opt = poptGetNextOpt(pc)) != -1) {
	}

	print_sam();
	print_policy();

	poptFreeContext(pc);

	return 0;
}
