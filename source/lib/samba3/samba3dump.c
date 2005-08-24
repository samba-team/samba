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
#include "lib/samba3/samba3.h"
#include "lib/cmdline/popt_common.h"

static NTSTATUS print_policy(struct samba3_policy *ret)
{
	printf("Min password length: %d\n", ret->min_password_length);

	return NT_STATUS_OK;
}

static NTSTATUS print_sam(struct samba3 *samba3)
{
	struct samba3_samaccount *accounts = samba3->samaccounts;
	uint32_t count = samba3->samaccount_count, i;
	
	for (i = 0; i < count; i++) {
		printf("%d: %s\n", accounts[i].user_rid, accounts[i].username);
	}

	return NT_STATUS_OK;
}
 
int main(int argc, char **argv)
{
	int opt;
	const char *libdir = "/var/lib/samba";
	struct samba3 *samba3;
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

	samba3 = samba3_read(libdir, NULL);

	print_sam(samba3);
	print_policy(&samba3->policy);

	poptFreeContext(pc);

	return 0;
}
