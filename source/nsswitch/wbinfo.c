/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   Winbind status program.

   Copyright (C) Tim Potter 2000
   
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

#include "winbind_nss_config.h"
#include "winbindd.h"

/* Prototypes from common.h */

enum nss_status generic_request(int req_type, 
				struct winbindd_request *request,
				struct winbindd_response *response);

/* Globals */

BOOL do_users, do_groups;

/* Print domain users */

BOOL print_domain_users(void)
{
	struct winbindd_response response;
	fstring name;

	/* Send request to winbind daemon */

	ZERO_STRUCT(response);

	if (generic_request(WINBINDD_LIST_USERS, NULL, &response) ==
	    WINBINDD_ERROR) {
		return False;
	}

	/* Look through extra data */

	if (!response.extra_data) {
		return False;
	}

	while(next_token((char **)&response.extra_data, name, ",", 
			 sizeof(fstring))) {
		printf("%s\n", name);
	}
	
	return True;
}

/* Print domain groups */

BOOL print_domain_groups(void)
{
	struct winbindd_response response;
	fstring name;

	ZERO_STRUCT(response);

	if (generic_request(WINBINDD_LIST_GROUPS, NULL, &response) ==
	    WINBINDD_ERROR) {
		return False;
	}

	/* Look through extra data */

	if (!response.extra_data) {
		return False;
	}

	while(next_token((char **)&response.extra_data, name, ",", 
			 sizeof(fstring))) {
		printf("%s\n", name);
	}
	
	return True;
}

/* Print program usage */

void usage(void)
{
}

/* Main program */

int main(int argc, char **argv)
{
	int opt;

	/* Parse command line options */

	while ((opt = getopt(argc, argv, "ug")) != EOF) {
		switch (opt) {
		case 'u':
			do_users = True;
			break;
		case 'g':
			do_groups = True;
			break;
		default:
			usage();
			exit(1);
		}
	}

	/* Process options */

	if (do_users && print_domain_users()) {
		DEBUG(0, ("Error fetching domain users\n"));
		return 1;

	}

	if (do_groups && !print_domain_groups()) {
		DEBUG(0, ("Error fetching domain groups\n"));
		return 1;
	}

	/* Clean exit */

	return 0;
}
