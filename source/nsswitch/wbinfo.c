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

BOOL do_users, do_groups, do_lookupsid, do_lookupname;

/* Convert sid to string */

static BOOL wbinfo_lookupsid(char *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;

	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.data.sid, sid);
	if (generic_request(WINBINDD_LOOKUPSID, &request, &response) ==
	    WINBINDD_ERROR) {
		return False;
	}

	/* Display response */

	printf("%s\n", response.data.name);

	return True;
}

/* Convert string to sid */

static BOOL wbinfo_lookupname(char *name)
{
	struct winbindd_request request;
	struct winbindd_response response;

	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.data.name, name);
	if (generic_request(WINBINDD_LOOKUPNAME, &request, &response) ==
	    WINBINDD_ERROR) {
		return False;
	}

	/* Display response */

	printf("%s\n", response.data.sid);

	return True;
}

/* Print domain users */

static BOOL print_domain_users(void)
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

static BOOL print_domain_groups(void)
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

static void usage(void)
{
	printf("Usage: wbinfo -u | -g | -n name | -s sid\n\n");
	printf("\t-u\tlists all domain users\n");
	printf("\t-g\tlists all domain groups\n");
	printf("\t-n name\tconverts name to sid\n");
	printf("\t-s sid\tconverts sid to name\n");
}

/* Main program */

int main(int argc, char **argv)
{
	int opt;

	/* Parse command line options */

	while ((opt = getopt(argc, argv, "ugs:n:")) != EOF) {
		switch (opt) {
		case 'u':
			if (!print_domain_users()) {
				printf("Error looking up domain users\n");
			}
			break;
		case 'g':
			if (!print_domain_groups()) {
				printf("Error looking up domain groups\n");
			}
			break;
		case 's':
			if (!wbinfo_lookupsid(optarg)) {
				printf("Could not lookup sid %s\n", optarg);
			}
			break;
		case 'n':
			if (!wbinfo_lookupname(optarg)) {
				printf("Could not lookup name %s\n", optarg);
			}
			break;
		default:
			usage();
			exit(1);
		}
	}

	/* Clean exit */

	return 0;
}
