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

#include "includes.h"
#include "winbindd.h"
#include "debug.h"

/* Prototypes from common.h */

NSS_STATUS winbindd_request(int req_type, 
			    struct winbindd_request *request,
			    struct winbindd_response *response);

/* List groups a user is a member of */

static BOOL wbinfo_get_usergroups(char *user)
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;
	int i;
	
	ZERO_STRUCT(response);

	/* Send request */

	fstrcpy(request.data.username, user);

	result = winbindd_request(WINBINDD_GETGROUPS, &request, &response);

	if (result != NSS_STATUS_SUCCESS) {
		return False;
	}

	for (i = 0; i < response.data.num_entries; i++) {
		printf("%d\n", (int)((gid_t *)response.extra_data)[i]);
	}

	return True;
}

/* List trusted domains */

static BOOL wbinfo_list_domains(void)
{
	struct winbindd_response response;
	fstring name;

	ZERO_STRUCT(response);

	/* Send request */

	if (winbindd_request(WINBINDD_LIST_TRUSTDOM, NULL, &response) !=
	    NSS_STATUS_SUCCESS) {
		return False;
	}

	/* Display response */

	if (response.extra_data) {
		while(next_token((char **)&response.extra_data, name, ",", 
				 sizeof(fstring))) {
			printf("%s\n", name);
		}
	}

	return True;
}

/* Check trust account password */

static BOOL wbinfo_check_secret(void)
{
        struct winbindd_response response;
        BOOL result;

        ZERO_STRUCT(response);

        result = winbindd_request(WINBINDD_CHECK_MACHACC, NULL, &response) ==
                NSS_STATUS_SUCCESS;

        if (result) {

                if (response.data.num_entries == 0) {
                        printf("Secret is good\n");
                } else {
                        printf("Secret is bad\n0x%08x\n", 
			       response.data.num_entries);
                }

                return True;
        }

        return False;
}

/* Convert uid to sid */

static BOOL wbinfo_uid_to_sid(uid_t uid)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	request.data.uid = uid;
	if (winbindd_request(WINBINDD_UID_TO_SID, &request, &response) !=
	    NSS_STATUS_SUCCESS) {
		return False;
	}

	/* Display response */

	printf("%s\n", response.data.sid.sid);

	return True;
}

/* Convert gid to sid */

static BOOL wbinfo_gid_to_sid(gid_t gid)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	request.data.gid = gid;
	if (winbindd_request(WINBINDD_GID_TO_SID, &request, &response) !=
	    NSS_STATUS_SUCCESS) {
		return False;
	}

	/* Display response */

	printf("%s\n", response.data.sid.sid);

	return True;
}

/* Convert sid to uid */

static BOOL wbinfo_sid_to_uid(char *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	fstrcpy(request.data.sid, sid);
	if (winbindd_request(WINBINDD_SID_TO_UID, &request, &response) !=
	    NSS_STATUS_SUCCESS) {
		return False;
	}

	/* Display response */

	printf("%d\n", (int)response.data.uid);

	return True;
}

static BOOL wbinfo_sid_to_gid(char *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	fstrcpy(request.data.sid, sid);
	if (winbindd_request(WINBINDD_SID_TO_GID, &request, &response) !=
	    NSS_STATUS_SUCCESS) {
		return False;
	}

	/* Display response */

	printf("%d\n", (int)response.data.gid);

	return True;
}

/* Convert sid to string */

static BOOL wbinfo_lookupsid(char *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send off request */

	fstrcpy(request.data.sid, sid);
	if (winbindd_request(WINBINDD_LOOKUPSID, &request, &response) !=
	    NSS_STATUS_SUCCESS) {
		return False;
	}

	/* Display response */

	printf("%s %d\n", response.data.name.name, response.data.name.type);

	return True;
}

/* Convert string to sid */

static BOOL wbinfo_lookupname(char *name)
{
	struct winbindd_request request;
	struct winbindd_response response;

	/*
	 * Don't do the lookup if the name has no separator.
	 */
 
	if (!strchr(name, *lp_winbind_separator()))
		return False;

	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.data.name, name);
	if (winbindd_request(WINBINDD_LOOKUPNAME, &request, &response) !=
	    NSS_STATUS_SUCCESS) {
		return False;
	}

	/* Display response */

	printf("%s %d\n", response.data.sid.sid, response.data.sid.type);

	return True;
}

/* Authenticate a user with a plaintext password */

static BOOL wbinfo_auth(char *username)
{
	struct winbindd_request request;
	struct winbindd_response response;
        NSS_STATUS result;
        char *p;

	/*
	 * Don't do the lookup if the name has no separator.
	 */
 
	if (!strchr(username, *lp_winbind_separator()))
		return False;

	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

        p = strchr(username, '%');

        if (p) {
                *p = 0;
                fstrcpy(request.data.auth.user, username);
                fstrcpy(request.data.auth.pass, p + 1);
                *p = '%';
        } else
                fstrcpy(request.data.auth.user, username);

	result = winbindd_request(WINBINDD_PAM_AUTH, &request, &response);

	/* Display response */

        printf("plaintext password authentication %s\n", 
               (result == NSS_STATUS_SUCCESS) ? "succeeded" : "failed");

        return result == NSS_STATUS_SUCCESS;
}

/* Authenticate a user with a challenge/response */

static BOOL wbinfo_auth_crap(char *username)
{
	struct winbindd_request request;
	struct winbindd_response response;
        NSS_STATUS result;
        fstring pass;
        char *p;

	/*
	 * Don't do the lookup if the name has no separator.
	 */
 
	if (!strchr(username, *lp_winbind_separator()))
		return False;

	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

        p = strchr(username, '%');

        if (p) {
                *p = 0;
                fstrcpy(request.data.auth_crap.user, username);
                fstrcpy(pass, p + 1);
                *p = '%';
        } else
                fstrcpy(request.data.auth_crap.user, username);

	generate_random_buffer(request.data.auth_crap.chal, 8, False);
        
        SMBencrypt((uchar *)pass, request.data.auth_crap.chal, 
                   (uchar *)request.data.auth_crap.lm_resp);
        SMBNTencrypt((uchar *)pass, request.data.auth_crap.chal,
                     (uchar *)request.data.auth_crap.nt_resp);

        request.data.auth_crap.lm_resp_len = 24;
        request.data.auth_crap.nt_resp_len = 24;

	result = winbindd_request(WINBINDD_PAM_AUTH_CRAP, &request, &response);

	/* Display response */

        printf("challenge/response password authentication %s\n", 
               (result == NSS_STATUS_SUCCESS) ? "succeeded" : "failed");

        return result == NSS_STATUS_SUCCESS;
}

/* Print domain users */

static BOOL print_domain_users(void)
{
	struct winbindd_response response;
	fstring name;

	/* Send request to winbind daemon */

	ZERO_STRUCT(response);

	if (winbindd_request(WINBINDD_LIST_USERS, NULL, &response) !=
	    NSS_STATUS_SUCCESS) {
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

	if (winbindd_request(WINBINDD_LIST_GROUPS, NULL, &response) !=
	    NSS_STATUS_SUCCESS) {
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

/* Set the authorised user for winbindd access in secrets.tdb */

static BOOL wbinfo_set_auth_user(char *username)
{
	char *password;

	/* Separate into user and password */

	password = strchr(username, '%');

	if (password) {
		*password = 0;
		password++;
	} else
		password = "";

	/* Store in secrets.tdb */

	if (!secrets_init() ||
	    !secrets_store(SECRETS_AUTH_USER, username, strlen(username) + 1) ||
	    !secrets_store(SECRETS_AUTH_PASSWORD, password, strlen(password) + 1)) {
		fprintf(stderr, "error storing authenticated user info\n");
		return False;
	}

	return True;
}

/* Print program usage */

static void usage(void)
{
	printf("Usage: wbinfo -ug | -n name | -sSY sid | -UG uid/gid | -tm "
               "| -aA user%%password\n");
	printf("\t-u\t\t\tlists all domain users\n");
	printf("\t-g\t\t\tlists all domain groups\n");
	printf("\t-n name\t\t\tconverts name to sid\n");
	printf("\t-s sid\t\t\tconverts sid to name\n");
	printf("\t-U uid\t\t\tconverts uid to sid\n");
	printf("\t-G gid\t\t\tconverts gid to sid\n");
	printf("\t-S sid\t\t\tconverts sid to uid\n");
	printf("\t-Y sid\t\t\tconverts sid to gid\n");
	printf("\t-t\t\t\tcheck shared secret\n");
	printf("\t-m\t\t\tlist trusted domains\n");
	printf("\t-r user\t\t\tget user groups\n");
	printf("\t-a user%%password\tauthenticate user\n");
	printf("\t-A user%%password\tstore session setup auth password\n");
}

/* Main program */

int main(int argc, char **argv)
{
	extern pstring global_myname;
	int opt;

	/* Samba client initialisation */

	if (!*global_myname) {
		char *p;

		fstrcpy(global_myname, myhostname());
		p = strchr(global_myname, '.');
		if (p) {
			*p = 0;
		}
	}

	TimeInit();

	charset_initialise();

	if (!lp_load(CONFIGFILE, True, False, False)) {
		fprintf(stderr, "wbinfo: error opening config file %s. Error was %s\n",
			CONFIGFILE, strerror(errno));
		exit(1);
	}
	
	load_interfaces();

	/* Parse command line options */

	if (argc == 1) {
		usage();
		return 1;
	}

	while ((opt = getopt(argc, argv, "ugs:n:U:G:S:Y:tmr:a:A:")) != EOF) {
		switch (opt) {
		case 'u':
			if (!print_domain_users()) {
				printf("Error looking up domain users\n");
				return 1;
			}
			break;
		case 'g':
			if (!print_domain_groups()) {
				printf("Error looking up domain groups\n");
				return 1;
			}
			break;
		case 's':
			if (!wbinfo_lookupsid(optarg)) {
				printf("Could not lookup sid %s\n", optarg);
				return 1;
			}
			break;
		case 'n':
			if (!wbinfo_lookupname(optarg)) {
				printf("Could not lookup name %s\n", optarg);
				return 1;
			}
			break;
		case 'U':
			if (!wbinfo_uid_to_sid(atoi(optarg))) {
				printf("Could not convert uid %s to sid\n",
				       optarg);
				return 1;
			}
			break;
		case 'G':
			if (!wbinfo_gid_to_sid(atoi(optarg))) {
				printf("Could not convert gid %s to sid\n",
				       optarg);
				return 1;
			}
			break;
		case 'S':
			if (!wbinfo_sid_to_uid(optarg)) {
				printf("Could not convert sid %s to uid\n",
				       optarg);
				return 1;
			}
			break;
		case 'Y':
			if (!wbinfo_sid_to_gid(optarg)) {
				printf("Could not convert sid %s to gid\n",
				       optarg);
				return 1;
			}
			break;
		case 't':
			if (!wbinfo_check_secret()) {
				printf("Could not check secret\n");
				return 1;
			}
			break;
		case 'm':
			if (!wbinfo_list_domains()) {
				printf("Could not list trusted domains\n");
				return 1;
			}
			break;
		case 'r':
			if (!wbinfo_get_usergroups(optarg)) {
				printf("Could not get groups for user %s\n", 
				       optarg);
				return 1;
			}
			break;
                case 'a': {
                        BOOL got_error = False;

                        if (!wbinfo_auth(optarg)) {
                                printf("Could not authenticate user %s with "
                                       "plaintext password\n", optarg);
                                got_error = True;
                        }

                        if (!wbinfo_auth_crap(optarg)) {
                                printf("Could not authenticate user %s with "
                                       "challenge/response\n", optarg);
                                got_error = True;
                        }

                        if (got_error)
                                return 1;
                        break;
				
                }
		case 'A': {
			if (!(wbinfo_set_auth_user(optarg))) {
				return 1;
			}
			break;
		}
                      /* Invalid option */

		default:
			usage();
			return 1;
		}
	}
	
	/* Clean exit */

	return 0;
}
