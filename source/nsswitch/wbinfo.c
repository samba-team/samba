/* 
   Unix SMB/CIFS implementation.

   Winbind status program.

   Copyright (C) Tim Potter      2000-2002
   Copyright (C) Andrew Bartlett 2002
   
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

static char winbind_separator(void)
{
	struct winbindd_response response;
	static BOOL got_sep;
	static char sep;

	if (got_sep)
		return sep;

	ZERO_STRUCT(response);

	/* Send off request */

	if (winbindd_request(WINBINDD_INFO, NULL, &response) !=
	    NSS_STATUS_SUCCESS) {
		printf("could not obtain winbind separator!\n");
		/* HACK: (this module should not call lp_ funtions) */
		return *lp_winbind_separator();
	}

	sep = response.data.info.winbind_separator;
	got_sep = True;

	if (!sep) {
		printf("winbind separator was NULL!\n");
		/* HACK: (this module should not call lp_ funtions) */
		sep = *lp_winbind_separator();
	}
	
	return sep;
}

static char *get_winbind_domain(void)
{
	struct winbindd_response response;
	static fstring winbind_domain;

	ZERO_STRUCT(response);

	/* Send off request */

	if (winbindd_request(WINBINDD_DOMAIN_NAME, NULL, &response) !=
	    NSS_STATUS_SUCCESS) {
		printf("could not obtain winbind domain name!\n");
		
		/* HACK: (this module should not call lp_ funtions) */
		return lp_workgroup();
	}

	fstrcpy(winbind_domain, response.data.domain_name);

	return winbind_domain;

}

/* Copy of parse_domain_user from winbindd_util.c.  Parse a string of the
   form DOMAIN/user into a domain and a user */

static BOOL parse_wbinfo_domain_user(const char *domuser, fstring domain, 
				     fstring user)
{

	char *p = strchr(domuser,winbind_separator());

	if (!p) {
		fstrcpy(user, domuser);
		fstrcpy(domain, get_winbind_domain());
		return True;
	}
        
	fstrcpy(user, p+1);
	fstrcpy(domain, domuser);
	domain[PTR_DIFF(p, domuser)] = 0;
	strupper(domain);

	return True;
}

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

	if (result != NSS_STATUS_SUCCESS)
		return False;

	for (i = 0; i < response.data.num_entries; i++)
		printf("%d\n", (int)((gid_t *)response.extra_data)[i]);

	SAFE_FREE(response.extra_data);

	return True;
}

/* Convert NetBIOS name to IP */

static BOOL wbinfo_wins_byname(char *name)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	fstrcpy(request.data.winsreq, name);

	if (winbindd_request(WINBINDD_WINS_BYNAME, &request, &response) !=
	    NSS_STATUS_SUCCESS) {
		return False;
	}

	/* Display response */

	printf("%s\n", response.data.winsresp);

	return True;
}

/* Convert IP to NetBIOS name */

static BOOL wbinfo_wins_byip(char *ip)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	fstrcpy(request.data.winsreq, ip);

	if (winbindd_request(WINBINDD_WINS_BYIP, &request, &response) !=
	    NSS_STATUS_SUCCESS) {
		return False;
	}

	/* Display response */

	printf("%s\n", response.data.winsresp);

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
	    NSS_STATUS_SUCCESS)
		return False;

	/* Display response */

	if (response.extra_data) {
		const char *extra_data = (const char *)response.extra_data;

		while(next_token(&extra_data, name, ",", sizeof(fstring)))
			printf("%s\n", name);

		SAFE_FREE(response.extra_data);
	}

	return True;
}


/* show sequence numbers */
static BOOL wbinfo_show_sequence(void)
{
	struct winbindd_response response;

	ZERO_STRUCT(response);

	/* Send request */

	if (winbindd_request(WINBINDD_SHOW_SEQUENCE, NULL, &response) !=
	    NSS_STATUS_SUCCESS)
		return False;

	/* Display response */

	if (response.extra_data) {
		char *extra_data = (char *)response.extra_data;
		printf("%s", extra_data);
		SAFE_FREE(response.extra_data);
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

                if (response.data.auth.nt_status == 0)
                        printf("Secret is good\n");
                else
                        printf("Secret is bad\n0x%08x\n", 
			       response.data.auth.nt_status);

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
	    NSS_STATUS_SUCCESS)
		return False;

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
	    NSS_STATUS_SUCCESS)
		return False;

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
	    NSS_STATUS_SUCCESS)
		return False;

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
	    NSS_STATUS_SUCCESS)
		return False;

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
	    NSS_STATUS_SUCCESS)
		return False;

	/* Display response */

	printf("%s%c%s %d\n", response.data.name.dom_name, 
		 winbind_separator(), response.data.name.name, 
		 response.data.name.type);

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

	parse_wbinfo_domain_user(name, request.data.name.dom_name, 
				 request.data.name.name);

	if (winbindd_request(WINBINDD_LOOKUPNAME, &request, &response) !=
	    NSS_STATUS_SUCCESS)
		return False;

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

	if (response.data.auth.nt_status)
		printf("error code was %s (0x%x)\n", 
		       response.data.auth.nt_status_string, 
		       response.data.auth.nt_status);

        return result == NSS_STATUS_SUCCESS;
}

#ifdef WITH_WINBIND_AUTH_CRAP

/* Authenticate a user with a challenge/response */

static BOOL wbinfo_auth_crap(char *username)
{
	struct winbindd_request request;
	struct winbindd_response response;
        NSS_STATUS result;
        fstring name_user;
        fstring name_domain;
        fstring pass;
        char *p;

	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

        p = strchr(username, '%');

        if (p) {
                *p = 0;
                fstrcpy(pass, p + 1);
	}
		
	parse_wbinfo_domain_user(username, name_domain, name_user);

	fstrcpy(request.data.auth_crap.user, name_user);

	fstrcpy(request.data.auth_crap.domain, name_domain);

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

	if (response.data.auth.nt_status)
		printf("error code was %s (0x%x)\n", 
		       response.data.auth.nt_status_string, 
		       response.data.auth.nt_status);

        return result == NSS_STATUS_SUCCESS;
}

#endif	/* WITH_WINBIND_AUTH_CRAP */

/* Print domain users */

static BOOL print_domain_users(void)
{
	struct winbindd_response response;
	const char *extra_data;
	fstring name;

	/* Send request to winbind daemon */

	ZERO_STRUCT(response);

	if (winbindd_request(WINBINDD_LIST_USERS, NULL, &response) !=
	    NSS_STATUS_SUCCESS)
		return False;

	/* Look through extra data */

	if (!response.extra_data)
		goto done;

	extra_data = (const char *)response.extra_data;

	while(next_token(&extra_data, name, ",", sizeof(fstring)))
		printf("%s\n", name);
	
	SAFE_FREE(response.extra_data);

done:
	if (response.nt_status)
		printf("0x%08x\n", response.nt_status);

	return True;
}

/* Print domain groups */

static BOOL print_domain_groups(void)
{
	struct winbindd_response response;
	const char *extra_data;
	fstring name;

	ZERO_STRUCT(response);

	if (winbindd_request(WINBINDD_LIST_GROUPS, NULL, &response) !=
	    NSS_STATUS_SUCCESS)
		return False;

	/* Look through extra data */

	if (!response.extra_data)
		goto done;

	extra_data = (const char *)response.extra_data;

	while(next_token(&extra_data, name, ",", sizeof(fstring)))
		printf("%s\n", name);

	SAFE_FREE(response.extra_data);

done:
	if (response.nt_status)
		printf("0x%08x\n", response.nt_status);
	
	return True;
}

/* Set the authorised user for winbindd access in secrets.tdb */

static BOOL wbinfo_set_auth_user(char *username)
{
	char *password;
	fstring user, domain;

	/* Separate into user and password */

	parse_wbinfo_domain_user(username, domain, user);

	password = strchr(user, '%');

	if (password) {
		*password = 0;
		password++;
	} else
		password = "";

	/* Store in secrets.tdb */

	secrets_init();

	if (!secrets_store(SECRETS_AUTH_USER, user, 
			   strlen(user) + 1) ||
	    !secrets_store(SECRETS_AUTH_DOMAIN, domain, 
			   strlen(domain) + 1) ||
	    !secrets_store(SECRETS_AUTH_PASSWORD, password,
			   strlen(password) + 1)) {
		fprintf(stderr, "error storing authenticated user info\n");
		return False;
	}

	return True;
}

static BOOL wbinfo_ping(void)
{
        NSS_STATUS result;
	
	result = winbindd_request(WINBINDD_PING, NULL, NULL);

	/* Display response */

        printf("'ping' to winbindd %s\n", 
               (result == NSS_STATUS_SUCCESS) ? "succeeded" : "failed");

        return result == NSS_STATUS_SUCCESS;
}

/* Print program usage */

static void usage(void)
{
	printf("Usage: wbinfo -ug | -n name | -sSY sid | -UG uid/gid | -tm "
               "| -[aA] user%%password\n");
	printf("Version: %s\n", VERSION);
	printf("\t-u\t\t\tlists all domain users\n");
	printf("\t-g\t\t\tlists all domain groups\n");
	printf("\t-n name\t\t\tconverts name to sid\n");
	printf("\t-s sid\t\t\tconverts sid to name\n");
	printf("\t-N name\t\t\tconverts NetBIOS name to IP (WINS)\n");
	printf("\t-I IP\t\t\tconverts IP address to NetBIOS name (WINS)\n");
	printf("\t-U uid\t\t\tconverts uid to sid\n");
	printf("\t-G gid\t\t\tconverts gid to sid\n");
	printf("\t-S sid\t\t\tconverts sid to uid\n");
	printf("\t-Y sid\t\t\tconverts sid to gid\n");
	printf("\t-t\t\t\tcheck shared secret\n");
	printf("\t-m\t\t\tlist trusted domains\n");
	printf("\t-r user\t\t\tget user groups\n");
	printf("\t-a user%%password\tauthenticate user\n");
	printf("\t-A user%%password\tstore user and password used by winbindd (root only)\n");
	printf("\t-p\t\t\t'ping' winbindd to see if it is alive\n");
	printf("\t--sequence\t\tshow sequence numbers of all domains\n");
	printf("\t--set-auth-user DOMAIN\\user%%password\tset password for restrict anonymous\n");
}

/* Main program */

enum {
	OPT_SET_AUTH_USER = 1000,
	OPT_SEQUENCE
};

int main(int argc, char **argv)
{
	extern pstring global_myname;
	int opt;

	poptContext pc;
	static char *string_arg;
	static int int_arg;
	BOOL got_command = False;
	int result = 1;

	struct poptOption long_options[] = {

		/* longName, shortName, argInfo, argPtr, value, descrip, 
		   argDesc */

		{ "help", 'h', POPT_ARG_NONE, 0, 'h' },
		{ "domain-users", 'u', POPT_ARG_NONE, 0, 'u' },
		{ "domain-groups", 'g', POPT_ARG_NONE, 0, 'g' },
		{ "WINS-by-name", 'N', POPT_ARG_STRING, &string_arg, 'N' },
		{ "WINS-by-ip", 'I', POPT_ARG_STRING, &string_arg, 'I' },
		{ "name-to-sid", 'n', POPT_ARG_STRING, &string_arg, 'n' },
		{ "sid-to-name", 's', POPT_ARG_STRING, &string_arg, 's' },
		{ "uid-to-sid", 'U', POPT_ARG_INT, &int_arg, 'U' },
		{ "gid-to-sid", 'G', POPT_ARG_INT, &int_arg, 'G' },
		{ "sid-to-uid", 'S', POPT_ARG_STRING, &string_arg, 'S' },
		{ "sid-to-gid", 'Y', POPT_ARG_STRING, &string_arg, 'Y' },
		{ "check-secret", 't', POPT_ARG_NONE, 0, 't' },
		{ "trusted-domains", 'm', POPT_ARG_NONE, 0, 'm' },
		{ "sequence", 0, POPT_ARG_NONE, 0, OPT_SEQUENCE },
		{ "user-groups", 'r', POPT_ARG_STRING, &string_arg, 'r' },
 		{ "authenticate", 'a', POPT_ARG_STRING, &string_arg, 'a' },
		{ "set-auth-user", 'A', POPT_ARG_STRING, &string_arg, OPT_SET_AUTH_USER },
		{ "ping", 'p', POPT_ARG_NONE, 0, 'p' },
		{ 0, 0, 0, 0 }
	};

	/* Samba client initialisation */

	if (!*global_myname) {
		char *p;

		fstrcpy(global_myname, myhostname());
		p = strchr(global_myname, '.');
		if (p)
			*p = 0;
	}

	TimeInit();

	codepage_initialise(lp_client_code_page());
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

	/* Parse options */

	pc = poptGetContext("wbinfo", argc, (const char **)argv, long_options, 0);

	while((opt = poptGetNextOpt(pc)) != -1) {
		if (got_command) {
			fprintf(stderr, "No more than one command may be specified at once.\n");
			exit(1);
		}
		got_command = True;
	}

	poptFreeContext(pc);

	pc = poptGetContext(NULL, argc, (const char **)argv, long_options, 
			    POPT_CONTEXT_KEEP_FIRST);

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'h':
			usage();
			result = 0;
			goto done;
		case 'u':
			if (!print_domain_users()) {
				printf("Error looking up domain users\n");
				goto done;
			}
			break;
		case 'g':
			if (!print_domain_groups()) {
				printf("Error looking up domain groups\n");
				goto done;
			}
			break;
		case 's':
			if (!wbinfo_lookupsid(string_arg)) {
				printf("Could not lookup sid %s\n", string_arg);
				goto done;
			}
			break;
		case 'n':
			if (!wbinfo_lookupname(string_arg)) {
				printf("Could not lookup name %s\n", string_arg);
				goto done;
			}
			break;
		case 'N':
			if (!wbinfo_wins_byname(string_arg)) {
				printf("Could not lookup WINS by name %s\n", string_arg);
				goto done;
			}
			break;
		case 'I':
			if (!wbinfo_wins_byip(string_arg)) {
				printf("Could not lookup WINS by IP %s\n", string_arg);
				goto done;
			}
			break;
		case 'U':
			if (!wbinfo_uid_to_sid(int_arg)) {
				printf("Could not convert uid %d to sid\n", int_arg);
				goto done;
			}
			break;
		case 'G':
			if (!wbinfo_gid_to_sid(int_arg)) {
				printf("Could not convert gid %d to sid\n",
				       int_arg);
				goto done;
			}
			break;
		case 'S':
			if (!wbinfo_sid_to_uid(string_arg)) {
				printf("Could not convert sid %s to uid\n",
				       string_arg);
				goto done;
			}
			break;
		case 'Y':
			if (!wbinfo_sid_to_gid(string_arg)) {
				printf("Could not convert sid %s to gid\n",
				       string_arg);
				goto done;
			}
			break;
		case 't':
			if (!wbinfo_check_secret()) {
				printf("Could not check secret\n");
				goto done;
			}
			break;
		case 'm':
			if (!wbinfo_list_domains()) {
				printf("Could not list trusted domains\n");
				goto done;
			}
			break;
		case OPT_SEQUENCE:
			if (!wbinfo_show_sequence()) {
				printf("Could not show sequence numbers\n");
				goto done;
			}
			break;
		case 'r':
			if (!wbinfo_get_usergroups(string_arg)) {
				printf("Could not get groups for user %s\n", 
				       string_arg);
				goto done;
			}
			break;
                case 'a': {
                        BOOL got_error = False;

                        if (!wbinfo_auth(string_arg)) {
                                printf("Could not authenticate user %s with "
                                       "plaintext password\n", string_arg);
                                got_error = True;
                        }
#ifdef WITH_WINBIND_AUTH_CRAP
                        if (!wbinfo_auth_crap(string_arg)) {
                                printf("Could not authenticate user %s with "
                                       "challenge/response\n", string_arg);
                                got_error = True;
                        }
#endif
                        if (got_error)
                                goto done;
                        break;
		}
                case 'p': {

                        if (!wbinfo_ping()) {
                                printf("could not ping winbindd!\n");
                                goto done;
			}
                        break;
		}
		case OPT_SET_AUTH_USER:
			if (!(wbinfo_set_auth_user(string_arg)))
				goto done;
			break;
		default:
			fprintf(stderr, "Invalid option\n");
			usage();
			goto done;
		}
	}

	result = 0;

	/* Exit code */

 done:
	poptFreeContext(pc);
	return result;
}
