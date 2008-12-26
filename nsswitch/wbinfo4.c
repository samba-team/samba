/*
   Unix SMB/CIFS implementation.

   Winbind status program.

   Copyright (C) Tim Potter      2000-2003
   Copyright (C) Andrew Bartlett 2002-2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "winbind_client.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "libcli/auth/libcli_auth.h"
#include "libcli/security/security.h"
#include "lib/cmdline/popt_common.h"
#include "dynconfig/dynconfig.h"
#include "param/param.h"

#ifndef fstrcpy
#define fstrcpy(d,s) safe_strcpy((d),(s),sizeof(fstring)-1)
#endif

extern int winbindd_fd;

static char winbind_separator_int(bool strict)
{
	struct winbindd_response response;
	static bool got_sep;
	static char sep;

	if (got_sep)
		return sep;

	ZERO_STRUCT(response);

	/* Send off request */

	if (winbindd_request_response(WINBINDD_INFO, NULL, &response) !=
	    NSS_STATUS_SUCCESS) {
		d_fprintf(stderr, "could not obtain winbind separator!\n");
		if (strict) {
			return 0;
		}
		/* HACK: (this module should not call lp_ funtions) */
		return *lp_winbind_separator(cmdline_lp_ctx);
	}

	sep = response.data.info.winbind_separator;
	got_sep = true;

	if (!sep) {
		d_fprintf(stderr, "winbind separator was NULL!\n");
		if (strict) {
			return 0;
		}
		/* HACK: (this module should not call lp_ funtions) */
		sep = *lp_winbind_separator(cmdline_lp_ctx);
	}

	return sep;
}

static char winbind_separator(void)
{
	return winbind_separator_int(false);
}

static const char *get_winbind_domain(void)
{
	struct winbindd_response response;
	static fstring winbind_domain;

	ZERO_STRUCT(response);

	/* Send off request */

	if (winbindd_request_response(WINBINDD_DOMAIN_NAME, NULL, &response) !=
	    NSS_STATUS_SUCCESS) {
		d_fprintf(stderr, "could not obtain winbind domain name!\n");

		/* HACK: (this module should not call lp_ funtions) */
		return lp_workgroup(cmdline_lp_ctx);
	}

	fstrcpy(winbind_domain, response.data.domain_name);

	return winbind_domain;

}

/* Copy of parse_domain_user from winbindd_util.c.  Parse a string of the
   form DOMAIN/user into a domain and a user */

static bool parse_wbinfo_domain_user(const char *domuser, fstring domain,
				     fstring user)
{

	char *p = strchr(domuser,winbind_separator());

	if (!p) {
		fstrcpy(user, domuser);
		fstrcpy(domain, get_winbind_domain());
		return true;
	}

	fstrcpy(user, p+1);
	fstrcpy(domain, domuser);
	domain[PTR_DIFF(p, domuser)] = 0;
	strupper_m(domain);

	return true;
}

/* pull pwent info for a given user */

static bool wbinfo_get_userinfo(char *user)
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	fstrcpy(request.data.username, user);

	result = winbindd_request_response(WINBINDD_GETPWNAM, &request, &response);

	if (result != NSS_STATUS_SUCCESS)
		return false;

	d_printf( "%s:%s:%d:%d:%s:%s:%s\n",
			  response.data.pw.pw_name,
			  response.data.pw.pw_passwd,
			  response.data.pw.pw_uid,
			  response.data.pw.pw_gid,
			  response.data.pw.pw_gecos,
			  response.data.pw.pw_dir,
			  response.data.pw.pw_shell );

	return true;
}

/* pull pwent info for a given uid */
static bool wbinfo_get_uidinfo(int uid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	request.data.uid = uid;

	result = winbindd_request_response(WINBINDD_GETPWUID, &request, &response);

	if (result != NSS_STATUS_SUCCESS)
		return false;

	d_printf( "%s:%s:%d:%d:%s:%s:%s\n",
		response.data.pw.pw_name,
		response.data.pw.pw_passwd,
		response.data.pw.pw_uid,
		response.data.pw.pw_gid,
		response.data.pw.pw_gecos,
		response.data.pw.pw_dir,
		response.data.pw.pw_shell );

	return true;
}

/* pull grent for a given group */
static bool wbinfo_get_groupinfo(char *group)
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	fstrcpy(request.data.groupname, group);

	result = winbindd_request_response(WINBINDD_GETGRNAM, &request,
				  &response);

	if ( result != NSS_STATUS_SUCCESS)
		return false;

	d_printf( "%s:%s:%d\n",
		  response.data.gr.gr_name,
		  response.data.gr.gr_passwd,
		  response.data.gr.gr_gid );

	return true;
}

/* pull grent for a given gid */
static bool wbinfo_get_gidinfo(int gid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	request.data.gid = gid;

	result = winbindd_request_response(WINBINDD_GETGRGID, &request,
				  &response);

	if ( result != NSS_STATUS_SUCCESS)
		return false;

	d_printf( "%s:%s:%d\n",
		  response.data.gr.gr_name,
		  response.data.gr.gr_passwd,
		  response.data.gr.gr_gid );

	return true;
}

/* List groups a user is a member of */

static bool wbinfo_get_usergroups(char *user)
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;
	int i;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	fstrcpy(request.data.username, user);

	result = winbindd_request_response(WINBINDD_GETGROUPS, &request, &response);

	if (result != NSS_STATUS_SUCCESS)
		return false;

	for (i = 0; i < response.data.num_entries; i++)
		d_printf("%d\n", (int)((gid_t *)response.extra_data.data)[i]);

	SAFE_FREE(response.extra_data.data);

	return true;
}


/* List group SIDs a user SID is a member of */
static bool wbinfo_get_usersids(char *user_sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;
	int i;
	const char *s;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */
	fstrcpy(request.data.sid, user_sid);

	result = winbindd_request_response(WINBINDD_GETUSERSIDS, &request, &response);

	if (result != NSS_STATUS_SUCCESS)
		return false;

	s = (const char *)response.extra_data.data;
	for (i = 0; i < response.data.num_entries; i++) {
		d_printf("%s\n", s);
		s += strlen(s) + 1;
	}

	SAFE_FREE(response.extra_data.data);

	return true;
}

static bool wbinfo_get_userdomgroups(const char *user_sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */
	fstrcpy(request.data.sid, user_sid);

	result = winbindd_request_response(WINBINDD_GETUSERDOMGROUPS, &request,
				  &response);

	if (result != NSS_STATUS_SUCCESS)
		return false;

	if (response.data.num_entries != 0)
		printf("%s", (char *)response.extra_data.data);

	SAFE_FREE(response.extra_data.data);

	return true;
}

/* Convert NetBIOS name to IP */

static bool wbinfo_wins_byname(char *name)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	fstrcpy(request.data.winsreq, name);

	if (winbindd_request_response(WINBINDD_WINS_BYNAME, &request, &response) !=
	    NSS_STATUS_SUCCESS) {
		return false;
	}

	/* Display response */

	d_printf("%s\n", response.data.winsresp);

	return true;
}

/* Convert IP to NetBIOS name */

static bool wbinfo_wins_byip(char *ip)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	fstrcpy(request.data.winsreq, ip);

	if (winbindd_request_response(WINBINDD_WINS_BYIP, &request, &response) !=
	    NSS_STATUS_SUCCESS) {
		return false;
	}

	/* Display response */

	d_printf("%s\n", response.data.winsresp);

	return true;
}

/* List trusted domains */

static bool wbinfo_list_domains(bool list_all_domains)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	request.data.list_all_domains = list_all_domains;

	if (winbindd_request_response(WINBINDD_LIST_TRUSTDOM, &request, &response) !=
	    NSS_STATUS_SUCCESS)
		return false;

	/* Display response */

	if (response.extra_data.data) {
		const char *extra_data = (char *)response.extra_data.data;
		fstring name;
		char *p;

		while(next_token(&extra_data, name, "\n", sizeof(fstring))) {
			p = strchr(name, '\\');
			if (p == 0) {
				d_fprintf(stderr, "Got invalid response: %s\n",
					 extra_data);
				return false;
			}
			*p = 0;
			d_printf("%s\n", name);
		}

		SAFE_FREE(response.extra_data.data);
	}

	return true;
}

/* List own domain */

static bool wbinfo_list_own_domain(void)
{
	d_printf("%s\n", get_winbind_domain());

	return true;
}

/* show sequence numbers */
static bool wbinfo_show_sequence(const char *domain)
{
	struct winbindd_request  request;
	struct winbindd_response response;

	ZERO_STRUCT(response);
	ZERO_STRUCT(request);

	if ( domain )
		fstrcpy( request.domain_name, domain );

	/* Send request */

	if (winbindd_request_response(WINBINDD_SHOW_SEQUENCE, &request, &response) !=
	    NSS_STATUS_SUCCESS)
		return false;

	/* Display response */

	if (response.extra_data.data) {
		char *extra_data = (char *)response.extra_data.data;
		d_printf("%s", extra_data);
		SAFE_FREE(response.extra_data.data);
	}

	return true;
}

/* Show domain info */

static bool wbinfo_domain_info(const char *domain_name)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	if ((strequal(domain_name, ".")) || (domain_name[0] == '\0'))
		fstrcpy(request.domain_name, get_winbind_domain());
	else
		fstrcpy(request.domain_name, domain_name);

	/* Send request */

	if (winbindd_request_response(WINBINDD_DOMAIN_INFO, &request, &response) !=
	    NSS_STATUS_SUCCESS)
		return false;

	/* Display response */

	d_printf("Name              : %s\n", response.data.domain_info.name);
	d_printf("Alt_Name          : %s\n", response.data.domain_info.alt_name);

	d_printf("SID               : %s\n", response.data.domain_info.sid);

	d_printf("Active Directory  : %s\n",
		 response.data.domain_info.active_directory ? "Yes" : "No");
	d_printf("Native            : %s\n",
		 response.data.domain_info.native_mode ? "Yes" : "No");

	d_printf("Primary           : %s\n",
		 response.data.domain_info.primary ? "Yes" : "No");

	return true;
}

/* Get a foreign DC's name */
static bool wbinfo_getdcname(const char *domain_name)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.domain_name, domain_name);

	/* Send request */

	if (winbindd_request_response(WINBINDD_GETDCNAME, &request, &response) !=
	    NSS_STATUS_SUCCESS) {
		d_fprintf(stderr, "Could not get dc name for %s\n", domain_name);
		return false;
	}

	/* Display response */

	d_printf("%s\n", response.data.dc_name);

	return true;
}

/* Check trust account password */

static bool wbinfo_check_secret(void)
{
        struct winbindd_response response;
        NSS_STATUS result;

        ZERO_STRUCT(response);

        result = winbindd_request_response(WINBINDD_CHECK_MACHACC, NULL, &response);

	d_printf("checking the trust secret via RPC calls %s\n",
		 (result == NSS_STATUS_SUCCESS) ? "succeeded" : "failed");

	if (result != NSS_STATUS_SUCCESS)
		d_fprintf(stderr, "error code was %s (0x%x)\n",
			 response.data.auth.nt_status_string,
			 response.data.auth.nt_status);

	return result == NSS_STATUS_SUCCESS;
}

/* Convert uid to sid */

static bool wbinfo_uid_to_sid(uid_t uid)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	request.data.uid = uid;

	if (winbindd_request_response(WINBINDD_UID_TO_SID, &request, &response) !=
	    NSS_STATUS_SUCCESS)
		return false;

	/* Display response */

	d_printf("%s\n", response.data.sid.sid);

	return true;
}

/* Convert gid to sid */

static bool wbinfo_gid_to_sid(gid_t gid)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	request.data.gid = gid;

	if (winbindd_request_response(WINBINDD_GID_TO_SID, &request, &response) !=
	    NSS_STATUS_SUCCESS)
		return false;

	/* Display response */

	d_printf("%s\n", response.data.sid.sid);

	return true;
}

/* Convert sid to uid */

static bool wbinfo_sid_to_uid(char *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	fstrcpy(request.data.sid, sid);

	if (winbindd_request_response(WINBINDD_SID_TO_UID, &request, &response) !=
	    NSS_STATUS_SUCCESS)
		return false;

	/* Display response */

	d_printf("%d\n", (int)response.data.uid);

	return true;
}

static bool wbinfo_sid_to_gid(char *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	fstrcpy(request.data.sid, sid);

	if (winbindd_request_response(WINBINDD_SID_TO_GID, &request, &response) !=
	    NSS_STATUS_SUCCESS)
		return false;

	/* Display response */

	d_printf("%d\n", (int)response.data.gid);

	return true;
}

static const char *sid_type_lookup(enum lsa_SidType r)
{
	switch (r) {
		case SID_NAME_USE_NONE: return "SID_NAME_USE_NONE"; break;
		case SID_NAME_USER: return "SID_NAME_USER"; break;
		case SID_NAME_DOM_GRP: return "SID_NAME_DOM_GRP"; break;
		case SID_NAME_DOMAIN: return "SID_NAME_DOMAIN"; break;
		case SID_NAME_ALIAS: return "SID_NAME_ALIAS"; break;
		case SID_NAME_WKN_GRP: return "SID_NAME_WKN_GRP"; break;
		case SID_NAME_DELETED: return "SID_NAME_DELETED"; break;
		case SID_NAME_INVALID: return "SID_NAME_INVALID"; break;
		case SID_NAME_UNKNOWN: return "SID_NAME_UNKNOWN"; break;
		case SID_NAME_COMPUTER: return "SID_NAME_COMPUTER"; break;
	}
	return "Invalid sid type\n";
}

/* Convert sid to string */

static bool wbinfo_lookupsid(char *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send off request */

	fstrcpy(request.data.sid, sid);

	if (winbindd_request_response(WINBINDD_LOOKUPSID, &request, &response) !=
	    NSS_STATUS_SUCCESS)
		return false;

	/* Display response */

	d_printf("%s%c%s %s\n", response.data.name.dom_name,
		 winbind_separator(), response.data.name.name,
		 sid_type_lookup(response.data.name.type));

	return true;
}

/* Convert string to sid */

static bool wbinfo_lookupname(char *name)
{
	struct winbindd_request request;
	struct winbindd_response response;

	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	parse_wbinfo_domain_user(name, request.data.name.dom_name,
				 request.data.name.name);

	if (winbindd_request_response(WINBINDD_LOOKUPNAME, &request, &response) !=
	    NSS_STATUS_SUCCESS)
		return false;

	/* Display response */

	d_printf("%s %s (%d)\n", response.data.sid.sid, sid_type_lookup(response.data.sid.type), response.data.sid.type);

	return true;
}

/* Authenticate a user with a plaintext password */

static bool wbinfo_auth_krb5(char *username, const char *cctype, uint32_t flags)
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

	request.flags = flags;

	fstrcpy(request.data.auth.krb5_cc_type, cctype);

	request.data.auth.uid = geteuid();

	result = winbindd_request_response(WINBINDD_PAM_AUTH, &request, &response);

	/* Display response */

	d_printf("plaintext kerberos password authentication for [%s] %s (requesting cctype: %s)\n",
		username, (result == NSS_STATUS_SUCCESS) ? "succeeded" : "failed", cctype);

	if (response.data.auth.nt_status)
		d_fprintf(stderr, "error code was %s (0x%x)\nerror messsage was: %s\n",
			 response.data.auth.nt_status_string,
			 response.data.auth.nt_status,
			 response.data.auth.error_string);

	if (result == NSS_STATUS_SUCCESS) {

		if (request.flags & WBFLAG_PAM_INFO3_TEXT) {
			if (response.data.auth.info3.user_flgs & NETLOGON_CACHED_ACCOUNT) {
				d_printf("user_flgs: NETLOGON_CACHED_ACCOUNT\n");
			}
		}

		if (response.data.auth.krb5ccname[0] != '\0') {
			d_printf("credentials were put in: %s\n", response.data.auth.krb5ccname);
		} else {
			d_printf("no credentials cached\n");
		}
	}

	return result == NSS_STATUS_SUCCESS;
}

/* Authenticate a user with a plaintext password */

static bool wbinfo_auth(char *username)
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

	result = winbindd_request_response(WINBINDD_PAM_AUTH, &request, &response);

	/* Display response */

        d_printf("plaintext password authentication %s\n",
               (result == NSS_STATUS_SUCCESS) ? "succeeded" : "failed");

	if (response.data.auth.nt_status)
		d_fprintf(stderr, "error code was %s (0x%x)\nerror messsage was: %s\n",
			 response.data.auth.nt_status_string,
			 response.data.auth.nt_status,
			 response.data.auth.error_string);

        return result == NSS_STATUS_SUCCESS;
}

/* Authenticate a user with a challenge/response */

static bool wbinfo_auth_crap(struct loadparm_context *lp_ctx, char *username)
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

	request.data.auth_crap.logon_parameters = MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT | MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT;

	fstrcpy(request.data.auth_crap.user, name_user);

	fstrcpy(request.data.auth_crap.domain,
			      name_domain);

	generate_random_buffer(request.data.auth_crap.chal, 8);

	if (lp_client_ntlmv2_auth(lp_ctx)) {
		DATA_BLOB server_chal;
		DATA_BLOB names_blob;

		DATA_BLOB lm_response;
		DATA_BLOB nt_response;

		TALLOC_CTX *mem_ctx;
		mem_ctx = talloc_new(NULL);
		if (mem_ctx == NULL) {
			d_printf("talloc_new failed\n");
			return false;
		}

		server_chal = data_blob(request.data.auth_crap.chal, 8);

		/* Pretend this is a login to 'us', for blob purposes */
		names_blob = NTLMv2_generate_names_blob(mem_ctx, lp_netbios_name(lp_ctx), lp_workgroup(lp_ctx));

		if (!SMBNTLMv2encrypt(mem_ctx, name_user, name_domain, pass, &server_chal,
				      &names_blob,
				      &lm_response, &nt_response, NULL, NULL)) {
			data_blob_free(&names_blob);
			data_blob_free(&server_chal);
			return false;
		}
		data_blob_free(&names_blob);
		data_blob_free(&server_chal);

		memcpy(request.data.auth_crap.nt_resp, nt_response.data,
		       MIN(nt_response.length,
			   sizeof(request.data.auth_crap.nt_resp)));
		request.data.auth_crap.nt_resp_len = nt_response.length;

		memcpy(request.data.auth_crap.lm_resp, lm_response.data,
		       MIN(lm_response.length,
			   sizeof(request.data.auth_crap.lm_resp)));
		request.data.auth_crap.lm_resp_len = lm_response.length;

		data_blob_free(&nt_response);
		data_blob_free(&lm_response);

	} else {
		if (lp_client_lanman_auth(lp_ctx)
		    && SMBencrypt(pass, request.data.auth_crap.chal,
			       (unsigned char *)request.data.auth_crap.lm_resp)) {
			request.data.auth_crap.lm_resp_len = 24;
		} else {
			request.data.auth_crap.lm_resp_len = 0;
		}
		SMBNTencrypt(pass, request.data.auth_crap.chal,
			     (unsigned char *)request.data.auth_crap.nt_resp);

		request.data.auth_crap.nt_resp_len = 24;
	}

	result = winbindd_request_response(WINBINDD_PAM_AUTH_CRAP, &request, &response);

	/* Display response */

        d_printf("challenge/response password authentication %s\n",
               (result == NSS_STATUS_SUCCESS) ? "succeeded" : "failed");

	if (response.data.auth.nt_status)
		d_fprintf(stderr, "error code was %s (0x%x)\nerror messsage was: %s\n",
			 response.data.auth.nt_status_string,
			 response.data.auth.nt_status,
			 response.data.auth.error_string);

        return result == NSS_STATUS_SUCCESS;
}

/* Print domain users */

static bool print_domain_users(const char *domain)
{
	struct winbindd_request request;
	struct winbindd_response response;
	const char *extra_data;
	fstring name;

	/* Send request to winbind daemon */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	if (domain) {
		/* '.' is the special sign for our own domain */
		if ( strequal(domain, ".") )
			fstrcpy( request.domain_name, get_winbind_domain() );
		else
			fstrcpy( request.domain_name, domain );
	}

	if (winbindd_request_response(WINBINDD_LIST_USERS, &request, &response) !=
	    NSS_STATUS_SUCCESS)
		return false;

	/* Look through extra data */

	if (!response.extra_data.data)
		return false;

	extra_data = (const char *)response.extra_data.data;

	while(next_token(&extra_data, name, ",", sizeof(fstring)))
		d_printf("%s\n", name);

	SAFE_FREE(response.extra_data.data);

	return true;
}

/* Print domain groups */

static bool print_domain_groups(const char *domain)
{
	struct winbindd_request  request;
	struct winbindd_response response;
	const char *extra_data;
	fstring name;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	if (domain) {
		if ( strequal(domain, ".") )
			fstrcpy( request.domain_name, get_winbind_domain() );
		else
			fstrcpy( request.domain_name, domain );
	}

	if (winbindd_request_response(WINBINDD_LIST_GROUPS, &request, &response) !=
	    NSS_STATUS_SUCCESS)
		return false;

	/* Look through extra data */

	if (!response.extra_data.data)
		return false;

	extra_data = (const char *)response.extra_data.data;

	while(next_token(&extra_data, name, ",", sizeof(fstring)))
		d_printf("%s\n", name);

	SAFE_FREE(response.extra_data.data);

	return true;
}

static bool wbinfo_ping(void)
{
        NSS_STATUS result;

	result = winbindd_request_response(WINBINDD_PING, NULL, NULL);

	/* Display response */

        d_printf("Ping to winbindd %s on fd %d\n",
               (result == NSS_STATUS_SUCCESS) ? "succeeded" : "failed", winbindd_fd);

        return result == NSS_STATUS_SUCCESS;
}

/* Main program */

enum {
	OPT_SET_AUTH_USER = 1000,
	OPT_GET_AUTH_USER,
	OPT_DOMAIN_NAME,
	OPT_SEQUENCE,
	OPT_GETDCNAME,
	OPT_USERDOMGROUPS,
	OPT_USERSIDS,
	OPT_ALLOCATE_UID,
	OPT_ALLOCATE_GID,
	OPT_SEPARATOR,
	OPT_LIST_ALL_DOMAINS,
	OPT_LIST_OWN_DOMAIN,
	OPT_UID_INFO,
	OPT_GROUP_INFO,
	OPT_GID_INFO,
};

int main(int argc, char **argv, char **envp)
{
	int opt;

	poptContext pc;
	static char *string_arg;
	static char *opt_domain_name;
	static int int_arg;
	int result = 1;

	struct poptOption long_options[] = {
		POPT_AUTOHELP

		/* longName, shortName, argInfo, argPtr, value, descrip,
		   argDesc */

		{ "domain-users", 'u', POPT_ARG_NONE, 0, 'u', "Lists all domain users", "domain"},
		{ "domain-groups", 'g', POPT_ARG_NONE, 0, 'g', "Lists all domain groups", "domain" },
		{ "WINS-by-name", 'N', POPT_ARG_STRING, &string_arg, 'N', "Converts NetBIOS name to IP", "NETBIOS-NAME" },
		{ "WINS-by-ip", 'I', POPT_ARG_STRING, &string_arg, 'I', "Converts IP address to NetBIOS name", "IP" },
		{ "name-to-sid", 'n', POPT_ARG_STRING, &string_arg, 'n', "Converts name to sid", "NAME" },
		{ "sid-to-name", 's', POPT_ARG_STRING, &string_arg, 's', "Converts sid to name", "SID" },
		{ "uid-to-sid", 'U', POPT_ARG_INT, &int_arg, 'U', "Converts uid to sid" , "UID" },
		{ "gid-to-sid", 'G', POPT_ARG_INT, &int_arg, 'G', "Converts gid to sid", "GID" },
		{ "sid-to-uid", 'S', POPT_ARG_STRING, &string_arg, 'S', "Converts sid to uid", "SID" },
		{ "sid-to-gid", 'Y', POPT_ARG_STRING, &string_arg, 'Y', "Converts sid to gid", "SID" },
		{ "check-secret", 't', POPT_ARG_NONE, 0, 't', "Check shared secret" },
		{ "trusted-domains", 'm', POPT_ARG_NONE, 0, 'm', "List trusted domains" },
		{ "all-domains", 0, POPT_ARG_NONE, 0, OPT_LIST_ALL_DOMAINS, "List all domains (trusted and own domain)" },
		{ "own-domain", 0, POPT_ARG_NONE, 0, OPT_LIST_OWN_DOMAIN, "List own domain" },
		{ "sequence", 0, POPT_ARG_NONE, 0, OPT_SEQUENCE, "Show sequence numbers of all domains" },
		{ "domain-info", 'D', POPT_ARG_STRING, &string_arg, 'D', "Show most of the info we have about the domain" },
		{ "user-info", 'i', POPT_ARG_STRING, &string_arg, 'i', "Get user info", "USER" },
		{ "uid-info", 0, POPT_ARG_INT, &int_arg, OPT_UID_INFO, "Get user info from uid", "UID" },
		{ "group-info", 0, POPT_ARG_STRING, &string_arg, OPT_GROUP_INFO, "Get group info", "GROUP" },
		{ "gid-info", 0, POPT_ARG_INT, &int_arg, OPT_GID_INFO, "Get group info from gid", "GID" },
		{ "user-groups", 'r', POPT_ARG_STRING, &string_arg, 'r', "Get user groups", "USER" },
		{ "user-domgroups", 0, POPT_ARG_STRING, &string_arg,
		  OPT_USERDOMGROUPS, "Get user domain groups", "SID" },
		{ "user-sids", 0, POPT_ARG_STRING, &string_arg, OPT_USERSIDS, "Get user group sids for user SID", "SID" },
		{ "authenticate", 'a', POPT_ARG_STRING, &string_arg, 'a', "authenticate user", "user%password" },
		{ "getdcname", 0, POPT_ARG_STRING, &string_arg, OPT_GETDCNAME,
		  "Get a DC name for a foreign domain", "domainname" },
		{ "ping", 'p', POPT_ARG_NONE, 0, 'p', "Ping winbindd to see if it is alive" },
		{ "domain", 0, POPT_ARG_STRING, &opt_domain_name, OPT_DOMAIN_NAME, "Define to the domain to restrict operation", "domain" },
#ifdef HAVE_KRB5
		{ "krb5auth", 'K', POPT_ARG_STRING, &string_arg, 'K', "authenticate user using Kerberos", "user%password" },
			/* destroys wbinfo --help output */
			/* "user%password,DOM\\user%password,user@EXAMPLE.COM,EXAMPLE.COM\\user%password" }, */
#endif
		{ "separator", 0, POPT_ARG_NONE, 0, OPT_SEPARATOR, "Get the active winbind separator", NULL },
		POPT_COMMON_VERSION
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};

	/* Parse options */

	pc = poptGetContext("wbinfo", argc, (const char **)argv, long_options, 0);

	/* Parse command line options */

	if (argc == 1) {
		poptPrintHelp(pc, stderr, 0);
		return 1;
	}

	while((opt = poptGetNextOpt(pc)) != -1) {
		/* get the generic configuration parameters like --domain */
	}

	poptFreeContext(pc);

	pc = poptGetContext(NULL, argc, (const char **)argv, long_options,
			    POPT_CONTEXT_KEEP_FIRST);

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'u':
			if (!print_domain_users(opt_domain_name)) {
				d_fprintf(stderr, "Error looking up domain users\n");
				goto done;
			}
			break;
		case 'g':
			if (!print_domain_groups(opt_domain_name)) {
				d_fprintf(stderr, "Error looking up domain groups\n");
				goto done;
			}
			break;
		case 's':
			if (!wbinfo_lookupsid(string_arg)) {
				d_fprintf(stderr, "Could not lookup sid %s\n", string_arg);
				goto done;
			}
			break;
		case 'n':
			if (!wbinfo_lookupname(string_arg)) {
				d_fprintf(stderr, "Could not lookup name %s\n", string_arg);
				goto done;
			}
			break;
		case 'N':
			if (!wbinfo_wins_byname(string_arg)) {
				d_fprintf(stderr, "Could not lookup WINS by name %s\n", string_arg);
				goto done;
			}
			break;
		case 'I':
			if (!wbinfo_wins_byip(string_arg)) {
				d_fprintf(stderr, "Could not lookup WINS by IP %s\n", string_arg);
				goto done;
			}
			break;
		case 'U':
			if (!wbinfo_uid_to_sid(int_arg)) {
				d_fprintf(stderr, "Could not convert uid %d to sid\n", int_arg);
				goto done;
			}
			break;
		case 'G':
			if (!wbinfo_gid_to_sid(int_arg)) {
				d_fprintf(stderr, "Could not convert gid %d to sid\n",
				       int_arg);
				goto done;
			}
			break;
		case 'S':
			if (!wbinfo_sid_to_uid(string_arg)) {
				d_fprintf(stderr, "Could not convert sid %s to uid\n",
				       string_arg);
				goto done;
			}
			break;
		case 'Y':
			if (!wbinfo_sid_to_gid(string_arg)) {
				d_fprintf(stderr, "Could not convert sid %s to gid\n",
				       string_arg);
				goto done;
			}
			break;
		case 't':
			if (!wbinfo_check_secret()) {
				d_fprintf(stderr, "Could not check secret\n");
				goto done;
			}
			break;
		case 'm':
			if (!wbinfo_list_domains(false)) {
				d_fprintf(stderr, "Could not list trusted domains\n");
				goto done;
			}
			break;
		case OPT_SEQUENCE:
			if (!wbinfo_show_sequence(opt_domain_name)) {
				d_fprintf(stderr, "Could not show sequence numbers\n");
				goto done;
			}
			break;
		case 'D':
			if (!wbinfo_domain_info(string_arg)) {
				d_fprintf(stderr, "Could not get domain info\n");
				goto done;
			}
			break;
		case 'i':
			if (!wbinfo_get_userinfo(string_arg)) {
				d_fprintf(stderr, "Could not get info for user %s\n",
						  string_arg);
				goto done;
			}
			break;
		case OPT_UID_INFO:
			if ( !wbinfo_get_uidinfo(int_arg)) {
				d_fprintf(stderr, "Could not get info for uid "
						"%d\n", int_arg);
				goto done;
			}
			break;
		case OPT_GROUP_INFO:
			if ( !wbinfo_get_groupinfo(string_arg)) {
				d_fprintf(stderr, "Could not get info for "
					  "group %s\n", string_arg);
				goto done;
			}
			break;
		case OPT_GID_INFO:
			if ( !wbinfo_get_gidinfo(int_arg)) {
				d_fprintf(stderr, "Could not get info for gid "
						"%d\n", int_arg);
				goto done;
			}
			break;
		case 'r':
			if (!wbinfo_get_usergroups(string_arg)) {
				d_fprintf(stderr, "Could not get groups for user %s\n",
				       string_arg);
				goto done;
			}
			break;
		case OPT_USERSIDS:
			if (!wbinfo_get_usersids(string_arg)) {
				d_fprintf(stderr, "Could not get group SIDs for user SID %s\n",
				       string_arg);
				goto done;
			}
			break;
		case OPT_USERDOMGROUPS:
			if (!wbinfo_get_userdomgroups(string_arg)) {
				d_fprintf(stderr, "Could not get user's domain groups "
					 "for user SID %s\n", string_arg);
				goto done;
			}
			break;
		case 'a': {
				bool got_error = false;

				if (!wbinfo_auth(string_arg)) {
					d_fprintf(stderr, "Could not authenticate user %s with "
						"plaintext password\n", string_arg);
					got_error = true;
				}

				if (!wbinfo_auth_crap(cmdline_lp_ctx, string_arg)) {
					d_fprintf(stderr, "Could not authenticate user %s with "
						"challenge/response\n", string_arg);
					got_error = true;
				}

				if (got_error)
					goto done;
				break;
			}
		case 'K': {
				uint32_t flags =  WBFLAG_PAM_KRB5 |
						WBFLAG_PAM_CACHED_LOGIN |
						WBFLAG_PAM_FALLBACK_AFTER_KRB5 |
						WBFLAG_PAM_INFO3_TEXT;

				if (!wbinfo_auth_krb5(string_arg, "FILE", flags)) {
					d_fprintf(stderr, "Could not authenticate user [%s] with "
						"Kerberos (ccache: %s)\n", string_arg, "FILE");
					goto done;
				}
				break;
			}
		case 'p':
			if (!wbinfo_ping()) {
				d_fprintf(stderr, "could not ping winbindd!\n");
				goto done;
			}
			break;
		case OPT_GETDCNAME:
			if (!wbinfo_getdcname(string_arg)) {
				goto done;
			}
			break;
		case OPT_SEPARATOR: {
			const char sep = winbind_separator_int(true);
			if ( !sep ) {
				goto done;
			}
			d_printf("%c\n", sep);
			break;
		}
		case OPT_LIST_ALL_DOMAINS:
			if (!wbinfo_list_domains(true)) {
				goto done;
			}
			break;
		case OPT_LIST_OWN_DOMAIN:
			if (!wbinfo_list_own_domain()) {
				goto done;
			}
			break;
		/* generic configuration options */
		case OPT_DOMAIN_NAME:
			break;
		default:
			d_fprintf(stderr, "Invalid option\n");
			poptPrintHelp(pc, stderr, 0);
			goto done;
		}
	}

	result = 0;

	/* Exit code */

 done:
	poptFreeContext(pc);
	return result;
}
