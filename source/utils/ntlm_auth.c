/* 
   Unix SMB/CIFS implementation.

   Winbind status program.

   Copyright (C) Tim Potter      2000-2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003-2004
   Copyright (C) Francesco Chemolli <kinkie@kame.usr.dsi.unimi.it> 2000 

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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

#define SQUID_BUFFER_SIZE 2010

enum stdio_helper_mode {
	SQUID_2_4_BASIC,
	SQUID_2_5_BASIC,
	SQUID_2_5_NTLMSSP,
	NTLMSSP_CLIENT_1,
	GSS_SPNEGO_CLIENT,
	NTLM_SERVER_1,
	NUM_HELPER_MODES
};

#define NTLM_AUTH_FLAG_USER_SESSION_KEY     0x0004
#define NTLM_AUTH_FLAG_LMKEY                0x0008


typedef void (*stdio_helper_function)(enum stdio_helper_mode stdio_helper_mode, 
				     char *buf, int length);

static void manage_squid_basic_request (enum stdio_helper_mode stdio_helper_mode, 
					char *buf, int length);

static void manage_squid_ntlmssp_request (enum stdio_helper_mode stdio_helper_mode, 
					  char *buf, int length);

static void manage_gensec_client_request (enum stdio_helper_mode stdio_helper_mode, 
					  char *buf, int length);

static void manage_ntlm_server_1_request (enum stdio_helper_mode stdio_helper_mode, 
					  char *buf, int length);

static const struct {
	enum stdio_helper_mode mode;
	const char *name;
	stdio_helper_function fn;
} stdio_helper_protocols[] = {
	{ SQUID_2_4_BASIC, "squid-2.4-basic", manage_squid_basic_request},
	{ SQUID_2_5_BASIC, "squid-2.5-basic", manage_squid_basic_request},
	{ SQUID_2_5_NTLMSSP, "squid-2.5-ntlmssp", manage_squid_ntlmssp_request},
	{ NTLMSSP_CLIENT_1, "ntlmssp-client-1", manage_gensec_client_request},
	{ GSS_SPNEGO_CLIENT, "gss-spnego-client", manage_gensec_client_request},
	{ NTLM_SERVER_1, "ntlm-server-1", manage_ntlm_server_1_request},
	{ NUM_HELPER_MODES, NULL, NULL}
};

extern int winbindd_fd;

const char *opt_username;
const char *opt_domain;
const char *opt_workstation;
const char *opt_password;


/* Copy of parse_domain_user from winbindd_util.c.  Parse a string of the
   form DOMAIN/user into a domain and a user */

static BOOL parse_ntlm_auth_domain_user(const char *domuser, fstring domain, 
				     fstring user)
{

	char *p = strchr(domuser,*lp_winbind_separator());

	if (!p) {
		return False;
	}
        
	fstrcpy(user, p+1);
	fstrcpy(domain, domuser);
	domain[PTR_DIFF(p, domuser)] = 0;
	strupper_m(domain);

	return True;
}

/* Authenticate a user with a plaintext password */

static BOOL check_plaintext_auth(const char *user, const char *pass, 
				 BOOL stdout_diagnostics)
{
        return (strcmp(pass, opt_password) == 0);
}

/* authenticate a user with an encrypted username/password */

static NTSTATUS local_pw_check_specified(const char *username, 
					 const char *domain, 
					 const char *workstation,
					 const DATA_BLOB *challenge, 
					 const DATA_BLOB *lm_response, 
					 const DATA_BLOB *nt_response, 
					 uint32 flags, 
					 DATA_BLOB *lm_session_key, 
					 DATA_BLOB *user_session_key, 
					 char **error_string, 
					 char **unix_name) 
{
	NTSTATUS nt_status;
	uint8_t lm_pw[16], nt_pw[16];
	uint8_t *lm_pwd, *nt_pwd;
	TALLOC_CTX *mem_ctx = talloc_init("local_pw_check_specified");
	if (!mem_ctx) {
		nt_status = NT_STATUS_NO_MEMORY;
	} else {
		
		E_md4hash(opt_password, nt_pw);
		if (E_deshash(opt_password, lm_pw)) {
			lm_pwd = lm_pw;
		} else {
			lm_pwd = NULL;
		}
		nt_pwd = nt_pw;
		
		
		nt_status = ntlm_password_check(mem_ctx, 
						challenge,
						lm_response,
						nt_response,
						NULL, NULL,
						username,
						username,
						domain,
						lm_pwd, nt_pwd, user_session_key, lm_session_key);
		
		if (NT_STATUS_IS_OK(nt_status)) {
			if (unix_name) {
				asprintf(unix_name, 
					 "%s%c%s", domain,
					 *lp_winbind_separator(), 
					 username);
			}
		} else {
			DEBUG(3, ("Login for user [%s]\\[%s]@[%s] failed due to [%s]\n", 
				  domain, username, workstation, 
				  nt_errstr(nt_status)));
		}
		talloc_destroy(mem_ctx);
	}
	if (error_string) {
		*error_string = strdup(nt_errstr(nt_status));
	}
	return nt_status;
	
	
}

static NTSTATUS local_pw_check(struct ntlmssp_state *ntlmssp_state, DATA_BLOB *user_session_key, DATA_BLOB *lm_session_key) 
{
	NTSTATUS nt_status;
	uint8 lm_pw[16], nt_pw[16];
	uint8_t *lm_pwd, *nt_pwd;

	E_md4hash(opt_password, nt_pw);
	if (E_deshash(opt_password, lm_pw)) {
		lm_pwd = lm_pw;
	} else {
			lm_pwd = NULL;
	}
	nt_pwd = nt_pw;
		
	nt_status = ntlm_password_check(ntlmssp_state->mem_ctx, 
					&ntlmssp_state->chal,
					&ntlmssp_state->lm_resp,
					&ntlmssp_state->nt_resp, 
					NULL, NULL,
					ntlmssp_state->user, 
					ntlmssp_state->user, 
					ntlmssp_state->domain,
					lm_pwd, nt_pwd, user_session_key, lm_session_key);
	
	if (NT_STATUS_IS_OK(nt_status)) {
		ntlmssp_state->auth_context = talloc_asprintf(ntlmssp_state->mem_ctx, 
							      "%s%c%s", ntlmssp_state->domain, 
							      *lp_winbind_separator(), 
							      ntlmssp_state->user);
	} else {
		DEBUG(3, ("Login for user [%s]\\[%s]@[%s] failed due to [%s]\n", 
			  ntlmssp_state->domain, ntlmssp_state->user, ntlmssp_state->workstation, 
			  nt_errstr(nt_status)));
		ntlmssp_state->auth_context = NULL;
	}
	return nt_status;
}

static NTSTATUS ntlm_auth_start_ntlmssp_server(struct ntlmssp_state **ntlmssp_state) 
{
	NTSTATUS status = ntlmssp_server_start(ntlmssp_state);
	
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not start NTLMSSP client: %s\n",
			  nt_errstr(status)));
		return status;
	}

	/* Have we been given a local password, or should we ask winbind? */
	if (opt_password) {
		(*ntlmssp_state)->check_password = local_pw_check;
		(*ntlmssp_state)->get_domain = lp_workgroup;
		(*ntlmssp_state)->get_global_myname = global_myname;
	} else {
		DEBUG(0, ("Winbind not supported in Samba4 ntlm_auth yet, specify --password\n"));
		exit(1);
	}
	return NT_STATUS_OK;
}

static void manage_squid_ntlmssp_request(enum stdio_helper_mode stdio_helper_mode, 
					 char *buf, int length) 
{
	static struct ntlmssp_state *ntlmssp_state = NULL;
	DATA_BLOB request, reply;
	NTSTATUS nt_status;

	if (strlen(buf) < 2) {
		DEBUG(1, ("NTLMSSP query [%s] invalid", buf));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	if (strlen(buf) > 3) {
		request = base64_decode_data_blob(buf + 3);
	} else {
		request = data_blob(NULL, 0);
	}

	if ((strncmp(buf, "PW ", 3) == 0)) {
		/* The calling application wants us to use a local password (rather than winbindd) */

		opt_password = strndup((const char *)request.data, request.length);

		if (opt_password == NULL) {
			DEBUG(1, ("Out of memory\n"));
			x_fprintf(x_stdout, "BH\n");
			data_blob_free(&request);
			return;
		}

		x_fprintf(x_stdout, "OK\n");
		data_blob_free(&request);
		return;
	}

	if (strncmp(buf, "YR", 2) == 0) {
		if (ntlmssp_state)
			ntlmssp_end(&ntlmssp_state);
	} else if (strncmp(buf, "KK", 2) == 0) {
		
	} else {
		DEBUG(1, ("NTLMSSP query [%s] invalid", buf));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	if (!ntlmssp_state) {
		if (!NT_STATUS_IS_OK(nt_status = ntlm_auth_start_ntlmssp_server(&ntlmssp_state))) {
			x_fprintf(x_stdout, "BH %s\n", nt_errstr(nt_status));
			return;
		}
	}

	DEBUG(10, ("got NTLMSSP packet:\n"));
	dump_data(10, (const char *)request.data, request.length);

	nt_status = ntlmssp_update(ntlmssp_state, NULL, request, &reply);
	
	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		char *reply_base64 = base64_encode_data_blob(reply);
		x_fprintf(x_stdout, "TT %s\n", reply_base64);
		SAFE_FREE(reply_base64);
		data_blob_free(&reply);
		DEBUG(10, ("NTLMSSP challenge\n"));
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_ACCESS_DENIED)) {
		x_fprintf(x_stdout, "BH %s\n", nt_errstr(nt_status));
		DEBUG(0, ("NTLMSSP BH: %s\n", nt_errstr(nt_status)));

		ntlmssp_end(&ntlmssp_state);
	} else if (!NT_STATUS_IS_OK(nt_status)) {
		x_fprintf(x_stdout, "NA %s\n", nt_errstr(nt_status));
		DEBUG(10, ("NTLMSSP %s\n", nt_errstr(nt_status)));
	} else {
		x_fprintf(x_stdout, "AF %s\n", (char *)ntlmssp_state->auth_context);
		DEBUG(10, ("NTLMSSP OK!\n"));
	}

	data_blob_free(&request);
}

static void manage_squid_basic_request(enum stdio_helper_mode stdio_helper_mode, 
				       char *buf, int length) 
{
	char *user, *pass;	
	user=buf;
	
	pass=memchr(buf,' ',length);
	if (!pass) {
		DEBUG(2, ("Password not found. Denying access\n"));
		x_fprintf(x_stdout, "ERR\n");
		return;
	}
	*pass='\0';
	pass++;
	
	if (stdio_helper_mode == SQUID_2_5_BASIC) {
		rfc1738_unescape(user);
		rfc1738_unescape(pass);
	}
	
	if (check_plaintext_auth(user, pass, False)) {
		x_fprintf(x_stdout, "OK\n");
	} else {
		x_fprintf(x_stdout, "ERR\n");
	}
}

static void manage_gensec_client_request(enum stdio_helper_mode stdio_helper_mode, 
					 char *buf, int length) 
{
	DATA_BLOB in;
	DATA_BLOB out;
	char *out_base64;
	static struct gensec_security gensec_state;
	NTSTATUS nt_status;
	BOOL first = False;

	if (strlen(buf) < 2) {
		DEBUG(1, ("query [%s] invalid", buf));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	if (strlen(buf) > 3) {
		in = base64_decode_data_blob(buf + 3);
	} else {
		in = data_blob(NULL, 0);
	}

	if (strncmp(buf, "PW ", 3) == 0) {

		/* We asked for a password and obviously got it :-) */

		opt_password = strndup((const char *)in.data, in.length);
		
		if (opt_password == NULL) {
			DEBUG(1, ("Out of memory\n"));
			x_fprintf(x_stdout, "BH\n");
			data_blob_free(&in);
			return;
		}

		x_fprintf(x_stdout, "OK\n");
		data_blob_free(&in);
		return;
	}
	if (strncmp(buf, "YR", 2) == 0) {
		if (gensec_state.ops) {
			gensec_state.ops->end(&gensec_state);
			gensec_state.ops = NULL;
		}
	} else if ( (strncmp(buf, "TT ", 3) != 0) &&
	     (strncmp(buf, "AF ", 3) != 0) &&
	     (strncmp(buf, "NA ", 3) != 0) ) {
		DEBUG(1, ("SPNEGO request [%s] invalid\n", buf));
		x_fprintf(x_stdout, "BH\n");
		data_blob_free(&in);
		return;
	}

	if (!opt_password) {
		x_fprintf(x_stdout, "PW\n");
		data_blob_free(&in);
		return;
	}

	/* setup gensec */
	if (!gensec_state.ops) {
		if (stdio_helper_mode == GSS_SPNEGO_CLIENT) {
			gensec_state.ops = gensec_security_by_oid(OID_SPNEGO);
		} else if (stdio_helper_mode == NTLMSSP_CLIENT_1) {
			gensec_state.ops = gensec_security_by_oid(OID_NTLMSSP);
		} else {
			exit(1);
		}
		gensec_state.user.name = opt_username;
		gensec_state.user.domain = opt_domain;
		gensec_state.user.password = opt_password;
		nt_status = gensec_state.ops->client_start(&gensec_state);

		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(1, ("SPENGO login failed to initialise: %s\n", nt_errstr(nt_status)));
			x_fprintf(x_stdout, "BH\n");
			return;
		}
		if (!in.length) {
			first = True;
		}
	}
	
	/* update */

	nt_status = gensec_state.ops->update(&gensec_state, NULL, in, &out);
	
	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {

		out_base64 = base64_encode_data_blob(out);
		if (first) {
			x_fprintf(x_stdout, "YR %s\n", out_base64);
		} else { 
			x_fprintf(x_stdout, "KK %s\n", out_base64);
		}
		SAFE_FREE(out_base64);


	} else if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("SPENGO login failed: %s\n", nt_errstr(nt_status)));
		x_fprintf(x_stdout, "BH\n");
	} else {
		x_fprintf(x_stdout, "AF\n");
	}

	return;
}

static void manage_ntlm_server_1_request(enum stdio_helper_mode stdio_helper_mode, 
					 char *buf, int length) 
{
	char *request, *parameter;	
	static DATA_BLOB challenge;
	static DATA_BLOB lm_response;
	static DATA_BLOB nt_response;
	static char *full_username;
	static char *username;
	static char *domain;
	static char *plaintext_password;
	static BOOL ntlm_server_1_user_session_key;
	static BOOL ntlm_server_1_lm_session_key;
	
	if (strequal(buf, ".")) {
		if (!full_username && !username) {	
			x_fprintf(x_stdout, "Error: No username supplied!\n");
		} else if (plaintext_password) {
			/* handle this request as plaintext */
			if (!full_username) {
				if (asprintf(&full_username, "%s%c%s", domain, *lp_winbind_separator(), username) == -1) {
					x_fprintf(x_stdout, "Error: Out of memory in asprintf!\n.\n");
					return;
				}
			}
			if (check_plaintext_auth(full_username, plaintext_password, False)) {
				x_fprintf(x_stdout, "Authenticated: Yes\n");
			} else {
				x_fprintf(x_stdout, "Authenticated: No\n");
			}
		} else if (!lm_response.data && !nt_response.data) {
			x_fprintf(x_stdout, "Error: No password supplied!\n");
		} else if (!challenge.data) {	
			x_fprintf(x_stdout, "Error: No lanman-challenge supplied!\n");
		} else {
			char *error_string = NULL;
			DATA_BLOB lm_key;
			DATA_BLOB user_session_key;
			uint32 flags = 0;

			if (full_username && !username) {
				fstring fstr_user;
				fstring fstr_domain;
				
				if (!parse_ntlm_auth_domain_user(full_username, fstr_user, fstr_domain)) {
					/* username might be 'tainted', don't print into our new-line deleimianted stream */
					x_fprintf(x_stdout, "Error: Could not parse into domain and username\n");
				}
				SAFE_FREE(username);
				SAFE_FREE(domain);
				username = smb_xstrdup(fstr_user);
				domain = smb_xstrdup(fstr_domain);
			}

			if (!domain) {
				domain = smb_xstrdup(lp_workgroup());
			}

			if (ntlm_server_1_lm_session_key) 
				flags |= NTLM_AUTH_FLAG_LMKEY;
			
			if (ntlm_server_1_user_session_key) 
				flags |= NTLM_AUTH_FLAG_USER_SESSION_KEY;

			if (!NT_STATUS_IS_OK(
				    local_pw_check_specified(username, 
							      domain, 
							      global_myname(),
							      &challenge, 
							      &lm_response, 
							      &nt_response, 
							      flags, 
							      &lm_key, 
							      &user_session_key,
							      &error_string,
							      NULL))) {

				x_fprintf(x_stdout, "Authenticated: No\n");
				x_fprintf(x_stdout, "Authentication-Error: %s\n.\n", error_string);
				SAFE_FREE(error_string);
			} else {
				static char zeros[16];
				char *hex_lm_key;
				char *hex_user_session_key;

				x_fprintf(x_stdout, "Authenticated: Yes\n");

				if (ntlm_server_1_lm_session_key 
				    && lm_key.length 
				    && (memcmp(zeros, lm_key.data, 
								lm_key.length) != 0)) {
					hex_encode(lm_key.data,
						   lm_key.length,
						   &hex_lm_key);
					x_fprintf(x_stdout, "LANMAN-Session-Key: %s\n", hex_lm_key);
					SAFE_FREE(hex_lm_key);
				}

				if (ntlm_server_1_user_session_key 
				    && user_session_key.length 
				    && (memcmp(zeros, user_session_key.data, 
					       user_session_key.length) != 0)) {
					hex_encode(user_session_key.data, 
						   user_session_key.length, 
						   &hex_user_session_key);
					x_fprintf(x_stdout, "User-Session-Key: %s\n", hex_user_session_key);
					SAFE_FREE(hex_user_session_key);
				}
			}
		}
		/* clear out the state */
		challenge = data_blob(NULL, 0);
		nt_response = data_blob(NULL, 0);
		lm_response = data_blob(NULL, 0);
		SAFE_FREE(full_username);
		SAFE_FREE(username);
		SAFE_FREE(domain);
		SAFE_FREE(plaintext_password);
		ntlm_server_1_user_session_key = False;
		ntlm_server_1_lm_session_key = False;
		x_fprintf(x_stdout, ".\n");

		return;
	}

	request = buf;

	/* Indicates a base64 encoded structure */
	parameter = strstr(request, ":: ");
	if (!parameter) {
		parameter = strstr(request, ": ");
		
		if (!parameter) {
			DEBUG(0, ("Parameter not found!\n"));
			x_fprintf(x_stdout, "Error: Parameter not found!\n.\n");
			return;
		}
		
		parameter[0] ='\0';
		parameter++;
		parameter[0] ='\0';
		parameter++;

	} else {
		parameter[0] ='\0';
		parameter++;
		parameter[0] ='\0';
		parameter++;
		parameter[0] ='\0';
		parameter++;

		base64_decode_inplace(parameter);
	}

	if (strequal(request, "LANMAN-Challenge")) {
		challenge = strhex_to_data_blob(parameter);
		if (challenge.length != 8) {
			x_fprintf(x_stdout, "Error: hex decode of %s failed! (got %d bytes, expected 8)\n.\n", 
				  parameter,
				  (int)challenge.length);
			challenge = data_blob(NULL, 0);
		}
	} else if (strequal(request, "NT-Response")) {
		nt_response = strhex_to_data_blob(parameter);
		if (nt_response.length < 24) {
			x_fprintf(x_stdout, "Error: hex decode of %s failed! (only got %d bytes, needed at least 24)\n.\n", 
				  parameter,
				  (int)nt_response.length);
			nt_response = data_blob(NULL, 0);
		}
	} else if (strequal(request, "LANMAN-Response")) {
		lm_response = strhex_to_data_blob(parameter);
		if (lm_response.length != 24) {
			x_fprintf(x_stdout, "Error: hex decode of %s failed! (got %d bytes, expected 24)\n.\n", 
				  parameter,
				  (int)lm_response.length);
			lm_response = data_blob(NULL, 0);
		}
	} else if (strequal(request, "Password")) {
		plaintext_password = smb_xstrdup(parameter);
	} else if (strequal(request, "NT-Domain")) {
		domain = smb_xstrdup(parameter);
	} else if (strequal(request, "Username")) {
		username = smb_xstrdup(parameter);
	} else if (strequal(request, "Full-Username")) {
		full_username = smb_xstrdup(parameter);
	} else if (strequal(request, "Request-User-Session-Key")) {
		ntlm_server_1_user_session_key = strequal(parameter, "Yes");
	} else if (strequal(request, "Request-LanMan-Session-Key")) {
		ntlm_server_1_lm_session_key = strequal(parameter, "Yes");
	} else {
		x_fprintf(x_stdout, "Error: Unknown request %s\n.\n", request);
	}
}

static void manage_squid_request(enum stdio_helper_mode helper_mode, stdio_helper_function fn) 
{
	char buf[SQUID_BUFFER_SIZE+1];
	int length;
	char *c;
	static BOOL err;

	/* this is not a typo - x_fgets doesn't work too well under squid */
	if (fgets(buf, sizeof(buf)-1, stdin) == NULL) {
		if (ferror(stdin)) {
			DEBUG(1, ("fgets() failed! dying..... errno=%d (%s)\n", ferror(stdin),
				  strerror(ferror(stdin))));
			
			exit(1);    /* BIIG buffer */
		}
		exit(0);
	}
    
	c=memchr(buf,'\n',sizeof(buf)-1);
	if (c) {
		*c = '\0';
		length = c-buf;
	} else {
		err = 1;
		return;
	}
	if (err) {
		DEBUG(2, ("Oversized message\n"));
		x_fprintf(x_stderr, "ERR\n");
		err = 0;
		return;
	}

	DEBUG(10, ("Got '%s' from squid (length: %d).\n",buf,length));

	if (buf[0] == '\0') {
		DEBUG(2, ("Invalid Request\n"));
		x_fprintf(x_stderr, "ERR\n");
		return;
	}
	
	fn(helper_mode, buf, length);
}


static void squid_stream(enum stdio_helper_mode stdio_mode, stdio_helper_function fn) {
	/* initialize FDescs */
	x_setbuf(x_stdout, NULL);
	x_setbuf(x_stderr, NULL);
	while(1) {
		manage_squid_request(stdio_mode, fn);
	}
}


/* Main program */

enum {
	OPT_USERNAME = 1000,
	OPT_DOMAIN,
	OPT_WORKSTATION,
	OPT_CHALLENGE,
	OPT_RESPONSE,
	OPT_LM,
	OPT_NT,
	OPT_PASSWORD,
	OPT_LM_KEY,
	OPT_USER_SESSION_KEY,
	OPT_DIAGNOSTICS,
	OPT_REQUIRE_MEMBERSHIP
};

 int main(int argc, const char **argv)
{
	static const char *helper_protocol;
	int opt;

	poptContext pc;

	/* NOTE: DO NOT change this interface without considering the implications!
	   This is an external interface, which other programs will use to interact 
	   with this helper.
	*/

	/* We do not use single-letter command abbreviations, because they harm future 
	   interface stability. */

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{ "helper-protocol", 0, POPT_ARG_STRING, &helper_protocol, OPT_DOMAIN, "operate as a stdio-based helper", "helper protocol to use"},
 		{ "domain", 0, POPT_ARG_STRING, &opt_domain, OPT_DOMAIN, "domain name"},
 		{ "workstation", 0, POPT_ARG_STRING, &opt_workstation, OPT_WORKSTATION, "workstation"},
		{ "username", 0, POPT_ARG_STRING, &opt_username, OPT_PASSWORD, "Username"},		
		{ "password", 0, POPT_ARG_STRING, &opt_password, OPT_PASSWORD, "User's plaintext password"},		
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};

	/* Samba client initialisation */

	setup_logging("ntlm_auth", DEBUG_STDOUT);

	if (!lp_load(dyn_CONFIGFILE, True, False, False)) {
		d_fprintf(stderr, "wbinfo: error opening config file %s. Error was %s\n",
			dyn_CONFIGFILE, strerror(errno));
		exit(1);
	}

	/* Parse options */

	pc = poptGetContext("ntlm_auth", argc, argv, long_options, 0);

	/* Parse command line options */

	if (argc == 1) {
		poptPrintHelp(pc, stderr, 0);
		return 1;
	}

	pc = poptGetContext(NULL, argc, (const char **)argv, long_options, 
			    POPT_CONTEXT_KEEP_FIRST);

	while((opt = poptGetNextOpt(pc)) != -1) {
		if (opt < -1) {
			break;
		}
	}
	if (opt < -1) {
		fprintf(stderr, "%s: %s\n",
			poptBadOption(pc, POPT_BADOPTION_NOALIAS),
			poptStrerror(opt));
		return 1;
	}

	if (opt_domain == NULL) {
		opt_domain = lp_workgroup();
	}

	if (helper_protocol) {
		int i;
		for (i=0; i<NUM_HELPER_MODES; i++) {
			if (strcmp(helper_protocol, stdio_helper_protocols[i].name) == 0) {
				squid_stream(stdio_helper_protocols[i].mode, stdio_helper_protocols[i].fn);
				exit(0);
			}
		}
		x_fprintf(x_stderr, "unknown helper protocol [%s]\n\nValid helper protools:\n\n", helper_protocol);

		for (i=0; i<NUM_HELPER_MODES; i++) {
			x_fprintf(x_stderr, "%s\n", stdio_helper_protocols[i].name);
		}

		exit(1);
	}

	if (!opt_username) {
		x_fprintf(x_stderr, "username must be specified!\n\n");
		poptPrintHelp(pc, stderr, 0);
		exit(1);
	}

	if (opt_workstation == NULL) {
		opt_workstation = lp_netbios_name();
	}

	if (!opt_password) {
		opt_password = getpass("password: ");
	}

	{
		char *user;

		asprintf(&user, "%s%c%s", opt_domain, *lp_winbind_separator(), opt_username);
		if (!check_plaintext_auth(user, opt_password, True)) {
			return 1;
		}
	}

	/* Exit code */

	poptFreeContext(pc);
	return 0;
}
