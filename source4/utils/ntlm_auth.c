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
	GSS_SPNEGO_SERVER,
	NTLM_SERVER_1,
	NUM_HELPER_MODES
};

#define NTLM_AUTH_FLAG_USER_SESSION_KEY     0x0004
#define NTLM_AUTH_FLAG_LMKEY                0x0008


typedef void (*stdio_helper_function)(enum stdio_helper_mode stdio_helper_mode, 
				      char *buf, int length, void **private);

static void manage_squid_basic_request (enum stdio_helper_mode stdio_helper_mode, 
					char *buf, int length, void **private);

static void manage_gensec_request (enum stdio_helper_mode stdio_helper_mode, 
				   char *buf, int length, void **private);

static void manage_ntlm_server_1_request (enum stdio_helper_mode stdio_helper_mode, 
					  char *buf, int length, void **private);

static void manage_squid_request(enum stdio_helper_mode helper_mode, 
				 stdio_helper_function fn, void *private);

static const struct {
	enum stdio_helper_mode mode;
	const char *name;
	stdio_helper_function fn;
} stdio_helper_protocols[] = {
	{ SQUID_2_4_BASIC, "squid-2.4-basic", manage_squid_basic_request},
	{ SQUID_2_5_BASIC, "squid-2.5-basic", manage_squid_basic_request},
	{ SQUID_2_5_NTLMSSP, "squid-2.5-ntlmssp", manage_gensec_request},
	{ GSS_SPNEGO_CLIENT, "gss-spnego-client", manage_gensec_request},
	{ GSS_SPNEGO_SERVER, "gss-spnego", manage_gensec_request},
	{ NTLMSSP_CLIENT_1, "ntlmssp-client-1", manage_gensec_request},
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

static void manage_squid_basic_request(enum stdio_helper_mode stdio_helper_mode, 
				       char *buf, int length, void **private) 
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

/* This is a bit hairy, but the basic idea is to do a password callback
   to the calling application.  The callback comes from within gensec */

static void manage_gensec_get_pw_request(enum stdio_helper_mode stdio_helper_mode, 
					 char *buf, int length, void **private)  
{
	DATA_BLOB in;
	struct gensec_security **gensec_state = (struct gensec_security **)private;
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

		(*gensec_state)->password_callback_private = talloc_strndup((*gensec_state)->mem_ctx, 
									    (const char *)in.data, in.length);
		
		if ((*gensec_state)->password_callback_private == NULL) {
			DEBUG(1, ("Out of memory\n"));
			x_fprintf(x_stdout, "BH\n");
			data_blob_free(&in);
			return;
		}

		x_fprintf(x_stdout, "OK\n");
		data_blob_free(&in);
		return;
	}
	DEBUG(1, ("Asked for (and expected) a password\n"));
	x_fprintf(x_stdout, "BH\n");
	data_blob_free(&in);
}

/* 
 * Callback for gensec, to ask the calling application for a password.  Uses the above function
 * for the stdio part of this.
 */

static NTSTATUS get_password(struct gensec_security *gensec_security, TALLOC_CTX *mem_ctx, 
			     char **password) 
{
	*password = NULL;
	
	/* Ask for a password */
	x_fprintf(x_stdout, "PW\n");
	gensec_security->password_callback_private = NULL;

	manage_squid_request(NUM_HELPER_MODES /* bogus */, manage_gensec_get_pw_request, &gensec_security);
	*password = (char *)gensec_security->password_callback_private;
	if (*password) {
		return NT_STATUS_OK;
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}
}

static void manage_gensec_request(enum stdio_helper_mode stdio_helper_mode, 
				  char *buf, int length, void **private) 
{
	DATA_BLOB in;
	DATA_BLOB out = data_blob(NULL, 0);
	char *out_base64 = NULL;
	const char *reply_arg = NULL;
	struct gensec_security **gensec_state = (struct gensec_security **)private;
	NTSTATUS nt_status;
	BOOL first = False;
	const char *reply_code;
	
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

	if (strncmp(buf, "YR", 2) == 0) {
		if (gensec_state && *gensec_state) {
			gensec_end(gensec_state);
			*gensec_state = NULL;
		}
	} else if ( (strncmp(buf, "OK", 2) == 0)) {
		/* do nothing */
		data_blob_free(&in);
		return;
	} else if ( (strncmp(buf, "TT ", 3) != 0) &&
		    (strncmp(buf, "KK ", 3) != 0) &&
		    (strncmp(buf, "AF ", 3) != 0) &&
		    (strncmp(buf, "NA ", 3) != 0) && 
		    (strncmp(buf, "PW ", 3) != 0)) {
		DEBUG(1, ("SPNEGO request [%s] invalid\n", buf));
		x_fprintf(x_stdout, "BH\n");
		data_blob_free(&in);
		return;
	}

	/* setup gensec */
	if (!(gensec_state && *gensec_state)) {
		switch (stdio_helper_mode) {
		case GSS_SPNEGO_CLIENT:
		case NTLMSSP_CLIENT_1:
			/* setup the client side */
			
			if (!NT_STATUS_IS_OK(gensec_client_start(gensec_state))) {
				exit(1);
			}
			gensec_set_username(*gensec_state, opt_username);
			gensec_set_domain(*gensec_state, opt_domain);		
			if (opt_password) {
				if (!NT_STATUS_IS_OK(gensec_set_password(*gensec_state, opt_password))) {
					DEBUG(1, ("Out of memory\n"));
					x_fprintf(x_stdout, "BH\n");
					data_blob_free(&in);
					return;
				}
			} else {
				gensec_set_password_callback(*gensec_state, get_password, NULL);
			}
			
			break;
		case GSS_SPNEGO_SERVER:
		case SQUID_2_5_NTLMSSP:
			if (!NT_STATUS_IS_OK(gensec_server_start(gensec_state))) {
				exit(1);
			}
			break;
		default:
			abort();
		}

		switch (stdio_helper_mode) {
		case GSS_SPNEGO_CLIENT:
		case GSS_SPNEGO_SERVER:
			nt_status = gensec_start_mech_by_oid(*gensec_state, OID_SPNEGO);
			break;
		case NTLMSSP_CLIENT_1:
		case SQUID_2_5_NTLMSSP:
			nt_status = gensec_start_mech_by_oid(*gensec_state, OID_NTLMSSP);
			break;
		default:
			abort();
		}

		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(1, ("SPENGO login failed to initialise: %s\n", nt_errstr(nt_status)));
			x_fprintf(x_stdout, "BH\n");
			return;
		}
		if (!in.length) {
			first = True;
		}
	}
	
	if (strncmp(buf, "PW ", 3) == 0) {

		if (!NT_STATUS_IS_OK(gensec_set_password(*gensec_state, 
							 talloc_strndup((*gensec_state)->mem_ctx, 
									(const char *)in.data, 
									in.length)))) {
			DEBUG(1, ("Out of memory\n"));
			x_fprintf(x_stdout, "BH\n");
			data_blob_free(&in);
			return;
		}

		x_fprintf(x_stdout, "OK\n");
		data_blob_free(&in);
		return;
	}

	/* update */

	nt_status = gensec_update(*gensec_state, NULL, in, &out);
	
	/* don't leak 'bad password'/'no such user' info to the network client */
	nt_status = nt_status_squash(nt_status);

	if (out.length) {
		out_base64 = base64_encode_data_blob(out);
	} else {
		out_base64 = NULL;
	}
	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		reply_arg = "*";
		if (first) {
			reply_code = "YR";
		} else if ((*gensec_state)->gensec_role == GENSEC_CLIENT) { 
			reply_code = "KK";
		} else if ((*gensec_state)->gensec_role == GENSEC_SERVER) { 
			reply_code = "TT";
		} else {
			abort();
		}


	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_ACCESS_DENIED)) {
		reply_code = "BH";
		reply_arg = nt_errstr(nt_status);
		DEBUG(1, ("GENSEC login failed: %s\n", nt_errstr(nt_status)));
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_UNSUCCESSFUL)) {
		reply_code = "BH";
		reply_arg = nt_errstr(nt_status);
		DEBUG(1, ("GENSEC login failed: %s\n", nt_errstr(nt_status)));
	} else if (!NT_STATUS_IS_OK(nt_status)) {
		reply_code = "NA";
		reply_arg = nt_errstr(nt_status);
		DEBUG(1, ("GENSEC login failed: %s\n", nt_errstr(nt_status)));
	} else if /* OK */ ((*gensec_state)->gensec_role == GENSEC_SERVER) {
		struct auth_session_info *session_info;

		nt_status = gensec_session_info(*gensec_state, &session_info);
		if (!NT_STATUS_IS_OK(nt_status)) {
			reply_code = "BH";
			reply_arg = nt_errstr(nt_status);
			DEBUG(1, ("GENSEC failed to retreive the session info: %s\n", nt_errstr(nt_status)));
		} else {

			reply_code = "AF";
			reply_arg = talloc_asprintf((*gensec_state)->mem_ctx, 
						    "%s%s%s", session_info->server_info->domain, 
						    lp_winbind_separator(), session_info->server_info->account_name);
			talloc_destroy(session_info->mem_ctx);
		}
	} else if ((*gensec_state)->gensec_role == GENSEC_CLIENT) {
		reply_code = "AF";
		reply_arg = NULL;
	} else {
		abort();
	}

	switch (stdio_helper_mode) {
	case GSS_SPNEGO_SERVER:
		x_fprintf(x_stdout, "%s %s %s\n", reply_code, 
			  out_base64 ? out_base64 : "*", 
			  reply_arg ? reply_arg : "*");
		break;
	default:
		if (out_base64) {
			x_fprintf(x_stdout, "%s %s\n", reply_code, out_base64);
		} else if (reply_arg) {
			x_fprintf(x_stdout, "%s %s\n", reply_code, reply_arg);
		} else {
			x_fprintf(x_stdout, "%s\n", reply_code);
		}
	}

	SAFE_FREE(out_base64);
	return;
}

static void manage_ntlm_server_1_request(enum stdio_helper_mode stdio_helper_mode, 
					 char *buf, int length, void **private) 
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
							      lp_netbios_name(),
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

static void manage_squid_request(enum stdio_helper_mode helper_mode, stdio_helper_function fn, void *private) 
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
	
	fn(helper_mode, buf, length, private);
}

static void squid_stream(enum stdio_helper_mode stdio_mode, stdio_helper_function fn) {
	void *private = NULL;
	/* initialize FDescs */
	x_setbuf(x_stdout, NULL);
	x_setbuf(x_stderr, NULL);
	while(1) {
		manage_squid_request(stdio_mode, fn, &private);
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

	setup_logging("ntlm_auth", DEBUG_STDERR);

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
