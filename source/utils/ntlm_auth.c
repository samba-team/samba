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
	GSS_SPNEGO,
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

static void manage_client_ntlmssp_request (enum stdio_helper_mode stdio_helper_mode, 
					   char *buf, int length);

static void manage_gss_spnego_request (enum stdio_helper_mode stdio_helper_mode, 
				       char *buf, int length);

static void manage_gss_spnego_client_request (enum stdio_helper_mode stdio_helper_mode, 
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
	{ NTLMSSP_CLIENT_1, "ntlmssp-client-1", manage_client_ntlmssp_request},
	{ GSS_SPNEGO, "gss-spnego", manage_gss_spnego_request},
	{ GSS_SPNEGO_CLIENT, "gss-spnego-client", manage_gss_spnego_client_request},
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

static NTSTATUS ntlm_auth_start_ntlmssp_client(struct ntlmssp_state **client_ntlmssp_state) 
{
	NTSTATUS status;
	if ( (opt_username == NULL) || (opt_domain == NULL) ) {
		DEBUG(1, ("Need username and domain for NTLMSSP\n"));
		return status;
	}

	status = ntlmssp_client_start(client_ntlmssp_state);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not start NTLMSSP client: %s\n",
			  nt_errstr(status)));
		ntlmssp_end(client_ntlmssp_state);
		return status;
	}

	status = ntlmssp_set_username(*client_ntlmssp_state, opt_username);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not set username: %s\n",
			  nt_errstr(status)));
		ntlmssp_end(client_ntlmssp_state);
		return status;
	}

	status = ntlmssp_set_domain(*client_ntlmssp_state, opt_domain);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not set domain: %s\n",
			  nt_errstr(status)));
		ntlmssp_end(client_ntlmssp_state);
		return status;
	}

	status = ntlmssp_set_password(*client_ntlmssp_state, opt_password);
	
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not set password: %s\n",
			  nt_errstr(status)));
		ntlmssp_end(client_ntlmssp_state);
		return status;
	}
	return NT_STATUS_OK;
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

static void manage_client_ntlmssp_request(enum stdio_helper_mode stdio_helper_mode, 
					 char *buf, int length) 
{
	static struct ntlmssp_state *ntlmssp_state = NULL;
	DATA_BLOB request, reply;
	NTSTATUS nt_status;
	BOOL first = False;
	
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

	if (strncmp(buf, "PW ", 3) == 0) {
		/* We asked for a password and obviously got it :-) */

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

	if (opt_password == NULL) {
		
		/* Request a password from the calling process.  After
		   sending it, the calling process should retry asking for the negotiate. */
		
		DEBUG(10, ("Requesting password\n"));
		x_fprintf(x_stdout, "PW\n");
		return;
	}

	if (strncmp(buf, "YR", 2) == 0) {
		if (ntlmssp_state)
			ntlmssp_end(&ntlmssp_state);
	} else if (strncmp(buf, "TT", 2) == 0) {
		
	} else {
		DEBUG(1, ("NTLMSSP query [%s] invalid", buf));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	if (!ntlmssp_state) {
		if (!NT_STATUS_IS_OK(nt_status = ntlm_auth_start_ntlmssp_client(&ntlmssp_state))) {
			x_fprintf(x_stdout, "BH %s\n", nt_errstr(nt_status));
			return;
		}
		first = True;
	}

	DEBUG(10, ("got NTLMSSP packet:\n"));
	dump_data(10, (const char *)request.data, request.length);

	nt_status = ntlmssp_update(ntlmssp_state, NULL, request, &reply);
	
	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		char *reply_base64 = base64_encode_data_blob(reply);
		if (first) {
			x_fprintf(x_stdout, "YR %s\n", reply_base64);
		} else { 
			x_fprintf(x_stdout, "KK %s\n", reply_base64);
		}
		SAFE_FREE(reply_base64);
		data_blob_free(&reply);
		DEBUG(10, ("NTLMSSP challenge\n"));
	} else if (NT_STATUS_IS_OK(nt_status)) {
		x_fprintf(x_stdout, "AF\n");
		DEBUG(10, ("NTLMSSP OK!\n"));
		if (ntlmssp_state)
			ntlmssp_end(&ntlmssp_state);
	} else {
		x_fprintf(x_stdout, "BH %s\n", nt_errstr(nt_status));
		DEBUG(0, ("NTLMSSP BH: %s\n", nt_errstr(nt_status)));
		if (ntlmssp_state)
			ntlmssp_end(&ntlmssp_state);
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

static void offer_gss_spnego_mechs(void) {

	DATA_BLOB token;
	struct spnego_data spnego;
	ssize_t len;
	char *reply_base64;

	pstring principal;
	pstring myname_lower;

	ZERO_STRUCT(spnego);

	pstrcpy(myname_lower, global_myname());
	strlower_m(myname_lower);

	pstr_sprintf(principal, "%s$@%s", myname_lower, lp_realm());

	/* Server negTokenInit (mech offerings) */
	spnego.type = SPNEGO_NEG_TOKEN_INIT;
	spnego.negTokenInit.mechTypes = smb_xmalloc(sizeof(char *) * 3);
#ifdef HAVE_KRB5
	spnego.negTokenInit.mechTypes[0] = smb_xstrdup(OID_KERBEROS5_OLD);
	spnego.negTokenInit.mechTypes[1] = smb_xstrdup(OID_NTLMSSP);
	spnego.negTokenInit.mechTypes[2] = NULL;
#else
	spnego.negTokenInit.mechTypes[0] = smb_xstrdup(OID_NTLMSSP);
	spnego.negTokenInit.mechTypes[1] = NULL;
#endif


	spnego.negTokenInit.mechListMIC = data_blob(principal,
						    strlen(principal));

	len = write_spnego_data(&token, &spnego);
	free_spnego_data(&spnego);

	if (len == -1) {
		DEBUG(1, ("Could not write SPNEGO data blob\n"));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	reply_base64 = base64_encode_data_blob(token);
	x_fprintf(x_stdout, "TT %s *\n", reply_base64);

	SAFE_FREE(reply_base64);
	data_blob_free(&token);
	DEBUG(10, ("sent SPNEGO negTokenInit\n"));
	return;
}

static void manage_gss_spnego_request(enum stdio_helper_mode stdio_helper_mode, 
				      char *buf, int length) 
{
	static struct ntlmssp_state *ntlmssp_state = NULL;
	struct spnego_data request, response;
	DATA_BLOB token;
	NTSTATUS status;
	ssize_t len;

	char *user = NULL;
	char *domain = NULL;

	const char *reply_code;
	char       *reply_base64;
	pstring     reply_argument;

	if (strlen(buf) < 2) {
		DEBUG(1, ("SPENGO query [%s] invalid", buf));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	if (strncmp(buf, "YR", 2) == 0) {
		if (ntlmssp_state)
			ntlmssp_end(&ntlmssp_state);
	} else if (strncmp(buf, "KK", 2) == 0) {
		
	} else {
		DEBUG(1, ("SPENGO query [%s] invalid", buf));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	if ( (strlen(buf) == 2)) {

		/* no client data, get the negTokenInit offering
                   mechanisms */

		offer_gss_spnego_mechs();
		return;
	}

	/* All subsequent requests have a blob. This might be negTokenInit or negTokenTarg */

	if (strlen(buf) <= 3) {
		DEBUG(1, ("GSS-SPNEGO query [%s] invalid\n", buf));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	token = base64_decode_data_blob(buf + 3);
	len = read_spnego_data(token, &request);
	data_blob_free(&token);

	if (len == -1) {
		DEBUG(1, ("GSS-SPNEGO query [%s] invalid", buf));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	if (request.type == SPNEGO_NEG_TOKEN_INIT) {

		/* Second request from Client. This is where the
		   client offers its mechanism to use. */

		if ( (request.negTokenInit.mechTypes == NULL) ||
		     (request.negTokenInit.mechTypes[0] == NULL) ) {
			DEBUG(1, ("Client did not offer any mechanism"));
			x_fprintf(x_stdout, "BH\n");
			return;
		}

		if (strcmp(request.negTokenInit.mechTypes[0], OID_NTLMSSP) == 0) {

			if ( request.negTokenInit.mechToken.data == NULL ) {
				DEBUG(1, ("Client did not provide  NTLMSSP data\n"));
				x_fprintf(x_stdout, "BH\n");
				return;
			}

			if ( ntlmssp_state != NULL ) {
				DEBUG(1, ("Client wants a new NTLMSSP challenge, but "
					  "already got one\n"));
				x_fprintf(x_stdout, "BH\n");
				ntlmssp_end(&ntlmssp_state);
				return;
			}

			if (!NT_STATUS_IS_OK(status = ntlm_auth_start_ntlmssp_server(&ntlmssp_state))) {
				x_fprintf(x_stdout, "BH %s\n", nt_errstr(status));
				return;
			}

			DEBUG(10, ("got NTLMSSP packet:\n"));
			dump_data(10, (const char *)request.negTokenInit.mechToken.data,
				  request.negTokenInit.mechToken.length);

			response.type = SPNEGO_NEG_TOKEN_TARG;
			response.negTokenTarg.supportedMech = strdup(OID_NTLMSSP);
			response.negTokenTarg.mechListMIC = data_blob(NULL, 0);

			status = ntlmssp_update(ntlmssp_state,
						NULL, 
						request.negTokenInit.mechToken,
						&response.negTokenTarg.responseToken);
		}

#ifdef HAVE_KRB5
		if (strcmp(request.negTokenInit.mechTypes[0], OID_KERBEROS5_OLD) == 0) {

			char *principal;
			DATA_BLOB auth_data;
			DATA_BLOB ap_rep;
			DATA_BLOB session_key;

			if ( request.negTokenInit.mechToken.data == NULL ) {
				DEBUG(1, ("Client did not provide Kerberos data\n"));
				x_fprintf(x_stdout, "BH\n");
				return;
			}

			response.type = SPNEGO_NEG_TOKEN_TARG;
			response.negTokenTarg.supportedMech = strdup(OID_KERBEROS5_OLD);
			response.negTokenTarg.mechListMIC = data_blob(NULL, 0);
			response.negTokenTarg.responseToken = data_blob(NULL, 0);

			status = ads_verify_ticket(lp_realm(),
						   &request.negTokenInit.mechToken,
						   &principal, &auth_data, &ap_rep,
						   &session_key);

			/* Now in "principal" we have the name we are
                           authenticated as. */

			if (NT_STATUS_IS_OK(status)) {

				domain = strchr(principal, '@');

				if (domain == NULL) {
					DEBUG(1, ("Did not get a valid principal "
						  "from ads_verify_ticket\n"));
					x_fprintf(x_stdout, "BH\n");
					return;
				}

				*domain++ = '\0';
				domain = strdup(domain);
				user = strdup(principal);

				data_blob_free(&ap_rep);
				data_blob_free(&auth_data);

				SAFE_FREE(principal);
			}
		}
#endif

	} else {

		if ( (request.negTokenTarg.supportedMech == NULL) ||
		     ( strcmp(request.negTokenTarg.supportedMech, OID_NTLMSSP) != 0 ) ) {
			/* Kerberos should never send a negTokenTarg, OID_NTLMSSP
			   is the only one we support that sends this stuff */
			DEBUG(1, ("Got a negTokenTarg for something non-NTLMSSP: %s\n",
				  request.negTokenTarg.supportedMech));
			x_fprintf(x_stdout, "BH\n");
			return;
		}

		if (request.negTokenTarg.responseToken.data == NULL) {
			DEBUG(1, ("Got a negTokenTarg without a responseToken!\n"));
			x_fprintf(x_stdout, "BH\n");
			return;
		}

		status = ntlmssp_update(ntlmssp_state,
					NULL,
					request.negTokenTarg.responseToken,
					&response.negTokenTarg.responseToken);

		response.type = SPNEGO_NEG_TOKEN_TARG;
		response.negTokenTarg.supportedMech = strdup(OID_NTLMSSP);
		response.negTokenTarg.mechListMIC = data_blob(NULL, 0);

		if (NT_STATUS_IS_OK(status)) {
			user = strdup(ntlmssp_state->user);
			domain = strdup(ntlmssp_state->domain);
			ntlmssp_end(&ntlmssp_state);
		}
	}

	free_spnego_data(&request);

	if (NT_STATUS_IS_OK(status)) {
		response.negTokenTarg.negResult = SPNEGO_ACCEPT_COMPLETED;
		reply_code = "AF";
		pstr_sprintf(reply_argument, "%s\\%s", domain, user);
	} else if (NT_STATUS_EQUAL(status,
				   NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		response.negTokenTarg.negResult = SPNEGO_ACCEPT_INCOMPLETE;
		reply_code = "TT";
		pstr_sprintf(reply_argument, "*");
	} else {
		response.negTokenTarg.negResult = SPNEGO_REJECT;
		reply_code = "NA";
		pstrcpy(reply_argument, nt_errstr(status));
	}

	SAFE_FREE(user);
	SAFE_FREE(domain);

	len = write_spnego_data(&token, &response);
	free_spnego_data(&response);

	if (len == -1) {
		DEBUG(1, ("Could not write SPNEGO data blob\n"));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	reply_base64 = base64_encode_data_blob(token);

	x_fprintf(x_stdout, "%s %s %s\n",
		  reply_code, reply_base64, reply_argument);

	SAFE_FREE(reply_base64);
	data_blob_free(&token);

	return;
}

static struct ntlmssp_state *client_ntlmssp_state = NULL;

static BOOL manage_client_ntlmssp_init(struct spnego_data spnego)
{
	NTSTATUS status;
	DATA_BLOB null_blob = data_blob(NULL, 0);
	DATA_BLOB to_server;
	char *to_server_base64;
	const char *my_mechs[] = {OID_NTLMSSP, NULL};

	DEBUG(10, ("Got spnego negTokenInit with NTLMSSP\n"));

	if (client_ntlmssp_state != NULL) {
		DEBUG(1, ("Request for initial SPNEGO request where "
			  "we already have a state\n"));
		return False;
	}

	if (!client_ntlmssp_state) {
		if (!NT_STATUS_IS_OK(status = ntlm_auth_start_ntlmssp_client(&client_ntlmssp_state))) {
			x_fprintf(x_stdout, "BH %s\n", nt_errstr(status));
			return False;
		}
	}


	if (opt_password == NULL) {

		/* Request a password from the calling process.  After
		   sending it, the calling process should retry with
		   the negTokenInit. */

		DEBUG(10, ("Requesting password\n"));
		x_fprintf(x_stdout, "PW\n");
		return True;
	}

	spnego.type = SPNEGO_NEG_TOKEN_INIT;
	spnego.negTokenInit.mechTypes = my_mechs;
	spnego.negTokenInit.reqFlags = 0;
	spnego.negTokenInit.mechListMIC = null_blob;

	status = ntlmssp_update(client_ntlmssp_state, 
				NULL,
				null_blob,
				&spnego.negTokenInit.mechToken);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		DEBUG(1, ("Expected MORE_PROCESSING_REQUIRED, got: %s\n",
			  nt_errstr(status)));
		ntlmssp_end(&client_ntlmssp_state);
		return False;
	}

	write_spnego_data(&to_server, &spnego);
	data_blob_free(&spnego.negTokenInit.mechToken);

	to_server_base64 = base64_encode_data_blob(to_server);
	data_blob_free(&to_server);
	x_fprintf(x_stdout, "KK %s\n", to_server_base64);
	SAFE_FREE(to_server_base64);
	return True;
}

static void manage_client_ntlmssp_targ(struct spnego_data spnego)
{
	NTSTATUS status;
	DATA_BLOB null_blob = data_blob(NULL, 0);
	DATA_BLOB request;
	DATA_BLOB to_server;
	char *to_server_base64;

	DEBUG(10, ("Got spnego negTokenTarg with NTLMSSP\n"));

	if (client_ntlmssp_state == NULL) {
		DEBUG(1, ("Got NTLMSSP tArg without a client state\n"));
		x_fprintf(x_stdout, "BH\n");
		ntlmssp_end(&client_ntlmssp_state);
		return;
	}

	if (spnego.negTokenTarg.negResult == SPNEGO_REJECT) {
		x_fprintf(x_stdout, "NA\n");
		ntlmssp_end(&client_ntlmssp_state);
		return;
	}

	if (spnego.negTokenTarg.negResult == SPNEGO_ACCEPT_COMPLETED) {
		x_fprintf(x_stdout, "AF\n");
		ntlmssp_end(&client_ntlmssp_state);
		return;
	}

	status = ntlmssp_update(client_ntlmssp_state,
				NULL,
				spnego.negTokenTarg.responseToken,
				&request);
		
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		DEBUG(1, ("Expected MORE_PROCESSING_REQUIRED from "
			  "ntlmssp_update, got: %s\n",
			  nt_errstr(status)));
		x_fprintf(x_stdout, "BH\n");
		data_blob_free(&request);
		ntlmssp_end(&client_ntlmssp_state);
		return;
	}

	spnego.type = SPNEGO_NEG_TOKEN_TARG;
	spnego.negTokenTarg.negResult = SPNEGO_ACCEPT_INCOMPLETE;
	spnego.negTokenTarg.supportedMech = OID_NTLMSSP;
	spnego.negTokenTarg.responseToken = request;
	spnego.negTokenTarg.mechListMIC = null_blob;
	
	write_spnego_data(&to_server, &spnego);
	data_blob_free(&request);

	to_server_base64 = base64_encode_data_blob(to_server);
	data_blob_free(&to_server);
	x_fprintf(x_stdout, "KK %s\n", to_server_base64);
	SAFE_FREE(to_server_base64);
	return;
}

#ifdef HAVE_KRB5

static BOOL manage_client_krb5_init(struct spnego_data spnego)
{
	char *principal;
	DATA_BLOB tkt, to_server;
	DATA_BLOB session_key_krb5 = data_blob(NULL, 0);
	struct spnego_data reply;
	char *reply_base64;
	int retval;
	
	const char *my_mechs[] = {OID_KERBEROS5_OLD, NULL};
	ssize_t len;

	if ( (spnego.negTokenInit.mechListMIC.data == NULL) ||
	     (spnego.negTokenInit.mechListMIC.length == 0) ) {
		DEBUG(1, ("Did not get a principal for krb5\n"));
		return False;
	}

	principal = malloc(spnego.negTokenInit.mechListMIC.length+1);

	if (principal == NULL) {
		DEBUG(1, ("Could not malloc principal\n"));
		return False;
	}

	memcpy(principal, spnego.negTokenInit.mechListMIC.data,
	       spnego.negTokenInit.mechListMIC.length);
	principal[spnego.negTokenInit.mechListMIC.length] = '\0';

	retval = cli_krb5_get_ticket(principal, 0, &tkt, &session_key_krb5);

	if (retval) {

		pstring user;

		/* Let's try to first get the TGT, for that we need a
                   password. */

		if (opt_password == NULL) {
			DEBUG(10, ("Requesting password\n"));
			x_fprintf(x_stdout, "PW\n");
			return True;
		}

		pstr_sprintf(user, "%s@%s", opt_username, opt_domain);

		if ((retval = kerberos_kinit_password(user, opt_password, 
						      0, NULL))) {
			DEBUG(10, ("Requesting TGT failed: %s\n", error_message(retval)));
			return False;
		}

		retval = cli_krb5_get_ticket(principal, 0, &tkt, &session_key_krb5);

		if (retval) {
			DEBUG(10, ("Kinit suceeded, but getting a ticket failed: %s\n", error_message(retval)));
			return False;
		}
	}

	data_blob_free(&session_key_krb5);

	ZERO_STRUCT(reply);

	reply.type = SPNEGO_NEG_TOKEN_INIT;
	reply.negTokenInit.mechTypes = my_mechs;
	reply.negTokenInit.reqFlags = 0;
	reply.negTokenInit.mechToken = tkt;
	reply.negTokenInit.mechListMIC = data_blob(NULL, 0);

	len = write_spnego_data(&to_server, &reply);
	data_blob_free(&tkt);

	if (len == -1) {
		DEBUG(1, ("Could not write SPNEGO data blob\n"));
		return False;
	}

	reply_base64 = base64_encode_data_blob(to_server);
	x_fprintf(x_stdout, "KK %s *\n", reply_base64);

	SAFE_FREE(reply_base64);
	data_blob_free(&to_server);
	DEBUG(10, ("sent GSS-SPNEGO KERBEROS5 negTokenInit\n"));
	return True;
}

static void manage_client_krb5_targ(struct spnego_data spnego)
{
	switch (spnego.negTokenTarg.negResult) {
	case SPNEGO_ACCEPT_INCOMPLETE:
		DEBUG(1, ("Got a Kerberos negTokenTarg with ACCEPT_INCOMPLETE\n"));
		x_fprintf(x_stdout, "BH\n");
		break;
	case SPNEGO_ACCEPT_COMPLETED:
		DEBUG(10, ("Accept completed\n"));
		x_fprintf(x_stdout, "AF\n");
		break;
	case SPNEGO_REJECT:
		DEBUG(10, ("Rejected\n"));
		x_fprintf(x_stdout, "NA\n");
		break;
	default:
		DEBUG(1, ("Got an invalid negTokenTarg\n"));
		x_fprintf(x_stdout, "AF\n");
	}
}

#endif

static void manage_gss_spnego_client_request(enum stdio_helper_mode stdio_helper_mode, 
					     char *buf, int length) 
{
	DATA_BLOB request;
	struct spnego_data spnego;
	ssize_t len;

	if (strlen(buf) <= 3) {
		DEBUG(1, ("SPNEGO query [%s] too short\n", buf));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	request = base64_decode_data_blob(buf+3);

	if (strncmp(buf, "PW ", 3) == 0) {

		/* We asked for a password and obviously got it :-) */

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

	if ( (strncmp(buf, "TT ", 3) != 0) &&
	     (strncmp(buf, "AF ", 3) != 0) &&
	     (strncmp(buf, "NA ", 3) != 0) ) {
		DEBUG(1, ("SPNEGO request [%s] invalid\n", buf));
		x_fprintf(x_stdout, "BH\n");
		data_blob_free(&request);
		return;
	}

	/* So we got a server challenge to generate a SPNEGO
           client-to-server request... */

	len = read_spnego_data(request, &spnego);
	data_blob_free(&request);

	if (len == -1) {
		DEBUG(1, ("Could not read SPNEGO data for [%s]\n", buf));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	if (spnego.type == SPNEGO_NEG_TOKEN_INIT) {

		/* The server offers a list of mechanisms */

		char **mechType = spnego.negTokenInit.mechTypes;

		while (*mechType != NULL) {

#ifdef HAVE_KRB5
			if ( (strcmp(*mechType, OID_KERBEROS5_OLD) == 0) ||
			     (strcmp(*mechType, OID_KERBEROS5) == 0) ) {
				if (manage_client_krb5_init(spnego))
					goto out;
			}
#endif

			if (strcmp(*mechType, OID_NTLMSSP) == 0) {
				if (manage_client_ntlmssp_init(spnego))
					goto out;
			}

			mechType++;
		}

		DEBUG(1, ("Server offered no compatible mechanism\n"));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	if (spnego.type == SPNEGO_NEG_TOKEN_TARG) {

		if (spnego.negTokenTarg.supportedMech == NULL) {
			/* On accept/reject Windows does not send the
                           mechanism anymore. Handle that here and
                           shut down the mechanisms. */

			switch (spnego.negTokenTarg.negResult) {
			case SPNEGO_ACCEPT_COMPLETED:
				x_fprintf(x_stdout, "AF\n");
				break;
			case SPNEGO_REJECT:
				x_fprintf(x_stdout, "NA\n");
				break;
			default:
				DEBUG(1, ("Got a negTokenTarg with no mech and an "
					  "unknown negResult: %d\n",
					  spnego.negTokenTarg.negResult));
				x_fprintf(x_stdout, "BH\n");
			}

			ntlmssp_end(&client_ntlmssp_state);
			goto out;
		}

		if (strcmp(spnego.negTokenTarg.supportedMech,
			   OID_NTLMSSP) == 0) {
			manage_client_ntlmssp_targ(spnego);
			goto out;
		}

#if HAVE_KRB5
		if (strcmp(spnego.negTokenTarg.supportedMech,
			   OID_KERBEROS5_OLD) == 0) {
			manage_client_krb5_targ(spnego);
			goto out;
		}
#endif

	}

	DEBUG(1, ("Got an SPNEGO token I could not handle [%s]!\n", buf));
	x_fprintf(x_stdout, "BH\n");
	return;

 out:
	free_spnego_data(&spnego);
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

	if (opt_domain == NULL) {
		opt_domain = lp_workgroup();
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
