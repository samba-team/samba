/* 
   Unix SMB/CIFS implementation.

   Winbind status program.

   Copyright (C) Tim Potter      2000-2002
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003
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

enum squid_mode {
	SQUID_2_4_BASIC,
	SQUID_2_5_BASIC,
	SQUID_2_5_NTLMSSP,
	GSS_SPNEGO,
	GSS_SPNEGO_CLIENT
};
	

extern int winbindd_fd;

static const char *opt_username;
static const char *opt_domain;
static const char *opt_workstation;
static const char *opt_password;
static DATA_BLOB opt_challenge;
static DATA_BLOB opt_lm_response;
static DATA_BLOB opt_nt_response;
static int request_lm_key;
static int request_nt_key;


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
		d_printf("could not obtain winbind separator!\n");
		return '\\';
	}

	sep = response.data.info.winbind_separator;
	got_sep = True;

	if (!sep) {
		d_printf("winbind separator was NULL!\n");
		return '\\';
	}
	
	return sep;
}

static const char *get_winbind_domain(void)
{
	struct winbindd_response response;

	static fstring winbind_domain;
	if (*winbind_domain) {
		return winbind_domain;
	}

	ZERO_STRUCT(response);

	/* Send off request */

	if (winbindd_request(WINBINDD_DOMAIN_NAME, NULL, &response) !=
	    NSS_STATUS_SUCCESS) {
		d_printf("could not obtain winbind domain name!\n");
		return NULL;
	}

	fstrcpy(winbind_domain, response.data.domain_name);

	return winbind_domain;

}

static const char *get_winbind_netbios_name(void)
{
	struct winbindd_response response;

	static fstring winbind_netbios_name;

	if (*winbind_netbios_name) {
		return winbind_netbios_name;
	}

	ZERO_STRUCT(response);

	/* Send off request */

	if (winbindd_request(WINBINDD_NETBIOS_NAME, NULL, &response) !=
	    NSS_STATUS_SUCCESS) {
		d_printf("could not obtain winbind netbios name!\n");
		return NULL;
	}

	fstrcpy(winbind_netbios_name, response.data.netbios_name);

	return winbind_netbios_name;

}

/* Authenticate a user with a plaintext password */

static BOOL check_plaintext_auth(const char *user, const char *pass, BOOL stdout_diagnostics)
{
	struct winbindd_request request;
	struct winbindd_response response;
        NSS_STATUS result;

	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.data.auth.user, user);
	fstrcpy(request.data.auth.pass, pass);

	result = winbindd_request(WINBINDD_PAM_AUTH, &request, &response);

	/* Display response */
	
	if (stdout_diagnostics) {
		if ((result != NSS_STATUS_SUCCESS) && (response.data.auth.nt_status == 0)) {
			d_printf("Reading winbind reply failed! (0x01)\n");
		}
		
		d_printf("%s: %s (0x%x)\n", 
			 response.data.auth.nt_status_string, 
			 response.data.auth.error_string, 
			 response.data.auth.nt_status);
	} else {
		if ((result != NSS_STATUS_SUCCESS) && (response.data.auth.nt_status == 0)) {
			DEBUG(1, ("Reading winbind reply failed! (0x01)\n"));
		}
		
		DEBUG(3, ("%s: %s (0x%x)\n", 
			  response.data.auth.nt_status_string, 
			  response.data.auth.error_string,
			  response.data.auth.nt_status));		
	}
		
        return (result == NSS_STATUS_SUCCESS);
}

/* authenticate a user with an encrypted username/password */

static NTSTATUS contact_winbind_auth_crap(const char *username, 
					  const char *domain, 
					  const char *workstation,
					  const DATA_BLOB *challenge, 
					  const DATA_BLOB *lm_response, 
					  const DATA_BLOB *nt_response, 
					  uint32 flags, 
					  uint8 lm_key[8], 
					  uint8 nt_key[16], 
					  char **error_string) 
{
	NTSTATUS nt_status;
        NSS_STATUS result;
	struct winbindd_request request;
	struct winbindd_response response;

	static uint8 zeros[16];

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	request.flags = flags;

	if (push_utf8_fstring(request.data.auth_crap.user, username) == -1) {
		*error_string = smb_xstrdup(
			"unable to create utf8 string for username");
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (push_utf8_fstring(request.data.auth_crap.domain, domain) == -1) {
		*error_string = smb_xstrdup(
			"unable to create utf8 string for domain");
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (push_utf8_fstring(request.data.auth_crap.workstation, 
			      workstation) == -1) {
		*error_string = smb_xstrdup(
			"unable to create utf8 string for workstation");
		return NT_STATUS_UNSUCCESSFUL;
	}

	memcpy(request.data.auth_crap.chal, challenge->data, MIN(challenge->length, 8));

	if (lm_response && lm_response->length) {
		memcpy(request.data.auth_crap.lm_resp, lm_response->data, MIN(lm_response->length, sizeof(request.data.auth_crap.lm_resp)));
		request.data.auth_crap.lm_resp_len = lm_response->length;
	}

	if (nt_response && nt_response->length) {
		memcpy(request.data.auth_crap.nt_resp, nt_response->data, MIN(nt_response->length, sizeof(request.data.auth_crap.nt_resp)));
                request.data.auth_crap.nt_resp_len = nt_response->length;
	}
	
	result = winbindd_request(WINBINDD_PAM_AUTH_CRAP, &request, &response);

	/* Display response */

	if ((result != NSS_STATUS_SUCCESS) && (response.data.auth.nt_status == 0)) {
		nt_status = NT_STATUS_UNSUCCESSFUL;
		if (error_string)
			*error_string = smb_xstrdup("Reading winbind reply failed!");
		return nt_status;
	}
	
	nt_status = (NT_STATUS(response.data.auth.nt_status));
	if (!NT_STATUS_IS_OK(nt_status)) {
		if (error_string) 
			*error_string = smb_xstrdup(response.data.auth.error_string);
		return nt_status;
	}

	if ((flags & WBFLAG_PAM_LMKEY) && lm_key 
	    && (memcmp(zeros, response.data.auth.first_8_lm_hash, 
		       sizeof(response.data.auth.first_8_lm_hash)) != 0)) {
		memcpy(lm_key, response.data.auth.first_8_lm_hash, 
			sizeof(response.data.auth.first_8_lm_hash));
	}
	if ((flags & WBFLAG_PAM_NTKEY) && nt_key
		    && (memcmp(zeros, response.data.auth.nt_session_key, 
			       sizeof(response.data.auth.nt_session_key)) != 0)) {
		memcpy(nt_key, response.data.auth.nt_session_key, 
			sizeof(response.data.auth.nt_session_key));
	}
	return nt_status;
}
				   
static NTSTATUS winbind_pw_check(struct ntlmssp_state *ntlmssp_state) 
{
	return contact_winbind_auth_crap(ntlmssp_state->user, ntlmssp_state->domain,
					 ntlmssp_state->workstation,
					 &ntlmssp_state->chal,
					 &ntlmssp_state->lm_resp,
					 &ntlmssp_state->nt_resp, 
					 0,
					 NULL, 
					 NULL, 
					 NULL);
}

static void manage_squid_ntlmssp_request(enum squid_mode squid_mode, 
					 char *buf, int length) 
{
	static NTLMSSP_STATE *ntlmssp_state = NULL;
	DATA_BLOB request, reply;
	NTSTATUS nt_status;

	if (strlen(buf) < 2) {
		DEBUG(1, ("NTLMSSP query [%s] invalid", buf));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	if (strlen(buf) > 3) {
		request = base64_decode_data_blob(buf + 3);
	} else if (strcmp(buf, "YR") == 0) {
		request = data_blob(NULL, 0);
		if (ntlmssp_state)
			ntlmssp_server_end(&ntlmssp_state);
	} else {
		DEBUG(1, ("NTLMSSP query [%s] invalid", buf));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	if (!ntlmssp_state) {
		ntlmssp_server_start(&ntlmssp_state);
		ntlmssp_state->check_password = winbind_pw_check;
		ntlmssp_state->get_domain = get_winbind_domain;
		ntlmssp_state->get_global_myname = get_winbind_netbios_name;
	}

	DEBUG(10, ("got NTLMSSP packet:\n"));
	dump_data(10, (const char *)request.data, request.length);

	nt_status = ntlmssp_server_update(ntlmssp_state, request, &reply);
	
	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		char *reply_base64 = base64_encode_data_blob(reply);
		x_fprintf(x_stdout, "TT %s\n", reply_base64);
		SAFE_FREE(reply_base64);
		data_blob_free(&reply);
		DEBUG(10, ("NTLMSSP challenge\n"));
	} else if (!NT_STATUS_IS_OK(nt_status)) {
		x_fprintf(x_stdout, "NA %s\n", nt_errstr(nt_status));
		DEBUG(10, ("NTLMSSP %s\n", nt_errstr(nt_status)));
	} else {
		x_fprintf(x_stdout, "AF %s\\%s\n", ntlmssp_state->domain, ntlmssp_state->user);
		DEBUG(10, ("NTLMSSP OK!\n"));
	}

	data_blob_free(&request);
}

static void manage_squid_basic_request(enum squid_mode squid_mode, 
				       char *buf, int length) 
{
	char *user, *pass;	
	user=buf;
	
	pass=memchr(buf,' ',length);
	if (!pass) {
		DEBUG(2, ("Password not found. Denying access\n"));
		x_fprintf(x_stderr, "ERR\n");
		return;
	}
	*pass='\0';
	pass++;
	
	if (squid_mode == SQUID_2_5_BASIC) {
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
	SPNEGO_DATA spnego;
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

static void manage_gss_spnego_request(enum squid_mode squid_mode,
				      char *buf, int length) 
{
	static NTLMSSP_STATE *ntlmssp_state = NULL;
	SPNEGO_DATA request, response;
	DATA_BLOB token;
	NTSTATUS status;
	ssize_t len;

	char *user = NULL;
	char *domain = NULL;

	const char *reply_code;
	char       *reply_base64;
	pstring     reply_argument;

	if (strlen(buf) < 2) {

		if (ntlmssp_state != NULL) {
			DEBUG(1, ("Request for initial SPNEGO request where "
				  "we already have a state\n"));
			x_fprintf(x_stdout, "BH\n");
			return;
		}

		DEBUG(1, ("NTLMSSP query [%s] invalid", buf));
		x_fprintf(x_stdout, "BH\n");
		return;
	}

	if ( (strlen(buf) == 2) && (strcmp(buf, "YR") == 0) ) {

		/* Initial request, get the negTokenInit offering
                   mechanisms */

		offer_gss_spnego_mechs();
		return;
	}

	/* All subsequent requests are "KK" (Knock, Knock ;)) and have
	   a blob. This might be negTokenInit or negTokenTarg */

	if ( (strlen(buf) <= 3) || (strncmp(buf, "KK", 2) != 0) ) {
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
		   client offers its mechanism to use. We currently
		   only support NTLMSSP, the decision for Kerberos
		   would be taken here. */

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
				ntlmssp_server_end(&ntlmssp_state);
				return;
			}

			ntlmssp_server_start(&ntlmssp_state);
			ntlmssp_state->check_password = winbind_pw_check;
			ntlmssp_state->get_domain = get_winbind_domain;
			ntlmssp_state->get_global_myname = get_winbind_netbios_name;

			DEBUG(10, ("got NTLMSSP packet:\n"));
			dump_data(10, (const char *)request.negTokenInit.mechToken.data,
				  request.negTokenInit.mechToken.length);

			response.type = SPNEGO_NEG_TOKEN_TARG;
			response.negTokenTarg.supportedMech = strdup(OID_NTLMSSP);
			response.negTokenTarg.mechListMIC = data_blob(NULL, 0);

			status = ntlmssp_server_update(ntlmssp_state,
						       request.negTokenInit.mechToken,
						       &response.negTokenTarg.responseToken);
		}

#ifdef HAVE_KRB5
		if (strcmp(request.negTokenInit.mechTypes[0], OID_KERBEROS5_OLD) == 0) {

			char *principal;
			DATA_BLOB auth_data;
			DATA_BLOB ap_rep;
			uint8 session_key[16];

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
						   session_key);

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

		status = ntlmssp_server_update(ntlmssp_state,
					       request.negTokenTarg.responseToken,
					       &response.negTokenTarg.responseToken);

		response.type = SPNEGO_NEG_TOKEN_TARG;
		response.negTokenTarg.supportedMech = strdup(OID_NTLMSSP);
		response.negTokenTarg.mechListMIC = data_blob(NULL, 0);

		if (NT_STATUS_IS_OK(status)) {
			user = strdup(ntlmssp_state->user);
			domain = strdup(ntlmssp_state->domain);
			ntlmssp_server_end(&ntlmssp_state);
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

static NTLMSSP_CLIENT_STATE *client_ntlmssp_state = NULL;

static BOOL manage_client_ntlmssp_init(SPNEGO_DATA spnego)
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

	if ( (opt_username == NULL) || (opt_domain == NULL) ) {
		DEBUG(1, ("Need username and domain for NTLMSSP\n"));
		return False;
	}

	if (opt_password == NULL) {

		/* Request a password from the calling process.  After
		   sending it, the calling process should retry with
		   the negTokenInit. */

		DEBUG(10, ("Requesting password\n"));
		x_fprintf(x_stdout, "PW\n");
		return True;
	}

	status = ntlmssp_client_start(&client_ntlmssp_state);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not start NTLMSSP client: %s\n",
			  nt_errstr(status)));
		ntlmssp_client_end(&client_ntlmssp_state);
		return False;
	}

	status = ntlmssp_set_username(client_ntlmssp_state, opt_username);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not set username: %s\n",
			  nt_errstr(status)));
		ntlmssp_client_end(&client_ntlmssp_state);
		return False;
	}

	status = ntlmssp_set_domain(client_ntlmssp_state, opt_domain);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not set domain: %s\n",
			  nt_errstr(status)));
		ntlmssp_client_end(&client_ntlmssp_state);
		return False;
	}

	status = ntlmssp_set_password(client_ntlmssp_state, opt_password);
	
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not set password: %s\n",
			  nt_errstr(status)));
		ntlmssp_client_end(&client_ntlmssp_state);
		return False;
	}

	spnego.type = SPNEGO_NEG_TOKEN_INIT;
	spnego.negTokenInit.mechTypes = my_mechs;
	spnego.negTokenInit.reqFlags = 0;
	spnego.negTokenInit.mechListMIC = null_blob;

	status = ntlmssp_client_update(client_ntlmssp_state, null_blob,
				       &spnego.negTokenInit.mechToken);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		DEBUG(1, ("Expected MORE_PROCESSING_REQUIRED, got: %s\n",
			  nt_errstr(status)));
		ntlmssp_client_end(&client_ntlmssp_state);
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

static void manage_client_ntlmssp_targ(SPNEGO_DATA spnego)
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
		ntlmssp_client_end(&client_ntlmssp_state);
		return;
	}

	if (spnego.negTokenTarg.negResult == SPNEGO_REJECT) {
		x_fprintf(x_stdout, "NA\n");
		ntlmssp_client_end(&client_ntlmssp_state);
		return;
	}

	if (spnego.negTokenTarg.negResult == SPNEGO_ACCEPT_COMPLETED) {
		x_fprintf(x_stdout, "AF\n");
		ntlmssp_client_end(&client_ntlmssp_state);
		return;
	}

	status = ntlmssp_client_update(client_ntlmssp_state,
				       spnego.negTokenTarg.responseToken,
				       &request);
		
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		DEBUG(1, ("Expected MORE_PROCESSING_REQUIRED from "
			  "ntlmssp_client_update, got: %s\n",
			  nt_errstr(status)));
		x_fprintf(x_stdout, "BH\n");
		data_blob_free(&request);
		ntlmssp_client_end(&client_ntlmssp_state);
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

static BOOL manage_client_krb5_init(SPNEGO_DATA spnego)
{
	char *principal;
	DATA_BLOB tkt, to_server;
	unsigned char session_key_krb5[16];
	SPNEGO_DATA reply;
	char *reply_base64;
	
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

	tkt = cli_krb5_get_ticket(principal, 0, session_key_krb5);

	if (tkt.data == NULL) {

		pstring user;

		/* Let's try to first get the TGT, for that we need a
                   password. */

		if (opt_password == NULL) {
			DEBUG(10, ("Requesting password\n"));
			x_fprintf(x_stdout, "PW\n");
			return True;
		}

		pstr_sprintf(user, "%s@%s", opt_username, opt_domain);

		if (kerberos_kinit_password(user, opt_password, 0) != 0) {
			DEBUG(10, ("Requesting TGT failed\n"));
			x_fprintf(x_stdout, "NA\n");
			return True;
		}

		tkt = cli_krb5_get_ticket(principal, 0, session_key_krb5);
	}

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

static void manage_client_krb5_targ(SPNEGO_DATA spnego)
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

static void manage_gss_spnego_client_request(enum squid_mode squid_mode,
					     char *buf, int length) 
{
	DATA_BLOB request;
	SPNEGO_DATA spnego;
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

		const char **mechType = spnego.negTokenInit.mechTypes;

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

			ntlmssp_client_end(&client_ntlmssp_state);
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

static void manage_squid_request(enum squid_mode squid_mode) 
{
	char buf[SQUID_BUFFER_SIZE+1];
	int length;
	char *c;
	static BOOL err;

	/* this is not a typo - x_fgets doesn't work too well under squid */
	if (fgets(buf, sizeof(buf)-1, stdin) == NULL) {
		DEBUG(1, ("fgets() failed! dying..... errno=%d (%s)\n", ferror(stdin),
			  strerror(ferror(stdin))));
		exit(1);    /* BIIG buffer */
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
	
	if (squid_mode == SQUID_2_5_BASIC || squid_mode == SQUID_2_4_BASIC) {
		manage_squid_basic_request(squid_mode, buf, length);
	} else if (squid_mode == SQUID_2_5_NTLMSSP) {
		manage_squid_ntlmssp_request(squid_mode, buf, length);
	} else if (squid_mode == GSS_SPNEGO) {
		manage_gss_spnego_request(squid_mode, buf, length);
	} else if (squid_mode == GSS_SPNEGO_CLIENT) {
		manage_gss_spnego_client_request(squid_mode, buf, length);
	}
}


static void squid_stream(enum squid_mode squid_mode) {
	/* initialize FDescs */
	x_setbuf(x_stdout, NULL);
	x_setbuf(x_stderr, NULL);
	while(1) {
		manage_squid_request(squid_mode);
	}
}


/* Authenticate a user with a challenge/response */

static BOOL check_auth_crap(void)
{
	NTSTATUS nt_status;
	uint32 flags = 0;
	char lm_key[8];
	char nt_key[16];
	char *hex_lm_key;
	char *hex_nt_key;
	char *error_string;
	static uint8 zeros[16];

	x_setbuf(x_stdout, NULL);

	if (request_lm_key) 
		flags |= WBFLAG_PAM_LMKEY;

	if (request_nt_key) 
		flags |= WBFLAG_PAM_NTKEY;

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain, 
					      opt_workstation,
					      &opt_challenge, 
					      &opt_lm_response, 
					      &opt_nt_response, 
					      flags,
					      (unsigned char *)lm_key, 
					      (unsigned char *)nt_key, 
					      &error_string);

	if (!NT_STATUS_IS_OK(nt_status)) {
		x_fprintf(x_stdout, "%s (0x%x)\n", 
			  error_string,
			  NT_STATUS_V(nt_status));
		SAFE_FREE(error_string);
		return False;
	}

	if (request_lm_key 
	    && (memcmp(zeros, lm_key, 
		       sizeof(lm_key)) != 0)) {
		hex_encode((const unsigned char *)lm_key,
			   sizeof(lm_key),
			   &hex_lm_key);
		x_fprintf(x_stdout, "LM_KEY: %s\n", hex_lm_key);
		SAFE_FREE(hex_lm_key);
	}
	if (request_nt_key 
	    && (memcmp(zeros, nt_key, 
		       sizeof(nt_key)) != 0)) {
		hex_encode((const unsigned char *)nt_key, 
			   sizeof(nt_key), 
			   &hex_nt_key);
		x_fprintf(x_stdout, "NT_KEY: %s\n", hex_nt_key);
		SAFE_FREE(hex_nt_key);
	}

        return True;
}

/* 
   Authenticate a user with a challenge/response, checking session key
   and valid authentication types
*/

static DATA_BLOB get_challenge(void) 
{
	static DATA_BLOB chal;
	if (opt_challenge.length)
		return opt_challenge;
	
	chal = data_blob(NULL, 8);

	generate_random_buffer(chal.data, chal.length, False);
	return chal;
}

/* 
 * Test LM authentication, no NT response supplied
 */

static BOOL test_lm(void) 
{
	NTSTATUS nt_status;
	uint32 flags = 0;
	DATA_BLOB lm_response = data_blob(NULL, 24);

	uchar lm_key[8];
	uchar nt_key[16];
	uchar lm_hash[16];
	DATA_BLOB chall = get_challenge();
	char *error_string;
	
	ZERO_STRUCT(lm_key);
	ZERO_STRUCT(nt_key);

	flags |= WBFLAG_PAM_LMKEY;
	flags |= WBFLAG_PAM_NTKEY;

	SMBencrypt(opt_password, chall.data, lm_response.data);
	E_deshash(opt_password, lm_hash); 

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain, opt_workstation,
					      &chall,
					      &lm_response,
					      NULL,
					      flags,
					      lm_key, 
					      nt_key,
					      &error_string);
	
	data_blob_free(&lm_response);

	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("%s (0x%x)\n", 
			 error_string,
			 NT_STATUS_V(nt_status));
		return False;
	}

	if (memcmp(lm_hash, lm_key, 
		   sizeof(lm_key)) != 0) {
		DEBUG(1, ("LM Key does not match expectations!\n"));
 		DEBUG(1, ("lm_key:\n"));
		dump_data(1, (const char *)lm_key, 8);
 		DEBUG(1, ("expected:\n"));
		dump_data(1, (const char *)lm_hash, 8);
	}
	if (memcmp(lm_hash, nt_key, 8) != 0) {
		DEBUG(1, ("Session Key (first 8, lm hash) does not match expectations!\n"));
 		DEBUG(1, ("nt_key:\n"));
		dump_data(1, (const char *)nt_key, 8);
 		DEBUG(1, ("expected:\n"));
		dump_data(1, (const char *)lm_hash, 8);
	}
        return True;
}

/* 
 * Test the normal 'LM and NTLM' combination
 */

static BOOL test_lm_ntlm(void) 
{
	BOOL pass = True;
	NTSTATUS nt_status;
	uint32 flags = 0;
	DATA_BLOB lm_response = data_blob(NULL, 24);
	DATA_BLOB nt_response = data_blob(NULL, 24);
	DATA_BLOB session_key = data_blob(NULL, 16);

	uchar lm_key[8];
	uchar nt_key[16];
	uchar lm_hash[16];
	uchar nt_hash[16];
	DATA_BLOB chall = get_challenge();
	char *error_string;
	
	ZERO_STRUCT(lm_key);
	ZERO_STRUCT(nt_key);

	flags |= WBFLAG_PAM_LMKEY;
	flags |= WBFLAG_PAM_NTKEY;

	SMBencrypt(opt_password,chall.data,lm_response.data);
	E_deshash(opt_password, lm_hash); 

	SMBNTencrypt(opt_password,chall.data,nt_response.data);

	E_md4hash(opt_password, nt_hash);
	SMBsesskeygen_ntv1(nt_hash, NULL, session_key.data);

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain, 
					      opt_workstation,
					      &chall,
					      &lm_response,
					      &nt_response,
					      flags,
					      lm_key, 
					      nt_key,
					      &error_string);
	
	data_blob_free(&lm_response);

	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("%s (0x%x)\n", 
			 error_string,
			 NT_STATUS_V(nt_status));
		SAFE_FREE(error_string);
		return False;
	}

	if (memcmp(lm_hash, lm_key, 
		   sizeof(lm_key)) != 0) {
		DEBUG(1, ("LM Key does not match expectations!\n"));
 		DEBUG(1, ("lm_key:\n"));
		dump_data(1, (const char *)lm_key, 8);
		DEBUG(1, ("expected:\n"));
		dump_data(1, (const char *)lm_hash, 8);
		pass = False;
	}
	if (memcmp(session_key.data, nt_key, 
		   sizeof(nt_key)) != 0) {
		DEBUG(1, ("NT Session Key does not match expectations!\n"));
 		DEBUG(1, ("nt_key:\n"));
		dump_data(1, (const char *)nt_key, 16);
 		DEBUG(1, ("expected:\n"));
		dump_data(1, (const char *)session_key.data, session_key.length);
		pass = False;
	}
        return pass;
}

/* 
 * Test the NTLM response only, no LM.
 */

static BOOL test_ntlm(void) 
{
	BOOL pass = True;
	NTSTATUS nt_status;
	uint32 flags = 0;
	DATA_BLOB nt_response = data_blob(NULL, 24);
	DATA_BLOB session_key = data_blob(NULL, 16);

	char lm_key[8];
	char nt_key[16];
	char lm_hash[16];
	char nt_hash[16];
	DATA_BLOB chall = get_challenge();
	char *error_string;
	
	ZERO_STRUCT(lm_key);
	ZERO_STRUCT(nt_key);

	flags |= WBFLAG_PAM_LMKEY;
	flags |= WBFLAG_PAM_NTKEY;

	SMBNTencrypt(opt_password,chall.data,nt_response.data);
	E_md4hash(opt_password, (unsigned char *)nt_hash);
	SMBsesskeygen_ntv1((const unsigned char *)nt_hash, NULL, session_key.data);

	E_deshash(opt_password, (unsigned char *)lm_hash); 

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain, 
					      opt_workstation,
					      &chall,
					      NULL,
					      &nt_response,
					      flags,
					      (unsigned char *)lm_key,
					      (unsigned char *)nt_key,
					      &error_string);
	
	data_blob_free(&nt_response);

	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("%s (0x%x)\n", 
			 error_string,
			 NT_STATUS_V(nt_status));
		SAFE_FREE(error_string);
		return False;
	}

	if (memcmp(lm_hash, lm_key, 
		   sizeof(lm_key)) != 0) {
		DEBUG(1, ("LM Key does not match expectations!\n"));
 		DEBUG(1, ("lm_key:\n"));
		dump_data(1, lm_key, 8);
		DEBUG(1, ("expected:\n"));
		dump_data(1, lm_hash, 8);
		pass = False;
	}
	if (memcmp(session_key.data, nt_key, 
		   sizeof(nt_key)) != 0) {
		DEBUG(1, ("NT Session Key does not match expectations!\n"));
 		DEBUG(1, ("nt_key:\n"));
		dump_data(1, nt_key, 16);
 		DEBUG(1, ("expected:\n"));
		dump_data(1, (const char *)session_key.data, session_key.length);
		pass = False;
	}
        return pass;
}

/* 
 * Test the NTLM response only, but in the LM field.
 */

static BOOL test_ntlm_in_lm(void) 
{
	BOOL pass = True;
	NTSTATUS nt_status;
	uint32 flags = 0;
	DATA_BLOB nt_response = data_blob(NULL, 24);

	uchar lm_key[8];
	uchar lm_hash[16];
	uchar nt_key[16];
	DATA_BLOB chall = get_challenge();
	char *error_string;
	
	ZERO_STRUCT(nt_key);

	flags |= WBFLAG_PAM_LMKEY;
	flags |= WBFLAG_PAM_NTKEY;

	SMBNTencrypt(opt_password,chall.data,nt_response.data);

	E_deshash(opt_password, lm_hash); 

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain, 
					      opt_workstation,
					      &chall,
					      &nt_response,
					      NULL,
					      flags,
					      lm_key,
					      nt_key,
					      &error_string);
	
	data_blob_free(&nt_response);

	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("%s (0x%x)\n", 
			 error_string,
			 NT_STATUS_V(nt_status));
		SAFE_FREE(error_string);
		return False;
	}

	if (memcmp(lm_hash, lm_key, 
		   sizeof(lm_key)) != 0) {
		DEBUG(1, ("LM Key does not match expectations!\n"));
 		DEBUG(1, ("lm_key:\n"));
		dump_data(1, (const char *)lm_key, 8);
		DEBUG(1, ("expected:\n"));
		dump_data(1, (const char *)lm_hash, 8);
		pass = False;
	}
	if (memcmp(lm_hash, nt_key, 8) != 0) {
		DEBUG(1, ("Session Key (first 8 lm hash) does not match expectations!\n"));
 		DEBUG(1, ("nt_key:\n"));
		dump_data(1, (const char *)nt_key, 16);
 		DEBUG(1, ("expected:\n"));
		dump_data(1, (const char *)lm_hash, 8);
		pass = False;
	}
        return pass;
}

/* 
 * Test the NTLM response only, but in the both the NT and LM fields.
 */

static BOOL test_ntlm_in_both(void) 
{
	BOOL pass = True;
	NTSTATUS nt_status;
	uint32 flags = 0;
	DATA_BLOB nt_response = data_blob(NULL, 24);
	DATA_BLOB session_key = data_blob(NULL, 16);

	char lm_key[8];
	char lm_hash[16];
	char nt_key[16];
	char nt_hash[16];
	DATA_BLOB chall = get_challenge();
	char *error_string;
	
	ZERO_STRUCT(lm_key);
	ZERO_STRUCT(nt_key);

	flags |= WBFLAG_PAM_LMKEY;
	flags |= WBFLAG_PAM_NTKEY;

	SMBNTencrypt(opt_password,chall.data,nt_response.data);
	E_md4hash(opt_password, (unsigned char *)nt_hash);
	SMBsesskeygen_ntv1((const unsigned char *)nt_hash, NULL, session_key.data);

	E_deshash(opt_password, (unsigned char *)lm_hash); 

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain, 
					      opt_workstation,
					      &chall,
					      &nt_response,
					      &nt_response,
					      flags,
					      (unsigned char *)lm_key,
					      (unsigned char *)nt_key,
					      &error_string);
	
	data_blob_free(&nt_response);

	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("%s (0x%x)\n", 
			 error_string,
			 NT_STATUS_V(nt_status));
		SAFE_FREE(error_string);
		return False;
	}

	if (memcmp(lm_hash, lm_key, 
		   sizeof(lm_key)) != 0) {
		DEBUG(1, ("LM Key does not match expectations!\n"));
 		DEBUG(1, ("lm_key:\n"));
		dump_data(1, lm_key, 8);
		DEBUG(1, ("expected:\n"));
		dump_data(1, lm_hash, 8);
		pass = False;
	}
	if (memcmp(session_key.data, nt_key, 
		   sizeof(nt_key)) != 0) {
		DEBUG(1, ("NT Session Key does not match expectations!\n"));
 		DEBUG(1, ("nt_key:\n"));
		dump_data(1, nt_key, 16);
 		DEBUG(1, ("expected:\n"));
		dump_data(1, (const char *)session_key.data, session_key.length);
		pass = False;
	}


        return pass;
}

/* 
 * Test the NTLMv2 response only
 */

static BOOL test_ntlmv2(void) 
{
	BOOL pass = True;
	NTSTATUS nt_status;
	uint32 flags = 0;
	DATA_BLOB ntlmv2_response = data_blob(NULL, 0);
	DATA_BLOB nt_session_key = data_blob(NULL, 0);
	DATA_BLOB names_blob = NTLMv2_generate_names_blob(get_winbind_netbios_name(), get_winbind_domain());

	uchar nt_key[16];
	DATA_BLOB chall = get_challenge();
	char *error_string;

	ZERO_STRUCT(nt_key);
	
	flags |= WBFLAG_PAM_NTKEY;

	if (!SMBNTLMv2encrypt(opt_username, opt_domain, opt_password, &chall,
			      &names_blob,
			      NULL, &ntlmv2_response, 
			      &nt_session_key)) {
		data_blob_free(&names_blob);
		return False;
	}
	data_blob_free(&names_blob);

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain, 
					      opt_workstation,
					      &chall,
					      NULL, 
					      &ntlmv2_response,
					      flags,
					      NULL, 
					      nt_key,
					      &error_string);
	
	data_blob_free(&ntlmv2_response);

	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("%s (0x%x)\n", 
			 error_string,
			 NT_STATUS_V(nt_status));
		SAFE_FREE(error_string);
		return False;
	}

	if (memcmp(nt_session_key.data, nt_key, 
		   sizeof(nt_key)) != 0) {
		DEBUG(1, ("NT Session Key does not match expectations!\n"));
 		DEBUG(1, ("nt_key:\n"));
		dump_data(1, (const char *)nt_key, 16);
 		DEBUG(1, ("expected:\n"));
		dump_data(1, (const char *)nt_session_key.data, nt_session_key.length);
		pass = False;
	}
        return pass;
}

/* 
 * Test the NTLMv2 and LMv2 responses
 */

static BOOL test_lmv2_ntlmv2(void) 
{
	BOOL pass = True;
	NTSTATUS nt_status;
	uint32 flags = 0;
	DATA_BLOB ntlmv2_response = data_blob(NULL, 0);
	DATA_BLOB lmv2_response = data_blob(NULL, 0);
	DATA_BLOB nt_session_key = data_blob(NULL, 0);
	DATA_BLOB names_blob = NTLMv2_generate_names_blob(get_winbind_netbios_name(), get_winbind_domain());

	uchar nt_key[16];
	DATA_BLOB chall = get_challenge();
	char *error_string;

	ZERO_STRUCT(nt_key);
	
	flags |= WBFLAG_PAM_NTKEY;

	if (!SMBNTLMv2encrypt(opt_username, opt_domain, opt_password, &chall,
			      &names_blob,
			      &lmv2_response, &ntlmv2_response, 
			      &nt_session_key)) {
		data_blob_free(&names_blob);
		return False;
	}
	data_blob_free(&names_blob);

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain, 
					      opt_workstation,
					      &chall,
					      &lmv2_response,
					      &ntlmv2_response,
					      flags,
					      NULL, 
					      nt_key,
					      &error_string);
	
	data_blob_free(&lmv2_response);
	data_blob_free(&ntlmv2_response);

	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("%s (0x%x)\n", 
			 error_string,
			 NT_STATUS_V(nt_status));
		SAFE_FREE(error_string);
		return False;
	}

	if (memcmp(nt_session_key.data, nt_key, 
		   sizeof(nt_key)) != 0) {
		DEBUG(1, ("NT Session Key does not match expectations!\n"));
 		DEBUG(1, ("nt_key:\n"));
		dump_data(1, (const char *)nt_key, 16);
 		DEBUG(1, ("expected:\n"));
		dump_data(1, (const char *)nt_session_key.data, nt_session_key.length);
		pass = False;
	}
        return pass;
}

/* 
 * Test the LMv2 response only
 */

static BOOL test_lmv2(void) 
{
	BOOL pass = True;
	NTSTATUS nt_status;
	uint32 flags = 0;
	DATA_BLOB lmv2_response = data_blob(NULL, 0);

	DATA_BLOB chall = get_challenge();
	char *error_string;

	if (!SMBNTLMv2encrypt(opt_username, opt_domain, opt_password, &chall,
			      NULL, 
			      &lmv2_response, NULL,
			      NULL)) {
		return False;
	}

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain, 
					      opt_workstation,
					      &chall,
					      &lmv2_response,
					      NULL, 
					      flags,
					      NULL, 
					      NULL,
					      &error_string);
	
	data_blob_free(&lmv2_response);

	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("%s (0x%x)\n", 
			 error_string,
			 NT_STATUS_V(nt_status));
		SAFE_FREE(error_string);
		return False;
	}

        return pass;
}

/* 
 * Test the normal 'LM and NTLM' combination but deliberately break one
 */

static BOOL test_ntlm_broken(BOOL break_lm) 
{
	BOOL pass = True;
	NTSTATUS nt_status;
	uint32 flags = 0;
	DATA_BLOB lm_response = data_blob(NULL, 24);
	DATA_BLOB nt_response = data_blob(NULL, 24);
	DATA_BLOB session_key = data_blob(NULL, 16);

	uchar lm_key[8];
	uchar nt_key[16];
	uchar lm_hash[16];
	uchar nt_hash[16];
	DATA_BLOB chall = get_challenge();
	char *error_string;
	
	ZERO_STRUCT(lm_key);
	ZERO_STRUCT(nt_key);

	flags |= WBFLAG_PAM_LMKEY;
	flags |= WBFLAG_PAM_NTKEY;

	SMBencrypt(opt_password,chall.data,lm_response.data);
	E_deshash(opt_password, lm_hash); 

	SMBNTencrypt(opt_password,chall.data,nt_response.data);

	E_md4hash(opt_password, nt_hash);
	SMBsesskeygen_ntv1(nt_hash, NULL, session_key.data);

	if (break_lm)
		lm_response.data[0]++;
	else
		nt_response.data[0]++;

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain, 
					      opt_workstation,
					      &chall,
					      &lm_response,
					      &nt_response,
					      flags,
					      lm_key, 
					      nt_key,
					      &error_string);
	
	data_blob_free(&lm_response);

	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("%s (0x%x)\n", 
			 error_string,
			 NT_STATUS_V(nt_status));
		SAFE_FREE(error_string);
		return False;
	}

	if (memcmp(lm_hash, lm_key, 
		   sizeof(lm_key)) != 0) {
		DEBUG(1, ("LM Key does not match expectations!\n"));
 		DEBUG(1, ("lm_key:\n"));
		dump_data(1, (const char *)lm_key, 8);
		DEBUG(1, ("expected:\n"));
		dump_data(1, (const char *)lm_hash, 8);
		pass = False;
	}
	if (memcmp(session_key.data, nt_key, 
		   sizeof(nt_key)) != 0) {
		DEBUG(1, ("NT Session Key does not match expectations!\n"));
 		DEBUG(1, ("nt_key:\n"));
		dump_data(1, (const char *)nt_key, 16);
 		DEBUG(1, ("expected:\n"));
		dump_data(1, (const char *)session_key.data, session_key.length);
		pass = False;
	}
        return pass;
}

static BOOL test_ntlm_lm_broken(void) 
{
	return test_ntlm_broken(True);
}

static BOOL test_ntlm_ntlm_broken(void) 
{
	return test_ntlm_broken(False);
}

static BOOL test_ntlmv2_broken(BOOL break_lmv2)
{
	BOOL pass = True;
	NTSTATUS nt_status;
	uint32 flags = 0;
	DATA_BLOB ntlmv2_response = data_blob(NULL, 0);
	DATA_BLOB lmv2_response = data_blob(NULL, 0);
	DATA_BLOB nt_session_key = data_blob(NULL, 0);
	DATA_BLOB names_blob = NTLMv2_generate_names_blob(get_winbind_netbios_name(), get_winbind_domain());

	uchar nt_key[16];
	DATA_BLOB chall = get_challenge();
	char *error_string;

	ZERO_STRUCT(nt_key);
	
	flags |= WBFLAG_PAM_NTKEY;
	 
	if (!SMBNTLMv2encrypt(opt_username, opt_domain, opt_password, &chall,
			      &names_blob,
			      &lmv2_response, &ntlmv2_response, 
			      &nt_session_key)) {
		data_blob_free(&names_blob);
		return False;
	}
	data_blob_free(&names_blob);

	/* Heh - this should break the appropriate password hash nicely! */

	if (break_lmv2)
		lmv2_response.data[0]++;
	else
		ntlmv2_response.data[0]++;

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain, 
					      opt_workstation,
					      &chall,
					      &lmv2_response,
					      &ntlmv2_response,
					      flags,
					      NULL,
					      nt_key,
					      &error_string);
	
	data_blob_free(&lmv2_response);
	data_blob_free(&ntlmv2_response);

	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("%s (0x%x)\n", 
			 error_string,
			 NT_STATUS_V(nt_status));
		SAFE_FREE(error_string);
		return False;
	}

        return pass;
}

static BOOL test_ntlmv2_lmv2_broken(void) 
{
	return test_ntlmv2_broken(True);
}

static BOOL test_ntlmv2_ntlmv2_broken(void) 
{
	return test_ntlmv2_broken(False);
}

/* 
   Tests:
   
   - LM only
   - NT and LM		   
   - NT
   - NT in LM field
   - NT in both fields
   - NTLMv2
   - NTLMv2 and LMv2
   - LMv2
   
   check we get the correct session key in each case
   check what values we get for the LM session key
   
*/

struct ntlm_tests {
	BOOL (*fn)(void);
	const char *name;
} test_table[] = {
	{test_lm, "LM"},
	{test_lm_ntlm, "LM and NTLM"},
	{test_ntlm, "NTLM"},
	{test_ntlm_in_lm, "NTLM in LM"},
	{test_ntlm_in_both, "NTLM in both"},
	{test_ntlmv2, "NTLMv2"},
	{test_lmv2_ntlmv2, "NTLMv2 and LMv2"},
	{test_lmv2, "LMv2"},
	{test_ntlmv2_lmv2_broken, "NTLMv2 and LMv2, LMv2 broken"},
	{test_ntlmv2_ntlmv2_broken, "NTLMv2 and LMv2, NTLMv2 broken"},
	{test_ntlm_lm_broken, "NTLM and LM, LM broken"},
	{test_ntlm_ntlm_broken, "NTLM and LM, NTLM broken"}
};

static BOOL diagnose_ntlm_auth(void)
{
	unsigned int i;
	BOOL pass = True;

	for (i=0; test_table[i].fn; i++) {
		if (!test_table[i].fn()) {
			DEBUG(1, ("Test %s failed!\n", test_table[i].name));
			pass = False;
		}
	}

        return pass;
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
	OPT_NT_KEY,
	OPT_DIAGNOSTICS
};

 int main(int argc, const char **argv)
{
	int opt;
	static const char *helper_protocol;
	static int diagnostics;

	static const char *hex_challenge;
	static const char *hex_lm_response;
	static const char *hex_nt_response;
	char *challenge;
	char *lm_response;
	char *nt_response;
	size_t challenge_len;
	size_t lm_response_len;
	size_t nt_response_len;

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
 		{ "username", 0, POPT_ARG_STRING, &opt_username, OPT_USERNAME, "username"},
 		{ "domain", 0, POPT_ARG_STRING, &opt_domain, OPT_DOMAIN, "domain name"},
 		{ "workstation", 0, POPT_ARG_STRING, &opt_workstation, OPT_WORKSTATION, "workstation"},
 		{ "challenge", 0, POPT_ARG_STRING, &hex_challenge, OPT_CHALLENGE, "challenge (HEX encoded)"},
		{ "lm-response", 0, POPT_ARG_STRING, &hex_lm_response, OPT_LM, "LM Response to the challenge (HEX encoded)"},
		{ "nt-response", 0, POPT_ARG_STRING, &hex_nt_response, OPT_NT, "NT or NTLMv2 Response to the challenge (HEX encoded)"},
		{ "password", 0, POPT_ARG_STRING, &opt_password, OPT_PASSWORD, "User's plaintext password"},		
		{ "request-lm-key", 0, POPT_ARG_NONE, &request_lm_key, OPT_LM_KEY, "Retreive LM session key"},
		{ "request-nt-key", 0, POPT_ARG_NONE, &request_nt_key, OPT_NT_KEY, "Retreive NT session key"},
		{ "diagnostics", 0, POPT_ARG_NONE, &diagnostics, OPT_DIAGNOSTICS, "Perform diagnostics on the authentictaion chain"},
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};

	/* Samba client initialisation */

	dbf = x_stderr;
	
	/* Samba client initialisation */

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
		switch (opt) {
		case OPT_CHALLENGE:
			challenge = smb_xmalloc((strlen(hex_challenge))/2+1);
			if ((challenge_len = strhex_to_str(challenge, 
							   strlen(hex_challenge), 
							   hex_challenge)) != 8) {
				x_fprintf(x_stderr, "hex decode of %s failed (only got %u bytes)!\n", 
					hex_challenge, challenge_len);
				exit(1);
			}
			opt_challenge = data_blob(challenge, challenge_len);
			SAFE_FREE(challenge);
			break;
		case OPT_LM: 
			lm_response = smb_xmalloc((strlen(hex_lm_response))/2+1);
			lm_response_len = strhex_to_str(lm_response, 	
							strlen(hex_lm_response), 
							hex_lm_response);
			if (lm_response_len != 24) {
				x_fprintf(x_stderr, "hex decode of %s failed!\n", hex_lm_response);
				exit(1);
			}
			opt_lm_response = data_blob(lm_response, lm_response_len);
			SAFE_FREE(lm_response);
			break;
		case OPT_NT: 
			nt_response = smb_xmalloc((strlen(hex_nt_response)+2)/2+1);
			nt_response_len = strhex_to_str(nt_response, 
							strlen(hex_nt_response), 
							hex_nt_response);
			if (nt_response_len < 24) {
				x_fprintf(x_stderr, "hex decode of %s failed!\n", hex_nt_response);
				exit(1);
			}
			opt_nt_response = data_blob(nt_response, nt_response_len);
			SAFE_FREE(nt_response);
			break;
		}
	}

	if (helper_protocol) {
		if (strcmp(helper_protocol, "squid-2.5-ntlmssp")== 0) {
			squid_stream(SQUID_2_5_NTLMSSP);
		} else if (strcmp(helper_protocol, "squid-2.5-basic")== 0) {
			squid_stream(SQUID_2_5_BASIC);
		} else if (strcmp(helper_protocol, "squid-2.4-basic")== 0) {
			squid_stream(SQUID_2_4_BASIC);
		} else if (strcmp(helper_protocol, "gss-spnego")== 0) {
			squid_stream(GSS_SPNEGO);
		} else if (strcmp(helper_protocol, "gss-spnego-client") == 0) {
			squid_stream(GSS_SPNEGO_CLIENT);
		} else {
			x_fprintf(x_stderr, "unknown helper protocol [%s]\n", helper_protocol);
			exit(1);
		}
	}

	if (!opt_username) {
		x_fprintf(x_stderr, "username must be specified!\n\n");
		poptPrintHelp(pc, stderr, 0);
		exit(1);
	}

	if (opt_domain == NULL) {
		opt_domain = get_winbind_domain();
	}

	if (opt_workstation == NULL) {
		opt_workstation = "";
	}

	if (opt_challenge.length) {
		if (!check_auth_crap()) {
			exit(1);
		}
		exit(0);
	} 

	if (!opt_password) {
		opt_password = getpass("password: ");
	}

	if (diagnostics) {
		if (!diagnose_ntlm_auth()) {
			exit(1);
		}
	} else {
		fstring user;

		fstr_sprintf(user, "%s%c%s", opt_domain, winbind_separator(), opt_username);
		if (!check_plaintext_auth(user, opt_password, True)) {
			exit(1);
		}
	}

	/* Exit code */

	poptFreeContext(pc);
	return 0;
}
