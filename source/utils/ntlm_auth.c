/* 
   Unix SMB/CIFS implementation.

   Winbind status program.

   Copyright (C) Tim Potter      2000-2002
   Copyright (C) Andrew Bartlett 2003
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
	SQUID_2_5_NTLMSSP
};
	

extern int winbindd_fd;

static const char *helper_protocol;
static const char *username;
static const char *domain;
static const char *workstation;
static const char *hex_challenge;
static const char *hex_lm_response;
static const char *hex_nt_response;
static unsigned char *challenge;
static size_t challenge_len;
static unsigned char *lm_response;
static size_t lm_response_len;
static unsigned char *nt_response;
static size_t nt_response_len;
static int request_lm_key;
static int request_nt_key;

static char *password;

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
		
		d_printf("%s (0x%x)\n", 
			 response.data.auth.nt_status_string, 
			 response.data.auth.nt_status);
	} else {
		if ((result != NSS_STATUS_SUCCESS) && (response.data.auth.nt_status == 0)) {
			DEBUG(1, ("Reading winbind reply failed! (0x01)\n"));
		}
		
		DEBUG(3, ("%s (0x%x)\n", 
			 response.data.auth.nt_status_string, 
			 response.data.auth.nt_status));		
	}
		
        return (result == NSS_STATUS_SUCCESS);
}

static NTSTATUS winbind_pw_check(struct ntlmssp_state *ntlmssp_state) 
{
	struct winbindd_request request;
	struct winbindd_response response;
        NSS_STATUS result;
	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.data.auth_crap.user, ntlmssp_state->user);

	fstrcpy(request.data.auth_crap.domain, ntlmssp_state->domain);
	fstrcpy(request.data.auth_crap.workstation, ntlmssp_state->workstation);
	
	memcpy(request.data.auth_crap.chal, ntlmssp_state->chal.data, 
	       MIN(ntlmssp_state->chal.length, 8));

	memcpy(request.data.auth_crap.lm_resp, ntlmssp_state->lm_resp.data, 
	       MIN(ntlmssp_state->lm_resp.length, sizeof(request.data.auth_crap.lm_resp)));
        
	memcpy(request.data.auth_crap.nt_resp, ntlmssp_state->nt_resp.data,
	       MIN(ntlmssp_state->nt_resp.length, sizeof(request.data.auth_crap.nt_resp)));
        
        request.data.auth_crap.lm_resp_len = ntlmssp_state->lm_resp.length;
        request.data.auth_crap.nt_resp_len = ntlmssp_state->nt_resp.length;

	result = winbindd_request(WINBINDD_PAM_AUTH_CRAP, &request, &response);

	/* Display response */

	if ((result != NSS_STATUS_SUCCESS) && (response.data.auth.nt_status == 0)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS(response.data.auth.nt_status);
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
	dump_data(10, request.data, request.length);

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
	struct winbindd_request request;
	struct winbindd_response response;
	char *lm_key;
	char *nt_key;
	static uint8 zeros[16];

        NSS_STATUS result;
	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	if (request_lm_key) 
		request.data.auth_crap.flags |= WINBIND_PAM_LMKEY;

	if (request_nt_key) 
		request.data.auth_crap.flags |= WINBIND_PAM_NTKEY;

	fstrcpy(request.data.auth_crap.user, username);

	fstrcpy(request.data.auth_crap.domain, domain);
	fstrcpy(request.data.auth_crap.workstation, workstation);
	
	memcpy(request.data.auth_crap.chal, challenge, MIN(challenge_len, 8));

	memcpy(request.data.auth_crap.lm_resp, lm_response, MIN(lm_response_len, sizeof(request.data.auth_crap.lm_resp)));
        
	memcpy(request.data.auth_crap.nt_resp, nt_response, MIN(nt_response_len, sizeof(request.data.auth_crap.nt_resp)));
        
        request.data.auth_crap.lm_resp_len = lm_response_len;
        request.data.auth_crap.nt_resp_len = nt_response_len;

	result = winbindd_request(WINBINDD_PAM_AUTH_CRAP, &request, &response);

	/* Display response */

	if ((result != NSS_STATUS_SUCCESS) && (response.data.auth.nt_status == 0)) {
		d_printf("Reading winbind reply failed! (0x01)\n");
	}

	d_printf("%s (0x%x)\n", 
		 response.data.auth.nt_status_string, 
		 response.data.auth.nt_status);

	if (response.data.auth.nt_status == 0) {
		if (request_lm_key 
		    && (memcmp(zeros, response.data.auth.first_8_lm_hash, 
			      sizeof(response.data.auth.first_8_lm_hash)) != 0)) {
			hex_encode(response.data.auth.first_8_lm_hash, 
				   sizeof(response.data.auth.first_8_lm_hash),
				   &lm_key);
			d_printf("LM_KEY: %s\n", lm_key);
			SAFE_FREE(lm_key);
		}
		if (request_nt_key 
		    && (memcmp(zeros, response.data.auth.nt_session_key, 
			      sizeof(response.data.auth.nt_session_key)) != 0)) {
			hex_encode(response.data.auth.nt_session_key, 
				   sizeof(response.data.auth.nt_session_key), 
				   &nt_key);
			d_printf("NT_KEY: %s\n", nt_key);
			SAFE_FREE(nt_key);
		}
	}

        return result == NSS_STATUS_SUCCESS;
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
	OPT_NT_KEY
};

 int main(int argc, const char **argv)
{
	int opt;

	poptContext pc;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{ "helper-protocol", 0, POPT_ARG_STRING, &helper_protocol, OPT_DOMAIN, "operate as a stdio-based helper", "helper protocol to use"},
 		{ "username", 0, POPT_ARG_STRING, &username, OPT_USERNAME, "username"},
 		{ "domain", 0, POPT_ARG_STRING, &domain, OPT_DOMAIN, "domain name"},
 		{ "workstation", 0, POPT_ARG_STRING, &domain, OPT_WORKSTATION, "workstation"},
 		{ "challenge", 0, POPT_ARG_STRING, &hex_challenge, OPT_CHALLENGE, "challenge (HEX encoded)"},
		{ "lm-response", 0, POPT_ARG_STRING, &hex_lm_response, OPT_LM, "LM Response to the challenge (HEX encoded)"},
		{ "nt-response", 0, POPT_ARG_STRING, &hex_nt_response, OPT_NT, "NT or NTLMv2 Response to the challenge (HEX encoded)"},
		{ "password", 0, POPT_ARG_STRING, &password, OPT_PASSWORD, "User's plaintext password"},		
		{ "request-lm-key", 0, POPT_ARG_NONE, &request_lm_key, OPT_LM_KEY, "Retreive LM session key"},
		{ "request-nt-key", 0, POPT_ARG_NONE, &request_nt_key, OPT_NT_KEY, "Retreive NT session key"},
		POPT_COMMON_SAMBA
		POPT_COMMON_CONNECTION
		POPT_COMMON_CREDENTIALS
		POPT_TABLEEND
	};

	/* Samba client initialisation */

	dbf = x_stderr;
	
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
			challenge_len = strlen(hex_challenge);
			challenge = smb_xmalloc((challenge_len+1)/2);
			if ((challenge_len = strhex_to_str(challenge, challenge_len, hex_challenge)) != 8) {
				fprintf(stderr, "hex decode of %s failed (only got %u bytes)!\n", 
					hex_challenge, challenge_len);
				exit(1);
			}
			break;
		case OPT_LM: 
			lm_response_len = strlen(hex_lm_response);
			lm_response = smb_xmalloc((lm_response_len+1)/2);
			if ((lm_response_len = strhex_to_str(lm_response, lm_response_len, hex_lm_response)) != 24) {
				fprintf(stderr, "hex decode of %s failed!\n", hex_lm_response);
				exit(1);
			}
			break;
		case OPT_NT: 
			nt_response_len = strlen(hex_nt_response);
			nt_response = smb_xmalloc((nt_response_len+1)/2);
			if ((nt_response_len = strhex_to_str(nt_response, nt_response_len, hex_nt_response)) < 24) {
				fprintf(stderr, "hex decode of %s failed!\n", hex_nt_response);
				exit(1);
			}
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
		} else {
			fprintf(stderr, "unknown helper protocol [%s]\n", helper_protocol);
			exit(1);
		}
	}

	if (domain == NULL) {
		domain = get_winbind_domain();
	}

	if (workstation == NULL) {
		workstation = "";
	}

	if (challenge) {
		if (!check_auth_crap()) {
			exit(1);
		}
	} else if (password) {
		fstring user;
		snprintf(user, sizeof(user)-1, "%s%c%s", domain, winbind_separator(), username);
		if (!check_plaintext_auth(user, password, True)) {
			exit(1);
		}
	}

	/* Exit code */

	poptFreeContext(pc);
	return 0;
}
