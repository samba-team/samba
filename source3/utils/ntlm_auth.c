/*
   Unix SMB/CIFS implementation.

   Winbind status program.

   Copyright (C) Tim Potter      2000-2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003-2004
   Copyright (C) Francesco Chemolli <kinkie@kame.usr.dsi.unimi.it> 2000
   Copyright (C) Robert O'Callahan 2006 (added cached credential code).
   Copyright (C) Kai Blin <kai@samba.org> 2008
   Copyright (C) Simo Sorce 2010

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
#include "lib/param/param.h"
#include "popt_common.h"
#include "libcli/security/security.h"
#include "utils/ntlm_auth.h"
#include "../libcli/auth/libcli_auth.h"
#include "auth/ntlmssp/ntlmssp.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "auth/credentials/credentials.h"
#include "librpc/crypto/gse.h"
#include "smb_krb5.h"
#include "lib/util/tiniparser.h"
#include "nsswitch/winbind_client.h"
#include "librpc/gen_ndr/krb5pac.h"
#include "../lib/util/asn1.h"
#include "auth/common_auth.h"
#include "source3/include/auth.h"
#include "source3/auth/proto.h"
#include "nsswitch/libwbclient/wbclient.h"
#include "lib/param/loadparm.h"
#include "lib/util/base64.h"
#include "cmdline_contexts.h"
#include "lib/util/tevent_ntstatus.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#ifdef HAVE_KRB5
#include "auth/kerberos/pac_utils.h"
#endif

#ifndef PAM_WINBIND_CONFIG_FILE
#define PAM_WINBIND_CONFIG_FILE "/etc/security/pam_winbind.conf"
#endif

#define WINBIND_KRB5_AUTH	0x00000080

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

#define INITIAL_BUFFER_SIZE 300
#define MAX_BUFFER_SIZE 630000

enum stdio_helper_mode {
	SQUID_2_4_BASIC,
	SQUID_2_5_BASIC,
	SQUID_2_5_NTLMSSP,
	NTLMSSP_CLIENT_1,
	GSS_SPNEGO_SERVER,
	GSS_SPNEGO_CLIENT,
	NTLM_SERVER_1,
	NTLM_CHANGE_PASSWORD_1,
	NUM_HELPER_MODES
};

enum ntlm_auth_cli_state {
	CLIENT_INITIAL = 0,
	CLIENT_RESPONSE,
	CLIENT_FINISHED,
	CLIENT_ERROR
};

struct ntlm_auth_state {
	TALLOC_CTX *mem_ctx;
	enum stdio_helper_mode helper_mode;
	enum ntlm_auth_cli_state cli_state;
	struct ntlmssp_state *ntlmssp_state;
	uint32_t neg_flags;
	char *want_feature_list;
	bool have_session_key;
	DATA_BLOB session_key;
	DATA_BLOB initial_message;
	void *gensec_private_1;
};
typedef void (*stdio_helper_function)(enum stdio_helper_mode stdio_helper_mode,
				      struct loadparm_context *lp_ctx,
				      struct ntlm_auth_state *state, char *buf,
					int length, void **private2);

static void manage_gensec_request(enum stdio_helper_mode stdio_helper_mode,
				  struct loadparm_context *lp_ctx,
				  char *buf, int length, void **private1);

static void manage_squid_request(enum stdio_helper_mode stdio_helper_mode,
				 struct loadparm_context *lp_ctx,
				 struct ntlm_auth_state *state,
				 stdio_helper_function fn, void **private2);

static void manage_squid_basic_request (enum stdio_helper_mode stdio_helper_mode,
				      struct loadparm_context *lp_ctx,
				      struct ntlm_auth_state *state,
					char *buf, int length, void **private2);

static void manage_squid_ntlmssp_request (enum stdio_helper_mode stdio_helper_mode,
				      struct loadparm_context *lp_ctx,
				      struct ntlm_auth_state *state,
					char *buf, int length, void **private2);

static void manage_client_ntlmssp_request (enum stdio_helper_mode stdio_helper_mode,
				      struct loadparm_context *lp_ctx,
				      struct ntlm_auth_state *state,
					char *buf, int length, void **private2);

static void manage_gss_spnego_request (enum stdio_helper_mode stdio_helper_mode,
				      struct loadparm_context *lp_ctx,
				      struct ntlm_auth_state *state,
					char *buf, int length, void **private2);

static void manage_gss_spnego_client_request (enum stdio_helper_mode stdio_helper_mode,
				      struct loadparm_context *lp_ctx,
				      struct ntlm_auth_state *state,
					char *buf, int length, void **private2);

static void manage_ntlm_server_1_request (enum stdio_helper_mode stdio_helper_mode,
				      struct loadparm_context *lp_ctx,
				      struct ntlm_auth_state *state,
					char *buf, int length, void **private2);

static void manage_ntlm_change_password_1_request(enum stdio_helper_mode stdio_helper_mode,
				      struct loadparm_context *lp_ctx,
				      struct ntlm_auth_state *state,
					char *buf, int length, void **private2);

static const struct {
	enum stdio_helper_mode mode;
	const char *name;
	stdio_helper_function fn;
} stdio_helper_protocols[] = {
	{ SQUID_2_4_BASIC, "squid-2.4-basic", manage_squid_basic_request},
	{ SQUID_2_5_BASIC, "squid-2.5-basic", manage_squid_basic_request},
	{ SQUID_2_5_NTLMSSP, "squid-2.5-ntlmssp", manage_squid_ntlmssp_request},
	{ NTLMSSP_CLIENT_1, "ntlmssp-client-1", manage_client_ntlmssp_request},
	{ GSS_SPNEGO_SERVER, "gss-spnego", manage_gss_spnego_request},
	{ GSS_SPNEGO_CLIENT, "gss-spnego-client", manage_gss_spnego_client_request},
	{ NTLM_SERVER_1, "ntlm-server-1", manage_ntlm_server_1_request},
	{ NTLM_CHANGE_PASSWORD_1, "ntlm-change-password-1", manage_ntlm_change_password_1_request},
	{ NUM_HELPER_MODES, NULL, NULL}
};

const char *opt_username;
const char *opt_domain;
const char *opt_workstation;
const char *opt_password;
static DATA_BLOB opt_challenge;
static DATA_BLOB opt_lm_response;
static DATA_BLOB opt_nt_response;
static int request_lm_key;
static int request_user_session_key;
static int use_cached_creds;
static int offline_logon;
static int opt_allow_mschapv2;

static const char *require_membership_of;
static const char *require_membership_of_sid;
static const char *opt_pam_winbind_conf;

const char *opt_target_service;
const char *opt_target_hostname;


/* This is a bit hairy, but the basic idea is to do a password callback
   to the calling application.  The callback comes from within gensec */

static void manage_gensec_get_pw_request(enum stdio_helper_mode stdio_helper_mode,
					 struct loadparm_context *lp_ctx,
					 struct ntlm_auth_state *state, char *buf, int length,
					 void **password)
{
	DATA_BLOB in;
	if (strlen(buf) < 2) {
		DEBUG(1, ("query [%s] invalid", buf));
		printf("BH Query invalid\n");
		return;
	}

	if (strlen(buf) > 3) {
		in = base64_decode_data_blob(buf + 3);
	} else {
		in = data_blob(NULL, 0);
	}

	if (strncmp(buf, "PW ", 3) == 0) {

		*password = talloc_strndup(NULL,
					   (const char *)in.data, in.length);

		if (*password == NULL) {
			DEBUG(1, ("Out of memory\n"));
			printf("BH Out of memory\n");
			data_blob_free(&in);
			return;
		}

		printf("OK\n");
		data_blob_free(&in);
		return;
	}
	DEBUG(1, ("Asked for (and expected) a password\n"));
	printf("BH Expected a password\n");
	data_blob_free(&in);
}

/**
 * Callback for password credentials.  This is not async, and when
 * GENSEC and the credentials code is made async, it will look rather
 * different.
 */

static const char *get_password(struct cli_credentials *credentials)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *password = NULL;
	struct ntlm_auth_state *state;

	state = talloc_zero(frame, struct ntlm_auth_state);
	if (state == NULL) {
		DEBUG(0, ("squid_stream: Failed to talloc ntlm_auth_state\n"));
		fprintf(stderr, "ERR\n");
		exit(1);
	}

	state->mem_ctx = state;

	/* Ask for a password */
	printf("PW\n");

	manage_squid_request(NUM_HELPER_MODES /* bogus */, NULL, state, manage_gensec_get_pw_request, (void **)&password);
	talloc_steal(credentials, password);
	TALLOC_FREE(frame);
	return password;
}

/**
 * A limited set of features are defined with text strings as needed
 * by ntlm_auth
 *
 */
static void gensec_want_feature_list(struct gensec_security *state, char* feature_list)
{
	if (in_list("NTLMSSP_FEATURE_SESSION_KEY", feature_list, true)) {
		DEBUG(10, ("want GENSEC_FEATURE_SESSION_KEY\n"));
		gensec_want_feature(state, GENSEC_FEATURE_SESSION_KEY);
	}
	if (in_list("NTLMSSP_FEATURE_SIGN", feature_list, true)) {
		DEBUG(10, ("want GENSEC_FEATURE_SIGN\n"));
		gensec_want_feature(state, GENSEC_FEATURE_SIGN);
	}
	if (in_list("NTLMSSP_FEATURE_SEAL", feature_list, true)) {
		DEBUG(10, ("want GENSEC_FEATURE_SEAL\n"));
		gensec_want_feature(state, GENSEC_FEATURE_SEAL);
	}
	if (in_list("NTLMSSP_FEATURE_CCACHE", feature_list, true)) {
		DEBUG(10, ("want GENSEC_FEATURE_NTLM_CCACHE\n"));
		gensec_want_feature(state, GENSEC_FEATURE_NTLM_CCACHE);
	}
}

static char winbind_separator(void)
{
	struct wbcInterfaceDetails *details;
	wbcErr ret;
	static bool got_sep;
	static char sep;

	if (got_sep)
		return sep;

	ret = wbcInterfaceDetails(&details);
	if (!WBC_ERROR_IS_OK(ret)) {
		d_fprintf(stderr, "could not obtain winbind separator!\n");
		return *lp_winbind_separator();
	}

	sep = details->winbind_separator;

	wbcFreeMemory(details);

	got_sep = True;

	if (!sep) {
		d_fprintf(stderr, "winbind separator was NULL!\n");
		return *lp_winbind_separator();
	}

	return sep;
}

const char *get_winbind_domain(void)
{
	struct wbcInterfaceDetails *details;
	wbcErr ret;

	static fstring winbind_domain;
	if (*winbind_domain) {
		return winbind_domain;
	}

	/* Send off request */

	ret = wbcInterfaceDetails(&details);
	if (!WBC_ERROR_IS_OK(ret)) {
		DEBUG(1, ("could not obtain winbind domain name!\n"));
		return lp_workgroup();
	}

	fstrcpy(winbind_domain, details->netbios_domain);

	wbcFreeMemory(details);

	return winbind_domain;

}

const char *get_winbind_netbios_name(void)
{
	struct wbcInterfaceDetails *details;
	wbcErr ret;

	static fstring winbind_netbios_name;

	if (*winbind_netbios_name) {
		return winbind_netbios_name;
	}

	/* Send off request */

	ret = wbcInterfaceDetails(&details);
	if (!WBC_ERROR_IS_OK(ret)) {
		DEBUG(1, ("could not obtain winbind netbios name!\n"));
		return lp_netbios_name();
	}

	fstrcpy(winbind_netbios_name, details->netbios_name);

	wbcFreeMemory(details);

	return winbind_netbios_name;

}

DATA_BLOB get_challenge(void) 
{
	static DATA_BLOB chal;
	if (opt_challenge.length)
		return opt_challenge;

	chal = data_blob(NULL, 8);

	generate_random_buffer(chal.data, chal.length);
	return chal;
}

/* Copy of parse_domain_user from winbindd_util.c.  Parse a string of the
   form DOMAIN/user into a domain and a user */

static bool parse_ntlm_auth_domain_user(const char *domuser, fstring domain,
				     fstring user)
{

	char *p = strchr(domuser,winbind_separator());

	if (!p) {
		return False;
	}

	fstrcpy(user, p+1);
	fstrcpy(domain, domuser);
	domain[PTR_DIFF(p, domuser)] = 0;
	return strupper_m(domain);
}

static bool get_require_membership_sid(void) {
	fstring domain, name, sidbuf;
	struct wbcDomainSid sid;
	enum wbcSidType type;
	wbcErr ret;

	if (!require_membership_of) {
		return True;
	}

	if (require_membership_of_sid) {
		return True;
	}

	/* Otherwise, ask winbindd for the name->sid request */

	if (!parse_ntlm_auth_domain_user(require_membership_of,
					 domain, name)) {
		DEBUG(0, ("Could not parse %s into separate domain/name parts!\n",
			  require_membership_of));
		return False;
	}

	ret = wbcLookupName(domain, name, &sid, &type);
	if (!WBC_ERROR_IS_OK(ret)) {
		DEBUG(0, ("Winbindd lookupname failed to resolve %s into a SID!\n",
			  require_membership_of));
		return False;
	}

	wbcSidToStringBuf(&sid, sidbuf, sizeof(sidbuf));

	require_membership_of_sid = SMB_STRDUP(sidbuf);

	if (require_membership_of_sid)
		return True;

	return False;
}

/*
 * Get some configuration from pam_winbind.conf to see if we
 * need to contact trusted domain
 */

int get_pam_winbind_config()
{
	int ctrl = 0;
	struct tiniparser_dictionary *d = NULL;

	if (!opt_pam_winbind_conf || !*opt_pam_winbind_conf) {
		opt_pam_winbind_conf = PAM_WINBIND_CONFIG_FILE;
	}

	d = tiniparser_load(opt_pam_winbind_conf);

	if (!d) {
		return 0;
	}

	if (tiniparser_getboolean(d, "global:krb5_auth", false)) {
		ctrl |= WINBIND_KRB5_AUTH;
	}

	tiniparser_freedict(d);

	return ctrl;
}

/* Authenticate a user with a plaintext password */

static bool check_plaintext_auth(const char *user, const char *pass,
				 bool stdout_diagnostics)
{
	struct winbindd_request request;
	struct winbindd_response response;
        NSS_STATUS result;

	if (!get_require_membership_sid()) {
		return False;
	}

	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.data.auth.user, user);
	fstrcpy(request.data.auth.pass, pass);
	if (require_membership_of_sid) {
		strlcpy(request.data.auth.require_membership_of_sid,
			require_membership_of_sid,
			sizeof(request.data.auth.require_membership_of_sid));
	}

	if (offline_logon) {
		request.flags |= WBFLAG_PAM_CACHED_LOGIN;
	}

	result = winbindd_request_response(NULL, WINBINDD_PAM_AUTH, &request, &response);

	/* Display response */

	if (stdout_diagnostics) {
		if ((result != NSS_STATUS_SUCCESS) && (response.data.auth.nt_status == 0)) {
			d_fprintf(stderr, "Reading winbind reply failed! (0x01)\n");
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

NTSTATUS contact_winbind_auth_crap(const char *username,
				   const char *domain,
				   const char *workstation,
				   const DATA_BLOB *challenge,
				   const DATA_BLOB *lm_response,
				   const DATA_BLOB *nt_response,
				   uint32_t flags,
				   uint32_t extra_logon_parameters,
				   uint8_t lm_key[8],
				   uint8_t user_session_key[16],
				   uint8_t *pauthoritative,
				   char **error_string,
				   char **unix_name)
{
	NTSTATUS nt_status;
        NSS_STATUS result;
	struct winbindd_request request;
	struct winbindd_response response;

	*pauthoritative = 1;

	if (!get_require_membership_sid()) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	request.flags = flags;

	request.data.auth_crap.logon_parameters = extra_logon_parameters
		| MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT | MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT;

	if (opt_allow_mschapv2) {
			request.data.auth_crap.logon_parameters |= MSV1_0_ALLOW_MSVCHAPV2;
	}

	if (require_membership_of_sid)
		fstrcpy(request.data.auth_crap.require_membership_of_sid, require_membership_of_sid);

        fstrcpy(request.data.auth_crap.user, username);
	fstrcpy(request.data.auth_crap.domain, domain);

	fstrcpy(request.data.auth_crap.workstation,
		workstation);

	memcpy(request.data.auth_crap.chal, challenge->data, MIN(challenge->length, 8));

	if (lm_response && lm_response->length) {
		memcpy(request.data.auth_crap.lm_resp,
		       lm_response->data,
		       MIN(lm_response->length, sizeof(request.data.auth_crap.lm_resp)));
		request.data.auth_crap.lm_resp_len = lm_response->length;
	}

	if (nt_response && nt_response->length) {
		if (nt_response->length > sizeof(request.data.auth_crap.nt_resp)) {
			request.flags = request.flags | WBFLAG_BIG_NTLMV2_BLOB;
			request.extra_len = nt_response->length;
			request.extra_data.data = SMB_MALLOC_ARRAY(char, request.extra_len);
			if (request.extra_data.data == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			memcpy(request.extra_data.data, nt_response->data,
			       nt_response->length);

		} else {
			memcpy(request.data.auth_crap.nt_resp,
			       nt_response->data, nt_response->length);
		}
                request.data.auth_crap.nt_resp_len = nt_response->length;
	}

	result = winbindd_priv_request_response(
		NULL,
		WINBINDD_PAM_AUTH_CRAP,
		&request,
		&response);
	SAFE_FREE(request.extra_data.data);

	/* Display response */

	if ((result != NSS_STATUS_SUCCESS) && (response.data.auth.nt_status == 0)) {
		nt_status = NT_STATUS_UNSUCCESSFUL;
		if (error_string)
			*error_string = smb_xstrdup("Reading winbind reply failed!");
		winbindd_free_response(&response);
		return nt_status;
	}

	nt_status = (NT_STATUS(response.data.auth.nt_status));
	if (!NT_STATUS_IS_OK(nt_status)) {
		if (error_string)
			*error_string = smb_xstrdup(response.data.auth.error_string);
		*pauthoritative = response.data.auth.authoritative;
		winbindd_free_response(&response);
		return nt_status;
	}

	if ((flags & WBFLAG_PAM_LMKEY) && lm_key) {
		memcpy(lm_key, response.data.auth.first_8_lm_hash,
		       sizeof(response.data.auth.first_8_lm_hash));
	}
	if ((flags & WBFLAG_PAM_USER_SESSION_KEY) && user_session_key) {
		memcpy(user_session_key, response.data.auth.user_session_key,
			sizeof(response.data.auth.user_session_key));
	}

	if (flags & WBFLAG_PAM_UNIX_NAME) {
		*unix_name = SMB_STRDUP(response.data.auth.unix_username);
		if (!*unix_name) {
			winbindd_free_response(&response);
			return NT_STATUS_NO_MEMORY;
		}
	}

	winbindd_free_response(&response);
	return nt_status;
}

/* contact server to change user password using auth crap */
static NTSTATUS contact_winbind_change_pswd_auth_crap(const char *username,
						      const char *domain,
						      const DATA_BLOB new_nt_pswd,
						      const DATA_BLOB old_nt_hash_enc,
						      const DATA_BLOB new_lm_pswd,
						      const DATA_BLOB old_lm_hash_enc,
						      char  **error_string)
{
	NTSTATUS nt_status;
	NSS_STATUS result;
	struct winbindd_request request;
	struct winbindd_response response;

	if (!get_require_membership_sid())
	{
		if(error_string)
			*error_string = smb_xstrdup("Can't get membership sid.");
		return NT_STATUS_INVALID_PARAMETER;
	}

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	if(username != NULL)
		fstrcpy(request.data.chng_pswd_auth_crap.user, username);
	if(domain != NULL)
		fstrcpy(request.data.chng_pswd_auth_crap.domain,domain);

	if(new_nt_pswd.length)
	{
		memcpy(request.data.chng_pswd_auth_crap.new_nt_pswd, new_nt_pswd.data, sizeof(request.data.chng_pswd_auth_crap.new_nt_pswd));
		request.data.chng_pswd_auth_crap.new_nt_pswd_len = new_nt_pswd.length;
	}

	if(old_nt_hash_enc.length)
	{
		memcpy(request.data.chng_pswd_auth_crap.old_nt_hash_enc, old_nt_hash_enc.data, sizeof(request.data.chng_pswd_auth_crap.old_nt_hash_enc));
		request.data.chng_pswd_auth_crap.old_nt_hash_enc_len = old_nt_hash_enc.length;
	}

	if(new_lm_pswd.length)
	{
		memcpy(request.data.chng_pswd_auth_crap.new_lm_pswd, new_lm_pswd.data, sizeof(request.data.chng_pswd_auth_crap.new_lm_pswd));
		request.data.chng_pswd_auth_crap.new_lm_pswd_len = new_lm_pswd.length;
	}

	if(old_lm_hash_enc.length)
	{
		memcpy(request.data.chng_pswd_auth_crap.old_lm_hash_enc, old_lm_hash_enc.data, sizeof(request.data.chng_pswd_auth_crap.old_lm_hash_enc));
		request.data.chng_pswd_auth_crap.old_lm_hash_enc_len = old_lm_hash_enc.length;
	}

	result = winbindd_request_response(NULL, WINBINDD_PAM_CHNG_PSWD_AUTH_CRAP, &request, &response);

	/* Display response */

	if ((result != NSS_STATUS_SUCCESS) && (response.data.auth.nt_status == 0))
	{
		nt_status = NT_STATUS_UNSUCCESSFUL;
		if (error_string)
			*error_string = smb_xstrdup("Reading winbind reply failed!");
		winbindd_free_response(&response);
		return nt_status;
	}

	nt_status = (NT_STATUS(response.data.auth.nt_status));
	if (!NT_STATUS_IS_OK(nt_status))
	{
		if (error_string) 
			*error_string = smb_xstrdup(response.data.auth.error_string);
		winbindd_free_response(&response);
		return nt_status;
	}

	winbindd_free_response(&response);

    return nt_status;
}

static NTSTATUS ntlm_auth_generate_session_info(struct auth4_context *auth_context,
						TALLOC_CTX *mem_ctx,
						void *server_returned_info,
						const char *original_user_name,
						uint32_t session_info_flags,
						struct auth_session_info **session_info_out)
{
	const char *unix_username = (const char *)server_returned_info;
	struct dom_sid *sids = NULL;
	struct auth_session_info *session_info = NULL;

	session_info = talloc_zero(mem_ctx, struct auth_session_info);
	if (session_info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	session_info->unix_info = talloc_zero(session_info, struct auth_user_info_unix);
	if (session_info->unix_info == NULL) {
		TALLOC_FREE(session_info);
		return NT_STATUS_NO_MEMORY;
	}
	session_info->unix_info->unix_name = talloc_strdup(session_info->unix_info,
							   unix_username);
	if (session_info->unix_info->unix_name == NULL) {
		TALLOC_FREE(session_info);
		return NT_STATUS_NO_MEMORY;
	}

	session_info->security_token = talloc_zero(session_info, struct security_token);
	if (session_info->security_token == NULL) {
		TALLOC_FREE(session_info);
		return NT_STATUS_NO_MEMORY;
	}

	sids = talloc_zero_array(session_info->security_token,
				 struct dom_sid, 3);
	if (sids == NULL) {
		TALLOC_FREE(session_info);
		return NT_STATUS_NO_MEMORY;
	}
	sid_copy(&sids[0], &global_sid_World);
	sid_copy(&sids[1], &global_sid_Network);
	sid_copy(&sids[2], &global_sid_Authenticated_Users);

	session_info->security_token->num_sids = talloc_array_length(sids);
	session_info->security_token->sids = sids;

	*session_info_out = session_info;

	return NT_STATUS_OK;
}

static NTSTATUS ntlm_auth_generate_session_info_pac(struct auth4_context *auth_ctx,
						    TALLOC_CTX *mem_ctx,
						    struct smb_krb5_context *smb_krb5_context,
						    DATA_BLOB *pac_blob,
						    const char *princ_name,
						    const struct tsocket_address *remote_address,
						    uint32_t session_info_flags,
						    struct auth_session_info **session_info)
{
	TALLOC_CTX *tmp_ctx;
	struct PAC_LOGON_INFO *logon_info = NULL;
	char *unixuser;
	NTSTATUS status;
	char *domain = NULL;
	char *realm = NULL;
	char *user = NULL;
	char *p;

	tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	if (pac_blob) {
#ifdef HAVE_KRB5
		status = kerberos_pac_logon_info(tmp_ctx, *pac_blob, NULL, NULL,
						 NULL, NULL, 0, &logon_info);
#else
		status = NT_STATUS_ACCESS_DENIED;
#endif
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	}

	DEBUG(3, ("Kerberos ticket principal name is [%s]\n", princ_name));

	p = strchr_m(princ_name, '@');
	if (!p) {
		DEBUG(3, ("[%s] Doesn't look like a valid principal\n",
			  princ_name));
		return NT_STATUS_LOGON_FAILURE;
	}

	user = talloc_strndup(mem_ctx, princ_name, p - princ_name);
	if (!user) {
		return NT_STATUS_NO_MEMORY;
	}

	realm = talloc_strdup(talloc_tos(), p + 1);
	if (!realm) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!strequal(realm, lp_realm())) {
		DEBUG(3, ("Ticket for foreign realm %s@%s\n", user, realm));
		if (!lp_allow_trusted_domains()) {
			return NT_STATUS_LOGON_FAILURE;
		}
	}

	if (logon_info && logon_info->info3.base.logon_domain.string) {
		domain = talloc_strdup(mem_ctx,
					logon_info->info3.base.logon_domain.string);
		if (!domain) {
			return NT_STATUS_NO_MEMORY;
		}
		DEBUG(10, ("Domain is [%s] (using PAC)\n", domain));
	} else {

		/* If we have winbind running, we can (and must) shorten the
		   username by using the short netbios name. Otherwise we will
		   have inconsistent user names. With Kerberos, we get the
		   fully qualified realm, with ntlmssp we get the short
		   name. And even w2k3 does use ntlmssp if you for example
		   connect to an ip address. */

		wbcErr wbc_status;
		struct wbcDomainInfo *info = NULL;

		DEBUG(10, ("Mapping [%s] to short name using winbindd\n",
			   realm));

		wbc_status = wbcDomainInfo(realm, &info);

		if (WBC_ERROR_IS_OK(wbc_status)) {
			domain = talloc_strdup(mem_ctx,
						info->short_name);
			wbcFreeMemory(info);
		} else {
			DEBUG(3, ("Could not find short name: %s\n",
				  wbcErrorString(wbc_status)));
			domain = talloc_strdup(mem_ctx, realm);
		}
		if (!domain) {
			return NT_STATUS_NO_MEMORY;
		}
		DEBUG(10, ("Domain is [%s] (using Winbind)\n", domain));
	}

	unixuser = talloc_asprintf(tmp_ctx, "%s%c%s", domain, winbind_separator(), user);
	if (!unixuser) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	status = ntlm_auth_generate_session_info(auth_ctx, mem_ctx, unixuser, NULL, session_info_flags, session_info);

done:
	TALLOC_FREE(tmp_ctx);
	return status;
}



/**
 * Return the challenge as determined by the authentication subsystem 
 * @return an 8 byte random challenge
 */

static NTSTATUS ntlm_auth_get_challenge(struct auth4_context *auth_ctx,
					uint8_t chal[8])
{
	if (auth_ctx->challenge.data.length == 8) {
		DEBUG(5, ("auth_get_challenge: returning previous challenge by module %s (normal)\n", 
			  auth_ctx->challenge.set_by));
		memcpy(chal, auth_ctx->challenge.data.data, 8);
		return NT_STATUS_OK;
	}

	if (!auth_ctx->challenge.set_by) {
		generate_random_buffer(chal, 8);

		auth_ctx->challenge.data		= data_blob_talloc(auth_ctx, chal, 8);
		NT_STATUS_HAVE_NO_MEMORY(auth_ctx->challenge.data.data);
		auth_ctx->challenge.set_by		= "random";
	}

	DEBUG(10,("auth_get_challenge: challenge set by %s\n",
		 auth_ctx->challenge.set_by));

	return NT_STATUS_OK;
}

/**
 * NTLM2 authentication modifies the effective challenge,
 * @param challenge The new challenge value
 */
static NTSTATUS ntlm_auth_set_challenge(struct auth4_context *auth_ctx, const uint8_t chal[8], const char *set_by)
{
	auth_ctx->challenge.set_by = talloc_strdup(auth_ctx, set_by);
	NT_STATUS_HAVE_NO_MEMORY(auth_ctx->challenge.set_by);

	auth_ctx->challenge.data = data_blob_talloc(auth_ctx, chal, 8);
	NT_STATUS_HAVE_NO_MEMORY(auth_ctx->challenge.data.data);

	return NT_STATUS_OK;
}

/**
 * Check the password on an NTLMSSP login.
 *
 * Return the session keys used on the connection.
 */

struct winbind_pw_check_state {
	uint8_t authoritative;
	void *server_info;
	DATA_BLOB nt_session_key;
	DATA_BLOB lm_session_key;
};

static struct tevent_req *winbind_pw_check_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct auth4_context *auth4_context,
	const struct auth_usersupplied_info *user_info)
{
	struct tevent_req *req = NULL;
	struct winbind_pw_check_state *state = NULL;
	NTSTATUS nt_status;
	char *error_string = NULL;
	uint8_t lm_key[8];
	uint8_t user_sess_key[16];
	char *unix_name = NULL;

	req = tevent_req_create(
		mem_ctx, &state, struct winbind_pw_check_state);
	if (req == NULL) {
		return NULL;
	}

	nt_status = contact_winbind_auth_crap(
		user_info->client.account_name,
		user_info->client.domain_name,
		user_info->workstation_name,
		&auth4_context->challenge.data,
		&user_info->password.response.lanman,
		&user_info->password.response.nt,
		WBFLAG_PAM_LMKEY |
		WBFLAG_PAM_USER_SESSION_KEY |
		WBFLAG_PAM_UNIX_NAME,
		0,
		lm_key, user_sess_key,
		&state->authoritative,
		&error_string,
		&unix_name);

	if (tevent_req_nterror(req, nt_status)) {
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_ACCESS_DENIED)) {
			DBG_ERR("Login for user [%s]\\[%s]@[%s] failed due "
				"to [%s]\n",
				user_info->client.domain_name,
				user_info->client.account_name,
				user_info->workstation_name,
				error_string ?
				error_string :
				"unknown error (NULL)");
		} else {
			DBG_NOTICE("Login for user [%s]\\[%s]@[%s] failed due "
				   "to [%s]\n",
				   user_info->client.domain_name,
				   user_info->client.account_name,
				   user_info->workstation_name,
				   error_string ?
				   error_string :
				   "unknown error (NULL)");
		}
		goto done;
	}

	if (!all_zero(lm_key, 8)) {
		state->lm_session_key = data_blob_talloc(state, NULL, 16);
		if (tevent_req_nomem(state->lm_session_key.data, req)) {
			goto done;
		}
		memcpy(state->lm_session_key.data, lm_key, 8);
		memset(state->lm_session_key.data+8, '\0', 8);
	}
	if (!all_zero(user_sess_key, 16)) {
		state->nt_session_key = data_blob_talloc(
			state, user_sess_key, 16);
		if (tevent_req_nomem(state->nt_session_key.data, req)) {
			goto done;
		}
	}
	state->server_info = talloc_strdup(state, unix_name);
	if (tevent_req_nomem(state->server_info, req)) {
		goto done;
	}
	tevent_req_done(req);

done:
	SAFE_FREE(error_string);
	SAFE_FREE(unix_name);
	return tevent_req_post(req, ev);
}

static NTSTATUS winbind_pw_check_recv(struct tevent_req *req,
				      TALLOC_CTX *mem_ctx,
				      uint8_t *pauthoritative,
				      void **server_returned_info,
				      DATA_BLOB *nt_session_key,
				      DATA_BLOB *lm_session_key)
{
	struct winbind_pw_check_state *state = tevent_req_data(
		req, struct winbind_pw_check_state);
	NTSTATUS status;

	if (pauthoritative != NULL) {
		*pauthoritative = state->authoritative;
	}

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	if (server_returned_info != NULL) {
		*server_returned_info = talloc_move(
			mem_ctx, &state->server_info);
	}
	if (nt_session_key != NULL) {
		*nt_session_key = (DATA_BLOB) {
			.data = talloc_move(
				mem_ctx, &state->nt_session_key.data),
			.length = state->nt_session_key.length,
		};
	}
	if (lm_session_key != NULL) {
		*lm_session_key = (DATA_BLOB) {
			.data = talloc_move(
				mem_ctx, &state->lm_session_key.data),
			.length = state->lm_session_key.length,
		};
	}

	return NT_STATUS_OK;
}

struct local_pw_check_state {
	uint8_t authoritative;
	void *server_info;
	DATA_BLOB nt_session_key;
	DATA_BLOB lm_session_key;
};

static struct tevent_req *local_pw_check_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct auth4_context *auth4_context,
	const struct auth_usersupplied_info *user_info)
{
	struct tevent_req *req = NULL;
	struct local_pw_check_state *state = NULL;
	struct samr_Password lm_pw, nt_pw;
	NTSTATUS nt_status;

	req = tevent_req_create(
		mem_ctx, &state, struct local_pw_check_state);
	if (req == NULL) {
		return NULL;
	}
	state->authoritative = 1;

	nt_lm_owf_gen (opt_password, nt_pw.hash, lm_pw.hash);

	nt_status = ntlm_password_check(
		state,
		true,
		NTLM_AUTH_ON,
		0,
		&auth4_context->challenge.data,
		&user_info->password.response.lanman,
		&user_info->password.response.nt,
		user_info->client.account_name,
		user_info->client.account_name,
		user_info->client.domain_name,
		&lm_pw,
		&nt_pw,
		&state->nt_session_key,
		&state->lm_session_key);

	if (tevent_req_nterror(req, nt_status)) {
		DBG_NOTICE("Login for user [%s]\\[%s]@[%s] failed due to "
			   "[%s]\n",
			   user_info->client.domain_name,
			   user_info->client.account_name,
			   user_info->workstation_name,
			   nt_errstr(nt_status));
		return tevent_req_post(req, ev);
	}

	state->server_info = talloc_asprintf(
		state,
		"%s%c%s",
		user_info->client.domain_name,
		*lp_winbind_separator(),
		user_info->client.account_name);
	if (tevent_req_nomem(state->server_info, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS local_pw_check_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    uint8_t *pauthoritative,
				    void **server_returned_info,
				    DATA_BLOB *nt_session_key,
				    DATA_BLOB *lm_session_key)
{
	struct local_pw_check_state *state = tevent_req_data(
		req, struct local_pw_check_state);
	NTSTATUS status;

	if (pauthoritative != NULL) {
		*pauthoritative = state->authoritative;
	}

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	if (server_returned_info != NULL) {
		*server_returned_info = talloc_move(
			mem_ctx, &state->server_info);
	}
	if (nt_session_key != NULL) {
		*nt_session_key = (DATA_BLOB) {
			.data = talloc_move(
				mem_ctx, &state->nt_session_key.data),
			.length = state->nt_session_key.length,
		};
	}
	if (lm_session_key != NULL) {
		*lm_session_key = (DATA_BLOB) {
			.data = talloc_move(
				mem_ctx, &state->lm_session_key.data),
			.length = state->lm_session_key.length,
		};
	}

	return NT_STATUS_OK;
}

static NTSTATUS ntlm_auth_prepare_gensec_client(TALLOC_CTX *mem_ctx,
						struct loadparm_context *lp_ctx,
						struct gensec_security **gensec_security_out)
{
	struct gensec_security *gensec_security = NULL;
	NTSTATUS nt_status;
	TALLOC_CTX *tmp_ctx;
	const struct gensec_security_ops **backends = NULL;
	struct gensec_settings *gensec_settings = NULL;
	size_t idx = 0;

	tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	gensec_settings = lpcfg_gensec_settings(tmp_ctx, lp_ctx);
	if (gensec_settings == NULL) {
		DEBUG(10, ("lpcfg_gensec_settings failed\n"));
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	backends = talloc_zero_array(gensec_settings,
				     const struct gensec_security_ops *, 4);
	if (backends == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	gensec_settings->backends = backends;

	gensec_init();

	/* These need to be in priority order, krb5 before NTLMSSP */
#if defined(HAVE_KRB5)
	backends[idx++] = &gensec_gse_krb5_security_ops;
#endif

	backends[idx++] = gensec_security_by_oid(NULL, GENSEC_OID_NTLMSSP);

	backends[idx++] = gensec_security_by_oid(NULL, GENSEC_OID_SPNEGO);

	nt_status = gensec_client_start(NULL, &gensec_security,
					gensec_settings);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	talloc_unlink(tmp_ctx, gensec_settings);

	if (opt_target_service != NULL) {
		nt_status = gensec_set_target_service(gensec_security,
						      opt_target_service);
		if (!NT_STATUS_IS_OK(nt_status)) {
			TALLOC_FREE(tmp_ctx);
			return nt_status;
		}
	}

	if (opt_target_hostname != NULL) {
		nt_status = gensec_set_target_hostname(gensec_security,
						       opt_target_hostname);
		if (!NT_STATUS_IS_OK(nt_status)) {
			TALLOC_FREE(tmp_ctx);
			return nt_status;
		}
	}

	*gensec_security_out = talloc_steal(mem_ctx, gensec_security);
	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}

static struct auth4_context *make_auth4_context_ntlm_auth(TALLOC_CTX *mem_ctx, bool local_pw)
{
	struct auth4_context *auth4_context = talloc_zero(mem_ctx, struct auth4_context);
	if (auth4_context == NULL) {
		DEBUG(10, ("failed to allocate auth4_context failed\n"));
		return NULL;
	}
	auth4_context->generate_session_info = ntlm_auth_generate_session_info;
	auth4_context->generate_session_info_pac = ntlm_auth_generate_session_info_pac;
	auth4_context->get_ntlm_challenge = ntlm_auth_get_challenge;
	auth4_context->set_ntlm_challenge = ntlm_auth_set_challenge;
	if (local_pw) {
		auth4_context->check_ntlm_password_send = local_pw_check_send;
		auth4_context->check_ntlm_password_recv = local_pw_check_recv;
	} else {
		auth4_context->check_ntlm_password_send =
			winbind_pw_check_send;
		auth4_context->check_ntlm_password_recv =
			winbind_pw_check_recv;
	}
	auth4_context->private_data = NULL;
	return auth4_context;
}

static NTSTATUS ntlm_auth_prepare_gensec_server(TALLOC_CTX *mem_ctx,
						struct loadparm_context *lp_ctx,
						struct gensec_security **gensec_security_out)
{
	struct gensec_security *gensec_security;
	NTSTATUS nt_status;

	TALLOC_CTX *tmp_ctx;
	const struct gensec_security_ops **backends;
	struct gensec_settings *gensec_settings;
	size_t idx = 0;
	struct cli_credentials *server_credentials;

	struct auth4_context *auth4_context;

	tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	auth4_context = make_auth4_context_ntlm_auth(tmp_ctx, opt_password);
	if (auth4_context == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	gensec_settings = lpcfg_gensec_settings(tmp_ctx, lp_ctx);
	if (lp_ctx == NULL) {
		DEBUG(10, ("lpcfg_gensec_settings failed\n"));
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * This should be a 'netbios domain -> DNS domain'
	 * mapping, and can currently validly return NULL on
	 * poorly configured systems.
	 *
	 * This is used for the NTLMSSP server
	 *
	 */
	if (opt_password) {
		gensec_settings->server_netbios_name = lp_netbios_name();
		gensec_settings->server_netbios_domain = lp_workgroup();
	} else {
		gensec_settings->server_netbios_name = get_winbind_netbios_name();
		gensec_settings->server_netbios_domain = get_winbind_domain();
	}

	gensec_settings->server_dns_domain = strlower_talloc(gensec_settings,
							     get_mydnsdomname(talloc_tos()));
	gensec_settings->server_dns_name = strlower_talloc(gensec_settings,
							   get_mydnsfullname());

	backends = talloc_zero_array(gensec_settings,
				     const struct gensec_security_ops *, 4);

	if (backends == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	gensec_settings->backends = backends;

	gensec_init();

	/* These need to be in priority order, krb5 before NTLMSSP */
#if defined(HAVE_KRB5)
	backends[idx++] = &gensec_gse_krb5_security_ops;
#endif

	backends[idx++] = gensec_security_by_oid(NULL, GENSEC_OID_NTLMSSP);

	backends[idx++] = gensec_security_by_oid(NULL, GENSEC_OID_SPNEGO);

	/*
	 * This is anonymous for now, because we just use it
	 * to set the kerberos state at the moment
	 */
	server_credentials = cli_credentials_init_anon(tmp_ctx);
	if (!server_credentials) {
		DBG_ERR("Failed to init server credentials\n");
		return NT_STATUS_NO_MEMORY;
	}

	cli_credentials_set_conf(server_credentials, lp_ctx);

	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC || lp_security() == SEC_ADS || USE_KERBEROS_KEYTAB) {
		cli_credentials_set_kerberos_state(server_credentials, CRED_AUTO_USE_KERBEROS);
	} else {
		cli_credentials_set_kerberos_state(server_credentials, CRED_DONT_USE_KERBEROS);
	}

	nt_status = gensec_server_start(tmp_ctx, gensec_settings,
					auth4_context, &gensec_security);

	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	gensec_set_credentials(gensec_security, server_credentials);

	/*
	 * TODO: Allow the caller to pass their own description here
	 * via a command-line option
	 */
	nt_status = gensec_set_target_service_description(gensec_security,
							  "ntlm_auth");
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	talloc_unlink(tmp_ctx, lp_ctx);
	talloc_unlink(tmp_ctx, server_credentials);
	talloc_unlink(tmp_ctx, gensec_settings);
	talloc_unlink(tmp_ctx, auth4_context);

	*gensec_security_out = talloc_steal(mem_ctx, gensec_security);
	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}

static void manage_client_ntlmssp_request(enum stdio_helper_mode stdio_helper_mode,
				   struct loadparm_context *lp_ctx,
				   struct ntlm_auth_state *state,
						char *buf, int length, void **private2)
{
	manage_gensec_request(stdio_helper_mode, lp_ctx, buf, length, &state->gensec_private_1);
	return;
}

static void manage_squid_basic_request(enum stdio_helper_mode stdio_helper_mode,
				   struct loadparm_context *lp_ctx,
				   struct ntlm_auth_state *state,
					char *buf, int length, void **private2)
{
	char *user, *pass;
	user=buf;

	pass=(char *)memchr(buf,' ',length);
	if (!pass) {
		DEBUG(2, ("Password not found. Denying access\n"));
		printf("ERR\n");
		return;
	}
	*pass='\0';
	pass++;

	if (state->helper_mode == SQUID_2_5_BASIC) {
		char *end = rfc1738_unescape(user);
		if (end == NULL || (end - user) != strlen(user)) {
			DEBUG(2, ("Badly rfc1738 encoded username: %s; "
				  "denying access\n", user));
			printf("ERR\n");
			return;
		}
		end = rfc1738_unescape(pass);
		if (end == NULL || (end - pass) != strlen(pass)) {
			DEBUG(2, ("Badly encoded password for %s; "
				  "denying access\n", user));
			printf("ERR\n");
			return;
		}
	}

	if (check_plaintext_auth(user, pass, False)) {
		printf("OK\n");
	} else {
		printf("ERR\n");
	}
}

static void manage_gensec_request(enum stdio_helper_mode stdio_helper_mode,
				  struct loadparm_context *lp_ctx,
				  char *buf, int length, void **private1)
{
	DATA_BLOB in;
	DATA_BLOB out = data_blob(NULL, 0);
	char *out_base64 = NULL;
	const char *reply_arg = NULL;
	struct gensec_ntlm_state {
		struct gensec_security *gensec_state;
		const char *set_password;
	};
	struct gensec_ntlm_state *state;

	NTSTATUS nt_status;
	bool first = false;
	const char *reply_code;
	struct cli_credentials *creds;

	static char *want_feature_list = NULL;
	static DATA_BLOB session_key;

	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_named(NULL, 0, "manage_gensec_request internal mem_ctx");
	if (mem_ctx == NULL) {
		printf("BH No Memory\n");
		exit(1);
	}

	if (*private1) {
		state = talloc_get_type(*private1, struct gensec_ntlm_state);
		if (state == NULL) {
			DBG_WARNING("*private1 is of type %s\n",
				    talloc_get_name(*private1));
			printf("BH *private1 is of type %s\n",
			       talloc_get_name(*private1));
			exit(1);
		}
	} else {
		state = talloc_zero(NULL, struct gensec_ntlm_state);
		if (!state) {
			printf("BH No Memory\n");
			exit(1);
		}
		*private1 = state;
		if (opt_password) {
			state->set_password = opt_password;
		}
	}

	if (strlen(buf) < 2) {
		DEBUG(1, ("query [%s] invalid", buf));
		printf("BH Query invalid\n");
		talloc_free(mem_ctx);
		return;
	}

	if (strlen(buf) > 3) {
		if(strncmp(buf, "SF ", 3) == 0) {
			DEBUG(10, ("Setting flags to negotiate\n"));
			talloc_free(want_feature_list);
			want_feature_list = talloc_strndup(state, buf+3, strlen(buf)-3);
			printf("OK\n");
			talloc_free(mem_ctx);
			return;
		}
		in = base64_decode_data_blob_talloc(mem_ctx, buf + 3);
	} else {
		in = data_blob(NULL, 0);
	}

	if (strncmp(buf, "YR", 2) == 0) {
		if (state->gensec_state) {
			talloc_free(state->gensec_state);
			state->gensec_state = NULL;
		}
	} else if ( (strncmp(buf, "OK", 2) == 0)) {
		/* Just return BH, like ntlm_auth from Samba 3 does. */
		printf("BH Command expected\n");
		talloc_free(mem_ctx);
		return;
	} else if ( (strncmp(buf, "TT ", 3) != 0) &&
		    (strncmp(buf, "KK ", 3) != 0) &&
		    (strncmp(buf, "AF ", 3) != 0) &&
		    (strncmp(buf, "NA ", 3) != 0) &&
		    (strncmp(buf, "UG", 2) != 0) &&
		    (strncmp(buf, "PW ", 3) != 0) &&
		    (strncmp(buf, "GK", 2) != 0) &&
		    (strncmp(buf, "GF", 2) != 0)) {
		DEBUG(1, ("SPNEGO request [%s] invalid prefix\n", buf));
		printf("BH SPNEGO request invalid prefix\n");
		talloc_free(mem_ctx);
		return;
	}

	/* setup gensec */
	if (!(state->gensec_state)) {
		switch (stdio_helper_mode) {
		case GSS_SPNEGO_CLIENT:
			/*
			 * cached credentials are only supported by
			 * NTLMSSP_CLIENT_1 for now.
			 */
			use_cached_creds = false;
			FALL_THROUGH;
		case NTLMSSP_CLIENT_1:
			/* setup the client side */

			if (state->set_password != NULL) {
				use_cached_creds = false;
			}

			if (use_cached_creds) {
				struct wbcCredentialCacheParams params;
				struct wbcCredentialCacheInfo *info = NULL;
				struct wbcAuthErrorInfo *error = NULL;
				wbcErr wbc_status;

				params.account_name = opt_username;
				params.domain_name = opt_domain;
				params.level = WBC_CREDENTIAL_CACHE_LEVEL_NTLMSSP;
				params.num_blobs = 0;
				params.blobs = NULL;

				wbc_status = wbcCredentialCache(&params, &info,
								&error);
				wbcFreeMemory(error);
				if (!WBC_ERROR_IS_OK(wbc_status)) {
					use_cached_creds = false;
				}
				wbcFreeMemory(info);
			}

			nt_status = ntlm_auth_prepare_gensec_client(state, lp_ctx,
								    &state->gensec_state);
			if (!NT_STATUS_IS_OK(nt_status)) {
				printf("BH GENSEC mech failed to start: %s\n",
				       nt_errstr(nt_status));
				talloc_free(mem_ctx);
				return;
			}

			creds = cli_credentials_init(state->gensec_state);
			cli_credentials_set_conf(creds, lp_ctx);
			if (opt_username) {
				cli_credentials_set_username(creds, opt_username, CRED_SPECIFIED);
			}
			if (opt_domain) {
				cli_credentials_set_domain(creds, opt_domain, CRED_SPECIFIED);
			}
			if (use_cached_creds) {
				gensec_want_feature(state->gensec_state,
						    GENSEC_FEATURE_NTLM_CCACHE);
			} else if (state->set_password) {
				cli_credentials_set_password(creds, state->set_password, CRED_SPECIFIED);
			} else {
				cli_credentials_set_password_callback(creds, get_password);
			}
			if (opt_workstation) {
				cli_credentials_set_workstation(creds, opt_workstation, CRED_SPECIFIED);
			}

			gensec_set_credentials(state->gensec_state, creds);

			break;
		case GSS_SPNEGO_SERVER:
		case SQUID_2_5_NTLMSSP:
		{
			nt_status = ntlm_auth_prepare_gensec_server(state, lp_ctx,
								    &state->gensec_state);
			if (!NT_STATUS_IS_OK(nt_status)) {
				printf("BH GENSEC mech failed to start: %s\n",
				       nt_errstr(nt_status));
				talloc_free(mem_ctx);
				return;
			}
			break;
		}
		default:
			talloc_free(mem_ctx);
			abort();
		}

		gensec_want_feature_list(state->gensec_state, want_feature_list);

		/* Session info is not complete, do not pass to auth log */
		gensec_want_feature(state->gensec_state, GENSEC_FEATURE_NO_AUTHZ_LOG);

		switch (stdio_helper_mode) {
		case GSS_SPNEGO_CLIENT:
		case GSS_SPNEGO_SERVER:
			nt_status = gensec_start_mech_by_oid(state->gensec_state, GENSEC_OID_SPNEGO);
			if (!in.length) {
				first = true;
			}
			break;
		case NTLMSSP_CLIENT_1:
			if (!in.length) {
				first = true;
			}
			FALL_THROUGH;
		case SQUID_2_5_NTLMSSP:
			nt_status = gensec_start_mech_by_oid(state->gensec_state, GENSEC_OID_NTLMSSP);
			break;
		default:
			talloc_free(mem_ctx);
			abort();
		}

		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(1, ("GENSEC mech failed to start: %s\n", nt_errstr(nt_status)));
			printf("BH GENSEC mech failed to start\n");
			talloc_free(mem_ctx);
			return;
		}

	}

	/* update */

	if (strncmp(buf, "PW ", 3) == 0) {
		state->set_password = talloc_strndup(state,
						     (const char *)in.data,
						     in.length);

		cli_credentials_set_password(gensec_get_credentials(state->gensec_state),
					     state->set_password,
					     CRED_SPECIFIED);
		printf("OK\n");
		talloc_free(mem_ctx);
		return;
	}

	if (strncmp(buf, "GK", 2) == 0) {
		char *base64_key;
		DEBUG(10, ("Requested session key\n"));
		nt_status = gensec_session_key(state->gensec_state, mem_ctx, &session_key);
		if(!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(1, ("gensec_session_key failed: %s\n", nt_errstr(nt_status)));
			printf("BH No session key\n");
			talloc_free(mem_ctx);
			return;
		} else {
			base64_key = base64_encode_data_blob(state, session_key);
			SMB_ASSERT(base64_key != NULL);
			printf("GK %s\n", base64_key);
			talloc_free(base64_key);
		}
		talloc_free(mem_ctx);
		return;
	}

	if (strncmp(buf, "GF", 2) == 0) {
		uint32_t neg_flags;

		DEBUG(10, ("Requested negotiated NTLMSSP feature flags\n"));

		neg_flags = gensec_ntlmssp_neg_flags(state->gensec_state);
		if (neg_flags == 0) {
			printf("BH\n");
			talloc_free(mem_ctx);
			return;
		}

		printf("GF 0x%08x\n", neg_flags);
		talloc_free(mem_ctx);
		return;
	}

	nt_status = gensec_update(state->gensec_state, mem_ctx, in, &out);

	/* don't leak 'bad password'/'no such user' info to the network client */
	nt_status = nt_status_squash(nt_status);

	if (out.length) {
		out_base64 = base64_encode_data_blob(mem_ctx, out);
		SMB_ASSERT(out_base64 != NULL);
	} else {
		out_base64 = NULL;
	}

	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		reply_arg = "*";
		if (first && state->gensec_state->gensec_role == GENSEC_CLIENT) {
			reply_code = "YR";
		} else if (state->gensec_state->gensec_role == GENSEC_CLIENT) {
			reply_code = "KK";
		} else if (state->gensec_state->gensec_role == GENSEC_SERVER) {
			reply_code = "TT";
		} else {
			abort();
		}


	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_ACCESS_DENIED)) {
		reply_code = "BH NT_STATUS_ACCESS_DENIED";
		reply_arg = nt_errstr(nt_status);
		DEBUG(1, ("GENSEC login failed: %s\n", nt_errstr(nt_status)));
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_UNSUCCESSFUL)) {
		reply_code = "BH NT_STATUS_UNSUCCESSFUL";
		reply_arg = nt_errstr(nt_status);
		DEBUG(1, ("GENSEC login failed: %s\n", nt_errstr(nt_status)));
	} else if (!NT_STATUS_IS_OK(nt_status)) {
		reply_code = "NA";
		reply_arg = nt_errstr(nt_status);
		DEBUG(1, ("GENSEC login failed: %s\n", nt_errstr(nt_status)));
	} else if /* OK */ (state->gensec_state->gensec_role == GENSEC_SERVER) {
		struct auth_session_info *session_info;

		nt_status = gensec_session_info(state->gensec_state, mem_ctx, &session_info);
		if (!NT_STATUS_IS_OK(nt_status)) {
			reply_code = "BH Failed to retrieve session info";
			reply_arg = nt_errstr(nt_status);
			DEBUG(1, ("GENSEC failed to retrieve the session info: %s\n", nt_errstr(nt_status)));
		} else {

			reply_code = "AF";
			reply_arg = talloc_strdup(state->gensec_state, session_info->unix_info->unix_name);
			if (reply_arg == NULL) {
				reply_code = "BH out of memory";
				reply_arg = nt_errstr(NT_STATUS_NO_MEMORY);
			}
			talloc_free(session_info);
		}
	} else if (state->gensec_state->gensec_role == GENSEC_CLIENT) {
		reply_code = "AF";
		reply_arg = out_base64;
	} else {
		abort();
	}

	switch (stdio_helper_mode) {
	case GSS_SPNEGO_SERVER:
		printf("%s %s %s\n", reply_code,
		       out_base64 ? out_base64 : "*",
		       reply_arg ? reply_arg : "*");
		break;
	default:
		if (out_base64) {
			printf("%s %s\n", reply_code, out_base64);
		} else if (reply_arg) {
			printf("%s %s\n", reply_code, reply_arg);
		} else {
			printf("%s\n", reply_code);
		}
	}

	talloc_free(mem_ctx);
	return;
}

static void manage_gss_spnego_request(enum stdio_helper_mode stdio_helper_mode,
				   struct loadparm_context *lp_ctx,
				   struct ntlm_auth_state *state,
				      char *buf, int length, void **private2)
{
	manage_gensec_request(stdio_helper_mode, lp_ctx, buf, length, &state->gensec_private_1);
	return;
}

static void manage_squid_ntlmssp_request(enum stdio_helper_mode stdio_helper_mode,
				   struct loadparm_context *lp_ctx,
				   struct ntlm_auth_state *state,
					 char *buf, int length, void **private2)
{
	manage_gensec_request(stdio_helper_mode, lp_ctx, buf, length, &state->gensec_private_1);
	return;
}

static void manage_gss_spnego_client_request(enum stdio_helper_mode stdio_helper_mode,
				   struct loadparm_context *lp_ctx,
				   struct ntlm_auth_state *state,
					     char *buf, int length, void **private2)
{
	manage_gensec_request(stdio_helper_mode, lp_ctx, buf, length, &state->gensec_private_1);
	return;
}

static void manage_ntlm_server_1_request(enum stdio_helper_mode stdio_helper_mode,
				   struct loadparm_context *lp_ctx,
				   struct ntlm_auth_state *state,
						char *buf, int length, void **private2)
{
	char *request, *parameter;
	static DATA_BLOB challenge;
	static DATA_BLOB lm_response;
	static DATA_BLOB nt_response;
	static char *full_username;
	static char *username;
	static char *domain;
	static char *plaintext_password;
	static bool ntlm_server_1_user_session_key;
	static bool ntlm_server_1_lm_session_key;

	if (strequal(buf, ".")) {
		if (!full_username && !username) {
			printf("Error: No username supplied!\n");
		} else if (plaintext_password) {
			/* handle this request as plaintext */
			if (!full_username) {
				if (asprintf(&full_username, "%s%c%s", domain, winbind_separator(), username) == -1) {
					printf("Error: Out of memory in "
					       "asprintf!\n.\n");
					return;
				}
			}
			if (check_plaintext_auth(full_username, plaintext_password, False)) {
				printf("Authenticated: Yes\n");
			} else {
				printf("Authenticated: No\n");
			}
		} else if (!lm_response.data && !nt_response.data) {
			printf("Error: No password supplied!\n");
		} else if (!challenge.data) {
			printf("Error: No lanman-challenge supplied!\n");
		} else {
			char *error_string = NULL;
			uchar lm_key[8];
			uchar user_session_key[16];
			uint32_t flags = 0;
			NTSTATUS nt_status;
			if (full_username && !username) {
				fstring fstr_user;
				fstring fstr_domain;

				if (!parse_ntlm_auth_domain_user(full_username, fstr_user, fstr_domain)) {
					/* username might be 'tainted', don't print into our new-line deleimianted stream */
					printf("Error: Could not parse into "
					       "domain and username\n");
				}
				SAFE_FREE(username);
				SAFE_FREE(domain);
				username = smb_xstrdup(fstr_user);
				domain = smb_xstrdup(fstr_domain);
			}

			if (opt_password) {
				DATA_BLOB nt_session_key, lm_session_key;
				struct samr_Password lm_pw, nt_pw;
				TALLOC_CTX *mem_ctx = talloc_new(NULL);
				ZERO_STRUCT(user_session_key);
				ZERO_STRUCT(lm_key);

				nt_lm_owf_gen (opt_password, nt_pw.hash, lm_pw.hash);
				nt_status = ntlm_password_check(mem_ctx,
								true,
								NTLM_AUTH_ON,
								0,
								&challenge,
								&lm_response,
								&nt_response,
								username,
								username,
								domain,
								&lm_pw, &nt_pw,
								&nt_session_key,
								&lm_session_key);
				error_string = smb_xstrdup(get_friendly_nt_error_msg(nt_status));
				if (ntlm_server_1_user_session_key) {
					if (nt_session_key.length == sizeof(user_session_key)) {
						memcpy(user_session_key,
						       nt_session_key.data,
						       sizeof(user_session_key));
					}
				}
				if (ntlm_server_1_lm_session_key) {
					if (lm_session_key.length == sizeof(lm_key)) {
						memcpy(lm_key,
						       lm_session_key.data,
						       sizeof(lm_key));
					}
				}
				TALLOC_FREE(mem_ctx);

			} else {
				uint8_t authoritative = 1;

				if (!domain) {
					domain = smb_xstrdup(get_winbind_domain());
				}

				if (ntlm_server_1_lm_session_key)
					flags |= WBFLAG_PAM_LMKEY;

				if (ntlm_server_1_user_session_key)
					flags |= WBFLAG_PAM_USER_SESSION_KEY;

				nt_status = contact_winbind_auth_crap(username,
								      domain,
								      lp_netbios_name(),
								      &challenge,
								      &lm_response,
								      &nt_response,
								      flags, 0,
								      lm_key,
								      user_session_key,
								      &authoritative,
								      &error_string,
								      NULL);
			}

			if (!NT_STATUS_IS_OK(nt_status)) {
				printf("Authenticated: No\n");
				printf("Authentication-Error: %s\n.\n",
				       error_string);
			} else {
				char *hex_lm_key;
				char *hex_user_session_key;

				printf("Authenticated: Yes\n");

				if (ntlm_server_1_lm_session_key 
				    && (!all_zero(lm_key,
						  sizeof(lm_key)))) {
					hex_lm_key = hex_encode_talloc(NULL,
								(const unsigned char *)lm_key,
								sizeof(lm_key));
					printf("LANMAN-Session-Key: %s\n",
					       hex_lm_key);
					TALLOC_FREE(hex_lm_key);
				}

				if (ntlm_server_1_user_session_key
				    && (!all_zero(user_session_key,
						  sizeof(user_session_key)))) {
					hex_user_session_key = hex_encode_talloc(NULL,
									  (const unsigned char *)user_session_key,
									  sizeof(user_session_key));
					printf("User-Session-Key: %s\n",
					       hex_user_session_key);
					TALLOC_FREE(hex_user_session_key);
				}
			}
			SAFE_FREE(error_string);
		}
		/* clear out the state */
		challenge = data_blob_null;
		nt_response = data_blob_null;
		lm_response = data_blob_null;
		SAFE_FREE(full_username);
		SAFE_FREE(username);
		SAFE_FREE(domain);
		SAFE_FREE(plaintext_password);
		ntlm_server_1_user_session_key = False;
		ntlm_server_1_lm_session_key = False;
		printf(".\n");

		return;
	}

	request = buf;

	/* Indicates a base64 encoded structure */
	parameter = strstr_m(request, ":: ");
	if (!parameter) {
		parameter = strstr_m(request, ": ");

		if (!parameter) {
			DEBUG(0, ("Parameter not found!\n"));
			printf("Error: Parameter not found!\n.\n");
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
		challenge = strhex_to_data_blob(NULL, parameter);
		if (challenge.length != 8) {
			printf("Error: hex decode of %s failed! "
			       "(got %d bytes, expected 8)\n.\n",
			       parameter,
			       (int)challenge.length);
			challenge = data_blob_null;
		}
	} else if (strequal(request, "NT-Response")) {
		nt_response = strhex_to_data_blob(NULL, parameter);
		if (nt_response.length < 24) {
			printf("Error: hex decode of %s failed! "
			       "(only got %d bytes, needed at least 24)\n.\n",
			       parameter,
			       (int)nt_response.length);
			nt_response = data_blob_null;
		}
	} else if (strequal(request, "LANMAN-Response")) {
		lm_response = strhex_to_data_blob(NULL, parameter);
		if (lm_response.length != 24) {
			printf("Error: hex decode of %s failed! "
			       "(got %d bytes, expected 24)\n.\n",
			       parameter,
			       (int)lm_response.length);
			lm_response = data_blob_null;
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
		printf("Error: Unknown request %s\n.\n", request);
	}
}

static void manage_ntlm_change_password_1_request(enum stdio_helper_mode stdio_helper_mode,
						  struct loadparm_context *lp_ctx,
						  struct ntlm_auth_state *state,
						  char *buf, int length, void **private2)
{
	char *request, *parameter;
	static DATA_BLOB new_nt_pswd;
	static DATA_BLOB old_nt_hash_enc;
	static DATA_BLOB new_lm_pswd;
	static DATA_BLOB old_lm_hash_enc;
	static char *full_username = NULL;
	static char *username = NULL;
	static char *domain = NULL;
	static char *newpswd =  NULL;
	static char *oldpswd = NULL;

	if (strequal(buf, "."))	{
		if(newpswd && oldpswd) {
			uchar old_nt_hash[16];
			uchar old_lm_hash[16];
			uchar new_nt_hash[16];
			uchar new_lm_hash[16];

			gnutls_cipher_hd_t cipher_hnd = NULL;
			gnutls_datum_t old_nt_key = {
				.data = old_nt_hash,
				.size = sizeof(old_nt_hash),
			};
			int rc;

			new_nt_pswd = data_blob(NULL, 516);
			old_nt_hash_enc = data_blob(NULL, 16);

			/* Calculate the MD4 hash (NT compatible) of the
			 * password */
			E_md4hash(oldpswd, old_nt_hash);
			E_md4hash(newpswd, new_nt_hash);

			/* E_deshash returns false for 'long'
			   passwords (> 14 DOS chars).

			   Therefore, don't send a buffer
			   encrypted with the truncated hash
			   (it could allow an even easier
			   attack on the password)

			   Likewise, obey the admin's restriction
			*/

			rc = gnutls_cipher_init(&cipher_hnd,
						GNUTLS_CIPHER_ARCFOUR_128,
						&old_nt_key,
						NULL);
			if (rc < 0) {
				DBG_ERR("gnutls_cipher_init failed: %s\n",
					gnutls_strerror(rc));
				if (rc == GNUTLS_E_UNWANTED_ALGORITHM) {
					DBG_ERR("Running in FIPS mode, NTLM blocked\n");
				}
				return;
			}

			if (lp_client_lanman_auth() &&
			    E_deshash(newpswd, new_lm_hash) &&
			    E_deshash(oldpswd, old_lm_hash)) {
				new_lm_pswd = data_blob(NULL, 516);
				old_lm_hash_enc = data_blob(NULL, 16);
				encode_pw_buffer(new_lm_pswd.data, newpswd,
						 STR_UNICODE);

				rc = gnutls_cipher_encrypt(cipher_hnd,
							   new_lm_pswd.data,
							   516);
				if (rc < 0) {
					gnutls_cipher_deinit(cipher_hnd);
					return;
				}
				rc = E_old_pw_hash(new_nt_hash, old_lm_hash,
					      old_lm_hash_enc.data);
				if (rc != 0) {
					DBG_ERR("E_old_pw_hash failed: %s\n",
						gnutls_strerror(rc));
					return;
				}
			} else {
				new_lm_pswd.data = NULL;
				new_lm_pswd.length = 0;
				old_lm_hash_enc.data = NULL;
				old_lm_hash_enc.length = 0;
			}

			encode_pw_buffer(new_nt_pswd.data, newpswd,
					 STR_UNICODE);

			rc = gnutls_cipher_encrypt(cipher_hnd,
						   new_nt_pswd.data,
						   516);
			gnutls_cipher_deinit(cipher_hnd);
			if (rc < 0) {
				return;
			}
			rc = E_old_pw_hash(new_nt_hash, old_nt_hash,
				      old_nt_hash_enc.data);
			if (rc != 0) {
				DBG_ERR("E_old_pw_hash failed: %s\n",
					gnutls_strerror(rc));
				return;
			}

			ZERO_ARRAY(old_nt_hash);
			ZERO_ARRAY(old_lm_hash);
			ZERO_ARRAY(new_nt_hash);
			ZERO_ARRAY(new_lm_hash);
		}

		if (!full_username && !username) {
			printf("Error: No username supplied!\n");
		} else if ((!new_nt_pswd.data || !old_nt_hash_enc.data) &&
			   (!new_lm_pswd.data || old_lm_hash_enc.data) ) {
			printf("Error: No NT or LM password "
			       "blobs supplied!\n");
		} else {
			char *error_string = NULL;

			if (full_username && !username)	{
				fstring fstr_user;
				fstring fstr_domain;

				if (!parse_ntlm_auth_domain_user(full_username,
								 fstr_user,
								 fstr_domain)) {
					/* username might be 'tainted', don't
					 * print into our new-line
					 * deleimianted stream */
					printf("Error: Could not "
					       "parse into domain and "
					       "username\n");
					SAFE_FREE(username);
					username = smb_xstrdup(full_username);
				} else {
					SAFE_FREE(username);
					SAFE_FREE(domain);
					username = smb_xstrdup(fstr_user);
					domain = smb_xstrdup(fstr_domain);
				}

			}

			if(!NT_STATUS_IS_OK(contact_winbind_change_pswd_auth_crap(
						    username, domain,
						    new_nt_pswd,
						    old_nt_hash_enc,
						    new_lm_pswd,
						    old_lm_hash_enc,
						    &error_string))) {
				printf("Password-Change: No\n");
				printf("Password-Change-Error: %s\n.\n",
				       error_string);
			} else {
				printf("Password-Change: Yes\n");
			}

			SAFE_FREE(error_string);
		}
		/* clear out the state */
		new_nt_pswd = data_blob_null;
		old_nt_hash_enc = data_blob_null;
		new_lm_pswd = data_blob_null;
		old_nt_hash_enc = data_blob_null;
		SAFE_FREE(full_username);
		SAFE_FREE(username);
		SAFE_FREE(domain);
		SAFE_FREE(newpswd);
		SAFE_FREE(oldpswd);
		printf(".\n");

		return;
	}

	request = buf;

	/* Indicates a base64 encoded structure */
	parameter = strstr_m(request, ":: ");
	if (!parameter) {
		parameter = strstr_m(request, ": ");

		if (!parameter)	{
			DEBUG(0, ("Parameter not found!\n"));
			printf("Error: Parameter not found!\n.\n");
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

	if (strequal(request, "new-nt-password-blob")) {
		new_nt_pswd = strhex_to_data_blob(NULL, parameter);
		if (new_nt_pswd.length != 516) {
			printf("Error: hex decode of %s failed! "
			       "(got %d bytes, expected 516)\n.\n",
			       parameter,
			       (int)new_nt_pswd.length);
			new_nt_pswd = data_blob_null;
		}
	} else if (strequal(request, "old-nt-hash-blob")) {
		old_nt_hash_enc = strhex_to_data_blob(NULL, parameter);
		if (old_nt_hash_enc.length != 16) {
			printf("Error: hex decode of %s failed! "
			       "(got %d bytes, expected 16)\n.\n",
			       parameter,
			       (int)old_nt_hash_enc.length);
			old_nt_hash_enc = data_blob_null;
		}
	} else if (strequal(request, "new-lm-password-blob")) {
		new_lm_pswd = strhex_to_data_blob(NULL, parameter);
		if (new_lm_pswd.length != 516) {
			printf("Error: hex decode of %s failed! "
			       "(got %d bytes, expected 516)\n.\n",
			       parameter,
			       (int)new_lm_pswd.length);
			new_lm_pswd = data_blob_null;
		}
	}
	else if (strequal(request, "old-lm-hash-blob"))	{
		old_lm_hash_enc = strhex_to_data_blob(NULL, parameter);
		if (old_lm_hash_enc.length != 16)
		{
			printf("Error: hex decode of %s failed! "
			       "(got %d bytes, expected 16)\n.\n",
			       parameter,
			       (int)old_lm_hash_enc.length);
			old_lm_hash_enc = data_blob_null;
		}
	} else if (strequal(request, "nt-domain")) {
		domain = smb_xstrdup(parameter);
	} else if(strequal(request, "username")) {
		username = smb_xstrdup(parameter);
	} else if(strequal(request, "full-username")) {
		username = smb_xstrdup(parameter);
	} else if(strequal(request, "new-password")) {
		newpswd = smb_xstrdup(parameter);
	} else if (strequal(request, "old-password")) {
		oldpswd = smb_xstrdup(parameter);
	} else {
		printf("Error: Unknown request %s\n.\n", request);
	}
}

static void manage_squid_request(enum stdio_helper_mode stdio_helper_mode,
				   struct loadparm_context *lp_ctx,
				   struct ntlm_auth_state *state,
		stdio_helper_function fn, void **private2)
{
	char *buf;
	char tmp[INITIAL_BUFFER_SIZE+1];
	int length, buf_size = 0;
	char *c;

	buf = talloc_strdup(state->mem_ctx, "");
	if (!buf) {
		DEBUG(0, ("Failed to allocate input buffer.\n"));
		fprintf(stderr, "ERR\n");
		exit(1);
	}

	do {

		/* this is not a typo - x_fgets doesn't work too well under
		 * squid */
		if (fgets(tmp, sizeof(tmp)-1, stdin) == NULL) {
			if (ferror(stdin)) {
				DEBUG(1, ("fgets() failed! dying..... errno=%d "
					  "(%s)\n", ferror(stdin),
					  strerror(ferror(stdin))));

				exit(1);
			}
			exit(0);
		}

		buf = talloc_strdup_append_buffer(buf, tmp);
		buf_size += INITIAL_BUFFER_SIZE;

		if (buf_size > MAX_BUFFER_SIZE) {
			DEBUG(2, ("Oversized message\n"));
			fprintf(stderr, "ERR\n");
			talloc_free(buf);
			return;
		}

		c = strchr(buf, '\n');
	} while (c == NULL);

	*c = '\0';
	length = c-buf;

	DEBUG(10, ("Got '%s' from squid (length: %d).\n",buf,length));

	if (buf[0] == '\0') {
		DEBUG(2, ("Invalid Request\n"));
		fprintf(stderr, "ERR\n");
		talloc_free(buf);
		return;
	}

	fn(stdio_helper_mode, lp_ctx, state, buf, length, private2);
	talloc_free(buf);
}


static void squid_stream(enum stdio_helper_mode stdio_mode,
			 struct loadparm_context *lp_ctx,
			 stdio_helper_function fn) {
	TALLOC_CTX *mem_ctx;
	struct ntlm_auth_state *state;

	/* initialize FDescs */
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	mem_ctx = talloc_init("ntlm_auth");
	if (!mem_ctx) {
		DEBUG(0, ("squid_stream: Failed to create talloc context\n"));
		fprintf(stderr, "ERR\n");
		exit(1);
	}

	state = talloc_zero(mem_ctx, struct ntlm_auth_state);
	if (!state) {
		DEBUG(0, ("squid_stream: Failed to talloc ntlm_auth_state\n"));
		fprintf(stderr, "ERR\n");
		exit(1);
	}

	state->mem_ctx = mem_ctx;
	state->helper_mode = stdio_mode;

	while(1) {
		TALLOC_CTX *frame = talloc_stackframe();
		manage_squid_request(stdio_mode, lp_ctx, state, fn, NULL);
		TALLOC_FREE(frame);
	}
}


/* Authenticate a user with a challenge/response */

static bool check_auth_crap(void)
{
	NTSTATUS nt_status;
	uint32_t flags = 0;
	char lm_key[8];
	char user_session_key[16];
	char *hex_lm_key;
	char *hex_user_session_key;
	char *error_string;
	uint8_t authoritative = 1;

	setbuf(stdout, NULL);

	if (request_lm_key)
		flags |= WBFLAG_PAM_LMKEY;

	if (request_user_session_key)
		flags |= WBFLAG_PAM_USER_SESSION_KEY;

	flags |= WBFLAG_PAM_NT_STATUS_SQUASH;

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain,
					      opt_workstation,
					      &opt_challenge,
					      &opt_lm_response,
					      &opt_nt_response,
					      flags, 0,
					      (unsigned char *)lm_key,
					      (unsigned char *)user_session_key,
					      &authoritative,
					      &error_string, NULL);

	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("%s (0x%x)\n", error_string,
		       NT_STATUS_V(nt_status));
		SAFE_FREE(error_string);
		return False;
	}

	if (request_lm_key
	    && (!all_zero((uint8_t *)lm_key, sizeof(lm_key)))) {
		hex_lm_key = hex_encode_talloc(talloc_tos(), (const unsigned char *)lm_key,
					sizeof(lm_key));
		printf("LM_KEY: %s\n", hex_lm_key);
		TALLOC_FREE(hex_lm_key);
	}
	if (request_user_session_key
	    && (!all_zero((uint8_t *)user_session_key,
			  sizeof(user_session_key)))) {
		hex_user_session_key = hex_encode_talloc(talloc_tos(), (const unsigned char *)user_session_key,
						  sizeof(user_session_key));
		printf("NT_KEY: %s\n", hex_user_session_key);
		TALLOC_FREE(hex_user_session_key);
	}

        return True;
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
	OPT_REQUIRE_MEMBERSHIP,
	OPT_USE_CACHED_CREDS,
	OPT_ALLOW_MSCHAPV2,
	OPT_PAM_WINBIND_CONF,
	OPT_TARGET_SERVICE,
	OPT_TARGET_HOSTNAME,
	OPT_OFFLINE_LOGON
};

 int main(int argc, const char **argv)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int opt;
	const char *helper_protocol = NULL;
	int diagnostics = 0;

	const char *hex_challenge = NULL;
	const char *hex_lm_response = NULL;
	const char *hex_nt_response = NULL;
	struct loadparm_context *lp_ctx;
	poptContext pc;

	/* NOTE: DO NOT change this interface without considering the implications!
	   This is an external interface, which other programs will use to interact
	   with this helper.
	*/

	/* We do not use single-letter command abbreviations, because they harm future
	   interface stability. */

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "helper-protocol",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &helper_protocol,
			.val        = OPT_DOMAIN,
			.descrip    = "operate as a stdio-based helper",
			.argDescrip = "helper protocol to use"
		},
		{
			.longName   = "username",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &opt_username,
			.val        = OPT_USERNAME,
			.descrip    = "username"
		},
		{
			.longName   = "domain",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &opt_domain,
			.val        = OPT_DOMAIN,
			.descrip    = "domain name"
		},
		{
			.longName   = "workstation",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &opt_workstation,
			.val        = OPT_WORKSTATION,
			.descrip    = "workstation"
		},
		{
			.longName   = "challenge",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &hex_challenge,
			.val        = OPT_CHALLENGE,
			.descrip    = "challenge (HEX encoded)"
		},
		{
			.longName   = "lm-response",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &hex_lm_response,
			.val        = OPT_LM,
			.descrip    = "LM Response to the challenge (HEX encoded)"
		},
		{
			.longName   = "nt-response",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &hex_nt_response,
			.val        = OPT_NT,
			.descrip    = "NT or NTLMv2 Response to the challenge (HEX encoded)"
		},
		{
			.longName   = "password",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &opt_password,
			.val        = OPT_PASSWORD,
			.descrip    = "User's plaintext password"
		},
		{
			.longName   = "request-lm-key",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &request_lm_key,
			.val        = OPT_LM_KEY,
			.descrip    = "Retrieve LM session key"
		},
		{
			.longName   = "request-nt-key",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &request_user_session_key,
			.val        = OPT_USER_SESSION_KEY,
			.descrip    = "Retrieve User (NT) session key"
		},
		{
			.longName   = "use-cached-creds",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &use_cached_creds,
			.val        = OPT_USE_CACHED_CREDS,
			.descrip    = "Use cached credentials if no password is given"
		},
		{
			.longName   = "allow-mschapv2",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &opt_allow_mschapv2,
			.val        = OPT_ALLOW_MSCHAPV2,
			.descrip    = "Explicitly allow MSCHAPv2",
		},
		{
			.longName   = "offline-logon",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &offline_logon,
			.val        = OPT_OFFLINE_LOGON,
			.descrip    = "Use cached passwords when DC is offline"
		},
		{
			.longName   = "diagnostics",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &diagnostics,
			.val        = OPT_DIAGNOSTICS,
			.descrip    = "Perform diagnostics on the authentication chain"
		},
		{
			.longName   = "require-membership-of",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &require_membership_of,
			.val        = OPT_REQUIRE_MEMBERSHIP,
			.descrip    = "Require that a user be a member of this group (either name or SID) for authentication to succeed",
		},
		{
			.longName   = "pam-winbind-conf",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &opt_pam_winbind_conf,
			.val        = OPT_PAM_WINBIND_CONF,
			.descrip    = "Require that request must set WBFLAG_PAM_CONTACT_TRUSTDOM when krb5 auth is required",
		},
		{
			.longName   = "target-service",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &opt_target_service,
			.val        = OPT_TARGET_SERVICE,
			.descrip    = "Target service (eg http)",
		},
		{
			.longName   = "target-hostname",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &opt_target_hostname,
			.val        = OPT_TARGET_HOSTNAME,
			.descrip    = "Target hostname",
		},
		POPT_COMMON_CONFIGFILE
		POPT_COMMON_VERSION
		POPT_COMMON_OPTION
		POPT_TABLEEND
	};

	/* Samba client initialisation */
	smb_init_locale();

	setup_logging("ntlm_auth", DEBUG_STDERR);
	fault_setup();

	/* Parse options */

	pc = poptGetContext("ntlm_auth", argc, argv, long_options, 0);

	/* Parse command line options */

	if (argc == 1) {
		poptPrintHelp(pc, stderr, 0);
		poptFreeContext(pc);
		return 1;
	}

	while((opt = poptGetNextOpt(pc)) != -1) {
		/* Get generic config options like --configfile */
	}

	poptFreeContext(pc);

	if (!lp_load_global(get_dyn_CONFIGFILE())) {
		d_fprintf(stderr, "ntlm_auth: error opening config file %s. Error was %s\n",
			get_dyn_CONFIGFILE(), strerror(errno));
		exit(1);
	}

	pc = poptGetContext(NULL, argc, (const char **)argv, long_options, 
			    POPT_CONTEXT_KEEP_FIRST);

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_CHALLENGE:
			opt_challenge = strhex_to_data_blob(NULL, hex_challenge);
			if (opt_challenge.length != 8) {
				fprintf(stderr, "hex decode of %s failed! "
					"(only got %d bytes)\n",
					hex_challenge,
					(int)opt_challenge.length);
				exit(1);
			}
			break;
		case OPT_LM:
			opt_lm_response = strhex_to_data_blob(NULL, hex_lm_response);
			if (opt_lm_response.length != 24) {
				fprintf(stderr, "hex decode of %s failed! "
					"(only got %d bytes)\n",
					hex_lm_response,
					(int)opt_lm_response.length);
				exit(1);
			}
			break;

		case OPT_NT:
			opt_nt_response = strhex_to_data_blob(NULL, hex_nt_response);
			if (opt_nt_response.length < 24) {
				fprintf(stderr, "hex decode of %s failed! "
					"(only got %d bytes)\n",
					hex_nt_response,
					(int)opt_nt_response.length);
				exit(1);
			}
			break;

                case OPT_REQUIRE_MEMBERSHIP:
			if (strncasecmp_m("S-", require_membership_of, 2) == 0) {
				require_membership_of_sid = require_membership_of;
			}
			break;
		}
	}

	if (opt_username) {
		char *domain = SMB_STRDUP(opt_username);
		char *p = strchr_m(domain, *lp_winbind_separator());
		if (p) {
			opt_username = p+1;
			*p = '\0';
			if (opt_domain && !strequal(opt_domain, domain)) {
				fprintf(stderr, "Domain specified in username (%s) "
					"doesn't match specified domain (%s)!\n\n",
					domain, opt_domain);
				poptPrintHelp(pc, stderr, 0);
				exit(1);
			}
			opt_domain = domain;
		} else {
			SAFE_FREE(domain);
		}
	}

	/* Note: if opt_domain is "" then send no domain */
	if (opt_domain == NULL) {
		opt_domain = get_winbind_domain();
	}

	if (opt_workstation == NULL) {
		opt_workstation = "";
	}

	lp_ctx = loadparm_init_s3(NULL, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		fprintf(stderr, "loadparm_init_s3() failed!\n");
		exit(1);
	}

	if (helper_protocol) {
		int i;
		for (i=0; i<NUM_HELPER_MODES; i++) {
			if (strcmp(helper_protocol, stdio_helper_protocols[i].name) == 0) {
				squid_stream(stdio_helper_protocols[i].mode, lp_ctx, stdio_helper_protocols[i].fn);
				exit(0);
			}
		}
		fprintf(stderr, "unknown helper protocol [%s]\n\n"
			"Valid helper protools:\n\n", helper_protocol);

		for (i=0; i<NUM_HELPER_MODES; i++) {
			fprintf(stderr, "%s\n",
				stdio_helper_protocols[i].name);
		}

		exit(1);
	}

	if (!opt_username || !*opt_username) {
		fprintf(stderr, "username must be specified!\n\n");
		poptPrintHelp(pc, stderr, 0);
		exit(1);
	}

	if (opt_challenge.length) {
		if (!check_auth_crap()) {
			exit(1);
		}
		exit(0);
	}

	if (!opt_password) {
		char pwd[256] = {0};
		int rc;

		rc = samba_getpass("Password: ", pwd, sizeof(pwd), false, false);
		if (rc == 0) {
			opt_password = SMB_STRDUP(pwd);
		}
	}

	if (diagnostics) {
		if (!diagnose_ntlm_auth()) {
			poptFreeContext(pc);
			return 1;
		}
	} else {
		fstring user;

		fstr_sprintf(user, "%s%c%s", opt_domain, winbind_separator(), opt_username);
		if (!check_plaintext_auth(user, opt_password, True)) {
			poptFreeContext(pc);
			return 1;
		}
	}

	/* Exit code */

	poptFreeContext(pc);
	TALLOC_FREE(frame);
	return 0;
}
