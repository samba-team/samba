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
#include "utils/ntlm_auth.h"
#include "../libcli/auth/libcli_auth.h"
#include "../libcli/auth/spnego.h"
#include "auth/ntlmssp/ntlmssp.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "auth/credentials/credentials.h"
#include "librpc/crypto/gse.h"
#include "smb_krb5.h"
#include "lib/util/tiniparser.h"
#include "../lib/crypto/arcfour.h"
#include "libads/kerberos_proto.h"
#include "nsswitch/winbind_client.h"
#include "librpc/gen_ndr/krb5pac.h"
#include "../lib/util/asn1.h"
#include "auth/common_auth.h"
#include "source3/include/auth.h"
#include "source3/auth/proto.h"
#include "nsswitch/libwbclient/wbclient.h"
#include "lib/param/loadparm.h"

#if HAVE_KRB5
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
		x_fprintf(x_stdout, "BH Query invalid\n");
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
			x_fprintf(x_stdout, "BH Out of memory\n");
			data_blob_free(&in);
			return;
		}

		x_fprintf(x_stdout, "OK\n");
		data_blob_free(&in);
		return;
	}
	DEBUG(1, ("Asked for (and expected) a password\n"));
	x_fprintf(x_stdout, "BH Expected a password\n");
	data_blob_free(&in);
}

/**
 * Callback for password credentials.  This is not async, and when
 * GENSEC and the credentials code is made async, it will look rather
 * different.
 */

static const char *get_password(struct cli_credentials *credentials)
{
	char *password = NULL;

	/* Ask for a password */
	x_fprintf(x_stdout, "PW\n");

	manage_squid_request(NUM_HELPER_MODES /* bogus */, NULL, NULL, manage_gensec_get_pw_request, (void **)&password);
	talloc_steal(credentials, password);
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
}

static char winbind_separator(void)
{
	struct winbindd_response response;
	static bool got_sep;
	static char sep;

	if (got_sep)
		return sep;

	ZERO_STRUCT(response);

	/* Send off request */

	if (winbindd_request_response(NULL, WINBINDD_INFO, NULL, &response) !=
	    NSS_STATUS_SUCCESS) {
		d_printf("could not obtain winbind separator!\n");
		return *lp_winbind_separator();
	}

	sep = response.data.info.winbind_separator;
	got_sep = True;

	if (!sep) {
		d_printf("winbind separator was NULL!\n");
		return *lp_winbind_separator();
	}

	return sep;
}

const char *get_winbind_domain(void)
{
	struct winbindd_response response;

	static fstring winbind_domain;
	if (*winbind_domain) {
		return winbind_domain;
	}

	ZERO_STRUCT(response);

	/* Send off request */

	if (winbindd_request_response(NULL, WINBINDD_DOMAIN_NAME, NULL, &response) !=
	    NSS_STATUS_SUCCESS) {
		DEBUG(1, ("could not obtain winbind domain name!\n"));
		return lp_workgroup();
	}

	fstrcpy(winbind_domain, response.data.domain_name);

	return winbind_domain;

}

const char *get_winbind_netbios_name(void)
{
	struct winbindd_response response;

	static fstring winbind_netbios_name;

	if (*winbind_netbios_name) {
		return winbind_netbios_name;
	}

	ZERO_STRUCT(response);

	/* Send off request */

	if (winbindd_request_response(NULL, WINBINDD_NETBIOS_NAME, NULL, &response) !=
	    NSS_STATUS_SUCCESS) {
		DEBUG(1, ("could not obtain winbind netbios name!\n"));
		return lp_netbios_name();
	}

	fstrcpy(winbind_netbios_name, response.data.netbios_name);

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
	struct winbindd_request request;
	struct winbindd_response response;

	if (!require_membership_of) {
		return True;
	}

	if (require_membership_of_sid) {
		return True;
	}

	/* Otherwise, ask winbindd for the name->sid request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	if (!parse_ntlm_auth_domain_user(require_membership_of, 
					 request.data.name.dom_name, 
					 request.data.name.name)) {
		DEBUG(0, ("Could not parse %s into separate domain/name parts!\n",
			  require_membership_of));
		return False;
	}

	if (winbindd_request_response(NULL, WINBINDD_LOOKUPNAME, &request, &response) !=
	    NSS_STATUS_SUCCESS) {
		DEBUG(0, ("Winbindd lookupname failed to resolve %s into a SID!\n", 
			  require_membership_of));
		return False;
	}

	require_membership_of_sid = SMB_STRDUP(response.data.sid.sid);

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

	result = winbindd_request_response(NULL, WINBINDD_PAM_AUTH, &request, &response);

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

NTSTATUS contact_winbind_auth_crap(const char *username,
				   const char *domain,
				   const char *workstation,
				   const DATA_BLOB *challenge,
				   const DATA_BLOB *lm_response,
				   const DATA_BLOB *nt_response,
				   uint32 flags,
				   uint32 extra_logon_parameters,
				   uint8 lm_key[8],
				   uint8 user_session_key[16],
				   char **error_string,
				   char **unix_name)
{
	NTSTATUS nt_status;
        NSS_STATUS result;
	struct winbindd_request request;
	struct winbindd_response response;

	if (!get_require_membership_sid()) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	request.flags = flags;

	request.data.auth_crap.logon_parameters = extra_logon_parameters
		| MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT | MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT;

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

	result = winbindd_request_response(NULL, WINBINDD_PAM_AUTH_CRAP, &request, &response);
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
	char *unix_username = (char *)server_returned_info;
	struct auth_session_info *session_info = talloc_zero(mem_ctx, struct auth_session_info);
	if (!session_info) {
		return NT_STATUS_NO_MEMORY;
	}

	session_info->unix_info = talloc_zero(session_info, struct auth_user_info_unix);
	if (!session_info->unix_info) {
		TALLOC_FREE(session_info);
		return NT_STATUS_NO_MEMORY;
	}
	session_info->unix_info->unix_name = talloc_steal(session_info->unix_info, unix_username);

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

static NTSTATUS winbind_pw_check(struct auth4_context *auth4_context, 
				 TALLOC_CTX *mem_ctx,
				 const struct auth_usersupplied_info *user_info, 
				 void **server_returned_info,
				 DATA_BLOB *session_key, DATA_BLOB *lm_session_key)
{
	static const char zeros[16] = { 0, };
	NTSTATUS nt_status;
	char *error_string = NULL;
	uint8 lm_key[8]; 
	uint8 user_sess_key[16]; 
	char *unix_name = NULL;

	nt_status = contact_winbind_auth_crap(user_info->client.account_name, user_info->client.domain_name, 
					      user_info->workstation_name, 
					      &auth4_context->challenge.data,
					      &user_info->password.response.lanman,
					      &user_info->password.response.nt,
					      WBFLAG_PAM_LMKEY | WBFLAG_PAM_USER_SESSION_KEY | WBFLAG_PAM_UNIX_NAME,
					      0,
					      lm_key, user_sess_key, 
					      &error_string, &unix_name);

	if (NT_STATUS_IS_OK(nt_status)) {
		if (memcmp(lm_key, zeros, 8) != 0) {
			*lm_session_key = data_blob_talloc(mem_ctx, NULL, 16);
			memcpy(lm_session_key->data, lm_key, 8);
			memset(lm_session_key->data+8, '\0', 8);
		}

		if (memcmp(user_sess_key, zeros, 16) != 0) {
			*session_key = data_blob_talloc(mem_ctx, user_sess_key, 16);
		}
		*server_returned_info = talloc_strdup(mem_ctx,
						      unix_name);
	} else {
		DEBUG(NT_STATUS_EQUAL(nt_status, NT_STATUS_ACCESS_DENIED) ? 0 : 3, 
		      ("Login for user [%s]\\[%s]@[%s] failed due to [%s]\n", 
		       user_info->client.domain_name, user_info->client.account_name,
		       user_info->workstation_name, 
		       error_string ? error_string : "unknown error (NULL)"));
	}

	SAFE_FREE(error_string);
	SAFE_FREE(unix_name);
	return nt_status;
}

static NTSTATUS local_pw_check(struct auth4_context *auth4_context, 
				TALLOC_CTX *mem_ctx,
				const struct auth_usersupplied_info *user_info, 
				void **server_returned_info,
				DATA_BLOB *session_key, DATA_BLOB *lm_session_key)
{
	NTSTATUS nt_status;
	struct samr_Password lm_pw, nt_pw;

	nt_lm_owf_gen (opt_password, nt_pw.hash, lm_pw.hash);

	nt_status = ntlm_password_check(mem_ctx,
					true, true, 0,
					&auth4_context->challenge.data,
					&user_info->password.response.lanman,
					&user_info->password.response.nt,
					user_info->client.account_name,
					user_info->client.account_name,
					user_info->client.domain_name, 
					&lm_pw, &nt_pw, session_key, lm_session_key);

	if (NT_STATUS_IS_OK(nt_status)) {
		*server_returned_info = talloc_asprintf(mem_ctx,
							"%s%c%s", user_info->client.domain_name,
							*lp_winbind_separator(), 
							user_info->client.account_name);
	} else {
		DEBUG(3, ("Login for user [%s]\\[%s]@[%s] failed due to [%s]\n", 
			  user_info->client.domain_name, user_info->client.account_name,
			  user_info->workstation_name, 
			  nt_errstr(nt_status)));
	}
	return nt_status;
}

static NTSTATUS ntlm_auth_start_ntlmssp_client(struct ntlmssp_state **client_ntlmssp_state)
{
	NTSTATUS status;
	if ( (opt_username == NULL) || (opt_domain == NULL) ) {
		status = NT_STATUS_UNSUCCESSFUL;
		DEBUG(1, ("Need username and domain for NTLMSSP\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = ntlmssp_client_start(NULL,
				      lp_netbios_name(),
				      lp_workgroup(),
				      lp_client_ntlmv2_auth(),
				      client_ntlmssp_state);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not start NTLMSSP client: %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(*client_ntlmssp_state);
		return status;
	}

	status = ntlmssp_set_username(*client_ntlmssp_state, opt_username);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not set username: %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(*client_ntlmssp_state);
		return status;
	}

	status = ntlmssp_set_domain(*client_ntlmssp_state, opt_domain);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not set domain: %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(*client_ntlmssp_state);
		return status;
	}

	if (opt_password) {
		status = ntlmssp_set_password(*client_ntlmssp_state, opt_password);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Could not set password: %s\n",
				  nt_errstr(status)));
			TALLOC_FREE(*client_ntlmssp_state);
			return status;
		}
	}

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
		auth4_context->check_ntlm_password = local_pw_check;
	} else {
		auth4_context->check_ntlm_password = winbind_pw_check;
	}
	auth4_context->private_data = NULL;
	return auth4_context;
}

static NTSTATUS ntlm_auth_start_ntlmssp_server(TALLOC_CTX *mem_ctx,
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
		DEBUG(0, ("auth_generic_prepare: Failed to init server credentials\n"));
		return NT_STATUS_NO_MEMORY;
	}
	
	cli_credentials_set_conf(server_credentials, lp_ctx);
	
	if (lp_security() == SEC_ADS || USE_KERBEROS_KEYTAB) {
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
	
	gensec_want_feature(gensec_security, GENSEC_FEATURE_SIGN);
	gensec_want_feature(gensec_security, GENSEC_FEATURE_SEAL);

	talloc_unlink(tmp_ctx, lp_ctx);
	talloc_unlink(tmp_ctx, server_credentials);
	talloc_unlink(tmp_ctx, gensec_settings);
	talloc_unlink(tmp_ctx, auth4_context);

	nt_status = gensec_start_mech_by_oid(gensec_security, GENSEC_OID_NTLMSSP);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}
	
	*gensec_security_out = talloc_steal(mem_ctx, gensec_security);
	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}

/*******************************************************************
 Used by firefox to drive NTLM auth to IIS servers.
*******************************************************************/

static NTSTATUS do_ccache_ntlm_auth(DATA_BLOB initial_msg, DATA_BLOB challenge_msg,
				DATA_BLOB *reply)
{
	struct winbindd_request wb_request;
	struct winbindd_response wb_response;
	int ctrl = 0;
	NSS_STATUS result;

	/* get winbindd to do the ntlmssp step on our behalf */
	ZERO_STRUCT(wb_request);
	ZERO_STRUCT(wb_response);

	/*
	 * This is tricky here. If we set krb5_auth in pam_winbind.conf
	 * creds for users in trusted domain will be stored the winbindd
	 * child of the trusted domain. If we ask the primary domain for
	 * ntlm_ccache_auth, it will fail. So, we have to ask the trusted
	 * domain's child for ccache_ntlm_auth. that is to say, we have to 
	 * set WBFLAG_PAM_CONTACT_TRUSTDOM in request.flags.
	 */
	ctrl = get_pam_winbind_config();

	if (ctrl & WINBIND_KRB5_AUTH) {
		wb_request.flags |= WBFLAG_PAM_CONTACT_TRUSTDOM;
	}

	fstr_sprintf(wb_request.data.ccache_ntlm_auth.user,
		"%s%c%s", opt_domain, winbind_separator(), opt_username);
	wb_request.data.ccache_ntlm_auth.uid = geteuid();
	wb_request.data.ccache_ntlm_auth.initial_blob_len = initial_msg.length;
	wb_request.data.ccache_ntlm_auth.challenge_blob_len = challenge_msg.length;
	wb_request.extra_len = initial_msg.length + challenge_msg.length;

	if (wb_request.extra_len > 0) {
		wb_request.extra_data.data = SMB_MALLOC_ARRAY(char, wb_request.extra_len);
		if (wb_request.extra_data.data == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		memcpy(wb_request.extra_data.data, initial_msg.data, initial_msg.length);
		memcpy(wb_request.extra_data.data + initial_msg.length,
			challenge_msg.data, challenge_msg.length);
	}

	result = winbindd_request_response(NULL, WINBINDD_CCACHE_NTLMAUTH, &wb_request, &wb_response);
	SAFE_FREE(wb_request.extra_data.data);

	if (result != NSS_STATUS_SUCCESS) {
		winbindd_free_response(&wb_response);
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (reply) {
		*reply = data_blob(wb_response.extra_data.data,
				wb_response.data.ccache_ntlm_auth.auth_blob_len);
		if (wb_response.data.ccache_ntlm_auth.auth_blob_len > 0 &&
				reply->data == NULL) {
			winbindd_free_response(&wb_response);
			return NT_STATUS_NO_MEMORY;
		}
	}

	winbindd_free_response(&wb_response);
	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

static void manage_client_ntlmssp_request(enum stdio_helper_mode stdio_helper_mode,
				   struct loadparm_context *lp_ctx,
				   struct ntlm_auth_state *state,
						char *buf, int length, void **private2)
{
	DATA_BLOB request, reply;
	NTSTATUS nt_status;

	if (!opt_username || !*opt_username) {
		x_fprintf(x_stderr, "username must be specified!\n\n");
		exit(1);
	}

	if (strlen(buf) < 2) {
		DEBUG(1, ("NTLMSSP query [%s] invalid\n", buf));
		x_fprintf(x_stdout, "BH NTLMSSP query invalid\n");
		return;
	}

	if (strlen(buf) > 3) {
		if(strncmp(buf, "SF ", 3) == 0) {
			DEBUG(10, ("Looking for flags to negotiate\n"));
			talloc_free(state->want_feature_list);
			state->want_feature_list = talloc_strdup(state->mem_ctx,
					buf+3);
			x_fprintf(x_stdout, "OK\n");
			return;
		}
		request = base64_decode_data_blob(buf + 3);
	} else {
		request = data_blob_null;
	}

	if (strncmp(buf, "PW ", 3) == 0) {
		/* We asked for a password and obviously got it :-) */

		opt_password = SMB_STRNDUP((const char *)request.data,
				request.length);

		if (opt_password == NULL) {
			DEBUG(1, ("Out of memory\n"));
			x_fprintf(x_stdout, "BH Out of memory\n");
			data_blob_free(&request);
			return;
		}

		x_fprintf(x_stdout, "OK\n");
		data_blob_free(&request);
		return;
	}

	if (!state->ntlmssp_state && use_cached_creds) {
		/* check whether cached credentials are usable. */
		DATA_BLOB empty_blob = data_blob_null;

		nt_status = do_ccache_ntlm_auth(empty_blob, empty_blob, NULL);
		if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			/* failed to use cached creds */
			use_cached_creds = False;
		}
	}

	if (opt_password == NULL && !use_cached_creds) {
		/* Request a password from the calling process.  After
		   sending it, the calling process should retry asking for the
		   negotiate. */

		DEBUG(10, ("Requesting password\n"));
		x_fprintf(x_stdout, "PW\n");
		return;
	}

	if (strncmp(buf, "YR", 2) == 0) {
		TALLOC_FREE(state->ntlmssp_state);
		state->cli_state = CLIENT_INITIAL;
	} else if (strncmp(buf, "TT", 2) == 0) {
		/* No special preprocessing required */
	} else if (strncmp(buf, "GF", 2) == 0) {
		DEBUG(10, ("Requested negotiated NTLMSSP flags\n"));

		if(state->cli_state == CLIENT_FINISHED) {
			x_fprintf(x_stdout, "GF 0x%08x\n", state->neg_flags);
		}
		else {
			x_fprintf(x_stdout, "BH\n");
		}

		data_blob_free(&request);
		return;
	} else if (strncmp(buf, "GK", 2) == 0 ) {
		DEBUG(10, ("Requested session key\n"));

		if(state->cli_state == CLIENT_FINISHED) {
			char *key64 = base64_encode_data_blob(state->mem_ctx,
					state->session_key);
			x_fprintf(x_stdout, "GK %s\n", key64?key64:"<NULL>");
			TALLOC_FREE(key64);
		}
		else {
			x_fprintf(x_stdout, "BH\n");
		}

		data_blob_free(&request);
		return;
	} else {
		DEBUG(1, ("NTLMSSP query [%s] invalid\n", buf));
		x_fprintf(x_stdout, "BH NTLMSSP query invalid\n");
		return;
	}

	if (!state->ntlmssp_state) {
		nt_status = ntlm_auth_start_ntlmssp_client(
				&state->ntlmssp_state);
		if (!NT_STATUS_IS_OK(nt_status)) {
			x_fprintf(x_stdout, "BH %s\n", nt_errstr(nt_status));
			return;
		}
		ntlmssp_want_feature_list(state->ntlmssp_state,
				state->want_feature_list);
		state->initial_message = data_blob_null;
	}

	DEBUG(10, ("got NTLMSSP packet:\n"));
	dump_data(10, request.data, request.length);

	if (use_cached_creds && !opt_password &&
			(state->cli_state == CLIENT_RESPONSE)) {
		nt_status = do_ccache_ntlm_auth(state->initial_message, request,
				&reply);
	} else {
		nt_status = ntlmssp_update(state->ntlmssp_state, request,
				&reply);
	}

	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		char *reply_base64 = base64_encode_data_blob(state->mem_ctx,
				reply);
		if (state->cli_state == CLIENT_INITIAL) {
			x_fprintf(x_stdout, "YR %s\n", reply_base64);
			state->initial_message = reply;
			state->cli_state = CLIENT_RESPONSE;
		} else {
			x_fprintf(x_stdout, "KK %s\n", reply_base64);
			data_blob_free(&reply);
		}
		TALLOC_FREE(reply_base64);
		DEBUG(10, ("NTLMSSP challenge\n"));
	} else if (NT_STATUS_IS_OK(nt_status)) {
		char *reply_base64 = base64_encode_data_blob(talloc_tos(),
				reply);
		x_fprintf(x_stdout, "AF %s\n", reply_base64);
		TALLOC_FREE(reply_base64);

		if(state->have_session_key)
			data_blob_free(&state->session_key);

		state->session_key = data_blob(
				state->ntlmssp_state->session_key.data,
				state->ntlmssp_state->session_key.length);
		state->neg_flags = state->ntlmssp_state->neg_flags;
		state->have_session_key = true;

		DEBUG(10, ("NTLMSSP OK!\n"));
		state->cli_state = CLIENT_FINISHED;
		TALLOC_FREE(state->ntlmssp_state);
	} else {
		x_fprintf(x_stdout, "BH %s\n", nt_errstr(nt_status));
		DEBUG(0, ("NTLMSSP BH: %s\n", nt_errstr(nt_status)));
		state->cli_state = CLIENT_ERROR;
		TALLOC_FREE(state->ntlmssp_state);
	}

	data_blob_free(&request);
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
		x_fprintf(x_stdout, "ERR\n");
		return;
	}
	*pass='\0';
	pass++;

	if (state->helper_mode == SQUID_2_5_BASIC) {
		rfc1738_unescape(user);
		rfc1738_unescape(pass);
	}

	if (check_plaintext_auth(user, pass, False)) {
		x_fprintf(x_stdout, "OK\n");
	} else {
		x_fprintf(x_stdout, "ERR\n");
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

	if (*private1) {
		state = (struct gensec_ntlm_state *)*private1;
	} else {
		state = talloc_zero(NULL, struct gensec_ntlm_state);
		if (!state) {
			x_fprintf(x_stdout, "BH No Memory\n");
			exit(1);
		}
		*private1 = state;
		if (opt_password) {
			state->set_password = opt_password;
		}
	}

	if (strlen(buf) < 2) {
		DEBUG(1, ("query [%s] invalid", buf));
		x_fprintf(x_stdout, "BH Query invalid\n");
		return;
	}

	if (strlen(buf) > 3) {
		if(strncmp(buf, "SF ", 3) == 0) {
			DEBUG(10, ("Setting flags to negotiate\n"));
			talloc_free(want_feature_list);
			want_feature_list = talloc_strndup(state, buf+3, strlen(buf)-3);
			x_fprintf(x_stdout, "OK\n");
			return;
		}
		in = base64_decode_data_blob(buf + 3);
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
		x_fprintf(x_stdout, "BH Command expected\n");
		data_blob_free(&in);
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
		x_fprintf(x_stdout, "BH SPNEGO request invalid prefix\n");
		data_blob_free(&in);
		return;
	}

	mem_ctx = talloc_named(NULL, 0, "manage_gensec_request internal mem_ctx");

	/* setup gensec */
	if (!(state->gensec_state)) {
		switch (stdio_helper_mode) {
		case GSS_SPNEGO_CLIENT:
		case NTLMSSP_CLIENT_1:
			/* setup the client side */

			nt_status = gensec_client_start(NULL, &state->gensec_state,
							lpcfg_gensec_settings(NULL, lp_ctx));
			if (!NT_STATUS_IS_OK(nt_status)) {
				x_fprintf(x_stdout, "BH GENSEC mech failed to start: %s\n", nt_errstr(nt_status));
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
			if (state->set_password) {
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
			nt_status = ntlm_auth_start_ntlmssp_server(state, lp_ctx,
								   &state->gensec_state);
			if (!NT_STATUS_IS_OK(nt_status)) {
				x_fprintf(x_stdout, "BH GENSEC mech failed to start: %s\n", nt_errstr(nt_status));
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
			/* fall through */
		case SQUID_2_5_NTLMSSP:
			nt_status = gensec_start_mech_by_oid(state->gensec_state, GENSEC_OID_NTLMSSP);
			break;
		default:
			talloc_free(mem_ctx);
			abort();
		}

		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(1, ("GENSEC mech failed to start: %s\n", nt_errstr(nt_status)));
			x_fprintf(x_stdout, "BH GENSEC mech failed to start\n");
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
		x_fprintf(x_stdout, "OK\n");
		data_blob_free(&in);
		talloc_free(mem_ctx);
		return;
	}

	if (strncmp(buf, "GK", 2) == 0) {
		char *base64_key;
		DEBUG(10, ("Requested session key\n"));
		nt_status = gensec_session_key(state->gensec_state, mem_ctx, &session_key);
		if(!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(1, ("gensec_session_key failed: %s\n", nt_errstr(nt_status)));
			x_fprintf(x_stdout, "BH No session key\n");
			talloc_free(mem_ctx);
			return;
		} else {
			base64_key = base64_encode_data_blob(state, session_key);
			x_fprintf(x_stdout, "GK %s\n", base64_key);
			talloc_free(base64_key);
		}
		talloc_free(mem_ctx);
		return;
	}

	if (stdio_helper_mode == SQUID_2_5_NTLMSSP && strncmp(buf, "GF", 2) == 0) {
		uint32_t neg_flags;

		neg_flags = gensec_ntlmssp_neg_flags(state->gensec_state);

		DEBUG(10, ("Requested negotiated feature flags\n"));
		x_fprintf(x_stdout, "GF 0x%08x\n", neg_flags);
		return;
	}

	nt_status = gensec_update(state->gensec_state, mem_ctx, in, &out);

	/* don't leak 'bad password'/'no such user' info to the network client */
	nt_status = nt_status_squash(nt_status);

	if (out.length) {
		out_base64 = base64_encode_data_blob(mem_ctx, out);
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
			reply_code = "BH Failed to retrive session info";
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

static struct ntlmssp_state *client_ntlmssp_state = NULL;

static bool manage_client_ntlmssp_init(struct spnego_data spnego)
{
	NTSTATUS status;
	DATA_BLOB null_blob = data_blob_null;
	DATA_BLOB to_server;
	char *to_server_base64;
	const char *my_mechs[] = {OID_NTLMSSP, NULL};
	TALLOC_CTX *ctx = talloc_tos();

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
	spnego.negTokenInit.reqFlags = data_blob_null;
	spnego.negTokenInit.reqFlagsPadding = 0;
	spnego.negTokenInit.mechListMIC = null_blob;

	status = ntlmssp_update(client_ntlmssp_state, null_blob,
				       &spnego.negTokenInit.mechToken);

	if ( !(NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) ||
			NT_STATUS_IS_OK(status)) ) {
		DEBUG(1, ("Expected OK or MORE_PROCESSING_REQUIRED, got: %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(client_ntlmssp_state);
		return False;
	}

	spnego_write_data(ctx, &to_server, &spnego);
	data_blob_free(&spnego.negTokenInit.mechToken);

	to_server_base64 = base64_encode_data_blob(talloc_tos(), to_server);
	data_blob_free(&to_server);
	x_fprintf(x_stdout, "KK %s\n", to_server_base64);
	TALLOC_FREE(to_server_base64);
	return True;
}

static void manage_client_ntlmssp_targ(struct spnego_data spnego)
{
	NTSTATUS status;
	DATA_BLOB null_blob = data_blob_null;
	DATA_BLOB request;
	DATA_BLOB to_server;
	char *to_server_base64;
	TALLOC_CTX *ctx = talloc_tos();

	DEBUG(10, ("Got spnego negTokenTarg with NTLMSSP\n"));

	if (client_ntlmssp_state == NULL) {
		DEBUG(1, ("Got NTLMSSP tArg without a client state\n"));
		x_fprintf(x_stdout, "BH Got NTLMSSP tArg without a client state\n");
		return;
	}

	if (spnego.negTokenTarg.negResult == SPNEGO_REJECT) {
		x_fprintf(x_stdout, "NA\n");
		TALLOC_FREE(client_ntlmssp_state);
		return;
	}

	if (spnego.negTokenTarg.negResult == SPNEGO_ACCEPT_COMPLETED) {
		x_fprintf(x_stdout, "AF\n");
		TALLOC_FREE(client_ntlmssp_state);
		return;
	}

	status = ntlmssp_update(client_ntlmssp_state,
				       spnego.negTokenTarg.responseToken,
				       &request);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) && !NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Expected MORE_PROCESSING_REQUIRED or OK from "
			  "ntlmssp_client_update, got: %s\n",
			  nt_errstr(status)));
		x_fprintf(x_stdout, "BH Expected MORE_PROCESSING_REQUIRED from "
				    "ntlmssp_client_update\n");
		data_blob_free(&request);
		TALLOC_FREE(client_ntlmssp_state);
		return;
	}

	spnego.type = SPNEGO_NEG_TOKEN_TARG;
	spnego.negTokenTarg.negResult = SPNEGO_ACCEPT_INCOMPLETE;
	spnego.negTokenTarg.supportedMech = (const char *)OID_NTLMSSP;
	spnego.negTokenTarg.responseToken = request;
	spnego.negTokenTarg.mechListMIC = null_blob;

	spnego_write_data(ctx, &to_server, &spnego);
	data_blob_free(&request);

	to_server_base64 = base64_encode_data_blob(talloc_tos(), to_server);
	data_blob_free(&to_server);
	x_fprintf(x_stdout, "KK %s\n", to_server_base64);
	TALLOC_FREE(to_server_base64);
	return;
}

#ifdef HAVE_KRB5

static bool manage_client_krb5_init(struct spnego_data spnego)
{
	char *principal;
	DATA_BLOB tkt, tkt_wrapped, to_server;
	DATA_BLOB session_key_krb5 = data_blob_null;
	struct spnego_data reply;
	char *reply_base64;
	int retval;

	const char *my_mechs[] = {OID_KERBEROS5_OLD, NULL};
	ssize_t len;
	TALLOC_CTX *ctx = talloc_tos();

	principal = spnego.negTokenInit.targetPrincipal;

	/* We may not be allowed to use the server-supplied SPNEGO principal, or it may not have been supplied to us
	 */
	if (!lp_client_use_spnego_principal() || strequal(principal, ADS_IGNORE_PRINCIPAL)) {
		principal = NULL;
	}
	
	if (principal == NULL &&
	    opt_target_service && opt_target_hostname && !is_ipaddress(opt_target_hostname)) {
		DEBUG(3,("manage_client_krb5_init: using target "
			 "hostname not SPNEGO principal\n"));

		principal = kerberos_get_principal_from_service_hostname(talloc_tos(),
									 opt_target_service,
									 opt_target_hostname,
									 lp_realm());

		if (!principal) {
			return false;
		}
		
		DEBUG(3,("manage_client_krb5_init: guessed "
			 "server principal=%s\n",
			 principal ? principal : "<null>"));
	}
	
	if (principal == NULL) {
		DEBUG(3,("manage_client_krb5_init: could not guess server principal\n"));
		return false;
	}

	retval = cli_krb5_get_ticket(ctx, principal, 0,
					  &tkt, &session_key_krb5,
					  0, NULL, NULL, NULL);
	if (retval) {
		char *user = NULL;

		/* Let's try to first get the TGT, for that we need a
                   password. */

		if (opt_password == NULL) {
			DEBUG(10, ("Requesting password\n"));
			x_fprintf(x_stdout, "PW\n");
			return True;
		}

		user = talloc_asprintf(talloc_tos(), "%s@%s", opt_username, opt_domain);
		if (!user) {
			return false;
		}

		if ((retval = kerberos_kinit_password(user, opt_password, 0, NULL))) {
			DEBUG(10, ("Requesting TGT failed: %s\n", error_message(retval)));
			return False;
		}

		retval = cli_krb5_get_ticket(ctx, principal, 0,
						  &tkt, &session_key_krb5,
						  0, NULL, NULL, NULL);
		if (retval) {
			DEBUG(10, ("Kinit suceeded, but getting a ticket failed: %s\n", error_message(retval)));
			return False;
		}

	}

	/* wrap that up in a nice GSS-API wrapping */
	tkt_wrapped = spnego_gen_krb5_wrap(ctx, tkt, TOK_ID_KRB_AP_REQ);

	data_blob_free(&session_key_krb5);

	ZERO_STRUCT(reply);

	reply.type = SPNEGO_NEG_TOKEN_INIT;
	reply.negTokenInit.mechTypes = my_mechs;
	reply.negTokenInit.reqFlags = data_blob_null;
	reply.negTokenInit.reqFlagsPadding = 0;
	reply.negTokenInit.mechToken = tkt_wrapped;
	reply.negTokenInit.mechListMIC = data_blob_null;

	len = spnego_write_data(ctx, &to_server, &reply);
	data_blob_free(&tkt);

	if (len == -1) {
		DEBUG(1, ("Could not write SPNEGO data blob\n"));
		return False;
	}

	reply_base64 = base64_encode_data_blob(talloc_tos(), to_server);
	x_fprintf(x_stdout, "KK %s *\n", reply_base64);

	TALLOC_FREE(reply_base64);
	data_blob_free(&to_server);
	DEBUG(10, ("sent GSS-SPNEGO KERBEROS5 negTokenInit\n"));
	return True;
}

static void manage_client_krb5_targ(struct spnego_data spnego)
{
	switch (spnego.negTokenTarg.negResult) {
	case SPNEGO_ACCEPT_INCOMPLETE:
		DEBUG(1, ("Got a Kerberos negTokenTarg with ACCEPT_INCOMPLETE\n"));
		x_fprintf(x_stdout, "BH Got a Kerberos negTokenTarg with "
				    "ACCEPT_INCOMPLETE\n");
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
				   struct loadparm_context *lp_ctx,
				   struct ntlm_auth_state *state,
					     char *buf, int length, void **private2)
{
	DATA_BLOB request;
	struct spnego_data spnego;
	ssize_t len;
	TALLOC_CTX *ctx = talloc_tos();

	if (!opt_username || !*opt_username) {
		x_fprintf(x_stderr, "username must be specified!\n\n");
		exit(1);
	}

	if (strlen(buf) <= 3) {
		DEBUG(1, ("SPNEGO query [%s] too short\n", buf));
		x_fprintf(x_stdout, "BH SPNEGO query too short\n");
		return;
	}

	request = base64_decode_data_blob(buf+3);

	if (strncmp(buf, "PW ", 3) == 0) {

		/* We asked for a password and obviously got it :-) */

		opt_password = SMB_STRNDUP((const char *)request.data, request.length);

		if (opt_password == NULL) {
			DEBUG(1, ("Out of memory\n"));
			x_fprintf(x_stdout, "BH Out of memory\n");
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
		x_fprintf(x_stdout, "BH SPNEGO request invalid\n");
		data_blob_free(&request);
		return;
	}

	/* So we got a server challenge to generate a SPNEGO
           client-to-server request... */

	len = spnego_read_data(ctx, request, &spnego);
	data_blob_free(&request);

	if (len == -1) {
		DEBUG(1, ("Could not read SPNEGO data for [%s]\n", buf));
		x_fprintf(x_stdout, "BH Could not read SPNEGO data\n");
		return;
	}

	if (spnego.type == SPNEGO_NEG_TOKEN_INIT) {

		/* The server offers a list of mechanisms */

		const char *const *mechType = spnego.negTokenInit.mechTypes;

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
		x_fprintf(x_stdout, "BH Server offered no compatible mechanism\n");
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
				x_fprintf(x_stdout, "BH Got a negTokenTarg with"
						    " no mech and an unknown "
						    "negResult\n");
			}

			TALLOC_FREE(client_ntlmssp_state);
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
	x_fprintf(x_stdout, "BH Got an SPNEGO token I could not handle\n");
	return;

 out:
	spnego_free_data(&spnego);
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
			x_fprintf(x_stdout, "Error: No username supplied!\n");
		} else if (plaintext_password) {
			/* handle this request as plaintext */
			if (!full_username) {
				if (asprintf(&full_username, "%s%c%s", domain, winbind_separator(), username) == -1) {
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
			uchar lm_key[8];
			uchar user_session_key[16];
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
				domain = smb_xstrdup(get_winbind_domain());
			}

			if (ntlm_server_1_lm_session_key) 
				flags |= WBFLAG_PAM_LMKEY;

			if (ntlm_server_1_user_session_key) 
				flags |= WBFLAG_PAM_USER_SESSION_KEY;

			if (!NT_STATUS_IS_OK(
				    contact_winbind_auth_crap(username, 
							      domain, 
							      lp_netbios_name(),
							      &challenge, 
							      &lm_response, 
							      &nt_response, 
							      flags, 0,
							      lm_key, 
							      user_session_key,
							      &error_string,
							      NULL))) {

				x_fprintf(x_stdout, "Authenticated: No\n");
				x_fprintf(x_stdout, "Authentication-Error: %s\n.\n", error_string);
			} else {
				static char zeros[16];
				char *hex_lm_key;
				char *hex_user_session_key;

				x_fprintf(x_stdout, "Authenticated: Yes\n");

				if (ntlm_server_1_lm_session_key 
				    && (memcmp(zeros, lm_key, 
					       sizeof(lm_key)) != 0)) {
					hex_lm_key = hex_encode_talloc(NULL,
								(const unsigned char *)lm_key,
								sizeof(lm_key));
					x_fprintf(x_stdout, "LANMAN-Session-Key: %s\n", hex_lm_key);
					TALLOC_FREE(hex_lm_key);
				}

				if (ntlm_server_1_user_session_key 
				    && (memcmp(zeros, user_session_key, 
					       sizeof(user_session_key)) != 0)) {
					hex_user_session_key = hex_encode_talloc(NULL,
									  (const unsigned char *)user_session_key, 
									  sizeof(user_session_key));
					x_fprintf(x_stdout, "User-Session-Key: %s\n", hex_user_session_key);
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
		x_fprintf(x_stdout, ".\n");

		return;
	}

	request = buf;

	/* Indicates a base64 encoded structure */
	parameter = strstr_m(request, ":: ");
	if (!parameter) {
		parameter = strstr_m(request, ": ");

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
		challenge = strhex_to_data_blob(NULL, parameter);
		if (challenge.length != 8) {
			x_fprintf(x_stdout, "Error: hex decode of %s failed! (got %d bytes, expected 8)\n.\n", 
				  parameter,
				  (int)challenge.length);
			challenge = data_blob_null;
		}
	} else if (strequal(request, "NT-Response")) {
		nt_response = strhex_to_data_blob(NULL, parameter);
		if (nt_response.length < 24) {
			x_fprintf(x_stdout, "Error: hex decode of %s failed! (only got %d bytes, needed at least 24)\n.\n", 
				  parameter,
				  (int)nt_response.length);
			nt_response = data_blob_null;
		}
	} else if (strequal(request, "LANMAN-Response")) {
		lm_response = strhex_to_data_blob(NULL, parameter);
		if (lm_response.length != 24) {
			x_fprintf(x_stdout, "Error: hex decode of %s failed! (got %d bytes, expected 24)\n.\n", 
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
		x_fprintf(x_stdout, "Error: Unknown request %s\n.\n", request);
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

			if (lp_client_lanman_auth() &&
			    E_deshash(newpswd, new_lm_hash) &&
			    E_deshash(oldpswd, old_lm_hash)) {
				new_lm_pswd = data_blob(NULL, 516);
				old_lm_hash_enc = data_blob(NULL, 16);
				encode_pw_buffer(new_lm_pswd.data, newpswd,
						 STR_UNICODE);

				arcfour_crypt(new_lm_pswd.data, old_nt_hash, 516);
				E_old_pw_hash(new_nt_hash, old_lm_hash,
					      old_lm_hash_enc.data);
			} else {
				new_lm_pswd.data = NULL;
				new_lm_pswd.length = 0;
				old_lm_hash_enc.data = NULL;
				old_lm_hash_enc.length = 0;
			}

			encode_pw_buffer(new_nt_pswd.data, newpswd,
					 STR_UNICODE);

			arcfour_crypt(new_nt_pswd.data, old_nt_hash, 516);
			E_old_pw_hash(new_nt_hash, old_nt_hash,
				      old_nt_hash_enc.data);
		}

		if (!full_username && !username) {	
			x_fprintf(x_stdout, "Error: No username supplied!\n");
		} else if ((!new_nt_pswd.data || !old_nt_hash_enc.data) &&
			   (!new_lm_pswd.data || old_lm_hash_enc.data) ) {
			x_fprintf(x_stdout, "Error: No NT or LM password "
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
					x_fprintf(x_stdout, "Error: Could not "
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
				x_fprintf(x_stdout, "Password-Change: No\n");
				x_fprintf(x_stdout, "Password-Change-Error: "
					  "%s\n.\n", error_string);
			} else {
				x_fprintf(x_stdout, "Password-Change: Yes\n");
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
		x_fprintf(x_stdout, ".\n");

		return;
	}

	request = buf;

	/* Indicates a base64 encoded structure */
	parameter = strstr_m(request, ":: ");
	if (!parameter) {
		parameter = strstr_m(request, ": ");

		if (!parameter)	{
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

	if (strequal(request, "new-nt-password-blob")) {
		new_nt_pswd = strhex_to_data_blob(NULL, parameter);
		if (new_nt_pswd.length != 516) {
			x_fprintf(x_stdout, "Error: hex decode of %s failed! "
				  "(got %d bytes, expected 516)\n.\n", 
				  parameter,
				  (int)new_nt_pswd.length);
			new_nt_pswd = data_blob_null;
		}
	} else if (strequal(request, "old-nt-hash-blob")) {
		old_nt_hash_enc = strhex_to_data_blob(NULL, parameter);
		if (old_nt_hash_enc.length != 16) {
			x_fprintf(x_stdout, "Error: hex decode of %s failed! "
				  "(got %d bytes, expected 16)\n.\n", 
				  parameter,
				  (int)old_nt_hash_enc.length);
			old_nt_hash_enc = data_blob_null;
		}
	} else if (strequal(request, "new-lm-password-blob")) {
		new_lm_pswd = strhex_to_data_blob(NULL, parameter);
		if (new_lm_pswd.length != 516) {
			x_fprintf(x_stdout, "Error: hex decode of %s failed! "
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
			x_fprintf(x_stdout, "Error: hex decode of %s failed! "
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
		x_fprintf(x_stdout, "Error: Unknown request %s\n.\n", request);
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
		x_fprintf(x_stderr, "ERR\n");
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
			x_fprintf(x_stderr, "ERR\n");
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
		x_fprintf(x_stderr, "ERR\n");
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
	x_setbuf(x_stdout, NULL);
	x_setbuf(x_stderr, NULL);

	mem_ctx = talloc_init("ntlm_auth");
	if (!mem_ctx) {
		DEBUG(0, ("squid_stream: Failed to create talloc context\n"));
		x_fprintf(x_stderr, "ERR\n");
		exit(1);
	}

	state = talloc_zero(mem_ctx, struct ntlm_auth_state);
	if (!state) {
		DEBUG(0, ("squid_stream: Failed to talloc ntlm_auth_state\n"));
		x_fprintf(x_stderr, "ERR\n");
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
	uint32 flags = 0;
	char lm_key[8];
	char user_session_key[16];
	char *hex_lm_key;
	char *hex_user_session_key;
	char *error_string;
	static uint8 zeros[16];

	x_setbuf(x_stdout, NULL);

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
					      &error_string, NULL);

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
		hex_lm_key = hex_encode_talloc(talloc_tos(), (const unsigned char *)lm_key,
					sizeof(lm_key));
		x_fprintf(x_stdout, "LM_KEY: %s\n", hex_lm_key);
		TALLOC_FREE(hex_lm_key);
	}
	if (request_user_session_key 
	    && (memcmp(zeros, user_session_key, 
		       sizeof(user_session_key)) != 0)) {
		hex_user_session_key = hex_encode_talloc(talloc_tos(), (const unsigned char *)user_session_key, 
						  sizeof(user_session_key));
		x_fprintf(x_stdout, "NT_KEY: %s\n", hex_user_session_key);
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
	OPT_PAM_WINBIND_CONF,
	OPT_TARGET_SERVICE,
	OPT_TARGET_HOSTNAME
};

 int main(int argc, const char **argv)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int opt;
	static const char *helper_protocol;
	static int diagnostics;

	static const char *hex_challenge;
	static const char *hex_lm_response;
	static const char *hex_nt_response;
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
		{ "helper-protocol", 0, POPT_ARG_STRING, &helper_protocol, OPT_DOMAIN, "operate as a stdio-based helper", "helper protocol to use"},
 		{ "username", 0, POPT_ARG_STRING, &opt_username, OPT_USERNAME, "username"},
 		{ "domain", 0, POPT_ARG_STRING, &opt_domain, OPT_DOMAIN, "domain name"},
 		{ "workstation", 0, POPT_ARG_STRING, &opt_workstation, OPT_WORKSTATION, "workstation"},
 		{ "challenge", 0, POPT_ARG_STRING, &hex_challenge, OPT_CHALLENGE, "challenge (HEX encoded)"},
		{ "lm-response", 0, POPT_ARG_STRING, &hex_lm_response, OPT_LM, "LM Response to the challenge (HEX encoded)"},
		{ "nt-response", 0, POPT_ARG_STRING, &hex_nt_response, OPT_NT, "NT or NTLMv2 Response to the challenge (HEX encoded)"},
		{ "password", 0, POPT_ARG_STRING, &opt_password, OPT_PASSWORD, "User's plaintext password"},		
		{ "request-lm-key", 0, POPT_ARG_NONE, &request_lm_key, OPT_LM_KEY, "Retrieve LM session key"},
		{ "request-nt-key", 0, POPT_ARG_NONE, &request_user_session_key, OPT_USER_SESSION_KEY, "Retrieve User (NT) session key"},
		{ "use-cached-creds", 0, POPT_ARG_NONE, &use_cached_creds, OPT_USE_CACHED_CREDS, "Use cached credentials if no password is given"},
		{ "diagnostics", 0, POPT_ARG_NONE, &diagnostics,
		  OPT_DIAGNOSTICS,
		  "Perform diagnostics on the authentication chain"},
		{ "require-membership-of", 0, POPT_ARG_STRING, &require_membership_of, OPT_REQUIRE_MEMBERSHIP, "Require that a user be a member of this group (either name or SID) for authentication to succeed" },
		{ "pam-winbind-conf", 0, POPT_ARG_STRING, &opt_pam_winbind_conf, OPT_PAM_WINBIND_CONF, "Require that request must set WBFLAG_PAM_CONTACT_TRUSTDOM when krb5 auth is required" },
		{ "target-service", 0, POPT_ARG_STRING, &opt_target_service, OPT_TARGET_SERVICE, "Target service (eg http)" },
		{ "target-hostname", 0, POPT_ARG_STRING, &opt_target_hostname, OPT_TARGET_HOSTNAME, "Target hostname" },
		POPT_COMMON_CONFIGFILE
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};

	/* Samba client initialisation */
	load_case_tables();

	setup_logging("ntlm_auth", DEBUG_STDERR);

	/* Parse options */

	pc = poptGetContext("ntlm_auth", argc, argv, long_options, 0);

	/* Parse command line options */

	if (argc == 1) {
		poptPrintHelp(pc, stderr, 0);
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
				x_fprintf(x_stderr, "hex decode of %s failed! (only got %d bytes)\n", 
					  hex_challenge,
					  (int)opt_challenge.length);
				exit(1);
			}
			break;
		case OPT_LM: 
			opt_lm_response = strhex_to_data_blob(NULL, hex_lm_response);
			if (opt_lm_response.length != 24) {
				x_fprintf(x_stderr, "hex decode of %s failed! (only got %d bytes)\n", 
					  hex_lm_response,
					  (int)opt_lm_response.length);
				exit(1);
			}
			break;

		case OPT_NT: 
			opt_nt_response = strhex_to_data_blob(NULL, hex_nt_response);
			if (opt_nt_response.length < 24) {
				x_fprintf(x_stderr, "hex decode of %s failed! (only got %d bytes)\n", 
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
				x_fprintf(x_stderr, "Domain specified in username (%s) "
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
		x_fprintf(x_stderr, "loadparm_init_s3() failed!\n");
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
		x_fprintf(x_stderr, "unknown helper protocol [%s]\n\nValid helper protools:\n\n", helper_protocol);

		for (i=0; i<NUM_HELPER_MODES; i++) {
			x_fprintf(x_stderr, "%s\n", stdio_helper_protocols[i].name);
		}

		exit(1);
	}

	if (!opt_username || !*opt_username) {
		x_fprintf(x_stderr, "username must be specified!\n\n");
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
			return 1;
		}
	} else {
		fstring user;

		fstr_sprintf(user, "%s%c%s", opt_domain, winbind_separator(), opt_username);
		if (!check_plaintext_auth(user, opt_password, True)) {
			return 1;
		}
	}

	/* Exit code */

	poptFreeContext(pc);
	TALLOC_FREE(frame);
	return 0;
}
