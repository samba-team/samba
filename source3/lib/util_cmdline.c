/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2007
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) James Peach 2006

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
#include "auth_info.h"
#include "secrets.h"
#include "param/param.h"
#include "librpc/gen_ndr/samr.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"

/**************************************************************************n
  Code to cope with username/password auth options from the commandline.
  Used mainly in client tools.
****************************************************************************/

struct user_auth_info {
	struct cli_credentials *creds;
	struct loadparm_context *lp_ctx;
	bool got_username;
	bool got_pass;
	int signing_state;
	bool smb_encrypt;
	bool use_machine_account;
	bool use_pw_nt_hash;
	char *pw_nt_hash;
};

struct user_auth_info *user_auth_info_init(TALLOC_CTX *mem_ctx)
{
	struct user_auth_info *result = NULL;

	result = talloc_zero(mem_ctx, struct user_auth_info);
	if (result == NULL) {
		return NULL;
	}

	result->lp_ctx = loadparm_init_s3(result, loadparm_s3_helpers());
	if (result->lp_ctx == NULL) {
		TALLOC_FREE(result);
		return NULL;
	}

	result->creds = cli_credentials_init(result);
	if (result->creds == NULL) {
		TALLOC_FREE(result);
		return NULL;
	}

	cli_credentials_set_conf(result->creds, result->lp_ctx);

	result->signing_state = SMB_SIGNING_DEFAULT;
	return result;
}

void set_cmdline_auth_info_guess(struct user_auth_info *auth_info)
{
	/*
	 * Note that cli_credentials_guess() calls
	 * cli_credentials_set_conf() again, which will
	 * hopefully cope with a reloaded smb.conf.
	 */
	cli_credentials_set_username(auth_info->creds, "GUEST", CRED_GUESS_ENV);
	cli_credentials_guess(auth_info->creds, auth_info->lp_ctx);
}

void set_cmdline_auth_info_from_file(struct user_auth_info *auth_info,
				     const char *filename)
{
	bool ok;

	ok = cli_credentials_parse_file(auth_info->creds, filename,
					CRED_SPECIFIED);
	if (!ok) {
		exit(EIO);
	}
	auth_info->got_username = true;
}

const char *get_cmdline_auth_info_username(const struct user_auth_info *auth_info)
{
	const char *username = NULL;

	username = cli_credentials_get_username(auth_info->creds);
	if (username == NULL) {
		return "";
	}

	return username;
}

void set_cmdline_auth_info_username(struct user_auth_info *auth_info,
				    const char *username)
{
	const char *new_val = NULL;

	if (username == NULL) {
		return;
	}
	cli_credentials_parse_string(auth_info->creds,
				     username,
				     CRED_SPECIFIED);
	new_val = cli_credentials_get_username(auth_info->creds);
	if (new_val == NULL) {
		exit(ENOMEM);
	}

	auth_info->got_username = true;
	if (strchr_m(username, '%') != NULL) {
		auth_info->got_pass = true;
	}
}

void reset_cmdline_auth_info_username(struct user_auth_info *auth_info)
{
	const char *username = NULL;
	const char *new_val = NULL;

	if (!auth_info->got_username) {
		return;
	}

	username = cli_credentials_get_username(auth_info->creds);
	if (username == NULL) {
		return;
	}
	if (username[0] == '\0') {
		return;
	}

	cli_credentials_parse_string(auth_info->creds,
				     username,
				     CRED_SPECIFIED);
	new_val = cli_credentials_get_username(auth_info->creds);
	if (new_val == NULL) {
		exit(ENOMEM);
	}
}

const char *get_cmdline_auth_info_domain(const struct user_auth_info *auth_info)
{
	const char *domain = NULL;

	domain = cli_credentials_get_domain(auth_info->creds);
	if (domain == NULL) {
		return "";
	}

	return domain;
}

void set_cmdline_auth_info_domain(struct user_auth_info *auth_info,
				  const char *domain)
{
	bool ok;

	ok = cli_credentials_set_domain(auth_info->creds, domain, CRED_SPECIFIED);
	if (!ok) {
		exit(ENOMEM);
	}
}

const char *get_cmdline_auth_info_password(const struct user_auth_info *auth_info)
{
	const char *password = NULL;

	if (auth_info->pw_nt_hash != NULL) {
		return auth_info->pw_nt_hash;
	}

	if (auth_info->use_pw_nt_hash) {
		struct user_auth_info *ai =
			discard_const_p(struct user_auth_info, auth_info);
		struct samr_Password *nt_hash = NULL;

		nt_hash = cli_credentials_get_nt_hash(ai->creds,
						      ai);
		if (nt_hash == NULL) {
			return "";
		}

		ai->pw_nt_hash = hex_encode_talloc(ai,
						   nt_hash->hash,
						   sizeof(nt_hash->hash));
		TALLOC_FREE(nt_hash);
		if (ai->pw_nt_hash == NULL) {
			return "";
		}

		return auth_info->pw_nt_hash;
	}

	password = cli_credentials_get_password(auth_info->creds);
	if (password == NULL) {
		return "";
	}

	return password;
}

void set_cmdline_auth_info_password(struct user_auth_info *auth_info,
				    const char *password)
{
	bool ok;

	auth_info->got_pass = true;

	if (password != NULL && strlen(password) == 0) {
		password = NULL;
	}

	ok = cli_credentials_set_password(auth_info->creds,
					  password,
					  CRED_SPECIFIED);
	if (!ok) {
		exit(ENOMEM);
	}
}

bool set_cmdline_auth_info_signing_state(struct user_auth_info *auth_info,
					 const char *arg)
{
	auth_info->signing_state = SMB_SIGNING_DEFAULT;
	if (strequal(arg, "off") || strequal(arg, "no") ||
			strequal(arg, "false")) {
		auth_info->signing_state = SMB_SIGNING_OFF;
	} else if (strequal(arg, "on") || strequal(arg, "yes") ||
			strequal(arg, "if_required") ||
			strequal(arg, "true") || strequal(arg, "auto")) {
		auth_info->signing_state = SMB_SIGNING_IF_REQUIRED;
	} else if (strequal(arg, "force") || strequal(arg, "required") ||
			strequal(arg, "forced")) {
		auth_info->signing_state = SMB_SIGNING_REQUIRED;
	} else {
		return false;
	}
	return true;
}

void set_cmdline_auth_info_signing_state_raw(struct user_auth_info *auth_info,
					     int signing_state)
{
	auth_info->signing_state = signing_state;
}

int get_cmdline_auth_info_signing_state(const struct user_auth_info *auth_info)
{
	if (auth_info->smb_encrypt) {
		return SMB_SIGNING_REQUIRED;
	}
	return auth_info->signing_state;
}

void set_cmdline_auth_info_use_ccache(struct user_auth_info *auth_info, bool b)
{
	uint32_t gensec_features;

	gensec_features = cli_credentials_get_gensec_features(auth_info->creds);
	gensec_features |= GENSEC_FEATURE_NTLM_CCACHE;
	cli_credentials_set_gensec_features(auth_info->creds, gensec_features);
}

bool get_cmdline_auth_info_use_ccache(const struct user_auth_info *auth_info)
{
	uint32_t gensec_features;

	gensec_features = cli_credentials_get_gensec_features(auth_info->creds);
	if (gensec_features & GENSEC_FEATURE_NTLM_CCACHE) {
		return true;
	}

	return false;
}

void set_cmdline_auth_info_use_pw_nt_hash(struct user_auth_info *auth_info,
					  bool b)
{
	TALLOC_FREE(auth_info->pw_nt_hash);
	auth_info->use_pw_nt_hash = b;
	cli_credentials_set_password_will_be_nt_hash(auth_info->creds, b);
}

bool get_cmdline_auth_info_use_pw_nt_hash(
	const struct user_auth_info *auth_info)
{
	return auth_info->use_pw_nt_hash;
}

void set_cmdline_auth_info_use_kerberos(struct user_auth_info *auth_info,
					bool b)
{
	enum credentials_use_kerberos krb5_state;

	if (b) {
		krb5_state = CRED_MUST_USE_KERBEROS;
	} else {
		krb5_state = CRED_DONT_USE_KERBEROS;
	}

	cli_credentials_set_kerberos_state(auth_info->creds, krb5_state);
}

bool get_cmdline_auth_info_use_kerberos(const struct user_auth_info *auth_info)
{
	enum credentials_use_kerberos krb5_state;

	krb5_state = cli_credentials_get_kerberos_state(auth_info->creds);

	if (krb5_state == CRED_MUST_USE_KERBEROS) {
		return true;
	}

	return false;
}

void set_cmdline_auth_info_fallback_after_kerberos(struct user_auth_info *auth_info,
					bool b)
{
	enum credentials_use_kerberos krb5_state;

	krb5_state = cli_credentials_get_kerberos_state(auth_info->creds);

	switch (krb5_state) {
	case CRED_MUST_USE_KERBEROS:
		if (b) {
			krb5_state = CRED_AUTO_USE_KERBEROS;
		}
		break;
	case CRED_AUTO_USE_KERBEROS:
		if (!b) {
			krb5_state = CRED_MUST_USE_KERBEROS;
		}
		break;
	case CRED_DONT_USE_KERBEROS:
		/* nothing to do */
		break;
	}

	cli_credentials_set_kerberos_state(auth_info->creds, krb5_state);
}

bool get_cmdline_auth_info_fallback_after_kerberos(const struct user_auth_info *auth_info)
{
	enum credentials_use_kerberos krb5_state;

	krb5_state = cli_credentials_get_kerberos_state(auth_info->creds);

	if (krb5_state == CRED_AUTO_USE_KERBEROS) {
		return true;
	}

	return false;
}

/* This should only be used by lib/popt_common.c JRA */
void set_cmdline_auth_info_use_krb5_ticket(struct user_auth_info *auth_info)
{
	set_cmdline_auth_info_use_kerberos(auth_info, true);
	auth_info->got_pass = true;
}

/* This should only be used by lib/popt_common.c JRA */
void set_cmdline_auth_info_smb_encrypt(struct user_auth_info *auth_info)
{
	auth_info->smb_encrypt = true;
}

void set_cmdline_auth_info_use_machine_account(struct user_auth_info *auth_info)
{
	cli_credentials_set_machine_account_pending(auth_info->creds,
						    auth_info->lp_ctx);
	auth_info->use_machine_account = true;
}

bool get_cmdline_auth_info_got_pass(const struct user_auth_info *auth_info)
{
	return auth_info->got_pass;
}

bool get_cmdline_auth_info_smb_encrypt(const struct user_auth_info *auth_info)
{
	return auth_info->smb_encrypt;
}

bool get_cmdline_auth_info_use_machine_account(const struct user_auth_info *auth_info)
{
	return auth_info->use_machine_account;
}

bool set_cmdline_auth_info_machine_account_creds(struct user_auth_info *auth_info)
{
	struct db_context *db_ctx = NULL;
	NTSTATUS status;

	if (!get_cmdline_auth_info_use_machine_account(auth_info)) {
		return false;
	}

	db_ctx = secrets_db_ctx();
	if (db_ctx == NULL) {
		d_printf("ERROR: Unable to open secrets database\n");
		return false;
	}

	cli_credentials_set_domain(auth_info->creds, lpcfg_workgroup(auth_info->lp_ctx),
				   CRED_SPECIFIED);

	status = cli_credentials_set_machine_account_db_ctx(auth_info->creds,
							    auth_info->lp_ctx,
							    db_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("ERROR: Unable to fetch machine password for "
			 "%s in domain %s - %s\n",
			 lpcfg_netbios_name(auth_info->lp_ctx),
			 lpcfg_workgroup(auth_info->lp_ctx),
			 nt_errstr(status));
		return false;
	}

	return true;
}

static const char *cmdline_auth_info_pw_callback(struct cli_credentials *creds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *name = NULL;
	char *label = NULL;
	char *ret = NULL;
	char pwd[256] = {0};
	int rc;

	name = cli_credentials_get_unparsed_name(creds, frame);
	if (name == NULL) {
		goto fail;
	}
	label = talloc_asprintf(frame, "Enter %s's password: ", name);
	if (label == NULL) {
		goto fail;
	}
	rc = samba_getpass(label, pwd, sizeof(pwd), false, false);
	if (rc != 0) {
		goto fail;
	}
	ret = talloc_strdup(creds, pwd);
	if (ret == NULL) {
		goto fail;
	}
	talloc_set_name_const(ret, __location__);
fail:
	ZERO_STRUCT(pwd);
	TALLOC_FREE(frame);
	return ret;
}

/****************************************************************************
 Ensure we have a password if one not given.
****************************************************************************/

void set_cmdline_auth_info_getpass(struct user_auth_info *auth_info)
{
	if (get_cmdline_auth_info_got_pass(auth_info) ||
	    get_cmdline_auth_info_use_ccache(auth_info) ||
	    get_cmdline_auth_info_use_kerberos(auth_info)) {
		/* Already got one... */
		return;
	}

	cli_credentials_set_password_callback(auth_info->creds,
					cmdline_auth_info_pw_callback);
}

struct cli_credentials *get_cmdline_auth_info_creds(
	const struct user_auth_info *auth_info)
{
	return auth_info->creds;
}
