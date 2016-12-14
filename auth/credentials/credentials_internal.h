/*
   samba -- Unix SMB/CIFS implementation.

   Client credentials structure

   Copyright (C) Jelmer Vernooij 2004-2006
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005

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
#ifndef __CREDENTIALS_INTERNAL_H__
#define __CREDENTIALS_INTERNAL_H__

#include "../lib/util/data_blob.h"
#include "librpc/gen_ndr/misc.h"

struct cli_credentials {
	enum credentials_obtained workstation_obtained;
	enum credentials_obtained username_obtained;
	enum credentials_obtained password_obtained;
	enum credentials_obtained domain_obtained;
	enum credentials_obtained realm_obtained;
	enum credentials_obtained ccache_obtained;
	enum credentials_obtained client_gss_creds_obtained;
	enum credentials_obtained principal_obtained;
	enum credentials_obtained keytab_obtained;
	enum credentials_obtained server_gss_creds_obtained;

	/* Threshold values (essentially a MAX() over a number of the
	 * above) for the ccache and GSS credentials, to ensure we
	 * regenerate/pick correctly */

	enum credentials_obtained ccache_threshold;
	enum credentials_obtained client_gss_creds_threshold;

	const char *workstation;
	const char *username;
	const char *password;
	const char *old_password;
	const char *domain;
	const char *realm;
	const char *principal;
	char *salt_principal;
	char *impersonate_principal;
	char *self_service;
	char *target_service;

	const char *bind_dn;

	/* Allows authentication from a keytab or similar */
	struct samr_Password *nt_hash;
	struct samr_Password *old_nt_hash;

	/* Allows NTLM pass-though authentication */
	DATA_BLOB lm_response;
	DATA_BLOB nt_response;

	struct ccache_container *ccache;
	struct gssapi_creds_container *client_gss_creds;
	struct keytab_container *keytab;
	struct gssapi_creds_container *server_gss_creds;

	const char *(*workstation_cb) (struct cli_credentials *);
	const char *(*password_cb) (struct cli_credentials *);
	const char *(*username_cb) (struct cli_credentials *);
	const char *(*domain_cb) (struct cli_credentials *);
	const char *(*realm_cb) (struct cli_credentials *);
	const char *(*principal_cb) (struct cli_credentials *);

	/* Private handle for the callback routines to use */
	void *priv_data;

	struct netlogon_creds_CredentialState *netlogon_creds;
	enum netr_SchannelType secure_channel_type;
	int kvno;
	time_t password_last_changed_time;

	struct smb_krb5_context *smb_krb5_context;

	/* We are flagged to get machine account details from the
	 * secrets.ldb when we are asked for a username or password */
	bool machine_account_pending;
	struct loadparm_context *machine_account_pending_lp_ctx;

	/* Is this a machine account? */
	bool machine_account;

	/* Should we be trying to use kerberos? */
	enum credentials_use_kerberos use_kerberos;

	/* Should we get a forwardable ticket? */
	enum credentials_krb_forwardable krb_forwardable;

	/* Forced SASL mechansim */
	char *forced_sasl_mech;

	/* gensec features which should be used for connections */
	uint32_t gensec_features;

	/* Number of retries left before bailing out */
	uint32_t password_tries;

	/* Whether any callback is currently running */
	bool callback_running;

	char winbind_separator;

	bool password_will_be_nt_hash;
};

#endif /* __CREDENTIALS_INTERNAL_H__ */
