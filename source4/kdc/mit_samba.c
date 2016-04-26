/*
   MIT-Samba4 library

   Copyright (c) 2010, Simo Sorce <idra@samba.org>

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

#define TEVENT_DEPRECATED 1

#include "includes.h"
#include "param/param.h"
#include "dsdb/samdb/samdb.h"
#include "system/kerberos.h"
#include <kdb.h>
#include <kadm5/kadm_err.h>
#include "kdc/sdb.h"
#include "kdc/sdb_kdb.h"
#include "auth/kerberos/kerberos.h"
#include "kdc/samba_kdc.h"
#include "kdc/pac-glue.h"
#include "kdc/db-glue.h"
#include "auth/auth.h"
#include "kdc/kpasswd_glue.h"
#include "auth/auth_sam.h"

#include "mit_samba.h"

void mit_samba_context_free(struct mit_samba_context *ctx)
{
	/* free heimdal's krb5_context */
	if (ctx->context) {
		krb5_free_context(ctx->context);
	}

	/* then free everything else */
	talloc_free(ctx);
}

int mit_samba_context_init(struct mit_samba_context **_ctx)
{
	NTSTATUS status;
	struct mit_samba_context *ctx;
	const char *s4_conf_file;
	int ret;
	struct samba_kdc_base_context base_ctx;

	ctx = talloc_zero(NULL, struct mit_samba_context);
	if (!ctx) {
		ret = ENOMEM;
		goto done;
	}

	base_ctx.ev_ctx = tevent_context_init(ctx);
	if (!base_ctx.ev_ctx) {
		ret = ENOMEM;
		goto done;
	}
	tevent_loop_allow_nesting(base_ctx.ev_ctx);
	base_ctx.lp_ctx = loadparm_init_global(false);
	if (!base_ctx.lp_ctx) {
		ret = ENOMEM;
		goto done;
	}

	setup_logging("mitkdc", DEBUG_STDOUT);

	/* init s4 configuration */
	s4_conf_file = lpcfg_configfile(base_ctx.lp_ctx);
	if (s4_conf_file) {
		lpcfg_load(base_ctx.lp_ctx, s4_conf_file);
	} else {
		lpcfg_load_default(base_ctx.lp_ctx);
	}

	status = samba_kdc_setup_db_ctx(ctx, &base_ctx, &ctx->db_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		ret = EINVAL;
		goto done;
	}

	/* init heimdal's krb_context and log facilities */
	ret = smb_krb5_init_context_basic(ctx,
					  ctx->db_ctx->lp_ctx,
					  &ctx->context);
	if (ret) {
		goto done;
	}

	ret = 0;

done:
	if (ret) {
		mit_samba_context_free(ctx);
	} else {
		*_ctx = ctx;
	}
	return ret;
}

static krb5_error_code ks_is_tgs_principal(struct mit_samba_context *ctx,
					   krb5_const_principal principal)
{
	char *p;
	int eq = -1;

	p = smb_krb5_principal_get_comp_string(ctx, ctx->context, principal, 0);

	eq = krb5_princ_size(ctx->context, principal) == 2 &&
	     (strcmp(p, KRB5_TGS_NAME) == 0);

	talloc_free(p);

	return eq;
}

int mit_samba_generate_salt(krb5_data *salt)
{
	if (salt == NULL) {
		return EINVAL;
	}

	salt->length = 16;
	salt->data = malloc(salt->length);
	if (salt->data == NULL) {
		return ENOMEM;
	}

	generate_random_buffer((uint8_t *)salt->data, salt->length);

	return 0;
}

int mit_samba_generate_random_password(krb5_data *pwd)
{
	TALLOC_CTX *tmp_ctx;
	char *password;

	if (pwd == NULL) {
		return EINVAL;
	}
	pwd->length = 24;

	tmp_ctx = talloc_named(NULL,
			       0,
			       "mit_samba_create_principal_password context");
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	password = generate_random_password(tmp_ctx, pwd->length, pwd->length);
	if (password == NULL) {
		talloc_free(tmp_ctx);
		return ENOMEM;
	}

	pwd->data = strdup(password);
	talloc_free(tmp_ctx);
	if (pwd->data == NULL) {
		return ENOMEM;
	}

	return 0;
}

int mit_samba_get_principal(struct mit_samba_context *ctx,
			    krb5_const_principal principal,
			    unsigned int kflags,
			    krb5_db_entry **_kentry)
{
	struct sdb_entry_ex sentry = {
		.free_entry = NULL,
	};
	krb5_db_entry *kentry;
	int ret;
	int sflags = 0;

	kentry = malloc(sizeof(krb5_db_entry));
	if (kentry == NULL) {
		return ENOMEM;
	}

	if (kflags & KRB5_KDB_FLAG_CANONICALIZE) {
		sflags |= SDB_F_CANON;
	}
	if (kflags & (KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY |
		      KRB5_KDB_FLAG_INCLUDE_PAC)) {
		/*
		 * KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY is equal to
		 * SDB_F_FOR_AS_REQ
		 *
		 * We use ANY to also allow AS_REQ for service principal names
		 * This is supported by Windows.
		 */
		sflags |= SDB_F_GET_ANY|SDB_F_FOR_AS_REQ;
	} else if (ks_is_tgs_principal(ctx, principal)) {
		sflags |= SDB_F_GET_KRBTGT;
	} else {
		sflags |= SDB_F_GET_SERVER|SDB_F_FOR_TGS_REQ;
	}

	/* always set this or the created_by data will not be populated by samba's
	 * backend and we will fail to parse the entry later */
	sflags |= SDB_F_ADMIN_DATA;

	ret = samba_kdc_fetch(ctx->context, ctx->db_ctx,
			      principal, sflags, 0, &sentry);
	switch (ret) {
	case 0:
		break;
	case SDB_ERR_NOENTRY:
		ret = KRB5_KDB_NOENTRY;
		goto done;
	case SDB_ERR_WRONG_REALM:
		/*
		 * If we have a wrong realm e.g. if we try get a cross forest
		 * ticket, we return a ticket with the correct realm. The KDC
		 * will detect this an return the appropriate return code.
		 */
		ret = 0;
		break;
	case SDB_ERR_NOT_FOUND_HERE:
		/* FIXME: RODC support */
	default:
		goto done;
	}

	ret = sdb_entry_ex_to_kdb_entry_ex(ctx->context, &sentry, kentry);

	sdb_free_entry(&sentry);

done:
	if (ret) {
		free(kentry);
	} else {
		*_kentry = kentry;
	}
	return ret;
}

int mit_samba_get_firstkey(struct mit_samba_context *ctx,
			   krb5_db_entry **_kentry)
{
	struct sdb_entry_ex sentry = {
		.free_entry = NULL,
	};
	krb5_db_entry *kentry;
	int ret;

	kentry = malloc(sizeof(krb5_db_entry));
	if (kentry == NULL) {
		return ENOMEM;
	}

	ret = samba_kdc_firstkey(ctx->context, ctx->db_ctx, &sentry);
	switch (ret) {
	case 0:
		break;
	case SDB_ERR_NOENTRY:
		free(kentry);
		return KRB5_KDB_NOENTRY;
	case SDB_ERR_NOT_FOUND_HERE:
		/* FIXME: RODC support */
	default:
		free(kentry);
		return ret;
	}

	ret = sdb_entry_ex_to_kdb_entry_ex(ctx->context, &sentry, kentry);

	sdb_free_entry(&sentry);

	if (ret) {
		free(kentry);
	} else {
		*_kentry = kentry;
	}
	return ret;
}

int mit_samba_get_nextkey(struct mit_samba_context *ctx,
			  krb5_db_entry **_kentry)
{
	struct sdb_entry_ex sentry = {
		.free_entry = NULL,
	};
	krb5_db_entry *kentry;
	int ret;

	kentry = malloc(sizeof(krb5_db_entry));
	if (kentry == NULL) {
		return ENOMEM;
	}

	ret = samba_kdc_nextkey(ctx->context, ctx->db_ctx, &sentry);
	switch (ret) {
	case 0:
		break;
	case SDB_ERR_NOENTRY:
		free(kentry);
		return KRB5_KDB_NOENTRY;
	case SDB_ERR_NOT_FOUND_HERE:
		/* FIXME: RODC support */
	default:
		free(kentry);
		return ret;
	}

	ret = sdb_entry_ex_to_kdb_entry_ex(ctx->context, &sentry, kentry);

	sdb_free_entry(&sentry);

	if (ret) {
		free(kentry);
	} else {
		*_kentry = kentry;
	}
	return ret;
}

int mit_samba_get_pac_data(struct mit_samba_context *ctx,
			   krb5_db_entry *client,
			   DATA_BLOB *data)
{
	TALLOC_CTX *tmp_ctx;
	DATA_BLOB *pac_blob;
	NTSTATUS nt_status;
	struct samba_kdc_entry *skdc_entry;

	skdc_entry = talloc_get_type_abort(client->e_data,
					   struct samba_kdc_entry);

	tmp_ctx = talloc_named(ctx, 0, "mit_samba_get_pac_data context");
	if (!tmp_ctx) {
		return ENOMEM;
	}

	nt_status = samba_kdc_get_pac_blob(tmp_ctx, skdc_entry, &pac_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return EINVAL;
	}

	data->data = (uint8_t *)malloc(pac_blob->length);
	if (!data->data) {
		talloc_free(tmp_ctx);
		return ENOMEM;
	}
	memcpy(data->data, pac_blob->data, pac_blob->length);
	data->length = pac_blob->length;

	talloc_free(tmp_ctx);
	return 0;
}

int mit_samba_update_pac_data(struct mit_samba_context *ctx,
			      krb5_db_entry *client,
			      DATA_BLOB *pac_data,
			      DATA_BLOB *logon_data)
{
	TALLOC_CTX *tmp_ctx;
	DATA_BLOB *logon_blob;
	krb5_error_code code;
	NTSTATUS nt_status;
	krb5_pac pac = NULL;
	int ret;
	struct samba_kdc_entry *skdc_entry = NULL;

	if (client) {
		skdc_entry = talloc_get_type_abort(client->e_data,
						   struct samba_kdc_entry);
	}

	/* The user account may be set not to want the PAC */
	if (client && !samba_princ_needs_pac(skdc_entry)) {
		return EINVAL;
	}

	tmp_ctx = talloc_named(ctx, 0, "mit_samba_update_pac_data context");
	if (!tmp_ctx) {
		return ENOMEM;
	}

	logon_blob = talloc_zero(tmp_ctx, DATA_BLOB);
	if (!logon_blob) {
		ret = ENOMEM;
		goto done;
	}

	code = krb5_pac_parse(ctx->context,
			      pac_data->data, pac_data->length, &pac);
	if (code) {
		ret = EINVAL;
		goto done;
	}

	/* TODO: An implementation-specific decision will need to be
	 * made as to when to check the KDC pac signature, and how to
	 * untrust untrusted RODCs */
	nt_status = samba_kdc_update_pac_blob(tmp_ctx, ctx->context,
					      pac, logon_blob, NULL, NULL);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Building PAC failed: %s\n",
			  nt_errstr(nt_status)));
		ret = EINVAL;
		goto done;
	}

	logon_data->data = (uint8_t *)malloc(logon_blob->length);
	if (!logon_data->data) {
		ret = ENOMEM;
		goto done;
	}
	memcpy(logon_data->data, logon_blob->data, logon_blob->length);
	logon_data->length = logon_blob->length;

	ret = 0;

done:
	if (pac) krb5_pac_free(ctx->context, pac);
	talloc_free(tmp_ctx);
	return ret;
}

/* provide header, function is exported but there are no public headers */

krb5_error_code encode_krb5_padata_sequence(krb5_pa_data *const *rep, krb5_data **code);

/* this function allocates 'data' using malloc.
 * The caller is responsible for freeing it */
static void samba_kdc_build_edata_reply(NTSTATUS nt_status, DATA_BLOB *e_data)
{
	krb5_error_code ret = 0;
	krb5_pa_data pa, *ppa = NULL;
	krb5_data *d = NULL;

	if (!e_data)
		return;

	e_data->data   = NULL;
	e_data->length = 0;

	pa.magic		= KV5M_PA_DATA;
	pa.pa_type		= KRB5_PADATA_PW_SALT;
	pa.length		= 12;
	pa.contents		= malloc(pa.length);
	if (!pa.contents) {
		return;
	}

	SIVAL(pa.contents, 0, NT_STATUS_V(nt_status));
	SIVAL(pa.contents, 4, 0);
	SIVAL(pa.contents, 8, 1);

	ppa = &pa;

	ret = encode_krb5_padata_sequence(&ppa, &d);
	free(pa.contents);
	if (ret) {
		return;
	}

	e_data->data   = (uint8_t *)d->data;
	e_data->length = d->length;

	/* free d, not d->data - gd */
	free(d);

	return;
}

int mit_samba_check_client_access(struct mit_samba_context *ctx,
				  krb5_db_entry *client,
				  const char *client_name,
				  krb5_db_entry *server,
				  const char *server_name,
				  const char *netbios_name,
				  bool password_change,
				  DATA_BLOB *e_data)
{
	struct samba_kdc_entry *skdc_entry;
	NTSTATUS nt_status;

	skdc_entry = talloc_get_type(client->e_data, struct samba_kdc_entry);

	nt_status = samba_kdc_check_client_access(skdc_entry,
						  client_name,
						  netbios_name,
						  password_change);

	if (!NT_STATUS_IS_OK(nt_status)) {
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_MEMORY)) {
			return ENOMEM;
		}

		samba_kdc_build_edata_reply(nt_status, e_data);

		return samba_kdc_map_policy_err(nt_status);
	}

	return 0;
}

int mit_samba_check_s4u2proxy(struct mit_samba_context *ctx,
			      krb5_db_entry *kentry,
			      const char *target_name,
			      bool is_nt_enterprise_name)
{
#if 1
	/*
	 * This is disabled because mit_samba_update_pac_data() does not handle
	 * S4U_DELEGATION_INFO
	 */

	return KRB5KDC_ERR_BADOPTION;
#else
	krb5_principal target_principal;
	int flags = 0;
	int ret;

	if (is_nt_enterprise_name) {
		flags = KRB5_PRINCIPAL_PARSE_ENTERPRISE;
	}

	ret = krb5_parse_name_flags(ctx->context, target_name,
				    flags, &target_principal);
	if (ret) {
		return ret;
	}

	ret = samba_kdc_check_s4u2proxy(ctx->context,
					ctx->db_ctx,
					skdc_entry,
					target_principal);

	krb5_free_principal(ctx->context, target_principal);

	return ret;
#endif
}

static krb5_error_code mit_samba_change_pwd_error(krb5_context context,
						  NTSTATUS result,
						  enum samPwdChangeReason reject_reason,
						  struct samr_DomInfo1 *dominfo)
{
	krb5_error_code code = KADM5_PASS_Q_GENERIC;

	if (NT_STATUS_EQUAL(result, NT_STATUS_NO_SUCH_USER)) {
		code = KADM5_BAD_PRINCIPAL;
		krb5_set_error_message(context,
				       code,
				       "No such user when changing password");
	}
	if (NT_STATUS_EQUAL(result, NT_STATUS_ACCESS_DENIED)) {
		code = KADM5_PASS_Q_GENERIC;
		krb5_set_error_message(context,
				       code,
				       "Not permitted to change password");
	}
	if (NT_STATUS_EQUAL(result, NT_STATUS_PASSWORD_RESTRICTION) &&
	    dominfo != NULL) {
		switch (reject_reason) {
		case SAM_PWD_CHANGE_PASSWORD_TOO_SHORT:
			code = KADM5_PASS_Q_TOOSHORT;
			krb5_set_error_message(context,
					       code,
					       "Password too short, password "
					       "must be at least %d characters "
					       "long.",
					       dominfo->min_password_length);
			break;
		case SAM_PWD_CHANGE_NOT_COMPLEX:
			code = KADM5_PASS_Q_DICT;
			krb5_set_error_message(context,
					       code,
					       "Password does not meet "
					       "complexity requirements");
			break;
		case SAM_PWD_CHANGE_PWD_IN_HISTORY:
			code = KADM5_PASS_TOOSOON;
			krb5_set_error_message(context,
					       code,
					       "Password is already in password "
					       "history. New password must not "
					       "match any of your %d previous "
					       "passwords.",
					       dominfo->password_history_length);
			break;
		default:
			code = KADM5_PASS_Q_GENERIC;
			krb5_set_error_message(context,
					       code,
					       "Password change rejected, "
					       "password changes may not be "
					       "permitted on this account, or "
					       "the minimum password age may "
					       "not have elapsed.");
			break;
		}
	}

	return code;
}

int mit_samba_kpasswd_change_password(struct mit_samba_context *ctx,
				      char *pwd,
				      krb5_db_entry *db_entry)
{
	NTSTATUS status;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *tmp_ctx;
	DATA_BLOB password;
	enum samPwdChangeReason reject_reason;
	struct samr_DomInfo1 *dominfo;
	const char *error_string = NULL;
	struct auth_user_info_dc *user_info_dc;
	struct samba_kdc_entry *p;
	krb5_error_code code = 0;

#ifdef DEBUG_PASSWORD
	DEBUG(1,("mit_samba_kpasswd_change_password called with: %s\n", pwd));
#endif

	tmp_ctx = talloc_named(ctx, 0, "mit_samba_kpasswd_change_password");
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	p = (struct samba_kdc_entry *)db_entry->e_data;

	status = authsam_make_user_info_dc(tmp_ctx,
					   ctx->db_ctx->samdb,
					   lpcfg_netbios_name(ctx->db_ctx->lp_ctx),
					   lpcfg_sam_name(ctx->db_ctx->lp_ctx),
					   p->realm_dn,
					   p->msg,
					   data_blob(NULL, 0),
					   data_blob(NULL, 0),
					   &user_info_dc);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,("authsam_make_user_info_dc failed: %s\n",
			nt_errstr(status)));
		talloc_free(tmp_ctx);
		return EINVAL;
	}

	status = auth_generate_session_info(tmp_ctx,
					    ctx->db_ctx->lp_ctx,
					    ctx->db_ctx->samdb,
					    user_info_dc,
					    0, /* session_info_flags */
					    &ctx->session_info);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,("auth_generate_session_info failed: %s\n",
			nt_errstr(status)));
		talloc_free(tmp_ctx);
		return EINVAL;
	}

	/* password is expected as UTF16 */

	if (!convert_string_talloc(tmp_ctx, CH_UTF8, CH_UTF16,
				   pwd, strlen(pwd),
				   &password.data, &password.length)) {
		DEBUG(1,("convert_string_talloc failed\n"));
		talloc_free(tmp_ctx);
		return EINVAL;
	}

	status = samdb_kpasswd_change_password(tmp_ctx,
					       ctx->db_ctx->lp_ctx,
					       ctx->db_ctx->ev_ctx,
					       ctx->db_ctx->samdb,
					       ctx->session_info,
					       &password,
					       &reject_reason,
					       &dominfo,
					       &error_string,
					       &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,("samdb_kpasswd_change_password failed: %s\n",
			nt_errstr(status)));
		code = KADM5_PASS_Q_GENERIC;
		krb5_set_error_message(ctx->context, code, "%s", error_string);
		goto out;
	}

	if (!NT_STATUS_IS_OK(result)) {
		code = mit_samba_change_pwd_error(ctx->context,
						  result,
						  reject_reason,
						  dominfo);
	}

out:
	talloc_free(tmp_ctx);

	return code;
}

void mit_samba_zero_bad_password_count(krb5_db_entry *db_entry)
{
	struct samba_kdc_entry *p;
	struct ldb_dn *domain_dn;

	p = (struct samba_kdc_entry *)db_entry->e_data;

	domain_dn = ldb_get_default_basedn(p->kdc_db_ctx->samdb);

	authsam_logon_success_accounting(p->kdc_db_ctx->samdb,
					 p->msg,
					 domain_dn,
					 true);
}


void mit_samba_update_bad_password_count(krb5_db_entry *db_entry)
{
	struct samba_kdc_entry *p;

	p = (struct samba_kdc_entry *)db_entry->e_data;

	authsam_update_bad_pwd_count(p->kdc_db_ctx->samdb,
				     p->msg,
				     ldb_get_default_basedn(p->kdc_db_ctx->samdb));
}
