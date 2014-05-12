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
#include "kdc/sdb.h"
#include "kdc/sdb_kdb.h"
#include "auth/kerberos/kerberos.h"
#include "kdc/samba_kdc.h"
#include "kdc/pac-glue.h"
#include "kdc/db-glue.h"

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

	ctx = talloc(NULL, struct mit_samba_context);
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


int mit_samba_get_principal(struct mit_samba_context *ctx,
			    char *principal_string,
			    unsigned int flags,
			    krb5_db_entry **_kentry)
{
	krb5_principal principal;
	struct sdb_entry_ex sentry;
	krb5_db_entry *kentry;
	int ret;
	int sflags = 0;

	kentry = malloc(sizeof(krb5_db_entry));
	if (kentry == NULL) {
		return ENOMEM;
	}

	ret = krb5_parse_name(ctx->context, principal_string, &principal);
	if (ret) {
		goto done;
	}

	ret = samba_kdc_fetch(ctx->context, ctx->db_ctx,
			      principal, sflags, 0, &sentry);
	switch (ret) {
	case 0:
		break;
	case SDB_ERR_NOENTRY:
		ret = KRB5_KDB_NOENTRY;
		goto done;
	case SDB_ERR_WRONG_REALM:
		ret = KRB5KDC_ERR_WRONG_REALM;
		break;
	case SDB_ERR_NOT_FOUND_HERE:
		/* FIXME: RODC support */
	default:
		goto done;
	}

	ret = sdb_entry_ex_to_kdb_entry_ex(ctx->context, &sentry, kentry);

	krb5_free_principal(NULL, principal);
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
	struct sdb_entry_ex sentry;
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
	struct sdb_entry_ex sentry;
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
