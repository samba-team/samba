/*
   MIT-Samba4 library

   Copyright (c) 2010, Simo Sorce <idra@samba.org>
   Copyright (c) 2014-2015 Guenther Deschner <gd@samba.org>
   Copyright (c) 2014-2016 Andreas Schneider <asn@samba.org>

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
#include "auth/kerberos/pac_utils.h"
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

	setup_logging("mitkdc", DEBUG_DEFAULT_STDOUT);

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
	krb5_principal referral_principal = NULL;

	kentry = calloc(1, sizeof(krb5_db_entry));
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


fetch_referral_principal:
	ret = samba_kdc_fetch(ctx->context, ctx->db_ctx,
			      principal, sflags, 0, &sentry);
	switch (ret) {
	case 0:
		break;
	case SDB_ERR_NOENTRY:
		ret = KRB5_KDB_NOENTRY;
		goto done;
	case SDB_ERR_WRONG_REALM: {
		char *dest_realm = NULL;
		const char *our_realm = lpcfg_realm(ctx->db_ctx->lp_ctx);

		if (sflags & SDB_F_FOR_AS_REQ) {
			/*
			 * If this is a request for a TGT, we are done. The KDC
			 * will return the correct error to the client.
			 */
			ret = 0;
			break;
		}

		if (referral_principal != NULL) {
			sdb_free_entry(&sentry);
			ret = KRB5_KDB_NOENTRY;
			goto done;
		}

		/*
		 * We get a TGS request
		 *
		 *     cifs/dc7.SAMBA2008R2.EXAMPLE.COM@ADDOM.SAMBA.EXAMPLE.COM
		 *
		 * to our DC for the realm
		 *
		 *     ADDOM.SAMBA.EXAMPLE.COM
		 *
		 * We look up if we have and entry in the database and get an
		 * entry with the pricipal:
		 *
		 *     cifs/dc7.SAMBA2008R2.EXAMPLE.COM@SAMBA2008R2.EXAMPLE.COM
		 *
		 * and the error: SDB_ERR_WRONG_REALM.
		 *
		 * In the case of a TGS-REQ we need to return a referral ticket
		 * fo the next trust hop to the client. This ticket will have
		 * the following principal:
		 *
		 *     krbtgt/SAMBA2008R2.EXAMPLE.COM@ADDOM.SAMBA.EXAMPLE.COM
		 *
		 * We just redo the lookup in the database with the referral
		 * principal and return success.
		 */
		dest_realm = smb_krb5_principal_get_realm(
			ctx, ctx->context, sentry.entry.principal);
		sdb_free_entry(&sentry);
		if (dest_realm == NULL) {
			ret = KRB5_KDB_NOENTRY;
			goto done;
		}

		ret = smb_krb5_make_principal(ctx->context,
					      &referral_principal,
					      our_realm,
					      KRB5_TGS_NAME,
					      dest_realm,
					      NULL);
		TALLOC_FREE(dest_realm);
		if (ret != 0) {
			goto done;
		}

		principal = referral_principal;
		goto fetch_referral_principal;
	}
	case SDB_ERR_NOT_FOUND_HERE:
		/* FIXME: RODC support */
	default:
		goto done;
	}

	ret = sdb_entry_ex_to_kdb_entry_ex(ctx->context, &sentry, kentry);

	sdb_free_entry(&sentry);

done:
	krb5_free_principal(ctx->context, referral_principal);
	referral_principal = NULL;

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

int mit_samba_get_pac(struct mit_samba_context *smb_ctx,
		      krb5_context context,
		      krb5_db_entry *client,
		      krb5_keyblock *client_key,
		      krb5_pac *pac)
{
	TALLOC_CTX *tmp_ctx;
	DATA_BLOB *logon_info_blob = NULL;
	DATA_BLOB *upn_dns_info_blob = NULL;
	DATA_BLOB *cred_ndr = NULL;
	DATA_BLOB **cred_ndr_ptr = NULL;
	DATA_BLOB cred_blob = data_blob_null;
	DATA_BLOB *pcred_blob = NULL;
	NTSTATUS nt_status;
	krb5_error_code code;
	struct samba_kdc_entry *skdc_entry;

	skdc_entry = talloc_get_type_abort(client->e_data,
					   struct samba_kdc_entry);

	tmp_ctx = talloc_named(smb_ctx,
			       0,
			       "mit_samba_get_pac_data_blobs context");
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

#if 0 /* TODO Find out if this is a pkinit_reply key */
	/* Check if we have a PREAUTH key */
	if (client_key != NULL) {
		cred_ndr_ptr = &cred_ndr;
	}
#endif

	nt_status = samba_kdc_get_pac_blobs(tmp_ctx,
					    skdc_entry,
					    &logon_info_blob,
					    cred_ndr_ptr,
					    &upn_dns_info_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return EINVAL;
	}

	if (cred_ndr != NULL) {
		code = samba_kdc_encrypt_pac_credentials(context,
							 client_key,
							 cred_ndr,
							 tmp_ctx,
							 &cred_blob);
		if (code != 0) {
			talloc_free(tmp_ctx);
			return code;
		}
		pcred_blob = &cred_blob;
	}

	code = samba_make_krb5_pac(context,
				   logon_info_blob,
				   pcred_blob,
				   upn_dns_info_blob,
				   NULL,
				   pac);

	talloc_free(tmp_ctx);
	return code;
}

krb5_error_code mit_samba_reget_pac(struct mit_samba_context *ctx,
				    krb5_context context,
				    int flags,
				    krb5_const_principal client_principal,
				    krb5_db_entry *client,
				    krb5_db_entry *server,
				    krb5_db_entry *krbtgt,
				    krb5_keyblock *krbtgt_keyblock,
				    krb5_pac *pac)
{
	TALLOC_CTX *tmp_ctx;
	krb5_error_code code;
	NTSTATUS nt_status;
	DATA_BLOB *pac_blob = NULL;
	DATA_BLOB *upn_blob = NULL;
	DATA_BLOB *deleg_blob = NULL;
	struct samba_kdc_entry *client_skdc_entry = NULL;
	struct samba_kdc_entry *krbtgt_skdc_entry = NULL;
	bool is_in_db = false;
	bool is_untrusted = false;
	size_t num_types = 0;
	uint32_t *types = NULL;
	uint32_t forced_next_type = 0;
	size_t i = 0;
	ssize_t logon_info_idx = -1;
	ssize_t delegation_idx = -1;
	ssize_t logon_name_idx = -1;
	ssize_t upn_dns_info_idx = -1;
	ssize_t srv_checksum_idx = -1;
	ssize_t kdc_checksum_idx = -1;
	krb5_pac new_pac = NULL;

	if (client != NULL) {
		client_skdc_entry =
			talloc_get_type_abort(client->e_data,
					      struct samba_kdc_entry);
	}

	if (server == NULL) {
		return EINVAL;
	}

	if (krbtgt == NULL) {
		return EINVAL;
	}
	krbtgt_skdc_entry =
		talloc_get_type_abort(krbtgt->e_data,
				      struct samba_kdc_entry);

	tmp_ctx = talloc_named(ctx, 0, "mit_samba_reget_pac context");
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	code = samba_krbtgt_is_in_db(krbtgt_skdc_entry,
				     &is_in_db,
				     &is_untrusted);
	if (code != 0) {
		goto done;
	}

	if (is_untrusted) {
		if (client == NULL) {
			code = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
			goto done;
		}

		nt_status = samba_kdc_get_pac_blobs(tmp_ctx,
						    client_skdc_entry,
						    &pac_blob,
						    NULL,
						    &upn_blob);
		if (!NT_STATUS_IS_OK(nt_status)) {
			code = EINVAL;
			goto done;
		}
	} else {
		struct PAC_SIGNATURE_DATA *pac_srv_sig;
		struct PAC_SIGNATURE_DATA *pac_kdc_sig;

		pac_blob = talloc_zero(tmp_ctx, DATA_BLOB);
		if (pac_blob == NULL) {
			code = ENOMEM;
			goto done;
		}

		pac_srv_sig = talloc_zero(tmp_ctx, struct PAC_SIGNATURE_DATA);
		if (pac_srv_sig == NULL) {
			code = ENOMEM;
			goto done;
		}

		pac_kdc_sig = talloc_zero(tmp_ctx, struct PAC_SIGNATURE_DATA);
		if (pac_kdc_sig == NULL) {
			code = ENOMEM;
			goto done;
		}

		nt_status = samba_kdc_update_pac_blob(tmp_ctx,
						      context,
						      krbtgt_skdc_entry->kdc_db_ctx->samdb,
						      *pac,
						      pac_blob,
						      pac_srv_sig,
						      pac_kdc_sig);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(0, ("Update PAC blob failed: %s\n",
				  nt_errstr(nt_status)));
			code = EINVAL;
			goto done;
		}

		if (is_in_db) {
			/*
			 * Now check the KDC signature, fetching the correct
			 * key based on the enc type.
			 */
			code = check_pac_checksum(pac_srv_sig->signature,
						  pac_kdc_sig,
						  context,
						  krbtgt_keyblock);
			if (code != 0) {
				DBG_INFO("PAC KDC signature failed to verify\n");
				goto done;
			}
		}
	}

	if (flags & KRB5_KDB_FLAG_CONSTRAINED_DELEGATION) {
		deleg_blob = talloc_zero(tmp_ctx, DATA_BLOB);
		if (deleg_blob == NULL) {
			code = ENOMEM;
			goto done;
		}

		nt_status = samba_kdc_update_delegation_info_blob(tmp_ctx,
								  context,
								  *pac,
								  server->princ,
								  discard_const(client_principal),
								  deleg_blob);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(0, ("Update delegation info failed: %s\n",
				  nt_errstr(nt_status)));
			code = EINVAL;
			goto done;
		}
	}

	/* Check the types of the given PAC */
	code = krb5_pac_get_types(context, *pac, &num_types, &types);
	if (code != 0) {
		goto done;
	}

	for (i = 0; i < num_types; i++) {
		switch (types[i]) {
		case PAC_TYPE_LOGON_INFO:
			if (logon_info_idx != -1) {
				DBG_WARNING("logon type[%u] twice [%zd] and [%zu]: \n",
					    types[i],
					    logon_info_idx,
					    i);
				SAFE_FREE(types);
				code = EINVAL;
				goto done;
			}
			logon_info_idx = i;
			break;
		case PAC_TYPE_CONSTRAINED_DELEGATION:
			if (delegation_idx != -1) {
				DBG_WARNING("logon type[%u] twice [%zd] and [%zu]: \n",
					    types[i],
					    delegation_idx,
					    i);
				SAFE_FREE(types);
				code = EINVAL;
				goto done;
			}
			delegation_idx = i;
			break;
		case PAC_TYPE_LOGON_NAME:
			if (logon_name_idx != -1) {
				DBG_WARNING("logon type[%u] twice [%zd] and [%zu]: \n",
					    types[i],
					    logon_name_idx,
					    i);
				SAFE_FREE(types);
				code = EINVAL;
				goto done;
			}
			logon_name_idx = i;
			break;
		case PAC_TYPE_UPN_DNS_INFO:
			if (upn_dns_info_idx != -1) {
				DBG_WARNING("logon type[%u] twice [%zd] and [%zu]: \n",
					    types[i],
					    upn_dns_info_idx,
					    i);
				SAFE_FREE(types);
				code = EINVAL;
				goto done;
			}
			upn_dns_info_idx = i;
			break;
		case PAC_TYPE_SRV_CHECKSUM:
			if (srv_checksum_idx != -1) {
				DBG_WARNING("logon type[%u] twice [%zd] and [%zu]: \n",
					    types[i],
					    srv_checksum_idx,
					    i);
				SAFE_FREE(types);
				code = EINVAL;
				goto done;
			}
			srv_checksum_idx = i;
			break;
		case PAC_TYPE_KDC_CHECKSUM:
			if (kdc_checksum_idx != -1) {
				DBG_WARNING("logon type[%u] twice [%zd] and [%zu]: \n",
					    types[i],
					    kdc_checksum_idx,
					    i);
				SAFE_FREE(types);
				code = EINVAL;
				goto done;
			}
			kdc_checksum_idx = i;
			break;
		default:
			continue;
		}
	}

	if (logon_info_idx == -1) {
		DEBUG(1, ("PAC_TYPE_LOGON_INFO missing\n"));
		SAFE_FREE(types);
		code = EINVAL;
		goto done;
	}
	if (logon_name_idx == -1) {
		DEBUG(1, ("PAC_TYPE_LOGON_NAME missing\n"));
		SAFE_FREE(types);
		code = EINVAL;
		goto done;
	}
	if (srv_checksum_idx == -1) {
		DEBUG(1, ("PAC_TYPE_SRV_CHECKSUM missing\n"));
		SAFE_FREE(types);
		code = EINVAL;
		goto done;
	}
	if (kdc_checksum_idx == -1) {
		DEBUG(1, ("PAC_TYPE_KDC_CHECKSUM missing\n"));
		SAFE_FREE(types);
		code = EINVAL;
		goto done;
	}

	/* Build an updated PAC */
	code = krb5_pac_init(context, &new_pac);
	if (code != 0) {
		SAFE_FREE(types);
		goto done;
	}

	for (i = 0;;) {
		krb5_data type_data;
		DATA_BLOB type_blob = data_blob_null;
		uint32_t type;

		if (forced_next_type != 0) {
			/*
			 * We need to inject possible missing types
			 */
			type = forced_next_type;
			forced_next_type = 0;
		} else if (i < num_types) {
			type = types[i];
			i++;
		} else {
			break;
		}

		switch (type) {
		case PAC_TYPE_LOGON_INFO:
			type_blob = *pac_blob;

			if (delegation_idx == -1 && deleg_blob != NULL) {
				/* inject CONSTRAINED_DELEGATION behind */
				forced_next_type = PAC_TYPE_CONSTRAINED_DELEGATION;
			}
			break;
		case PAC_TYPE_CONSTRAINED_DELEGATION:
			if (deleg_blob != NULL) {
				type_blob = *deleg_blob;
			}
			break;
		case PAC_TYPE_CREDENTIAL_INFO:
			/*
			 * Note that we copy the credential blob,
			 * as it's only usable with the PKINIT based
			 * AS-REP reply key, it's only available on the
			 * host which did the AS-REQ/AS-REP exchange.
			 *
			 * This matches Windows 2008R2...
			 */
			break;
		case PAC_TYPE_LOGON_NAME:
			/*
			 * This is generated in the main KDC code
			 */
			continue;
		case PAC_TYPE_UPN_DNS_INFO:
			/*
			 * Replace in the RODC case, otherwise
			 * upn_blob is NULL and we just copy.
			 */
			if (upn_blob != NULL) {
				type_blob = *upn_blob;
			}
			break;
		case PAC_TYPE_SRV_CHECKSUM:
			/*
			 * This is generated in the main KDC code
			 */
			continue;
		case PAC_TYPE_KDC_CHECKSUM:
			/*
			 * This is generated in the main KDC code
			 */
			continue;
		default:
			/* just copy... */
			break;
		}

		if (type_blob.length != 0) {
			code = smb_krb5_copy_data_contents(&type_data,
							   type_blob.data,
							   type_blob.length);
			if (code != 0) {
				SAFE_FREE(types);
				krb5_pac_free(context, new_pac);
				goto done;
			}
		} else {
			code = krb5_pac_get_buffer(context,
						   *pac,
						   type,
						   &type_data);
			if (code != 0) {
				SAFE_FREE(types);
				krb5_pac_free(context, new_pac);
				goto done;
			}
		}

		code = krb5_pac_add_buffer(context,
					   new_pac,
					   type,
					   &type_data);
		smb_krb5_free_data_contents(context, &type_data);
		if (code != 0) {
			SAFE_FREE(types);
			krb5_pac_free(context, new_pac);
			goto done;
		}
	}

	SAFE_FREE(types);

	/* We now replace the pac */
	krb5_pac_free(context, *pac);
	*pac = new_pac;
done:
	talloc_free(tmp_ctx);
	return code;
}

/* provide header, function is exported but there are no public headers */

krb5_error_code encode_krb5_padata_sequence(krb5_pa_data *const *rep, krb5_data **code);

/* this function allocates 'data' using malloc.
 * The caller is responsible for freeing it */
static void samba_kdc_build_edata_reply(NTSTATUS nt_status, DATA_BLOB *e_data)
{
	krb5_error_code ret = 0;
	krb5_pa_data pa, *ppa[2];
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

	ppa[0] = &pa;
	ppa[1] = NULL;

	ret = encode_krb5_padata_sequence(ppa, &d);
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
					   lpcfg_sam_dnsname(ctx->db_ctx->lp_ctx),
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
	struct netr_SendToSamBase *send_to_sam = NULL;
	struct samba_kdc_entry *p;
	struct ldb_dn *domain_dn;

	p = (struct samba_kdc_entry *)db_entry->e_data;

	domain_dn = ldb_get_default_basedn(p->kdc_db_ctx->samdb);

	authsam_logon_success_accounting(p->kdc_db_ctx->samdb,
					 p->msg,
					 domain_dn,
					 true,
					 &send_to_sam);
	/* TODO: RODC support */
}


void mit_samba_update_bad_password_count(krb5_db_entry *db_entry)
{
	struct samba_kdc_entry *p;

	p = (struct samba_kdc_entry *)db_entry->e_data;

	authsam_update_bad_pwd_count(p->kdc_db_ctx->samdb,
				     p->msg,
				     ldb_get_default_basedn(p->kdc_db_ctx->samdb));
}

bool mit_samba_princ_needs_pac(krb5_db_entry *db_entry)
{
	struct samba_kdc_entry *skdc_entry =
		talloc_get_type_abort(db_entry->e_data, struct samba_kdc_entry);

	return samba_princ_needs_pac(skdc_entry);
}
