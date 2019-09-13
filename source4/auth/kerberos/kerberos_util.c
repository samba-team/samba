/* 
   Unix SMB/CIFS implementation.

   Kerberos utility functions for GENSEC
   
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005

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
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_proto.h"
#include "auth/credentials/credentials_krb5.h"
#include "auth/kerberos/kerberos_credentials.h"
#include "auth/kerberos/kerberos_util.h"

struct principal_container {
	struct smb_krb5_context *smb_krb5_context;
	krb5_principal principal;
	const char *string_form; /* Optional */
};

static krb5_error_code free_principal(struct principal_container *pc)
{
	/* current heimdal - 0.6.3, which we need anyway, fixes segfaults here */
	krb5_free_principal(pc->smb_krb5_context->krb5_context, pc->principal);

	return 0;
}


static krb5_error_code parse_principal(TALLOC_CTX *parent_ctx,
				       const char *princ_string,
				       struct smb_krb5_context *smb_krb5_context,
				       krb5_principal *princ,
				       const char **error_string)
{
	int ret;
	struct principal_container *mem_ctx;
	if (princ_string == NULL) {
		 *princ = NULL;
		 return 0;
	}

	ret = krb5_parse_name(smb_krb5_context->krb5_context,
			      princ_string, princ);

	if (ret) {
		(*error_string) = smb_get_krb5_error_message(
						smb_krb5_context->krb5_context,
						ret, parent_ctx);
		return ret;
	}

	mem_ctx = talloc(parent_ctx, struct principal_container);
	if (!mem_ctx) {
		(*error_string) = error_message(ENOMEM);
		return ENOMEM;
	}

	/* This song-and-dance effectivly puts the principal
	 * into talloc, so we can't loose it. */
	mem_ctx->smb_krb5_context = talloc_reference(mem_ctx,
						     smb_krb5_context);
	mem_ctx->principal = *princ;
	talloc_set_destructor(mem_ctx, free_principal);
	return 0;
}

/* Obtain the principal set on this context.  Requires a
 * smb_krb5_context because we are doing krb5 principal parsing with
 * the library routines.  The returned princ is placed in the talloc
 * system by means of a destructor (do *not* free). */

krb5_error_code principal_from_credentials(TALLOC_CTX *parent_ctx,
				struct cli_credentials *credentials,
				struct smb_krb5_context *smb_krb5_context,
				krb5_principal *princ,
				enum credentials_obtained *obtained,
				const char **error_string)
{
	krb5_error_code ret;
	const char *princ_string;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);
	*obtained = CRED_UNINITIALISED;

	if (!mem_ctx) {
		(*error_string) = error_message(ENOMEM);
		return ENOMEM;
	}
	princ_string = cli_credentials_get_principal_and_obtained(credentials,
								  mem_ctx,
								  obtained);
	if (!princ_string) {
		*princ = NULL;
		return 0;
	}

	ret = parse_principal(parent_ctx, princ_string,
			      smb_krb5_context, princ, error_string);
	talloc_free(mem_ctx);
	return ret;
}

/* Obtain the principal set on this context.  Requires a
 * smb_krb5_context because we are doing krb5 principal parsing with
 * the library routines.  The returned princ is placed in the talloc
 * system by means of a destructor (do *not* free). */

static krb5_error_code impersonate_principal_from_credentials(
				TALLOC_CTX *parent_ctx,
				struct cli_credentials *credentials,
				struct smb_krb5_context *smb_krb5_context,
				krb5_principal *princ,
				const char **error_string)
{
	return parse_principal(parent_ctx,
			cli_credentials_get_impersonate_principal(credentials),
			smb_krb5_context, princ, error_string);
}

krb5_error_code smb_krb5_create_principals_array(TALLOC_CTX *mem_ctx,
						 krb5_context context,
						 const char *account_name,
						 const char *realm,
						 uint32_t num_spns,
						 const char *spns[],
						 uint32_t *pnum_principals,
						 krb5_principal **pprincipals,
						 const char **error_string)
{
	krb5_error_code code;
	TALLOC_CTX *tmp_ctx;
	uint32_t num_principals = 0;
	krb5_principal *principals;
	uint32_t i;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		*error_string = "Cannot allocate tmp_ctx";
		return ENOMEM;
	}

	if (realm == NULL) {
		*error_string = "Cannot create principal without a realm";
		code = EINVAL;
		goto done;
	}

	if (account_name == NULL && (num_spns == 0 || spns == NULL)) {
		*error_string = "Cannot create principal without an account or SPN";
		code = EINVAL;
		goto done;
	}

	if (account_name != NULL && account_name[0] != '\0') {
		num_principals++;
	}
	num_principals += num_spns;

	principals = talloc_zero_array(tmp_ctx,
				       krb5_principal,
				       num_principals);
	if (principals == NULL) {
		*error_string = "Cannot allocate principals";
		code = ENOMEM;
		goto done;
	}

	for (i = 0; i < num_spns; i++) {
		code = krb5_parse_name(context, spns[i], &(principals[i]));
		if (code != 0) {
			*error_string = smb_get_krb5_error_message(context,
								   code,
								   mem_ctx);
			goto done;
		}
	}

	if (account_name != NULL && account_name[0] != '\0') {
		code = smb_krb5_make_principal(context,
					       &(principals[i]),
					       realm,
					       account_name,
					       NULL);
		if (code != 0) {
			*error_string = smb_get_krb5_error_message(context,
								   code,
								   mem_ctx);
			goto done;
		}
	}

	if (pnum_principals != NULL) {
		*pnum_principals = num_principals;

		if (pprincipals != NULL) {
			*pprincipals = talloc_steal(mem_ctx, principals);
		}
	}

	code = 0;
done:
	talloc_free(tmp_ctx);
	return code;
}

/**
 * Return a freshly allocated ccache (destroyed by destructor on child
 * of parent_ctx), for a given set of client credentials 
 */

 krb5_error_code kinit_to_ccache(TALLOC_CTX *parent_ctx,
				 struct cli_credentials *credentials,
				 struct smb_krb5_context *smb_krb5_context,
				 struct tevent_context *event_ctx,
				 krb5_ccache ccache,
				 enum credentials_obtained *obtained,
				 const char **error_string)
{
	krb5_error_code ret;
	const char *password;
#ifdef SAMBA4_USES_HEIMDAL
	const char *self_service;
#endif
	const char *target_service;
	time_t kdc_time = 0;
	krb5_principal princ;
	krb5_principal impersonate_principal;
	int tries;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);
	krb5_get_init_creds_opt *krb_options;

	if (!mem_ctx) {
		(*error_string) = strerror(ENOMEM);
		return ENOMEM;
	}

	ret = principal_from_credentials(mem_ctx, credentials, smb_krb5_context, &princ, obtained, error_string);
	if (ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	if (princ == NULL) {
		(*error_string) = talloc_asprintf(credentials, "principal, username or realm was not specified in the credentials");
		talloc_free(mem_ctx);
		return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
	}

	ret = impersonate_principal_from_credentials(mem_ctx, credentials, smb_krb5_context, &impersonate_principal, error_string);
	if (ret) {
		talloc_free(mem_ctx);
		return ret;
	}

#ifdef SAMBA4_USES_HEIMDAL
	self_service = cli_credentials_get_self_service(credentials);
#endif
	target_service = cli_credentials_get_target_service(credentials);

	password = cli_credentials_get_password(credentials);

	/* setup the krb5 options we want */
	if ((ret = krb5_get_init_creds_opt_alloc(smb_krb5_context->krb5_context, &krb_options))) {
		(*error_string) = talloc_asprintf(credentials, "krb5_get_init_creds_opt_alloc failed (%s)\n",
						  smb_get_krb5_error_message(smb_krb5_context->krb5_context,
									     ret, mem_ctx));
		talloc_free(mem_ctx);
		return ret;
	}

#ifdef SAMBA4_USES_HEIMDAL /* Disable for now MIT reads defaults when needed */
	/* get the defaults */
	krb5_get_init_creds_opt_set_default_flags(smb_krb5_context->krb5_context, NULL, NULL, krb_options);
#endif
	/* set if we want a forwardable ticket */
	switch (cli_credentials_get_krb_forwardable(credentials)) {
	case CRED_AUTO_KRB_FORWARDABLE:
		break;
	case CRED_NO_KRB_FORWARDABLE:
		krb5_get_init_creds_opt_set_forwardable(krb_options, FALSE);
		break;
	case CRED_FORCE_KRB_FORWARDABLE:
		krb5_get_init_creds_opt_set_forwardable(krb_options, TRUE);
		break;
	}

#ifdef SAMBA4_USES_HEIMDAL /* FIXME: MIT does not have this yet */
	/*
	 * In order to work against windows KDCs even if we use
	 * the netbios domain name as realm, we need to add the following
	 * flags:
	 * KRB5_INIT_CREDS_NO_C_CANON_CHECK;
	 * KRB5_INIT_CREDS_NO_C_NO_EKU_CHECK;
	 *
	 * On MIT: Set pkinit_eku_checking to none
	 */
	krb5_get_init_creds_opt_set_win2k(smb_krb5_context->krb5_context,
					  krb_options, true);
	krb5_get_init_creds_opt_set_canonicalize(smb_krb5_context->krb5_context,
						 krb_options, true);
#else /* MIT */
	krb5_get_init_creds_opt_set_canonicalize(krb_options, true);
#endif

	tries = 2;
	while (tries--) {
#ifdef SAMBA4_USES_HEIMDAL
		struct tevent_context *previous_ev;
		/* Do this every time, in case we have weird recursive issues here */
		ret = smb_krb5_context_set_event_ctx(smb_krb5_context, event_ctx, &previous_ev);
		if (ret) {
			talloc_free(mem_ctx);
			return ret;
		}
#endif
		if (password) {
			if (impersonate_principal) {
#ifdef SAMBA4_USES_HEIMDAL
				ret = smb_krb5_kinit_s4u2_ccache(smb_krb5_context->krb5_context,
								 ccache,
								 princ,
								 password,
								 impersonate_principal,
								 self_service,
								 target_service,
								 krb_options,
								 NULL,
								 &kdc_time);
#else
				talloc_free(mem_ctx);
				(*error_string) = "INTERNAL error: s4u2 ops "
					"are not supported with MIT build yet";
				return EINVAL;
#endif
			} else {
				ret = smb_krb5_kinit_password_ccache(smb_krb5_context->krb5_context,
								     ccache,
								     princ,
								     password,
								     target_service,
								     krb_options,
								     NULL,
								     &kdc_time);
			}
		} else if (impersonate_principal) {
			talloc_free(mem_ctx);
			(*error_string) = "INTERNAL error: Cannot impersonate principal with just a keyblock.  A password must be specified in the credentials";
			return EINVAL;
		} else {
			/* No password available, try to use a keyblock instead */
			
			krb5_keyblock keyblock;
			const struct samr_Password *mach_pwd;
			mach_pwd = cli_credentials_get_nt_hash(credentials, mem_ctx);
			if (!mach_pwd) {
				talloc_free(mem_ctx);
				(*error_string) = "kinit_to_ccache: No password available for kinit\n";
				krb5_get_init_creds_opt_free(smb_krb5_context->krb5_context, krb_options);
#ifdef SAMBA4_USES_HEIMDAL
				smb_krb5_context_remove_event_ctx(smb_krb5_context, previous_ev, event_ctx);
#endif
				return EINVAL;
			}
			ret = smb_krb5_keyblock_init_contents(smb_krb5_context->krb5_context,
						 ENCTYPE_ARCFOUR_HMAC,
						 mach_pwd->hash, sizeof(mach_pwd->hash), 
						 &keyblock);
			
			if (ret == 0) {
				ret = smb_krb5_kinit_keyblock_ccache(smb_krb5_context->krb5_context,
								     ccache,
								     princ,
								     &keyblock,
								     target_service,
								     krb_options,
								     NULL,
								     &kdc_time);
				krb5_free_keyblock_contents(smb_krb5_context->krb5_context, &keyblock);
			}
		}

#ifdef SAMBA4_USES_HEIMDAL
		smb_krb5_context_remove_event_ctx(smb_krb5_context, previous_ev, event_ctx);
#endif

		if (ret == KRB5KRB_AP_ERR_SKEW || ret == KRB5_KDCREP_SKEW) {
			/* Perhaps we have been given an invalid skew, so try again without it */
			time_t t = time(NULL);
			krb5_set_real_time(smb_krb5_context->krb5_context, t, 0);
		} else {
			/* not a skew problem */
			break;
		}
	}

	krb5_get_init_creds_opt_free(smb_krb5_context->krb5_context, krb_options);

	if (ret == KRB5KRB_AP_ERR_SKEW || ret == KRB5_KDCREP_SKEW) {
		(*error_string) = talloc_asprintf(credentials, "kinit for %s failed (%s)\n",
						  cli_credentials_get_principal(credentials, mem_ctx),
						  smb_get_krb5_error_message(smb_krb5_context->krb5_context,
									     ret, mem_ctx));
		talloc_free(mem_ctx);
		return ret;
	}

	/* cope with ticket being in the future due to clock skew */
	if ((unsigned)kdc_time > time(NULL)) {
		time_t t = time(NULL);
		int time_offset =(unsigned)kdc_time-t;
		DEBUG(4,("Advancing clock by %d seconds to cope with clock skew\n", time_offset));
		krb5_set_real_time(smb_krb5_context->krb5_context, t + time_offset + 1, 0);
	}
	
	if (ret == KRB5KDC_ERR_PREAUTH_FAILED && cli_credentials_wrong_password(credentials)) {
		ret = kinit_to_ccache(parent_ctx,
				      credentials,
				      smb_krb5_context,
				      event_ctx,
				      ccache, obtained,
				      error_string);
	}

	if (ret) {
		(*error_string) = talloc_asprintf(credentials, "kinit for %s failed (%s)\n",
						  cli_credentials_get_principal(credentials, mem_ctx),
						  smb_get_krb5_error_message(smb_krb5_context->krb5_context,
									     ret, mem_ctx));
		talloc_free(mem_ctx);
		return ret;
	}

	DEBUG(10,("kinit for %s succeeded\n",
		cli_credentials_get_principal(credentials, mem_ctx)));


	talloc_free(mem_ctx);
	return 0;
}

static krb5_error_code free_keytab_container(struct keytab_container *ktc)
{
	return krb5_kt_close(ktc->smb_krb5_context->krb5_context, ktc->keytab);
}

krb5_error_code smb_krb5_get_keytab_container(TALLOC_CTX *mem_ctx,
				struct smb_krb5_context *smb_krb5_context,
				krb5_keytab opt_keytab,
				const char *keytab_name,
				struct keytab_container **ktc)
{
	krb5_keytab keytab;
	krb5_error_code ret;

	if (opt_keytab) {
		keytab = opt_keytab;
	} else {
		ret = krb5_kt_resolve(smb_krb5_context->krb5_context,
						keytab_name, &keytab);
		if (ret) {
			DEBUG(1,("failed to open krb5 keytab: %s\n",
				 smb_get_krb5_error_message(
					smb_krb5_context->krb5_context,
					ret, mem_ctx)));
			return ret;
		}
	}

	*ktc = talloc(mem_ctx, struct keytab_container);
	if (!*ktc) {
		return ENOMEM;
	}

	(*ktc)->smb_krb5_context = talloc_reference(*ktc, smb_krb5_context);
	(*ktc)->keytab = keytab;
	(*ktc)->password_based = false;
	talloc_set_destructor(*ktc, free_keytab_container);

	return 0;
}

/*
 * Walk the keytab, looking for entries of this principal name,
 * with KVNO other than current kvno -1.
 *
 * These entries are now stale,
 * we only keep the current and previous entries around.
 *
 * Inspired by the code in Samba3 for 'use kerberos keytab'.
 */
krb5_error_code smb_krb5_remove_obsolete_keytab_entries(TALLOC_CTX *mem_ctx,
							krb5_context context,
							krb5_keytab keytab,
							uint32_t num_principals,
							krb5_principal *principals,
							krb5_kvno kvno,
							bool *found_previous,
							const char **error_string)
{
	TALLOC_CTX *tmp_ctx;
	krb5_error_code code;
	krb5_kt_cursor cursor;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		*error_string = "Cannot allocate tmp_ctx";
		return ENOMEM;
	}

	*found_previous = true;

	code = krb5_kt_start_seq_get(context, keytab, &cursor);
	switch (code) {
	case 0:
		break;
#ifdef HEIM_ERR_OPNOTSUPP
	case HEIM_ERR_OPNOTSUPP:
#endif
	case ENOENT:
	case KRB5_KT_END:
		/* no point enumerating if there isn't anything here */
		code = 0;
		goto done;
	default:
		*error_string = talloc_asprintf(mem_ctx,
						"failed to open keytab for read of old entries: %s\n",
						smb_get_krb5_error_message(context, code, mem_ctx));
		goto done;
	}

	do {
		krb5_kvno old_kvno = kvno - 1;
		krb5_keytab_entry entry;
		bool matched = false;
		uint32_t i;

		code = krb5_kt_next_entry(context, keytab, &entry, &cursor);
		if (code) {
			break;
		}

		for (i = 0; i < num_principals; i++) {
			krb5_boolean ok;

			ok = smb_krb5_kt_compare(context,
						&entry,
						principals[i],
						0,
						0);
			if (ok) {
				matched = true;
				break;
			}
		}

		if (!matched) {
			/*
			 * Free the entry, it wasn't the one we were looking
			 * for anyway
			 */
			krb5_kt_free_entry(context, &entry);
			/* Make sure we do not double free */
			ZERO_STRUCT(entry);
			continue;
		}

		/*
		 * Delete it, if it is not kvno - 1.
		 *
		 * Some keytab files store the kvno only in 8bits. Limit the
		 * compare to 8bits, so that we don't miss old keys and delete
		 * them.
		 */
		if ((entry.vno & 0xff) != (old_kvno & 0xff)) {
			krb5_error_code rc;

			/* Release the enumeration.  We are going to
			 * have to start this from the top again,
			 * because deletes during enumeration may not
			 * always be consistent.
			 *
			 * Also, the enumeration locks a FILE: keytab
			 */
			krb5_kt_end_seq_get(context, keytab, &cursor);

			code = krb5_kt_remove_entry(context, keytab, &entry);
			krb5_kt_free_entry(context, &entry);

			/* Make sure we do not double free */
			ZERO_STRUCT(entry);

			/* Deleted: Restart from the top */
			rc = krb5_kt_start_seq_get(context, keytab, &cursor);
			if (rc != 0) {
				krb5_kt_free_entry(context, &entry);

				/* Make sure we do not double free */
				ZERO_STRUCT(entry);

				DEBUG(1, ("failed to restart enumeration of keytab: %s\n",
					  smb_get_krb5_error_message(context,
								     code,
								     tmp_ctx)));

				talloc_free(tmp_ctx);
				return rc;
			}

			if (code != 0) {
				break;
			}

		} else {
			*found_previous = true;
		}

		/* Free the entry, we don't need it any more */
		krb5_kt_free_entry(context, &entry);
		/* Make sure we do not double free */
		ZERO_STRUCT(entry);
	} while (code == 0);

	krb5_kt_end_seq_get(context, keytab, &cursor);

	switch (code) {
	case 0:
		break;
	case ENOENT:
	case KRB5_KT_END:
		break;
	default:
		*error_string = talloc_asprintf(mem_ctx,
						"failed in deleting old entries for principal: %s\n",
						smb_get_krb5_error_message(context,
									   code,
									   mem_ctx));
	}

	code = 0;
done:
	talloc_free(tmp_ctx);
	return code;
}
