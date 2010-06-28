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

struct principal_container {
	struct smb_krb5_context *smb_krb5_context;
	krb5_principal principal;
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
		(*error_string) = smb_get_krb5_error_message(smb_krb5_context->krb5_context, ret, parent_ctx);
		return ret;
	}

	mem_ctx = talloc(parent_ctx, struct principal_container);
	if (!mem_ctx) {
		(*error_string) = error_message(ENOMEM);
		return ENOMEM;
	}

	/* This song-and-dance effectivly puts the principal
	 * into talloc, so we can't loose it. */
	mem_ctx->smb_krb5_context = talloc_reference(mem_ctx, smb_krb5_context);
	mem_ctx->principal = *princ;
	talloc_set_destructor(mem_ctx, free_principal);
	return 0;
}

static krb5_error_code salt_principal_from_credentials(TALLOC_CTX *parent_ctx, 
						       struct cli_credentials *machine_account, 
						       struct smb_krb5_context *smb_krb5_context,
						       krb5_principal *salt_princ)
{
	krb5_error_code ret;
	char *machine_username;
	char *salt_body;
	char *lower_realm;
	const char *salt_principal;
	const char *error_string;
	struct principal_container *mem_ctx = talloc(parent_ctx, struct principal_container);
	if (!mem_ctx) {
		return ENOMEM;
	}

	salt_principal = cli_credentials_get_salt_principal(machine_account);
	if (salt_principal) {
		ret = parse_principal(parent_ctx, salt_principal, smb_krb5_context, salt_princ, &error_string);
	} else {
		machine_username = talloc_strdup(mem_ctx, cli_credentials_get_username(machine_account));
		
		if (!machine_username) {
			talloc_free(mem_ctx);
			return ENOMEM;
		}
		
		if (machine_username[strlen(machine_username)-1] == '$') {
			machine_username[strlen(machine_username)-1] = '\0';
		}
		lower_realm = strlower_talloc(mem_ctx, cli_credentials_get_realm(machine_account));
		if (!lower_realm) {
			talloc_free(mem_ctx);
			return ENOMEM;
		}
		
		salt_body = talloc_asprintf(mem_ctx, "%s.%s", machine_username, 
					    lower_realm);
		if (!salt_body) {
			talloc_free(mem_ctx);
		return ENOMEM;
		}
		
		ret = krb5_make_principal(smb_krb5_context->krb5_context, salt_princ, 
					  cli_credentials_get_realm(machine_account), 
					  "host", salt_body, NULL);
		if (ret == 0) {
			/* This song-and-dance effectivly puts the principal
			 * into talloc, so we can't loose it. */
			mem_ctx->smb_krb5_context = talloc_reference(mem_ctx, smb_krb5_context);
			mem_ctx->principal = *salt_princ;
			talloc_set_destructor(mem_ctx, free_principal);
		}
	} 

	return ret;
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
	if (!mem_ctx) {
		(*error_string) = error_message(ENOMEM);
		return ENOMEM;
	}
	princ_string = cli_credentials_get_principal_and_obtained(credentials, mem_ctx, obtained);
	if (!princ_string) {
		(*error_string) = error_message(ENOMEM);
		return ENOMEM;
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

 krb5_error_code impersonate_principal_from_credentials(TALLOC_CTX *parent_ctx,
							struct cli_credentials *credentials,
							struct smb_krb5_context *smb_krb5_context,
							krb5_principal *princ,
							const char **error_string)
{
	return parse_principal(parent_ctx, cli_credentials_get_impersonate_principal(credentials),
			       smb_krb5_context, princ, error_string);
}

/**
 * Return a freshly allocated ccache (destroyed by destructor on child
 * of parent_ctx), for a given set of client credentials 
 */

 krb5_error_code kinit_to_ccache(TALLOC_CTX *parent_ctx,
				 struct cli_credentials *credentials,
				 struct smb_krb5_context *smb_krb5_context,
				 krb5_ccache ccache,
				 enum credentials_obtained *obtained,
				 const char **error_string)
{
	krb5_error_code ret;
	const char *password, *target_service;
	time_t kdc_time = 0;
	krb5_principal princ;
	krb5_principal impersonate_principal;
	int tries;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);

	if (!mem_ctx) {
		(*error_string) = strerror(ENOMEM);
		return ENOMEM;
	}

	ret = principal_from_credentials(mem_ctx, credentials, smb_krb5_context, &princ, obtained, error_string);
	if (ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	ret = impersonate_principal_from_credentials(mem_ctx, credentials, smb_krb5_context, &impersonate_principal, error_string);
	if (ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	target_service = cli_credentials_get_target_service(credentials);

	password = cli_credentials_get_password(credentials);

	tries = 2;
	while (tries--) {
		if (password) {
			ret = kerberos_kinit_password_cc(smb_krb5_context->krb5_context, ccache, 
							 princ, password,
							 impersonate_principal, target_service,
							 NULL, &kdc_time);
		} else if (impersonate_principal) {
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
				return EINVAL;
			}
			ret = krb5_keyblock_init(smb_krb5_context->krb5_context,
						 ENCTYPE_ARCFOUR_HMAC,
						 mach_pwd->hash, sizeof(mach_pwd->hash), 
						 &keyblock);
			
			if (ret == 0) {
				ret = kerberos_kinit_keyblock_cc(smb_krb5_context->krb5_context, ccache, 
								 princ, &keyblock,
								 target_service,
								 NULL, &kdc_time);
				krb5_free_keyblock_contents(smb_krb5_context->krb5_context, &keyblock);
			}
		}

		if (ret == KRB5KRB_AP_ERR_SKEW || ret == KRB5_KDCREP_SKEW) {
			/* Perhaps we have been given an invalid skew, so try again without it */
			time_t t = time(NULL);
			krb5_set_real_time(smb_krb5_context->krb5_context, t, 0);
		} else {
			/* not a skew problem */
			break;
		}
	}

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
	talloc_free(mem_ctx);
	return 0;
}

static krb5_error_code free_keytab(struct keytab_container *ktc)
{
	return krb5_kt_close(ktc->smb_krb5_context->krb5_context, ktc->keytab);
}

krb5_error_code smb_krb5_open_keytab(TALLOC_CTX *mem_ctx,
			 struct smb_krb5_context *smb_krb5_context, 
			 const char *keytab_name, struct keytab_container **ktc) 
{
	krb5_keytab keytab;
	krb5_error_code ret;
	ret = krb5_kt_resolve(smb_krb5_context->krb5_context, keytab_name, &keytab);
	if (ret) {
		DEBUG(1,("failed to open krb5 keytab: %s\n", 
			 smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
						    ret, mem_ctx)));
		return ret;
	}

	*ktc = talloc(mem_ctx, struct keytab_container);
	if (!*ktc) {
		return ENOMEM;
	}

	(*ktc)->smb_krb5_context = talloc_reference(*ktc, smb_krb5_context);
	(*ktc)->keytab = keytab;
	talloc_set_destructor(*ktc, free_keytab);

	return 0;
}

static krb5_error_code keytab_add_keys(TALLOC_CTX *parent_ctx,
				       const char *princ_string,
				       krb5_principal princ,
				       krb5_principal salt_princ,
				       int kvno,
				       const char *password_s,
				       struct smb_krb5_context *smb_krb5_context,
				       const char **enctype_strings,
				       krb5_keytab keytab)
{
	int i;
	krb5_error_code ret;
	krb5_data password;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);
	if (!mem_ctx) {
		return ENOMEM;
	}

	password.data = discard_const_p(char *, password_s);
	password.length = strlen(password_s);

	for (i=0; enctype_strings[i]; i++) {
		krb5_keytab_entry entry;
		krb5_enctype enctype;
		ret = krb5_string_to_enctype(smb_krb5_context->krb5_context, enctype_strings[i], &enctype);
		if (ret != 0) {
			DEBUG(1, ("Failed to interpret %s as a krb5 encryption type: %s\n",				  
				  enctype_strings[i],
				  smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
							     ret, mem_ctx)));
			talloc_free(mem_ctx);
			return ret;
		}
		ret = create_kerberos_key_from_string(smb_krb5_context->krb5_context, 
						      salt_princ, &password, &entry.keyblock, enctype);
		if (ret != 0) {
			talloc_free(mem_ctx);
			return ret;
		}

                entry.principal = princ;
                entry.vno       = kvno;
		ret = krb5_kt_add_entry(smb_krb5_context->krb5_context, keytab, &entry);
		if (ret != 0) {
			DEBUG(1, ("Failed to add %s entry for %s(kvno %d) to keytab: %s\n",
				  enctype_strings[i],
				  princ_string,
				  kvno,
				  smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
							     ret, mem_ctx)));
			talloc_free(mem_ctx);
			krb5_free_keyblock_contents(smb_krb5_context->krb5_context, &entry.keyblock);
			return ret;
		}

		DEBUG(5, ("Added %s(kvno %d) to keytab (%s)\n", 
			  princ_string, kvno,
			  enctype_strings[i]));
		
		krb5_free_keyblock_contents(smb_krb5_context->krb5_context, &entry.keyblock);
	}
	talloc_free(mem_ctx);
	return 0;
}

static krb5_error_code create_keytab(TALLOC_CTX *parent_ctx,
			 struct cli_credentials *machine_account,
			 struct smb_krb5_context *smb_krb5_context,
			 const char **enctype_strings,
			 krb5_keytab keytab,
			 bool add_old) 
{
	krb5_error_code ret;
	const char *password_s;
	const char *old_secret;
	int kvno;
	krb5_principal salt_princ;
	krb5_principal princ;
	const char *princ_string;
	const char *error_string;
	enum credentials_obtained obtained;

	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);
	if (!mem_ctx) {
		return ENOMEM;
	}

	princ_string = cli_credentials_get_principal(machine_account, mem_ctx);
	/* Get the principal we will store the new keytab entries under */
	ret = principal_from_credentials(mem_ctx, machine_account, smb_krb5_context, &princ, &obtained, &error_string);
	if (ret) {
		DEBUG(1,("create_keytab: makeing krb5 principal failed (%s)\n", error_string));
		talloc_free(mem_ctx);
		return ret;
	}

	/* The salt used to generate these entries may be different however, fetch that */
	ret = salt_principal_from_credentials(mem_ctx, machine_account, 
					      smb_krb5_context, 
					      &salt_princ);
	if (ret) {
		DEBUG(1,("create_keytab: makeing salt principal failed (%s)\n",
			 smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
						    ret, mem_ctx)));
		talloc_free(mem_ctx);
		return ret;
	}

	/* Finally, do the dance to get the password to put in the entry */
	password_s = cli_credentials_get_password(machine_account);
	if (!password_s) {
		krb5_keytab_entry entry;
		const struct samr_Password *mach_pwd;

		if (!str_list_check(enctype_strings, "arcfour-hmac-md5")) {
			DEBUG(1, ("Asked to create keytab, but with only an NT hash supplied, "
				  "but not listing arcfour-hmac-md5 as an enc type to include in the keytab!\n"));
			talloc_free(mem_ctx);
			return EINVAL;
		}

		/* If we don't have the plaintext password, try for
		 * the MD4 password hash */
		mach_pwd = cli_credentials_get_nt_hash(machine_account, mem_ctx);
		if (!mach_pwd) {
			/* OK, nothing to do here */
			talloc_free(mem_ctx);
			return 0;
		}
		ret = krb5_keyblock_init(smb_krb5_context->krb5_context,
					 ETYPE_ARCFOUR_HMAC_MD5,
					 mach_pwd->hash, sizeof(mach_pwd->hash), 
					 &entry.keyblock);
		if (ret) {
			DEBUG(1, ("create_keytab: krb5_keyblock_init failed: %s\n",
				  smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
							     ret, mem_ctx)));
			talloc_free(mem_ctx);
			return ret;
		}

		entry.principal = princ;
		entry.vno       = cli_credentials_get_kvno(machine_account);
		ret = krb5_kt_add_entry(smb_krb5_context->krb5_context, keytab, &entry);
		if (ret) {
			DEBUG(1, ("Failed to add ARCFOUR_HMAC (only) entry for %s to keytab: %s",
				  cli_credentials_get_principal(machine_account, mem_ctx), 
				  smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
							     ret, mem_ctx)));
			talloc_free(mem_ctx);
			krb5_free_keyblock_contents(smb_krb5_context->krb5_context, &entry.keyblock);
			return ret;
		}
		
		DEBUG(5, ("Added %s(kvno %d) to keytab (arcfour-hmac-md5)\n", 
			  cli_credentials_get_principal(machine_account, mem_ctx),
			  cli_credentials_get_kvno(machine_account)));

		krb5_free_keyblock_contents(smb_krb5_context->krb5_context, &entry.keyblock);

		/* Can't go any further, we only have this one key */
		talloc_free(mem_ctx);
		return 0;
	}
	
	kvno = cli_credentials_get_kvno(machine_account);
	/* good, we actually have the real plaintext */
	ret = keytab_add_keys(mem_ctx, princ_string, princ, salt_princ, 
			      kvno, password_s, smb_krb5_context, 
			      enctype_strings, keytab);
	if (!ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	if (!add_old || kvno == 0) {
		talloc_free(mem_ctx);
		return 0;
	}

	old_secret = cli_credentials_get_old_password(machine_account);
	if (!old_secret) {
		talloc_free(mem_ctx);
		return 0;
	}
	
	ret = keytab_add_keys(mem_ctx, princ_string, princ, salt_princ, 
			      kvno - 1, old_secret, smb_krb5_context, 
			      enctype_strings, keytab);
	if (!ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	talloc_free(mem_ctx);
	return 0;
}


/*
 * Walk the keytab, looking for entries of this principal name, with KVNO other than current kvno -1.
 *
 * These entries are now stale, we only keep the current, and previous entries around.
 *
 * Inspired by the code in Samba3 for 'use kerberos keytab'.
 *
 */

static krb5_error_code remove_old_entries(TALLOC_CTX *parent_ctx,
					  struct cli_credentials *machine_account,
					  struct smb_krb5_context *smb_krb5_context,
					  krb5_keytab keytab, bool *found_previous)
{
	krb5_error_code ret, ret2;
	krb5_kt_cursor cursor;
	krb5_principal princ;
	int kvno;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);
	const char *princ_string;
	const char *error_string;
	enum credentials_obtained obtained;

	if (!mem_ctx) {
		return ENOMEM;
	}

	*found_previous = false;
	princ_string = cli_credentials_get_principal(machine_account, mem_ctx);

	/* Get the principal we will store the new keytab entries under */
	ret = principal_from_credentials(mem_ctx, machine_account, smb_krb5_context, &princ, &obtained, &error_string);
	if (ret) {
		DEBUG(1,("update_keytab: makeing krb5 principal failed (%s)\n", error_string));
		talloc_free(mem_ctx);
		return ret;
	}

	kvno = cli_credentials_get_kvno(machine_account);

	/* for each entry in the keytab */
	ret = krb5_kt_start_seq_get(smb_krb5_context->krb5_context, keytab, &cursor);
	switch (ret) {
	case 0:
		break;
	case HEIM_ERR_OPNOTSUPP:
	case ENOENT:
	case KRB5_KT_END:
		/* no point enumerating if there isn't anything here */
		talloc_free(mem_ctx);
		return 0;
	default:
		DEBUG(1,("failed to open keytab for read of old entries: %s\n",
			 smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
						    ret, mem_ctx)));
		talloc_free(mem_ctx);
		return ret;
	}

	while (!ret) {
		krb5_keytab_entry entry;
		ret = krb5_kt_next_entry(smb_krb5_context->krb5_context, keytab, &entry, &cursor);
		if (ret) {
			break;
		}
		/* if it matches our principal */
		if (!krb5_kt_compare(smb_krb5_context->krb5_context, &entry, princ, 0, 0)) {
			/* Free the entry, it wasn't the one we were looking for anyway */
			krb5_kt_free_entry(smb_krb5_context->krb5_context, &entry);
			continue;
		}

		/* delete it, if it is not kvno -1 */
		if (entry.vno != (kvno - 1 )) {
			/* Release the enumeration.  We are going to
			 * have to start this from the top again,
			 * because deletes during enumeration may not
			 * always be consistant.
			 *
			 * Also, the enumeration locks a FILE: keytab
			 */
		
			krb5_kt_end_seq_get(smb_krb5_context->krb5_context, keytab, &cursor);

			ret = krb5_kt_remove_entry(smb_krb5_context->krb5_context, keytab, &entry);
			krb5_kt_free_entry(smb_krb5_context->krb5_context, &entry);

			/* Deleted: Restart from the top */
			ret2 = krb5_kt_start_seq_get(smb_krb5_context->krb5_context, keytab, &cursor);
			if (ret2) {
				krb5_kt_free_entry(smb_krb5_context->krb5_context, &entry);
				DEBUG(1,("failed to restart enumeration of keytab: %s\n",
					 smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
								    ret, mem_ctx)));
				
				talloc_free(mem_ctx);
				return ret2;
			}

			if (ret) {
				break;
			}
			
		} else {
			*found_previous = true;
		}
		
		/* Free the entry, we don't need it any more */
		krb5_kt_free_entry(smb_krb5_context->krb5_context, &entry);
		
		
	}
	krb5_kt_end_seq_get(smb_krb5_context->krb5_context, keytab, &cursor);

	switch (ret) {
	case 0:
		break;
	case ENOENT:
	case KRB5_KT_END:
		ret = 0;
		break;
	default:
		DEBUG(1,("failed in deleting old entries for principal: %s: %s\n",
			 princ_string, 
			 smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
						    ret, mem_ctx)));
	}
	talloc_free(mem_ctx);
	return ret;
}

krb5_error_code smb_krb5_update_keytab(TALLOC_CTX *parent_ctx,
			   struct cli_credentials *machine_account,
			   struct smb_krb5_context *smb_krb5_context,
			   const char **enctype_strings,
			   struct keytab_container *keytab_container) 
{
	krb5_error_code ret;
	bool found_previous;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);
	if (!mem_ctx) {
		return ENOMEM;
	}

	ret = remove_old_entries(mem_ctx, machine_account, 
				 smb_krb5_context, keytab_container->keytab, &found_previous);
	if (ret != 0) {
		talloc_free(mem_ctx);
		return ret;
	}
	
	/* Create a new keytab.  If during the cleanout we found
	 * entires for kvno -1, then don't try and duplicate them.
	 * Otherwise, add kvno, and kvno -1 */
	
	ret = create_keytab(mem_ctx, machine_account, smb_krb5_context, 
			    enctype_strings, 
			    keytab_container->keytab, 
			    found_previous ? false : true);
	talloc_free(mem_ctx);
	return ret;
}

krb5_error_code smb_krb5_create_memory_keytab(TALLOC_CTX *parent_ctx,
					   struct cli_credentials *machine_account,
					   struct smb_krb5_context *smb_krb5_context,
					   const char **enctype_strings,
					   struct keytab_container **keytab_container) 
{
	krb5_error_code ret;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);
	const char *rand_string;
	const char *keytab_name;
	if (!mem_ctx) {
		return ENOMEM;
	}
	
	*keytab_container = talloc(mem_ctx, struct keytab_container);

	rand_string = generate_random_str(mem_ctx, 16);
	if (!rand_string) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	keytab_name = talloc_asprintf(mem_ctx, "MEMORY:%s", 
				      rand_string);
	if (!keytab_name) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	ret = smb_krb5_open_keytab(mem_ctx, smb_krb5_context, keytab_name, keytab_container);
	if (ret) {
		return ret;
	}

	ret = smb_krb5_update_keytab(mem_ctx, machine_account, smb_krb5_context, enctype_strings, *keytab_container);
	if (ret == 0) {
		talloc_steal(parent_ctx, *keytab_container);
	} else {
		*keytab_container = NULL;
	}
	talloc_free(mem_ctx);
	return ret;
}

/* Translate between the IETF encryption type values and the Microsoft msDS-SupportedEncryptionTypes values */
uint32_t kerberos_enctype_to_bitmap(krb5_enctype enc_type_enum)
{
	switch (enc_type_enum) {
	case ENCTYPE_DES_CBC_CRC:
		return ENC_CRC32;
	case ENCTYPE_DES_CBC_MD5:
		return ENC_RSA_MD5;
	case ENCTYPE_ARCFOUR_HMAC_MD5:
		return ENC_RC4_HMAC_MD5;
	case ENCTYPE_AES128_CTS_HMAC_SHA1_96:
		return ENC_HMAC_SHA1_96_AES128;
	case ENCTYPE_AES256_CTS_HMAC_SHA1_96:
		return ENC_HMAC_SHA1_96_AES256;
	default:
		return 0;
	}
}

/* Translate between the Microsoft msDS-SupportedEncryptionTypes values and the IETF encryption type values */
krb5_enctype kerberos_enctype_bitmap_to_enctype(uint32_t enctype_bitmap)
{
	switch (enctype_bitmap) {
	case ENC_CRC32:
		return ENCTYPE_DES_CBC_CRC;
	case ENC_RSA_MD5:
		return ENCTYPE_DES_CBC_MD5;
	case ENC_RC4_HMAC_MD5:
		return ENCTYPE_ARCFOUR_HMAC_MD5;
	case ENC_HMAC_SHA1_96_AES128:
		return ENCTYPE_AES128_CTS_HMAC_SHA1_96;
	case ENC_HMAC_SHA1_96_AES256:
		return ENCTYPE_AES256_CTS_HMAC_SHA1_96;
	default:
		return 0;
	}
}

/* Return an array of krb5_enctype values */
krb5_error_code kerberos_enctype_bitmap_to_enctypes(TALLOC_CTX *mem_ctx, uint32_t enctype_bitmap, krb5_enctype **enctypes)
{
	unsigned int i, j = 0;
	*enctypes = talloc_zero_array(mem_ctx, krb5_enctype, 8*sizeof(enctype_bitmap));
	if (!*enctypes) {
		return ENOMEM;
	}
	for (i=0; i<(8*sizeof(enctype_bitmap)); i++) {
		if ((1 << i) & enctype_bitmap) {
			(*enctypes)[j] = kerberos_enctype_bitmap_to_enctype(enctype_bitmap);
			if (!(*enctypes)[j]) {
				return KRB5_PROG_ETYPE_NOSUPP;
			}
			j++;
		}
	}
	return 0;
}
