/*
 *  GSSAPI Security Extensions
 *  Krb5 helpers
 *  Copyright (C) Simo Sorce 2010.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smb_krb5.h"
#include "secrets.h"
#include "librpc/gen_ndr/secrets.h"
#include "gse_krb5.h"
#include "lib/param/loadparm.h"
#include "libads/kerberos_proto.h"

#ifdef HAVE_KRB5

static krb5_error_code flush_keytab(krb5_context krbctx, krb5_keytab keytab)
{
	krb5_error_code ret;
	krb5_kt_cursor kt_cursor;
	krb5_keytab_entry kt_entry;

	ZERO_STRUCT(kt_entry);

	ret = krb5_kt_start_seq_get(krbctx, keytab, &kt_cursor);
	if (ret == KRB5_KT_END || ret == ENOENT ) {
		/* no entries */
		return 0;
	}

	ret = krb5_kt_next_entry(krbctx, keytab, &kt_entry, &kt_cursor);
	while (ret == 0) {

		/* we need to close and reopen enumeration because we modify
		 * the keytab */
		ret = krb5_kt_end_seq_get(krbctx, keytab, &kt_cursor);
		if (ret) {
			DEBUG(1, (__location__ ": krb5_kt_end_seq_get() "
				  "failed (%s)\n", error_message(ret)));
			goto out;
		}

		/* remove the entry */
		ret = krb5_kt_remove_entry(krbctx, keytab, &kt_entry);
		if (ret) {
			DEBUG(1, (__location__ ": krb5_kt_remove_entry() "
				  "failed (%s)\n", error_message(ret)));
			goto out;
		}
		smb_krb5_kt_free_entry(krbctx, &kt_entry);
		ZERO_STRUCT(kt_entry);

		/* now reopen */
		ret = krb5_kt_start_seq_get(krbctx, keytab, &kt_cursor);
		if (ret) {
			DEBUG(1, (__location__ ": krb5_kt_start_seq() failed "
				  "(%s)\n", error_message(ret)));
			goto out;
		}

		ret = krb5_kt_next_entry(krbctx, keytab,
					 &kt_entry, &kt_cursor);
	}

	if (ret != KRB5_KT_END && ret != ENOENT) {
		DEBUG(1, (__location__ ": flushing keytab we got [%s]!\n",
			  error_message(ret)));
	}

	ret = 0;

out:
	return ret;
}

static krb5_error_code fill_keytab_from_password(krb5_context krbctx,
						 krb5_keytab keytab,
						 krb5_principal princ,
						 krb5_kvno vno,
						 struct secrets_domain_info1_password *pw)
{
	krb5_error_code ret;
	krb5_enctype *enctypes;
	uint16_t i;

	ret = smb_krb5_get_allowed_etypes(krbctx, &enctypes);
	if (ret) {
		DEBUG(1, (__location__
			  ": Can't determine permitted enctypes!\n"));
		return ret;
	}

	for (i = 0; i < pw->num_keys; i++) {
		krb5_keytab_entry kt_entry;
		krb5_keyblock *key = NULL;
		unsigned int ei;
		bool found_etype = false;

		for (ei=0; enctypes[ei] != 0; ei++) {
			if ((uint32_t)enctypes[ei] != pw->keys[i].keytype) {
				continue;
			}

			found_etype = true;
			break;
		}

		if (!found_etype) {
			continue;
		}

		ZERO_STRUCT(kt_entry);
		kt_entry.principal = princ;
		kt_entry.vno = vno;

		key = KRB5_KT_KEY(&kt_entry);
		KRB5_KEY_TYPE(key) = pw->keys[i].keytype;
		KRB5_KEY_DATA(key) = pw->keys[i].value.data;
		KRB5_KEY_LENGTH(key) = pw->keys[i].value.length;

		ret = krb5_kt_add_entry(krbctx, keytab, &kt_entry);
		if (ret) {
			DEBUG(1, (__location__ ": Failed to add entry to "
				  "keytab for enctype %d (error: %s)\n",
				  (unsigned)pw->keys[i].keytype,
				  error_message(ret)));
			goto out;
		}
	}

	ret = 0;

out:
	SAFE_FREE(enctypes);
	return ret;
}

#define SRV_MEM_KEYTAB_NAME "MEMORY:cifs_srv_keytab"
#define CLEARTEXT_PRIV_ENCTYPE -99

static krb5_error_code fill_mem_keytab_from_secrets(krb5_context krbctx,
						    krb5_keytab *keytab)
{
	TALLOC_CTX *frame = talloc_stackframe();
	krb5_error_code ret;
	const char *domain = lp_workgroup();
	struct secrets_domain_info1 *info = NULL;
	const char *realm = NULL;
	const DATA_BLOB *ct = NULL;
	krb5_kt_cursor kt_cursor;
	krb5_keytab_entry kt_entry;
	krb5_principal princ = NULL;
	krb5_kvno kvno = 0; /* FIXME: fetch current vno from KDC ? */
	NTSTATUS status;

	if (!secrets_init()) {
		DEBUG(1, (__location__ ": secrets_init failed\n"));
		TALLOC_FREE(frame);
		return KRB5_CONFIG_CANTOPEN;
	}

	status = secrets_fetch_or_upgrade_domain_info(domain,
						      frame,
						      &info);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("secrets_fetch_or_upgrade_domain_info(%s) - %s\n",
			    domain, nt_errstr(status));
		TALLOC_FREE(frame);
		return KRB5_LIBOS_CANTREADPWD;
	}
	ct = &info->password->cleartext_blob;

	if (info->domain_info.dns_domain.string != NULL) {
		realm = strupper_talloc(frame,
				info->domain_info.dns_domain.string);
		if (realm == NULL) {
			TALLOC_FREE(frame);
			return ENOMEM;
		}
	}

	ZERO_STRUCT(kt_entry);
	ZERO_STRUCT(kt_cursor);

	/* check if the keytab already has any entry */
	ret = krb5_kt_start_seq_get(krbctx, *keytab, &kt_cursor);
	if (ret != KRB5_KT_END && ret != ENOENT ) {
		/* check if we have our special enctype used to hold
		 * the clear text password. If so, check it out so that
		 * we can verify if the keytab needs to be upgraded */
		while ((ret = krb5_kt_next_entry(krbctx, *keytab,
					   &kt_entry, &kt_cursor)) == 0) {
			if (smb_krb5_kt_get_enctype_from_entry(&kt_entry) ==
			    CLEARTEXT_PRIV_ENCTYPE) {
				break;
			}
			smb_krb5_kt_free_entry(krbctx, &kt_entry);
			ZERO_STRUCT(kt_entry);
		}

		if (ret != 0 && ret != KRB5_KT_END && ret != ENOENT ) {
			/* Error parsing keytab */
			DEBUG(1, (__location__ ": Failed to parse memory "
				  "keytab!\n"));
			goto out;
		}

		if (ret == 0) {
			/* found private entry,
			 * check if keytab is up to date */

			if ((ct->length == KRB5_KEY_LENGTH(KRB5_KT_KEY(&kt_entry))) &&
			    (memcmp(KRB5_KEY_DATA(KRB5_KT_KEY(&kt_entry)),
						ct->data, ct->length) == 0)) {
				/* keytab is already up to date, return */
				smb_krb5_kt_free_entry(krbctx, &kt_entry);
				goto out;
			}

			smb_krb5_kt_free_entry(krbctx, &kt_entry);
			ZERO_STRUCT(kt_entry);


			/* flush keytab, we need to regen it */
			ret = flush_keytab(krbctx, *keytab);
			if (ret) {
				DEBUG(1, (__location__ ": Failed to flush "
					  "memory keytab!\n"));
				goto out;
			}
		}
	}

	if (!all_zero((uint8_t *)&kt_cursor, sizeof(kt_cursor)) && *keytab) {
		krb5_kt_end_seq_get(krbctx, *keytab, &kt_cursor);
	}

	/* keytab is not up to date, fill it up */

	ret = smb_krb5_make_principal(krbctx, &princ, realm,
				      info->account_name, NULL);
	if (ret) {
		DEBUG(1, (__location__ ": Failed to get host principal!\n"));
		goto out;
	}

	ret = fill_keytab_from_password(krbctx, *keytab,
					princ, kvno,
					info->password);
	if (ret) {
		DBG_WARNING("fill_keytab_from_password() failed for "
			    "info->password.\n.");
		goto out;
	}

	if (info->old_password != NULL) {
		ret = fill_keytab_from_password(krbctx, *keytab,
						princ, kvno - 1,
						info->old_password);
		if (ret) {
			DBG_WARNING("fill_keytab_from_password() failed for "
				    "info->old_password.\n.");
			goto out;
		}
	}

	if (info->older_password != NULL) {
		ret = fill_keytab_from_password(krbctx, *keytab,
						princ, kvno - 2,
						info->older_password);
		if (ret) {
			DBG_WARNING("fill_keytab_from_password() failed for "
				    "info->older_password.\n.");
			goto out;
		}
	}

	if (info->next_change != NULL) {
		ret = fill_keytab_from_password(krbctx, *keytab,
						princ, kvno - 3,
						info->next_change->password);
		if (ret) {
			DBG_WARNING("fill_keytab_from_password() failed for "
				    "info->next_change->password.\n.");
			goto out;
		}
	}

	/* add our private enctype + cleartext password so that we can
	 * update the keytab if secrets change later on */
	ZERO_STRUCT(kt_entry);
	kt_entry.principal = princ;
	kt_entry.vno = 0;

	KRB5_KEY_TYPE(KRB5_KT_KEY(&kt_entry)) = CLEARTEXT_PRIV_ENCTYPE;
	KRB5_KEY_LENGTH(KRB5_KT_KEY(&kt_entry)) = ct->length;
	KRB5_KEY_DATA(KRB5_KT_KEY(&kt_entry)) = ct->data;

	ret = krb5_kt_add_entry(krbctx, *keytab, &kt_entry);
	if (ret) {
		DEBUG(1, (__location__ ": Failed to add entry to "
			  "keytab for private enctype (%d) (error: %s)\n",
			   CLEARTEXT_PRIV_ENCTYPE, error_message(ret)));
		goto out;
	}

	ret = 0;

out:
	if (!all_zero((uint8_t *)&kt_cursor, sizeof(kt_cursor)) && *keytab) {
		krb5_kt_end_seq_get(krbctx, *keytab, &kt_cursor);
	}

	if (princ) {
		krb5_free_principal(krbctx, princ);
	}

	TALLOC_FREE(frame);
	return ret;
}

static krb5_error_code fill_mem_keytab_from_system_keytab(krb5_context krbctx,
							  krb5_keytab *mkeytab)
{
	krb5_error_code ret = 0;
	krb5_keytab keytab = NULL;
	krb5_kt_cursor kt_cursor = { 0, };
	krb5_keytab_entry kt_entry = { 0, };
	char *valid_princ_formats[7] = { NULL, NULL, NULL,
					 NULL, NULL, NULL, NULL };
	char *entry_princ_s = NULL;
	fstring my_name, my_fqdn;
	unsigned i;
	int err;

	/* Generate the list of principal names which we expect
	 * clients might want to use for authenticating to the file
	 * service.  We allow name$,{host,cifs}/{name,fqdn,name.REALM}. */

	fstrcpy(my_name, lp_netbios_name());

	my_fqdn[0] = '\0';
	name_to_fqdn(my_fqdn, lp_netbios_name());

	err = asprintf(&valid_princ_formats[0],
			"%s$@%s", my_name, lp_realm());
	if (err == -1) {
		ret = ENOMEM;
		goto out;
	}
	err = asprintf(&valid_princ_formats[1],
			"host/%s@%s", my_name, lp_realm());
	if (err == -1) {
		ret = ENOMEM;
		goto out;
	}
	err = asprintf(&valid_princ_formats[2],
			"host/%s@%s", my_fqdn, lp_realm());
	if (err == -1) {
		ret = ENOMEM;
		goto out;
	}
	err = asprintf(&valid_princ_formats[3],
			"host/%s.%s@%s", my_name, lp_realm(), lp_realm());
	if (err == -1) {
		ret = ENOMEM;
		goto out;
	}
	err = asprintf(&valid_princ_formats[4],
			"cifs/%s@%s", my_name, lp_realm());
	if (err == -1) {
		ret = ENOMEM;
		goto out;
	}
	err = asprintf(&valid_princ_formats[5],
			"cifs/%s@%s", my_fqdn, lp_realm());
	if (err == -1) {
		ret = ENOMEM;
		goto out;
	}
	err = asprintf(&valid_princ_formats[6],
			"cifs/%s.%s@%s", my_name, lp_realm(), lp_realm());
	if (err == -1) {
		ret = ENOMEM;
		goto out;
	}

	ret = smb_krb5_kt_open_relative(krbctx, NULL, false, &keytab);
	if (ret) {
		DEBUG(1, ("smb_krb5_kt_open failed (%s)\n",
			  error_message(ret)));
		goto out;
	}

	/*
	 * Iterate through the keytab.  For each key, if the principal
	 * name case-insensitively matches one of the allowed formats,
	 * copy it to the memory keytab.
	 */

	ret = krb5_kt_start_seq_get(krbctx, keytab, &kt_cursor);
	if (ret) {
		DEBUG(1, (__location__ ": krb5_kt_start_seq_get failed (%s)\n",
			  error_message(ret)));
		/*
		 * krb5_kt_start_seq_get() may leaves bogus data
		 * in kt_cursor. And we want to use the all_zero()
		 * logic below.
		 *
		 * See bug #10490
		 */
		ZERO_STRUCT(kt_cursor);
		goto out;
	}

	while ((krb5_kt_next_entry(krbctx, keytab,
				   &kt_entry, &kt_cursor) == 0)) {
		ret = smb_krb5_unparse_name(talloc_tos(), krbctx,
					    kt_entry.principal,
					    &entry_princ_s);
		if (ret) {
			DEBUG(1, (__location__ ": smb_krb5_unparse_name "
				  "failed (%s)\n", error_message(ret)));
			goto out;
		}

		for (i = 0; i < ARRAY_SIZE(valid_princ_formats); i++) {

			if (!strequal(entry_princ_s, valid_princ_formats[i])) {
				continue;
			}

			ret = krb5_kt_add_entry(krbctx, *mkeytab, &kt_entry);
			if (ret) {
				DEBUG(1, (__location__ ": smb_krb5_unparse_name "
					  "failed (%s)\n", error_message(ret)));
				goto out;
			}
		}

		/* Free the name we parsed. */
		TALLOC_FREE(entry_princ_s);

		/* Free the entry we just read. */
		smb_krb5_kt_free_entry(krbctx, &kt_entry);
		ZERO_STRUCT(kt_entry);
	}
	krb5_kt_end_seq_get(krbctx, keytab, &kt_cursor);

	ZERO_STRUCT(kt_cursor);

out:

	for (i = 0; i < ARRAY_SIZE(valid_princ_formats); i++) {
		SAFE_FREE(valid_princ_formats[i]);
	}

	TALLOC_FREE(entry_princ_s);

	if (!all_zero((uint8_t *)&kt_entry, sizeof(kt_entry))) {
		smb_krb5_kt_free_entry(krbctx, &kt_entry);
	}

	if (!all_zero((uint8_t *)&kt_cursor, sizeof(kt_cursor)) && keytab) {
		krb5_kt_end_seq_get(krbctx, keytab, &kt_cursor);
	}

	if (keytab) {
		krb5_kt_close(krbctx, keytab);
	}

	return ret;
}

static krb5_error_code fill_mem_keytab_from_dedicated_keytab(krb5_context krbctx,
							     krb5_keytab *mkeytab)
{
	krb5_error_code ret = 0;
	krb5_keytab keytab = NULL;
	krb5_kt_cursor kt_cursor;
	krb5_keytab_entry kt_entry;

	ret = smb_krb5_kt_open(krbctx, lp_dedicated_keytab_file(),
				   false, &keytab);
	if (ret) {
		DEBUG(1, ("smb_krb5_kt_open failed (%s)\n",
			  error_message(ret)));
		return ret;
	}

	/*
	 * Copy the dedicated keyab to our in-memory keytab.
	 */

	ret = krb5_kt_start_seq_get(krbctx, keytab, &kt_cursor);
	if (ret) {
		DEBUG(1, (__location__ ": krb5_kt_start_seq_get failed (%s)\n",
			  error_message(ret)));
		goto out;
	}

	while ((krb5_kt_next_entry(krbctx, keytab,
				   &kt_entry, &kt_cursor) == 0)) {

		ret = krb5_kt_add_entry(krbctx, *mkeytab, &kt_entry);

		/* Free the entry we just read. */
		smb_krb5_kt_free_entry(krbctx, &kt_entry);

		if (ret) {
			DEBUG(1, (__location__ ": smb_krb5_unparse_name "
				  "failed (%s)\n", error_message(ret)));
			break;
		}
	}
	krb5_kt_end_seq_get(krbctx, keytab, &kt_cursor);

out:
	
	krb5_kt_close(krbctx, keytab);

	return ret;
}

krb5_error_code gse_krb5_get_server_keytab(krb5_context krbctx,
					   krb5_keytab *keytab)
{
	krb5_error_code ret = 0;
	krb5_error_code ret1 = 0;
	krb5_error_code ret2 = 0;

	*keytab = NULL;

	/* create memory keytab */
	ret = krb5_kt_resolve(krbctx, SRV_MEM_KEYTAB_NAME, keytab);
	if (ret) {
		DEBUG(1, (__location__ ": Failed to get memory "
			  "keytab!\n"));
		return ret;
	}

	switch (lp_kerberos_method()) {
	default:
	case KERBEROS_VERIFY_SECRETS:
		ret = fill_mem_keytab_from_secrets(krbctx, keytab);
		break;
	case KERBEROS_VERIFY_SYSTEM_KEYTAB:
		ret = fill_mem_keytab_from_system_keytab(krbctx, keytab);
		break;
	case KERBEROS_VERIFY_DEDICATED_KEYTAB:
		/* just use whatever keytab is configured */
		ret = fill_mem_keytab_from_dedicated_keytab(krbctx, keytab);
		break;
	case KERBEROS_VERIFY_SECRETS_AND_KEYTAB:
		ret1 = fill_mem_keytab_from_secrets(krbctx, keytab);
		if (ret1) {
			DEBUG(3, (__location__ ": Warning! Unable to set mem "
				  "keytab from secrets!\n"));
		}
		/* Now append system keytab keys too */
		ret2 = fill_mem_keytab_from_system_keytab(krbctx, keytab);
		if (ret2) {
			DEBUG(3, (__location__ ": Warning! Unable to set mem "
				  "keytab from system keytab!\n"));
		}
		if (ret1 == 0 || ret2 == 0) {
			ret = 0;
		} else {
			ret = ret1;
		}
		break;
	}

	if (ret) {
		krb5_kt_close(krbctx, *keytab);
		*keytab = NULL;
		DEBUG(1,("%s: Error! Unable to set mem keytab - %d\n",
			 __location__, ret));
	}

	return ret;
}

#endif /* HAVE_KRB5 */
