/*
   Unix SMB/CIFS implementation.

   Database Glue between Samba and the KDC

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2009
   Copyright (C) Simo Sorce <idra@samba.org> 2010

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
#include "system/time.h"
#include "../libds/common/flags.h"
#include "lib/ldb/include/ldb.h"
#include "librpc/gen_ndr/netlogon.h"
#include "libcli/security/security.h"
#include "auth/auth.h"
#include "auth/credentials/credentials.h"
#include "auth/auth_sam.h"
#include "../lib/util/util_ldb.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "librpc/gen_ndr/lsa.h"
#include "libcli/auth/libcli_auth.h"
#include "param/param.h"
#include "../lib/crypto/md4.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include <hdb.h>
#include "kdc/samba_kdc.h"
#include "kdc/db-glue.h"

enum samba_kdc_ent_type
{ SAMBA_KDC_ENT_TYPE_CLIENT, SAMBA_KDC_ENT_TYPE_SERVER,
  SAMBA_KDC_ENT_TYPE_KRBTGT, SAMBA_KDC_ENT_TYPE_TRUST, SAMBA_KDC_ENT_TYPE_ANY };

enum trust_direction {
	UNKNOWN = 0,
	INBOUND = LSA_TRUST_DIRECTION_INBOUND,
	OUTBOUND = LSA_TRUST_DIRECTION_OUTBOUND
};

static const char *trust_attrs[] = {
	"trustPartner",
	"trustAuthIncoming",
	"trustAuthOutgoing",
	"whenCreated",
	"msDS-SupportedEncryptionTypes",
	"trustAttributes",
	"trustDirection",
	"trustType",
	NULL
};

static KerberosTime ldb_msg_find_krb5time_ldap_time(struct ldb_message *msg, const char *attr, KerberosTime default_val)
{
    const char *tmp;
    const char *gentime;
    struct tm tm;

    gentime = ldb_msg_find_attr_as_string(msg, attr, NULL);
    if (!gentime)
	return default_val;

    tmp = strptime(gentime, "%Y%m%d%H%M%SZ", &tm);
    if (tmp == NULL) {
	    return default_val;
    }

    return timegm(&tm);
}

static HDBFlags uf2HDBFlags(krb5_context context, int userAccountControl, enum samba_kdc_ent_type ent_type)
{
	HDBFlags flags = int2HDBFlags(0);

	/* we don't allow kadmin deletes */
	flags.immutable = 1;

	/* mark the principal as invalid to start with */
	flags.invalid = 1;

	flags.renewable = 1;

	/* All accounts are servers, but this may be disabled again in the caller */
	flags.server = 1;

	/* Account types - clear the invalid bit if it turns out to be valid */
	if (userAccountControl & UF_NORMAL_ACCOUNT) {
		if (ent_type == SAMBA_KDC_ENT_TYPE_CLIENT || ent_type == SAMBA_KDC_ENT_TYPE_ANY) {
			flags.client = 1;
		}
		flags.invalid = 0;
	}

	if (userAccountControl & UF_INTERDOMAIN_TRUST_ACCOUNT) {
		if (ent_type == SAMBA_KDC_ENT_TYPE_CLIENT || ent_type == SAMBA_KDC_ENT_TYPE_ANY) {
			flags.client = 1;
		}
		flags.invalid = 0;
	}
	if (userAccountControl & UF_WORKSTATION_TRUST_ACCOUNT) {
		if (ent_type == SAMBA_KDC_ENT_TYPE_CLIENT || ent_type == SAMBA_KDC_ENT_TYPE_ANY) {
			flags.client = 1;
		}
		flags.invalid = 0;
	}
	if (userAccountControl & UF_SERVER_TRUST_ACCOUNT) {
		if (ent_type == SAMBA_KDC_ENT_TYPE_CLIENT || ent_type == SAMBA_KDC_ENT_TYPE_ANY) {
			flags.client = 1;
		}
		flags.invalid = 0;
	}

	/* Not permitted to act as a client if disabled */
	if (userAccountControl & UF_ACCOUNTDISABLE) {
		flags.client = 0;
	}
	if (userAccountControl & UF_LOCKOUT) {
		flags.invalid = 1;
	}
/*
	if (userAccountControl & UF_PASSWORD_NOTREQD) {
		flags.invalid = 1;
	}
*/
/*
	UF_PASSWORD_CANT_CHANGE and UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED are irrelevent
*/
	if (userAccountControl & UF_TEMP_DUPLICATE_ACCOUNT) {
		flags.invalid = 1;
	}

/* UF_DONT_EXPIRE_PASSWD and UF_USE_DES_KEY_ONLY handled in samba_kdc_message2entry() */

/*
	if (userAccountControl & UF_MNS_LOGON_ACCOUNT) {
		flags.invalid = 1;
	}
*/
	if (userAccountControl & UF_SMARTCARD_REQUIRED) {
		flags.require_hwauth = 1;
	}
	if (userAccountControl & UF_TRUSTED_FOR_DELEGATION) {
		flags.ok_as_delegate = 1;
	}
	if (!(userAccountControl & UF_NOT_DELEGATED)) {
		flags.forwardable = 1;
		flags.proxiable = 1;
	}

	if (userAccountControl & UF_DONT_REQUIRE_PREAUTH) {
		flags.require_preauth = 0;
	} else {
		flags.require_preauth = 1;

	}
	return flags;
}

static int samba_kdc_entry_destructor(struct samba_kdc_entry *p)
{
    hdb_entry_ex *entry_ex = p->entry_ex;
    free_hdb_entry(&entry_ex->entry);
    return 0;
}

static void samba_kdc_free_entry(krb5_context context, hdb_entry_ex *entry_ex)
{
	/* this function is called only from hdb_free_entry().
	 * Make sure we neutralize the destructor or we will
	 * get a double free later when hdb_free_entry() will
	 * try to call free_hdb_entry() */
	talloc_set_destructor(entry_ex->ctx, NULL);

	/* now proceed to free the talloc part */
	talloc_free(entry_ex->ctx);
}

static krb5_error_code samba_kdc_message2entry_keys(krb5_context context,
						    TALLOC_CTX *mem_ctx,
						    struct ldb_message *msg,
						    uint32_t rid,
						    unsigned int userAccountControl,
						    enum samba_kdc_ent_type ent_type,
						    hdb_entry_ex *entry_ex)
{
	krb5_error_code ret = 0;
	enum ndr_err_code ndr_err;
	struct samr_Password *hash;
	const struct ldb_val *sc_val;
	struct supplementalCredentialsBlob scb;
	struct supplementalCredentialsPackage *scpk = NULL;
	bool newer_keys = false;
	struct package_PrimaryKerberosBlob _pkb;
	struct package_PrimaryKerberosCtr3 *pkb3 = NULL;
	struct package_PrimaryKerberosCtr4 *pkb4 = NULL;
	uint16_t i;
	uint16_t allocated_keys = 0;

	/* Supported Enc for this entry */
	uint32_t supported_enctypes = ENC_ALL_TYPES; /* by default, we support all enc types */

	/* However, if this is a TGS-REQ, then lock it down to a
	 * reasonable guess as to what the server can decode.  The
	 * krbtgt is special - default to use what is stored for the KDC */
	if (rid != DOMAIN_RID_KRBTGT && ent_type == SAMBA_KDC_ENT_TYPE_SERVER) {
		/* This is the standard set for a server that has not declared a msDS-SupportedEncryptionTypes */
		supported_enctypes = ENC_CRC32 | ENC_RSA_MD5 | ENC_RC4_HMAC_MD5;
	}
	supported_enctypes = ldb_msg_find_attr_as_uint(msg, "msDS-SupportedEncryptionTypes",
							supported_enctypes);
	if (rid == DOMAIN_RID_KRBTGT) {
		/* Be double-sure never to use DES here */
		supported_enctypes &= ~(ENC_CRC32|ENC_RSA_MD5);
	}

	switch (ent_type) {
	case SAMBA_KDC_ENT_TYPE_KRBTGT:
	case SAMBA_KDC_ENT_TYPE_TRUST:
		/* Disallow krbtgt and trust tickets to be DES encrypted, it's just too dangerous */
		supported_enctypes &= ~(ENC_CRC32|ENC_RSA_MD5);
		break;
	default:
		break;
		/* No further restrictions */
	}

	/* If UF_USE_DES_KEY_ONLY has been set, then don't allow use of the newer enc types */
	if (userAccountControl & UF_USE_DES_KEY_ONLY) {
		/* However, don't allow use of DES, if we were told not to by msDS-SupportedEncTypes */
		supported_enctypes &= ENC_CRC32|ENC_RSA_MD5;
	}

	entry_ex->entry.keys.val = NULL;
	entry_ex->entry.keys.len = 0;

	entry_ex->entry.kvno = ldb_msg_find_attr_as_int(msg, "msDS-KeyVersionNumber", 0);

	/* Get keys from the db */

	hash = samdb_result_hash(mem_ctx, msg, "unicodePwd");
	sc_val = ldb_msg_find_ldb_val(msg, "supplementalCredentials");

	/* unicodePwd for enctype 0x17 (23) if present */
	if (hash) {
		allocated_keys++;
	}

	/* supplementalCredentials if present */
	if (sc_val) {
		ndr_err = ndr_pull_struct_blob_all(sc_val, mem_ctx, &scb,
						   (ndr_pull_flags_fn_t)ndr_pull_supplementalCredentialsBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			dump_data(0, sc_val->data, sc_val->length);
			ret = EINVAL;
			goto out;
		}

		if (scb.sub.signature != SUPPLEMENTAL_CREDENTIALS_SIGNATURE) {
			NDR_PRINT_DEBUG(supplementalCredentialsBlob, &scb);
			ret = EINVAL;
			goto out;
		}

		for (i=0; i < scb.sub.num_packages; i++) {
			if (strcmp("Primary:Kerberos-Newer-Keys", scb.sub.packages[i].name) == 0) {
				scpk = &scb.sub.packages[i];
				if (!scpk->data || !scpk->data[0]) {
					scpk = NULL;
					continue;
				}
				newer_keys = true;
				break;
			} else if (strcmp("Primary:Kerberos", scb.sub.packages[i].name) == 0) {
				scpk = &scb.sub.packages[i];
				if (!scpk->data || !scpk->data[0]) {
					scpk = NULL;
				}
				/*
				 * we don't break here in hope to find
				 * a Kerberos-Newer-Keys package
				 */
			}
		}
	}
	/*
	 * Primary:Kerberos-Newer-Keys or Primary:Kerberos element
	 * of supplementalCredentials
	 */
	if (scpk) {
		DATA_BLOB blob;

		blob = strhex_to_data_blob(mem_ctx, scpk->data);
		if (!blob.data) {
			ret = ENOMEM;
			goto out;
		}

		/* we cannot use ndr_pull_struct_blob_all() here, as w2k and w2k3 add padding bytes */
		ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &_pkb,
					       (ndr_pull_flags_fn_t)ndr_pull_package_PrimaryKerberosBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			ret = EINVAL;
			krb5_set_error_message(context, ret, "samba_kdc_message2entry_keys: could not parse package_PrimaryKerberosBlob");
			krb5_warnx(context, "samba_kdc_message2entry_keys: could not parse package_PrimaryKerberosBlob");
			goto out;
		}

		if (newer_keys && _pkb.version != 4) {
			ret = EINVAL;
			krb5_set_error_message(context, ret, "samba_kdc_message2entry_keys: Primary:Kerberos-Newer-Keys not version 4");
			krb5_warnx(context, "samba_kdc_message2entry_keys: Primary:Kerberos-Newer-Keys not version 4");
			goto out;
		}

		if (!newer_keys && _pkb.version != 3) {
			ret = EINVAL;
			krb5_set_error_message(context, ret, "samba_kdc_message2entry_keys: could not parse Primary:Kerberos not version 3");
			krb5_warnx(context, "samba_kdc_message2entry_keys: could not parse Primary:Kerberos not version 3");
			goto out;
		}

		if (_pkb.version == 4) {
			pkb4 = &_pkb.ctr.ctr4;
			allocated_keys += pkb4->num_keys;
		} else if (_pkb.version == 3) {
			pkb3 = &_pkb.ctr.ctr3;
			allocated_keys += pkb3->num_keys;
		}
	}

	if (allocated_keys == 0) {
		/* oh, no password.  Apparently (comment in
		 * hdb-ldap.c) this violates the ASN.1, but this
		 * allows an entry with no keys (yet). */
		return 0;
	}

	/* allocate space to decode into */
	entry_ex->entry.keys.len = 0;
	entry_ex->entry.keys.val = calloc(allocated_keys, sizeof(Key));
	if (entry_ex->entry.keys.val == NULL) {
		ret = ENOMEM;
		goto out;
	}

	if (hash && (supported_enctypes & ENC_RC4_HMAC_MD5)) {
		Key key;

		key.mkvno = 0;
		key.salt = NULL; /* No salt for this enc type */

		ret = krb5_keyblock_init(context,
					 ENCTYPE_ARCFOUR_HMAC,
					 hash->hash, sizeof(hash->hash),
					 &key.key);
		if (ret) {
			goto out;
		}

		entry_ex->entry.keys.val[entry_ex->entry.keys.len] = key;
		entry_ex->entry.keys.len++;
	}

	if (pkb4) {
		for (i=0; i < pkb4->num_keys; i++) {
			Key key;

			if (!pkb4->keys[i].value) continue;

			if (!(kerberos_enctype_to_bitmap(pkb4->keys[i].keytype) & supported_enctypes)) {
				continue;
			}

			key.mkvno = 0;
			key.salt = NULL;

			if (pkb4->salt.string) {
				DATA_BLOB salt;

				salt = data_blob_string_const(pkb4->salt.string);

				key.salt = calloc(1, sizeof(*key.salt));
				if (key.salt == NULL) {
					ret = ENOMEM;
					goto out;
				}

				key.salt->type = hdb_pw_salt;

				ret = krb5_data_copy(&key.salt->salt, salt.data, salt.length);
				if (ret) {
					free(key.salt);
					key.salt = NULL;
					goto out;
				}
			}

			/* TODO: maybe pass the iteration_count somehow... */

			ret = krb5_keyblock_init(context,
						 pkb4->keys[i].keytype,
						 pkb4->keys[i].value->data,
						 pkb4->keys[i].value->length,
						 &key.key);
			if (ret == KRB5_PROG_ETYPE_NOSUPP) {
				DEBUG(2,("Unsupported keytype ignored - type %u\n",
					 pkb4->keys[i].keytype));
				ret = 0;
				continue;
			}
			if (ret) {
				if (key.salt) {
					free_Salt(key.salt);
					free(key.salt);
					key.salt = NULL;
				}
				goto out;
			}

			entry_ex->entry.keys.val[entry_ex->entry.keys.len] = key;
			entry_ex->entry.keys.len++;
		}
	} else if (pkb3) {
		for (i=0; i < pkb3->num_keys; i++) {
			Key key;

			if (!pkb3->keys[i].value) continue;

			if (!(kerberos_enctype_to_bitmap(pkb3->keys[i].keytype) & supported_enctypes)) {
				continue;
			}

			key.mkvno = 0;
			key.salt = NULL;

			if (pkb3->salt.string) {
				DATA_BLOB salt;

				salt = data_blob_string_const(pkb3->salt.string);

				key.salt = calloc(1, sizeof(*key.salt));
				if (key.salt == NULL) {
					ret = ENOMEM;
					goto out;
				}

				key.salt->type = hdb_pw_salt;

				ret = krb5_data_copy(&key.salt->salt, salt.data, salt.length);
				if (ret) {
					free(key.salt);
					key.salt = NULL;
					goto out;
				}
			}

			ret = krb5_keyblock_init(context,
						 pkb3->keys[i].keytype,
						 pkb3->keys[i].value->data,
						 pkb3->keys[i].value->length,
						 &key.key);
			if (ret) {
				if (key.salt) {
					free_Salt(key.salt);
					free(key.salt);
					key.salt = NULL;
				}
				goto out;
			}

			entry_ex->entry.keys.val[entry_ex->entry.keys.len] = key;
			entry_ex->entry.keys.len++;
		}
	}

out:
	if (ret != 0) {
		entry_ex->entry.keys.len = 0;
	}
	if (entry_ex->entry.keys.len == 0 && entry_ex->entry.keys.val) {
		free(entry_ex->entry.keys.val);
		entry_ex->entry.keys.val = NULL;
	}
	return ret;
}

/*
 * Construct an hdb_entry from a directory entry.
 */
static krb5_error_code samba_kdc_message2entry(krb5_context context,
					 struct samba_kdc_db_context *kdc_db_ctx,
					 TALLOC_CTX *mem_ctx, krb5_const_principal principal,
					 enum samba_kdc_ent_type ent_type,
					 struct ldb_dn *realm_dn,
					 struct ldb_message *msg,
					 hdb_entry_ex *entry_ex)
{
	struct loadparm_context *lp_ctx = kdc_db_ctx->lp_ctx;
	unsigned int userAccountControl;
	unsigned int i;
	krb5_error_code ret = 0;
	krb5_boolean is_computer = FALSE;
	char *realm = strupper_talloc(mem_ctx, lpcfg_realm(lp_ctx));

	struct samba_kdc_entry *p;
	NTTIME acct_expiry;
	NTSTATUS status;

	uint32_t rid;
	struct ldb_message_element *objectclasses;
	struct ldb_val computer_val;
	const char *samAccountName = ldb_msg_find_attr_as_string(msg, "samAccountName", NULL);
	computer_val.data = discard_const_p(uint8_t,"computer");
	computer_val.length = strlen((const char *)computer_val.data);

	if (!samAccountName) {
		ret = ENOENT;
		krb5_set_error_message(context, ret, "samba_kdc_message2entry: no samAccountName present");
		goto out;
	}

	objectclasses = ldb_msg_find_element(msg, "objectClass");

	if (objectclasses && ldb_msg_find_val(objectclasses, &computer_val)) {
		is_computer = TRUE;
	}

	memset(entry_ex, 0, sizeof(*entry_ex));

	if (!realm) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "talloc_strdup: out of memory");
		goto out;
	}

	p = talloc(mem_ctx, struct samba_kdc_entry);
	if (!p) {
		ret = ENOMEM;
		goto out;
	}

	p->kdc_db_ctx = kdc_db_ctx;
	p->entry_ex = entry_ex;
	p->realm_dn = talloc_reference(p, realm_dn);
	if (!p->realm_dn) {
		ret = ENOMEM;
		goto out;
	}

	talloc_set_destructor(p, samba_kdc_entry_destructor);

	/* make sure we do not have bogus data in there */
	memset(&entry_ex->entry, 0, sizeof(hdb_entry));

	entry_ex->ctx = p;
	entry_ex->free_entry = samba_kdc_free_entry;

	userAccountControl = ldb_msg_find_attr_as_uint(msg, "userAccountControl", 0);


	entry_ex->entry.principal = malloc(sizeof(*(entry_ex->entry.principal)));
	if (ent_type == SAMBA_KDC_ENT_TYPE_ANY && principal == NULL) {
		krb5_make_principal(context, &entry_ex->entry.principal, realm, samAccountName, NULL);
	} else {
		ret = copy_Principal(principal, entry_ex->entry.principal);
		if (ret) {
			krb5_clear_error_message(context);
			goto out;
		}

		/* While we have copied the client principal, tests
		 * show that Win2k3 returns the 'corrected' realm, not
		 * the client-specified realm.  This code attempts to
		 * replace the client principal's realm with the one
		 * we determine from our records */

		/* this has to be with malloc() */
		krb5_principal_set_realm(context, entry_ex->entry.principal, realm);
	}

	/* First try and figure out the flags based on the userAccountControl */
	entry_ex->entry.flags = uf2HDBFlags(context, userAccountControl, ent_type);

	/* Windows 2008 seems to enforce this (very sensible) rule by
	 * default - don't allow offline attacks on a user's password
	 * by asking for a ticket to them as a service (encrypted with
	 * their probably patheticly insecure password) */

	if (entry_ex->entry.flags.server
	    && lpcfg_parm_bool(lp_ctx, NULL, "kdc", "require spn for service", true)) {
		if (!is_computer && !ldb_msg_find_attr_as_string(msg, "servicePrincipalName", NULL)) {
			entry_ex->entry.flags.server = 0;
		}
	}

	{
		/* These (created_by, modified_by) parts of the entry are not relevant for Samba4's use
		 * of the Heimdal KDC.  They are stored in a the traditional
		 * DB for audit purposes, and still form part of the structure
		 * we must return */

		/* use 'whenCreated' */
		entry_ex->entry.created_by.time = ldb_msg_find_krb5time_ldap_time(msg, "whenCreated", 0);
		/* use 'kadmin' for now (needed by mit_samba) */
		krb5_make_principal(context,
				    &entry_ex->entry.created_by.principal,
				    realm, "kadmin", NULL);

		entry_ex->entry.modified_by = (Event *) malloc(sizeof(Event));
		if (entry_ex->entry.modified_by == NULL) {
			ret = ENOMEM;
			krb5_set_error_message(context, ret, "malloc: out of memory");
			goto out;
		}

		/* use 'whenChanged' */
		entry_ex->entry.modified_by->time = ldb_msg_find_krb5time_ldap_time(msg, "whenChanged", 0);
		/* use 'kadmin' for now (needed by mit_samba) */
		krb5_make_principal(context,
				    &entry_ex->entry.modified_by->principal,
				    realm, "kadmin", NULL);
	}


	/* The lack of password controls etc applies to krbtgt by
	 * virtue of being that particular RID */
	status = dom_sid_split_rid(NULL, samdb_result_dom_sid(mem_ctx, msg, "objectSid"), NULL, &rid);

	if (!NT_STATUS_IS_OK(status)) {
		ret = EINVAL;
		goto out;
	}

	if (rid == DOMAIN_RID_KRBTGT) {
		entry_ex->entry.valid_end = NULL;
		entry_ex->entry.pw_end = NULL;

		entry_ex->entry.flags.invalid = 0;
		entry_ex->entry.flags.server = 1;

		/* Don't mark all requests for the krbtgt/realm as
		 * 'change password', as otherwise we could get into
		 * trouble, and not enforce the password expirty.
		 * Instead, only do it when request is for the kpasswd service */
		if (ent_type == SAMBA_KDC_ENT_TYPE_SERVER
		    && principal->name.name_string.len == 2
		    && (strcmp(principal->name.name_string.val[0], "kadmin") == 0)
		    && (strcmp(principal->name.name_string.val[1], "changepw") == 0)
		    && lpcfg_is_my_domain_or_realm(lp_ctx, principal->realm)) {
			entry_ex->entry.flags.change_pw = 1;
		}
		entry_ex->entry.flags.client = 0;
		entry_ex->entry.flags.forwardable = 1;
		entry_ex->entry.flags.ok_as_delegate = 1;
	} else if (entry_ex->entry.flags.server && ent_type == SAMBA_KDC_ENT_TYPE_SERVER) {
		/* The account/password expiry only applies when the account is used as a
		 * client (ie password login), not when used as a server */

		/* Make very well sure we don't use this for a client,
		 * it could bypass the password restrictions */
		entry_ex->entry.flags.client = 0;

		entry_ex->entry.valid_end = NULL;
		entry_ex->entry.pw_end = NULL;

	} else {
		NTTIME must_change_time
			= samdb_result_force_password_change(kdc_db_ctx->samdb, mem_ctx,
							     realm_dn, msg);
		if (must_change_time == 0x7FFFFFFFFFFFFFFFULL) {
			entry_ex->entry.pw_end = NULL;
		} else {
			entry_ex->entry.pw_end = malloc(sizeof(*entry_ex->entry.pw_end));
			if (entry_ex->entry.pw_end == NULL) {
				ret = ENOMEM;
				goto out;
			}
			*entry_ex->entry.pw_end = nt_time_to_unix(must_change_time);
		}

		acct_expiry = samdb_result_account_expires(msg);
		if (acct_expiry == 0x7FFFFFFFFFFFFFFFULL) {
			entry_ex->entry.valid_end = NULL;
		} else {
			entry_ex->entry.valid_end = malloc(sizeof(*entry_ex->entry.valid_end));
			if (entry_ex->entry.valid_end == NULL) {
				ret = ENOMEM;
				goto out;
			}
			*entry_ex->entry.valid_end = nt_time_to_unix(acct_expiry);
		}
	}

	entry_ex->entry.valid_start = NULL;

	entry_ex->entry.max_life = NULL;

	entry_ex->entry.max_renew = NULL;

	entry_ex->entry.generation = NULL;

	/* Get keys from the db */
	ret = samba_kdc_message2entry_keys(context, p, msg, 
					   rid, userAccountControl,
					   ent_type, entry_ex);
	if (ret) {
		/* Could be bougus data in the entry, or out of memory */
		goto out;
	}

	entry_ex->entry.etypes = malloc(sizeof(*(entry_ex->entry.etypes)));
	if (entry_ex->entry.etypes == NULL) {
		krb5_clear_error_message(context);
		ret = ENOMEM;
		goto out;
	}
	entry_ex->entry.etypes->len = entry_ex->entry.keys.len;
	entry_ex->entry.etypes->val = calloc(entry_ex->entry.etypes->len, sizeof(int));
	if (entry_ex->entry.etypes->val == NULL) {
		krb5_clear_error_message(context);
		ret = ENOMEM;
		goto out;
	}
	for (i=0; i < entry_ex->entry.etypes->len; i++) {
		entry_ex->entry.etypes->val[i] = entry_ex->entry.keys.val[i].key.keytype;
	}


	p->msg = talloc_steal(p, msg);

out:
	if (ret != 0) {
		/* This doesn't free ent itself, that is for the eventual caller to do */
		hdb_free_entry(context, entry_ex);
	} else {
		talloc_steal(kdc_db_ctx, entry_ex->ctx);
	}

	return ret;
}

/*
 * Construct an hdb_entry from a directory entry.
 */
static krb5_error_code samba_kdc_trust_message2entry(krb5_context context,
					       struct samba_kdc_db_context *kdc_db_ctx,
					       TALLOC_CTX *mem_ctx, krb5_const_principal principal,
					       enum trust_direction direction,
					       struct ldb_dn *realm_dn,
					       struct ldb_message *msg,
					       hdb_entry_ex *entry_ex)
{
	struct loadparm_context *lp_ctx = kdc_db_ctx->lp_ctx;
	const char *dnsdomain;
	char *realm = strupper_talloc(mem_ctx, lpcfg_realm(lp_ctx));
	DATA_BLOB password_utf16;
	struct samr_Password password_hash;
	const struct ldb_val *password_val;
	struct trustAuthInOutBlob password_blob;
	struct samba_kdc_entry *p;

	enum ndr_err_code ndr_err;
	int ret, trust_direction_flags;
	unsigned int i;

	p = talloc(mem_ctx, struct samba_kdc_entry);
	if (!p) {
		ret = ENOMEM;
		goto out;
	}

	p->kdc_db_ctx = kdc_db_ctx;
	p->entry_ex = entry_ex;
	p->realm_dn = realm_dn;

	talloc_set_destructor(p, samba_kdc_entry_destructor);

	/* make sure we do not have bogus data in there */
	memset(&entry_ex->entry, 0, sizeof(hdb_entry));

	entry_ex->ctx = p;
	entry_ex->free_entry = samba_kdc_free_entry;

	/* use 'whenCreated' */
	entry_ex->entry.created_by.time = ldb_msg_find_krb5time_ldap_time(msg, "whenCreated", 0);
	/* use 'kadmin' for now (needed by mit_samba) */
	krb5_make_principal(context,
			    &entry_ex->entry.created_by.principal,
			    realm, "kadmin", NULL);

	entry_ex->entry.valid_start = NULL;

	trust_direction_flags = ldb_msg_find_attr_as_int(msg, "trustDirection", 0);

	if (direction == INBOUND) {
		password_val = ldb_msg_find_ldb_val(msg, "trustAuthIncoming");

	} else { /* OUTBOUND */
		dnsdomain = ldb_msg_find_attr_as_string(msg, "trustPartner", NULL);
		/* replace realm */
		talloc_free(realm);
		realm = strupper_talloc(mem_ctx, dnsdomain);
		password_val = ldb_msg_find_ldb_val(msg, "trustAuthOutgoing");
	}

	if (!password_val || !(trust_direction_flags & direction)) {
		ret = ENOENT;
		goto out;
	}

	ndr_err = ndr_pull_struct_blob(password_val, mem_ctx, &password_blob,
					   (ndr_pull_flags_fn_t)ndr_pull_trustAuthInOutBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		ret = EINVAL;
		goto out;
	}

	entry_ex->entry.kvno = -1;
	for (i=0; i < password_blob.count; i++) {
		if (password_blob.current->array[i].AuthType == TRUST_AUTH_TYPE_VERSION) {
			entry_ex->entry.kvno = password_blob.current->array[i].AuthInfo.version.version;
		}
	}

	for (i=0; i < password_blob.count; i++) {
		if (password_blob.current->array[i].AuthType == TRUST_AUTH_TYPE_CLEAR) {
			password_utf16 = data_blob_const(password_blob.current->array[i].AuthInfo.clear.password,
							 password_blob.current->array[i].AuthInfo.clear.size);
			/* In the future, generate all sorts of
			 * hashes, but for now we can't safely convert
			 * the random strings windows uses into
			 * utf8 */

			/* but as it is utf16 already, we can get the NT password/arcfour-hmac-md5 key */
			mdfour(password_hash.hash, password_utf16.data, password_utf16.length);
			break;
		} else if (password_blob.current->array[i].AuthType == TRUST_AUTH_TYPE_NT4OWF) {
			password_hash = password_blob.current->array[i].AuthInfo.nt4owf.password;
			break;
		}
	}

	if (i < password_blob.count) {
		Key key;
		/* Must have found a cleartext or MD4 password */
		entry_ex->entry.keys.val = calloc(1, sizeof(Key));

		key.mkvno = 0;
		key.salt = NULL; /* No salt for this enc type */

		if (entry_ex->entry.keys.val == NULL) {
			ret = ENOMEM;
			goto out;
		}

		ret = krb5_keyblock_init(context,
					 ENCTYPE_ARCFOUR_HMAC,
					 password_hash.hash, sizeof(password_hash.hash),
					 &key.key);

		entry_ex->entry.keys.val[entry_ex->entry.keys.len] = key;
		entry_ex->entry.keys.len++;
	}

	entry_ex->entry.principal = malloc(sizeof(*(entry_ex->entry.principal)));

	ret = copy_Principal(principal, entry_ex->entry.principal);
	if (ret) {
		krb5_clear_error_message(context);
		goto out;
	}

	/* While we have copied the client principal, tests
	 * show that Win2k3 returns the 'corrected' realm, not
	 * the client-specified realm.  This code attempts to
	 * replace the client principal's realm with the one
	 * we determine from our records */

	krb5_principal_set_realm(context, entry_ex->entry.principal, realm);
	entry_ex->entry.flags = int2HDBFlags(0);
	entry_ex->entry.flags.immutable = 1;
	entry_ex->entry.flags.invalid = 0;
	entry_ex->entry.flags.server = 1;
	entry_ex->entry.flags.require_preauth = 1;

	entry_ex->entry.pw_end = NULL;

	entry_ex->entry.max_life = NULL;

	entry_ex->entry.max_renew = NULL;

	entry_ex->entry.generation = NULL;

	entry_ex->entry.etypes = malloc(sizeof(*(entry_ex->entry.etypes)));
	if (entry_ex->entry.etypes == NULL) {
		krb5_clear_error_message(context);
		ret = ENOMEM;
		goto out;
	}
	entry_ex->entry.etypes->len = entry_ex->entry.keys.len;
	entry_ex->entry.etypes->val = calloc(entry_ex->entry.etypes->len, sizeof(int));
	if (entry_ex->entry.etypes->val == NULL) {
		krb5_clear_error_message(context);
		ret = ENOMEM;
		goto out;
	}
	for (i=0; i < entry_ex->entry.etypes->len; i++) {
		entry_ex->entry.etypes->val[i] = entry_ex->entry.keys.val[i].key.keytype;
	}


	p->msg = talloc_steal(p, msg);

out:
	if (ret != 0) {
		/* This doesn't free ent itself, that is for the eventual caller to do */
		hdb_free_entry(context, entry_ex);
	} else {
		talloc_steal(kdc_db_ctx, entry_ex->ctx);
	}

	return ret;

}

static krb5_error_code samba_kdc_lookup_trust(krb5_context context, struct ldb_context *ldb_ctx,
					TALLOC_CTX *mem_ctx,
					const char *realm,
					struct ldb_dn *realm_dn,
					struct ldb_message **pmsg)
{
	int lret;
	krb5_error_code ret;
	char *filter = NULL;
	const char * const *attrs = trust_attrs;

	struct ldb_result *res = NULL;
	filter = talloc_asprintf(mem_ctx, "(&(objectClass=trustedDomain)(|(flatname=%s)(trustPartner=%s)))", realm, realm);

	if (!filter) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "talloc_asprintf: out of memory");
		return ret;
	}

	lret = ldb_search(ldb_ctx, mem_ctx, &res,
			  ldb_get_default_basedn(ldb_ctx),
			  LDB_SCOPE_SUBTREE, attrs, "%s", filter);
	if (lret != LDB_SUCCESS) {
		DEBUG(3, ("Failed to search for %s: %s\n", filter, ldb_errstring(ldb_ctx)));
		return HDB_ERR_NOENTRY;
	} else if (res->count == 0 || res->count > 1) {
		DEBUG(3, ("Failed find a single entry for %s: got %d\n", filter, res->count));
		talloc_free(res);
		return HDB_ERR_NOENTRY;
	}
	talloc_steal(mem_ctx, res->msgs);
	*pmsg = res->msgs[0];
	talloc_free(res);
	return 0;
}

static krb5_error_code samba_kdc_lookup_client(krb5_context context,
						struct samba_kdc_db_context *kdc_db_ctx,
						TALLOC_CTX *mem_ctx,
						krb5_const_principal principal,
						const char **attrs,
						struct ldb_dn **realm_dn,
						struct ldb_message **msg) {
	NTSTATUS nt_status;
	char *principal_string;
	krb5_error_code ret;

	ret = krb5_unparse_name(context, principal, &principal_string);

	if (ret != 0) {
		return ret;
	}

	nt_status = sam_get_results_principal(kdc_db_ctx->samdb,
					      mem_ctx, principal_string, attrs,
					      realm_dn, msg);
	free(principal_string);
	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_SUCH_USER)) {
		return HDB_ERR_NOENTRY;
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_MEMORY)) {
		return ENOMEM;
	} else if (!NT_STATUS_IS_OK(nt_status)) {
		return EINVAL;
	}

	return ret;
}

static krb5_error_code samba_kdc_fetch_client(krb5_context context,
					       struct samba_kdc_db_context *kdc_db_ctx,
					       TALLOC_CTX *mem_ctx,
					       krb5_const_principal principal,
					       hdb_entry_ex *entry_ex) {
	struct ldb_dn *realm_dn;
	krb5_error_code ret;
	struct ldb_message *msg = NULL;

	ret = samba_kdc_lookup_client(context, kdc_db_ctx,
				       mem_ctx, principal, user_attrs,
				       &realm_dn, &msg);
	if (ret != 0) {
		return ret;
	}

	ret = samba_kdc_message2entry(context, kdc_db_ctx, mem_ctx,
				       principal, SAMBA_KDC_ENT_TYPE_CLIENT,
				       realm_dn, msg, entry_ex);
	return ret;
}

static krb5_error_code samba_kdc_fetch_krbtgt(krb5_context context,
					struct samba_kdc_db_context *kdc_db_ctx,
					TALLOC_CTX *mem_ctx,
					krb5_const_principal principal,
					hdb_entry_ex *entry_ex)
{
	struct loadparm_context *lp_ctx = kdc_db_ctx->lp_ctx;
	krb5_error_code ret;
	struct ldb_message *msg = NULL;
	struct ldb_dn *realm_dn = ldb_get_default_basedn(kdc_db_ctx->samdb);
	const char *realm;

	krb5_principal alloc_principal = NULL;
	if (principal->name.name_string.len != 2
	    || (strcmp(principal->name.name_string.val[0], KRB5_TGS_NAME) != 0)) {
		/* Not a krbtgt */
		return HDB_ERR_NOENTRY;
	}

	/* krbtgt case.  Either us or a trusted realm */

	if (lpcfg_is_my_domain_or_realm(lp_ctx, principal->realm)
	    && lpcfg_is_my_domain_or_realm(lp_ctx, principal->name.name_string.val[1])) {
		/* us */
 		/* Cludge, cludge cludge.  If the realm part of krbtgt/realm,
 		 * is in our db, then direct the caller at our primary
 		 * krbtgt */

		int lret;
		char *realm_fixed;

		lret = dsdb_search_one(kdc_db_ctx->samdb, mem_ctx,
				       &msg, realm_dn, LDB_SCOPE_SUBTREE,
				       krbtgt_attrs,
				       DSDB_SEARCH_SHOW_EXTENDED_DN,
				       "(&(objectClass=user)(samAccountName=krbtgt))");
		if (lret == LDB_ERR_NO_SUCH_OBJECT) {
			krb5_warnx(context, "samba_kdc_fetch: could not find own KRBTGT in DB!");
			krb5_set_error_message(context, HDB_ERR_NOENTRY, "samba_kdc_fetch: could not find own KRBTGT in DB!");
			return HDB_ERR_NOENTRY;
		} else if (lret != LDB_SUCCESS) {
			krb5_warnx(context, "samba_kdc_fetch: could not find own KRBTGT in DB: %s", ldb_errstring(kdc_db_ctx->samdb));
			krb5_set_error_message(context, HDB_ERR_NOENTRY, "samba_kdc_fetch: could not find own KRBTGT in DB: %s", ldb_errstring(kdc_db_ctx->samdb));
			return HDB_ERR_NOENTRY;
		}

		realm_fixed = strupper_talloc(mem_ctx, lpcfg_realm(lp_ctx));
 		if (!realm_fixed) {
			ret = ENOMEM;
 			krb5_set_error_message(context, ret, "strupper_talloc: out of memory");
 			return ret;
 		}

 		ret = krb5_copy_principal(context, principal, &alloc_principal);
 		if (ret) {
 			return ret;
 		}

 		free(alloc_principal->name.name_string.val[1]);
		alloc_principal->name.name_string.val[1] = strdup(realm_fixed);
 		talloc_free(realm_fixed);
 		if (!alloc_principal->name.name_string.val[1]) {
			ret = ENOMEM;
 			krb5_set_error_message(context, ret, "samba_kdc_fetch: strdup() failed!");
 			return ret;
 		}
 		principal = alloc_principal;

		ret = samba_kdc_message2entry(context, kdc_db_ctx, mem_ctx,
					principal, SAMBA_KDC_ENT_TYPE_KRBTGT,
					realm_dn, msg, entry_ex);
		if (ret != 0) {
			krb5_warnx(context, "samba_kdc_fetch: self krbtgt message2entry failed");
		}
		return ret;

	} else {
		enum trust_direction direction = UNKNOWN;

		/* Either an inbound or outbound trust */

		if (strcasecmp(lpcfg_realm(lp_ctx), principal->realm) == 0) {
			/* look for inbound trust */
			direction = INBOUND;
			realm = principal->name.name_string.val[1];
		}

		if (strcasecmp(lpcfg_realm(lp_ctx), principal->name.name_string.val[1]) == 0) {
			/* look for outbound trust */
			direction = OUTBOUND;
			realm = principal->realm;
		}

		/* Trusted domains are under CN=system */

		ret = samba_kdc_lookup_trust(context, kdc_db_ctx->samdb,
				       mem_ctx,
				       realm, realm_dn, &msg);

		if (ret != 0) {
			krb5_warnx(context, "samba_kdc_fetch: could not find principal in DB");
			krb5_set_error_message(context, ret, "samba_kdc_fetch: could not find principal in DB");
			return ret;
		}

		ret = samba_kdc_trust_message2entry(context, kdc_db_ctx, mem_ctx,
					      principal, direction,
					      realm_dn, msg, entry_ex);
		if (ret != 0) {
			krb5_warnx(context, "samba_kdc_fetch: trust_message2entry failed");
		}
		return ret;
	}

}

static krb5_error_code samba_kdc_lookup_server(krb5_context context,
						struct samba_kdc_db_context *kdc_db_ctx,
						TALLOC_CTX *mem_ctx,
						krb5_const_principal principal,
						const char **attrs,
						struct ldb_dn **realm_dn,
						struct ldb_message **msg)
{
	krb5_error_code ret;
	const char *realm;
	if (principal->name.name_string.len >= 2) {
		/* 'normal server' case */
		int ldb_ret;
		NTSTATUS nt_status;
		struct ldb_dn *user_dn;
		char *principal_string;

		ret = krb5_unparse_name_flags(context, principal,
					      KRB5_PRINCIPAL_UNPARSE_NO_REALM,
					      &principal_string);
		if (ret != 0) {
			return ret;
		}

		/* At this point we may find the host is known to be
		 * in a different realm, so we should generate a
		 * referral instead */
		nt_status = crack_service_principal_name(kdc_db_ctx->samdb,
							 mem_ctx, principal_string,
							 &user_dn, realm_dn);
		free(principal_string);

		if (!NT_STATUS_IS_OK(nt_status)) {
			return HDB_ERR_NOENTRY;
		}

		ldb_ret = dsdb_search_one(kdc_db_ctx->samdb,
					  mem_ctx,
					  msg, user_dn, LDB_SCOPE_BASE,
					  attrs, DSDB_SEARCH_SHOW_EXTENDED_DN, "(objectClass=*)");
		if (ldb_ret != LDB_SUCCESS) {
			return HDB_ERR_NOENTRY;
		}

	} else {
		int lret;
		char *filter = NULL;
		char *short_princ;
		/* server as client principal case, but we must not lookup userPrincipalNames */
		*realm_dn = ldb_get_default_basedn(kdc_db_ctx->samdb);
		realm = krb5_principal_get_realm(context, principal);

		/* TODO: Check if it is our realm, otherwise give referall */

		ret = krb5_unparse_name_flags(context, principal,  KRB5_PRINCIPAL_UNPARSE_NO_REALM, &short_princ);

		if (ret != 0) {
			krb5_set_error_message(context, ret, "samba_kdc_lookup_principal: could not parse principal");
			krb5_warnx(context, "samba_kdc_lookup_principal: could not parse principal");
			return ret;
		}

		lret = dsdb_search_one(kdc_db_ctx->samdb, mem_ctx, msg,
				       *realm_dn, LDB_SCOPE_SUBTREE,
				       attrs,
				       DSDB_SEARCH_SHOW_EXTENDED_DN,
				       "(&(objectClass=user)(samAccountName=%s))",
				       ldb_binary_encode_string(mem_ctx, short_princ));
		free(short_princ);
		if (lret == LDB_ERR_NO_SUCH_OBJECT) {
			DEBUG(3, ("Failed find a entry for %s\n", filter));
			return HDB_ERR_NOENTRY;
		}
		if (lret != LDB_SUCCESS) {
			DEBUG(3, ("Failed single search for for %s - %s\n",
				  filter, ldb_errstring(kdc_db_ctx->samdb)));
			return HDB_ERR_NOENTRY;
		}
	}

	return 0;
}

static krb5_error_code samba_kdc_fetch_server(krb5_context context,
					       struct samba_kdc_db_context *kdc_db_ctx,
					       TALLOC_CTX *mem_ctx,
					       krb5_const_principal principal,
					       hdb_entry_ex *entry_ex)
{
	krb5_error_code ret;
	struct ldb_dn *realm_dn;
	struct ldb_message *msg;

	ret = samba_kdc_lookup_server(context, kdc_db_ctx, mem_ctx, principal,
				       server_attrs, &realm_dn, &msg);
	if (ret != 0) {
		return ret;
	}

	ret = samba_kdc_message2entry(context, kdc_db_ctx, mem_ctx,
				principal, SAMBA_KDC_ENT_TYPE_SERVER,
				realm_dn, msg, entry_ex);
	if (ret != 0) {
		krb5_warnx(context, "samba_kdc_fetch: message2entry failed");
	}

	return ret;
}

krb5_error_code samba_kdc_fetch(krb5_context context,
				struct samba_kdc_db_context *kdc_db_ctx,
				krb5_const_principal principal,
				unsigned flags,
				hdb_entry_ex *entry_ex)
{
	krb5_error_code ret = HDB_ERR_NOENTRY;
	TALLOC_CTX *mem_ctx = talloc_named(kdc_db_ctx, 0, "samba_kdc_fetch context");

	if (!mem_ctx) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "samba_kdc_fetch: talloc_named() failed!");
		return ret;
	}

	if (flags & HDB_F_GET_CLIENT) {
		ret = samba_kdc_fetch_client(context, kdc_db_ctx, mem_ctx, principal, entry_ex);
		if (ret != HDB_ERR_NOENTRY) goto done;
	}
	if (flags & HDB_F_GET_SERVER) {
		/* krbtgt fits into this situation for trusted realms, and for resolving different versions of our own realm name */
		ret = samba_kdc_fetch_krbtgt(context, kdc_db_ctx, mem_ctx, principal, entry_ex);
		if (ret != HDB_ERR_NOENTRY) goto done;

		/* We return 'no entry' if it does not start with krbtgt/, so move to the common case quickly */
		ret = samba_kdc_fetch_server(context, kdc_db_ctx, mem_ctx, principal, entry_ex);
		if (ret != HDB_ERR_NOENTRY) goto done;
	}
	if (flags & HDB_F_GET_KRBTGT) {
		ret = samba_kdc_fetch_krbtgt(context, kdc_db_ctx, mem_ctx, principal, entry_ex);
		if (ret != HDB_ERR_NOENTRY) goto done;
	}

done:
	talloc_free(mem_ctx);
	return ret;
}

struct samba_kdc_seq {
	unsigned int index;
	unsigned int count;
	struct ldb_message **msgs;
	struct ldb_dn *realm_dn;
};

static krb5_error_code samba_kdc_seq(krb5_context context,
				     struct samba_kdc_db_context *kdc_db_ctx,
				     hdb_entry_ex *entry)
{
	krb5_error_code ret;
	struct samba_kdc_seq *priv = kdc_db_ctx->seq_ctx;
	TALLOC_CTX *mem_ctx;
	hdb_entry_ex entry_ex;
	memset(&entry_ex, '\0', sizeof(entry_ex));

	if (!priv) {
		return HDB_ERR_NOENTRY;
	}

	mem_ctx = talloc_named(priv, 0, "samba_kdc_seq context");

	if (!mem_ctx) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "samba_kdc_seq: talloc_named() failed!");
		return ret;
	}

	if (priv->index < priv->count) {
		ret = samba_kdc_message2entry(context, kdc_db_ctx, mem_ctx,
					NULL, SAMBA_KDC_ENT_TYPE_ANY,
					priv->realm_dn, priv->msgs[priv->index++], entry);
	} else {
		ret = HDB_ERR_NOENTRY;
	}

	if (ret != 0) {
		TALLOC_FREE(priv);
		kdc_db_ctx->seq_ctx = NULL;
	} else {
		talloc_free(mem_ctx);
	}

	return ret;
}

krb5_error_code samba_kdc_firstkey(krb5_context context,
				   struct samba_kdc_db_context *kdc_db_ctx,
				   hdb_entry_ex *entry)
{
	struct ldb_context *ldb_ctx = kdc_db_ctx->samdb;
	struct samba_kdc_seq *priv = kdc_db_ctx->seq_ctx;
	char *realm;
	struct ldb_result *res = NULL;
	krb5_error_code ret;
	TALLOC_CTX *mem_ctx;
	int lret;

	if (priv) {
		TALLOC_FREE(priv);
		kdc_db_ctx->seq_ctx = NULL;
	}

	priv = (struct samba_kdc_seq *) talloc(kdc_db_ctx, struct samba_kdc_seq);
	if (!priv) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "talloc: out of memory");
		return ret;
	}

	priv->index = 0;
	priv->msgs = NULL;
	priv->realm_dn = ldb_get_default_basedn(ldb_ctx);
	priv->count = 0;

	mem_ctx = talloc_named(priv, 0, "samba_kdc_firstkey context");

	if (!mem_ctx) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "samba_kdc_firstkey: talloc_named() failed!");
		return ret;
	}

	ret = krb5_get_default_realm(context, &realm);
	if (ret != 0) {
		TALLOC_FREE(priv);
		return ret;
	}

	lret = ldb_search(ldb_ctx, priv, &res,
			  priv->realm_dn, LDB_SCOPE_SUBTREE, user_attrs,
			  "(objectClass=user)");

	if (lret != LDB_SUCCESS) {
		TALLOC_FREE(priv);
		return HDB_ERR_NOENTRY;
	}

	priv->count = res->count;
	priv->msgs = talloc_steal(priv, res->msgs);
	talloc_free(res);

	kdc_db_ctx->seq_ctx = priv;

	ret = samba_kdc_seq(context, kdc_db_ctx, entry);

	if (ret != 0) {
		TALLOC_FREE(priv);
		kdc_db_ctx->seq_ctx = NULL;
	} else {
		talloc_free(mem_ctx);
	}
	return ret;
}

krb5_error_code samba_kdc_nextkey(krb5_context context,
				  struct samba_kdc_db_context *kdc_db_ctx,
				  hdb_entry_ex *entry)
{
	return samba_kdc_seq(context, kdc_db_ctx, entry);
}

/* Check if a given entry may delegate or do s4u2self to this target principal
 *
 * This is currently a very nasty hack - allowing only delegation to itself.
 *
 * This is shared between the constrained delegation and S4U2Self code.
 */
krb5_error_code
samba_kdc_check_identical_client_and_server(krb5_context context,
					    struct samba_kdc_db_context *kdc_db_ctx,
					    hdb_entry_ex *entry,
					    krb5_const_principal target_principal)
{
	krb5_error_code ret;
	krb5_principal enterprise_prinicpal = NULL;
	struct ldb_dn *realm_dn;
	struct ldb_message *msg;
	struct dom_sid *orig_sid;
	struct dom_sid *target_sid;
	struct samba_kdc_entry *p = talloc_get_type(entry->ctx, struct samba_kdc_entry);
	const char *delegation_check_attrs[] = {
		"objectSid", NULL
	};

	TALLOC_CTX *mem_ctx = talloc_named(kdc_db_ctx, 0, "samba_kdc_check_constrained_delegation");

	if (!mem_ctx) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "samba_kdc_fetch: talloc_named() failed!");
		return ret;
	}

	if (target_principal->name.name_type == KRB5_NT_ENTERPRISE_PRINCIPAL) {
		/* Need to reparse the enterprise principal to find the real target */
		if (target_principal->name.name_string.len != 1) {
			ret = KRB5_PARSE_MALFORMED;
			krb5_set_error_message(context, ret, "samba_kdc_check_constrained_delegation: request for delegation to enterprise principal with wrong (%d) number of components",
					       target_principal->name.name_string.len);
			talloc_free(mem_ctx);
			return ret;
		}
		ret = krb5_parse_name(context, target_principal->name.name_string.val[0],
				      &enterprise_prinicpal);
		if (ret) {
			talloc_free(mem_ctx);
			return ret;
		}
		target_principal = enterprise_prinicpal;
	}

	ret = samba_kdc_lookup_server(context, kdc_db_ctx, mem_ctx, target_principal,
				       delegation_check_attrs, &realm_dn, &msg);

	krb5_free_principal(context, enterprise_prinicpal);

	if (ret != 0) {
		talloc_free(mem_ctx);
		return ret;
	}

	orig_sid = samdb_result_dom_sid(mem_ctx, p->msg, "objectSid");
	target_sid = samdb_result_dom_sid(mem_ctx, msg, "objectSid");

	/* Allow delegation to the same principal, even if by a different
	 * name.  The easy and safe way to prove this is by SID
	 * comparison */
	if (!(orig_sid && target_sid && dom_sid_equal(orig_sid, target_sid))) {
		talloc_free(mem_ctx);
		return KRB5KDC_ERR_BADOPTION;
	}

	talloc_free(mem_ctx);
	return ret;
}

/* Certificates printed by a the Certificate Authority might have a
 * slightly different form of the user principal name to that in the
 * database.  Allow a mismatch where they both refer to the same
 * SID */

krb5_error_code
samba_kdc_check_pkinit_ms_upn_match(krb5_context context,
				    struct samba_kdc_db_context *kdc_db_ctx,
				     hdb_entry_ex *entry,
				     krb5_const_principal certificate_principal)
{
	krb5_error_code ret;
	struct ldb_dn *realm_dn;
	struct ldb_message *msg;
	struct dom_sid *orig_sid;
	struct dom_sid *target_sid;
	struct samba_kdc_entry *p = talloc_get_type(entry->ctx, struct samba_kdc_entry);
	const char *ms_upn_check_attrs[] = {
		"objectSid", NULL
	};

	TALLOC_CTX *mem_ctx = talloc_named(kdc_db_ctx, 0, "samba_kdc_check_pkinit_ms_upn_match");

	if (!mem_ctx) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "samba_kdc_fetch: talloc_named() failed!");
		return ret;
	}

	ret = samba_kdc_lookup_client(context, kdc_db_ctx,
				       mem_ctx, certificate_principal,
				       ms_upn_check_attrs, &realm_dn, &msg);

	if (ret != 0) {
		talloc_free(mem_ctx);
		return ret;
	}

	orig_sid = samdb_result_dom_sid(mem_ctx, p->msg, "objectSid");
	target_sid = samdb_result_dom_sid(mem_ctx, msg, "objectSid");

	/* Consider these to be the same principal, even if by a different
	 * name.  The easy and safe way to prove this is by SID
	 * comparison */
	if (!(orig_sid && target_sid && dom_sid_equal(orig_sid, target_sid))) {
		talloc_free(mem_ctx);
		return KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;
	}

	talloc_free(mem_ctx);
	return ret;
}

