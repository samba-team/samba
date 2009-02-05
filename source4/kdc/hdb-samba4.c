/*
 * Copyright (c) 1999-2001, 2003, PADL Software Pty Ltd.
 * Copyright (c) 2004, Andrew Bartlett <abartlet@samba.org>.
 * Copyright (c) 2004, Stefan Metzmacher <metze@samba.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of PADL Software  nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "includes.h"
#include "system/time.h"
#include "dsdb/common/flags.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "librpc/gen_ndr/netlogon.h"
#include "auth/auth.h"
#include "auth/credentials/credentials.h"
#include "auth/auth_sam.h"
#include "../lib/util/util_ldb.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "librpc/gen_ndr/lsa.h"
#include "libcli/auth/libcli_auth.h"
#include "param/param.h"
#include "events/events.h"
#include "kdc/kdc.h"
#include "../lib/crypto/md4.h"

enum hdb_ldb_ent_type 
{ HDB_SAMBA4_ENT_TYPE_CLIENT, HDB_SAMBA4_ENT_TYPE_SERVER, 
  HDB_SAMBA4_ENT_TYPE_KRBTGT, HDB_SAMBA4_ENT_TYPE_TRUST, HDB_SAMBA4_ENT_TYPE_ANY };

enum trust_direction {
	UNKNOWN = 0,
	INBOUND = LSA_TRUST_DIRECTION_INBOUND, 
	OUTBOUND = LSA_TRUST_DIRECTION_OUTBOUND
};

static const char *realm_ref_attrs[] = {
	"nCName", 
	"dnsRoot", 
	NULL
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

static HDBFlags uf2HDBFlags(krb5_context context, int userAccountControl, enum hdb_ldb_ent_type ent_type) 
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
		if (ent_type == HDB_SAMBA4_ENT_TYPE_CLIENT || ent_type == HDB_SAMBA4_ENT_TYPE_ANY) {
			flags.client = 1;
		}
		flags.invalid = 0;
	}
	
	if (userAccountControl & UF_INTERDOMAIN_TRUST_ACCOUNT) {
		if (ent_type == HDB_SAMBA4_ENT_TYPE_CLIENT || ent_type == HDB_SAMBA4_ENT_TYPE_ANY) {
			flags.client = 1;
		}
		flags.invalid = 0;
	}
	if (userAccountControl & UF_WORKSTATION_TRUST_ACCOUNT) {
		if (ent_type == HDB_SAMBA4_ENT_TYPE_CLIENT || ent_type == HDB_SAMBA4_ENT_TYPE_ANY) {
			flags.client = 1;
		}
		flags.invalid = 0;
	}
	if (userAccountControl & UF_SERVER_TRUST_ACCOUNT) {
		if (ent_type == HDB_SAMBA4_ENT_TYPE_CLIENT || ent_type == HDB_SAMBA4_ENT_TYPE_ANY) {
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

/* UF_DONT_EXPIRE_PASSWD and UF_USE_DES_KEY_ONLY handled in LDB_message2entry() */

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

static int hdb_ldb_destructor(struct hdb_ldb_private *p)
{
    hdb_entry_ex *entry_ex = p->entry_ex;
    free_hdb_entry(&entry_ex->entry);
    return 0;
}

static void hdb_ldb_free_entry(krb5_context context, hdb_entry_ex *entry_ex)
{
	talloc_free(entry_ex->ctx);
}

static krb5_error_code LDB_message2entry_keys(krb5_context context,
					      struct smb_iconv_convenience *iconv_convenience,
					      TALLOC_CTX *mem_ctx,
					      struct ldb_message *msg,
					      unsigned int userAccountControl,
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
	uint32_t i;
	uint32_t allocated_keys = 0;

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
		ndr_err = ndr_pull_struct_blob_all(sc_val, mem_ctx, iconv_convenience, &scb,
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
		ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, iconv_convenience, &_pkb,
					       (ndr_pull_flags_fn_t)ndr_pull_package_PrimaryKerberosBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			krb5_set_error_string(context, "LDB_message2entry_keys: could not parse package_PrimaryKerberosBlob");
			krb5_warnx(context, "LDB_message2entry_keys: could not parse package_PrimaryKerberosBlob");
			ret = EINVAL;
			goto out;
		}

		if (newer_keys && _pkb.version != 4) {
			krb5_set_error_string(context, "LDB_message2entry_keys: Primary:Kerberos-Newer-Keys not version 4");
			krb5_warnx(context, "LDB_message2entry_keys: Primary:Kerberos-Newer-Keys not version 4");
			ret = EINVAL;
			goto out;
		}

		if (!newer_keys && _pkb.version != 3) {
			krb5_set_error_string(context, "LDB_message2entry_keys: could not parse Primary:Kerberos not version 3");
			krb5_warnx(context, "LDB_message2entry_keys: could not parse Primary:Kerberos not version 3");
			ret = EINVAL;
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

	if (hash && !(userAccountControl & UF_USE_DES_KEY_ONLY)) {
		Key key;

		key.mkvno = 0;
		key.salt = NULL; /* No salt for this enc type */

		ret = krb5_keyblock_init(context,
					 ENCTYPE_ARCFOUR_HMAC_MD5,
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
			bool use = true;
			Key key;

			if (!pkb4->keys[i].value) continue;

			if (userAccountControl & UF_USE_DES_KEY_ONLY) {
				switch (pkb4->keys[i].keytype) {
				case ENCTYPE_DES_CBC_CRC:
				case ENCTYPE_DES_CBC_MD5:
					break;
				default:
					use = false;
					break;
				}
			}

			if (!use) continue;

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
			bool use = true;
			Key key;

			if (!pkb3->keys[i].value) continue;

			if (userAccountControl & UF_USE_DES_KEY_ONLY) {
				switch (pkb3->keys[i].keytype) {
				case ENCTYPE_DES_CBC_CRC:
				case ENCTYPE_DES_CBC_MD5:
					break;
				default:
					use = false;
					break;
				}
			}

			if (!use) continue;

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
static krb5_error_code LDB_message2entry(krb5_context context, HDB *db, 
					 TALLOC_CTX *mem_ctx, krb5_const_principal principal,
					 enum hdb_ldb_ent_type ent_type, 
					 struct ldb_message *msg,
					 struct ldb_message *realm_ref_msg,
					 hdb_entry_ex *entry_ex)
{
	unsigned int userAccountControl;
	int i;
	krb5_error_code ret = 0;
	krb5_boolean is_computer = FALSE;
	const char *dnsdomain = ldb_msg_find_attr_as_string(realm_ref_msg, "dnsRoot", NULL);
	char *realm = strupper_talloc(mem_ctx, dnsdomain);
	struct loadparm_context *lp_ctx = ldb_get_opaque((struct ldb_context *)db->hdb_db, "loadparm");
	struct ldb_dn *domain_dn = samdb_result_dn((struct ldb_context *)db->hdb_db,
							mem_ctx,
							realm_ref_msg,
							"nCName",
							ldb_dn_new(mem_ctx, (struct ldb_context *)db->hdb_db, NULL));

	struct hdb_ldb_private *p;
	NTTIME acct_expiry;

	struct ldb_message_element *objectclasses;
	struct ldb_val computer_val;
	computer_val.data = discard_const_p(uint8_t,"computer");
	computer_val.length = strlen((const char *)computer_val.data);
	
	objectclasses = ldb_msg_find_element(msg, "objectClass");
	
	if (objectclasses && ldb_msg_find_val(objectclasses, &computer_val)) {
		is_computer = TRUE;
	}

	memset(entry_ex, 0, sizeof(*entry_ex));

	if (!realm) {
		krb5_set_error_string(context, "talloc_strdup: out of memory");
		ret = ENOMEM;
		goto out;
	}
			
	p = talloc(mem_ctx, struct hdb_ldb_private);
	if (!p) {
		ret = ENOMEM;
		goto out;
	}

	p->entry_ex = entry_ex;
	p->iconv_convenience = lp_iconv_convenience(lp_ctx);
	p->netbios_name = lp_netbios_name(lp_ctx);

	talloc_set_destructor(p, hdb_ldb_destructor);

	entry_ex->ctx = p;
	entry_ex->free_entry = hdb_ldb_free_entry;

	userAccountControl = ldb_msg_find_attr_as_uint(msg, "userAccountControl", 0);

	
	entry_ex->entry.principal = malloc(sizeof(*(entry_ex->entry.principal)));
	if (ent_type == HDB_SAMBA4_ENT_TYPE_ANY && principal == NULL) {
		const char *samAccountName = ldb_msg_find_attr_as_string(msg, "samAccountName", NULL);
		if (!samAccountName) {
			krb5_set_error_string(context, "LDB_message2entry: no samAccountName present");
			ret = ENOENT;
			goto out;
		}
		samAccountName = ldb_msg_find_attr_as_string(msg, "samAccountName", NULL);
		krb5_make_principal(context, &entry_ex->entry.principal, realm, samAccountName, NULL);
	} else {
		char *strdup_realm;
		ret = copy_Principal(principal, entry_ex->entry.principal);
		if (ret) {
			krb5_clear_error_string(context);
			goto out;
		}

		/* While we have copied the client principal, tests
		 * show that Win2k3 returns the 'corrected' realm, not
		 * the client-specified realm.  This code attempts to
		 * replace the client principal's realm with the one
		 * we determine from our records */
		
		/* this has to be with malloc() */
		strdup_realm = strdup(realm);
		if (!strdup_realm) {
			ret = ENOMEM;
			krb5_clear_error_string(context);
			goto out;
		}
		free(*krb5_princ_realm(context, entry_ex->entry.principal));
		krb5_princ_set_realm(context, entry_ex->entry.principal, &strdup_realm);
	}

	entry_ex->entry.flags = uf2HDBFlags(context, userAccountControl, ent_type);

	if (ent_type == HDB_SAMBA4_ENT_TYPE_KRBTGT) {
		entry_ex->entry.flags.invalid = 0;
		entry_ex->entry.flags.server = 1;
		entry_ex->entry.flags.forwardable = 1;
		entry_ex->entry.flags.ok_as_delegate = 1;
	}

	if (lp_parm_bool(lp_ctx, NULL, "kdc", "require spn for service", true)) {
		if (!is_computer && !ldb_msg_find_attr_as_string(msg, "servicePrincipalName", NULL)) {
			entry_ex->entry.flags.server = 0;
		}
	}

	/* use 'whenCreated' */
	entry_ex->entry.created_by.time = ldb_msg_find_krb5time_ldap_time(msg, "whenCreated", 0);
	/* use '???' */
	entry_ex->entry.created_by.principal = NULL;

	entry_ex->entry.modified_by = (Event *) malloc(sizeof(Event));
	if (entry_ex->entry.modified_by == NULL) {
		krb5_set_error_string(context, "malloc: out of memory");
		ret = ENOMEM;
		goto out;
	}

	/* use 'whenChanged' */
	entry_ex->entry.modified_by->time = ldb_msg_find_krb5time_ldap_time(msg, "whenChanged", 0);
	/* use '???' */
	entry_ex->entry.modified_by->principal = NULL;

	entry_ex->entry.valid_start = NULL;

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

	if (ent_type != HDB_SAMBA4_ENT_TYPE_KRBTGT) {
		NTTIME must_change_time
			= samdb_result_force_password_change((struct ldb_context *)db->hdb_db, mem_ctx, 
							     domain_dn, msg);
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
	} else {
		entry_ex->entry.pw_end = NULL;
	}
			
	entry_ex->entry.max_life = NULL;

	entry_ex->entry.max_renew = NULL;

	entry_ex->entry.generation = NULL;

	/* Get keys from the db */
	ret = LDB_message2entry_keys(context, p->iconv_convenience, p, msg, userAccountControl, entry_ex);
	if (ret) {
		/* Could be bougus data in the entry, or out of memory */
		goto out;
	}

	entry_ex->entry.etypes = malloc(sizeof(*(entry_ex->entry.etypes)));
	if (entry_ex->entry.etypes == NULL) {
		krb5_clear_error_string(context);
		ret = ENOMEM;
		goto out;
	}
	entry_ex->entry.etypes->len = entry_ex->entry.keys.len;
	entry_ex->entry.etypes->val = calloc(entry_ex->entry.etypes->len, sizeof(int));
	if (entry_ex->entry.etypes->val == NULL) {
		krb5_clear_error_string(context);
		ret = ENOMEM;
		goto out;
	}
	for (i=0; i < entry_ex->entry.etypes->len; i++) {
		entry_ex->entry.etypes->val[i] = entry_ex->entry.keys.val[i].key.keytype;
	}


	p->msg = talloc_steal(p, msg);
	p->realm_ref_msg = talloc_steal(p, realm_ref_msg);
	p->samdb = (struct ldb_context *)db->hdb_db;
	
out:
	if (ret != 0) {
		/* This doesn't free ent itself, that is for the eventual caller to do */
		hdb_free_entry(context, entry_ex);
	} else {
		talloc_steal(db, entry_ex->ctx);
	}

	return ret;
}

/*
 * Construct an hdb_entry from a directory entry.
 */
static krb5_error_code LDB_trust_message2entry(krb5_context context, HDB *db, 
					       struct loadparm_context *lp_ctx,
					       TALLOC_CTX *mem_ctx, krb5_const_principal principal,
					       enum trust_direction direction,
					       struct ldb_message *msg,
					       hdb_entry_ex *entry_ex)
{
	
	const char *dnsdomain;
	char *realm;
	char *strdup_realm;
	DATA_BLOB password_utf16;
	struct samr_Password password_hash;
	const struct ldb_val *password_val;
	struct trustAuthInOutBlob password_blob;
	struct hdb_ldb_private *p;

	enum ndr_err_code ndr_err;
	int i, ret, trust_direction_flags;

	p = talloc(mem_ctx, struct hdb_ldb_private);
	if (!p) {
		ret = ENOMEM;
		goto out;
	}

	p->entry_ex = entry_ex;
	p->iconv_convenience = lp_iconv_convenience(lp_ctx);
	p->netbios_name = lp_netbios_name(lp_ctx);

	talloc_set_destructor(p, hdb_ldb_destructor);

	entry_ex->ctx = p;
	entry_ex->free_entry = hdb_ldb_free_entry;

	/* use 'whenCreated' */
	entry_ex->entry.created_by.time = ldb_msg_find_krb5time_ldap_time(msg, "whenCreated", 0);
	/* use '???' */
	entry_ex->entry.created_by.principal = NULL;

	entry_ex->entry.valid_start = NULL;

	trust_direction_flags = ldb_msg_find_attr_as_int(msg, "trustDirection", 0);

	if (direction == INBOUND) {
		realm = strupper_talloc(mem_ctx, lp_realm(lp_ctx));
		password_val = ldb_msg_find_ldb_val(msg, "trustAuthIncoming");

	} else { /* OUTBOUND */
		dnsdomain = ldb_msg_find_attr_as_string(msg, "trustPartner", NULL);
		realm = strupper_talloc(mem_ctx, dnsdomain);
		password_val = ldb_msg_find_ldb_val(msg, "trustAuthOutgoing");
	}

	if (!password_val || !(trust_direction_flags & direction)) {
		ret = ENOENT;
		goto out;
	}

	ndr_err = ndr_pull_struct_blob(password_val, mem_ctx, p->iconv_convenience, &password_blob,
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
	entry_ex->entry.keys.len = 0;
	entry_ex->entry.keys.val = NULL;

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
					 ENCTYPE_ARCFOUR_HMAC_MD5,
					 password_hash.hash, sizeof(password_hash.hash), 
					 &key.key);
		
		entry_ex->entry.keys.val[entry_ex->entry.keys.len] = key;
		entry_ex->entry.keys.len++;
	}
		
	entry_ex->entry.principal = malloc(sizeof(*(entry_ex->entry.principal)));

	ret = copy_Principal(principal, entry_ex->entry.principal);
	if (ret) {
		krb5_clear_error_string(context);
		goto out;
	}
	
	/* While we have copied the client principal, tests
	 * show that Win2k3 returns the 'corrected' realm, not
	 * the client-specified realm.  This code attempts to
	 * replace the client principal's realm with the one
	 * we determine from our records */
	
	/* this has to be with malloc() */
	strdup_realm = strdup(realm);
	if (!strdup_realm) {
		ret = ENOMEM;
		krb5_clear_error_string(context);
		goto out;
	}
	free(*krb5_princ_realm(context, entry_ex->entry.principal));
	krb5_princ_set_realm(context, entry_ex->entry.principal, &strdup_realm);
	
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
		krb5_clear_error_string(context);
		ret = ENOMEM;
		goto out;
	}
	entry_ex->entry.etypes->len = entry_ex->entry.keys.len;
	entry_ex->entry.etypes->val = calloc(entry_ex->entry.etypes->len, sizeof(int));
	if (entry_ex->entry.etypes->val == NULL) {
		krb5_clear_error_string(context);
		ret = ENOMEM;
		goto out;
	}
	for (i=0; i < entry_ex->entry.etypes->len; i++) {
		entry_ex->entry.etypes->val[i] = entry_ex->entry.keys.val[i].key.keytype;
	}


	p->msg = talloc_steal(p, msg);
	p->realm_ref_msg = NULL;
	p->samdb = (struct ldb_context *)db->hdb_db;
	
out:
	if (ret != 0) {
		/* This doesn't free ent itself, that is for the eventual caller to do */
		hdb_free_entry(context, entry_ex);
	} else {
		talloc_steal(db, entry_ex->ctx);
	}

	return ret;

}

static krb5_error_code LDB_lookup_principal(krb5_context context, struct ldb_context *ldb_ctx, 					
					    TALLOC_CTX *mem_ctx,
					    krb5_const_principal principal,
					    enum hdb_ldb_ent_type ent_type,
					    struct ldb_dn *realm_dn,
					    struct ldb_message ***pmsg)
{
	krb5_error_code ret;
	int lret;
	char *filter = NULL;
	const char * const *princ_attrs = user_attrs;

	char *short_princ;
	char *short_princ_talloc;

	struct ldb_result *res = NULL;

	ret = krb5_unparse_name_flags(context, principal,  KRB5_PRINCIPAL_UNPARSE_NO_REALM, &short_princ);

	if (ret != 0) {
		krb5_set_error_string(context, "LDB_lookup_principal: could not parse principal");
		krb5_warnx(context, "LDB_lookup_principal: could not parse principal");
		return ret;
	}

	short_princ_talloc = talloc_strdup(mem_ctx, short_princ);
	free(short_princ);
	if (!short_princ_talloc) {
		krb5_set_error_string(context, "LDB_lookup_principal: talloc_strdup() failed!");
		return ENOMEM;
	}

	switch (ent_type) {
	case HDB_SAMBA4_ENT_TYPE_CLIENT:
	case HDB_SAMBA4_ENT_TYPE_TRUST:
	case HDB_SAMBA4_ENT_TYPE_ANY:
		/* Can't happen */
		return EINVAL;
	case HDB_SAMBA4_ENT_TYPE_KRBTGT:
		filter = talloc_asprintf(mem_ctx, "(&(objectClass=user)(samAccountName=%s))", 
					 KRB5_TGS_NAME);
		break;
	case HDB_SAMBA4_ENT_TYPE_SERVER:
		filter = talloc_asprintf(mem_ctx, "(&(objectClass=user)(samAccountName=%s))", 
					 short_princ_talloc);
		break;
	}

	if (!filter) {
		krb5_set_error_string(context, "talloc_asprintf: out of memory");
		return ENOMEM;
	}

	lret = ldb_search(ldb_ctx, mem_ctx, &res, realm_dn,
			  LDB_SCOPE_SUBTREE, princ_attrs, "%s", filter);
	if (lret != LDB_SUCCESS) {
		DEBUG(3, ("Failed to search for %s: %s\n", filter, ldb_errstring(ldb_ctx)));
		return HDB_ERR_NOENTRY;
	} else if (res->count == 0 || res->count > 1) {
		DEBUG(3, ("Failed find a single entry for %s: got %d\n", filter, res->count));
		talloc_free(res);
		return HDB_ERR_NOENTRY;
	}
	talloc_steal(mem_ctx, res->msgs);
	*pmsg = res->msgs;
	talloc_free(res);
	return 0;
}

static krb5_error_code LDB_lookup_trust(krb5_context context, struct ldb_context *ldb_ctx, 					
					TALLOC_CTX *mem_ctx,
					const char *realm,
					struct ldb_dn *realm_dn,
					struct ldb_message ***pmsg)
{
	int lret;
	char *filter = NULL;
	const char * const *attrs = trust_attrs;

	struct ldb_result *res = NULL;
	filter = talloc_asprintf(mem_ctx, "(&(objectClass=trustedDomain)(|(flatname=%s)(trustPartner=%s)))", realm, realm);

	if (!filter) {
		krb5_set_error_string(context, "talloc_asprintf: out of memory");
		return ENOMEM;
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
	*pmsg = res->msgs;
	talloc_free(res);
	return 0;
}

static krb5_error_code LDB_lookup_realm(krb5_context context, struct ldb_context *ldb_ctx, 
					TALLOC_CTX *mem_ctx,
					const char *realm,
					struct ldb_message ***pmsg)
{
 	int ret;
	struct ldb_result *cross_ref_res;
	struct ldb_dn *partitions_basedn = samdb_partitions_dn(ldb_ctx, mem_ctx);

	ret = ldb_search(ldb_ctx, mem_ctx, &cross_ref_res,
			partitions_basedn, LDB_SCOPE_SUBTREE, realm_ref_attrs,
			"(&(&(|(&(dnsRoot=%s)(nETBIOSName=*))(nETBIOSName=%s))(objectclass=crossRef))(ncName=*))",
			realm, realm);

	if (ret != LDB_SUCCESS) {
		DEBUG(3, ("Failed to search to lookup realm(%s): %s\n", realm, ldb_errstring(ldb_ctx)));
		talloc_free(cross_ref_res);
		return HDB_ERR_NOENTRY;
	} else if (cross_ref_res->count == 0 || cross_ref_res->count > 1) {
		DEBUG(3, ("Failed find a single entry for realm %s: got %d\n", realm, cross_ref_res->count));
		talloc_free(cross_ref_res);
		return HDB_ERR_NOENTRY;
	}

	if (pmsg) {
		*pmsg = cross_ref_res->msgs;
		talloc_steal(mem_ctx, cross_ref_res->msgs);
	}
	talloc_free(cross_ref_res);

	return 0;
}


static krb5_error_code LDB_open(krb5_context context, HDB *db, int flags, mode_t mode)
{
	if (db->hdb_master_key_set) {
		krb5_warnx(context, "LDB_open: use of a master key incompatible with LDB\n");
		krb5_set_error_string(context, "LDB_open: use of a master key incompatible with LDB\n");
		return HDB_ERR_NOENTRY;
	}		

	return 0;
}

static krb5_error_code LDB_close(krb5_context context, HDB *db)
{
	return 0;
}

static krb5_error_code LDB_lock(krb5_context context, HDB *db, int operation)
{
	return 0;
}

static krb5_error_code LDB_unlock(krb5_context context, HDB *db)
{
	return 0;
}

static krb5_error_code LDB_rename(krb5_context context, HDB *db, const char *new_name)
{
	return HDB_ERR_DB_INUSE;
}

static krb5_error_code LDB_fetch_client(krb5_context context, HDB *db, 
					TALLOC_CTX *mem_ctx, 
					krb5_const_principal principal,
					unsigned flags,
					hdb_entry_ex *entry_ex) {
	NTSTATUS nt_status;
	char *principal_string;
	krb5_error_code ret;
	struct ldb_message **msg = NULL;
	struct ldb_message **realm_ref_msg = NULL;

	ret = krb5_unparse_name(context, principal, &principal_string);
	
	if (ret != 0) {
		return ret;
	}
	
	nt_status = sam_get_results_principal((struct ldb_context *)db->hdb_db,
					      mem_ctx, principal_string, 
					      &msg, &realm_ref_msg);
	free(principal_string);
	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_SUCH_USER)) {
		return HDB_ERR_NOENTRY;
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_MEMORY)) {
		return ENOMEM;
	} else if (!NT_STATUS_IS_OK(nt_status)) {
		return EINVAL;
	}
	
	ret = LDB_message2entry(context, db, mem_ctx, 
				principal, HDB_SAMBA4_ENT_TYPE_CLIENT,
				msg[0], realm_ref_msg[0], entry_ex);
	return ret;
}

static krb5_error_code LDB_fetch_krbtgt(krb5_context context, HDB *db, 
					TALLOC_CTX *mem_ctx, 
					krb5_const_principal principal,
					unsigned flags,
					hdb_entry_ex *entry_ex)
{
	krb5_error_code ret;
	struct ldb_message **msg = NULL;
	struct ldb_message **realm_ref_msg_1 = NULL;
	struct ldb_message **realm_ref_msg_2 = NULL;
	struct ldb_dn *realm_dn;
	const char *realm;

	krb5_principal alloc_principal = NULL;
	if (principal->name.name_string.len != 2
	    || (strcmp(principal->name.name_string.val[0], KRB5_TGS_NAME) != 0)) {
		/* Not a krbtgt */
		return HDB_ERR_NOENTRY;
	}

	/* krbtgt case.  Either us or a trusted realm */

	if ((LDB_lookup_realm(context, (struct ldb_context *)db->hdb_db,
			      mem_ctx, principal->realm, &realm_ref_msg_1) == 0)
	    && (LDB_lookup_realm(context, (struct ldb_context *)db->hdb_db,
				 mem_ctx, principal->name.name_string.val[1], &realm_ref_msg_2) == 0)
	    && (ldb_dn_compare(realm_ref_msg_1[0]->dn, realm_ref_msg_1[0]->dn) == 0)) {
		/* us */		
 		/* Cludge, cludge cludge.  If the realm part of krbtgt/realm,
 		 * is in our db, then direct the caller at our primary
 		 * krbtgt */
 		
 		const char *dnsdomain = ldb_msg_find_attr_as_string(realm_ref_msg_1[0], "dnsRoot", NULL);
 		char *realm_fixed = strupper_talloc(mem_ctx, dnsdomain);
 		if (!realm_fixed) {
 			krb5_set_error_string(context, "strupper_talloc: out of memory");
 			return ENOMEM;
 		}
 		
 		ret = krb5_copy_principal(context, principal, &alloc_principal);
 		if (ret) {
 			return ret;
 		}
 
 		free(alloc_principal->name.name_string.val[1]);
		alloc_principal->name.name_string.val[1] = strdup(realm_fixed);
 		talloc_free(realm_fixed);
 		if (!alloc_principal->name.name_string.val[1]) {
 			krb5_set_error_string(context, "LDB_fetch: strdup() failed!");
 			return ENOMEM;
 		}
 		principal = alloc_principal;
		realm_dn = samdb_result_dn((struct ldb_context *)db->hdb_db, mem_ctx, realm_ref_msg_1[0], "nCName", NULL);
		
		ret = LDB_lookup_principal(context, (struct ldb_context *)db->hdb_db, 
					   mem_ctx, 
					   principal, HDB_SAMBA4_ENT_TYPE_KRBTGT, realm_dn, &msg);
		
		if (ret != 0) {
			krb5_warnx(context, "LDB_fetch: could not find principal in DB");
			krb5_set_error_string(context, "LDB_fetch: could not find principal in DB");
			return ret;
		}
		
		ret = LDB_message2entry(context, db, mem_ctx, 
					principal, HDB_SAMBA4_ENT_TYPE_KRBTGT, 
					msg[0], realm_ref_msg_1[0], entry_ex);
		if (ret != 0) {
			krb5_warnx(context, "LDB_fetch: self krbtgt message2entry failed");	
		}
		return ret;

	} else {
		enum trust_direction direction = UNKNOWN;

		struct loadparm_context *lp_ctx = talloc_get_type(ldb_get_opaque(db->hdb_db, "loadparm"), struct loadparm_context);
		/* Either an inbound or outbound trust */

		if (strcasecmp(lp_realm(lp_ctx), principal->realm) == 0) {
			/* look for inbound trust */
			direction = INBOUND;
			realm = principal->name.name_string.val[1];
		}

		if (strcasecmp(lp_realm(lp_ctx), principal->name.name_string.val[1]) == 0) {
			/* look for outbound trust */
			direction = OUTBOUND;
			realm = principal->realm;
		}

		/* Trusted domains are under CN=system */
		
		ret = LDB_lookup_trust(context, (struct ldb_context *)db->hdb_db, 
				       mem_ctx, 
				       realm, realm_dn, &msg);
		
		if (ret != 0) {
			krb5_warnx(context, "LDB_fetch: could not find principal in DB");
			krb5_set_error_string(context, "LDB_fetch: could not find principal in DB");
			return ret;
		}
		
		ret = LDB_trust_message2entry(context, db, lp_ctx, mem_ctx, 
					      principal, direction, 
					      msg[0], entry_ex);
		if (ret != 0) {
			krb5_warnx(context, "LDB_fetch: trust_message2entry failed");	
		}
		return ret;

		
		/* we should lookup trusted domains */
		return HDB_ERR_NOENTRY;
	}

}

static krb5_error_code LDB_fetch_server(krb5_context context, HDB *db, 
					TALLOC_CTX *mem_ctx, 
					krb5_const_principal principal,
					unsigned flags,
					hdb_entry_ex *entry_ex)
{
	krb5_error_code ret;
	const char *realm;
	struct ldb_message **msg = NULL;
	struct ldb_message **realm_ref_msg = NULL;
	struct ldb_dn *partitions_basedn = samdb_partitions_dn(db->hdb_db, mem_ctx);
	if (principal->name.name_string.len >= 2) {
		/* 'normal server' case */
		int ldb_ret;
		NTSTATUS nt_status;
		struct ldb_dn *user_dn, *domain_dn;
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
		nt_status = crack_service_principal_name((struct ldb_context *)db->hdb_db,
							 mem_ctx, principal_string, 
							 &user_dn, &domain_dn);
		free(principal_string);
		
		if (!NT_STATUS_IS_OK(nt_status)) {
			return HDB_ERR_NOENTRY;
		}
		
		ldb_ret = gendb_search_dn((struct ldb_context *)db->hdb_db,
					  mem_ctx, user_dn, &msg, user_attrs);
		
		if (ldb_ret != 1) {
			return HDB_ERR_NOENTRY;
		}
		
		ldb_ret = gendb_search((struct ldb_context *)db->hdb_db,
				       mem_ctx, partitions_basedn, &realm_ref_msg, realm_ref_attrs, 
				       "ncName=%s", ldb_dn_get_linearized(domain_dn));
		
		if (ldb_ret != 1) {
			return HDB_ERR_NOENTRY;
		}
		
	} else {
		struct ldb_dn *realm_dn;
		/* server as client principal case, but we must not lookup userPrincipalNames */

		realm = krb5_principal_get_realm(context, principal);
		
		ret = LDB_lookup_realm(context, (struct ldb_context *)db->hdb_db, 
				       mem_ctx, realm, &realm_ref_msg);
		if (ret != 0) {
			return HDB_ERR_NOENTRY;
		}
		
		realm_dn = samdb_result_dn((struct ldb_context *)db->hdb_db, mem_ctx, realm_ref_msg[0], "nCName", NULL);
		
		ret = LDB_lookup_principal(context, (struct ldb_context *)db->hdb_db, 
					   mem_ctx, 
					   principal, HDB_SAMBA4_ENT_TYPE_SERVER, realm_dn, &msg);
		
		if (ret != 0) {
			return ret;
		}
	}

	ret = LDB_message2entry(context, db, mem_ctx, 
				principal, HDB_SAMBA4_ENT_TYPE_SERVER,
				msg[0], realm_ref_msg[0], entry_ex);
	if (ret != 0) {
		krb5_warnx(context, "LDB_fetch: message2entry failed");	
	}

	return ret;
}
			
static krb5_error_code LDB_fetch(krb5_context context, HDB *db, 
				 krb5_const_principal principal,
				 unsigned flags,
				 hdb_entry_ex *entry_ex)
{
	krb5_error_code ret = HDB_ERR_NOENTRY;

	TALLOC_CTX *mem_ctx = talloc_named(db, 0, "LDB_fetch context");

	if (!mem_ctx) {
		krb5_set_error_string(context, "LDB_fetch: talloc_named() failed!");
		return ENOMEM;
	}

	if (flags & HDB_F_GET_CLIENT) {
		ret = LDB_fetch_client(context, db, mem_ctx, principal, flags, entry_ex);
		if (ret != HDB_ERR_NOENTRY) goto done;
	}
	if (flags & HDB_F_GET_SERVER) {
		/* krbtgt fits into this situation for trusted realms, and for resolving different versions of our own realm name */
		ret = LDB_fetch_krbtgt(context, db, mem_ctx, principal, flags, entry_ex);
		if (ret != HDB_ERR_NOENTRY) goto done;

		/* We return 'no entry' if it does not start with krbtgt/, so move to the common case quickly */
		ret = LDB_fetch_server(context, db, mem_ctx, principal, flags, entry_ex);
		if (ret != HDB_ERR_NOENTRY) goto done;
	}
	if (flags & HDB_F_GET_KRBTGT) {
		ret = LDB_fetch_krbtgt(context, db, mem_ctx, principal, flags, entry_ex);
		if (ret != HDB_ERR_NOENTRY) goto done;
	}

done:
	talloc_free(mem_ctx);
	return ret;
}

static krb5_error_code LDB_store(krb5_context context, HDB *db, unsigned flags, hdb_entry_ex *entry)
{
	return HDB_ERR_DB_INUSE;
}

static krb5_error_code LDB_remove(krb5_context context, HDB *db, krb5_const_principal principal)
{
	return HDB_ERR_DB_INUSE;
}

struct hdb_ldb_seq {
	struct ldb_context *ctx;
	int index;
	int count;
	struct ldb_message **msgs;
	struct ldb_message **realm_ref_msgs;
};

static krb5_error_code LDB_seq(krb5_context context, HDB *db, unsigned flags, hdb_entry_ex *entry)
{
	krb5_error_code ret;
	struct hdb_ldb_seq *priv = (struct hdb_ldb_seq *)db->hdb_dbc;
	TALLOC_CTX *mem_ctx;
	hdb_entry_ex entry_ex;
	memset(&entry_ex, '\0', sizeof(entry_ex));

	if (!priv) {
		return HDB_ERR_NOENTRY;
	}

	mem_ctx = talloc_named(priv, 0, "LDB_seq context");

	if (!mem_ctx) {
		krb5_set_error_string(context, "LDB_seq: talloc_named() failed!");
		return ENOMEM;
	}

	if (priv->index < priv->count) {
		ret = LDB_message2entry(context, db, mem_ctx, 
					NULL, HDB_SAMBA4_ENT_TYPE_ANY, 
					priv->msgs[priv->index++], 
					priv->realm_ref_msgs[0], entry);
	} else {
		ret = HDB_ERR_NOENTRY;
	}

	if (ret != 0) {
		talloc_free(priv);
		db->hdb_dbc = NULL;
	} else {
		talloc_free(mem_ctx);
	}

	return ret;
}

static krb5_error_code LDB_firstkey(krb5_context context, HDB *db, unsigned flags,
					hdb_entry_ex *entry)
{
	struct ldb_context *ldb_ctx = (struct ldb_context *)db->hdb_db;
	struct hdb_ldb_seq *priv = (struct hdb_ldb_seq *)db->hdb_dbc;
	char *realm;
	struct ldb_dn *realm_dn = NULL;
	struct ldb_result *res = NULL;
	struct ldb_message **realm_ref_msgs = NULL;
	krb5_error_code ret;
	TALLOC_CTX *mem_ctx;
	int lret;

	if (priv) {
		talloc_free(priv);
		db->hdb_dbc = NULL;
	}

	priv = (struct hdb_ldb_seq *) talloc(db, struct hdb_ldb_seq);
	if (!priv) {
		krb5_set_error_string(context, "talloc: out of memory");
		return ENOMEM;
	}

	priv->ctx = ldb_ctx;
	priv->index = 0;
	priv->msgs = NULL;
	priv->realm_ref_msgs = NULL;
	priv->count = 0;

	mem_ctx = talloc_named(priv, 0, "LDB_firstkey context");

	if (!mem_ctx) {
		krb5_set_error_string(context, "LDB_firstkey: talloc_named() failed!");
		return ENOMEM;
	}

	ret = krb5_get_default_realm(context, &realm);
	if (ret != 0) {
		talloc_free(priv);
		return ret;
	}
		
	ret = LDB_lookup_realm(context, (struct ldb_context *)db->hdb_db, 
			       mem_ctx, realm, &realm_ref_msgs);

	free(realm);

	if (ret != 0) {
		talloc_free(priv);
		krb5_warnx(context, "LDB_firstkey: could not find realm\n");
		return HDB_ERR_NOENTRY;
	}

	realm_dn = samdb_result_dn((struct ldb_context *)db->hdb_db, mem_ctx, realm_ref_msgs[0], "nCName", NULL);

	priv->realm_ref_msgs = talloc_steal(priv, realm_ref_msgs);

	lret = ldb_search(ldb_ctx, priv, &res,
			  realm_dn, LDB_SCOPE_SUBTREE, user_attrs,
			  "(objectClass=user)");

	if (lret != LDB_SUCCESS) {
		talloc_free(priv);
		return HDB_ERR_NOENTRY;
	}

	priv->count = res->count;
	priv->msgs = talloc_steal(priv, res->msgs);
	talloc_free(res);

	db->hdb_dbc = priv;

	ret = LDB_seq(context, db, flags, entry);

	if (ret != 0) {
    		talloc_free(priv);
		db->hdb_dbc = NULL;
	} else {
		talloc_free(mem_ctx);
	}
	return ret;
}

static krb5_error_code LDB_nextkey(krb5_context context, HDB *db, unsigned flags,
				   hdb_entry_ex *entry)
{
	return LDB_seq(context, db, flags, entry);
}

static krb5_error_code LDB_destroy(krb5_context context, HDB *db)
{
	talloc_free(db);
	return 0;
}

/* This interface is to be called by the KDC, which is expecting Samba
 * calling conventions.  It is also called by a wrapper
 * (hdb_ldb_create) from the kpasswdd -> krb5 -> keytab_hdb -> hdb
 * code */

NTSTATUS kdc_hdb_samba4_create(TALLOC_CTX *mem_ctx, 
			    struct tevent_context *ev_ctx, 
			    struct loadparm_context *lp_ctx,
			    krb5_context context, struct HDB **db, const char *arg)
{
	NTSTATUS nt_status;
	struct auth_session_info *session_info;
	*db = talloc(mem_ctx, HDB);
	if (!*db) {
		krb5_set_error_string(context, "malloc: out of memory");
		return NT_STATUS_NO_MEMORY;
	}

	(*db)->hdb_master_key_set = 0;
	(*db)->hdb_db = NULL;

	nt_status = auth_system_session_info(*db, lp_ctx, &session_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}
	
	/* The idea here is very simple.  Using Kerberos to
	 * authenticate the KDC to the LDAP server is higly likely to
	 * be circular.
	 *
	 * In future we may set this up to use EXERNAL and SSL
	 * certificates, for now it will almost certainly be NTLMSSP
	*/
	
	cli_credentials_set_kerberos_state(session_info->credentials, 
					   CRED_DONT_USE_KERBEROS);

	/* Setup the link to LDB */
	(*db)->hdb_db = samdb_connect(*db, ev_ctx, lp_ctx, session_info);
	if ((*db)->hdb_db == NULL) {
		DEBUG(1, ("hdb_ldb_create: Cannot open samdb for KDC backend!"));
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	(*db)->hdb_dbc = NULL;
	(*db)->hdb_open = LDB_open;
	(*db)->hdb_close = LDB_close;
	(*db)->hdb_fetch = LDB_fetch;
	(*db)->hdb_store = LDB_store;
	(*db)->hdb_remove = LDB_remove;
	(*db)->hdb_firstkey = LDB_firstkey;
	(*db)->hdb_nextkey = LDB_nextkey;
	(*db)->hdb_lock = LDB_lock;
	(*db)->hdb_unlock = LDB_unlock;
	(*db)->hdb_rename = LDB_rename;
	/* we don't implement these, as we are not a lockable database */
	(*db)->hdb__get = NULL;
	(*db)->hdb__put = NULL;
	/* kadmin should not be used for deletes - use other tools instead */
	(*db)->hdb__del = NULL;
	(*db)->hdb_destroy = LDB_destroy;

	return NT_STATUS_OK;
}

krb5_error_code hdb_samba4_create(krb5_context context, struct HDB **db, const char *arg)
{
	NTSTATUS nt_status;
	/* The global kdc_mem_ctx and kdc_lp_ctx, Disgusting, ugly hack, but it means one less private hook */
	nt_status = kdc_hdb_samba4_create(kdc_mem_ctx, kdc_ev_ctx, kdc_lp_ctx,
					  context, db, arg);

	if (NT_STATUS_IS_OK(nt_status)) {
		return 0;
	}
	return EINVAL;
}
