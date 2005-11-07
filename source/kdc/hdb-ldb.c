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
#include "kdc.h"
#include "ads.h"
#include "hdb.h"
#include "lib/ldb/include/ldb.h"
#include "system/iconv.h"
#include "librpc/gen_ndr/netlogon.h"

enum hdb_ldb_ent_type 
{ HDB_LDB_ENT_TYPE_CLIENT, HDB_LDB_ENT_TYPE_SERVER, 
  HDB_LDB_ENT_TYPE_KRBTGT, HDB_LDB_ENT_TYPE_ANY };

static const char * const krb5_attrs[] = {
	"objectClass",
	"sAMAccountName",

	"userPrincipalName",
	"servicePrincipalName",

	"unicodePwd",
	"lmPwdHash",
	"ntPwdHash",

	"userAccountControl",

	"pwdLastSet",
	"accountExpires",

	"whenCreated",
	"whenChanged",

	"msDS-KeyVersionNumber",
	NULL
};

static const char *realm_ref_attrs[] = {
	"nCName", 
	"dnsRoot", 
	NULL
};

static KerberosTime ldb_msg_find_krb5time_ldap_time(struct ldb_message *msg, const char *attr, KerberosTime default_val)
{
    const char *tmp;
    const char *gentime;
    struct tm tm;

    gentime = ldb_msg_find_string(msg, attr, NULL);
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

	krb5_warnx(context, "uf2HDBFlags: userAccountControl: %08x\n", userAccountControl);

	/* we don't allow kadmin deletes */
	flags.immutable = 1;

	/* mark the principal as invalid to start with */
	flags.invalid = 1;

	flags.renewable = 1;

	/* All accounts are servers, but this may be disabled again in the caller */
	flags.server = 1;

	/* Account types - clear the invalid bit if it turns out to be valid */
	if (userAccountControl & UF_NORMAL_ACCOUNT) {
		if (ent_type == HDB_LDB_ENT_TYPE_CLIENT || ent_type == HDB_LDB_ENT_TYPE_ANY) {
			flags.client = 1;
		}
		flags.invalid = 0;
	}
	
	if (userAccountControl & UF_INTERDOMAIN_TRUST_ACCOUNT) {
		if (ent_type == HDB_LDB_ENT_TYPE_CLIENT || ent_type == HDB_LDB_ENT_TYPE_ANY) {
			flags.client = 1;
		}
		flags.invalid = 0;
	}
	if (userAccountControl & UF_WORKSTATION_TRUST_ACCOUNT) {
		if (ent_type == HDB_LDB_ENT_TYPE_CLIENT || ent_type == HDB_LDB_ENT_TYPE_ANY) {
			flags.client = 1;
		}
		flags.invalid = 0;
	}
	if (userAccountControl & UF_SERVER_TRUST_ACCOUNT) {
		if (ent_type == HDB_LDB_ENT_TYPE_CLIENT || ent_type == HDB_LDB_ENT_TYPE_ANY) {
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
	if (userAccountControl & UF_PASSWORD_CANT_CHANGE) {
		flags.invalid = 1;
	}
*/
/*
	if (userAccountControl & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED) {
		flags.invalid = 1;
	}
*/
	if (userAccountControl & UF_TEMP_DUPLICATE_ACCOUNT) {
		flags.invalid = 1;
	}

/* UF_DONT_EXPIRE_PASSWD handled in LDB_message2entry() */

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

/*
	if (userAccountControl & UF_SMARTCARD_USE_DES_KEY_ONLY) {
		flags.invalid = 1;
	}
*/
	if (userAccountControl & UF_DONT_REQUIRE_PREAUTH) {
		flags.require_preauth = 0;
	} else {
		flags.require_preauth = 1;

	}

	krb5_warnx(context, "uf2HDBFlags: HDBFlags: %08x\n", HDBFlags2int(flags));

	return flags;
}

static krb5_error_code hdb_ldb_free_private(krb5_context context, hdb_entry_ex *entry_ex)
{
	talloc_free(entry_ex->private);
	return 0;
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
	const char *unicodePwd;
	unsigned int userAccountControl;
	int i;
	krb5_error_code ret = 0;
	const char *dnsdomain = ldb_msg_find_string(realm_ref_msg, "dnsRoot", NULL);
	char *realm = strupper_talloc(mem_ctx, dnsdomain);

	struct hdb_ldb_private *private;
	hdb_entry *ent = &entry_ex->entry;

	memset(ent, 0, sizeof(*ent));

	krb5_warnx(context, "LDB_message2entry:\n");

	if (!realm) {
		krb5_set_error_string(context, "talloc_strdup: out of memory");
		ret = ENOMEM;
		goto out;
	}
			
	userAccountControl = ldb_msg_find_uint(msg, "userAccountControl", 0);
	
	ent->principal = malloc(sizeof(*(ent->principal)));
	if (ent_type == HDB_LDB_ENT_TYPE_ANY && principal == NULL) {
		const char *samAccountName = ldb_msg_find_string(msg, "samAccountName", NULL);
		if (!samAccountName) {
			krb5_set_error_string(context, "LDB_message2entry: no samAccountName present");
			ret = ENOENT;
			goto out;
		}
		samAccountName = ldb_msg_find_string(msg, "samAccountName", NULL);
		krb5_make_principal(context, &ent->principal, realm, samAccountName, NULL);
	} else {
		char *strdup_realm;
		ret = copy_Principal(principal, ent->principal);
		if (ret) {
			krb5_clear_error_string(context);
			goto out;
		}

		/* While we have copied the client principal, tests
		 * show that Win2k3 returns the 'corrected' realm, not
		 * the client-specified realm.  This code attempts to
		 * replace the client principal's realm with the one
		 * we determine from our records */
		
		/* don't leak */
		free(*krb5_princ_realm(context, ent->principal));
		
		/* this has to be with malloc() */
		strdup_realm = strdup(realm);
		if (!strdup_realm) {
			ret = ENOMEM;
			krb5_clear_error_string(context);
			goto out;
		}
		krb5_princ_set_realm(context, ent->principal, &strdup_realm);
	}

	ent->kvno = ldb_msg_find_int(msg, "msDS-KeyVersionNumber", 0);

	ent->flags = uf2HDBFlags(context, userAccountControl, ent_type);

	if (ent_type == HDB_LDB_ENT_TYPE_KRBTGT) {
		ent->flags.invalid = 0;
		ent->flags.server = 1;
		ent->flags.forwardable = 1;
		ent->flags.ok_as_delegate = 1;
	}

	if (lp_parm_bool(-1, "kdc", "require spn for service", True)) {
		if (!ldb_msg_find_string(msg, "servicePrincipalName", NULL)) {
			ent->flags.server = 0;
		}
	}

	/* use 'whenCreated' */
	ent->created_by.time = ldb_msg_find_krb5time_ldap_time(msg, "whenCreated", 0);
	/* use '???' */
	ent->created_by.principal = NULL;

	ent->modified_by = (Event *) malloc(sizeof(Event));
	if (ent->modified_by == NULL) {
		krb5_set_error_string(context, "malloc: out of memory");
		ret = ENOMEM;
		goto out;
	}

	/* use 'whenChanged' */
	ent->modified_by->time = ldb_msg_find_krb5time_ldap_time(msg, "whenChanged", 0);
	/* use '???' */
	ent->modified_by->principal = NULL;

	ent->valid_start = NULL;

	ent->valid_end = NULL;
	ent->pw_end = NULL;

	ent->max_life = NULL;

	ent->max_renew = NULL;

	ent->generation = NULL;

	/* create the keys and enctypes */
	unicodePwd = ldb_msg_find_string(msg, "unicodePwd", NULL);
	if (unicodePwd) {
		/* Many, many thanks to lukeh@padl.com for this
		 * algorithm, described in his Nov 10 2004 mail to
		 * samba-technical@samba.org */

		Principal *salt_principal;
		const char *user_principal_name = ldb_msg_find_string(msg, "userPrincipalName", NULL);
		struct ldb_message_element *objectclasses;
		struct ldb_val computer_val;
		computer_val.data = discard_const_p(uint8_t,"computer");
		computer_val.length = strlen((const char *)computer_val.data);
		
		objectclasses = ldb_msg_find_element(msg, "objectClass");

		if (objectclasses && ldb_msg_find_val(objectclasses, &computer_val)) {
			/* Determine a salting principal */
			char *samAccountName = talloc_strdup(mem_ctx, ldb_msg_find_string(msg, "samAccountName", NULL));
			char *saltbody;
			if (!samAccountName) {
				krb5_set_error_string(context, "LDB_message2entry: no samAccountName present");
				ret = ENOENT;
				goto out;
			}
			if (samAccountName[strlen(samAccountName)-1] == '$') {
				samAccountName[strlen(samAccountName)-1] = '\0';
			}
			saltbody = talloc_asprintf(mem_ctx, "%s.%s", samAccountName, dnsdomain);
			
			ret = krb5_make_principal(context, &salt_principal, realm, "host", saltbody, NULL);
		} else if (user_principal_name) {
			char *p;
			user_principal_name = talloc_strdup(mem_ctx, user_principal_name);
			if (!user_principal_name) {
				ret = ENOMEM;
				goto out;
			} else {
				p = strchr(user_principal_name, '@');
				if (p) {
					p[0] = '\0';
				}
				ret = krb5_make_principal(context, &salt_principal, realm, user_principal_name, NULL);
			} 
		} else {
			const char *samAccountName = ldb_msg_find_string(msg, "samAccountName", NULL);
			ret = krb5_make_principal(context, &salt_principal, realm, samAccountName, NULL);
		}

		if (ret == 0) {
			size_t num_keys = ent->keys.len;
			/*
			 * create keys from unicodePwd
			 */
			ret = hdb_generate_key_set_password(context, salt_principal, 
							    unicodePwd, 
							    &ent->keys.val, &num_keys);
			ent->keys.len = num_keys;
			krb5_free_principal(context, salt_principal);
		}

		if (ret != 0) {
			krb5_warnx(context, "could not generate keys from unicodePwd\n");
			ent->keys.val = NULL;
			ent->keys.len = 0;
			goto out;
		}
	} else {
		const struct ldb_val *val;
		krb5_data keyvalue;

		val = ldb_msg_find_ldb_val(msg, "ntPwdHash");
		if (!val) {
			krb5_warnx(context, "neither type of key available for this account\n");
			ent->keys.val = NULL;
			ent->keys.len = 0;
		} else if (val->length < 16) {
			ent->keys.val = NULL;
			ent->keys.len = 0;
			krb5_warnx(context, "ntPwdHash has invalid length: %d\n",
				   (int)val->length);
		} else {
			ret = krb5_data_alloc (&keyvalue, 16);
			if (ret) {
				krb5_clear_error_string(context);
				ret = ENOMEM;
				goto out;
			}

			memcpy(keyvalue.data, val->data, 16);

			ent->keys.val = malloc(sizeof(ent->keys.val[0]));
			if (ent->keys.val == NULL) {
				krb5_data_free(&keyvalue);
				krb5_clear_error_string(context);
				ret = ENOMEM;
				goto out;
			}
			
			memset(&ent->keys.val[0], 0, sizeof(Key));
			ent->keys.val[0].key.keytype = ETYPE_ARCFOUR_HMAC_MD5;
			ent->keys.val[0].key.keyvalue = keyvalue;
			
			ent->keys.len = 1;
		}
	}		


	ent->etypes = malloc(sizeof(*(ent->etypes)));
	if (ent->etypes == NULL) {
		krb5_clear_error_string(context);
		ret = ENOMEM;
		goto out;
	}
	ent->etypes->len = ent->keys.len;
	ent->etypes->val = calloc(ent->etypes->len, sizeof(int));
	if (ent->etypes->val == NULL) {
		krb5_clear_error_string(context);
		ret = ENOMEM;
		goto out;
	}
	for (i=0; i < ent->etypes->len; i++) {
		ent->etypes->val[i] = ent->keys.val[i].key.keytype;
	}


	private = talloc(db, struct hdb_ldb_private);
	if (!private) {
		ret = ENOMEM;
		goto out;
	}

	private->msg = talloc_steal(private, msg);
	private->realm_ref_msg = talloc_steal(private, realm_ref_msg);
	private->samdb = (struct ldb_context *)db->hdb_db;
	
	entry_ex->private = private;
	entry_ex->free_private = hdb_ldb_free_private;
	entry_ex->check_client_access = hdb_ldb_check_client_access;
	entry_ex->authz_data_tgs_req = hdb_ldb_authz_data_tgs_req;
	entry_ex->authz_data_as_req = hdb_ldb_authz_data_as_req;

out:
	if (ret != 0) {
		/* This doesn't free ent itself, that is for the eventual caller to do */
		hdb_free_entry(context, &entry_ex->entry);
	}

	return ret;
}

static krb5_error_code LDB_lookup_principal(krb5_context context, struct ldb_context *ldb_ctx, 					
					    TALLOC_CTX *mem_ctx,
					    krb5_const_principal principal,
					    enum hdb_ldb_ent_type ent_type,
					    const struct ldb_dn *realm_dn,
					    struct ldb_message ***pmsg)
{
	krb5_error_code ret;
	int count;
	char *filter = NULL;
	const char * const *princ_attrs = krb5_attrs;

	char *princ_str;
	char *princ_str_talloc;
	char *short_princ;
	char *short_princ_talloc;

	char *realm_dn_str;

	struct ldb_message **msg = NULL;

	ret = krb5_unparse_name(context, principal, &princ_str);

	if (ret != 0) {
		krb5_set_error_string(context, "LDB_lookup_principal: could not parse principal");
		krb5_warnx(context, "LDB_lookup_principal: could not parse principal");
		return ret;
	}

	ret = krb5_unparse_name_norealm(context, principal, &short_princ);

	if (ret != 0) {
		free(princ_str);
		krb5_set_error_string(context, "LDB_lookup_principal: could not parse principal");
		krb5_warnx(context, "LDB_lookup_principal: could not parse principal");
		return ret;
	}

	princ_str_talloc = talloc_strdup(mem_ctx, princ_str);
	short_princ_talloc = talloc_strdup(mem_ctx, short_princ);
	free(princ_str);
	free(short_princ);
	if (!short_princ || !princ_str_talloc) {
		krb5_set_error_string(context, "LDB_lookup_principal: talloc_strdup() failed!");
		return ENOMEM;
	}

	switch (ent_type) {
	case HDB_LDB_ENT_TYPE_CLIENT:
		/* Can't happen */
		return EINVAL;
		break;
	case HDB_LDB_ENT_TYPE_KRBTGT:
		filter = talloc_asprintf(mem_ctx, "(&(objectClass=user)(samAccountName=%s))", 
					 KRB5_TGS_NAME);
		break;
	case HDB_LDB_ENT_TYPE_SERVER:
		filter = talloc_asprintf(mem_ctx, "(&(objectClass=user)(samAccountName=%s))", 
					 short_princ_talloc);
		break;
	case HDB_LDB_ENT_TYPE_ANY:
		filter = talloc_asprintf(mem_ctx, "(&(objectClass=user)(|(|(samAccountName=%s)(servicePrincipalName=%s))(userPrincipalName=%s)))", 
					 short_princ_talloc, short_princ_talloc, princ_str_talloc);
		break;
	}

	if (!filter) {
		krb5_set_error_string(context, "talloc_asprintf: out of memory");
		return ENOMEM;
	}

	count = ldb_search(ldb_ctx, realm_dn, LDB_SCOPE_SUBTREE, filter, 
			   princ_attrs, &msg);

	realm_dn_str = ldb_dn_linearize(mem_ctx, realm_dn);

	if (count < 1) {
		krb5_warnx(context, "ldb_search: basedn: '%s' filter: '%s' failed: %d", 
			   realm_dn_str, filter, count);
		krb5_set_error_string(context, "ldb_search: basedn: '%s' filter: '%s' failed: %d", 
				      realm_dn_str, filter, count);
		return HDB_ERR_NOENTRY;
	} else if (count > 1) {
		talloc_free(msg);
		krb5_warnx(context, "ldb_search: basedn: '%s' filter: '%s' more than 1 entry: %d", 
			   realm_dn_str, filter, count);
		krb5_set_error_string(context, "ldb_search: basedn: '%s' filter: '%s' more than 1 entry: %d", 
				      realm_dn_str, filter, count);
		return HDB_ERR_NOENTRY;
	}
	*pmsg = talloc_steal(mem_ctx, msg);
	return 0;
}

static krb5_error_code LDB_lookup_realm(krb5_context context, struct ldb_context *ldb_ctx, 
					TALLOC_CTX *mem_ctx,
					const char *realm,
					struct ldb_message ***pmsg)
{
 	int count;
	char *cross_ref_filter;
	struct ldb_message **cross_ref_msg;

	cross_ref_filter = talloc_asprintf(mem_ctx, 
					   "(&(&(|(&(dnsRoot=%s)(nETBIOSName=*))(nETBIOSName=%s))(objectclass=crossRef))(ncName=*))",
					   realm, realm);
	if (!cross_ref_filter) {
		krb5_set_error_string(context, "asprintf: out of memory");
		return ENOMEM;
	}

	count = ldb_search(ldb_ctx, NULL, LDB_SCOPE_SUBTREE, cross_ref_filter, 
			   realm_ref_attrs, &cross_ref_msg);

	if (count < 1) {
		krb5_warnx(context, "ldb_search: filter: '%s' failed: %d", cross_ref_filter, count);
		krb5_set_error_string(context, "ldb_search: filter: '%s' failed: %d", cross_ref_filter, count);

		talloc_free(cross_ref_msg);
		return HDB_ERR_NOENTRY;
	} else if (count > 1) {
		krb5_warnx(context, "ldb_search: filter: '%s' more than 1 entry: %d", cross_ref_filter, count);
		krb5_set_error_string(context, "ldb_search: filter: '%s' more than 1 entry: %d", cross_ref_filter, count);

		talloc_free(cross_ref_msg);
		return HDB_ERR_NOENTRY;
	}

	if (pmsg) {
		*pmsg = talloc_steal(mem_ctx, cross_ref_msg);
	} else {
		talloc_free(cross_ref_msg);
	}

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

static krb5_error_code LDB_fetch_ex(krb5_context context, HDB *db, unsigned flags,
				    krb5_const_principal principal,
				    enum hdb_ent_type ent_type,
				    hdb_entry_ex *entry_ex)
{
	struct ldb_message **msg = NULL;
	struct ldb_message **realm_ref_msg = NULL;
	struct ldb_message **realm_fixed_msg = NULL;
	enum hdb_ldb_ent_type ldb_ent_type;
	krb5_error_code ret;

	const char *realm;
	const struct ldb_dn *realm_dn;
	TALLOC_CTX *mem_ctx = talloc_named(NULL, 0, "LDB_fetch context");

	if (!mem_ctx) {
		krb5_set_error_string(context, "LDB_fetch: talloc_named() failed!");
		return ENOMEM;
	}

	switch (ent_type) {
	case HDB_ENT_TYPE_CLIENT:
	{
		NTSTATUS nt_status;
		char *principal_string;
		ldb_ent_type = HDB_LDB_ENT_TYPE_CLIENT;

		ret = krb5_unparse_name(context, principal, &principal_string);
		
		if (ret != 0) {
			talloc_free(mem_ctx);
			return ret;
		}

		nt_status = sam_get_results_principal((struct ldb_context *)db->hdb_db,
						      mem_ctx, principal_string, 
						      &msg, &realm_ref_msg);
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_SUCH_USER)) {
			return HDB_ERR_NOENTRY;
		} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_MEMORY)) {
			return ENOMEM;
		} else if (!NT_STATUS_IS_OK(nt_status)) {
			return EINVAL;
		}

		ret = LDB_message2entry(context, db, mem_ctx, 
					principal, ldb_ent_type, 
					msg[0], realm_ref_msg[0], entry_ex);

		talloc_free(mem_ctx);
		return ret;
	}
	case HDB_ENT_TYPE_SERVER:
		if (principal->name.name_string.len == 2
		    && (strcmp(principal->name.name_string.val[0], KRB5_TGS_NAME) == 0)) {
			/* krbtgt case.  Either us or a trusted realm */
			if ((LDB_lookup_realm(context, (struct ldb_context *)db->hdb_db,
					      mem_ctx, principal->name.name_string.val[1], &realm_fixed_msg) == 0)) {
				/* us */
				/* Cludge, cludge cludge.  If the realm part of krbtgt/realm,
				 * is in our db, then direct the caller at our primary
				 * krgtgt */

				const char *dnsdomain = ldb_msg_find_string(realm_fixed_msg[0], "dnsRoot", NULL);
				char *realm_fixed = strupper_talloc(mem_ctx, dnsdomain);
				if (!realm_fixed) {
					krb5_set_error_string(context, "strupper_talloc: out of memory");
					talloc_free(mem_ctx);
					return ENOMEM;
				}
				
				free(principal->name.name_string.val[1]);
				principal->name.name_string.val[1] = strdup(realm_fixed);
				talloc_free(realm_fixed);
				if (!principal->name.name_string.val[1]) {
					krb5_set_error_string(context, "LDB_fetch: strdup() failed!");
					talloc_free(mem_ctx);
					return ENOMEM;
				}
				ldb_ent_type = HDB_LDB_ENT_TYPE_KRBTGT;
				break;
			} else {
				/* we should lookup trusted domains */
				return HDB_ERR_NOENTRY;
			}

		} else if (principal->name.name_string.len >= 2) {
			/* 'normal server' case */
			int ldb_ret;
			NTSTATUS nt_status;
			struct ldb_dn *user_dn, *domain_dn;
			char *principal_string;
			ldb_ent_type = HDB_LDB_ENT_TYPE_SERVER;
			
			ret = krb5_unparse_name_norealm(context, principal, &principal_string);
			
			if (ret != 0) {
				talloc_free(mem_ctx);
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
				talloc_free(mem_ctx);
				return HDB_ERR_NOENTRY;
			}
			
			ldb_ret = gendb_search_dn((struct ldb_context *)db->hdb_db,
						  mem_ctx, user_dn, &msg, krb5_attrs);
			
			if (ldb_ret != 1) {
				return HDB_ERR_NOENTRY;
			}
			
			ldb_ret = gendb_search((struct ldb_context *)db->hdb_db,
					       mem_ctx, NULL, &realm_ref_msg, realm_ref_attrs, 
					       "ncName=%s", ldb_dn_linearize(mem_ctx, domain_dn));
			
			if (ldb_ret != 1) {
				return HDB_ERR_NOENTRY;
			}

			ret = LDB_message2entry(context, db, mem_ctx, 
						principal, ldb_ent_type, 
						msg[0], realm_ref_msg[0], entry_ex);
			talloc_free(mem_ctx);
			return ret;
			
		} else {
			ldb_ent_type = HDB_LDB_ENT_TYPE_SERVER;
			/* server as client principal case, but we must not lookup userPrincipalNames */
			break;
		}
	case HDB_ENT_TYPE_ANY:
		ldb_ent_type = HDB_LDB_ENT_TYPE_ANY;
		break;
	default:
		krb5_warnx(context, "LDB_fetch: invalid ent_type specified!");
		talloc_free(mem_ctx);
		return HDB_ERR_NOENTRY;
	}


	realm = krb5_principal_get_realm(context, principal);

	ret = LDB_lookup_realm(context, (struct ldb_context *)db->hdb_db, 
			       mem_ctx, realm, &realm_ref_msg);
	if (ret != 0) {
		krb5_warnx(context, "LDB_fetch: could not find realm");
		talloc_free(mem_ctx);
		return HDB_ERR_NOENTRY;
	}

	realm_dn = samdb_result_dn(mem_ctx, realm_ref_msg[0], "nCName", NULL);

	ret = LDB_lookup_principal(context, (struct ldb_context *)db->hdb_db, 
				   mem_ctx, 
				   principal, ldb_ent_type, realm_dn, &msg);

	if (ret != 0) {
		krb5_warnx(context, "LDB_fetch: could not find principal in DB");
		krb5_set_error_string(context, "LDB_fetch: could not find principal in DB");
		talloc_free(mem_ctx);
		return ret;
	} else {
		ret = LDB_message2entry(context, db, mem_ctx, 
					principal, ldb_ent_type, 
					msg[0], realm_ref_msg[0], entry_ex);
		if (ret != 0) {
			krb5_warnx(context, "LDB_fetch: message2entry failed\n");	
		}
	}

	talloc_free(mem_ctx);
	return ret;
}

static krb5_error_code LDB_fetch(krb5_context context, HDB *db, unsigned flags,
				 krb5_const_principal principal,
				 enum hdb_ent_type ent_type,
				 hdb_entry *entry)
{
	struct hdb_entry_ex entry_ex;
	krb5_error_code ret;

	memset(&entry_ex, '\0', sizeof(entry_ex));
	ret = LDB_fetch_ex(context, db, flags, principal, ent_type, &entry_ex);
	
	if (ret == 0) {
		if (entry_ex.free_private) {
			entry_ex.free_private(context, &entry_ex);
		}
		*entry = entry_ex.entry;
	}
	return ret;
}

static krb5_error_code LDB_store(krb5_context context, HDB *db, unsigned flags, hdb_entry *entry)
{
	return HDB_ERR_DB_INUSE;
}

static krb5_error_code LDB_remove(krb5_context context, HDB *db, hdb_entry *entry)
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

static krb5_error_code LDB_seq(krb5_context context, HDB *db, unsigned flags, hdb_entry *entry)
{
	krb5_error_code ret;
	struct hdb_ldb_seq *priv = (struct hdb_ldb_seq *)db->hdb_openp;
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
					NULL, HDB_LDB_ENT_TYPE_ANY, 
					priv->msgs[priv->index++], 
					priv->realm_ref_msgs[0], &entry_ex);
		if (ret == 0) {
			if (entry_ex.free_private) {
				entry_ex.free_private(context, &entry_ex);
			}
			*entry = entry_ex.entry;
		}
	} else {
		ret = HDB_ERR_NOENTRY;
	}

	if (ret != 0) {
		talloc_free(priv);
		db->hdb_openp = NULL;
	} else {
		talloc_free(mem_ctx);
	}

	return ret;
}

static krb5_error_code LDB_firstkey(krb5_context context, HDB *db, unsigned flags,
					hdb_entry *entry)
{
	struct ldb_context *ldb_ctx = (struct ldb_context *)db->hdb_db;
	struct hdb_ldb_seq *priv = (struct hdb_ldb_seq *)db->hdb_openp;
	char *realm;
	struct ldb_dn *realm_dn = NULL;
	struct ldb_message **msgs = NULL;
	struct ldb_message **realm_ref_msgs = NULL;
	krb5_error_code ret;
	TALLOC_CTX *mem_ctx;

	if (priv) {
		talloc_free(priv);
		db->hdb_openp = 0;
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

	realm_dn = samdb_result_dn(mem_ctx, realm_ref_msgs[0], "nCName", NULL);

	priv->realm_ref_msgs = talloc_steal(priv, realm_ref_msgs);

	krb5_warnx(context, "LDB_firstkey: realm ok\n");

	priv->count = ldb_search(ldb_ctx, realm_dn,
				 LDB_SCOPE_SUBTREE, "(objectClass=user)",
				 krb5_attrs, &msgs);

	priv->msgs = talloc_steal(priv, msgs);

	if (priv->count <= 0) {
		talloc_free(priv);
		return HDB_ERR_NOENTRY;
	}

	db->hdb_openp = priv;

	ret = LDB_seq(context, db, flags, entry);
	
	if (ret != 0) {
    		talloc_free(priv);
		db->hdb_openp = NULL;
	} else {
		talloc_free(mem_ctx);
	}
	return ret;
}

static krb5_error_code LDB_nextkey(krb5_context context, HDB *db, unsigned flags,
					hdb_entry *entry)
{
	return LDB_seq(context, db, flags, entry);
}

static krb5_error_code LDB_destroy(krb5_context context, HDB *db)
{
	talloc_free(db);
	return 0;
}

krb5_error_code hdb_ldb_create(TALLOC_CTX *mem_ctx, 
			       krb5_context context, struct HDB **db, const char *arg)
{
	*db = talloc(mem_ctx, HDB);
	if (!*db) {
		krb5_set_error_string(context, "malloc: out of memory");
		return ENOMEM;
	}

	(*db)->hdb_master_key_set = 0;
	(*db)->hdb_db = NULL;

	/* Setup the link to LDB */
	(*db)->hdb_db = samdb_connect(*db, system_session(db));
	if ((*db)->hdb_db == NULL) {
		krb5_warnx(context, "hdb_ldb_create: samdb_connect failed!");
		krb5_set_error_string(context, "samdb_connect failed!");
		talloc_free(*db);
		return HDB_ERR_NOENTRY;
	}

	(*db)->hdb_openp = 0;
	(*db)->hdb_open = LDB_open;
	(*db)->hdb_close = LDB_close;
	(*db)->hdb_fetch = LDB_fetch;
	(*db)->hdb_fetch_ex = LDB_fetch_ex;
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

	return 0;
}
