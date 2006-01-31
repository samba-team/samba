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
#include "lib/ldb/include/ldb_errors.h"
#include "system/iconv.h"
#include "librpc/gen_ndr/netlogon.h"
#include "auth/auth.h"
#include "dsdb/samdb/samdb.h"

enum hdb_ldb_ent_type 
{ HDB_LDB_ENT_TYPE_CLIENT, HDB_LDB_ENT_TYPE_SERVER, 
  HDB_LDB_ENT_TYPE_KRBTGT, HDB_LDB_ENT_TYPE_ANY };

static const char * const krb5_attrs[] = {
	"objectClass",
	"sAMAccountName",

	"userPrincipalName",
	"servicePrincipalName",

	"krb5Key",

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

static int hdb_ldb_destrutor(void *ptr)
{
    struct hdb_ldb_private *private = ptr;
    hdb_entry_ex *entry_ex = private->entry_ex;
    free_hdb_entry(&entry_ex->entry);
    return 0;
}

static void hdb_ldb_free_entry(krb5_context context, hdb_entry_ex *entry_ex)
{
	talloc_free(entry_ex->ctx);
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
	const char *dnsdomain = ldb_msg_find_string(realm_ref_msg, "dnsRoot", NULL);
	char *realm = strupper_talloc(mem_ctx, dnsdomain);
	struct ldb_dn *domain_dn = samdb_result_dn(mem_ctx, realm_ref_msg, "nCName", ldb_dn_new(mem_ctx));

	struct hdb_ldb_private *private;
	NTTIME acct_expiry;
	struct ldb_message_element *ldb_keys;

	struct ldb_message_element *objectclasses;
	struct ldb_val computer_val;
	computer_val.data = discard_const_p(uint8_t,"computer");
	computer_val.length = strlen((const char *)computer_val.data);
	
	objectclasses = ldb_msg_find_element(msg, "objectClass");
	
	if (objectclasses && ldb_msg_find_val(objectclasses, &computer_val)) {
		is_computer = TRUE;
	}

	memset(entry_ex, 0, sizeof(*entry_ex));

	krb5_warnx(context, "LDB_message2entry:\n");

	if (!realm) {
		krb5_set_error_string(context, "talloc_strdup: out of memory");
		ret = ENOMEM;
		goto out;
	}
			
	private = talloc(mem_ctx, struct hdb_ldb_private);
	if (!private) {
		ret = ENOMEM;
		goto out;
	}

	private->entry_ex = entry_ex;

	talloc_set_destructor(private, hdb_ldb_destrutor);

	entry_ex->ctx = private;
	entry_ex->free_entry = hdb_ldb_free_entry;

	userAccountControl = ldb_msg_find_uint(msg, "userAccountControl", 0);

	
	entry_ex->entry.principal = malloc(sizeof(*(entry_ex->entry.principal)));
	if (ent_type == HDB_LDB_ENT_TYPE_ANY && principal == NULL) {
		const char *samAccountName = ldb_msg_find_string(msg, "samAccountName", NULL);
		if (!samAccountName) {
			krb5_set_error_string(context, "LDB_message2entry: no samAccountName present");
			ret = ENOENT;
			goto out;
		}
		samAccountName = ldb_msg_find_string(msg, "samAccountName", NULL);
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
		
		/* don't leak */
		free(*krb5_princ_realm(context, entry_ex->entry.principal));
		
		/* this has to be with malloc() */
		strdup_realm = strdup(realm);
		if (!strdup_realm) {
			ret = ENOMEM;
			krb5_clear_error_string(context);
			goto out;
		}
		krb5_princ_set_realm(context, entry_ex->entry.principal, &strdup_realm);
	}

	entry_ex->entry.kvno = ldb_msg_find_int(msg, "msDS-KeyVersionNumber", 0);

	entry_ex->entry.flags = uf2HDBFlags(context, userAccountControl, ent_type);

	if (ent_type == HDB_LDB_ENT_TYPE_KRBTGT) {
		entry_ex->entry.flags.invalid = 0;
		entry_ex->entry.flags.server = 1;
		entry_ex->entry.flags.forwardable = 1;
		entry_ex->entry.flags.ok_as_delegate = 1;
	}

	if (lp_parm_bool(-1, "kdc", "require spn for service", True)) {
		if (!is_computer && !ldb_msg_find_string(msg, "servicePrincipalName", NULL)) {
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

	acct_expiry = samdb_result_nttime(msg, "accountExpires", (NTTIME)-1);
	if ((acct_expiry == (NTTIME)-1) ||
	    (acct_expiry == 0x7FFFFFFFFFFFFFFFULL)) {
		entry_ex->entry.valid_end = NULL;
	} else {
		entry_ex->entry.valid_end = malloc(sizeof(*entry_ex->entry.valid_end));
		if (entry_ex->entry.valid_end == NULL) {
			ret = ENOMEM;
			goto out;
		}
		*entry_ex->entry.valid_end = nt_time_to_unix(acct_expiry);
	}

	if (!(userAccountControl & UF_DONT_EXPIRE_PASSWD) &&
	    (ent_type != HDB_LDB_ENT_TYPE_KRBTGT)) {
		NTTIME must_change_time
			= samdb_result_force_password_change((struct ldb_context *)db->hdb_db, mem_ctx, 
							     domain_dn, msg, 
							     "pwdLastSet");
		if (must_change_time != 0) {
			entry_ex->entry.pw_end = malloc(sizeof(*entry_ex->entry.pw_end));
			if (entry_ex->entry.pw_end == NULL) {
				ret = ENOMEM;
				goto out;
			}
			*entry_ex->entry.pw_end = nt_time_to_unix(must_change_time);
		} else {
			entry_ex->entry.pw_end = NULL;
		}
	} else {
		entry_ex->entry.pw_end = NULL;
	}
			
	entry_ex->entry.max_life = NULL;

	entry_ex->entry.max_renew = NULL;

	entry_ex->entry.generation = NULL;

	/* Get krb5Key from the db */

	ldb_keys = ldb_msg_find_element(msg, "krb5Key");

	if (!ldb_keys) {
		/* oh, no password.  Apparently (comment in
		 * hdb-ldap.c) this violates the ASN.1, but this
		 * allows an entry with no keys (yet). */
		entry_ex->entry.keys.val = NULL;
		entry_ex->entry.keys.len = 0;
	} else {
		/* allocate space to decode into */
		entry_ex->entry.keys.val = calloc(ldb_keys->num_values, sizeof(Key));
		if (entry_ex->entry.keys.val == NULL) {
			ret = ENOMEM;
			goto out;
		}
		entry_ex->entry.keys.len = ldb_keys->num_values;

		/* Decode Kerberos keys into the hdb structure */
		for (i=0; i < entry_ex->entry.keys.len; i++) {
			size_t decode_len;
			ret = decode_Key(ldb_keys->values[i].data, ldb_keys->values[i].length, 
					 &entry_ex->entry.keys.val[i], &decode_len);
			if (ret) {
				/* Could be bougus data in the entry, or out of memory */
				goto out;
			}
		}
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


	private->msg = talloc_steal(private, msg);
	private->realm_ref_msg = talloc_steal(private, realm_ref_msg);
	private->samdb = (struct ldb_context *)db->hdb_db;
	
	entry_ex->check_client_access = hdb_ldb_check_client_access;
	entry_ex->authz_data_tgs_req = hdb_ldb_authz_data_tgs_req;
	entry_ex->authz_data_as_req = hdb_ldb_authz_data_as_req;

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
					    const struct ldb_dn *realm_dn,
					    struct ldb_message ***pmsg)
{
	krb5_error_code ret;
	int lret;
	char *filter = NULL;
	const char * const *princ_attrs = krb5_attrs;

	char *short_princ;
	char *short_princ_talloc;

	char *realm_dn_str;

	struct ldb_result *res = NULL;

	ret = krb5_unparse_name_norealm(context, principal, &short_princ);

	if (ret != 0) {
		krb5_set_error_string(context, "LDB_lookup_principal: could not parse principal");
		krb5_warnx(context, "LDB_lookup_principal: could not parse principal");
		return ret;
	}

	short_princ_talloc = talloc_strdup(mem_ctx, short_princ);
	free(short_princ);
	if (!short_princ || !short_princ_talloc) {
		krb5_set_error_string(context, "LDB_lookup_principal: talloc_strdup() failed!");
		return ENOMEM;
	}

	switch (ent_type) {
	case HDB_LDB_ENT_TYPE_CLIENT:
		/* Can't happen */
		return EINVAL;
	case HDB_LDB_ENT_TYPE_ANY:
		/* Can't happen */
		return EINVAL;
	case HDB_LDB_ENT_TYPE_KRBTGT:
		filter = talloc_asprintf(mem_ctx, "(&(objectClass=user)(samAccountName=%s))", 
					 KRB5_TGS_NAME);
		break;
	case HDB_LDB_ENT_TYPE_SERVER:
		filter = talloc_asprintf(mem_ctx, "(&(objectClass=user)(samAccountName=%s))", 
					 short_princ_talloc);
		break;
	}

	if (!filter) {
		krb5_set_error_string(context, "talloc_asprintf: out of memory");
		return ENOMEM;
	}

	lret = ldb_search(ldb_ctx, realm_dn, LDB_SCOPE_SUBTREE, filter, princ_attrs, &res);

	realm_dn_str = ldb_dn_linearize(mem_ctx, realm_dn);

	if (lret != LDB_SUCCESS) {
		DEBUG(3, ("Failed to search for %s: %s\n", filter, ldb_errstring(ldb_ctx)));
		return HDB_ERR_NOENTRY;
	} else if (res->count == 0 || res->count > 1) {
		DEBUG(3, ("Failed find a single entry for %s: got %d\n", filter, res->count));
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
	char *cross_ref_filter;
	struct ldb_result *cross_ref_res;

	cross_ref_filter = talloc_asprintf(mem_ctx, 
					   "(&(&(|(&(dnsRoot=%s)(nETBIOSName=*))(nETBIOSName=%s))(objectclass=crossRef))(ncName=*))",
					   realm, realm);
	if (!cross_ref_filter) {
		krb5_set_error_string(context, "asprintf: out of memory");
		return ENOMEM;
	}

	ret = ldb_search(ldb_ctx, NULL, LDB_SCOPE_SUBTREE, cross_ref_filter, realm_ref_attrs, &cross_ref_res);

	if (ret != LDB_SUCCESS) {
		DEBUG(3, ("Failed to search for %s: %s\n", cross_ref_filter, ldb_errstring(ldb_ctx)));
		talloc_free(cross_ref_res);
		return HDB_ERR_NOENTRY;
	} else if (cross_ref_res->count == 0 || cross_ref_res->count > 1) {
		DEBUG(3, ("Failed find a single entry for %s: got %d\n", cross_ref_filter, cross_ref_res->count));
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

static krb5_error_code LDB_fetch(krb5_context context, HDB *db, unsigned flags,
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
	TALLOC_CTX *mem_ctx = talloc_named(db, 0, "LDB_fetch context");

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
		free(principal_string);
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_SUCH_USER)) {
			talloc_free(mem_ctx);
			return HDB_ERR_NOENTRY;
		} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_MEMORY)) {
			talloc_free(mem_ctx);
			return ENOMEM;
		} else if (!NT_STATUS_IS_OK(nt_status)) {
			talloc_free(mem_ctx);
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
				talloc_free(mem_ctx);
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
				talloc_free(mem_ctx);
				return HDB_ERR_NOENTRY;
			}
			
			ldb_ret = gendb_search((struct ldb_context *)db->hdb_db,
					       mem_ctx, NULL, &realm_ref_msg, realm_ref_attrs, 
					       "ncName=%s", ldb_dn_linearize(mem_ctx, domain_dn));
			
			if (ldb_ret != 1) {
				talloc_free(mem_ctx);
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
		krb5_warnx(context, "LDB_fetch: ENT_TYPE_ANY is not valid in hdb-ldb!");
		talloc_free(mem_ctx);
		return HDB_ERR_NOENTRY;
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

static krb5_error_code LDB_store(krb5_context context, HDB *db, unsigned flags, hdb_entry_ex *entry)
{
	return HDB_ERR_DB_INUSE;
}

static krb5_error_code LDB_remove(krb5_context context, HDB *db, hdb_entry_ex *entry)
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
					priv->realm_ref_msgs[0], entry);
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
					hdb_entry_ex *entry)
{
	struct ldb_context *ldb_ctx = (struct ldb_context *)db->hdb_db;
	struct hdb_ldb_seq *priv = (struct hdb_ldb_seq *)db->hdb_openp;
	char *realm;
	struct ldb_dn *realm_dn = NULL;
	struct ldb_result *res = NULL;
	struct ldb_message **realm_ref_msgs = NULL;
	krb5_error_code ret;
	TALLOC_CTX *mem_ctx;
	int lret;

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

	lret = ldb_search(ldb_ctx, realm_dn,
				 LDB_SCOPE_SUBTREE, "(objectClass=user)",
				 krb5_attrs, &res);

	if (lret != LDB_SUCCESS) {
		talloc_free(priv);
		return HDB_ERR_NOENTRY;
	}

	priv->count = res->count;
	priv->msgs = talloc_steal(priv, res->msgs);
	talloc_free(res);

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

NTSTATUS kdc_hdb_ldb_create(TALLOC_CTX *mem_ctx, 
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

	nt_status = auth_system_session_info(*db, &session_info);
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
	(*db)->hdb_db = samdb_connect(*db, session_info);
	if ((*db)->hdb_db == NULL) {
		DEBUG(1, ("hdb_ldb_create: Cannot open samdb for KDC backend!"));
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	(*db)->hdb_openp = 0;
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

krb5_error_code hdb_ldb_create(krb5_context context, struct HDB **db, const char *arg)
{
	NTSTATUS nt_status;
	/* Disgusting, ugly hack, but it means one less private hook */
	nt_status = kdc_hdb_ldb_create(context->mem_ctx, context, db, arg);

	if (NT_STATUS_IS_OK(nt_status)) {
		return 0;
	}
	return EINVAL;
}
