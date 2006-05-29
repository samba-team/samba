/* 
   ldb database module

   Copyright (C) Simo Sorce  2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Andrew Tridgell 2004

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/*
 *  Name: ldb
 *
 *  Component: ldb password_hash module
 *
 *  Description: correctly update hash values based on changes to sambaPassword and friends
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include "libcli/ldap/ldap.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "librpc/gen_ndr/misc.h"
#include "librpc/gen_ndr/samr.h"
#include "libcli/auth/libcli_auth.h"
#include "libcli/security/security.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "system/time.h"
#include "dsdb/samdb/samdb.h"
#include "ads.h"
#include "hdb.h"

/* If we have decided there is reason to work on this request, then
 * setup all the password hash types correctly.
 *
 * If the administrator doesn't want the sambaPassword stored (set in the
 * domain and per-account policies) then we must strip that out before
 * we do the first operation.
 *
 * Once this is done (which could update anything at all), we
 * calculate the password hashes.
 *
 * This function must not only update the ntPwdHash, lmPwdHash and
 * krb5Key fields, it must also atomicly increment the
 * msDS-KeyVersionNumber.  We should be in a transaction, so all this
 * should be quite safe...
 *
 * Finally, if the administrator has requested that a password history
 * be maintained, then this should also be written out.
 *
 */


static int password_hash_handle(struct ldb_module *module, struct ldb_request *req, 
			     const struct ldb_message *msg)
{
	int ret, old_ret = -1;
	uint_t pwdProperties, pwdHistoryLength;
	uint_t userAccountControl;
	const char *dnsDomain, *realm;
	const char *sambaPassword = NULL;
	struct samr_Password *sambaLMPwdHistory, *sambaNTPwdHistory;
	struct samr_Password *lmPwdHash, *ntPwdHash;
	struct samr_Password *lmOldHash = NULL, *ntOldHash = NULL;
	struct samr_Password *new_sambaLMPwdHistory, *new_sambaNTPwdHistory;
	struct samr_Password local_lmNewHash, local_ntNewHash;
	int sambaLMPwdHistory_len, sambaNTPwdHistory_len;
	uint_t kvno;
	struct dom_sid *domain_sid;
	time_t now = time(NULL);
	NTTIME now_nt;
	int i;
	krb5_error_code krb5_ret;

	struct smb_krb5_context *smb_krb5_context;

	struct ldb_message_element *attribute;
	struct ldb_dn *dn = msg->dn;
	struct ldb_message *msg2;

	struct ldb_request *search_request = NULL;
	struct ldb_request *modify_request;
	struct ldb_request *modified_orig_request;
	struct ldb_result *res, *dom_res, *old_res;

	struct ldb_message_element *objectclasses;
	struct ldb_val computer_val;
	struct ldb_val person_val;
	BOOL is_computer;

	struct ldb_message *modify_msg;

	const char *domain_expression;
	const char *old_user_attrs[] = { "lmPwdHash", "ntPwdHash", NULL };
	const char *user_attrs[] = { "userAccountControl", "sambaLMPwdHistory", 
				     "sambaNTPwdHistory", 
				     "ntPwdHash", 
				     "objectSid", "msDS-KeyVersionNumber", 
				     "objectClass", "userPrincipalName",
				     "samAccountName", 
				     NULL };
	const char * const domain_attrs[] = { "pwdProperties", "pwdHistoryLength", 
					      "dnsDomain", NULL };

	TALLOC_CTX *mem_ctx;

	/* Do the original action */
	
	mem_ctx = talloc_new(module);
	if (!mem_ctx) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (req->operation == LDB_REQ_MODIFY) {
		search_request = talloc(mem_ctx, struct ldb_request);
		if (!search_request) {
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* Look up the old ntPwdHash and lmPwdHash values, so
		 * we can later place these into the password
		 * history */

		search_request->operation = LDB_REQ_SEARCH;
		search_request->op.search.base = dn;
		search_request->op.search.scope = LDB_SCOPE_BASE;
		search_request->op.search.tree = ldb_parse_tree(module->ldb, NULL);
		search_request->op.search.attrs = old_user_attrs;
		search_request->controls = NULL;
		
		old_ret = ldb_next_request(module, search_request);
	}

	/* we can't change things untill we copy it */
	msg2 = ldb_msg_copy_shallow(mem_ctx, msg);

	/* look again, this time at the copied attribute */
	if (!msg2 || (attribute = ldb_msg_find_element(msg2, "sambaPassword")) == NULL ) {
		talloc_free(mem_ctx);
		/* Gah?  where did it go?  Oh well... */
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Wipe out the sambaPassword attribute set, we will handle it in
	 * the second modify.  We might not want it written to disk */
	
	if (req->operation == LDB_REQ_ADD) {
		if (attribute->num_values > 1) {
			ldb_set_errstring(module->ldb,
					  talloc_asprintf(mem_ctx, "sambaPassword_handle: "
							  "attempted set of multiple sambaPassword attributes on %s rejected",
							  ldb_dn_linearize(mem_ctx, dn)));
			talloc_free(mem_ctx);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		if (attribute->num_values == 1) {
			sambaPassword = (const char *)attribute->values[0].data;
			ldb_msg_remove_attr(msg2, "sambaPassword");
		}
	} else if (((attribute->flags & LDB_FLAG_MOD_MASK) == LDB_FLAG_MOD_ADD)
		   || ((attribute->flags & LDB_FLAG_MOD_MASK) == LDB_FLAG_MOD_REPLACE)) {
		if (attribute->num_values > 1) {
			ldb_set_errstring(module->ldb,
					  talloc_asprintf(mem_ctx, "sambaPassword_handle: "
							  "attempted set of multiple sambaPassword attributes on %s rejected",
							  ldb_dn_linearize(mem_ctx, dn)));
			talloc_free(mem_ctx);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		
		if (attribute->num_values == 1) {
			sambaPassword = (const char *)attribute->values[0].data;
			ldb_msg_remove_attr(msg2, "sambaPassword");
		}
	}

	modified_orig_request = talloc(mem_ctx, struct ldb_request);
	if (!modified_orig_request) {
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*modified_orig_request = *req;
	switch (modified_orig_request->operation) {
	case LDB_REQ_ADD:
		modified_orig_request->op.add.message = msg2;
		break;
	case LDB_REQ_MODIFY:
		modified_orig_request->op.mod.message = msg2;
		break;
	default:
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Send the (modified) request of the original caller down to the database */
	ret = ldb_next_request(module, modified_orig_request);
	if (ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	/* While we do the search first (for the old password hashes),
	 * we don't want to override any error that the modify may
	 * have returned.  Now check the error */
	if (req->operation == LDB_REQ_MODIFY) {
		if (old_ret) {
			talloc_free(mem_ctx);
			return old_ret;
		}

		/* Find out the old passwords details of the user */
		old_res = search_request->op.search.res;
		talloc_steal(mem_ctx, old_res);
		talloc_free(search_request);
		
		if (old_res->count != 1) {
			ldb_set_errstring(module->ldb, 
					  talloc_asprintf(mem_ctx, "password_hash_handle: "
							  "(pre) search for %s found %d != 1 objects, for entry we just modified",
							  ldb_dn_linearize(mem_ctx, dn),
							  old_res->count));
			/* What happend?  The above add/modify worked... */
			talloc_free(mem_ctx);
			return LDB_ERR_NO_SUCH_OBJECT;
		}

		lmOldHash = samdb_result_hash(mem_ctx, old_res->msgs[0],   "lmPwdHash");
		ntOldHash = samdb_result_hash(mem_ctx, old_res->msgs[0],   "ntPwdHash");
	}

	/* Start finding out details we need for the second modify.
	 * We do this after the first add/modify because other modules
	 * will have filled in the templates, and we may have had
	 * things like the username (affecting the salt) changed along
	 * with the password. */

	/* Now find out what is on the entry after the above add/modify */
	search_request = talloc(mem_ctx, struct ldb_request);
	if (!search_request) {
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	search_request->operation       = LDB_REQ_SEARCH;
	search_request->op.search.base  = dn;
	search_request->op.search.scope = LDB_SCOPE_BASE;
	search_request->op.search.tree  = ldb_parse_tree(module->ldb, NULL);
	search_request->op.search.attrs = user_attrs;
	search_request->controls = NULL;
	
	ret = ldb_next_request(module, search_request);
	if (ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	/* Find out the full details of the user */
	res = search_request->op.search.res;
	talloc_steal(mem_ctx, res);
	talloc_free(search_request);

	if (res->count != 1) {
		ldb_set_errstring(module->ldb,
				  talloc_asprintf(mem_ctx, "password_hash_handle: "
						  "search for %s found %d != 1 objects, for entry we just added/modified",
						  ldb_dn_linearize(mem_ctx, dn),
						  res->count));
		/* What happend?  The above add/modify worked... */
		talloc_free(mem_ctx);
		return LDB_ERR_NO_SUCH_OBJECT;
	}

	userAccountControl = samdb_result_uint(res->msgs[0],   "userAccountControl", 0);
	sambaLMPwdHistory_len   = samdb_result_hashes(mem_ctx, res->msgs[0], 
						 "sambaLMPwdHistory", &sambaLMPwdHistory);
	sambaNTPwdHistory_len   = samdb_result_hashes(mem_ctx, res->msgs[0], 
						 "sambaNTPwdHistory", &sambaNTPwdHistory);
	ntPwdHash          = samdb_result_hash(mem_ctx, res->msgs[0],   "ntPwdHash");
	kvno               = samdb_result_uint(res->msgs[0],   "msDS-KeyVersionNumber", 0);

	domain_sid         = samdb_result_sid_prefix(mem_ctx, res->msgs[0], "objectSid");

	
	objectclasses = ldb_msg_find_element(res->msgs[0], "objectClass");
	person_val = data_blob_string_const("person");
	
	if (!objectclasses || !ldb_msg_find_val(objectclasses, &person_val)) {
		/* Not a 'person', so the rest of this doesn't make
		 * sense.  How we got a sambaPassword this far I don't
		 * know... */
		ldb_set_errstring(module->ldb,
				  talloc_asprintf(mem_ctx, "password_hash_handle: "
						  "attempted set of sambaPassword on non-'person' object %s rejected",
						  ldb_dn_linearize(mem_ctx, dn)));
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	computer_val = data_blob_string_const("computer");
	
	if (ldb_msg_find_val(objectclasses, &computer_val)) {
		is_computer = True;
	} else {
		is_computer = False;
	}
	
	domain_expression  = talloc_asprintf(mem_ctx, "(&(objectSid=%s)(objectClass=domain))", 
					     ldap_encode_ndr_dom_sid(mem_ctx, domain_sid));

	/* Find the user's domain, then find out the domain password
	 * properties */
	ret = ldb_search(module->ldb, NULL, LDB_SCOPE_SUBTREE, domain_expression, 
			 domain_attrs, &dom_res);
	if (ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	if (dom_res->count != 1) {
		/* What happend?  The user we are modifying must be odd... */
		ldb_set_errstring(module->ldb, 
				  talloc_asprintf(mem_ctx, "password_hash_handle: "
						  "search for domain %s found %d != 1 objects",
						  dom_sid_string(mem_ctx, domain_sid),
						  dom_res->count));
		talloc_free(mem_ctx);
		return LDB_ERR_NO_SUCH_OBJECT;
	}

	pwdProperties    = samdb_result_uint(dom_res->msgs[0],   "pwdProperties", 0);
	pwdHistoryLength = samdb_result_uint(dom_res->msgs[0],   "pwdHistoryLength", 0);
	dnsDomain        = ldb_msg_find_string(dom_res->msgs[0], "dnsDomain", NULL);
	realm            = strupper_talloc(mem_ctx, dnsDomain);

	/* Some operations below require kerberos contexts */
	if (smb_krb5_init_context(mem_ctx, &smb_krb5_context) != 0) {
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Prepare the modifications to set all the hash/key types */
	modify_msg = ldb_msg_new(req);
	modify_msg->dn = talloc_reference(modify_msg, dn);

#define CHECK_RET(x) \
	do {					\
		int check_ret = x;		\
		if (check_ret != LDB_SUCCESS) { \
			talloc_free(mem_ctx);	\
			return check_ret;	\
		}				\
	} while(0)

	/* Setup krb5Key (we want to either delete an existing value,
	 * or replace with a new one).  Both the unicode and NT hash
	 * only branches append keys to this multivalued entry. */
	CHECK_RET(ldb_msg_add_empty(modify_msg, "krb5Key", LDB_FLAG_MOD_REPLACE));

	/* Yay, we can compute new password hashes from the unicode
	 * password */
	if (sambaPassword) {
		Principal *salt_principal;
		const char *user_principal_name = ldb_msg_find_string(res->msgs[0], "userPrincipalName", NULL);
		
		Key *keys;
		size_t num_keys;

		/* compute the new nt and lm hashes */
		if (E_deshash(sambaPassword, local_lmNewHash.hash)) {
			lmPwdHash = &local_lmNewHash;
		} else {
			lmPwdHash = NULL;
		}
		E_md4hash(sambaPassword, local_ntNewHash.hash);
		ntPwdHash = &local_ntNewHash;
		CHECK_RET(ldb_msg_add_empty(modify_msg, "ntPwdHash", 
					    LDB_FLAG_MOD_REPLACE));
		CHECK_RET(samdb_msg_add_hash(module->ldb, req, 
					     modify_msg, "ntPwdHash", 
					     ntPwdHash));
		CHECK_RET(ldb_msg_add_empty(modify_msg, "lmPwdHash", 
					    LDB_FLAG_MOD_REPLACE));
		if (lmPwdHash) {
			CHECK_RET(samdb_msg_add_hash(module->ldb, req, 
						     modify_msg, "lmPwdHash", 
						     lmPwdHash));
		}

		/* Many, many thanks to lukeh@padl.com for this
		 * algorithm, described in his Nov 10 2004 mail to
		 * samba-technical@samba.org */

		if (is_computer) {
			/* Determine a salting principal */
			char *samAccountName = talloc_strdup(mem_ctx, ldb_msg_find_string(res->msgs[0], "samAccountName", NULL));
			char *saltbody;
			if (!samAccountName) {
				ldb_set_errstring(module->ldb,
						  talloc_asprintf(mem_ctx, "password_hash_handle: "
								  "generation of new kerberos keys failed: %s is a computer without a samAccountName",
								  ldb_dn_linearize(mem_ctx, dn)));
				talloc_free(mem_ctx);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			if (samAccountName[strlen(samAccountName)-1] == '$') {
				samAccountName[strlen(samAccountName)-1] = '\0';
			}
			saltbody = talloc_asprintf(mem_ctx, "%s.%s", samAccountName, dnsDomain);
			
			krb5_ret = krb5_make_principal(smb_krb5_context->krb5_context, &salt_principal, realm, "host", saltbody, NULL);
		} else if (user_principal_name) {
			char *p;
			user_principal_name = talloc_strdup(mem_ctx, user_principal_name);
			if (!user_principal_name) {
				talloc_free(mem_ctx);
				return LDB_ERR_OPERATIONS_ERROR;
			} else {
				p = strchr(user_principal_name, '@');
				if (p) {
					p[0] = '\0';
				}
				krb5_ret = krb5_make_principal(smb_krb5_context->krb5_context, &salt_principal, realm, user_principal_name, NULL);
			} 
		} else {
			const char *samAccountName = ldb_msg_find_string(res->msgs[0], "samAccountName", NULL);
			if (!samAccountName) {
				ldb_set_errstring(module->ldb,
						  talloc_asprintf(mem_ctx, "password_hash_handle: "
								  "generation of new kerberos keys failed: %s has no samAccountName",
								  ldb_dn_linearize(mem_ctx, dn)));
				talloc_free(mem_ctx);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			krb5_ret = krb5_make_principal(smb_krb5_context->krb5_context, &salt_principal, realm, samAccountName, NULL);
		}


		if (krb5_ret) {
			ldb_set_errstring(module->ldb,
					  talloc_asprintf(mem_ctx, "password_hash_handle: "
							  "generation of a saltking principal failed: %s",
							  smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
										     krb5_ret, mem_ctx)));
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* TODO: We may wish to control the encryption types chosen in future */
		krb5_ret = hdb_generate_key_set_password(smb_krb5_context->krb5_context,
							 salt_principal, sambaPassword, &keys, &num_keys);
		krb5_free_principal(smb_krb5_context->krb5_context, salt_principal);

		if (krb5_ret) {
			ldb_set_errstring(module->ldb,
					  talloc_asprintf(mem_ctx, "password_hash_handle: "
							  "generation of new kerberos keys failed: %s",
							  smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
										     krb5_ret, mem_ctx)));
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* Walking all the key types generated, transform each
		 * key into an ASN.1 blob
		 */
		for (i=0; i < num_keys; i++) {
			unsigned char *buf;
			size_t buf_size;
			size_t len;
			struct ldb_val val;
			
			if (keys[i].key.keytype == ETYPE_ARCFOUR_HMAC_MD5) {
				/* We might end up doing this below:
				 * This ensures we get the unicode
				 * conversion right.  This should also
				 * be fixed in the Heimdal libs */
				continue;
			}
			ASN1_MALLOC_ENCODE(Key, buf, buf_size, &keys[i], &len, krb5_ret);
			if (krb5_ret) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
			
			val.data = talloc_memdup(req, buf, len);
			val.length = len;
			free(buf);
			if (!val.data || krb5_ret) {
				hdb_free_keys (smb_krb5_context->krb5_context, num_keys, keys);
				talloc_free(mem_ctx);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			ret = ldb_msg_add_value(modify_msg, "krb5Key", &val);
			if (ret != LDB_SUCCESS) {
				hdb_free_keys (smb_krb5_context->krb5_context, num_keys, keys);
				talloc_free(mem_ctx);
				return ret;
			}
		}
		
		hdb_free_keys (smb_krb5_context->krb5_context, num_keys, keys);
	}

	/* Possibly kill off the cleartext or store it */
	CHECK_RET(ldb_msg_add_empty(modify_msg, "sambaPassword", LDB_FLAG_MOD_REPLACE));

	if (sambaPassword && (pwdProperties & DOMAIN_PASSWORD_STORE_CLEARTEXT) &&
	    (userAccountControl & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED)) {
		CHECK_RET(ldb_msg_add_string(modify_msg, "sambaPassword", sambaPassword));
	}
	
	/* Even if we didn't get a sambaPassword, we can still setup
	 * krb5Key from the NT hash. 
	 *
	 * This is an append, so it works with the 'continue' in the
	 * unicode loop above, to use Samba's NT hash function, which
	 * is more correct than Heimdal's
	 */
	if (ntPwdHash) {
		unsigned char *buf;
		size_t buf_size;
		size_t len;
		struct ldb_val val;
		Key key;
		
		key.mkvno = 0;
		key.salt = NULL; /* No salt for this enc type */

		krb5_ret = krb5_keyblock_init(smb_krb5_context->krb5_context,
					      ETYPE_ARCFOUR_HMAC_MD5,
					      ntPwdHash->hash, sizeof(ntPwdHash->hash), 
					      &key.key);
		if (krb5_ret) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ASN1_MALLOC_ENCODE(Key, buf, buf_size, &key, &len, krb5_ret);
		if (krb5_ret) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		krb5_free_keyblock_contents(smb_krb5_context->krb5_context,
					    &key.key);
		
		val.data = talloc_memdup(req, buf, len);
		val.length = len;
		free(buf);
		if (!val.data || ret) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		CHECK_RET(ldb_msg_add_value(modify_msg, "krb5Key", &val));
	}

	/* If the original caller did anything with pwdLastSet then skip this.  It could be an incoming samsync */
	attribute = ldb_msg_find_element(msg, "pwdLastSet");
	if (attribute == NULL) {
		/* Update the password last set time */
		unix_to_nt_time(&now_nt, now);
		CHECK_RET(ldb_msg_add_empty(modify_msg, "pwdLastSet", LDB_FLAG_MOD_REPLACE));
		CHECK_RET(samdb_msg_add_uint64(module->ldb, mem_ctx, modify_msg, "pwdLastSet", now_nt));
	}

	/* If the original caller did anything with "msDS-KeyVersionNumber" then skip this.  It could be an incoming samsync */
	attribute = ldb_msg_find_element(msg, "msDS-KeyVersionNumber");
	if (attribute == NULL) {
		if (kvno == 0) {
			CHECK_RET(ldb_msg_add_empty(modify_msg, "msDS-KeyVersionNumber",
						    LDB_FLAG_MOD_REPLACE));
			CHECK_RET(samdb_msg_add_uint(module->ldb, mem_ctx, modify_msg, "msDS-KeyVersionNumber", kvno + 1));
		} else {
			/* While we should be in a transaction, go one extra
			 * step in the dance for an 'atomic' increment.  This
			 * may be of value against remote LDAP servers.  (Note
			 * however that Mulitmaster replication stil offers no
			 * such guarantee) */
			
			struct ldb_val old_kvno, new_kvno;
			old_kvno.data = (uint8_t *)talloc_asprintf(mem_ctx, "%u", kvno);
			if (!old_kvno.data) {
				return -1;
			}
			old_kvno.length = strlen((char *)old_kvno.data);
			
			new_kvno.data = (uint8_t *)talloc_asprintf(mem_ctx, "%u", kvno + 1);
			if (!new_kvno.data) {
				return -1;
			}
			new_kvno.length = strlen((char *)new_kvno.data);
			
			CHECK_RET(ldb_msg_add_empty(modify_msg, "msDS-KeyVersionNumber",
						    LDB_FLAG_MOD_DELETE));
			CHECK_RET(ldb_msg_add_empty(modify_msg, "msDS-KeyVersionNumber",
						    LDB_FLAG_MOD_ADD));
			modify_msg->elements[modify_msg->num_elements - 2].num_values = 1;
			modify_msg->elements[modify_msg->num_elements - 2].values = &old_kvno;
			modify_msg->elements[modify_msg->num_elements - 1].num_values = 1;
			modify_msg->elements[modify_msg->num_elements - 1].values = &new_kvno;
		}
	}

	CHECK_RET(ldb_msg_add_empty(modify_msg, "sambaLMPwdHistory",
				    LDB_FLAG_MOD_REPLACE));
	CHECK_RET(ldb_msg_add_empty(modify_msg, "sambaNTPwdHistory",
				    LDB_FLAG_MOD_REPLACE));

	/* If we have something to put into the history, or an old
	 * history element to expire, update the history */
	if (pwdHistoryLength > 0 && 
	    ((sambaNTPwdHistory_len > 0) || (sambaLMPwdHistory_len > 0) 
	     || lmOldHash || ntOldHash)) {
		/* store the password history */
		new_sambaLMPwdHistory = talloc_array(mem_ctx, struct samr_Password, 
						pwdHistoryLength);
		if (!new_sambaLMPwdHistory) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		new_sambaNTPwdHistory = talloc_array(mem_ctx, struct samr_Password, 
						pwdHistoryLength);
		if (!new_sambaNTPwdHistory) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		for (i=0;i<MIN(pwdHistoryLength-1, sambaLMPwdHistory_len);i++) {
			new_sambaLMPwdHistory[i+1] = sambaLMPwdHistory[i];
		}
		for (i=0;i<MIN(pwdHistoryLength-1, sambaNTPwdHistory_len);i++) {
			new_sambaNTPwdHistory[i+1] = sambaNTPwdHistory[i];
		}
		
		/* Don't store 'long' passwords in the LM history, 
		   but make sure to 'expire' one password off the other end */
		if (lmOldHash) {
			new_sambaLMPwdHistory[0] = *lmOldHash;
		} else {
			ZERO_STRUCT(new_sambaLMPwdHistory[0]);
		}
		sambaLMPwdHistory_len = MIN(sambaLMPwdHistory_len + 1, pwdHistoryLength);
		
		/* Likewise, we might not have an old NT password (lm
		 * only password change function on previous change) */
		if (ntOldHash) {
			new_sambaNTPwdHistory[0] = *ntOldHash;
		} else {
			ZERO_STRUCT(new_sambaNTPwdHistory[0]);
		}
		sambaNTPwdHistory_len = MIN(sambaNTPwdHistory_len + 1, pwdHistoryLength);
		
		CHECK_RET(samdb_msg_add_hashes(mem_ctx, modify_msg, 
					       "sambaLMPwdHistory", 
					       new_sambaLMPwdHistory, 
					       sambaLMPwdHistory_len));
		
		CHECK_RET(samdb_msg_add_hashes(mem_ctx, modify_msg, 
					       "sambaNTPwdHistory", 
					       new_sambaNTPwdHistory, 
					       sambaNTPwdHistory_len));
	}

	/* Too much code above, we should check we got it close to reasonable */
	CHECK_RET(ldb_msg_sanity_check(modify_msg));

	modify_request = talloc(mem_ctx, struct ldb_request);
	if (!modify_request) {
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	modify_request->operation = LDB_REQ_MODIFY;
	modify_request->op.mod.message = modify_msg;
	modify_request->controls = NULL;

	ret = ldb_next_request(module, modify_request);
	
	talloc_free(mem_ctx);
	return ret;
}

/* add_record: do things with the sambaPassword attribute */
static int password_hash_add(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.add.message;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "password_hash_add_record\n");

	if (ldb_dn_is_special(msg->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}
	
	/* If no part of this touches the sambaPassword, then we don't
	 * need to make any changes.  For password changes/set there should
	 * be a 'delete' or a 'modify' on this attribute. */
	if (ldb_msg_find_element(msg, "sambaPassword") == NULL ) {
		return ldb_next_request(module, req);
	}

	return password_hash_handle(module, req, msg);
}

/* modify_record: do things with the sambaPassword attribute */
static int password_hash_modify(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.mod.message;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "password_hash_modify_record\n");

	if (ldb_dn_is_special(msg->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}
	
	/* If no part of this touches the sambaPassword, then we don't
	 * need to make any changes.  For password changes/set there should
	 * be a 'delete' or a 'modify' on this attribute. */
	if (ldb_msg_find_element(msg, "sambaPassword") == NULL ) {
		return ldb_next_request(module, req);
	}

	return password_hash_handle(module, req, msg);
}

enum ph_type {PH_ADD, PH_MOD};
enum ph_step {PH_ADD_SEARCH_DOM, PH_ADD_DO_ADD, PH_MOD_DO_REQ, PH_MOD_SEARCH_SELF, PH_MOD_SEARCH_DOM, PH_MOD_DO_MOD};

struct ph_async_context {

	enum ph_type type;
	enum ph_step step;

	struct ldb_module *module;
	struct ldb_request *orig_req;

	struct ldb_request *dom_req;
	struct ldb_async_result *dom_res;

	struct ldb_request *down_req;

	struct ldb_request *search_req;
	struct ldb_async_result *search_res;

	struct ldb_request *mod_req;
};

struct domain_data {
	uint_t pwdProperties;
	uint_t pwdHistoryLength;
	char *dnsDomain;
	char *realm;
};

static int add_password_hashes(struct ldb_module *module, struct ldb_message *msg, int is_mod)
{
	const char *sambaPassword;
	struct samr_Password tmp_hash;
	
	sambaPassword = ldb_msg_find_string(msg, "sambaPassword", NULL);
	if (sambaPassword == NULL) { /* impossible, what happened ?! */
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (is_mod) {
		if (ldb_msg_add_empty(msg, "ntPwdHash", LDB_FLAG_MOD_REPLACE) != 0) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		if (ldb_msg_add_empty(msg, "lmPwdHash", LDB_FLAG_MOD_REPLACE) != 0) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}	

	/* compute the new nt and lm hashes */
	E_md4hash(sambaPassword, tmp_hash.hash);
	if (samdb_msg_add_hash(module->ldb, msg, msg, "ntPwdHash", &tmp_hash) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (E_deshash(sambaPassword, tmp_hash.hash)) {
		if (samdb_msg_add_hash(module->ldb, msg, msg, "lmPwdHash", &tmp_hash) != 0) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	return LDB_SUCCESS;
}

static int add_krb5_keys_from_password(struct ldb_module *module, struct ldb_message *msg,
					struct smb_krb5_context *smb_krb5_context,
					struct domain_data *domain,
					const char *samAccountName,
					const char *user_principal_name,
					int is_computer)
{
	const char *sambaPassword;
	Principal *salt_principal;
	krb5_error_code krb5_ret;
	size_t num_keys;
	Key *keys;
	int i;

	/* Many, many thanks to lukeh@padl.com for this
	 * algorithm, described in his Nov 10 2004 mail to
	 * samba-technical@samba.org */

	sambaPassword = ldb_msg_find_string(msg, "sambaPassword", NULL);
	if (sambaPassword == NULL) { /* impossible, what happened ?! */
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (is_computer) {
		/* Determine a salting principal */
		char *name = talloc_strdup(msg, samAccountName);
		char *saltbody;
		if (name == NULL) {
			ldb_set_errstring(module->ldb,
					  talloc_asprintf(msg, "password_hash_handle: "
							  "generation of new kerberos keys failed: %s is a computer without a samAccountName",
							  ldb_dn_linearize(msg, msg->dn)));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		if (name[strlen(name)-1] == '$') {
			name[strlen(name)-1] = '\0';
		}
		saltbody = talloc_asprintf(msg, "%s.%s", name, domain->dnsDomain);
		
		krb5_ret = krb5_make_principal(smb_krb5_context->krb5_context,
						&salt_principal,
						domain->realm, "host",
						saltbody, NULL);
	} else if (user_principal_name) {
		char *p;
		user_principal_name = talloc_strdup(msg, user_principal_name);
		if (user_principal_name == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		} else {
			p = strchr(user_principal_name, '@');
			if (p) {
				p[0] = '\0';
			}
			krb5_ret = krb5_make_principal(smb_krb5_context->krb5_context,
							&salt_principal,
							domain->realm, user_principal_name, NULL);
		} 
	} else {
		if (!samAccountName) {
			ldb_set_errstring(module->ldb,
					  talloc_asprintf(msg, "password_hash_handle: "
							  "generation of new kerberos keys failed: %s has no samAccountName",
							  ldb_dn_linearize(msg, msg->dn)));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		krb5_ret = krb5_make_principal(smb_krb5_context->krb5_context,
						&salt_principal,
						domain->realm, samAccountName,
						NULL);
	}

	if (krb5_ret) {
		ldb_set_errstring(module->ldb,
				  talloc_asprintf(msg, "password_hash_handle: "
						  "generation of a saltking principal failed: %s",
						  smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
									     krb5_ret, msg)));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* TODO: We may wish to control the encryption types chosen in future */
	krb5_ret = hdb_generate_key_set_password(smb_krb5_context->krb5_context,
						 salt_principal, sambaPassword, &keys, &num_keys);
	krb5_free_principal(smb_krb5_context->krb5_context, salt_principal);

	if (krb5_ret) {
		ldb_set_errstring(module->ldb,
				  talloc_asprintf(msg, "password_hash_handle: "
						  "generation of new kerberos keys failed: %s",
						  smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
									     krb5_ret, msg)));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Walking all the key types generated, transform each
	 * key into an ASN.1 blob
	 */
	for (i=0; i < num_keys; i++) {
		unsigned char *buf;
		size_t buf_size;
		size_t len;
		struct ldb_val val;
		int ret;
		
		if (keys[i].key.keytype == ENCTYPE_ARCFOUR_HMAC) {
			/* We might end up doing this below:
			 * This ensures we get the unicode
			 * conversion right.  This should also
			 * be fixed in the Heimdal libs */
			continue;
		}
		ASN1_MALLOC_ENCODE(Key, buf, buf_size, &keys[i], &len, krb5_ret);
		if (krb5_ret) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		val.data = talloc_memdup(msg, buf, len);
		val.length = len;
		free(buf);
		if (!val.data || krb5_ret) {
			hdb_free_keys (smb_krb5_context->krb5_context, num_keys, keys);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ret = ldb_msg_add_value(msg, "krb5Key", &val);
		if (ret != LDB_SUCCESS) {
			hdb_free_keys (smb_krb5_context->krb5_context, num_keys, keys);
			return ret;
		}
	}
	
	hdb_free_keys (smb_krb5_context->krb5_context, num_keys, keys);

	return LDB_SUCCESS;
}

static int add_krb5_keys_from_NThash(struct ldb_module *module, struct ldb_message *msg,
					struct smb_krb5_context *smb_krb5_context)
{
	struct samr_Password *ntPwdHash;
	krb5_error_code krb5_ret;
	unsigned char *buf;
	size_t buf_size;
	size_t len;
	struct ldb_val val;
	Key key;
	
	key.mkvno = 0;
	key.salt = NULL; /* No salt for this enc type */

	ntPwdHash = samdb_result_hash(msg, msg, "ntPwdHash");
	if (ntPwdHash == NULL) { /* what happened ?! */
		return LDB_ERR_OPERATIONS_ERROR;
	}

	krb5_ret = krb5_keyblock_init(smb_krb5_context->krb5_context,
				 ENCTYPE_ARCFOUR_HMAC,
				 ntPwdHash->hash, sizeof(ntPwdHash->hash), 
				 &key.key);
	if (krb5_ret) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ASN1_MALLOC_ENCODE(Key, buf, buf_size, &key, &len, krb5_ret);
	if (krb5_ret) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	krb5_free_keyblock_contents(smb_krb5_context->krb5_context,
				    &key.key);
	
	val.data = talloc_memdup(msg, buf, len);
	val.length = len;
	free(buf);
	if (!val.data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	if (ldb_msg_add_value(msg, "krb5Key", &val) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return LDB_SUCCESS;
}

static int set_pwdLastSet(struct ldb_module *module, struct ldb_message *msg, int is_mod)
{
	NTTIME now_nt;

	/* set it as now */
	unix_to_nt_time(&now_nt, time(NULL));

	if (!is_mod) {
		/* be sure there isn't a 0 value set (eg. coming from the template) */
		ldb_msg_remove_attr(msg, "pwdLastSet");
		/* add */
		if (ldb_msg_add_empty(msg, "pwdLastSet", LDB_FLAG_MOD_ADD) != 0) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	} else {
		/* replace */
		if (ldb_msg_add_empty(msg, "pwdLastSet", LDB_FLAG_MOD_REPLACE) != 0) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	if (samdb_msg_add_uint64(module->ldb, msg, msg, "pwdLastSet", now_nt) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return LDB_SUCCESS;
}

static int add_keyVersionNumber(struct ldb_module *module, struct ldb_message *msg, int previous)
{
	/* replace or add */
	if (ldb_msg_add_empty(msg, "msDS-KeyVersionNumber", LDB_FLAG_MOD_REPLACE) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (samdb_msg_add_uint(module->ldb, msg, msg, "msDS-KeyVersionNumber", previous+1) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return LDB_SUCCESS;
}

static int setPwdHistory(struct ldb_module *module, struct ldb_message *msg, struct ldb_message *old_msg, int hlen)
{
	struct samr_Password *nt_hash;
	struct samr_Password *lm_hash;
	struct samr_Password *nt_history;
	struct samr_Password *lm_history;
	struct samr_Password *new_nt_history;
	struct samr_Password *new_lm_history;
	int nt_hist_len;
	int lm_hist_len;
	int i;

	nt_hash = samdb_result_hash(msg, old_msg, "ntPwdHash");
	lm_hash = samdb_result_hash(msg, old_msg, "lmPwdHash");

	/* if no previous passwords just return */
	if (nt_hash == NULL && lm_hash == NULL) return LDB_SUCCESS;

	nt_hist_len = samdb_result_hashes(msg, old_msg, "sambaNTPwdHistory", &nt_history);
	lm_hist_len = samdb_result_hashes(msg, old_msg, "sambaLMPwdHistory", &lm_history);

	/* We might not have an old NT password */
	new_nt_history = talloc_array(msg, struct samr_Password, hlen);
	if (new_nt_history == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	for (i = 0; i < MIN(hlen-1, nt_hist_len); i++) {
		new_nt_history[i+1] = nt_history[i];
	}
	nt_hist_len = i + 1;
	if (nt_hash) {
		new_nt_history[0] = *nt_hash;
	} else {
		ZERO_STRUCT(new_nt_history[0]);
	}
	if (ldb_msg_add_empty(msg, "sambaNTPwdHistory", LDB_FLAG_MOD_REPLACE) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	if (samdb_msg_add_hashes(msg, msg, "sambaNTPwdHistory", new_nt_history, nt_hist_len) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
		

	/* Don't store 'long' passwords in the LM history, 
	   but make sure to 'expire' one password off the other end */
	new_lm_history = talloc_array(msg, struct samr_Password, hlen);
	if (new_lm_history == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	for (i = 0; i < MIN(hlen-1, lm_hist_len); i++) {
		new_lm_history[i+1] = lm_history[i];
	}
	lm_hist_len = i + 1;
	if (lm_hash) {
		new_lm_history[0] = *lm_hash;
	} else {
		ZERO_STRUCT(new_lm_history[0]);
	}
	if (ldb_msg_add_empty(msg, "sambaLMPwdHistory", LDB_FLAG_MOD_REPLACE) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	if (samdb_msg_add_hashes(msg, msg, "sambaLMPwdHistory", new_lm_history, lm_hist_len) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return LDB_SUCCESS;
}

static struct ldb_async_handle *ph_init_handle(struct ldb_request *req, struct ldb_module *module, enum ph_type type)
{
	struct ph_async_context *ac;
	struct ldb_async_handle *h;

	h = talloc_zero(req, struct ldb_async_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Out of Memory"));
		return NULL;
	}

	h->module = module;

	ac = talloc_zero(h, struct ph_async_context);
	if (ac == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Out of Memory"));
		talloc_free(h);
		return NULL;
	}

	h->private_data = (void *)ac;

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->type = type;
	ac->module = module;
	ac->orig_req = req;

	return h;
}

static int get_domain_data_callback(struct ldb_context *ldb, void *context, struct ldb_async_result *ares)
{
	struct ph_async_context *ac;

	if (!context || !ares) {
		ldb_set_errstring(ldb, talloc_asprintf(ldb, "NULL Context or Result in callback"));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac = talloc_get_type(context, struct ph_async_context);

	/* we are interested only in the single reply (base search) we receive here */
	if (ares->type == LDB_REPLY_ENTRY) {
		if (ac->dom_res != NULL) {
			ldb_set_errstring(ldb, talloc_asprintf(ldb, "Too many results"));
			talloc_free(ares);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ac->dom_res = talloc_steal(ac, ares);
	} else {
		talloc_free(ares);
	}

	return LDB_SUCCESS;
}

static int build_domain_data_request(struct ph_async_context *ac,
				     struct dom_sid *sid)
{
	/* attrs[] is returned from this function in
	   ac->dom_req->op.search.attrs, so it must be static, as
	   otherwise the compiler can put it on the stack */
	static const char * const attrs[] = { "pwdProperties", "pwdHistoryLength", "dnsDomain", NULL };
	char *filter;

	ac->dom_req = talloc_zero(ac, struct ldb_request);
	if (ac->dom_req == NULL) {
		ldb_debug(ac->module->ldb, LDB_DEBUG_ERROR, "Out of Memory!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac->dom_req->operation = LDB_ASYNC_SEARCH;
	ac->dom_req->op.search.base = NULL;
	ac->dom_req->op.search.scope = LDB_SCOPE_SUBTREE;

	filter = talloc_asprintf(ac->dom_req, "(&(objectSid=%s)(objectClass=domain))", dom_sid_string(ac->dom_req, sid));
	if (filter == NULL) {
		ldb_debug(ac->module->ldb, LDB_DEBUG_ERROR, "Out of Memory!\n");
		talloc_free(ac->dom_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->dom_req->op.search.tree = ldb_parse_tree(ac->module->ldb, filter);
	if (ac->dom_req->op.search.tree == NULL) {
		ldb_set_errstring(ac->module->ldb, talloc_asprintf(ac, "Invalid search filter"));
		talloc_free(ac->dom_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac->dom_req->op.search.attrs = attrs;
	ac->dom_req->controls = NULL;
	ac->dom_req->async.context = ac;
	ac->dom_req->async.callback = get_domain_data_callback;
	ac->dom_req->async.timeout = ac->orig_req->async.timeout;

	return LDB_SUCCESS;
}

static struct domain_data *get_domain_data(struct ldb_module *module, void *mem_ctx, struct ldb_async_result *res)
{
	struct domain_data *data;
	const char *tmp;
	
	data = talloc_zero(mem_ctx, struct domain_data);
	if (data == NULL) {
		return NULL;
	}

	data->pwdProperties = samdb_result_uint(res->message, "pwdProperties", 0);
	data->pwdHistoryLength = samdb_result_uint(res->message, "pwdHistoryLength", 0);
	tmp = ldb_msg_find_string(res->message, "dnsDomain", NULL);

	if (tmp != NULL) {
		data->dnsDomain = talloc_strdup(data, tmp);
		if (data->dnsDomain == NULL) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Out of memory!\n");
			return NULL;
		}
		data->realm = strupper_talloc(mem_ctx, tmp);
		if (data->realm == NULL) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Out of memory!\n");
			return NULL;
		}
	}

	return data;
}

static int password_hash_add_async(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_async_handle *h;
	struct ph_async_context *ac;
	struct ldb_message_element *attribute;
	struct dom_sid *domain_sid;
	int ret;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "password_hash_add_async\n");

	if (ldb_dn_is_special(req->op.add.message->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	/* nobody must touch password Histories */
	if (ldb_msg_find_element(req->op.add.message, "sambaNTPwdHistory") ||
	    ldb_msg_find_element(req->op.add.message, "sambaLMPwdHistory")) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* If no part of this touches the sambaPassword, then we don't
	 * need to make any changes.  For password changes/set there should
	 * be a 'delete' or a 'modify' on this attribute. */
	if ((attribute = ldb_msg_find_element(req->op.add.message, "sambaPassword")) == NULL ) {
		return ldb_next_request(module, req);
	}

	/* if it is not an entry of type person its an error */
	/* TODO: remove this when sambaPassword will be in schema */
	if (!ldb_msg_check_string_attribute(req->op.add.message, "objectClass", "person")) {
		return LDB_ERR_OBJECT_CLASS_VIOLATION;
	}

	/* check sambaPassword is single valued here */
	/* TODO: remove this when sambaPassword will be single valued in schema */
	if (attribute->num_values > 1) {
		ldb_set_errstring(module->ldb, talloc_asprintf(req,
					"mupltiple values for sambaPassword not allowed!\n"));
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/* get user domain data */
	domain_sid = samdb_result_sid_prefix(req, req->op.add.message, "objectSid");
	if (domain_sid == NULL) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "can't handle entry with missing objectSid!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	h = ph_init_handle(req, module, PH_ADD);
	if (!h) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac = talloc_get_type(h->private_data, struct ph_async_context);

	ret = build_domain_data_request(ac, domain_sid);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->step = PH_ADD_SEARCH_DOM;

	req->async.handle = h;

	return ldb_next_request(module, ac->dom_req);
}

static int password_hash_add_async_do_add(struct ldb_async_handle *h) {

	struct ph_async_context *ac;
	struct domain_data *domain;
	struct smb_krb5_context *smb_krb5_context;
	struct ldb_message *msg;

	ac = talloc_get_type(h->private_data, struct ph_async_context);

	domain = get_domain_data(ac->module, ac, ac->dom_res);
	if (domain == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->down_req = talloc(ac, struct ldb_request);
	if (ac->down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*(ac->down_req) = *(ac->orig_req);
	ac->down_req->op.add.message = msg = ldb_msg_copy_shallow(ac->down_req, ac->orig_req->op.add.message);
	if (ac->down_req->op.add.message == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	/* Some operations below require kerberos contexts */
	if (smb_krb5_init_context(ac->down_req, &smb_krb5_context) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* we can compute new password hashes from the unicode password */
	if (add_password_hashes(ac->module, msg, 0) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* now add krb5 keys based on unicode password */
	if (add_krb5_keys_from_password(ac->module, msg, smb_krb5_context, domain,
					ldb_msg_find_string(msg, "samAccountName", NULL),
					ldb_msg_find_string(msg, "userPrincipalName", NULL),
					ldb_msg_check_string_attribute(msg, "objectClass", "computer")
				       ) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* add also kr5 keys based on NT the hash */
	if (add_krb5_keys_from_NThash(ac->module, msg, smb_krb5_context) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* if both the domain properties and the user account controls do not permit
	 * clear text passwords then wipe out the sambaPassword */
	if ((!(domain->pwdProperties & DOMAIN_PASSWORD_STORE_CLEARTEXT)) ||
	    (!(ldb_msg_find_uint(msg, "userAccountControl", 0) & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED))) {
		ldb_msg_remove_attr(msg, "sambaPassword");
	}

	/* don't touch it if a value is set. It could be an incoming samsync */
	if (ldb_msg_find_uint64(msg, "pwdLastSet", 0) == 0) {
		if (set_pwdLastSet(ac->module, msg, 0) != LDB_SUCCESS) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	/* don't touch it if a value is set. It could be an incoming samsync */
	if (!ldb_msg_find_element(msg, "msDS-KeyVersionNumber")) {
		if (add_keyVersionNumber(ac->module, msg, 0) != LDB_SUCCESS) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->step = PH_ADD_DO_ADD;

	/* perform the operation */
	return ldb_next_request(ac->module, ac->down_req);
}

static int password_hash_mod_async_search_self(struct ldb_async_handle *h);

static int password_hash_modify_async(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_async_handle *h;
	struct ph_async_context *ac;
	struct ldb_message_element *sambaAttr;
	struct ldb_message_element *ntAttr;
	struct ldb_message_element *lmAttr;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "password_hash_add_async\n");

	if (ldb_dn_is_special(req->op.mod.message->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}
	
	/* nobody must touch password Histories */
	if (ldb_msg_find_element(req->op.mod.message, "sambaNTPwdHistory") ||
	    ldb_msg_find_element(req->op.mod.message, "sambaLMPwdHistory")) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	sambaAttr = ldb_msg_find_element(req->op.mod.message, "sambaPassword");
	ntAttr = ldb_msg_find_element(req->op.mod.message, "ntPwdHash");
	lmAttr = ldb_msg_find_element(req->op.mod.message, "lmPwdHash");

	/* check passwords are single valued here */
	/* TODO: remove this when passwords will be single valued in schema */
	if (sambaAttr && (sambaAttr->num_values > 1)) {
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}
	if (ntAttr && (ntAttr->num_values > 1)) {
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}
	if (lmAttr && (lmAttr->num_values > 1)) {
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/* If no part of this touches the sambaPassword OR ntPwdHash and/or lmPwdHash, then we don't
	 * need to make any changes.  For password changes/set there should
	 * be a 'delete' or a 'modify' on this attribute. */
	/* If the only operation is the deletion of the passwords then go on */
	if (	   ((!sambaAttr) || ((sambaAttr->flags & LDB_FLAG_MOD_MASK) == LDB_FLAG_MOD_DELETE))
		&& ((!ntAttr) || ((ntAttr->flags & LDB_FLAG_MOD_MASK) == LDB_FLAG_MOD_DELETE))
		&& ((!lmAttr) || ((lmAttr->flags & LDB_FLAG_MOD_MASK) == LDB_FLAG_MOD_DELETE))	) {

		return ldb_next_request(module, req);
	}

	h = ph_init_handle(req, module, PH_MOD);
	if (!h) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac = talloc_get_type(h->private_data, struct ph_async_context);

	/* return or own handle to deal with this call */
	req->async.handle = h;

	/* prepare the first operation */
	ac->down_req = talloc_zero(ac, struct ldb_request);
	if (ac->down_req == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module->ldb, "Out of memory!"));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*(ac->down_req) = *req; /* copy the request */

	/* use a new message structure so that we can modify it */
	ac->down_req->op.mod.message = ldb_msg_copy_shallow(ac->down_req, req->op.mod.message);

	/* - remove any imodification to the password from the first commit
	 *   we will make the real modification later */
	if (sambaAttr) ldb_msg_remove_attr(ac->down_req->op.mod.message, "sambaPassword");
	if (ntAttr) ldb_msg_remove_attr(ac->down_req->op.mod.message, "ntPwdHash");
	if (lmAttr) ldb_msg_remove_attr(ac->down_req->op.mod.message, "lmPwdHash");

	/* if there was nothing else to be modify skip to next step */
	if (ac->down_req->op.mod.message->num_elements == 0) {
		talloc_free(ac->down_req);
		ac->down_req = NULL;
		return password_hash_mod_async_search_self(h);
	}
	
	ac->down_req->async.context = NULL;
	ac->down_req->async.callback = NULL;

	ac->step = PH_MOD_DO_REQ;

	return ldb_next_request(module, ac->down_req);
}

static int get_self_callback(struct ldb_context *ldb, void *context, struct ldb_async_result *ares)
{
	struct ph_async_context *ac;

	if (!context || !ares) {
		ldb_set_errstring(ldb, talloc_asprintf(ldb, "NULL Context or Result in callback"));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac = talloc_get_type(context, struct ph_async_context);

	/* we are interested only in the single reply (base search) we receive here */
	if (ares->type == LDB_REPLY_ENTRY) {
		if (ac->search_res != NULL) {
			ldb_set_errstring(ldb, talloc_asprintf(ldb, "Too many results"));
			talloc_free(ares);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* if it is not an entry of type person this is an error */
		/* TODO: remove this when sambaPassword will be in schema */
		if (!ldb_msg_check_string_attribute(ares->message, "objectClass", "person")) {
			ldb_set_errstring(ldb, talloc_asprintf(ldb, "Object class violation"));
			talloc_free(ares);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
		}

		ac->search_res = talloc_steal(ac, ares);
	} else {
		talloc_free(ares);
	}

	return LDB_SUCCESS;
}

static int password_hash_mod_async_search_self(struct ldb_async_handle *h) {

	struct ph_async_context *ac;

	ac = talloc_get_type(h->private_data, struct ph_async_context);

	/* prepare the search operation */
	ac->search_req = talloc_zero(ac, struct ldb_request);
	if (ac->search_req == NULL) {
		ldb_debug(ac->module->ldb, LDB_DEBUG_ERROR, "Out of Memory!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->search_req->operation = LDB_ASYNC_SEARCH;
	ac->search_req->op.search.base = ac->orig_req->op.mod.message->dn;
	ac->search_req->op.search.scope = LDB_SCOPE_BASE;
	ac->search_req->op.search.tree = ldb_parse_tree(ac->module->ldb, NULL);
	if (ac->search_req->op.search.tree == NULL) {
		ldb_set_errstring(ac->module->ldb, talloc_asprintf(ac, "Invalid search filter"));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac->search_req->op.search.attrs = NULL;
	ac->search_req->controls = NULL;
	ac->search_req->async.context = ac;
	ac->search_req->async.callback = get_self_callback;
	ac->search_req->async.timeout = ac->orig_req->async.timeout;

	ac->step = PH_MOD_SEARCH_SELF;

	return ldb_next_request(ac->module, ac->search_req);
}

static int password_hash_mod_async_search_dom(struct ldb_async_handle *h) {

	struct ph_async_context *ac;
	struct dom_sid *domain_sid;
	int ret;

	ac = talloc_get_type(h->private_data, struct ph_async_context);

	/* get object domain sid */
	domain_sid = samdb_result_sid_prefix(ac, ac->search_res->message, "objectSid");
	if (domain_sid == NULL) {
		ldb_debug(ac->module->ldb, LDB_DEBUG_ERROR, "can't handle entry with missing objectSid!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* get user domain data */
	ret = build_domain_data_request(ac, domain_sid);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->step = PH_MOD_SEARCH_DOM;

	return ldb_next_request(ac->module, ac->dom_req);
}

static int password_hash_mod_async_do_mod(struct ldb_async_handle *h) {

	struct ph_async_context *ac;
	struct domain_data *domain;
	struct smb_krb5_context *smb_krb5_context;
	struct ldb_message_element *sambaAttr;
	struct ldb_message *msg;
	int phlen;

	ac = talloc_get_type(h->private_data, struct ph_async_context);

	domain = get_domain_data(ac->module, ac, ac->dom_res);
	if (domain == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->mod_req = talloc(ac, struct ldb_request);
	if (ac->mod_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*(ac->mod_req) = *(ac->orig_req);
	
	/* use a new message structure so that we can modify it */
	ac->mod_req->op.mod.message = msg = ldb_msg_new(ac->mod_req);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* modify dn */
	msg->dn = ac->orig_req->op.mod.message->dn;

	/* Some operations below require kerberos contexts */
	if (smb_krb5_init_context(ac->mod_req, &smb_krb5_context) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* we are going to replace the existing krb5key or delete it */
	if (ldb_msg_add_empty(msg, "krb5key", LDB_FLAG_MOD_REPLACE) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* if we have sambaPassword in the original message add the operatio on it here */
	sambaAttr = ldb_msg_find_element(ac->orig_req->op.mod.message, "sambaPassword");
	if (sambaAttr) {

		if (ldb_msg_add(msg, sambaAttr, sambaAttr->flags) != 0) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* we are not deleteing it add password hashes */
	       	if ((sambaAttr->flags & LDB_FLAG_MOD_MASK) != LDB_FLAG_MOD_DELETE) {
		
			/* we can compute new password hashes from the unicode password */
			if (add_password_hashes(ac->module, msg, 1) != LDB_SUCCESS) {
				return LDB_ERR_OPERATIONS_ERROR;
			}

			/* now add krb5 keys based on unicode password */
			if (add_krb5_keys_from_password(ac->module, msg, smb_krb5_context, domain,
				ldb_msg_find_string(ac->search_res->message, "samAccountName", NULL),
				ldb_msg_find_string(ac->search_res->message, "userPrincipalName", NULL),
				ldb_msg_check_string_attribute(ac->search_res->message, "objectClass", "computer")
						       ) != LDB_SUCCESS) {
				return LDB_ERR_OPERATIONS_ERROR;
			}

			/* if the domain properties or the user account controls do not permit
			 * clear text passwords then wipe out the sambaPassword */
			if ((!(domain->pwdProperties & DOMAIN_PASSWORD_STORE_CLEARTEXT)) ||
			    (!(ldb_msg_find_uint(ac->search_res->message, "userAccountControl", 0) & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED))) {
				ldb_msg_remove_attr(msg, "sambaPassword");
			}

		}
	}

	/* if we don't have sambaPassword or we are trying to delete it try with nt or lm hasehs */
	if ((!sambaAttr) || ((sambaAttr->flags & LDB_FLAG_MOD_MASK) == LDB_FLAG_MOD_DELETE)) {
		struct ldb_message_element *el;
		
		el = ldb_msg_find_element(ac->orig_req->op.mod.message, "ntPwdHash");
		if (ldb_msg_add(msg, el, el->flags) != 0) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		el = ldb_msg_find_element(ac->orig_req->op.mod.message, "lmPwdHash");
		if (ldb_msg_add(msg, el, el->flags) != 0) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	/* add also kr5 keys based on NT the hash */
	if (add_krb5_keys_from_NThash(ac->module, msg, smb_krb5_context) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* set change time */
	if (set_pwdLastSet(ac->module, msg, 1) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* don't touch it if a value is set. It could be an incoming samsync */
	if (add_keyVersionNumber(ac->module, msg,
				 ldb_msg_find_uint(msg, "msDS-KeyVersionNumber", 0)
				) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if ((phlen = samdb_result_uint(ac->dom_res->message, "pwdHistoryLength", 0)) > 0) {
		if (setPwdHistory(ac->module, msg, ac->search_res->message, phlen) != LDB_SUCCESS) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->step = PH_MOD_DO_MOD;

	/* perform the search */
	return ldb_next_request(ac->module, ac->mod_req);
}

static int ph_async_wait(struct ldb_async_handle *handle) {
	struct ph_async_context *ac;
	int ret;
    
	if (!handle || !handle->private_data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (handle->state == LDB_ASYNC_DONE) {
		return handle->status;
	}

	handle->state = LDB_ASYNC_PENDING;
	handle->status = LDB_SUCCESS;

	ac = talloc_get_type(handle->private_data, struct ph_async_context);

	switch (ac->step) {
	case PH_ADD_SEARCH_DOM:
		ret = ldb_async_wait(ac->dom_req->async.handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->dom_req->async.handle->status != LDB_SUCCESS) {
			handle->status = ac->dom_req->async.handle->status;
			goto done;
		}

		if (ac->dom_req->async.handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* domain search done, go on */
		return password_hash_add_async_do_add(handle);

	case PH_ADD_DO_ADD:
		ret = ldb_async_wait(ac->down_req->async.handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->down_req->async.handle->status != LDB_SUCCESS) {
			handle->status = ac->down_req->async.handle->status;
			goto done;
		}

		if (ac->down_req->async.handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		break;
		
	case PH_MOD_DO_REQ:
		ret = ldb_async_wait(ac->down_req->async.handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->down_req->async.handle->status != LDB_SUCCESS) {
			handle->status = ac->down_req->async.handle->status;
			goto done;
		}

		if (ac->down_req->async.handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* non-password mods done, go on */
		return password_hash_mod_async_search_self(handle);
		
	case PH_MOD_SEARCH_SELF:
		ret = ldb_async_wait(ac->search_req->async.handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->search_req->async.handle->status != LDB_SUCCESS) {
			handle->status = ac->search_req->async.handle->status;
			goto done;
		}

		if (ac->search_req->async.handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* self search done, go on */
		return password_hash_mod_async_search_dom(handle);
		
	case PH_MOD_SEARCH_DOM:
		ret = ldb_async_wait(ac->dom_req->async.handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->dom_req->async.handle->status != LDB_SUCCESS) {
			handle->status = ac->dom_req->async.handle->status;
			goto done;
		}

		if (ac->dom_req->async.handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* domain search done, go on */
		return password_hash_mod_async_do_mod(handle);

	case PH_MOD_DO_MOD:
		ret = ldb_async_wait(ac->mod_req->async.handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->mod_req->async.handle->status != LDB_SUCCESS) {
			handle->status = ac->mod_req->async.handle->status;
			goto done;
		}

		if (ac->mod_req->async.handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		break;
		
	default:
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	ret = LDB_SUCCESS;

done:
	handle->state = LDB_ASYNC_DONE;
	return ret;
}

static int ph_async_wait_all(struct ldb_async_handle *handle) {

	int ret;

	while (handle->state != LDB_ASYNC_DONE) {
		ret = ph_async_wait(handle);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return handle->status;
}

static int password_hash_async_wait(struct ldb_async_handle *handle, enum ldb_async_wait_type type)
{
	if (type == LDB_WAIT_ALL) {
		return ph_async_wait_all(handle);
	} else {
		return ph_async_wait(handle);
	}
}

static int password_hash_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_REQ_ADD:
		return password_hash_add(module, req);

	case LDB_REQ_MODIFY:
		return password_hash_modify(module, req);

	default:
		return ldb_next_request(module, req);

	}
}

static const struct ldb_module_ops password_hash_ops = {
	.name          = "password_hash",
	.add           = password_hash_add_async,
	.modify        = password_hash_modify_async,
	.request       = password_hash_request,
	.async_wait    = password_hash_async_wait
};


int password_hash_module_init(void)
{
	return ldb_register_module(&password_hash_ops);
}
