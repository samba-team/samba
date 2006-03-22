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
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/auth/libcli_auth.h"
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
	
	/* If no part of this touches the sambaPassword, then we don't
	 * need to make any changes.  For password changes/set there should
	 * be a 'delete' or a 'modify' on this attribute. */
	if ((attribute = ldb_msg_find_element(msg, "sambaPassword")) == NULL ) {
		return ldb_next_request(module, req);
	}

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
	
	domain_expression  = talloc_asprintf(mem_ctx, "(&(objectSid=%s)(|(objectClass=domain)(objectClass=builtinDomain)))", 
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
		
		CHECK_RET(samdb_msg_add_hashes(module->ldb, mem_ctx, modify_msg, 
					       "sambaLMPwdHistory", 
					       new_sambaLMPwdHistory, 
					       sambaLMPwdHistory_len));
		
		CHECK_RET(samdb_msg_add_hashes(module->ldb, mem_ctx, modify_msg, 
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
	
	return password_hash_handle(module, req, msg);
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
	.request       = password_hash_request
};


int password_hash_module_init(void)
{
	return ldb_register_module(&password_hash_ops);
}
