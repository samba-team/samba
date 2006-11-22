/* 
   ldb database module

   Copyright (C) Simo Sorce  2004-2006
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2006
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
#include "dsdb/common/flags.h"
#include "hdb.h"
#include "dsdb/samdb/ldb_modules/password_modules.h"

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

struct ph_context {

	enum ph_type {PH_ADD, PH_MOD} type;
	enum ph_step {PH_ADD_SEARCH_DOM, PH_ADD_DO_ADD, PH_MOD_DO_REQ, PH_MOD_SEARCH_SELF, PH_MOD_SEARCH_DOM, PH_MOD_DO_MOD} step;

	struct ldb_module *module;
	struct ldb_request *orig_req;

	struct ldb_request *dom_req;
	struct ldb_reply *dom_res;

	struct ldb_request *down_req;

	struct ldb_request *search_req;
	struct ldb_reply *search_res;

	struct ldb_request *mod_req;

	struct dom_sid *domain_sid;
};

struct domain_data {
	BOOL store_cleartext;
	uint_t pwdProperties;
	uint_t pwdHistoryLength;
	char *dns_domain;
	char *realm;
};

static int add_password_hashes(struct ldb_module *module, struct ldb_message *msg, int is_mod)
{
	const char *sambaPassword;
	struct samr_Password tmp_hash;
	
	sambaPassword = ldb_msg_find_attr_as_string(msg, "sambaPassword", NULL);
	if (sambaPassword == NULL) { /* impossible, what happened ?! */
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	if (is_mod) {
		if (ldb_msg_add_empty(msg, "ntPwdHash", LDB_FLAG_MOD_REPLACE, NULL) != 0) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		if (ldb_msg_add_empty(msg, "lmPwdHash", LDB_FLAG_MOD_REPLACE, NULL) != 0) {
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

	sambaPassword = ldb_msg_find_attr_as_string(msg, "sambaPassword", NULL);
	if (sambaPassword == NULL) { /* impossible, what happened ?! */
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (is_computer) {
		/* Determine a salting principal */
		char *name = talloc_strdup(msg, samAccountName);
		char *saltbody;
		if (name == NULL) {
			ldb_asprintf_errstring(module->ldb,
						"password_hash_handle: "
						"generation of new kerberos keys failed: %s is a computer without a samAccountName",
						ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		if (name[strlen(name)-1] == '$') {
			name[strlen(name)-1] = '\0';
		}
		saltbody = talloc_asprintf(msg, "%s.%s", name, domain->dns_domain);
		
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
			ldb_asprintf_errstring(module->ldb,
						"password_hash_handle: "
						"generation of new kerberos keys failed: %s has no samAccountName",
						ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		krb5_ret = krb5_make_principal(smb_krb5_context->krb5_context,
						&salt_principal,
						domain->realm, samAccountName,
						NULL);
	}

	if (krb5_ret) {
		ldb_asprintf_errstring(module->ldb,
					"password_hash_handle: "
					"generation of a saltking principal failed: %s",
					smb_get_krb5_error_message(smb_krb5_context->krb5_context, krb5_ret, msg));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* TODO: We may wish to control the encryption types chosen in future */
	krb5_ret = hdb_generate_key_set_password(smb_krb5_context->krb5_context,
						 salt_principal, sambaPassword, &keys, &num_keys);
	krb5_free_principal(smb_krb5_context->krb5_context, salt_principal);

	if (krb5_ret) {
		ldb_asprintf_errstring(module->ldb,
					"password_hash_handle: "
					"generation of new kerberos keys failed: %s",
					smb_get_krb5_error_message(smb_krb5_context->krb5_context, krb5_ret, msg));
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
		
		val.data = talloc_memdup(msg, buf, len);
		val.length = len;
		free(buf);
		if (!val.data || krb5_ret) {
			hdb_free_keys (smb_krb5_context->krb5_context, num_keys, keys);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ret = ldb_msg_add_value(msg, "krb5Key", &val, NULL);
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
	
	val.data = talloc_memdup(msg, buf, len);
	val.length = len;
	free(buf);
	if (!val.data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	if (ldb_msg_add_value(msg, "krb5Key", &val, NULL) != 0) {
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
		if (ldb_msg_add_empty(msg, "pwdLastSet", LDB_FLAG_MOD_ADD, NULL) != 0) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	} else {
		/* replace */
		if (ldb_msg_add_empty(msg, "pwdLastSet", LDB_FLAG_MOD_REPLACE, NULL) != 0) {
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
	if (ldb_msg_add_empty(msg, "msDS-KeyVersionNumber", LDB_FLAG_MOD_REPLACE, NULL) != 0) {
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
	if (ldb_msg_add_empty(msg, "sambaNTPwdHistory", LDB_FLAG_MOD_REPLACE, NULL) != LDB_SUCCESS) {
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
	if (ldb_msg_add_empty(msg, "sambaLMPwdHistory", LDB_FLAG_MOD_REPLACE, NULL) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	if (samdb_msg_add_hashes(msg, msg, "sambaLMPwdHistory", new_lm_history, lm_hist_len) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return LDB_SUCCESS;
}

static struct ldb_handle *ph_init_handle(struct ldb_request *req, struct ldb_module *module, enum ph_type type)
{
	struct ph_context *ac;
	struct ldb_handle *h;

	h = talloc_zero(req, struct ldb_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		return NULL;
	}

	h->module = module;

	ac = talloc_zero(h, struct ph_context);
	if (ac == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
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

static int get_domain_data_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct ph_context *ac;

	if (!context || !ares) {
		ldb_set_errstring(ldb, "NULL Context or Result in callback");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac = talloc_get_type(context, struct ph_context);

	/* we are interested only in the single reply (base search) we receive here */
	if (ares->type == LDB_REPLY_ENTRY) {
		if (ac->dom_res != NULL) {
			ldb_set_errstring(ldb, "Too many results");
			talloc_free(ares);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ac->dom_res = talloc_steal(ac, ares);
	} else {
		talloc_free(ares);
	}

	return LDB_SUCCESS;
}

static int build_domain_data_request(struct ph_context *ac)
{
	/* attrs[] is returned from this function in
	   ac->dom_req->op.search.attrs, so it must be static, as
	   otherwise the compiler can put it on the stack */
	static const char * const attrs[] = { "pwdProperties", "pwdHistoryLength", NULL };
	char *filter;

	ac->dom_req = talloc_zero(ac, struct ldb_request);
	if (ac->dom_req == NULL) {
		ldb_debug(ac->module->ldb, LDB_DEBUG_ERROR, "Out of Memory!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac->dom_req->operation = LDB_SEARCH;
	ac->dom_req->op.search.base = ldb_get_default_basedn(ac->module->ldb);
	ac->dom_req->op.search.scope = LDB_SCOPE_SUBTREE;

	filter = talloc_asprintf(ac->dom_req, "(&(objectSid=%s)(|(objectClass=domain)(objectClass=builtinDomain)))", 
				 ldap_encode_ndr_dom_sid(ac->dom_req, ac->domain_sid));
	if (filter == NULL) {
		ldb_debug(ac->module->ldb, LDB_DEBUG_ERROR, "Out of Memory!\n");
		talloc_free(ac->dom_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->dom_req->op.search.tree = ldb_parse_tree(ac->dom_req, filter);
	if (ac->dom_req->op.search.tree == NULL) {
		ldb_set_errstring(ac->module->ldb, "Invalid search filter");
		talloc_free(ac->dom_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac->dom_req->op.search.attrs = attrs;
	ac->dom_req->controls = NULL;
	ac->dom_req->context = ac;
	ac->dom_req->callback = get_domain_data_callback;
	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->dom_req);

	return LDB_SUCCESS;
}

static struct domain_data *get_domain_data(struct ldb_module *module, void *ctx, struct ldb_reply *res)
{
	struct domain_data *data;
	const char *tmp;
	struct ph_context *ac;
	char *p;

	ac = talloc_get_type(ctx, struct ph_context);

	data = talloc_zero(ac, struct domain_data);
	if (data == NULL) {
		return NULL;
	}

	if (res == NULL) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Could not find this user's domain: %s!\n", dom_sid_string(data, ac->domain_sid));
		talloc_free(data);
		return NULL;
	}

	data->pwdProperties= samdb_result_uint(res->message, "pwdProperties", 0);
	data->store_cleartext = data->pwdProperties & DOMAIN_PASSWORD_STORE_CLEARTEXT;
	data->pwdHistoryLength = samdb_result_uint(res->message, "pwdHistoryLength", 0);

	/* For a domain DN, this puts things in dotted notation */
	/* For builtin domains, this will give details for the host,
	 * but that doesn't really matter, as it's just used for salt
	 * and kerberos principals, which don't exist here */

	tmp = ldb_dn_canonical_string(ctx, res->message->dn);
	if (!tmp) {
		return NULL;
	}
	
	/* But it puts a trailing (or just before 'builtin') / on things, so kill that */
	p = strchr(tmp, '/');
	if (p) {
		p[0] = '\0';
	}

	if (tmp != NULL) {
		data->dns_domain = strlower_talloc(data, tmp);
		if (data->dns_domain == NULL) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Out of memory!\n");
			return NULL;
		}
		data->realm = strupper_talloc(data, tmp);
		if (data->realm == NULL) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Out of memory!\n");
			return NULL;
		}
	}

	return data;
}

static int password_hash_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_handle *h;
	struct ph_context *ac;
	struct ldb_message_element *sambaAttr;
	struct ldb_message_element *ntAttr;
	struct ldb_message_element *lmAttr;
	int ret;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "password_hash_add\n");

	if (ldb_dn_is_special(req->op.add.message->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	/* If the caller is manipulating the local passwords directly, let them pass */
	if (ldb_dn_compare_base(ldb_dn_new(req, module->ldb, LOCAL_BASE),
				req->op.add.message->dn) == 0) {
		return ldb_next_request(module, req);
	}

	/* nobody must touch password Histories */
	if (ldb_msg_find_element(req->op.add.message, "sambaNTPwdHistory") ||
	    ldb_msg_find_element(req->op.add.message, "sambaLMPwdHistory")) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* If no part of this ADD touches the sambaPassword, or the NT
	 * or LM hashes, then we don't need to make any changes.  */

	sambaAttr = ldb_msg_find_element(req->op.mod.message, "sambaPassword");
	ntAttr = ldb_msg_find_element(req->op.mod.message, "ntPwdHash");
	lmAttr = ldb_msg_find_element(req->op.mod.message, "lmPwdHash");

	if ((!sambaAttr) && (!ntAttr) && (!lmAttr)) {
		return ldb_next_request(module, req);
	}

	/* if it is not an entry of type person its an error */
	/* TODO: remove this when sambaPassword will be in schema */
	if (!ldb_msg_check_string_attribute(req->op.add.message, "objectClass", "person")) {
		ldb_set_errstring(module->ldb, "Cannot set a password on entry that does not have objectClass 'person'");
		return LDB_ERR_OBJECT_CLASS_VIOLATION;
	}

	/* check sambaPassword is single valued here */
	/* TODO: remove this when sambaPassword will be single valued in schema */
	if (sambaAttr && sambaAttr->num_values > 1) {
		ldb_set_errstring(module->ldb, "mupltiple values for sambaPassword not allowed!\n");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	if (ntAttr && (ntAttr->num_values > 1)) {
		ldb_set_errstring(module->ldb, "mupltiple values for lmPwdHash not allowed!\n");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}
	if (lmAttr && (lmAttr->num_values > 1)) {
		ldb_set_errstring(module->ldb, "mupltiple values for lmPwdHash not allowed!\n");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	if (sambaAttr && sambaAttr->num_values == 0) {
		ldb_set_errstring(module->ldb, "sambaPassword must have a value!\n");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	if (ntAttr && (ntAttr->num_values == 0)) {
		ldb_set_errstring(module->ldb, "lmPwdHash must have a value!\n");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}
	if (lmAttr && (lmAttr->num_values == 0)) {
		ldb_set_errstring(module->ldb, "lmPwdHash must have a value!\n");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	h = ph_init_handle(req, module, PH_ADD);
	if (!h) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac = talloc_get_type(h->private_data, struct ph_context);

	/* get user domain data */
	ac->domain_sid = samdb_result_sid_prefix(ac, req->op.add.message, "objectSid");
	if (ac->domain_sid == NULL) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "can't handle entry with missing objectSid!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = build_domain_data_request(ac);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->step = PH_ADD_SEARCH_DOM;

	req->handle = h;

	return ldb_next_request(module, ac->dom_req);
}

static int password_hash_add_do_add(struct ldb_handle *h) {

	struct ph_context *ac;
	struct domain_data *domain;
	struct smb_krb5_context *smb_krb5_context;
	struct ldb_message_element *sambaAttr;
	struct ldb_message *msg;
	int ret;

	ac = talloc_get_type(h->private_data, struct ph_context);

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

	/* if we have sambaPassword in the original message add the operatio on it here */
	sambaAttr = ldb_msg_find_element(msg, "sambaPassword");
	if (sambaAttr) {
		unsigned int user_account_control;
		ret = add_password_hashes(ac->module, msg, 0);
		/* we can compute new password hashes from the unicode password */
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		
		/* now add krb5 keys based on unicode password */
		ret = add_krb5_keys_from_password(ac->module, msg, smb_krb5_context, domain,
						  ldb_msg_find_attr_as_string(msg, "samAccountName", NULL),
						  ldb_msg_find_attr_as_string(msg, "userPrincipalName", NULL),
						  ldb_msg_check_string_attribute(msg, "objectClass", "computer"));
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		
		/* if both the domain properties and the user account controls do not permit
		 * clear text passwords then wipe out the sambaPassword */
		user_account_control = ldb_msg_find_attr_as_uint(msg, "userAccountControl", 0);
		if (domain->store_cleartext && (user_account_control & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED)) {
			/* Keep sambaPassword attribute */
		} else {
			ldb_msg_remove_attr(msg, "sambaPassword");
		}
	}

	/* add also krb5 keys based on NT the hash (we might have ntPwdHash, but not the cleartext */
	ret = add_krb5_keys_from_NThash(ac->module, msg, smb_krb5_context);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
		
	/* don't touch it if a value is set. It could be an incoming samsync */
	if (ldb_msg_find_attr_as_uint64(msg, "pwdLastSet", 0) == 0) {
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

	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->down_req);

	/* perform the operation */
	return ldb_next_request(ac->module, ac->down_req);
}

static int password_hash_mod_search_self(struct ldb_handle *h);

static int password_hash_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_handle *h;
	struct ph_context *ac;
	struct ldb_message_element *sambaAttr;
	struct ldb_message_element *ntAttr;
	struct ldb_message_element *lmAttr;
	struct ldb_message *msg;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "password_hash_modify\n");

	if (ldb_dn_is_special(req->op.mod.message->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}
	
	/* If the caller is manipulating the local passwords directly, let them pass */
	if (ldb_dn_compare_base(ldb_dn_new(req, module->ldb, LOCAL_BASE),
				req->op.mod.message->dn) == 0) {
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
	ac = talloc_get_type(h->private_data, struct ph_context);

	/* return or own handle to deal with this call */
	req->handle = h;

	/* prepare the first operation */
	ac->down_req = talloc_zero(ac, struct ldb_request);
	if (ac->down_req == NULL) {
		ldb_set_errstring(module->ldb, "Out of memory!");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*(ac->down_req) = *req; /* copy the request */

	/* use a new message structure so that we can modify it */
	ac->down_req->op.mod.message = msg = ldb_msg_copy_shallow(ac->down_req, req->op.mod.message);

	/* - remove any imodification to the password from the first commit
	 *   we will make the real modification later */
	if (sambaAttr) ldb_msg_remove_attr(msg, "sambaPassword");
	if (ntAttr) ldb_msg_remove_attr(msg, "ntPwdHash");
	if (lmAttr) ldb_msg_remove_attr(msg, "lmPwdHash");

	/* if there was nothing else to be modify skip to next step */
	if (msg->num_elements == 0) {
		talloc_free(ac->down_req);
		ac->down_req = NULL;
		return password_hash_mod_search_self(h);
	}
	
	ac->down_req->context = NULL;
	ac->down_req->callback = NULL;

	ac->step = PH_MOD_DO_REQ;

	ldb_set_timeout_from_prev_req(module->ldb, req, ac->down_req);

	return ldb_next_request(module, ac->down_req);
}

static int get_self_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct ph_context *ac;

	if (!context || !ares) {
		ldb_set_errstring(ldb, "NULL Context or Result in callback");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac = talloc_get_type(context, struct ph_context);

	/* we are interested only in the single reply (base search) we receive here */
	if (ares->type == LDB_REPLY_ENTRY) {
		if (ac->search_res != NULL) {
			ldb_set_errstring(ldb, "Too many results");
			talloc_free(ares);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* if it is not an entry of type person this is an error */
		/* TODO: remove this when sambaPassword will be in schema */
		if (!ldb_msg_check_string_attribute(ares->message, "objectClass", "person")) {
			ldb_set_errstring(ldb, "Object class violation");
			talloc_free(ares);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
		}

		ac->search_res = talloc_steal(ac, ares);
	} else {
		talloc_free(ares);
	}

	return LDB_SUCCESS;
}

static int password_hash_mod_search_self(struct ldb_handle *h) {

	struct ph_context *ac;
	static const char * const attrs[] = { "userAccountControl", "sambaLMPwdHistory", 
					      "sambaNTPwdHistory", 
					      "objectSid", "msDS-KeyVersionNumber", 
					      "objectClass", "userPrincipalName",
					      "samAccountName", 
					      "lmPwdHash", "ntPwdHash",
					      NULL };

	ac = talloc_get_type(h->private_data, struct ph_context);

	/* prepare the search operation */
	ac->search_req = talloc_zero(ac, struct ldb_request);
	if (ac->search_req == NULL) {
		ldb_debug(ac->module->ldb, LDB_DEBUG_ERROR, "Out of Memory!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->search_req->operation = LDB_SEARCH;
	ac->search_req->op.search.base = ac->orig_req->op.mod.message->dn;
	ac->search_req->op.search.scope = LDB_SCOPE_BASE;
	ac->search_req->op.search.tree = ldb_parse_tree(ac->search_req, NULL);
	if (ac->search_req->op.search.tree == NULL) {
		ldb_set_errstring(ac->module->ldb, "Invalid search filter");
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac->search_req->op.search.attrs = attrs;
	ac->search_req->controls = NULL;
	ac->search_req->context = ac;
	ac->search_req->callback = get_self_callback;
	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->search_req);

	ac->step = PH_MOD_SEARCH_SELF;

	return ldb_next_request(ac->module, ac->search_req);
}

static int password_hash_mod_search_dom(struct ldb_handle *h) {

	struct ph_context *ac;
	int ret;

	ac = talloc_get_type(h->private_data, struct ph_context);

	/* get object domain sid */
	ac->domain_sid = samdb_result_sid_prefix(ac, ac->search_res->message, "objectSid");
	if (ac->domain_sid == NULL) {
		ldb_debug(ac->module->ldb, LDB_DEBUG_ERROR, "can't handle entry with missing objectSid!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* get user domain data */
	ret = build_domain_data_request(ac);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->step = PH_MOD_SEARCH_DOM;

	return ldb_next_request(ac->module, ac->dom_req);
}

static int password_hash_mod_do_mod(struct ldb_handle *h) {

	struct ph_context *ac;
	struct domain_data *domain;
	struct smb_krb5_context *smb_krb5_context;
	struct ldb_message_element *sambaAttr;
	struct ldb_message *msg;
	int phlen;
	int ret;
	BOOL added_hashes = False;

	ac = talloc_get_type(h->private_data, struct ph_context);

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
	if (ldb_msg_add_empty(msg, "krb5key", LDB_FLAG_MOD_REPLACE, NULL) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* if we have sambaPassword in the original message add the operation on it here */
	sambaAttr = ldb_msg_find_element(ac->orig_req->op.mod.message, "sambaPassword");
	if (sambaAttr) {

		if (ldb_msg_add(msg, sambaAttr, sambaAttr->flags) != 0) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* if we are actually settting a new unicode password,
		 * use it to generate the password hashes */
	       	if (((sambaAttr->flags & LDB_FLAG_MOD_MASK) != LDB_FLAG_MOD_DELETE)
		    && (sambaAttr->num_values == 1)) {
			/* we can compute new password hashes from the unicode password */
			ret = add_password_hashes(ac->module, msg, 1);
			if (ret != LDB_SUCCESS) {
				return ret;
			}

			added_hashes = True;

			/* now add krb5 keys based on unicode password */
			ret = add_krb5_keys_from_password(ac->module, msg, smb_krb5_context, domain,
							  ldb_msg_find_attr_as_string(ac->search_res->message, "samAccountName", NULL),
							  ldb_msg_find_attr_as_string(ac->search_res->message, "userPrincipalName", NULL),
							  ldb_msg_check_string_attribute(ac->search_res->message, "objectClass", "computer"));

			if (ret != LDB_SUCCESS) {
				return ret;
			}

			/* if the domain properties or the user account controls do not permit
			 * clear text passwords then wipe out the sambaPassword */
			if (domain->store_cleartext &&
			    (ldb_msg_find_attr_as_uint(ac->search_res->message, "userAccountControl", 0) & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED)) {
				/* Keep sambaPassword attribute */
			} else {
				ldb_msg_remove_attr(msg, "sambaPassword");
			}

		}
	}

	/* if we didn't create the hashes above, try using values supplied directly */
	if (!added_hashes) {
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

	/* add also krb5 keys based on NT the hash */
	if (add_krb5_keys_from_NThash(ac->module, msg, smb_krb5_context) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* set change time */
	if (set_pwdLastSet(ac->module, msg, 1) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* don't touch it if a value is set. It could be an incoming samsync */
	if (!ldb_msg_find_element(ac->orig_req->op.mod.message, 
				 "msDS-KeyVersionNumber")) {
		if (add_keyVersionNumber(ac->module, msg,
					 ldb_msg_find_attr_as_uint(ac->search_res->message, 
							   "msDS-KeyVersionNumber", 0)
			    ) != LDB_SUCCESS) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	if ((phlen = samdb_result_uint(ac->dom_res->message, "pwdHistoryLength", 0)) > 0) {
		if (setPwdHistory(ac->module, msg, ac->search_res->message, phlen) != LDB_SUCCESS) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->step = PH_MOD_DO_MOD;

	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->mod_req);

	/* perform the search */
	return ldb_next_request(ac->module, ac->mod_req);
}

static int ph_wait(struct ldb_handle *handle) {
	struct ph_context *ac;
	int ret;
    
	if (!handle || !handle->private_data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (handle->state == LDB_ASYNC_DONE) {
		return handle->status;
	}

	handle->state = LDB_ASYNC_PENDING;
	handle->status = LDB_SUCCESS;

	ac = talloc_get_type(handle->private_data, struct ph_context);

	switch (ac->step) {
	case PH_ADD_SEARCH_DOM:
		ret = ldb_wait(ac->dom_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->dom_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->dom_req->handle->status;
			goto done;
		}

		if (ac->dom_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* domain search done, go on */
		return password_hash_add_do_add(handle);

	case PH_ADD_DO_ADD:
		ret = ldb_wait(ac->down_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->down_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->down_req->handle->status;
			goto done;
		}

		if (ac->down_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		break;
		
	case PH_MOD_DO_REQ:
		ret = ldb_wait(ac->down_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->down_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->down_req->handle->status;
			goto done;
		}

		if (ac->down_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* non-password mods done, go on */
		return password_hash_mod_search_self(handle);
		
	case PH_MOD_SEARCH_SELF:
		ret = ldb_wait(ac->search_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->search_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->search_req->handle->status;
			goto done;
		}

		if (ac->search_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* self search done, go on */
		return password_hash_mod_search_dom(handle);
		
	case PH_MOD_SEARCH_DOM:
		ret = ldb_wait(ac->dom_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->dom_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->dom_req->handle->status;
			goto done;
		}

		if (ac->dom_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* domain search done, go on */
		return password_hash_mod_do_mod(handle);

	case PH_MOD_DO_MOD:
		ret = ldb_wait(ac->mod_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->mod_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->mod_req->handle->status;
			goto done;
		}

		if (ac->mod_req->handle->state != LDB_ASYNC_DONE) {
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

static int ph_wait_all(struct ldb_handle *handle) {

	int ret;

	while (handle->state != LDB_ASYNC_DONE) {
		ret = ph_wait(handle);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return handle->status;
}

static int password_hash_wait(struct ldb_handle *handle, enum ldb_wait_type type)
{
	if (type == LDB_WAIT_ALL) {
		return ph_wait_all(handle);
	} else {
		return ph_wait(handle);
	}
}

static const struct ldb_module_ops password_hash_ops = {
	.name          = "password_hash",
	.add           = password_hash_add,
	.modify        = password_hash_modify,
	.wait          = password_hash_wait
};


int password_hash_module_init(void)
{
	return ldb_register_module(&password_hash_ops);
}
