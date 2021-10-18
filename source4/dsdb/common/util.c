/* 
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Volker Lendecke 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007

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
#include "events/events.h"
#include "ldb.h"
#include "ldb_module.h"
#include "ldb_errors.h"
#include "../lib/util/util_ldb.h"
#include "../lib/crypto/crypto.h"
#include "dsdb/samdb/samdb.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "../libds/common/flags.h"
#include "dsdb/common/proto.h"
#include "libcli/ldap/ldap_ndr.h"
#include "param/param.h"
#include "libcli/auth/libcli_auth.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "system/locale.h"
#include "system/filesys.h"
#include "lib/util/tsort.h"
#include "dsdb/common/util.h"
#include "lib/socket/socket.h"
#include "librpc/gen_ndr/irpc.h"
#include "libds/common/flag_mapping.h"
#include "lib/util/access.h"
#include "lib/util/util_str_hex.h"
#include "lib/util/sys_rw_data.h"
#include "libcli/util/ntstatus.h"

/*
 * This included to allow us to handle DSDB_FLAG_REPLICATED_UPDATE in
 * dsdb_request_add_controls()
 */
#include "dsdb/samdb/ldb_modules/util.h"

/* default is 30 minutes: -1e7 * 30 * 60 */
#define DEFAULT_OBSERVATION_WINDOW              -18000000000

/*
  search the sam for the specified attributes in a specific domain, filter on
  objectSid being in domain_sid.
*/
int samdb_search_domain(struct ldb_context *sam_ldb,
			TALLOC_CTX *mem_ctx, 
			struct ldb_dn *basedn,
			struct ldb_message ***res,
			const char * const *attrs,
			const struct dom_sid *domain_sid,
			const char *format, ...)  _PRINTF_ATTRIBUTE(7,8)
{
	va_list ap;
	int i, count;

	va_start(ap, format);
	count = gendb_search_v(sam_ldb, mem_ctx, basedn,
			       res, attrs, format, ap);
	va_end(ap);

	i=0;

	while (i<count) {
		struct dom_sid *entry_sid;

		entry_sid = samdb_result_dom_sid(mem_ctx, (*res)[i], "objectSid");

		if ((entry_sid == NULL) ||
		    (!dom_sid_in_domain(domain_sid, entry_sid))) {
			/* Delete that entry from the result set */
			(*res)[i] = (*res)[count-1];
			count -= 1;
			talloc_free(entry_sid);
			continue;
		}
		talloc_free(entry_sid);
		i += 1;
	}

	return count;
}

/*
  search the sam for a single string attribute in exactly 1 record
*/
const char *samdb_search_string_v(struct ldb_context *sam_ldb,
				  TALLOC_CTX *mem_ctx,
				  struct ldb_dn *basedn,
				  const char *attr_name,
				  const char *format, va_list ap) _PRINTF_ATTRIBUTE(5,0)
{
	int count;
	const char *attrs[2] = { NULL, NULL };
	struct ldb_message **res = NULL;

	attrs[0] = attr_name;

	count = gendb_search_v(sam_ldb, mem_ctx, basedn, &res, attrs, format, ap);
	if (count > 1) {		
		DEBUG(1,("samdb: search for %s %s not single valued (count=%d)\n", 
			 attr_name, format, count));
	}
	if (count != 1) {
		talloc_free(res);
		return NULL;
	}

	return ldb_msg_find_attr_as_string(res[0], attr_name, NULL);
}

/*
  search the sam for a single string attribute in exactly 1 record
*/
const char *samdb_search_string(struct ldb_context *sam_ldb,
				TALLOC_CTX *mem_ctx,
				struct ldb_dn *basedn,
				const char *attr_name,
				const char *format, ...) _PRINTF_ATTRIBUTE(5,6)
{
	va_list ap;
	const char *str;

	va_start(ap, format);
	str = samdb_search_string_v(sam_ldb, mem_ctx, basedn, attr_name, format, ap);
	va_end(ap);

	return str;
}

struct ldb_dn *samdb_search_dn(struct ldb_context *sam_ldb,
			       TALLOC_CTX *mem_ctx,
			       struct ldb_dn *basedn,
			       const char *format, ...) _PRINTF_ATTRIBUTE(4,5)
{
	va_list ap;
	struct ldb_dn *ret;
	struct ldb_message **res = NULL;
	int count;

	va_start(ap, format);
	count = gendb_search_v(sam_ldb, mem_ctx, basedn, &res, NULL, format, ap);
	va_end(ap);

	if (count != 1) return NULL;

	ret = talloc_steal(mem_ctx, res[0]->dn);
	talloc_free(res);

	return ret;
}

/*
  search the sam for a dom_sid attribute in exactly 1 record
*/
struct dom_sid *samdb_search_dom_sid(struct ldb_context *sam_ldb,
				     TALLOC_CTX *mem_ctx,
				     struct ldb_dn *basedn,
				     const char *attr_name,
				     const char *format, ...) _PRINTF_ATTRIBUTE(5,6)
{
	va_list ap;
	int count;
	struct ldb_message **res;
	const char *attrs[2] = { NULL, NULL };
	struct dom_sid *sid;

	attrs[0] = attr_name;

	va_start(ap, format);
	count = gendb_search_v(sam_ldb, mem_ctx, basedn, &res, attrs, format, ap);
	va_end(ap);
	if (count > 1) {		
		DEBUG(1,("samdb: search for %s %s not single valued (count=%d)\n", 
			 attr_name, format, count));
	}
	if (count != 1) {
		talloc_free(res);
		return NULL;
	}
	sid = samdb_result_dom_sid(mem_ctx, res[0], attr_name);
	talloc_free(res);
	return sid;	
}

/*
  search the sam for a single integer attribute in exactly 1 record
*/
unsigned int samdb_search_uint(struct ldb_context *sam_ldb,
			 TALLOC_CTX *mem_ctx,
			 unsigned int default_value,
			 struct ldb_dn *basedn,
			 const char *attr_name,
			 const char *format, ...) _PRINTF_ATTRIBUTE(6,7)
{
	va_list ap;
	int count;
	struct ldb_message **res;
	const char *attrs[2] = { NULL, NULL };

	attrs[0] = attr_name;

	va_start(ap, format);
	count = gendb_search_v(sam_ldb, mem_ctx, basedn, &res, attrs, format, ap);
	va_end(ap);

	if (count != 1) {
		return default_value;
	}

	return ldb_msg_find_attr_as_uint(res[0], attr_name, default_value);
}

/*
  search the sam for a single signed 64 bit integer attribute in exactly 1 record
*/
int64_t samdb_search_int64(struct ldb_context *sam_ldb,
			   TALLOC_CTX *mem_ctx,
			   int64_t default_value,
			   struct ldb_dn *basedn,
			   const char *attr_name,
			   const char *format, ...) _PRINTF_ATTRIBUTE(6,7)
{
	va_list ap;
	int count;
	struct ldb_message **res;
	const char *attrs[2] = { NULL, NULL };

	attrs[0] = attr_name;

	va_start(ap, format);
	count = gendb_search_v(sam_ldb, mem_ctx, basedn, &res, attrs, format, ap);
	va_end(ap);

	if (count != 1) {
		return default_value;
	}

	return ldb_msg_find_attr_as_int64(res[0], attr_name, default_value);
}

/*
  search the sam for multipe records each giving a single string attribute
  return the number of matches, or -1 on error
*/
int samdb_search_string_multiple(struct ldb_context *sam_ldb,
				 TALLOC_CTX *mem_ctx,
				 struct ldb_dn *basedn,
				 const char ***strs,
				 const char *attr_name,
				 const char *format, ...) _PRINTF_ATTRIBUTE(6,7)
{
	va_list ap;
	int count, i;
	const char *attrs[2] = { NULL, NULL };
	struct ldb_message **res = NULL;

	attrs[0] = attr_name;

	va_start(ap, format);
	count = gendb_search_v(sam_ldb, mem_ctx, basedn, &res, attrs, format, ap);
	va_end(ap);

	if (count <= 0) {
		return count;
	}

	/* make sure its single valued */
	for (i=0;i<count;i++) {
		if (res[i]->num_elements != 1) {
			DEBUG(1,("samdb: search for %s %s not single valued\n", 
				 attr_name, format));
			talloc_free(res);
			return -1;
		}
	}

	*strs = talloc_array(mem_ctx, const char *, count+1);
	if (! *strs) {
		talloc_free(res);
		return -1;
	}

	for (i=0;i<count;i++) {
		(*strs)[i] = ldb_msg_find_attr_as_string(res[i], attr_name, NULL);
	}
	(*strs)[count] = NULL;

	return count;
}

struct ldb_dn *samdb_result_dn(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, const struct ldb_message *msg,
			       const char *attr, struct ldb_dn *default_value)
{
	struct ldb_dn *ret_dn = ldb_msg_find_attr_as_dn(ldb, mem_ctx, msg, attr);
	if (!ret_dn) {
		return default_value;
	}
	return ret_dn;
}

/*
  pull a rid from a objectSid in a result set. 
*/
uint32_t samdb_result_rid_from_sid(TALLOC_CTX *mem_ctx, const struct ldb_message *msg, 
				   const char *attr, uint32_t default_value)
{
	struct dom_sid *sid;
	uint32_t rid;

	sid = samdb_result_dom_sid(mem_ctx, msg, attr);
	if (sid == NULL) {
		return default_value;
	}
	rid = sid->sub_auths[sid->num_auths-1];
	talloc_free(sid);
	return rid;
}

/*
  pull a dom_sid structure from a objectSid in a result set. 
*/
struct dom_sid *samdb_result_dom_sid(TALLOC_CTX *mem_ctx, const struct ldb_message *msg, 
				     const char *attr)
{
	ssize_t ret;
	const struct ldb_val *v;
	struct dom_sid *sid;
	v = ldb_msg_find_ldb_val(msg, attr);
	if (v == NULL) {
		return NULL;
	}
	sid = talloc(mem_ctx, struct dom_sid);
	if (sid == NULL) {
		return NULL;
	}
	ret = sid_parse(v->data, v->length, sid);
	if (ret == -1) {
		talloc_free(sid);
		return NULL;
	}
	return sid;
}

/*
  pull a guid structure from a objectGUID in a result set. 
*/
struct GUID samdb_result_guid(const struct ldb_message *msg, const char *attr)
{
	const struct ldb_val *v;
	struct GUID guid;
	NTSTATUS status;

	v = ldb_msg_find_ldb_val(msg, attr);
	if (!v) return GUID_zero();

	status = GUID_from_ndr_blob(v, &guid);
	if (!NT_STATUS_IS_OK(status)) {
		return GUID_zero();
	}

	return guid;
}

/*
  pull a sid prefix from a objectSid in a result set. 
  this is used to find the domain sid for a user
*/
struct dom_sid *samdb_result_sid_prefix(TALLOC_CTX *mem_ctx, const struct ldb_message *msg, 
					const char *attr)
{
	struct dom_sid *sid = samdb_result_dom_sid(mem_ctx, msg, attr);
	if (!sid || sid->num_auths < 1) return NULL;
	sid->num_auths--;
	return sid;
}

/*
  pull a NTTIME in a result set. 
*/
NTTIME samdb_result_nttime(const struct ldb_message *msg, const char *attr,
			   NTTIME default_value)
{
	return ldb_msg_find_attr_as_uint64(msg, attr, default_value);
}

/*
 * Windows stores 0 for lastLogoff.
 * But when a MS DC return the lastLogoff (as Logoff Time)
 * it returns 0x7FFFFFFFFFFFFFFF, not returning this value in this case
 * cause windows 2008 and newer version to fail for SMB requests
 */
NTTIME samdb_result_last_logoff(const struct ldb_message *msg)
{
	NTTIME ret = ldb_msg_find_attr_as_uint64(msg, "lastLogoff",0);

	if (ret == 0)
		ret = 0x7FFFFFFFFFFFFFFFULL;

	return ret;
}

/*
 * Windows uses both 0 and 9223372036854775807 (0x7FFFFFFFFFFFFFFFULL) to
 * indicate an account doesn't expire.
 *
 * When Windows initially creates an account, it sets
 * accountExpires = 9223372036854775807 (0x7FFFFFFFFFFFFFFF).  However,
 * when changing from an account having a specific expiration date to
 * that account never expiring, it sets accountExpires = 0.
 *
 * Consolidate that logic here to allow clearer logic for account expiry in
 * the rest of the code.
 */
NTTIME samdb_result_account_expires(const struct ldb_message *msg)
{
	NTTIME ret = ldb_msg_find_attr_as_uint64(msg, "accountExpires",
						 0);

	if (ret == 0)
		ret = 0x7FFFFFFFFFFFFFFFULL;

	return ret;
}

/*
  construct the allow_password_change field from the PwdLastSet attribute and the 
  domain password settings
*/
NTTIME samdb_result_allow_password_change(struct ldb_context *sam_ldb, 
					  TALLOC_CTX *mem_ctx, 
					  struct ldb_dn *domain_dn, 
					  struct ldb_message *msg, 
					  const char *attr)
{
	uint64_t attr_time = ldb_msg_find_attr_as_uint64(msg, attr, 0);
	int64_t minPwdAge;

	if (attr_time == 0) {
		return 0;
	}

	minPwdAge = samdb_search_int64(sam_ldb, mem_ctx, 0, domain_dn, "minPwdAge", NULL);

	/* yes, this is a -= not a += as minPwdAge is stored as the negative
	   of the number of 100-nano-seconds */
	attr_time -= minPwdAge;

	return attr_time;
}

/*
  pull a samr_Password structutre from a result set. 
*/
struct samr_Password *samdb_result_hash(TALLOC_CTX *mem_ctx, const struct ldb_message *msg, const char *attr)
{
	struct samr_Password *hash = NULL;
	const struct ldb_val *val = ldb_msg_find_ldb_val(msg, attr);
	if (val && (val->length >= sizeof(hash->hash))) {
		hash = talloc(mem_ctx, struct samr_Password);
		memcpy(hash->hash, val->data, MIN(val->length, sizeof(hash->hash)));
	}
	return hash;
}

/*
  pull an array of samr_Password structures from a result set.
*/
unsigned int samdb_result_hashes(TALLOC_CTX *mem_ctx, const struct ldb_message *msg,
			   const char *attr, struct samr_Password **hashes)
{
	unsigned int count, i;
	const struct ldb_val *val = ldb_msg_find_ldb_val(msg, attr);

	*hashes = NULL;
	if (!val) {
		return 0;
	}
	count = val->length / 16;
	if (count == 0) {
		return 0;
	}

	*hashes = talloc_array(mem_ctx, struct samr_Password, count);
	if (! *hashes) {
		return 0;
	}

	for (i=0;i<count;i++) {
		memcpy((*hashes)[i].hash, (i*16)+(char *)val->data, 16);
	}

	return count;
}

NTSTATUS samdb_result_passwords_from_history(TALLOC_CTX *mem_ctx,
					     struct loadparm_context *lp_ctx,
					     struct ldb_message *msg,
					     unsigned int idx,
					     struct samr_Password **lm_pwd,
					     struct samr_Password **nt_pwd)
{
	struct samr_Password *lmPwdHash, *ntPwdHash;

	if (nt_pwd) {
		unsigned int num_nt;
		num_nt = samdb_result_hashes(mem_ctx, msg, "ntPwdHistory", &ntPwdHash);
		if (num_nt <= idx) {
			*nt_pwd = NULL;
		} else {
			*nt_pwd = &ntPwdHash[idx];
		}
	}
	if (lm_pwd) {
		/* Ensure that if we have turned off LM
		 * authentication, that we never use the LM hash, even
		 * if we store it */
		if (lpcfg_lanman_auth(lp_ctx)) {
			unsigned int num_lm;
			num_lm = samdb_result_hashes(mem_ctx, msg, "lmPwdHistory", &lmPwdHash);
			if (num_lm <= idx) {
				*lm_pwd = NULL;
			} else {
				*lm_pwd = &lmPwdHash[idx];
			}
		} else {
			*lm_pwd = NULL;
		}
	}
	return NT_STATUS_OK;
}

NTSTATUS samdb_result_passwords_no_lockout(TALLOC_CTX *mem_ctx,
					   struct loadparm_context *lp_ctx,
					   const struct ldb_message *msg,
					   struct samr_Password **lm_pwd,
					   struct samr_Password **nt_pwd)
{
	struct samr_Password *lmPwdHash, *ntPwdHash;

	if (nt_pwd) {
		unsigned int num_nt;
		num_nt = samdb_result_hashes(mem_ctx, msg, "unicodePwd", &ntPwdHash);
		if (num_nt == 0) {
			*nt_pwd = NULL;
		} else if (num_nt > 1) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		} else {
			*nt_pwd = &ntPwdHash[0];
		}
	}
	if (lm_pwd) {
		/* Ensure that if we have turned off LM
		 * authentication, that we never use the LM hash, even
		 * if we store it */
		if (lpcfg_lanman_auth(lp_ctx)) {
			unsigned int num_lm;
			num_lm = samdb_result_hashes(mem_ctx, msg, "dBCSPwd", &lmPwdHash);
			if (num_lm == 0) {
				*lm_pwd = NULL;
			} else if (num_lm > 1) {
				return NT_STATUS_INTERNAL_DB_CORRUPTION;
			} else {
				*lm_pwd = &lmPwdHash[0];
			}
		} else {
			*lm_pwd = NULL;
		}
	}
	return NT_STATUS_OK;
}

NTSTATUS samdb_result_passwords(TALLOC_CTX *mem_ctx,
				struct loadparm_context *lp_ctx,
				const struct ldb_message *msg,
				struct samr_Password **lm_pwd,
				struct samr_Password **nt_pwd)
{
	uint16_t acct_flags;

	acct_flags = samdb_result_acct_flags(msg,
					     "msDS-User-Account-Control-Computed");
	/* Quit if the account was locked out. */
	if (acct_flags & ACB_AUTOLOCK) {
		DEBUG(3,("samdb_result_passwords: Account for user %s was locked out.\n",
			 ldb_dn_get_linearized(msg->dn)));
		return NT_STATUS_ACCOUNT_LOCKED_OUT;
	}

	return samdb_result_passwords_no_lockout(mem_ctx, lp_ctx, msg,
						 lm_pwd, nt_pwd);
}

/*
  pull a samr_LogonHours structutre from a result set. 
*/
struct samr_LogonHours samdb_result_logon_hours(TALLOC_CTX *mem_ctx, struct ldb_message *msg, const char *attr)
{
	struct samr_LogonHours hours;
	size_t units_per_week = 168;
	const struct ldb_val *val = ldb_msg_find_ldb_val(msg, attr);

	ZERO_STRUCT(hours);

	if (val) {
		units_per_week = val->length * 8;
	}

	hours.bits = talloc_array(mem_ctx, uint8_t, units_per_week/8);
	if (!hours.bits) {
		return hours;
	}
	hours.units_per_week = units_per_week;
	memset(hours.bits, 0xFF, units_per_week/8);
	if (val) {
		memcpy(hours.bits, val->data, val->length);
	}

	return hours;
}

/*
  pull a set of account_flags from a result set. 

  Naturally, this requires that userAccountControl and
  (if not null) the attributes 'attr' be already
  included in msg
*/
uint32_t samdb_result_acct_flags(const struct ldb_message *msg, const char *attr)
{
	uint32_t userAccountControl = ldb_msg_find_attr_as_uint(msg, "userAccountControl", 0);
	uint32_t attr_flags = 0;
	uint32_t acct_flags = ds_uf2acb(userAccountControl);
	if (attr) {
		attr_flags = ldb_msg_find_attr_as_uint(msg, attr, UF_ACCOUNTDISABLE);
		if (attr_flags == UF_ACCOUNTDISABLE) {
			DEBUG(0, ("Attribute %s not found, disabling account %s!\n", attr,
				  ldb_dn_get_linearized(msg->dn)));
		}
		acct_flags |= ds_uf2acb(attr_flags);
	}

	return acct_flags;
}

NTSTATUS samdb_result_parameters(TALLOC_CTX *mem_ctx,
				 struct ldb_message *msg,
				 const char *attr,
				 struct lsa_BinaryString *s)
{
	int i;
	const struct ldb_val *val = ldb_msg_find_ldb_val(msg, attr);

	ZERO_STRUCTP(s);

	if (!val) {
		return NT_STATUS_OK;
	}

	if ((val->length % 2) != 0) {
		/*
		 * If the on-disk data is not even in length, we know
		 * it is corrupt, and can not be safely pushed.  We
		 * would either truncate, send either a un-initilaised
		 * byte or send a forced zero byte
		 */
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	s->array = talloc_array(mem_ctx, uint16_t, val->length/2);
	if (!s->array) {
		return NT_STATUS_NO_MEMORY;
	}
	s->length = s->size = val->length;

	/* The on-disk format is the 'network' format, being UTF16LE (sort of) */
	for (i = 0; i < s->length / 2; i++) {
		s->array[i] = SVAL(val->data, i * 2);
	}

	return NT_STATUS_OK;
}

/* Find an attribute, with a particular value */

/* The current callers of this function expect a very specific
 * behaviour: In particular, objectClass subclass equivalence is not
 * wanted.  This means that we should not lookup the schema for the
 * comparison function */
struct ldb_message_element *samdb_find_attribute(struct ldb_context *ldb, 
						 const struct ldb_message *msg, 
						 const char *name, const char *value)
{
	unsigned int i;
	struct ldb_message_element *el = ldb_msg_find_element(msg, name);

	if (!el) {
		return NULL;
	}

	for (i=0;i<el->num_values;i++) {
		if (ldb_attr_cmp(value, (char *)el->values[i].data) == 0) {
			return el;
		}
	}

	return NULL;
}

static int samdb_find_or_add_attribute_ex(struct ldb_context *ldb,
					  struct ldb_message *msg,
					  const char *name,
					  const char *set_value,
					  unsigned attr_flags,
					  bool *added)
{
	int ret;
	struct ldb_message_element *el;

	SMB_ASSERT(attr_flags != 0);

       	el = ldb_msg_find_element(msg, name);
	if (el) {
		if (added != NULL) {
			*added = false;
		}

		return LDB_SUCCESS;
	}

	ret = ldb_msg_add_empty(msg, name,
				attr_flags,
				&el);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (set_value != NULL) {
		ret = ldb_msg_add_string(msg, name, set_value);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (added != NULL) {
		*added = true;
	}
	return LDB_SUCCESS;
}

int samdb_find_or_add_attribute(struct ldb_context *ldb, struct ldb_message *msg, const char *name, const char *set_value)
{
	return samdb_find_or_add_attribute_ex(ldb, msg, name, set_value, LDB_FLAG_MOD_ADD, NULL);
}

/*
  add a dom_sid element to a message
*/
int samdb_msg_add_dom_sid(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			  const char *attr_name, const struct dom_sid *sid)
{
	struct ldb_val v;
	enum ndr_err_code ndr_err;

	ndr_err = ndr_push_struct_blob(&v, mem_ctx, 
				       sid,
				       (ndr_push_flags_fn_t)ndr_push_dom_sid);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ldb_operr(sam_ldb);
	}
	return ldb_msg_add_value(msg, attr_name, &v, NULL);
}


/*
  add a delete element operation to a message
*/
int samdb_msg_add_delete(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			 const char *attr_name)
{
	/* we use an empty replace rather than a delete, as it allows for 
	   dsdb_replace() to be used everywhere */
	return ldb_msg_add_empty(msg, attr_name, LDB_FLAG_MOD_REPLACE, NULL);
}

/*
  add an add attribute value to a message or enhance an existing attribute
  which has the same name and the add flag set.
*/
int samdb_msg_add_addval(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx,
			 struct ldb_message *msg, const char *attr_name,
			 const char *value)
{
	struct ldb_message_element *el;
	struct ldb_val val, *vals;
	char *v;
	unsigned int i;
	bool found = false;
	int ret;

	v = talloc_strdup(mem_ctx, value);
	if (v == NULL) {
		return ldb_oom(sam_ldb);
	}

	val.data = (uint8_t *) v;
	val.length = strlen(v);

	if (val.length == 0) {
		/* allow empty strings as non-existent attributes */
		return LDB_SUCCESS;
	}

	for (i = 0; i < msg->num_elements; i++) {
		el = &msg->elements[i];
		if ((ldb_attr_cmp(el->name, attr_name) == 0) &&
		    (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_ADD)) {
			found = true;
			break;
		}
	}
	if (!found) {
		ret = ldb_msg_add_empty(msg, attr_name, LDB_FLAG_MOD_ADD,
					&el);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	vals = talloc_realloc(msg->elements, el->values, struct ldb_val,
			      el->num_values + 1);
	if (vals == NULL) {
		return ldb_oom(sam_ldb);
	}
	el->values = vals;
	el->values[el->num_values] = val;
	++(el->num_values);

	return LDB_SUCCESS;
}

/*
  add a delete attribute value to a message or enhance an existing attribute
  which has the same name and the delete flag set.
*/
int samdb_msg_add_delval(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx,
			 struct ldb_message *msg, const char *attr_name,
			 const char *value)
{
	struct ldb_message_element *el;
	struct ldb_val val, *vals;
	char *v;
	unsigned int i;
	bool found = false;
	int ret;

	v = talloc_strdup(mem_ctx, value);
	if (v == NULL) {
		return ldb_oom(sam_ldb);
	}

	val.data = (uint8_t *) v;
	val.length = strlen(v);

	if (val.length == 0) {
		/* allow empty strings as non-existent attributes */
		return LDB_SUCCESS;
	}

	for (i = 0; i < msg->num_elements; i++) {
		el = &msg->elements[i];
		if ((ldb_attr_cmp(el->name, attr_name) == 0) &&
		    (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_DELETE)) {
			found = true;
			break;
		}
	}
	if (!found) {
		ret = ldb_msg_add_empty(msg, attr_name, LDB_FLAG_MOD_DELETE,
					&el);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	vals = talloc_realloc(msg->elements, el->values, struct ldb_val,
			      el->num_values + 1);
	if (vals == NULL) {
		return ldb_oom(sam_ldb);
	}
	el->values = vals;
	el->values[el->num_values] = val;
	++(el->num_values);

	return LDB_SUCCESS;
}

/*
  add a int element to a message
*/
int samdb_msg_add_int(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
		       const char *attr_name, int v)
{
	const char *s = talloc_asprintf(mem_ctx, "%d", v);
	if (s == NULL) {
		return ldb_oom(sam_ldb);
	}
	return ldb_msg_add_string(msg, attr_name, s);
}

/*
 * Add an unsigned int element to a message
 *
 * The issue here is that we have not yet first cast to int32_t explicitly,
 * before we cast to an signed int to printf() into the %d or cast to a
 * int64_t before we then cast to a long long to printf into a %lld.
 *
 * There are *no* unsigned integers in Active Directory LDAP, even the RID
 * allocations and ms-DS-Secondary-KrbTgt-Number are *signed* quantities.
 * (See the schema, and the syntax definitions in schema_syntax.c).
 *
 */
int samdb_msg_add_uint(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
		       const char *attr_name, unsigned int v)
{
	return samdb_msg_add_int(sam_ldb, mem_ctx, msg, attr_name, (int)v);
}

/*
  add a (signed) int64_t element to a message
*/
int samdb_msg_add_int64(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			const char *attr_name, int64_t v)
{
	const char *s = talloc_asprintf(mem_ctx, "%lld", (long long)v);
	if (s == NULL) {
		return ldb_oom(sam_ldb);
	}
	return ldb_msg_add_string(msg, attr_name, s);
}

/*
 * Add an unsigned int64_t (uint64_t) element to a message
 *
 * The issue here is that we have not yet first cast to int32_t explicitly,
 * before we cast to an signed int to printf() into the %d or cast to a
 * int64_t before we then cast to a long long to printf into a %lld.
 *
 * There are *no* unsigned integers in Active Directory LDAP, even the RID
 * allocations and ms-DS-Secondary-KrbTgt-Number are *signed* quantities.
 * (See the schema, and the syntax definitions in schema_syntax.c).
 *
 */
int samdb_msg_add_uint64(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			const char *attr_name, uint64_t v)
{
	return samdb_msg_add_int64(sam_ldb, mem_ctx, msg, attr_name, (int64_t)v);
}

/*
  add a samr_Password element to a message
*/
int samdb_msg_add_hash(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
		       const char *attr_name, const struct samr_Password *hash)
{
	struct ldb_val val;
	val.data = talloc_memdup(mem_ctx, hash->hash, 16);
	if (!val.data) {
		return ldb_oom(sam_ldb);
	}
	val.length = 16;
	return ldb_msg_add_value(msg, attr_name, &val, NULL);
}

/*
  add a samr_Password array to a message
*/
int samdb_msg_add_hashes(struct ldb_context *ldb,
			 TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			 const char *attr_name, struct samr_Password *hashes,
			 unsigned int count)
{
	struct ldb_val val;
	unsigned int i;
	val.data = talloc_array_size(mem_ctx, 16, count);
	val.length = count*16;
	if (!val.data) {
		return ldb_oom(ldb);
	}
	for (i=0;i<count;i++) {
		memcpy(i*16 + (char *)val.data, hashes[i].hash, 16);
	}
	return ldb_msg_add_value(msg, attr_name, &val, NULL);
}

/*
  add a acct_flags element to a message
*/
int samdb_msg_add_acct_flags(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			     const char *attr_name, uint32_t v)
{
	return samdb_msg_add_uint(sam_ldb, mem_ctx, msg, attr_name, ds_acb2uf(v));
}

/*
  add a logon_hours element to a message
*/
int samdb_msg_add_logon_hours(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			      const char *attr_name, struct samr_LogonHours *hours)
{
	struct ldb_val val;
	val.length = hours->units_per_week / 8;
	val.data = hours->bits;
	return ldb_msg_add_value(msg, attr_name, &val, NULL);
}

/*
  add a parameters element to a message
*/
int samdb_msg_add_parameters(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			     const char *attr_name, struct lsa_BinaryString *parameters)
{
	int i;
	struct ldb_val val;
	if ((parameters->length % 2) != 0) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}

	val.data = talloc_array(mem_ctx, uint8_t, parameters->length);
	if (val.data == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	val.length = parameters->length;
	for (i = 0; i < parameters->length / 2; i++) {
		/*
		 * The on-disk format needs to be in the 'network'
		 * format, parmeters->array is a uint16_t array of
		 * length parameters->length / 2
		 */
		SSVAL(val.data, i * 2, parameters->array[i]);
	}
	return ldb_msg_add_steal_value(msg, attr_name, &val);
}

/*
 * Sets an unsigned int element in a message
 *
 * The issue here is that we have not yet first cast to int32_t explicitly,
 * before we cast to an signed int to printf() into the %d or cast to a
 * int64_t before we then cast to a long long to printf into a %lld.
 *
 * There are *no* unsigned integers in Active Directory LDAP, even the RID
 * allocations and ms-DS-Secondary-KrbTgt-Number are *signed* quantities.
 * (See the schema, and the syntax definitions in schema_syntax.c).
 *
 */
int samdb_msg_set_uint(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx,
		       struct ldb_message *msg, const char *attr_name,
		       unsigned int v)
{
	struct ldb_message_element *el;

	el = ldb_msg_find_element(msg, attr_name);
	if (el) {
		el->num_values = 0;
	}
	return samdb_msg_add_uint(sam_ldb, mem_ctx, msg, attr_name, v);
}

/*
 * Handle ldb_request in transaction
 */
int dsdb_autotransaction_request(struct ldb_context *sam_ldb,
				 struct ldb_request *req)
{
	int ret;

	ret = ldb_transaction_start(sam_ldb);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_request(sam_ldb, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	if (ret == LDB_SUCCESS) {
		return ldb_transaction_commit(sam_ldb);
	}
	ldb_transaction_cancel(sam_ldb);

	return ret;
}

/*
  return a default security descriptor
*/
struct security_descriptor *samdb_default_security_descriptor(TALLOC_CTX *mem_ctx)
{
	struct security_descriptor *sd;

	sd = security_descriptor_initialise(mem_ctx);

	return sd;
}

struct ldb_dn *samdb_aggregate_schema_dn(struct ldb_context *sam_ctx, TALLOC_CTX *mem_ctx) 
{
	struct ldb_dn *schema_dn = ldb_get_schema_basedn(sam_ctx);
	struct ldb_dn *aggregate_dn;
	if (!schema_dn) {
		return NULL;
	}

	aggregate_dn = ldb_dn_copy(mem_ctx, schema_dn);
	if (!aggregate_dn) {
		return NULL;
	}
	if (!ldb_dn_add_child_fmt(aggregate_dn, "CN=Aggregate")) {
		return NULL;
	}
	return aggregate_dn;
}

struct ldb_dn *samdb_partitions_dn(struct ldb_context *sam_ctx, TALLOC_CTX *mem_ctx)
{
	struct ldb_dn *new_dn;

	new_dn = ldb_dn_copy(mem_ctx, ldb_get_config_basedn(sam_ctx));
	if ( ! ldb_dn_add_child_fmt(new_dn, "CN=Partitions")) {
		talloc_free(new_dn);
		return NULL;
	}
	return new_dn;
}

struct ldb_dn *samdb_infrastructure_dn(struct ldb_context *sam_ctx, TALLOC_CTX *mem_ctx)
{
       struct ldb_dn *new_dn;

       new_dn = ldb_dn_copy(mem_ctx, ldb_get_default_basedn(sam_ctx));
       if ( ! ldb_dn_add_child_fmt(new_dn, "CN=Infrastructure")) {
               talloc_free(new_dn);
               return NULL;
       }
       return new_dn;
}

struct ldb_dn *samdb_sites_dn(struct ldb_context *sam_ctx, TALLOC_CTX *mem_ctx)
{
	struct ldb_dn *new_dn;

	new_dn = ldb_dn_copy(mem_ctx, ldb_get_config_basedn(sam_ctx));
	if ( ! ldb_dn_add_child_fmt(new_dn, "CN=Sites")) {
		talloc_free(new_dn);
		return NULL;
	}
	return new_dn;
}

struct ldb_dn *samdb_extended_rights_dn(struct ldb_context *sam_ctx, TALLOC_CTX *mem_ctx)
{
	struct ldb_dn *new_dn;

	new_dn = ldb_dn_copy(mem_ctx, ldb_get_config_basedn(sam_ctx));
	if ( ! ldb_dn_add_child_fmt(new_dn, "CN=Extended-Rights")) {
		talloc_free(new_dn);
		return NULL;
	}
	return new_dn;
}
/*
  work out the domain sid for the current open ldb
*/
const struct dom_sid *samdb_domain_sid(struct ldb_context *ldb)
{
	TALLOC_CTX *tmp_ctx;
	const struct dom_sid *domain_sid;
	const char *attrs[] = {
		"objectSid",
		NULL
	};
	struct ldb_result *res;
	int ret;

	/* see if we have a cached copy */
	domain_sid = (struct dom_sid *)ldb_get_opaque(ldb, "cache.domain_sid");
	if (domain_sid) {
		return domain_sid;
	}

	tmp_ctx = talloc_new(ldb);
	if (tmp_ctx == NULL) {
		goto failed;
	}

	ret = ldb_search(ldb, tmp_ctx, &res, ldb_get_default_basedn(ldb), LDB_SCOPE_BASE, attrs, "objectSid=*");

	if (ret != LDB_SUCCESS) {
		goto failed;
	}

	if (res->count != 1) {
		goto failed;
	}

	domain_sid = samdb_result_dom_sid(tmp_ctx, res->msgs[0], "objectSid");
	if (domain_sid == NULL) {
		goto failed;
	}

	/* cache the domain_sid in the ldb */
	if (ldb_set_opaque(ldb, "cache.domain_sid", discard_const_p(struct dom_sid, domain_sid)) != LDB_SUCCESS) {
		goto failed;
	}

	talloc_steal(ldb, domain_sid);
	talloc_free(tmp_ctx);

	return domain_sid;

failed:
	talloc_free(tmp_ctx);
	return NULL;
}

/*
  get domain sid from cache
*/
const struct dom_sid *samdb_domain_sid_cache_only(struct ldb_context *ldb)
{
	return (struct dom_sid *)ldb_get_opaque(ldb, "cache.domain_sid");
}

bool samdb_set_domain_sid(struct ldb_context *ldb, const struct dom_sid *dom_sid_in)
{
	TALLOC_CTX *tmp_ctx;
	struct dom_sid *dom_sid_new;
	struct dom_sid *dom_sid_old;

	/* see if we have a cached copy */
	dom_sid_old = talloc_get_type(ldb_get_opaque(ldb, 
						     "cache.domain_sid"), struct dom_sid);

	tmp_ctx = talloc_new(ldb);
	if (tmp_ctx == NULL) {
		goto failed;
	}

	dom_sid_new = dom_sid_dup(tmp_ctx, dom_sid_in);
	if (!dom_sid_new) {
		goto failed;
	}

	/* cache the domain_sid in the ldb */
	if (ldb_set_opaque(ldb, "cache.domain_sid", dom_sid_new) != LDB_SUCCESS) {
		goto failed;
	}

	talloc_steal(ldb, dom_sid_new);
	talloc_free(tmp_ctx);
	talloc_free(dom_sid_old);

	return true;

failed:
	DEBUG(1,("Failed to set our own cached domain SID in the ldb!\n"));
	talloc_free(tmp_ctx);
	return false;
}

/*
  work out the domain guid for the current open ldb
*/
const struct GUID *samdb_domain_guid(struct ldb_context *ldb)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct GUID *domain_guid = NULL;
	const char *attrs[] = {
		"objectGUID",
		NULL
	};
	struct ldb_result *res = NULL;
	int ret;

	/* see if we have a cached copy */
	domain_guid = (struct GUID *)ldb_get_opaque(ldb, "cache.domain_guid");
	if (domain_guid) {
		return domain_guid;
	}

	tmp_ctx = talloc_new(ldb);
	if (tmp_ctx == NULL) {
		goto failed;
	}

	ret = ldb_search(ldb, tmp_ctx, &res, ldb_get_default_basedn(ldb), LDB_SCOPE_BASE, attrs, "objectGUID=*");
	if (ret != LDB_SUCCESS) {
		goto failed;
	}

	if (res->count != 1) {
		goto failed;
	}

	domain_guid = talloc(tmp_ctx, struct GUID);
	if (domain_guid == NULL) {
		goto failed;
	}
	*domain_guid = samdb_result_guid(res->msgs[0], "objectGUID");

	/* cache the domain_sid in the ldb */
	if (ldb_set_opaque(ldb, "cache.domain_guid", domain_guid) != LDB_SUCCESS) {
		goto failed;
	}

	talloc_steal(ldb, domain_guid);
	talloc_free(tmp_ctx);

	return domain_guid;

failed:
	talloc_free(tmp_ctx);
	return NULL;
}

bool samdb_set_ntds_settings_dn(struct ldb_context *ldb, struct ldb_dn *ntds_settings_dn_in)
{
	TALLOC_CTX *tmp_ctx;
	struct ldb_dn *ntds_settings_dn_new;
	struct ldb_dn *ntds_settings_dn_old;

	/* see if we have a forced copy from provision */
	ntds_settings_dn_old = talloc_get_type(ldb_get_opaque(ldb, 
							      "forced.ntds_settings_dn"), struct ldb_dn);

	tmp_ctx = talloc_new(ldb);
	if (tmp_ctx == NULL) {
		goto failed;
	}

	ntds_settings_dn_new = ldb_dn_copy(tmp_ctx, ntds_settings_dn_in);
	if (!ntds_settings_dn_new) {
		goto failed;
	}

	/* set the DN in the ldb to avoid lookups during provision */
	if (ldb_set_opaque(ldb, "forced.ntds_settings_dn", ntds_settings_dn_new) != LDB_SUCCESS) {
		goto failed;
	}

	talloc_steal(ldb, ntds_settings_dn_new);
	talloc_free(tmp_ctx);
	talloc_free(ntds_settings_dn_old);

	return true;

failed:
	DEBUG(1,("Failed to set our NTDS Settings DN in the ldb!\n"));
	talloc_free(tmp_ctx);
	return false;
}

/*
  work out the ntds settings dn for the current open ldb
*/
struct ldb_dn *samdb_ntds_settings_dn(struct ldb_context *ldb, TALLOC_CTX *mem_ctx)
{
	TALLOC_CTX *tmp_ctx;
	const char *root_attrs[] = { "dsServiceName", NULL };
	int ret;
	struct ldb_result *root_res;
	struct ldb_dn *settings_dn;

	/* see if we have a cached copy */
	settings_dn = (struct ldb_dn *)ldb_get_opaque(ldb, "forced.ntds_settings_dn");
	if (settings_dn) {
		return ldb_dn_copy(mem_ctx, settings_dn);
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		goto failed;
	}

	ret = ldb_search(ldb, tmp_ctx, &root_res, ldb_dn_new(tmp_ctx, ldb, ""), LDB_SCOPE_BASE, root_attrs, NULL);
	if (ret != LDB_SUCCESS) {
		DEBUG(1,("Searching for dsServiceName in rootDSE failed: %s\n", 
			 ldb_errstring(ldb)));
		goto failed;
	}

	if (root_res->count != 1) {
		goto failed;
	}

	settings_dn = ldb_msg_find_attr_as_dn(ldb, tmp_ctx, root_res->msgs[0], "dsServiceName");

	/* note that we do not cache the DN here, as that would mean
	 * we could not handle server renames at runtime. Only
	 * provision sets up forced.ntds_settings_dn */

	talloc_steal(mem_ctx, settings_dn);
	talloc_free(tmp_ctx);

	return settings_dn;

failed:
	DEBUG(1,("Failed to find our own NTDS Settings DN in the ldb!\n"));
	talloc_free(tmp_ctx);
	return NULL;
}

/*
  work out the ntds settings invocationID/objectGUID for the current open ldb
*/
static const struct GUID *samdb_ntds_GUID(struct ldb_context *ldb,
					  const char *attribute,
					  const char *cache_name)
{
	TALLOC_CTX *tmp_ctx;
	const char *attrs[] = { attribute, NULL };
	int ret;
	struct ldb_result *res;
	struct GUID *ntds_guid;
	struct ldb_dn *ntds_settings_dn = NULL;
	const char *errstr = NULL;

	/* see if we have a cached copy */
	ntds_guid = (struct GUID *)ldb_get_opaque(ldb, cache_name);
	if (ntds_guid != NULL) {
		return ntds_guid;
	}

	tmp_ctx = talloc_new(ldb);
	if (tmp_ctx == NULL) {
		goto failed;
	}

	ntds_settings_dn = samdb_ntds_settings_dn(ldb, tmp_ctx);
	if (ntds_settings_dn == NULL) {
		errstr = "samdb_ntds_settings_dn() returned NULL";
		goto failed;
	}

	ret = ldb_search(ldb, tmp_ctx, &res, ntds_settings_dn,
			 LDB_SCOPE_BASE, attrs, NULL);
	if (ret) {
		errstr = ldb_errstring(ldb);
		goto failed;
	}

	if (res->count != 1) {
		errstr = "incorrect number of results from base search";
		goto failed;
	}

	ntds_guid = talloc(tmp_ctx, struct GUID);
	if (ntds_guid == NULL) {
		goto failed;
	}

	*ntds_guid = samdb_result_guid(res->msgs[0], attribute);

	if (GUID_all_zero(ntds_guid)) {
		if (ldb_msg_find_ldb_val(res->msgs[0], attribute)) {
			errstr = "failed to find the GUID attribute";
		} else {
			errstr = "failed to parse the GUID";
		}
		goto failed;
	}

	/* cache the domain_sid in the ldb */
	if (ldb_set_opaque(ldb, cache_name, ntds_guid) != LDB_SUCCESS) {
		errstr = "ldb_set_opaque() failed";
		goto failed;
	}

	talloc_steal(ldb, ntds_guid);
	talloc_free(tmp_ctx);

	return ntds_guid;

failed:
	DBG_WARNING("Failed to find our own NTDS Settings %s in the ldb: %s!\n",
		    attribute, errstr);
	talloc_free(tmp_ctx);
	return NULL;
}

/*
  work out the ntds settings objectGUID for the current open ldb
*/
const struct GUID *samdb_ntds_objectGUID(struct ldb_context *ldb)
{
	return samdb_ntds_GUID(ldb, "objectGUID", "cache.ntds_guid");
}

/*
  work out the ntds settings invocationId for the current open ldb
*/
const struct GUID *samdb_ntds_invocation_id(struct ldb_context *ldb)
{
	return samdb_ntds_GUID(ldb, "invocationId", "cache.invocation_id");
}

static bool samdb_set_ntds_GUID(struct ldb_context *ldb,
				const struct GUID *ntds_guid_in,
				const char *attribute,
				const char *cache_name)
{
	TALLOC_CTX *tmp_ctx;
	struct GUID *ntds_guid_new;
	struct GUID *ntds_guid_old;

	/* see if we have a cached copy */
	ntds_guid_old = (struct GUID *)ldb_get_opaque(ldb, cache_name);

	tmp_ctx = talloc_new(ldb);
	if (tmp_ctx == NULL) {
		goto failed;
	}

	ntds_guid_new = talloc(tmp_ctx, struct GUID);
	if (!ntds_guid_new) {
		goto failed;
	}

	*ntds_guid_new = *ntds_guid_in;

	/* cache the domain_sid in the ldb */
	if (ldb_set_opaque(ldb, cache_name, ntds_guid_new) != LDB_SUCCESS) {
		goto failed;
	}

	talloc_steal(ldb, ntds_guid_new);
	talloc_free(tmp_ctx);
	talloc_free(ntds_guid_old);

	return true;

failed:
	DBG_WARNING("Failed to set our own cached %s in the ldb!\n",
		    attribute);
	talloc_free(tmp_ctx);
	return false;
}

bool samdb_set_ntds_objectGUID(struct ldb_context *ldb, const struct GUID *ntds_guid_in)
{
	return samdb_set_ntds_GUID(ldb,
				   ntds_guid_in,
				   "objectGUID",
				   "cache.ntds_guid");
}

bool samdb_set_ntds_invocation_id(struct ldb_context *ldb, const struct GUID *invocation_id_in)
{
	return samdb_set_ntds_GUID(ldb,
				   invocation_id_in,
				   "invocationId",
				   "cache.invocation_id");
}

/*
  work out the server dn for the current open ldb
*/
struct ldb_dn *samdb_server_dn(struct ldb_context *ldb, TALLOC_CTX *mem_ctx)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct ldb_dn *dn;
	if (!tmp_ctx) {
		return NULL;
	}
	dn = ldb_dn_get_parent(mem_ctx, samdb_ntds_settings_dn(ldb, tmp_ctx));
	talloc_free(tmp_ctx);
	return dn;
	
}

/*
  work out the server dn for the current open ldb
*/
struct ldb_dn *samdb_server_site_dn(struct ldb_context *ldb, TALLOC_CTX *mem_ctx)
{
	struct ldb_dn *server_dn;
	struct ldb_dn *servers_dn;
	struct ldb_dn *server_site_dn;

	/* TODO: there must be a saner way to do this!! */
	server_dn = samdb_server_dn(ldb, mem_ctx);
	if (!server_dn) return NULL;

	servers_dn = ldb_dn_get_parent(mem_ctx, server_dn);
	talloc_free(server_dn);
	if (!servers_dn) return NULL;

	server_site_dn = ldb_dn_get_parent(mem_ctx, servers_dn);
	talloc_free(servers_dn);

	return server_site_dn;
}

/*
  find the site name from a computers DN record
 */
int samdb_find_site_for_computer(struct ldb_context *ldb,
				 TALLOC_CTX *mem_ctx, struct ldb_dn *computer_dn,
				 const char **site_name)
{
	int ret;
	struct ldb_dn *dn;
	const struct ldb_val *rdn_val;

	*site_name = NULL;

	ret = samdb_reference_dn(ldb, mem_ctx, computer_dn, "serverReferenceBL", &dn);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (!ldb_dn_remove_child_components(dn, 2)) {
		talloc_free(dn);
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	rdn_val = ldb_dn_get_rdn_val(dn);
	if (rdn_val == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	(*site_name) = talloc_strndup(mem_ctx, (const char *)rdn_val->data, rdn_val->length);
	talloc_free(dn);
	if (!*site_name) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	return LDB_SUCCESS;
}

/*
  find the NTDS GUID from a computers DN record
 */
int samdb_find_ntdsguid_for_computer(struct ldb_context *ldb, struct ldb_dn *computer_dn,
				     struct GUID *ntds_guid)
{
	int ret;
	struct ldb_dn *dn;

	*ntds_guid = GUID_zero();

	ret = samdb_reference_dn(ldb, ldb, computer_dn, "serverReferenceBL", &dn);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (!ldb_dn_add_child_fmt(dn, "CN=NTDS Settings")) {
		talloc_free(dn);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = dsdb_find_guid_by_dn(ldb, dn, ntds_guid);
	talloc_free(dn);
	return ret;
}

/*
  find a 'reference' DN that points at another object
  (eg. serverReference, rIDManagerReference etc)
 */
int samdb_reference_dn(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, struct ldb_dn *base,
		       const char *attribute, struct ldb_dn **dn)
{
	const char *attrs[2];
	struct ldb_result *res;
	int ret;

	attrs[0] = attribute;
	attrs[1] = NULL;

	ret = dsdb_search(ldb, mem_ctx, &res, base, LDB_SCOPE_BASE, attrs, DSDB_SEARCH_ONE_ONLY|DSDB_SEARCH_SHOW_EXTENDED_DN, NULL);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Cannot find DN %s to get attribute %s for reference dn: %s",
				       ldb_dn_get_linearized(base), attribute, ldb_errstring(ldb));
		return ret;
	}

	*dn = ldb_msg_find_attr_as_dn(ldb, mem_ctx, res->msgs[0], attribute);
	if (!*dn) {
		if (!ldb_msg_find_element(res->msgs[0], attribute)) {
			ldb_asprintf_errstring(ldb, "Cannot find attribute %s of %s to calculate reference dn", attribute,
					       ldb_dn_get_linearized(base));
		} else {
			ldb_asprintf_errstring(ldb, "Cannot interpret attribute %s of %s as a dn", attribute,
					       ldb_dn_get_linearized(base));
		}
		talloc_free(res);
		return LDB_ERR_NO_SUCH_ATTRIBUTE;
	}

	talloc_free(res);
	return LDB_SUCCESS;
}

/*
  find if a DN (must have GUID component!) is our ntdsDsa
 */
int samdb_dn_is_our_ntdsa(struct ldb_context *ldb, struct ldb_dn *dn, bool *is_ntdsa)
{
	NTSTATUS status;
	struct GUID dn_guid;
	const struct GUID *our_ntds_guid;
	status = dsdb_get_extended_dn_guid(dn, &dn_guid, "GUID");
	if (!NT_STATUS_IS_OK(status)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	our_ntds_guid = samdb_ntds_objectGUID(ldb);
	if (!our_ntds_guid) {
		DEBUG(0, ("Failed to find our NTDS Settings GUID for comparison with %s - %s\n", ldb_dn_get_linearized(dn), ldb_errstring(ldb)));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*is_ntdsa = GUID_equal(&dn_guid, our_ntds_guid);
	return LDB_SUCCESS;
}

/*
  find a 'reference' DN that points at another object and indicate if it is our ntdsDsa
 */
int samdb_reference_dn_is_our_ntdsa(struct ldb_context *ldb, struct ldb_dn *base,
				    const char *attribute, bool *is_ntdsa)
{
	int ret;
	struct ldb_dn *referenced_dn;
	TALLOC_CTX *tmp_ctx = talloc_new(ldb);
	if (tmp_ctx == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = samdb_reference_dn(ldb, tmp_ctx, base, attribute, &referenced_dn);
	if (ret != LDB_SUCCESS) {
		DEBUG(0, ("Failed to find object %s for attribute %s - %s\n", ldb_dn_get_linearized(base), attribute, ldb_errstring(ldb)));
		return ret;
	}

	ret = samdb_dn_is_our_ntdsa(ldb, referenced_dn, is_ntdsa);
	
	talloc_free(tmp_ctx);
	return ret;
}

/*
  find our machine account via the serverReference attribute in the
  server DN
 */
int samdb_server_reference_dn(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, struct ldb_dn **dn)
{
	struct ldb_dn *server_dn;
	int ret;

	server_dn = samdb_server_dn(ldb, mem_ctx);
	if (server_dn == NULL) {
		return ldb_error(ldb, LDB_ERR_NO_SUCH_OBJECT, __func__);
	}

	ret = samdb_reference_dn(ldb, mem_ctx, server_dn, "serverReference", dn);
	talloc_free(server_dn);

	return ret;
}

/*
  find the RID Manager$ DN via the rIDManagerReference attribute in the
  base DN
 */
int samdb_rid_manager_dn(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, struct ldb_dn **dn)
{
	return samdb_reference_dn(ldb, mem_ctx, ldb_get_default_basedn(ldb),
				  "rIDManagerReference", dn);
}

/*
  find the RID Set DN via the rIDSetReferences attribute in our
  machine account DN
 */
int samdb_rid_set_dn(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, struct ldb_dn **dn)
{
	struct ldb_dn *server_ref_dn = NULL;
	int ret;

	ret = samdb_server_reference_dn(ldb, mem_ctx, &server_ref_dn);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	ret = samdb_reference_dn(ldb, mem_ctx, server_ref_dn, "rIDSetReferences", dn);
	talloc_free(server_ref_dn);
	return ret;
}

const char *samdb_server_site_name(struct ldb_context *ldb, TALLOC_CTX *mem_ctx)
{
	const struct ldb_val *val = ldb_dn_get_rdn_val(samdb_server_site_dn(ldb,
									    mem_ctx));

	if (val == NULL) {
		return NULL;
	}

	return (const char *) val->data;
}

/*
 * Finds the client site by using the client's IP address.
 * The "subnet_name" returns the name of the subnet if parameter != NULL
 *
 * Has a Windows-based fallback to provide the only site available, or an empty
 * string if there are multiple sites.
 */
const char *samdb_client_site_name(struct ldb_context *ldb, TALLOC_CTX *mem_ctx,
				   const char *ip_address, char **subnet_name,
				   bool fallback)
{
	const char *attrs[] = { "cn", "siteObject", NULL };
	struct ldb_dn *sites_container_dn = NULL;
	struct ldb_dn *subnets_dn = NULL;
	struct ldb_dn *sites_dn = NULL;
	struct ldb_result *res = NULL;
	const struct ldb_val *val = NULL;
	const char *site_name = NULL;
	const char *l_subnet_name = NULL;
	const char *allow_list[2] = { NULL, NULL };
	unsigned int i, count;
	int ret;

	/*
	 * if we don't have a client ip e.g. ncalrpc
	 * the server site is the client site
	 */
	if (ip_address == NULL) {
		return samdb_server_site_name(ldb, mem_ctx);
	}

	sites_container_dn = samdb_sites_dn(ldb, mem_ctx);
	if (sites_container_dn == NULL) {
		goto exit;
	}

	subnets_dn = ldb_dn_copy(mem_ctx, sites_container_dn);
	if ( ! ldb_dn_add_child_fmt(subnets_dn, "CN=Subnets")) {
		goto exit;
	}

	ret = ldb_search(ldb, mem_ctx, &res, subnets_dn, LDB_SCOPE_ONELEVEL,
			 attrs, NULL);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		count = 0;
	} else if (ret != LDB_SUCCESS) {
		goto exit;
	} else {
		count = res->count;
	}

	for (i = 0; i < count; i++) {
		l_subnet_name = ldb_msg_find_attr_as_string(res->msgs[i], "cn",
							    NULL);

		allow_list[0] = l_subnet_name;

		if (allow_access_nolog(NULL, allow_list, "", ip_address)) {
			sites_dn = ldb_msg_find_attr_as_dn(ldb, mem_ctx,
							   res->msgs[i],
							   "siteObject");
			if (sites_dn == NULL) {
				/* No reference, maybe another subnet matches */
				continue;
			}

			/* "val" cannot be NULL here since "sites_dn" != NULL */
			val = ldb_dn_get_rdn_val(sites_dn);
			site_name = talloc_strdup(mem_ctx,
						  (const char *) val->data);

			TALLOC_FREE(sites_dn);

			break;
		}
	}

	if (site_name == NULL && fallback) {
		/* This is the Windows Server fallback rule: when no subnet
		 * exists and we have only one site available then use it (it
		 * is for sure the same as our server site). If more sites do
		 * exist then we don't know which one to use and set the site
		 * name to "". */
		size_t cnt = 0;
		ret = dsdb_domain_count(
			ldb,
			&cnt,
			sites_container_dn,
			NULL,
			LDB_SCOPE_SUBTREE,
			"(objectClass=site)");
		if (ret != LDB_SUCCESS) {
			goto exit;
		}
		if (cnt == 1) {
			site_name = samdb_server_site_name(ldb, mem_ctx);
		} else {
			site_name = talloc_strdup(mem_ctx, "");
		}
		l_subnet_name = NULL;
	}

	if (subnet_name != NULL) {
		*subnet_name = talloc_strdup(mem_ctx, l_subnet_name);
	}

exit:
	TALLOC_FREE(sites_container_dn);
	TALLOC_FREE(subnets_dn);
	TALLOC_FREE(res);

	return site_name;
}

/*
  work out if we are the PDC for the domain of the current open ldb
*/
bool samdb_is_pdc(struct ldb_context *ldb)
{
	int ret;
	bool is_pdc;

	ret = samdb_reference_dn_is_our_ntdsa(ldb, ldb_get_default_basedn(ldb), "fsmoRoleOwner", 
					      &is_pdc);
	if (ret != LDB_SUCCESS) {
		DEBUG(1,("Failed to find if we are the PDC for this ldb: Searching for fSMORoleOwner in %s failed: %s\n", 
			 ldb_dn_get_linearized(ldb_get_default_basedn(ldb)), 
			 ldb_errstring(ldb)));
		return false;
	}

	return is_pdc;
}

/*
  work out if we are a Global Catalog server for the domain of the current open ldb
*/
bool samdb_is_gc(struct ldb_context *ldb)
{
	uint32_t options = 0;
	if (samdb_ntds_options(ldb, &options) != LDB_SUCCESS) {
		return false;
	}
	return (options & DS_NTDSDSA_OPT_IS_GC) != 0;
}

/* Find a domain object in the parents of a particular DN.  */
int samdb_search_for_parent_domain(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, struct ldb_dn *dn,
				   struct ldb_dn **parent_dn, const char **errstring)
{
	TALLOC_CTX *local_ctx;
	struct ldb_dn *sdn = dn;
	struct ldb_result *res = NULL;
	int ret = LDB_SUCCESS;
	const char *attrs[] = { NULL };

	local_ctx = talloc_new(mem_ctx);
	if (local_ctx == NULL) return ldb_oom(ldb);

	while ((sdn = ldb_dn_get_parent(local_ctx, sdn))) {
		ret = ldb_search(ldb, local_ctx, &res, sdn, LDB_SCOPE_BASE, attrs,
				 "(|(objectClass=domain)(objectClass=builtinDomain))");
		if (ret == LDB_SUCCESS) {
			if (res->count == 1) {
				break;
			}
		} else {
			break;
		}
	}

	if (ret != LDB_SUCCESS) {
		*errstring = talloc_asprintf(mem_ctx, "Error searching for parent domain of %s, failed searching for %s: %s",
					     ldb_dn_get_linearized(dn),
					     ldb_dn_get_linearized(sdn),
					     ldb_errstring(ldb));
		talloc_free(local_ctx);
		return ret;
	}
	/* should never be true with 'ret=LDB_SUCCESS', here to satisfy clang */
	if (res == NULL) {
		talloc_free(local_ctx);
		return LDB_ERR_OTHER;
	}
	if (res->count != 1) {
		*errstring = talloc_asprintf(mem_ctx, "Invalid dn (%s), not child of a domain object",
					     ldb_dn_get_linearized(dn));
		DEBUG(0,(__location__ ": %s\n", *errstring));
		talloc_free(local_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	*parent_dn = talloc_steal(mem_ctx, res->msgs[0]->dn);
	talloc_free(local_ctx);
	return ret;
}

static void pwd_timeout_debug(struct tevent_context *unused1,
			      struct tevent_timer *unused2,
			      struct timeval unused3,
			      void *unused4)
{
	DEBUG(0, ("WARNING: check_password_complexity: password script "
		  "took more than 1 second to run\n"));
}


/*
 * Performs checks on a user password (plaintext UNIX format - attribute
 * "password"). The remaining parameters have to be extracted from the domain
 * object in the AD.
 *
 * Result codes from "enum samr_ValidationStatus" (consider "samr.idl")
 */
enum samr_ValidationStatus samdb_check_password(TALLOC_CTX *mem_ctx,
						struct loadparm_context *lp_ctx,
						const char *account_name,
						const char *user_principal_name,
						const char *full_name,
						const DATA_BLOB *utf8_blob,
						const uint32_t pwdProperties,
						const uint32_t minPwdLength)
{
	const struct loadparm_substitution *lp_sub =
		lpcfg_noop_substitution();
	char *password_script = NULL;
	const char *utf8_pw = (const char *)utf8_blob->data;

	/*
	 * This looks strange because it is.
	 *
	 * The check for the number of characters in the password
	 * should clearly not be against the byte length, or else a
	 * single UTF8 character would count for more than one.
	 *
	 * We have chosen to use the number of 16-bit units that the
	 * password encodes to as the measure of length.  This is not
	 * the same as the number of codepoints, if a password
	 * contains a character beyond the Basic Multilingual Plane
	 * (above 65535) it will count for more than one "character".
	 */

	size_t password_characters_roughly = strlen_m(utf8_pw);

	/* checks if the "minPwdLength" property is satisfied */
	if (minPwdLength > password_characters_roughly) {
		return SAMR_VALIDATION_STATUS_PWD_TOO_SHORT;
	}

	/* We might not be asked to check the password complexity */
	if (!(pwdProperties & DOMAIN_PASSWORD_COMPLEX)) {
		return SAMR_VALIDATION_STATUS_SUCCESS;
	}

	if (password_characters_roughly == 0) {
		return SAMR_VALIDATION_STATUS_NOT_COMPLEX_ENOUGH;
	}

	password_script = lpcfg_check_password_script(lp_ctx, lp_sub, mem_ctx);
	if (password_script != NULL && *password_script != '\0') {
		int check_ret = 0;
		int error = 0;
		ssize_t nwritten = 0;
		struct tevent_context *event_ctx = NULL;
		struct tevent_req *req = NULL;
		int cps_stdin = -1;
		const char * const cmd[4] = {
			"/bin/sh", "-c",
			password_script,
			NULL
		};

		event_ctx = tevent_context_init(mem_ctx);
		if (event_ctx == NULL) {
			TALLOC_FREE(password_script);
			return SAMR_VALIDATION_STATUS_PASSWORD_FILTER_ERROR;
		}

		/* Gives a warning after 1 second, terminates after 10 */
		tevent_add_timer(event_ctx, event_ctx,
				 tevent_timeval_current_ofs(1, 0),
				 pwd_timeout_debug, NULL);

		check_ret = setenv("SAMBA_CPS_ACCOUNT_NAME", account_name, 1);
		if (check_ret != 0) {
			TALLOC_FREE(password_script);
			TALLOC_FREE(event_ctx);
			return SAMR_VALIDATION_STATUS_PASSWORD_FILTER_ERROR;
		}
		if (user_principal_name != NULL) {
			check_ret = setenv("SAMBA_CPS_USER_PRINCIPAL_NAME",
					   user_principal_name, 1);
		} else {
			unsetenv("SAMBA_CPS_USER_PRINCIPAL_NAME");
		}
		if (check_ret != 0) {
			TALLOC_FREE(password_script);
			TALLOC_FREE(event_ctx);
			return SAMR_VALIDATION_STATUS_PASSWORD_FILTER_ERROR;
		}
		if (full_name != NULL) {
			check_ret = setenv("SAMBA_CPS_FULL_NAME", full_name, 1);
		} else {
			unsetenv("SAMBA_CPS_FULL_NAME");
		}
		if (check_ret != 0) {
			TALLOC_FREE(password_script);
			TALLOC_FREE(event_ctx);
			return SAMR_VALIDATION_STATUS_PASSWORD_FILTER_ERROR;
		}

		req = samba_runcmd_send(event_ctx, event_ctx,
					tevent_timeval_current_ofs(10, 0),
					100, 100, cmd, NULL);
		unsetenv("SAMBA_CPS_ACCOUNT_NAME");
		unsetenv("SAMBA_CPS_USER_PRINCIPAL_NAME");
		unsetenv("SAMBA_CPS_FULL_NAME");
		if (req == NULL) {
			TALLOC_FREE(password_script);
			TALLOC_FREE(event_ctx);
			return SAMR_VALIDATION_STATUS_PASSWORD_FILTER_ERROR;
		}

		cps_stdin = samba_runcmd_export_stdin(req);

		nwritten = write_data(
			cps_stdin, utf8_blob->data, utf8_blob->length);
		if (nwritten == -1) {
			close(cps_stdin);
			TALLOC_FREE(password_script);
			TALLOC_FREE(event_ctx);
			return SAMR_VALIDATION_STATUS_PASSWORD_FILTER_ERROR;
		}

		close(cps_stdin);

		if (!tevent_req_poll(req, event_ctx)) {
			TALLOC_FREE(password_script);
			TALLOC_FREE(event_ctx);
			return SAMR_VALIDATION_STATUS_PASSWORD_FILTER_ERROR;
		}

		check_ret = samba_runcmd_recv(req, &error);
		TALLOC_FREE(event_ctx);

		if (error == ETIMEDOUT) {
			DEBUG(0, ("check_password_complexity: check password script took too long!\n"));
			TALLOC_FREE(password_script);
			return SAMR_VALIDATION_STATUS_PASSWORD_FILTER_ERROR;
		}
		DEBUG(5,("check_password_complexity: check password script (%s) "
			 "returned [%d]\n", password_script, check_ret));

		if (check_ret != 0) {
			DEBUG(1,("check_password_complexity: "
				 "check password script said new password is not good "
				 "enough!\n"));
			TALLOC_FREE(password_script);
			return SAMR_VALIDATION_STATUS_NOT_COMPLEX_ENOUGH;
		}

		TALLOC_FREE(password_script);
		return SAMR_VALIDATION_STATUS_SUCCESS;
	}

	TALLOC_FREE(password_script);

	/*
	 * Here are the standard AD password quality rules, which we
	 * run after the script.
	 */

	if (!check_password_quality(utf8_pw)) {
		return SAMR_VALIDATION_STATUS_NOT_COMPLEX_ENOUGH;
	}

	return SAMR_VALIDATION_STATUS_SUCCESS;
}

/*
 * Callback for "samdb_set_password" password change
 */
int samdb_set_password_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	int ret;

	if (!ares) {
		return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
	}

	if (ares->error != LDB_SUCCESS) {
		ret = ares->error;
		req->context = talloc_steal(req,
					    ldb_reply_get_control(ares, DSDB_CONTROL_PASSWORD_CHANGE_STATUS_OID));
		talloc_free(ares);
		return ldb_request_done(req, ret);
	}

	if (ares->type != LDB_REPLY_DONE) {
		talloc_free(ares);
		return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
	}

	req->context = talloc_steal(req,
				    ldb_reply_get_control(ares, DSDB_CONTROL_PASSWORD_CHANGE_STATUS_OID));
	talloc_free(ares);
	return ldb_request_done(req, LDB_SUCCESS);
}

/*
 * Sets the user password using plaintext UTF16 (attribute "new_password") or
 * LM (attribute "lmNewHash") or NT (attribute "ntNewHash") hash. Also pass
 * the old LM and/or NT hash (attributes "lmOldHash"/"ntOldHash") if it is a
 * user change or not. The "rejectReason" gives some more information if the
 * change failed.
 *
 * Results: NT_STATUS_OK, NT_STATUS_INVALID_PARAMETER, NT_STATUS_UNSUCCESSFUL,
 *   NT_STATUS_WRONG_PASSWORD, NT_STATUS_PASSWORD_RESTRICTION
 */
static NTSTATUS samdb_set_password_internal(struct ldb_context *ldb, TALLOC_CTX *mem_ctx,
			    struct ldb_dn *user_dn, struct ldb_dn *domain_dn,
			    const DATA_BLOB *new_password,
			    const struct samr_Password *lmNewHash,
			    const struct samr_Password *ntNewHash,
			    const struct samr_Password *lmOldHash,
			    const struct samr_Password *ntOldHash,
			    enum samPwdChangeReason *reject_reason,
			    struct samr_DomInfo1 **_dominfo,
			    bool permit_interdomain_trust)
{
	struct ldb_message *msg;
	struct ldb_message_element *el;
	struct ldb_request *req;
	struct dsdb_control_password_change_status *pwd_stat = NULL;
	int ret;
	bool hash_values = false;
	NTSTATUS status = NT_STATUS_OK;

#define CHECK_RET(x) \
	if (x != LDB_SUCCESS) { \
		talloc_free(msg); \
		return NT_STATUS_NO_MEMORY; \
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	msg->dn = user_dn;
	if ((new_password != NULL)
			&& ((lmNewHash == NULL) && (ntNewHash == NULL))) {
		/* we have the password as plaintext UTF16 */
		CHECK_RET(ldb_msg_add_value(msg, "clearTextPassword",
					    new_password, NULL));
		el = ldb_msg_find_element(msg, "clearTextPassword");
		el->flags = LDB_FLAG_MOD_REPLACE;
	} else if ((new_password == NULL)
			&& ((lmNewHash != NULL) || (ntNewHash != NULL))) {
		/* we have a password as LM and/or NT hash */
		if (lmNewHash != NULL) {
			CHECK_RET(samdb_msg_add_hash(ldb, mem_ctx, msg,
				"dBCSPwd", lmNewHash));
			el = ldb_msg_find_element(msg, "dBCSPwd");
			el->flags = LDB_FLAG_MOD_REPLACE;
		}
		if (ntNewHash != NULL) {
			CHECK_RET(samdb_msg_add_hash(ldb, mem_ctx, msg,
				"unicodePwd", ntNewHash));
			el = ldb_msg_find_element(msg, "unicodePwd");
			el->flags = LDB_FLAG_MOD_REPLACE;
		}
		hash_values = true;
	} else {
		/* the password wasn't specified correctly */
		talloc_free(msg);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* build modify request */
	ret = ldb_build_mod_req(&req, ldb, mem_ctx, msg, NULL, NULL,
				samdb_set_password_callback, NULL);
        if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
        }

	/* A password change operation */
	if ((ntOldHash != NULL) || (lmOldHash != NULL)) {
		struct dsdb_control_password_change *change;

		change = talloc(req, struct dsdb_control_password_change);
		if (change == NULL) {
			talloc_free(req);
			talloc_free(msg);
			return NT_STATUS_NO_MEMORY;
		}

		change->old_nt_pwd_hash = ntOldHash;
		change->old_lm_pwd_hash = lmOldHash;

		ret = ldb_request_add_control(req,
					      DSDB_CONTROL_PASSWORD_CHANGE_OID,
					      true, change);
		if (ret != LDB_SUCCESS) {
			talloc_free(req);
			talloc_free(msg);
			return NT_STATUS_NO_MEMORY;
		}
	}
	if (hash_values) {
		ret = ldb_request_add_control(req,
					      DSDB_CONTROL_PASSWORD_HASH_VALUES_OID,
					      true, NULL);
		if (ret != LDB_SUCCESS) {
			talloc_free(req);
			talloc_free(msg);
			return NT_STATUS_NO_MEMORY;
		}
	}
	if (permit_interdomain_trust) {
		ret = ldb_request_add_control(req,
					      DSDB_CONTROL_PERMIT_INTERDOMAIN_TRUST_UAC_OID,
					      false, NULL);
		if (ret != LDB_SUCCESS) {
			talloc_free(req);
			talloc_free(msg);
			return NT_STATUS_NO_MEMORY;
		}
	}
	ret = ldb_request_add_control(req,
				      DSDB_CONTROL_PASSWORD_CHANGE_STATUS_OID,
				      true, NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(req);
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dsdb_autotransaction_request(ldb, req);

	if (req->context != NULL) {
		struct ldb_control *control = talloc_get_type_abort(req->context,
								    struct ldb_control);
		pwd_stat = talloc_get_type_abort(control->data,
						 struct dsdb_control_password_change_status);
		talloc_steal(mem_ctx, pwd_stat);
	}

	talloc_free(req);
	talloc_free(msg);

	/* Sets the domain info (if requested) */
	if (_dominfo != NULL) {
		struct samr_DomInfo1 *dominfo;

		dominfo = talloc_zero(mem_ctx, struct samr_DomInfo1);
		if (dominfo == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		if (pwd_stat != NULL) {
			dominfo->min_password_length     = pwd_stat->domain_data.minPwdLength;
			dominfo->password_properties     = pwd_stat->domain_data.pwdProperties;
			dominfo->password_history_length = pwd_stat->domain_data.pwdHistoryLength;
			dominfo->max_password_age        = pwd_stat->domain_data.maxPwdAge;
			dominfo->min_password_age        = pwd_stat->domain_data.minPwdAge;
		}

		*_dominfo = dominfo;
	}

	if (reject_reason != NULL) {
		if (pwd_stat != NULL) {
			*reject_reason = pwd_stat->reject_reason;
		} else {
			*reject_reason = SAM_PWD_CHANGE_NO_ERROR;
		}
	}

	if (pwd_stat != NULL) {
		talloc_free(pwd_stat);
	}

	if (ret == LDB_ERR_CONSTRAINT_VIOLATION) {
		const char *errmsg = ldb_errstring(ldb);
		char *endptr = NULL;
		WERROR werr = WERR_GEN_FAILURE;
		status = NT_STATUS_UNSUCCESSFUL;
		if (errmsg != NULL) {
			werr = W_ERROR(strtol(errmsg, &endptr, 16));
			DBG_WARNING("%s\n", errmsg);
		}
		if (endptr != errmsg) {
			if (W_ERROR_EQUAL(werr, WERR_INVALID_PASSWORD)) {
				status = NT_STATUS_WRONG_PASSWORD;
			}
			if (W_ERROR_EQUAL(werr, WERR_PASSWORD_RESTRICTION)) {
				status = NT_STATUS_PASSWORD_RESTRICTION;
			}
		}
	} else if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		/* don't let the caller know if an account doesn't exist */
		status = NT_STATUS_WRONG_PASSWORD;
	} else if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
		status = NT_STATUS_ACCESS_DENIED;
	} else if (ret != LDB_SUCCESS) {
		DEBUG(1, ("Failed to set password on %s: %s\n",
			  ldb_dn_get_linearized(user_dn),
			  ldb_errstring(ldb)));
		status = NT_STATUS_UNSUCCESSFUL;
	}

	return status;
}

NTSTATUS samdb_set_password(struct ldb_context *ldb, TALLOC_CTX *mem_ctx,
			    struct ldb_dn *user_dn, struct ldb_dn *domain_dn,
			    const DATA_BLOB *new_password,
			    const struct samr_Password *lmNewHash,
			    const struct samr_Password *ntNewHash,
			    const struct samr_Password *lmOldHash,
			    const struct samr_Password *ntOldHash,
			    enum samPwdChangeReason *reject_reason,
			    struct samr_DomInfo1 **_dominfo)
{
	return samdb_set_password_internal(ldb, mem_ctx,
			    user_dn, domain_dn,
			    new_password,
			    lmNewHash, ntNewHash,
			    lmOldHash, ntOldHash,
			    reject_reason, _dominfo,
			    false); /* reject trusts */
}

/*
 * Sets the user password using plaintext UTF16 (attribute "new_password") or
 * LM (attribute "lmNewHash") or NT (attribute "ntNewHash") hash. Also pass
 * the old LM and/or NT hash (attributes "lmOldHash"/"ntOldHash") if it is a
 * user change or not. The "rejectReason" gives some more information if the
 * change failed.
 *
 * This wrapper function for "samdb_set_password" takes a SID as input rather
 * than a user DN.
 *
 * This call encapsulates a new LDB transaction for changing the password;
 * therefore the user hasn't to start a new one.
 *
 * Results: NT_STATUS_OK, NT_STATUS_INTERNAL_DB_CORRUPTION,
 *   NT_STATUS_INVALID_PARAMETER, NT_STATUS_UNSUCCESSFUL,
 *   NT_STATUS_WRONG_PASSWORD, NT_STATUS_PASSWORD_RESTRICTION,
 *   NT_STATUS_TRANSACTION_ABORTED, NT_STATUS_NO_SUCH_USER
 */
NTSTATUS samdb_set_password_sid(struct ldb_context *ldb, TALLOC_CTX *mem_ctx,
				const struct dom_sid *user_sid,
				const uint32_t *new_version, /* optional for trusts */
				const DATA_BLOB *new_password,
				const struct samr_Password *lmNewHash,
				const struct samr_Password *ntNewHash,
				const struct samr_Password *lmOldHash,
				const struct samr_Password *ntOldHash,
				enum samPwdChangeReason *reject_reason,
				struct samr_DomInfo1 **_dominfo) 
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS nt_status;
	const char * const user_attrs[] = {
		"userAccountControl",
		"sAMAccountName",
		NULL
	};
	struct ldb_message *user_msg = NULL;
	int ret;
	uint32_t uac = 0;

	ret = ldb_transaction_start(ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(1, ("Failed to start transaction: %s\n", ldb_errstring(ldb)));
		TALLOC_FREE(frame);
		return NT_STATUS_TRANSACTION_ABORTED;
	}

	ret = dsdb_search_one(ldb, frame, &user_msg, ldb_get_default_basedn(ldb),
			      LDB_SCOPE_SUBTREE, user_attrs, 0,
			      "(&(objectSid=%s)(objectClass=user))",
			      ldap_encode_ndr_dom_sid(frame, user_sid));
	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(ldb);
		DEBUG(3, ("samdb_set_password_sid: SID[%s] not found in samdb %s - %s, "
			  "returning NO_SUCH_USER\n",
			  dom_sid_string(frame, user_sid),
			  ldb_strerror(ret), ldb_errstring(ldb)));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_SUCH_USER;
	}

	uac = ldb_msg_find_attr_as_uint(user_msg, "userAccountControl", 0);
	if (!(uac & UF_ACCOUNT_TYPE_MASK)) {
		ldb_transaction_cancel(ldb);
		DEBUG(1, ("samdb_set_password_sid: invalid "
			  "userAccountControl[0x%08X] for SID[%s] DN[%s], "
			  "returning NO_SUCH_USER\n",
			  (unsigned)uac, dom_sid_string(frame, user_sid),
			  ldb_dn_get_linearized(user_msg->dn)));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_SUCH_USER;
	}

	if (uac & UF_INTERDOMAIN_TRUST_ACCOUNT) {
		const char * const tdo_attrs[] = {
			"trustAuthIncoming",
			"trustDirection",
			NULL
		};
		struct ldb_message *tdo_msg = NULL;
		const char *account_name = NULL;
		uint32_t trust_direction;
		uint32_t i;
		const struct ldb_val *old_val = NULL;
		struct trustAuthInOutBlob old_blob = {
			.count = 0,
		};
		uint32_t old_version = 0;
		struct AuthenticationInformation *old_version_a = NULL;
		uint32_t _new_version = 0;
		struct trustAuthInOutBlob new_blob = {
			.count = 0,
		};
		struct ldb_val new_val = {
			.length = 0,
		};
		struct timeval tv = timeval_current();
		NTTIME now = timeval_to_nttime(&tv);
		enum ndr_err_code ndr_err;

		if (new_password == NULL && ntNewHash == NULL) {
			ldb_transaction_cancel(ldb);
			DEBUG(1, ("samdb_set_password_sid: "
				  "no new password provided "
				  "sAMAccountName for SID[%s] DN[%s], "
				  "returning INVALID_PARAMETER\n",
				  dom_sid_string(frame, user_sid),
				  ldb_dn_get_linearized(user_msg->dn)));
			TALLOC_FREE(frame);
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (new_password != NULL && ntNewHash != NULL) {
			ldb_transaction_cancel(ldb);
			DEBUG(1, ("samdb_set_password_sid: "
				  "two new passwords provided "
				  "sAMAccountName for SID[%s] DN[%s], "
				  "returning INVALID_PARAMETER\n",
				  dom_sid_string(frame, user_sid),
				  ldb_dn_get_linearized(user_msg->dn)));
			TALLOC_FREE(frame);
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (new_password != NULL && (new_password->length % 2)) {
			ldb_transaction_cancel(ldb);
			DEBUG(2, ("samdb_set_password_sid: "
				  "invalid utf16 length (%zu) "
				  "sAMAccountName for SID[%s] DN[%s], "
				  "returning WRONG_PASSWORD\n",
				  new_password->length,
				  dom_sid_string(frame, user_sid),
				  ldb_dn_get_linearized(user_msg->dn)));
			TALLOC_FREE(frame);
			return NT_STATUS_WRONG_PASSWORD;
		}

		if (new_password != NULL && new_password->length >= 500) {
			ldb_transaction_cancel(ldb);
			DEBUG(2, ("samdb_set_password_sid: "
				  "utf16 password too long (%zu) "
				  "sAMAccountName for SID[%s] DN[%s], "
				  "returning WRONG_PASSWORD\n",
				  new_password->length,
				  dom_sid_string(frame, user_sid),
				  ldb_dn_get_linearized(user_msg->dn)));
			TALLOC_FREE(frame);
			return NT_STATUS_WRONG_PASSWORD;
		}

		account_name = ldb_msg_find_attr_as_string(user_msg,
							"sAMAccountName", NULL);
		if (account_name == NULL) {
			ldb_transaction_cancel(ldb);
			DEBUG(1, ("samdb_set_password_sid: missing "
				  "sAMAccountName for SID[%s] DN[%s], "
				  "returning NO_SUCH_USER\n",
				  dom_sid_string(frame, user_sid),
				  ldb_dn_get_linearized(user_msg->dn)));
			TALLOC_FREE(frame);
			return NT_STATUS_NO_SUCH_USER;
		}

		nt_status = dsdb_trust_search_tdo_by_type(ldb,
							  SEC_CHAN_DOMAIN,
							  account_name,
							  tdo_attrs,
							  frame, &tdo_msg);
		if (!NT_STATUS_IS_OK(nt_status)) {
			ldb_transaction_cancel(ldb);
			DEBUG(1, ("samdb_set_password_sid: dsdb_trust_search_tdo "
				  "failed(%s) for sAMAccountName[%s] SID[%s] DN[%s], "
				  "returning INTERNAL_DB_CORRUPTION\n",
				  nt_errstr(nt_status), account_name,
				  dom_sid_string(frame, user_sid),
				  ldb_dn_get_linearized(user_msg->dn)));
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		trust_direction = ldb_msg_find_attr_as_int(tdo_msg,
							   "trustDirection", 0);
		if (!(trust_direction & LSA_TRUST_DIRECTION_INBOUND)) {
			ldb_transaction_cancel(ldb);
			DEBUG(1, ("samdb_set_password_sid: direction[0x%08X] is "
				  "not inbound for sAMAccountName[%s] "
				  "DN[%s] TDO[%s], "
				  "returning INTERNAL_DB_CORRUPTION\n",
				  (unsigned)trust_direction,
				  account_name,
				  ldb_dn_get_linearized(user_msg->dn),
				  ldb_dn_get_linearized(tdo_msg->dn)));
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		old_val = ldb_msg_find_ldb_val(tdo_msg, "trustAuthIncoming");
		if (old_val != NULL) {
			ndr_err = ndr_pull_struct_blob(old_val, frame, &old_blob,
					(ndr_pull_flags_fn_t)ndr_pull_trustAuthInOutBlob);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				ldb_transaction_cancel(ldb);
				DEBUG(1, ("samdb_set_password_sid: "
					  "failed(%s) to parse "
					  "trustAuthOutgoing sAMAccountName[%s] "
					  "DN[%s] TDO[%s], "
					  "returning INTERNAL_DB_CORRUPTION\n",
					  ndr_map_error2string(ndr_err),
					  account_name,
					  ldb_dn_get_linearized(user_msg->dn),
					  ldb_dn_get_linearized(tdo_msg->dn)));

				TALLOC_FREE(frame);
				return NT_STATUS_INTERNAL_DB_CORRUPTION;
			}
		}

		for (i = old_blob.current.count; i > 0; i--) {
			struct AuthenticationInformation *a =
				&old_blob.current.array[i - 1];

			switch (a->AuthType) {
			case TRUST_AUTH_TYPE_NONE:
				if (i == old_blob.current.count) {
					/*
					 * remove TRUST_AUTH_TYPE_NONE at the
					 * end
					 */
					old_blob.current.count--;
				}
				break;

			case TRUST_AUTH_TYPE_VERSION:
				old_version_a = a;
				old_version = a->AuthInfo.version.version;
				break;

			case TRUST_AUTH_TYPE_CLEAR:
				break;

			case TRUST_AUTH_TYPE_NT4OWF:
				break;
			}
		}

		if (new_version == NULL) {
			_new_version = 0;
			new_version = &_new_version;
		}

		if (old_version_a != NULL && *new_version != (old_version + 1)) {
			old_version_a->LastUpdateTime = now;
			old_version_a->AuthType = TRUST_AUTH_TYPE_NONE;
		}

		new_blob.count = MAX(old_blob.current.count, 2);
		new_blob.current.array = talloc_zero_array(frame,
						struct AuthenticationInformation,
						new_blob.count);
		if (new_blob.current.array == NULL) {
			ldb_transaction_cancel(ldb);
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
		new_blob.previous.array = talloc_zero_array(frame,
						struct AuthenticationInformation,
						new_blob.count);
		if (new_blob.current.array == NULL) {
			ldb_transaction_cancel(ldb);
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		for (i = 0; i < old_blob.current.count; i++) {
			struct AuthenticationInformation *o =
				&old_blob.current.array[i];
			struct AuthenticationInformation *p =
				&new_blob.previous.array[i];

			*p = *o;
			new_blob.previous.count++;
		}
		for (; i < new_blob.count; i++) {
			struct AuthenticationInformation *pi =
				&new_blob.previous.array[i];

			if (i == 0) {
				/*
				 * new_blob.previous is still empty so
				 * we'll do new_blob.previous = new_blob.current
				 * below.
				 */
				break;
			}

			pi->LastUpdateTime = now;
			pi->AuthType = TRUST_AUTH_TYPE_NONE;
			new_blob.previous.count++;
		}

		for (i = 0; i < new_blob.count; i++) {
			struct AuthenticationInformation *ci =
				&new_blob.current.array[i];

			ci->LastUpdateTime = now;
			switch (i) {
			case 0:
				if (ntNewHash != NULL) {
					ci->AuthType = TRUST_AUTH_TYPE_NT4OWF;
					ci->AuthInfo.nt4owf.password = *ntNewHash;
					break;
				}

				ci->AuthType = TRUST_AUTH_TYPE_CLEAR;
				ci->AuthInfo.clear.size = new_password->length;
				ci->AuthInfo.clear.password = new_password->data;
				break;
			case 1:
				ci->AuthType = TRUST_AUTH_TYPE_VERSION;
				ci->AuthInfo.version.version = *new_version;
				break;
			default:
				ci->AuthType = TRUST_AUTH_TYPE_NONE;
				break;
			}

			new_blob.current.count++;
		}

		if (new_blob.previous.count == 0) {
			TALLOC_FREE(new_blob.previous.array);
			new_blob.previous = new_blob.current;
		}

		ndr_err = ndr_push_struct_blob(&new_val, frame, &new_blob,
				(ndr_push_flags_fn_t)ndr_push_trustAuthInOutBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			ldb_transaction_cancel(ldb);
			DEBUG(1, ("samdb_set_password_sid: "
				  "failed(%s) to generate "
				  "trustAuthOutgoing sAMAccountName[%s] "
				  "DN[%s] TDO[%s], "
				  "returning UNSUCCESSFUL\n",
				  ndr_map_error2string(ndr_err),
				  account_name,
				  ldb_dn_get_linearized(user_msg->dn),
				  ldb_dn_get_linearized(tdo_msg->dn)));
			TALLOC_FREE(frame);
			return NT_STATUS_UNSUCCESSFUL;
		}

		tdo_msg->num_elements = 0;
		TALLOC_FREE(tdo_msg->elements);

		ret = ldb_msg_add_empty(tdo_msg, "trustAuthIncoming",
					LDB_FLAG_MOD_REPLACE, NULL);
		if (ret != LDB_SUCCESS) {
			ldb_transaction_cancel(ldb);
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
		ret = ldb_msg_add_value(tdo_msg, "trustAuthIncoming",
					&new_val, NULL);
		if (ret != LDB_SUCCESS) {
			ldb_transaction_cancel(ldb);
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		ret = ldb_modify(ldb, tdo_msg);
		if (ret != LDB_SUCCESS) {
			nt_status = dsdb_ldb_err_to_ntstatus(ret);
			ldb_transaction_cancel(ldb);
			DEBUG(1, ("samdb_set_password_sid: "
				  "failed to replace "
				  "trustAuthOutgoing sAMAccountName[%s] "
				  "DN[%s] TDO[%s], "
				  "%s - %s\n",
				  account_name,
				  ldb_dn_get_linearized(user_msg->dn),
				  ldb_dn_get_linearized(tdo_msg->dn),
				  nt_errstr(nt_status), ldb_errstring(ldb)));
			TALLOC_FREE(frame);
			return nt_status;
		}
	}

	nt_status = samdb_set_password_internal(ldb, mem_ctx,
						user_msg->dn, NULL,
						new_password,
						lmNewHash, ntNewHash,
						lmOldHash, ntOldHash,
						reject_reason, _dominfo,
						true); /* permit trusts */
	if (!NT_STATUS_IS_OK(nt_status)) {
		ldb_transaction_cancel(ldb);
		TALLOC_FREE(frame);
		return nt_status;
	}

	ret = ldb_transaction_commit(ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to commit transaction to change password on %s: %s\n",
			 ldb_dn_get_linearized(user_msg->dn),
			 ldb_errstring(ldb)));
		TALLOC_FREE(frame);
		return NT_STATUS_TRANSACTION_ABORTED;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}


NTSTATUS samdb_create_foreign_security_principal(struct ldb_context *sam_ctx, TALLOC_CTX *mem_ctx, 
						 struct dom_sid *sid, struct ldb_dn **ret_dn) 
{
	struct ldb_message *msg;
	struct ldb_dn *basedn = NULL;
	char *sidstr;
	int ret;

	sidstr = dom_sid_string(mem_ctx, sid);
	NT_STATUS_HAVE_NO_MEMORY(sidstr);

	/* We might have to create a ForeignSecurityPrincipal, even if this user
	 * is in our own domain */

	msg = ldb_msg_new(sidstr);
	if (msg == NULL) {
		talloc_free(sidstr);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dsdb_wellknown_dn(sam_ctx, sidstr,
				ldb_get_default_basedn(sam_ctx),
				DS_GUID_FOREIGNSECURITYPRINCIPALS_CONTAINER,
				&basedn);
	if (ret != LDB_SUCCESS) {
		DEBUG(0, ("Failed to find DN for "
			  "ForeignSecurityPrincipal container - %s\n", ldb_errstring(sam_ctx)));
		talloc_free(sidstr);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* add core elements to the ldb_message for the alias */
	msg->dn = basedn;
	if ( ! ldb_dn_add_child_fmt(msg->dn, "CN=%s", sidstr)) {
		talloc_free(sidstr);
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_msg_add_string(msg, "objectClass",
				 "foreignSecurityPrincipal");
	if (ret != LDB_SUCCESS) {
		talloc_free(sidstr);
		return NT_STATUS_NO_MEMORY;
	}

	/* create the alias */
	ret = ldb_add(sam_ctx, msg);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to create foreignSecurityPrincipal "
			 "record %s: %s\n", 
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(sam_ctx)));
		talloc_free(sidstr);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	*ret_dn = talloc_steal(mem_ctx, msg->dn);
	talloc_free(sidstr);

	return NT_STATUS_OK;
}


/*
  Find the DN of a domain, assuming it to be a dotted.dns name
*/

struct ldb_dn *samdb_dns_domain_to_dn(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, const char *dns_domain) 
{
	unsigned int i;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	const char *binary_encoded;
	const char * const *split_realm;
	struct ldb_dn *dn;

	if (!tmp_ctx) {
		return NULL;
	}

	split_realm = (const char * const *)str_list_make(tmp_ctx, dns_domain, ".");
	if (!split_realm) {
		talloc_free(tmp_ctx);
		return NULL;
	}
	dn = ldb_dn_new(mem_ctx, ldb, NULL);
	for (i=0; split_realm[i]; i++) {
		binary_encoded = ldb_binary_encode_string(tmp_ctx, split_realm[i]);
		if (!ldb_dn_add_base_fmt(dn, "dc=%s", binary_encoded)) {
			DEBUG(2, ("Failed to add dc=%s element to DN %s\n",
				  binary_encoded, ldb_dn_get_linearized(dn)));
			talloc_free(tmp_ctx);
			return NULL;
		}
	}
	if (!ldb_dn_validate(dn)) {
		DEBUG(2, ("Failed to validated DN %s\n",
			  ldb_dn_get_linearized(dn)));
		talloc_free(tmp_ctx);
		return NULL;
	}
	talloc_free(tmp_ctx);
	return dn;
}


/*
  Find the DNS equivalent of a DN, in dotted DNS form
*/
char *samdb_dn_to_dns_domain(TALLOC_CTX *mem_ctx, struct ldb_dn *dn)
{
	int i, num_components = ldb_dn_get_comp_num(dn);
	char *dns_name = talloc_strdup(mem_ctx, "");
	if (dns_name == NULL) {
		return NULL;
	}

	for (i=0; i<num_components; i++) {
		const struct ldb_val *v = ldb_dn_get_component_val(dn, i);
		char *s;
		if (v == NULL) {
			talloc_free(dns_name);
			return NULL;
		}
		s = talloc_asprintf_append_buffer(dns_name, "%*.*s.",
						  (int)v->length, (int)v->length, (char *)v->data);
		if (s == NULL) {
			talloc_free(dns_name);
			return NULL;
		}
		dns_name = s;
	}

	/* remove the last '.' */
	if (dns_name[0] != 0) {
		dns_name[strlen(dns_name)-1] = 0;
	}

	return dns_name;
}

/*
  Find the DNS _msdcs name for a given NTDS GUID. The resulting DNS
  name is based on the forest DNS name
*/
char *samdb_ntds_msdcs_dns_name(struct ldb_context *samdb,
				TALLOC_CTX *mem_ctx,
				const struct GUID *ntds_guid)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	const char *guid_str;
	struct ldb_dn *forest_dn;
	const char *dnsforest;
	char *ret;

	guid_str = GUID_string(tmp_ctx, ntds_guid);
	if (guid_str == NULL) {
		talloc_free(tmp_ctx);
		return NULL;
	}
	forest_dn = ldb_get_root_basedn(samdb);
	if (forest_dn == NULL) {
		talloc_free(tmp_ctx);
		return NULL;
	}
	dnsforest = samdb_dn_to_dns_domain(tmp_ctx, forest_dn);
	if (dnsforest == NULL) {
		talloc_free(tmp_ctx);
		return NULL;
	}
	ret = talloc_asprintf(mem_ctx, "%s._msdcs.%s", guid_str, dnsforest);
	talloc_free(tmp_ctx);
	return ret;
}


/*
  Find the DN of a domain, be it the netbios or DNS name 
*/
struct ldb_dn *samdb_domain_to_dn(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, 
				  const char *domain_name) 
{
	const char * const domain_ref_attrs[] = {
		"ncName", NULL
	};
	const char * const domain_ref2_attrs[] = {
		NULL
	};
	struct ldb_result *res_domain_ref;
	char *escaped_domain = ldb_binary_encode_string(mem_ctx, domain_name);
	/* find the domain's DN */
	int ret_domain = ldb_search(ldb, mem_ctx,
					    &res_domain_ref, 
					    samdb_partitions_dn(ldb, mem_ctx), 
					    LDB_SCOPE_ONELEVEL, 
					    domain_ref_attrs,
					    "(&(nETBIOSName=%s)(objectclass=crossRef))", 
					    escaped_domain);
	if (ret_domain != LDB_SUCCESS) {
		return NULL;
	}

	if (res_domain_ref->count == 0) {
		ret_domain = ldb_search(ldb, mem_ctx,
						&res_domain_ref, 
						samdb_dns_domain_to_dn(ldb, mem_ctx, domain_name),
						LDB_SCOPE_BASE,
						domain_ref2_attrs,
						"(objectclass=domain)");
		if (ret_domain != LDB_SUCCESS) {
			return NULL;
		}

		if (res_domain_ref->count == 1) {
			return res_domain_ref->msgs[0]->dn;
		}
		return NULL;
	}

	if (res_domain_ref->count > 1) {
		DEBUG(0,("Found %d records matching domain [%s]\n", 
			 ret_domain, domain_name));
		return NULL;
	}

	return samdb_result_dn(ldb, mem_ctx, res_domain_ref->msgs[0], "nCName", NULL);

}


/*
  use a GUID to find a DN
 */
int dsdb_find_dn_by_guid(struct ldb_context *ldb, 
			 TALLOC_CTX *mem_ctx,
			 const struct GUID *guid,
			 uint32_t dsdb_flags,
			 struct ldb_dn **dn)
{
	int ret;
	struct ldb_result *res;
	const char *attrs[] = { NULL };
	char *guid_str = GUID_string(mem_ctx, guid);

	if (!guid_str) {
		return ldb_operr(ldb);
	}

	ret = dsdb_search(ldb, mem_ctx, &res, NULL, LDB_SCOPE_SUBTREE, attrs,
			  DSDB_SEARCH_SEARCH_ALL_PARTITIONS |
			  DSDB_SEARCH_SHOW_EXTENDED_DN |
			  DSDB_SEARCH_ONE_ONLY | dsdb_flags,
			  "objectGUID=%s", guid_str);
	talloc_free(guid_str);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	*dn = talloc_steal(mem_ctx, res->msgs[0]->dn);
	talloc_free(res);

	return LDB_SUCCESS;
}

/*
  use a DN to find a GUID with a given attribute name
 */
int dsdb_find_guid_attr_by_dn(struct ldb_context *ldb,
			      struct ldb_dn *dn, const char *attribute,
			      struct GUID *guid)
{
	int ret;
	struct ldb_result *res = NULL;
	const char *attrs[2];
	TALLOC_CTX *tmp_ctx = talloc_new(ldb);

	attrs[0] = attribute;
	attrs[1] = NULL;

	ret = dsdb_search_dn(ldb, tmp_ctx, &res, dn, attrs,
			     DSDB_SEARCH_SHOW_DELETED |
			     DSDB_SEARCH_SHOW_RECYCLED);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	/* satisfy clang */
	if (res == NULL) {
		talloc_free(tmp_ctx);
		return LDB_ERR_OTHER;
	}
	if (res->count < 1) {
		talloc_free(tmp_ctx);
		return ldb_error(ldb, LDB_ERR_NO_SUCH_OBJECT, __func__);
	}
	*guid = samdb_result_guid(res->msgs[0], attribute);
	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}

/*
  use a DN to find a GUID
 */
int dsdb_find_guid_by_dn(struct ldb_context *ldb,
			 struct ldb_dn *dn, struct GUID *guid)
{
	return dsdb_find_guid_attr_by_dn(ldb, dn, "objectGUID", guid);
}



/*
 adds the given GUID to the given ldb_message. This value is added
 for the given attr_name (may be either "objectGUID" or "parentGUID").
 */
int dsdb_msg_add_guid(struct ldb_message *msg,
		struct GUID *guid,
		const char *attr_name)
{
	int ret;
	struct ldb_val v;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx =  talloc_init("dsdb_msg_add_guid");

	status = GUID_to_ndr_blob(guid, tmp_ctx, &v);
	if (!NT_STATUS_IS_OK(status)) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	ret = ldb_msg_add_steal_value(msg, attr_name, &v);
	if (ret != LDB_SUCCESS) {
		DEBUG(4,(__location__ ": Failed to add %s to the message\n",
					 attr_name));
		goto done;
	}

	ret = LDB_SUCCESS;

done:
	talloc_free(tmp_ctx);
	return ret;

}


/*
  use a DN to find a SID
 */
int dsdb_find_sid_by_dn(struct ldb_context *ldb, 
			struct ldb_dn *dn, struct dom_sid *sid)
{
	int ret;
	struct ldb_result *res = NULL;
	const char *attrs[] = { "objectSid", NULL };
	TALLOC_CTX *tmp_ctx = talloc_new(ldb);
	struct dom_sid *s;

	ZERO_STRUCTP(sid);

	ret = dsdb_search_dn(ldb, tmp_ctx, &res, dn, attrs,
			     DSDB_SEARCH_SHOW_DELETED |
			     DSDB_SEARCH_SHOW_RECYCLED);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	if (res == NULL) {
		talloc_free(tmp_ctx);
		return LDB_ERR_OTHER;
	}
	if (res->count < 1) {
		talloc_free(tmp_ctx);
		return ldb_error(ldb, LDB_ERR_NO_SUCH_OBJECT, __func__);
	}
	s = samdb_result_dom_sid(tmp_ctx, res->msgs[0], "objectSid");
	if (s == NULL) {
		talloc_free(tmp_ctx);
		return ldb_error(ldb, LDB_ERR_NO_SUCH_OBJECT, __func__);
	}
	*sid = *s;
	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}

/*
  use a SID to find a DN
 */
int dsdb_find_dn_by_sid(struct ldb_context *ldb,
			TALLOC_CTX *mem_ctx,
			struct dom_sid *sid, struct ldb_dn **dn)
{
	int ret;
	struct ldb_result *res;
	const char *attrs[] = { NULL };
	char *sid_str = ldap_encode_ndr_dom_sid(mem_ctx, sid);

	if (!sid_str) {
		return ldb_operr(ldb);
	}

	ret = dsdb_search(ldb, mem_ctx, &res, NULL, LDB_SCOPE_SUBTREE, attrs,
			  DSDB_SEARCH_SEARCH_ALL_PARTITIONS |
			  DSDB_SEARCH_SHOW_EXTENDED_DN |
			  DSDB_SEARCH_ONE_ONLY,
			  "objectSid=%s", sid_str);
	talloc_free(sid_str);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	*dn = talloc_steal(mem_ctx, res->msgs[0]->dn);
	talloc_free(res);

	return LDB_SUCCESS;
}

/*
  load a repsFromTo blob list for a given partition GUID
  attr must be "repsFrom" or "repsTo"
 */
WERROR dsdb_loadreps(struct ldb_context *sam_ctx, TALLOC_CTX *mem_ctx, struct ldb_dn *dn,
		     const char *attr, struct repsFromToBlob **r, uint32_t *count)
{
	const char *attrs[] = { attr, NULL };
	struct ldb_result *res = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	unsigned int i;
	struct ldb_message_element *el;
	int ret;

	*r = NULL;
	*count = 0;

	ret = dsdb_search_dn(sam_ctx, tmp_ctx, &res, dn, attrs, 0);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		/* partition hasn't been replicated yet */
		return WERR_OK;
	}
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("dsdb_loadreps: failed to read partition object: %s\n", ldb_errstring(sam_ctx)));
		talloc_free(tmp_ctx);
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	/* satisfy clang */
	if (res == NULL) {
		talloc_free(tmp_ctx);
		return WERR_DS_DRA_INTERNAL_ERROR;
	}
	el = ldb_msg_find_element(res->msgs[0], attr);
	if (el == NULL) {
		/* it's OK to be empty */
		talloc_free(tmp_ctx);
		return WERR_OK;
	}

	*count = el->num_values;
	*r = talloc_array(mem_ctx, struct repsFromToBlob, *count);
	if (*r == NULL) {
		talloc_free(tmp_ctx);
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	for (i=0; i<(*count); i++) {
		enum ndr_err_code ndr_err;
		ndr_err = ndr_pull_struct_blob(&el->values[i], 
					       mem_ctx, 
					       &(*r)[i], 
					       (ndr_pull_flags_fn_t)ndr_pull_repsFromToBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
	}

	talloc_free(tmp_ctx);
	
	return WERR_OK;
}

/*
  save the repsFromTo blob list for a given partition GUID
  attr must be "repsFrom" or "repsTo"
 */
WERROR dsdb_savereps(struct ldb_context *sam_ctx, TALLOC_CTX *mem_ctx, struct ldb_dn *dn,
		     const char *attr, struct repsFromToBlob *r, uint32_t count)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct ldb_message *msg;
	struct ldb_message_element *el;
	unsigned int i;

	msg = ldb_msg_new(tmp_ctx);
	msg->dn = dn;
	if (ldb_msg_add_empty(msg, attr, LDB_FLAG_MOD_REPLACE, &el) != LDB_SUCCESS) {
		goto failed;
	}

	el->values = talloc_array(msg, struct ldb_val, count);
	if (!el->values) {
		goto failed;
	}

	for (i=0; i<count; i++) {
		struct ldb_val v;
		enum ndr_err_code ndr_err;

		ndr_err = ndr_push_struct_blob(&v, tmp_ctx, 
					       &r[i], 
					       (ndr_push_flags_fn_t)ndr_push_repsFromToBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			goto failed;
		}

		el->num_values++;
		el->values[i] = v;
	}

	if (dsdb_modify(sam_ctx, msg, 0) != LDB_SUCCESS) {
		DEBUG(0,("Failed to store %s - %s\n", attr, ldb_errstring(sam_ctx)));
		goto failed;
	}

	talloc_free(tmp_ctx);
	
	return WERR_OK;

failed:
	talloc_free(tmp_ctx);
	return WERR_DS_DRA_INTERNAL_ERROR;
}


/*
  load the uSNHighest and the uSNUrgent attributes from the @REPLCHANGED
  object for a partition
 */
int dsdb_load_partition_usn(struct ldb_context *ldb, struct ldb_dn *dn,
				uint64_t *uSN, uint64_t *urgent_uSN)
{
	struct ldb_request *req;
	int ret;
	TALLOC_CTX *tmp_ctx = talloc_new(ldb);
	struct dsdb_control_current_partition *p_ctrl;
	struct ldb_result *res;

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	ret = ldb_build_search_req(&req, ldb, tmp_ctx,
				   ldb_dn_new(tmp_ctx, ldb, "@REPLCHANGED"),
				   LDB_SCOPE_BASE,
				   NULL, NULL,
				   NULL,
				   res, ldb_search_default_callback,
				   NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	p_ctrl = talloc(req, struct dsdb_control_current_partition);
	if (p_ctrl == NULL) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}
	p_ctrl->version = DSDB_CONTROL_CURRENT_PARTITION_VERSION;
	p_ctrl->dn = dn;
	
	ret = ldb_request_add_control(req,
				      DSDB_CONTROL_CURRENT_PARTITION_OID,
				      false, p_ctrl);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	
	/* Run the new request */
	ret = ldb_request(ldb, req);
	
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	if (ret == LDB_ERR_NO_SUCH_OBJECT || ret == LDB_ERR_INVALID_DN_SYNTAX) {
		/* it hasn't been created yet, which means
		   an implicit value of zero */
		*uSN = 0;
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	if (res->count < 1) {
		*uSN = 0;
		if (urgent_uSN) {
			*urgent_uSN = 0;
		}
	} else {
		*uSN = ldb_msg_find_attr_as_uint64(res->msgs[0], "uSNHighest", 0);
		if (urgent_uSN) {
			*urgent_uSN = ldb_msg_find_attr_as_uint64(res->msgs[0], "uSNUrgent", 0);
		}
	}

	talloc_free(tmp_ctx);

	return LDB_SUCCESS;	
}

int drsuapi_DsReplicaCursor2_compare(const struct drsuapi_DsReplicaCursor2 *c1,
						   const struct drsuapi_DsReplicaCursor2 *c2)
{
	return GUID_compare(&c1->source_dsa_invocation_id, &c2->source_dsa_invocation_id);
}

int drsuapi_DsReplicaCursor_compare(const struct drsuapi_DsReplicaCursor *c1,
				    const struct drsuapi_DsReplicaCursor *c2)
{
	return GUID_compare(&c1->source_dsa_invocation_id, &c2->source_dsa_invocation_id);
}


/*
  see if a computer identified by its invocationId is a RODC
*/
int samdb_is_rodc(struct ldb_context *sam_ctx, const struct GUID *objectGUID, bool *is_rodc)
{
	/* 1) find the DN for this servers NTDSDSA object
	   2) search for the msDS-isRODC attribute
	   3) if not present then not a RODC
	   4) if present and TRUE then is a RODC
	*/
	struct ldb_dn *config_dn;
	const char *attrs[] = { "msDS-isRODC", NULL };
	int ret;
	struct ldb_result *res;
	TALLOC_CTX *tmp_ctx = talloc_new(sam_ctx);

	config_dn = ldb_get_config_basedn(sam_ctx);
	if (!config_dn) {
		talloc_free(tmp_ctx);
		return ldb_operr(sam_ctx);
	}

	ret = dsdb_search(sam_ctx, tmp_ctx, &res, config_dn, LDB_SCOPE_SUBTREE, attrs,
			  DSDB_SEARCH_ONE_ONLY, "objectGUID=%s", GUID_string(tmp_ctx, objectGUID));

	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		*is_rodc = false;
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	if (ret != LDB_SUCCESS) {
		DEBUG(1,(("Failed to find our own NTDS Settings object by objectGUID=%s!\n"),
			 GUID_string(tmp_ctx, objectGUID)));
		*is_rodc = false;
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = ldb_msg_find_attr_as_bool(res->msgs[0], "msDS-isRODC", 0);
	*is_rodc = (ret == 1);

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}


/*
  see if we are a RODC
*/
int samdb_rodc(struct ldb_context *sam_ctx, bool *am_rodc)
{
	const struct GUID *objectGUID;
	int ret;
	bool *cached;

	/* see if we have a cached copy */
	cached = (bool *)ldb_get_opaque(sam_ctx, "cache.am_rodc");
	if (cached) {
		*am_rodc = *cached;
		return LDB_SUCCESS;
	}

	objectGUID = samdb_ntds_objectGUID(sam_ctx);
	if (!objectGUID) {
		return ldb_operr(sam_ctx);
	}

	ret = samdb_is_rodc(sam_ctx, objectGUID, am_rodc);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	cached = talloc(sam_ctx, bool);
	if (cached == NULL) {
		return ldb_oom(sam_ctx);
	}
	*cached = *am_rodc;

	ret = ldb_set_opaque(sam_ctx, "cache.am_rodc", cached);
	if (ret != LDB_SUCCESS) {
		talloc_free(cached);
		return ldb_operr(sam_ctx);
	}

	return LDB_SUCCESS;
}

int samdb_dns_host_name(struct ldb_context *sam_ctx, const char **host_name)
{
	const char *_host_name = NULL;
	const char *attrs[] = { "dnsHostName", NULL };
	TALLOC_CTX *tmp_ctx = NULL;
	int ret;
	struct ldb_result *res = NULL;

	_host_name = (const char *)ldb_get_opaque(sam_ctx, "cache.dns_host_name");
	if (_host_name != NULL) {
		*host_name = _host_name;
		return LDB_SUCCESS;
	}

	tmp_ctx = talloc_new(sam_ctx);

	ret = dsdb_search_dn(sam_ctx, tmp_ctx, &res, NULL, attrs, 0);

	if (res == NULL || res->count != 1 || ret != LDB_SUCCESS) {
		DEBUG(0, ("Failed to get rootDSE for dnsHostName: %s",
			  ldb_errstring(sam_ctx)));
		TALLOC_FREE(tmp_ctx);
		return ret;
	}

	_host_name = ldb_msg_find_attr_as_string(res->msgs[0],
						 "dnsHostName",
						 NULL);
	if (_host_name == NULL) {
		DEBUG(0, ("Failed to get dnsHostName from rootDSE"));
		TALLOC_FREE(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = ldb_set_opaque(sam_ctx, "cache.dns_host_name",
			     discard_const_p(char *, _host_name));
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(tmp_ctx);
		return ldb_operr(sam_ctx);
	}

	*host_name = talloc_steal(sam_ctx, _host_name);

	TALLOC_FREE(tmp_ctx);
	return LDB_SUCCESS;
}

bool samdb_set_am_rodc(struct ldb_context *ldb, bool am_rodc)
{
	TALLOC_CTX *tmp_ctx;
	bool *cached;

	tmp_ctx = talloc_new(ldb);
	if (tmp_ctx == NULL) {
		goto failed;
	}

	cached = talloc(tmp_ctx, bool);
	if (!cached) {
		goto failed;
	}

	*cached = am_rodc;
	if (ldb_set_opaque(ldb, "cache.am_rodc", cached) != LDB_SUCCESS) {
		goto failed;
	}

	talloc_steal(ldb, cached);
	talloc_free(tmp_ctx);
	return true;

failed:
	DEBUG(1,("Failed to set our own cached am_rodc in the ldb!\n"));
	talloc_free(tmp_ctx);
	return false;
}


/*
 * return NTDSSiteSettings options. See MS-ADTS 7.1.1.2.2.1.1
 * flags are DS_NTDSSETTINGS_OPT_*
 */
int samdb_ntds_site_settings_options(struct ldb_context *ldb_ctx,
					uint32_t *options)
{
	int rc;
	TALLOC_CTX *tmp_ctx;
	struct ldb_result *res;
	struct ldb_dn *site_dn;
	const char *attrs[] = { "options", NULL };

	tmp_ctx = talloc_new(ldb_ctx);
	if (tmp_ctx == NULL)
		goto failed;

        /* Retrieve the site dn for the ldb that we
	 * have open.  This is our local site.
         */
        site_dn = samdb_server_site_dn(ldb_ctx, tmp_ctx);
	if (site_dn == NULL)
		goto failed;

	/* Perform a one level (child) search from the local
         * site distinguided name.   We're looking for the
         * "options" attribute within the nTDSSiteSettings
         * object
	 */
	rc = ldb_search(ldb_ctx, tmp_ctx, &res, site_dn,
			LDB_SCOPE_ONELEVEL, attrs,
                        "objectClass=nTDSSiteSettings");

        if (rc != LDB_SUCCESS || res->count != 1)
		goto failed;

	*options = ldb_msg_find_attr_as_uint(res->msgs[0], "options", 0);

	talloc_free(tmp_ctx);

	return LDB_SUCCESS;

failed:
	DEBUG(1,("Failed to find our NTDS Site Settings options in ldb!\n"));
	talloc_free(tmp_ctx);
	return ldb_error(ldb_ctx, LDB_ERR_NO_SUCH_OBJECT, __func__);
}

/*
  return NTDS options flags. See MS-ADTS 7.1.1.2.2.1.2.1.1 

  flags are DS_NTDS_OPTION_*
*/
int samdb_ntds_options(struct ldb_context *ldb, uint32_t *options)
{
	TALLOC_CTX *tmp_ctx;
	const char *attrs[] = { "options", NULL };
	int ret;
	struct ldb_result *res;

	tmp_ctx = talloc_new(ldb);
	if (tmp_ctx == NULL) {
		goto failed;
	}

	ret = ldb_search(ldb, tmp_ctx, &res, samdb_ntds_settings_dn(ldb, tmp_ctx), LDB_SCOPE_BASE, attrs, NULL);
	if (ret != LDB_SUCCESS) {
		goto failed;
	}

	if (res->count != 1) {
		goto failed;
	}

	*options = ldb_msg_find_attr_as_uint(res->msgs[0], "options", 0);

	talloc_free(tmp_ctx);

	return LDB_SUCCESS;

failed:
	DEBUG(1,("Failed to find our own NTDS Settings options in the ldb!\n"));
	talloc_free(tmp_ctx);
	return ldb_error(ldb, LDB_ERR_NO_SUCH_OBJECT, __func__);
}

const char* samdb_ntds_object_category(TALLOC_CTX *tmp_ctx, struct ldb_context *ldb)
{
	const char *attrs[] = { "objectCategory", NULL };
	int ret;
	struct ldb_result *res;

	ret = ldb_search(ldb, tmp_ctx, &res, samdb_ntds_settings_dn(ldb, tmp_ctx), LDB_SCOPE_BASE, attrs, NULL);
	if (ret != LDB_SUCCESS) {
		goto failed;
	}

	if (res->count != 1) {
		goto failed;
	}

	return ldb_msg_find_attr_as_string(res->msgs[0], "objectCategory", NULL);

failed:
	DEBUG(1,("Failed to find our own NTDS Settings objectCategory in the ldb!\n"));
	return NULL;
}

/*
 * Function which generates a "lDAPDisplayName" attribute from a "CN" one.
 * Algorithm implemented according to MS-ADTS 3.1.1.2.3.4
 */
const char *samdb_cn_to_lDAPDisplayName(TALLOC_CTX *mem_ctx, const char *cn)
{
	char **tokens, *ret;
	size_t i;

	tokens = str_list_make(mem_ctx, cn, " -_");
	if (tokens == NULL || tokens[0] == NULL) {
		return NULL;
	}

	/* "tolower()" and "toupper()" should also work properly on 0x00 */
	tokens[0][0] = tolower(tokens[0][0]);
	for (i = 1; tokens[i] != NULL; i++)
		tokens[i][0] = toupper(tokens[i][0]);

	ret = talloc_strdup(mem_ctx, tokens[0]);
	for (i = 1; tokens[i] != NULL; i++)
		ret = talloc_asprintf_append_buffer(ret, "%s", tokens[i]);

	talloc_free(tokens);

	return ret;
}

/*
 * This detects and returns the domain functional level (DS_DOMAIN_FUNCTION_*)
 */
int dsdb_functional_level(struct ldb_context *ldb)
{
	int *domainFunctionality =
		talloc_get_type(ldb_get_opaque(ldb, "domainFunctionality"), int);
	if (!domainFunctionality) {
		/* this is expected during initial provision */
		DEBUG(4,(__location__ ": WARNING: domainFunctionality not setup\n"));
		return DS_DOMAIN_FUNCTION_2000;
	}
	return *domainFunctionality;
}

/*
 * This detects and returns the forest functional level (DS_DOMAIN_FUNCTION_*)
 */
int dsdb_forest_functional_level(struct ldb_context *ldb)
{
	int *forestFunctionality =
		talloc_get_type(ldb_get_opaque(ldb, "forestFunctionality"), int);
	if (!forestFunctionality) {
		DEBUG(0,(__location__ ": WARNING: forestFunctionality not setup\n"));
		return DS_DOMAIN_FUNCTION_2000;
	}
	return *forestFunctionality;
}

/*
  set a GUID in an extended DN structure
 */
int dsdb_set_extended_dn_guid(struct ldb_dn *dn, const struct GUID *guid, const char *component_name)
{
	struct ldb_val v;
	NTSTATUS status;
	int ret;

	status = GUID_to_ndr_blob(guid, dn, &v);
	if (!NT_STATUS_IS_OK(status)) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}

	ret = ldb_dn_set_extended_component(dn, component_name, &v);
	data_blob_free(&v);
	return ret;
}

/*
  return a GUID from a extended DN structure
 */
NTSTATUS dsdb_get_extended_dn_guid(struct ldb_dn *dn, struct GUID *guid, const char *component_name)
{
	const struct ldb_val *v;

	v = ldb_dn_get_extended_component(dn, component_name);
	if (v == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	return GUID_from_ndr_blob(v, guid);
}

/*
  return a uint64_t from a extended DN structure
 */
NTSTATUS dsdb_get_extended_dn_uint64(struct ldb_dn *dn, uint64_t *val, const char *component_name)
{
	const struct ldb_val *v;
	int error = 0;

	v = ldb_dn_get_extended_component(dn, component_name);
	if (v == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* Just check we don't allow the caller to fill our stack */
	if (v->length >= 64) {
		return NT_STATUS_INVALID_PARAMETER;
	} else {
		char s[v->length+1];
		memcpy(s, v->data, v->length);
		s[v->length] = 0;

		*val = smb_strtoull(s, NULL, 0, &error, SMB_STR_STANDARD);
		if (error != 0) {
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	return NT_STATUS_OK;
}

/*
  return a NTTIME from a extended DN structure
 */
NTSTATUS dsdb_get_extended_dn_nttime(struct ldb_dn *dn, NTTIME *nttime, const char *component_name)
{
	return dsdb_get_extended_dn_uint64(dn, nttime, component_name);
}

/*
  return a uint32_t from a extended DN structure
 */
NTSTATUS dsdb_get_extended_dn_uint32(struct ldb_dn *dn, uint32_t *val, const char *component_name)
{
	const struct ldb_val *v;
	int error = 0;

	v = ldb_dn_get_extended_component(dn, component_name);
	if (v == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* Just check we don't allow the caller to fill our stack */
	if (v->length >= 32) {
		return NT_STATUS_INVALID_PARAMETER;
	} else {
		char s[v->length + 1];
		memcpy(s, v->data, v->length);
		s[v->length] = 0;
		*val = smb_strtoul(s, NULL, 0, &error, SMB_STR_STANDARD);
		if (error != 0) {
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	return NT_STATUS_OK;
}

/*
  return a dom_sid from a extended DN structure
 */
NTSTATUS dsdb_get_extended_dn_sid(struct ldb_dn *dn, struct dom_sid *sid, const char *component_name)
{
	const struct ldb_val *sid_blob;
	enum ndr_err_code ndr_err;

	sid_blob = ldb_dn_get_extended_component(dn, component_name);
	if (!sid_blob) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	ndr_err = ndr_pull_struct_blob_all_noalloc(sid_blob, sid,
						   (ndr_pull_flags_fn_t)ndr_pull_dom_sid);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	return NT_STATUS_OK;
}


/*
  return RMD_FLAGS directly from a ldb_dn
  returns 0 if not found
 */
uint32_t dsdb_dn_rmd_flags(struct ldb_dn *dn)
{
	uint32_t rmd_flags = 0;
	NTSTATUS status = dsdb_get_extended_dn_uint32(dn, &rmd_flags,
						      "RMD_FLAGS");
	if (NT_STATUS_IS_OK(status)) {
		return rmd_flags;
	}
	return 0;
}

/*
  return RMD_FLAGS directly from a ldb_val for a DN
  returns 0 if RMD_FLAGS is not found
 */
uint32_t dsdb_dn_val_rmd_flags(const struct ldb_val *val)
{
	const char *p;
	uint32_t flags;
	char *end;
	int error = 0;

	if (val->length < 13) {
		return 0;
	}
	p = memmem(val->data, val->length, "<RMD_FLAGS=", 11);
	if (!p) {
		return 0;
	}
	flags = smb_strtoul(p+11, &end, 10, &error, SMB_STR_STANDARD);
	if (!end || *end != '>' || error != 0) {
		/* it must end in a > */
		return 0;
	}
	return flags;
}

/*
  return true if a ldb_val containing a DN in storage form is deleted
 */
bool dsdb_dn_is_deleted_val(const struct ldb_val *val)
{
	return (dsdb_dn_val_rmd_flags(val) & DSDB_RMD_FLAG_DELETED) != 0;
}

/*
  return true if a ldb_val containing a DN in storage form is
  in the upgraded w2k3 linked attribute format
 */
bool dsdb_dn_is_upgraded_link_val(const struct ldb_val *val)
{
	return memmem(val->data, val->length, "<RMD_VERSION=", 13) != NULL;
}

/*
  return a DN for a wellknown GUID
 */
int dsdb_wellknown_dn(struct ldb_context *samdb, TALLOC_CTX *mem_ctx,
		      struct ldb_dn *nc_root, const char *wk_guid,
		      struct ldb_dn **wkguid_dn)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	const char *attrs[] = { NULL };
	int ret;
	struct ldb_dn *dn;
	struct ldb_result *res = NULL;

	/* construct the magic WKGUID DN */
	dn = ldb_dn_new_fmt(tmp_ctx, samdb, "<WKGUID=%s,%s>",
			    wk_guid, ldb_dn_get_linearized(nc_root));
	if (!wkguid_dn) {
		talloc_free(tmp_ctx);
		return ldb_operr(samdb);
	}

	ret = dsdb_search_dn(samdb, tmp_ctx, &res, dn, attrs,
			     DSDB_SEARCH_SHOW_DELETED |
			     DSDB_SEARCH_SHOW_RECYCLED);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	/* fix clang warning */
	if (res == NULL){
		talloc_free(tmp_ctx);
		return LDB_ERR_OTHER;
	}

	(*wkguid_dn) = talloc_steal(mem_ctx, res->msgs[0]->dn);
	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}


static int dsdb_dn_compare_ptrs(struct ldb_dn **dn1, struct ldb_dn **dn2)
{
	return ldb_dn_compare(*dn1, *dn2);
}

/*
  find a NC root given a DN within the NC
 */
int dsdb_find_nc_root(struct ldb_context *samdb, TALLOC_CTX *mem_ctx, struct ldb_dn *dn,
		      struct ldb_dn **nc_root)
{
	const char *root_attrs[] = { "namingContexts", NULL };
	TALLOC_CTX *tmp_ctx;
	int ret;
	struct ldb_message_element *el;
	struct ldb_result *root_res;
	unsigned int i;
	struct ldb_dn **nc_dns;

	tmp_ctx = talloc_new(samdb);
	if (tmp_ctx == NULL) {
		return ldb_oom(samdb);
	}

	ret = ldb_search(samdb, tmp_ctx, &root_res,
			 ldb_dn_new(tmp_ctx, samdb, ""), LDB_SCOPE_BASE, root_attrs, NULL);
	if (ret != LDB_SUCCESS || root_res->count == 0) {
		DEBUG(1,("Searching for namingContexts in rootDSE failed: %s\n", ldb_errstring(samdb)));
		talloc_free(tmp_ctx);
		return ret;
	}

	el = ldb_msg_find_element(root_res->msgs[0], "namingContexts");
	if ((el == NULL) || (el->num_values < 3)) {
		struct ldb_message *tmp_msg;

		DEBUG(5,("dsdb_find_nc_root: Finding a valid 'namingContexts' element in the RootDSE failed. Using a temporary list.\n"));

		/* This generates a temporary list of NCs in order to let the
		 * provisioning work. */
		tmp_msg = ldb_msg_new(tmp_ctx);
		if (tmp_msg == NULL) {
			talloc_free(tmp_ctx);
			return ldb_oom(samdb);
		}
		ret = ldb_msg_add_steal_string(tmp_msg, "namingContexts",
					       ldb_dn_alloc_linearized(tmp_msg, ldb_get_schema_basedn(samdb)));
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}
		ret = ldb_msg_add_steal_string(tmp_msg, "namingContexts",
					       ldb_dn_alloc_linearized(tmp_msg, ldb_get_config_basedn(samdb)));
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}
		ret = ldb_msg_add_steal_string(tmp_msg, "namingContexts",
					       ldb_dn_alloc_linearized(tmp_msg, ldb_get_default_basedn(samdb)));
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}
		el = &tmp_msg->elements[0];
	}

       nc_dns = talloc_array(tmp_ctx, struct ldb_dn *, el->num_values);
       if (!nc_dns) {
	       talloc_free(tmp_ctx);
	       return ldb_oom(samdb);
       }

       for (i=0; i<el->num_values; i++) {
	       nc_dns[i] = ldb_dn_from_ldb_val(nc_dns, samdb, &el->values[i]);
	       if (nc_dns[i] == NULL) {
		       talloc_free(tmp_ctx);
		       return ldb_operr(samdb);
	       }
       }

       TYPESAFE_QSORT(nc_dns, el->num_values, dsdb_dn_compare_ptrs);

       for (i=0; i<el->num_values; i++) {
               if (ldb_dn_compare_base(nc_dns[i], dn) == 0) {
		       (*nc_root) = talloc_steal(mem_ctx, nc_dns[i]);
                       talloc_free(tmp_ctx);
                       return LDB_SUCCESS;
               }
       }

       talloc_free(tmp_ctx);
       return ldb_error(samdb, LDB_ERR_NO_SUCH_OBJECT, __func__);
}


/*
  find the deleted objects DN for any object, by looking for the NC
  root, then looking up the wellknown GUID
 */
int dsdb_get_deleted_objects_dn(struct ldb_context *ldb,
				TALLOC_CTX *mem_ctx, struct ldb_dn *obj_dn,
				struct ldb_dn **do_dn)
{
	struct ldb_dn *nc_root;
	int ret;

	ret = dsdb_find_nc_root(ldb, mem_ctx, obj_dn, &nc_root);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = dsdb_wellknown_dn(ldb, mem_ctx, nc_root, DS_GUID_DELETED_OBJECTS_CONTAINER, do_dn);
	talloc_free(nc_root);
	return ret;
}

/*
  return the tombstoneLifetime, in days
 */
int dsdb_tombstone_lifetime(struct ldb_context *ldb, uint32_t *lifetime)
{
	struct ldb_dn *dn;
	dn = ldb_get_config_basedn(ldb);
	if (!dn) {
		return ldb_error(ldb, LDB_ERR_NO_SUCH_OBJECT, __func__);
	}
	dn = ldb_dn_copy(ldb, dn);
	if (!dn) {
		return ldb_operr(ldb);
	}
	/* see MS-ADTS section 7.1.1.2.4.1.1. There doesn't appear to
	 be a wellknown GUID for this */
	if (!ldb_dn_add_child_fmt(dn, "CN=Directory Service,CN=Windows NT,CN=Services")) {
		talloc_free(dn);
		return ldb_operr(ldb);
	}

	*lifetime = samdb_search_uint(ldb, dn, 180, dn, "tombstoneLifetime", "objectClass=nTDSService");
	talloc_free(dn);
	return LDB_SUCCESS;
}

/*
  compare a ldb_val to a string case insensitively
 */
int samdb_ldb_val_case_cmp(const char *s, struct ldb_val *v)
{
	size_t len = strlen(s);
	int ret;
	if (len > v->length) return 1;
	ret = strncasecmp(s, (const char *)v->data, v->length);
	if (ret != 0) return ret;
	if (v->length > len && v->data[len] != 0) {
		return -1;
	}
	return 0;
}


/*
  load the UDV for a partition in v2 format
  The list is returned sorted, and with our local cursor added
 */
int dsdb_load_udv_v2(struct ldb_context *samdb, struct ldb_dn *dn, TALLOC_CTX *mem_ctx,
		     struct drsuapi_DsReplicaCursor2 **cursors, uint32_t *count)
{
	static const char *attrs[] = { "replUpToDateVector", NULL };
	struct ldb_result *r = NULL;
	const struct ldb_val *ouv_value;
	unsigned int i;
	int ret;
	uint64_t highest_usn = 0;
	const struct GUID *our_invocation_id;
	static const struct timeval tv1970;
	NTTIME nt1970 = timeval_to_nttime(&tv1970);

	ret = dsdb_search_dn(samdb, mem_ctx, &r, dn, attrs, DSDB_SEARCH_SHOW_RECYCLED|DSDB_SEARCH_SHOW_DELETED);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	/* fix clang warning */
	if (r == NULL) {
		return LDB_ERR_OTHER;
	}
	ouv_value = ldb_msg_find_ldb_val(r->msgs[0], "replUpToDateVector");
	if (ouv_value) {
		enum ndr_err_code ndr_err;
		struct replUpToDateVectorBlob ouv;

		ndr_err = ndr_pull_struct_blob(ouv_value, r, &ouv,
					       (ndr_pull_flags_fn_t)ndr_pull_replUpToDateVectorBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(r);
			return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
		}
		if (ouv.version != 2) {
			/* we always store as version 2, and
			 * replUpToDateVector is not replicated
			 */
			return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
		}

		*count = ouv.ctr.ctr2.count;
		*cursors = talloc_steal(mem_ctx, ouv.ctr.ctr2.cursors);
	} else {
		*count = 0;
		*cursors = NULL;
	}

	talloc_free(r);

	our_invocation_id = samdb_ntds_invocation_id(samdb);
	if (!our_invocation_id) {
		DEBUG(0,(__location__ ": No invocationID on samdb - %s\n", ldb_errstring(samdb)));
		talloc_free(*cursors);
		return ldb_operr(samdb);
	}

	ret = ldb_sequence_number(samdb, LDB_SEQ_HIGHEST_SEQ, &highest_usn);
	if (ret != LDB_SUCCESS) {
		/* nothing to add - this can happen after a vampire */
		TYPESAFE_QSORT(*cursors, *count, drsuapi_DsReplicaCursor2_compare);
		return LDB_SUCCESS;
	}

	for (i=0; i<*count; i++) {
		if (GUID_equal(our_invocation_id, &(*cursors)[i].source_dsa_invocation_id)) {
			(*cursors)[i].highest_usn = highest_usn;
			(*cursors)[i].last_sync_success = nt1970;
			TYPESAFE_QSORT(*cursors, *count, drsuapi_DsReplicaCursor2_compare);
			return LDB_SUCCESS;
		}
	}

	(*cursors) = talloc_realloc(mem_ctx, *cursors, struct drsuapi_DsReplicaCursor2, (*count)+1);
	if (! *cursors) {
		return ldb_oom(samdb);
	}

	(*cursors)[*count].source_dsa_invocation_id = *our_invocation_id;
	(*cursors)[*count].highest_usn = highest_usn;
	(*cursors)[*count].last_sync_success = nt1970;
	(*count)++;

	TYPESAFE_QSORT(*cursors, *count, drsuapi_DsReplicaCursor2_compare);

	return LDB_SUCCESS;
}

/*
  load the UDV for a partition in version 1 format
  The list is returned sorted, and with our local cursor added
 */
int dsdb_load_udv_v1(struct ldb_context *samdb, struct ldb_dn *dn, TALLOC_CTX *mem_ctx,
		     struct drsuapi_DsReplicaCursor **cursors, uint32_t *count)
{
	struct drsuapi_DsReplicaCursor2 *v2 = NULL;
	uint32_t i;
	int ret;

	ret = dsdb_load_udv_v2(samdb, dn, mem_ctx, &v2, count);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (*count == 0) {
		talloc_free(v2);
		*cursors = NULL;
		return LDB_SUCCESS;
	}

	*cursors = talloc_array(mem_ctx, struct drsuapi_DsReplicaCursor, *count);
	if (*cursors == NULL) {
		talloc_free(v2);
		return ldb_oom(samdb);
	}

	for (i=0; i<*count; i++) {
		(*cursors)[i].source_dsa_invocation_id = v2[i].source_dsa_invocation_id;
		(*cursors)[i].highest_usn = v2[i].highest_usn;
	}
	talloc_free(v2);
	return LDB_SUCCESS;
}

/*
  add a set of controls to a ldb_request structure based on a set of
  flags. See util.h for a list of available flags
 */
int dsdb_request_add_controls(struct ldb_request *req, uint32_t dsdb_flags)
{
	int ret;
	if (dsdb_flags & DSDB_SEARCH_SEARCH_ALL_PARTITIONS) {
		struct ldb_search_options_control *options;
		/* Using the phantom root control allows us to search all partitions */
		options = talloc(req, struct ldb_search_options_control);
		if (options == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		options->search_options = LDB_SEARCH_OPTION_PHANTOM_ROOT;

		ret = ldb_request_add_control(req,
					      LDB_CONTROL_SEARCH_OPTIONS_OID,
					      true, options);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_SEARCH_NO_GLOBAL_CATALOG) {
		ret = ldb_request_add_control(req,
					      DSDB_CONTROL_NO_GLOBAL_CATALOG,
					      false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_SEARCH_SHOW_DELETED) {
		ret = ldb_request_add_control(req, LDB_CONTROL_SHOW_DELETED_OID, true, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_SEARCH_SHOW_RECYCLED) {
		ret = ldb_request_add_control(req, LDB_CONTROL_SHOW_RECYCLED_OID, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT) {
		ret = ldb_request_add_control(req, DSDB_CONTROL_DN_STORAGE_FORMAT_OID, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_SEARCH_SHOW_EXTENDED_DN) {
		struct ldb_extended_dn_control *extended_ctrl = talloc(req, struct ldb_extended_dn_control);
		if (!extended_ctrl) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		extended_ctrl->type = 1;

		ret = ldb_request_add_control(req, LDB_CONTROL_EXTENDED_DN_OID, true, extended_ctrl);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_SEARCH_REVEAL_INTERNALS) {
		ret = ldb_request_add_control(req, LDB_CONTROL_REVEAL_INTERNALS, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_MODIFY_RELAX) {
		ret = ldb_request_add_control(req, LDB_CONTROL_RELAX_OID, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_MODIFY_PERMISSIVE) {
		ret = ldb_request_add_control(req, LDB_CONTROL_PERMISSIVE_MODIFY_OID, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_FLAG_AS_SYSTEM) {
		ret = ldb_request_add_control(req, LDB_CONTROL_AS_SYSTEM_OID, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_TREE_DELETE) {
		ret = ldb_request_add_control(req, LDB_CONTROL_TREE_DELETE_OID, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_PROVISION) {
		ret = ldb_request_add_control(req, LDB_CONTROL_PROVISION_OID, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	/* This is a special control to bypass the password_hash module for use in pdb_samba4 for Samba3 upgrades */
	if (dsdb_flags & DSDB_BYPASS_PASSWORD_HASH) {
		ret = ldb_request_add_control(req, DSDB_CONTROL_BYPASS_PASSWORD_HASH_OID, true, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_PASSWORD_BYPASS_LAST_SET) {
		/* 
		 * This must not be critical, as it will only be
		 * handled (and need to be handled) if the other
		 * attributes in the request bring password_hash into
		 * action
		 */
		ret = ldb_request_add_control(req, DSDB_CONTROL_PASSWORD_BYPASS_LAST_SET_OID, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_REPLMD_VANISH_LINKS) {
		ret = ldb_request_add_control(req, DSDB_CONTROL_REPLMD_VANISH_LINKS, true, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_MODIFY_PARTIAL_REPLICA) {
		ret = ldb_request_add_control(req, DSDB_CONTROL_PARTIAL_REPLICA, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_FLAG_REPLICATED_UPDATE) {
		ret = ldb_request_add_control(req, DSDB_CONTROL_REPLICATED_UPDATE_OID, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return LDB_SUCCESS;
}

/*
   returns true if a control with the specified "oid" exists
*/
bool dsdb_request_has_control(struct ldb_request *req, const char *oid)
{
	return (ldb_request_get_control(req, oid) != NULL);
}

/*
  an add with a set of controls
*/
int dsdb_add(struct ldb_context *ldb, const struct ldb_message *message,
	     uint32_t dsdb_flags)
{
	struct ldb_request *req;
	int ret;

	ret = ldb_build_add_req(&req, ldb, ldb,
				message,
				NULL,
				NULL,
				ldb_op_default_callback,
				NULL);

	if (ret != LDB_SUCCESS) return ret;

	ret = dsdb_request_add_controls(req, dsdb_flags);
	if (ret != LDB_SUCCESS) {
		talloc_free(req);
		return ret;
	}

	ret = dsdb_autotransaction_request(ldb, req);

	talloc_free(req);
	return ret;
}

/*
  a modify with a set of controls
*/
int dsdb_modify(struct ldb_context *ldb, const struct ldb_message *message,
		uint32_t dsdb_flags)
{
	struct ldb_request *req;
	int ret;

	ret = ldb_build_mod_req(&req, ldb, ldb,
				message,
				NULL,
				NULL,
				ldb_op_default_callback,
				NULL);

	if (ret != LDB_SUCCESS) return ret;

	ret = dsdb_request_add_controls(req, dsdb_flags);
	if (ret != LDB_SUCCESS) {
		talloc_free(req);
		return ret;
	}

	ret = dsdb_autotransaction_request(ldb, req);

	talloc_free(req);
	return ret;
}

/*
  a delete with a set of flags
*/
int dsdb_delete(struct ldb_context *ldb, struct ldb_dn *dn,
		uint32_t dsdb_flags)
{
	struct ldb_request *req;
	int ret;

	ret = ldb_build_del_req(&req, ldb, ldb,
				dn,
				NULL,
				NULL,
				ldb_op_default_callback,
				NULL);

	if (ret != LDB_SUCCESS) return ret;

	ret = dsdb_request_add_controls(req, dsdb_flags);
	if (ret != LDB_SUCCESS) {
		talloc_free(req);
		return ret;
	}

	ret = dsdb_autotransaction_request(ldb, req);

	talloc_free(req);
	return ret;
}

/*
  like dsdb_modify() but set all the element flags to
  LDB_FLAG_MOD_REPLACE
 */
int dsdb_replace(struct ldb_context *ldb, struct ldb_message *msg, uint32_t dsdb_flags)
{
	unsigned int i;

	/* mark all the message elements as LDB_FLAG_MOD_REPLACE */
	for (i=0;i<msg->num_elements;i++) {
		msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
	}

	return dsdb_modify(ldb, msg, dsdb_flags);
}


/*
  search for attrs on one DN, allowing for dsdb_flags controls
 */
int dsdb_search_dn(struct ldb_context *ldb,
		   TALLOC_CTX *mem_ctx,
		   struct ldb_result **_result,
		   struct ldb_dn *basedn,
		   const char * const *attrs,
		   uint32_t dsdb_flags)
{
	int ret;
	struct ldb_request *req;
	struct ldb_result *res;

	res = talloc_zero(mem_ctx, struct ldb_result);
	if (!res) {
		return ldb_oom(ldb);
	}

	ret = ldb_build_search_req(&req, ldb, res,
				   basedn,
				   LDB_SCOPE_BASE,
				   NULL,
				   attrs,
				   NULL,
				   res,
				   ldb_search_default_callback,
				   NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(res);
		return ret;
	}

	ret = dsdb_request_add_controls(req, dsdb_flags);
	if (ret != LDB_SUCCESS) {
		talloc_free(res);
		return ret;
	}

	ret = ldb_request(ldb, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	talloc_free(req);
	if (ret != LDB_SUCCESS) {
		talloc_free(res);
		return ret;
	}

	*_result = res;
	return LDB_SUCCESS;
}

/*
  search for attrs on one DN, by the GUID of the DN, allowing for
  dsdb_flags controls
 */
int dsdb_search_by_dn_guid(struct ldb_context *ldb,
			   TALLOC_CTX *mem_ctx,
			   struct ldb_result **_result,
			   const struct GUID *guid,
			   const char * const *attrs,
			   uint32_t dsdb_flags)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct ldb_dn *dn;
	int ret;

	dn = ldb_dn_new_fmt(tmp_ctx, ldb, "<GUID=%s>", GUID_string(tmp_ctx, guid));
	if (dn == NULL) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	ret = dsdb_search_dn(ldb, mem_ctx, _result, dn, attrs, dsdb_flags);
	talloc_free(tmp_ctx);
	return ret;
}

/*
  general search with dsdb_flags for controls
 */
int dsdb_search(struct ldb_context *ldb,
		TALLOC_CTX *mem_ctx,
		struct ldb_result **_result,
		struct ldb_dn *basedn,
		enum ldb_scope scope,
		const char * const *attrs,
		uint32_t dsdb_flags,
		const char *exp_fmt, ...) _PRINTF_ATTRIBUTE(8, 9)
{
	int ret;
	struct ldb_request *req;
	struct ldb_result *res;
	va_list ap;
	char *expression = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	/* cross-partitions searches with a basedn break multi-domain support */
	SMB_ASSERT(basedn == NULL || (dsdb_flags & DSDB_SEARCH_SEARCH_ALL_PARTITIONS) == 0);

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	if (exp_fmt) {
		va_start(ap, exp_fmt);
		expression = talloc_vasprintf(tmp_ctx, exp_fmt, ap);
		va_end(ap);

		if (!expression) {
			talloc_free(tmp_ctx);
			return ldb_oom(ldb);
		}
	}

	ret = ldb_build_search_req(&req, ldb, tmp_ctx,
				   basedn,
				   scope,
				   expression,
				   attrs,
				   NULL,
				   res,
				   ldb_search_default_callback,
				   NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_request_add_controls(req, dsdb_flags);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		ldb_reset_err_string(ldb);
		return ret;
	}

	ret = ldb_request(ldb, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	if (dsdb_flags & DSDB_SEARCH_ONE_ONLY) {
		if (res->count == 0) {
			talloc_free(tmp_ctx);
			ldb_reset_err_string(ldb);
			return ldb_error(ldb, LDB_ERR_NO_SUCH_OBJECT, __func__);
		}
		if (res->count != 1) {
			talloc_free(tmp_ctx);
			ldb_reset_err_string(ldb);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
	}

	*_result = talloc_steal(mem_ctx, res);
	talloc_free(tmp_ctx);

	return LDB_SUCCESS;
}


/*
  general search with dsdb_flags for controls
  returns exactly 1 record or an error
 */
int dsdb_search_one(struct ldb_context *ldb,
		    TALLOC_CTX *mem_ctx,
		    struct ldb_message **msg,
		    struct ldb_dn *basedn,
		    enum ldb_scope scope,
		    const char * const *attrs,
		    uint32_t dsdb_flags,
		    const char *exp_fmt, ...) _PRINTF_ATTRIBUTE(8, 9)
{
	int ret;
	struct ldb_result *res;
	va_list ap;
	char *expression = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	dsdb_flags |= DSDB_SEARCH_ONE_ONLY;

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	if (exp_fmt) {
		va_start(ap, exp_fmt);
		expression = talloc_vasprintf(tmp_ctx, exp_fmt, ap);
		va_end(ap);

		if (!expression) {
			talloc_free(tmp_ctx);
			return ldb_oom(ldb);
		}
		ret = dsdb_search(ldb, tmp_ctx, &res, basedn, scope, attrs,
				  dsdb_flags, "%s", expression);
	} else {
		ret = dsdb_search(ldb, tmp_ctx, &res, basedn, scope, attrs,
				  dsdb_flags, NULL);
	}

	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	*msg = talloc_steal(mem_ctx, res->msgs[0]);
	talloc_free(tmp_ctx);

	return LDB_SUCCESS;
}

/* returns back the forest DNS name */
const char *samdb_forest_name(struct ldb_context *ldb, TALLOC_CTX *mem_ctx)
{
	const char *forest_name = ldb_dn_canonical_string(mem_ctx,
							  ldb_get_root_basedn(ldb));
	char *p;

	if (forest_name == NULL) {
		return NULL;
	}

	p = strchr(forest_name, '/');
	if (p) {
		*p = '\0';
	}

	return forest_name;
}

/* returns back the default domain DNS name */
const char *samdb_default_domain_name(struct ldb_context *ldb, TALLOC_CTX *mem_ctx)
{
	const char *domain_name = ldb_dn_canonical_string(mem_ctx,
							  ldb_get_default_basedn(ldb));
	char *p;

	if (domain_name == NULL) {
		return NULL;
	}

	p = strchr(domain_name, '/');
	if (p) {
		*p = '\0';
	}

	return domain_name;
}

/*
   validate that an DSA GUID belongs to the specified user sid.
   The user SID must be a domain controller account (either RODC or
   RWDC)
 */
int dsdb_validate_dsa_guid(struct ldb_context *ldb,
			   const struct GUID *dsa_guid,
			   const struct dom_sid *sid)
{
	/* strategy:
	    - find DN of record with the DSA GUID in the
	      configuration partition (objectGUID)
            - remove "NTDS Settings" component from DN
	    - do a base search on that DN for serverReference with
	      extended-dn enabled
            - extract objectSid from resulting serverReference
              attribute
	    - check this sid matches the sid argument
	*/
	struct ldb_dn *config_dn;
	TALLOC_CTX *tmp_ctx = talloc_new(ldb);
	struct ldb_message *msg;
	const char *attrs1[] = { NULL };
	const char *attrs2[] = { "serverReference", NULL };
	int ret;
	struct ldb_dn *dn, *account_dn;
	struct dom_sid sid2;
	NTSTATUS status;

	config_dn = ldb_get_config_basedn(ldb);

	ret = dsdb_search_one(ldb, tmp_ctx, &msg, config_dn, LDB_SCOPE_SUBTREE,
			      attrs1, 0, "(&(objectGUID=%s)(objectClass=nTDSDSA))", GUID_string(tmp_ctx, dsa_guid));
	if (ret != LDB_SUCCESS) {
		DEBUG(1,(__location__ ": Failed to find DSA objectGUID %s for sid %s\n",
			 GUID_string(tmp_ctx, dsa_guid), dom_sid_string(tmp_ctx, sid)));
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}
	dn = msg->dn;

	if (!ldb_dn_remove_child_components(dn, 1)) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	ret = dsdb_search_one(ldb, tmp_ctx, &msg, dn, LDB_SCOPE_BASE,
			      attrs2, DSDB_SEARCH_SHOW_EXTENDED_DN,
			      "(objectClass=server)");
	if (ret != LDB_SUCCESS) {
		DEBUG(1,(__location__ ": Failed to find server record for DSA with objectGUID %s, sid %s\n",
			 GUID_string(tmp_ctx, dsa_guid), dom_sid_string(tmp_ctx, sid)));
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	account_dn = ldb_msg_find_attr_as_dn(ldb, tmp_ctx, msg, "serverReference");
	if (account_dn == NULL) {
		DEBUG(1,(__location__ ": Failed to find account dn "
			 "(serverReference) for %s, parent of DSA with "
			 "objectGUID %s, sid %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 GUID_string(tmp_ctx, dsa_guid),
			 dom_sid_string(tmp_ctx, sid)));
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	status = dsdb_get_extended_dn_sid(account_dn, &sid2, "SID");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,(__location__ ": Failed to find SID for DSA with objectGUID %s, sid %s\n",
			 GUID_string(tmp_ctx, dsa_guid), dom_sid_string(tmp_ctx, sid)));
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	if (!dom_sid_equal(sid, &sid2)) {
		/* someone is trying to spoof another account */
		DEBUG(0,(__location__ ": Bad DSA objectGUID %s for sid %s - expected sid %s\n",
			 GUID_string(tmp_ctx, dsa_guid),
			 dom_sid_string(tmp_ctx, sid),
			 dom_sid_string(tmp_ctx, &sid2)));
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}

static const char * const secret_attributes[] = {
	DSDB_SECRET_ATTRIBUTES,
	NULL
};

/*
  check if the attribute belongs to the RODC filtered attribute set
  Note that attributes that are in the filtered attribute set are the
  ones that _are_ always sent to a RODC
*/
bool dsdb_attr_in_rodc_fas(const struct dsdb_attribute *sa)
{
	/* they never get secret attributes */
	if (is_attr_in_list(secret_attributes, sa->lDAPDisplayName)) {
		return false;
	}

	/* they do get non-secret critical attributes */
	if (sa->schemaFlagsEx & SCHEMA_FLAG_ATTR_IS_CRITICAL) {
		return true;
	}

	/* they do get non-secret attributes marked as being in the FAS  */
	if (sa->searchFlags & SEARCH_FLAG_RODC_ATTRIBUTE) {
		return true;
	}

	/* other attributes are denied */
	return false;
}

/* return fsmo role dn and role owner dn for a particular role*/
WERROR dsdb_get_fsmo_role_info(TALLOC_CTX *tmp_ctx,
			       struct ldb_context *ldb,
			       uint32_t role,
			       struct ldb_dn **fsmo_role_dn,
			       struct ldb_dn **role_owner_dn)
{
	int ret;
	switch (role) {
	case DREPL_NAMING_MASTER:
		*fsmo_role_dn = samdb_partitions_dn(ldb, tmp_ctx);
		ret = samdb_reference_dn(ldb, tmp_ctx, *fsmo_role_dn, "fSMORoleOwner", role_owner_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in Naming Master object - %s",
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		break;
	case DREPL_INFRASTRUCTURE_MASTER:
		*fsmo_role_dn = samdb_infrastructure_dn(ldb, tmp_ctx);
		ret = samdb_reference_dn(ldb, tmp_ctx, *fsmo_role_dn, "fSMORoleOwner", role_owner_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in Schema Master object - %s",
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		break;
	case DREPL_RID_MASTER:
		ret = samdb_rid_manager_dn(ldb, tmp_ctx, fsmo_role_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0, (__location__ ": Failed to find RID Manager object - %s", ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		ret = samdb_reference_dn(ldb, tmp_ctx, *fsmo_role_dn, "fSMORoleOwner", role_owner_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in RID Manager object - %s",
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		break;
	case DREPL_SCHEMA_MASTER:
		*fsmo_role_dn = ldb_get_schema_basedn(ldb);
		ret = samdb_reference_dn(ldb, tmp_ctx, *fsmo_role_dn, "fSMORoleOwner", role_owner_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in Schema Master object - %s",
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		break;
	case DREPL_PDC_MASTER:
		*fsmo_role_dn = ldb_get_default_basedn(ldb);
		ret = samdb_reference_dn(ldb, tmp_ctx, *fsmo_role_dn, "fSMORoleOwner", role_owner_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in Pd Master object - %s",
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		break;
	default:
		return WERR_DS_DRA_INTERNAL_ERROR;
	}
	return WERR_OK;
}

const char *samdb_dn_to_dnshostname(struct ldb_context *ldb,
				    TALLOC_CTX *mem_ctx,
				    struct ldb_dn *server_dn)
{
	int ldb_ret;
	struct ldb_result *res = NULL;
	const char * const attrs[] = { "dNSHostName", NULL};

	ldb_ret = ldb_search(ldb, mem_ctx, &res,
			     server_dn,
			     LDB_SCOPE_BASE,
			     attrs, NULL);
	if (ldb_ret != LDB_SUCCESS) {
		DEBUG(4, ("Failed to find dNSHostName for dn %s, ldb error: %s",
			  ldb_dn_get_linearized(server_dn), ldb_errstring(ldb)));
		return NULL;
	}

	return ldb_msg_find_attr_as_string(res->msgs[0], "dNSHostName", NULL);
}

/*
  returns true if an attribute is in the filter,
  false otherwise, provided that attribute value is provided with the expression
*/
bool dsdb_attr_in_parse_tree(struct ldb_parse_tree *tree,
			     const char *attr)
{
       unsigned int i;
       switch (tree->operation) {
       case LDB_OP_AND:
       case LDB_OP_OR:
               for (i=0;i<tree->u.list.num_elements;i++) {
                       if (dsdb_attr_in_parse_tree(tree->u.list.elements[i],
                                                       attr))
                               return true;
               }
               return false;
       case LDB_OP_NOT:
               return dsdb_attr_in_parse_tree(tree->u.isnot.child, attr);
       case LDB_OP_EQUALITY:
       case LDB_OP_GREATER:
       case LDB_OP_LESS:
       case LDB_OP_APPROX:
               if (ldb_attr_cmp(tree->u.equality.attr, attr) == 0) {
                       return true;
               }
               return false;
       case LDB_OP_SUBSTRING:
               if (ldb_attr_cmp(tree->u.substring.attr, attr) == 0) {
                       return true;
               }
               return false;
       case LDB_OP_PRESENT:
	       /* (attrname=*) is not filtered out */
               return false;
       case LDB_OP_EXTENDED:
               if (tree->u.extended.attr &&
                   ldb_attr_cmp(tree->u.extended.attr, attr) == 0) {
		       return true;
               }
               return false;
       }
       return false;
}

bool is_attr_in_list(const char * const * attrs, const char *attr)
{
	unsigned int i;

	for (i = 0; attrs[i]; i++) {
		if (ldb_attr_cmp(attrs[i], attr) == 0)
			return true;
	}

	return false;
}

int dsdb_werror_at(struct ldb_context *ldb, int ldb_ecode, WERROR werr,
		   const char *location, const char *func,
		   const char *reason)
{
	if (reason == NULL) {
		reason = win_errstr(werr);
	}
	ldb_asprintf_errstring(ldb, "%08X: %s at %s:%s",
			       W_ERROR_V(werr), reason, location, func);
	return ldb_ecode;
}

/*
  map an ldb error code to an approximate NTSTATUS code
 */
NTSTATUS dsdb_ldb_err_to_ntstatus(int err)
{
	switch (err) {
	case LDB_SUCCESS:
		return NT_STATUS_OK;

	case LDB_ERR_PROTOCOL_ERROR:
		return NT_STATUS_DEVICE_PROTOCOL_ERROR;

	case LDB_ERR_TIME_LIMIT_EXCEEDED:
		return NT_STATUS_IO_TIMEOUT;

	case LDB_ERR_SIZE_LIMIT_EXCEEDED:
		return NT_STATUS_BUFFER_TOO_SMALL;

	case LDB_ERR_COMPARE_FALSE:
	case LDB_ERR_COMPARE_TRUE:
		return NT_STATUS_REVISION_MISMATCH;

	case LDB_ERR_AUTH_METHOD_NOT_SUPPORTED:
		return NT_STATUS_NOT_SUPPORTED;

	case LDB_ERR_STRONG_AUTH_REQUIRED:
	case LDB_ERR_CONFIDENTIALITY_REQUIRED:
	case LDB_ERR_SASL_BIND_IN_PROGRESS:
	case LDB_ERR_INAPPROPRIATE_AUTHENTICATION:
	case LDB_ERR_INVALID_CREDENTIALS:
	case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
	case LDB_ERR_UNWILLING_TO_PERFORM:
		return NT_STATUS_ACCESS_DENIED;

	case LDB_ERR_NO_SUCH_OBJECT:
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	case LDB_ERR_REFERRAL:
	case LDB_ERR_NO_SUCH_ATTRIBUTE:
		return NT_STATUS_NOT_FOUND;

	case LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION:
		return NT_STATUS_NOT_SUPPORTED;

	case LDB_ERR_ADMIN_LIMIT_EXCEEDED:
		return NT_STATUS_BUFFER_TOO_SMALL;

	case LDB_ERR_UNDEFINED_ATTRIBUTE_TYPE:
	case LDB_ERR_INAPPROPRIATE_MATCHING:
	case LDB_ERR_CONSTRAINT_VIOLATION:
	case LDB_ERR_INVALID_ATTRIBUTE_SYNTAX:
	case LDB_ERR_INVALID_DN_SYNTAX:
	case LDB_ERR_NAMING_VIOLATION:
	case LDB_ERR_OBJECT_CLASS_VIOLATION:
	case LDB_ERR_NOT_ALLOWED_ON_NON_LEAF:
	case LDB_ERR_NOT_ALLOWED_ON_RDN:
		return NT_STATUS_INVALID_PARAMETER;

	case LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS:
	case LDB_ERR_ENTRY_ALREADY_EXISTS:
		return NT_STATUS_ERROR_DS_OBJ_STRING_NAME_EXISTS;

	case LDB_ERR_BUSY:
		return NT_STATUS_NETWORK_BUSY;

	case LDB_ERR_ALIAS_PROBLEM:
	case LDB_ERR_ALIAS_DEREFERENCING_PROBLEM:
	case LDB_ERR_UNAVAILABLE:
	case LDB_ERR_LOOP_DETECT:
	case LDB_ERR_OBJECT_CLASS_MODS_PROHIBITED:
	case LDB_ERR_AFFECTS_MULTIPLE_DSAS:
	case LDB_ERR_OTHER:
	case LDB_ERR_OPERATIONS_ERROR:
		break;
	}
	return NT_STATUS_UNSUCCESSFUL;
}


/*
  create a new naming context that will hold a partial replica
 */
int dsdb_create_partial_replica_NC(struct ldb_context *ldb,  struct ldb_dn *dn)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ldb);
	struct ldb_message *msg;
	int ret;

	msg = ldb_msg_new(tmp_ctx);
	if (msg == NULL) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	msg->dn = dn;
	ret = ldb_msg_add_string(msg, "objectClass", "top");
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	/* [MS-DRSR] implies that we should only add the 'top'
	 * objectclass, but that would cause lots of problems with our
	 * objectclass code as top is not structural, so we add
	 * 'domainDNS' as well to keep things sane. We're expecting
	 * this new NC to be of objectclass domainDNS after
	 * replication anyway
	 */
	ret = ldb_msg_add_string(msg, "objectClass", "domainDNS");
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	ret = ldb_msg_add_fmt(msg, "instanceType", "%u",
			      INSTANCE_TYPE_IS_NC_HEAD|
			      INSTANCE_TYPE_NC_ABOVE|
			      INSTANCE_TYPE_UNINSTANT);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	ret = dsdb_add(ldb, msg, DSDB_MODIFY_PARTIAL_REPLICA);
	if (ret != LDB_SUCCESS && ret != LDB_ERR_ENTRY_ALREADY_EXISTS) {
		DEBUG(0,("Failed to create new NC for %s - %s (%s)\n",
			 ldb_dn_get_linearized(dn),
			 ldb_errstring(ldb), ldb_strerror(ret)));
		talloc_free(tmp_ctx);
		return ret;
	}

	DEBUG(1,("Created new NC for %s\n", ldb_dn_get_linearized(dn)));

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}

/*
 * Return the effective badPwdCount
 *
 * This requires that the user_msg have (if present):
 *  - badPasswordTime
 *  - badPwdCount
 *
 * This also requires that the domain_msg have (if present):
 *  - lockOutObservationWindow
 */
static int dsdb_effective_badPwdCount(const struct ldb_message *user_msg,
				      int64_t lockOutObservationWindow,
				      NTTIME now)
{
	int64_t badPasswordTime;
	badPasswordTime = ldb_msg_find_attr_as_int64(user_msg, "badPasswordTime", 0);

	if (badPasswordTime - lockOutObservationWindow >= now) {
		return ldb_msg_find_attr_as_int(user_msg, "badPwdCount", 0);
	} else {
		return 0;
	}
}

/*
 * Returns a user's PSO, or NULL if none was found
 */
static struct ldb_result *lookup_user_pso(struct ldb_context *sam_ldb,
					  TALLOC_CTX *mem_ctx,
					  const struct ldb_message *user_msg,
					  const char * const *attrs)
{
	struct ldb_result *res = NULL;
	struct ldb_dn *pso_dn = NULL;
	int ret;

	/* if the user has a PSO that applies, then use the PSO's setting */
	pso_dn = ldb_msg_find_attr_as_dn(sam_ldb, mem_ctx, user_msg,
					 "msDS-ResultantPSO");

	if (pso_dn != NULL) {

		ret = dsdb_search_dn(sam_ldb, mem_ctx, &res, pso_dn, attrs, 0);
		if (ret != LDB_SUCCESS) {

			/*
			 * log the error. The caller should fallback to using
			 * the default domain password settings
			 */
			DBG_ERR("Error retrieving msDS-ResultantPSO %s for %s",
				ldb_dn_get_linearized(pso_dn),
				ldb_dn_get_linearized(user_msg->dn));
		}
		talloc_free(pso_dn);
	}
	return res;
}

/*
 * Return the effective badPwdCount
 *
 * This requires that the user_msg have (if present):
 *  - badPasswordTime
 *  - badPwdCount
 *  - msDS-ResultantPSO
 */
int samdb_result_effective_badPwdCount(struct ldb_context *sam_ldb,
				       TALLOC_CTX *mem_ctx,
				       struct ldb_dn *domain_dn,
				       const struct ldb_message *user_msg)
{
	struct timeval tv_now = timeval_current();
	NTTIME now = timeval_to_nttime(&tv_now);
	int64_t lockOutObservationWindow;
	struct ldb_result *res = NULL;
	const char *attrs[] = { "msDS-LockoutObservationWindow",
				NULL };

	res = lookup_user_pso(sam_ldb, mem_ctx, user_msg, attrs);

	if (res != NULL) {
		lockOutObservationWindow =
			ldb_msg_find_attr_as_int64(res->msgs[0],
						   "msDS-LockoutObservationWindow",
						    DEFAULT_OBSERVATION_WINDOW);
		talloc_free(res);
	} else {

		/* no PSO was found, lookup the default domain setting */
		lockOutObservationWindow =
			 samdb_search_int64(sam_ldb, mem_ctx, 0, domain_dn,
					    "lockOutObservationWindow", NULL);
	}

	return dsdb_effective_badPwdCount(user_msg, lockOutObservationWindow, now);
}

/*
 * Returns the lockoutThreshold that applies. If a PSO is specified, then that
 * setting is used over the domain defaults
 */
static int64_t get_lockout_threshold(struct ldb_message *domain_msg,
				     struct ldb_message *pso_msg)
{
	if (pso_msg != NULL) {
		return ldb_msg_find_attr_as_int(pso_msg,
						"msDS-LockoutThreshold", 0);
	} else {
		return ldb_msg_find_attr_as_int(domain_msg,
						"lockoutThreshold", 0);
	}
}

/*
 * Returns the lockOutObservationWindow that applies. If a PSO is specified,
 * then that setting is used over the domain defaults
 */
static int64_t get_lockout_observation_window(struct ldb_message *domain_msg,
					      struct ldb_message *pso_msg)
{
	if (pso_msg != NULL) {
		return ldb_msg_find_attr_as_int64(pso_msg,
						  "msDS-LockoutObservationWindow",
						   DEFAULT_OBSERVATION_WINDOW);
	} else {
		return ldb_msg_find_attr_as_int64(domain_msg,
						  "lockOutObservationWindow",
						   DEFAULT_OBSERVATION_WINDOW);
	}
}

/*
 * Prepare an update to the badPwdCount and associated attributes.
 *
 * This requires that the user_msg have (if present):
 *  - objectSid
 *  - badPasswordTime
 *  - badPwdCount
 *
 * This also requires that the domain_msg have (if present):
 *  - pwdProperties
 *  - lockoutThreshold
 *  - lockOutObservationWindow
 *
 * This also requires that the pso_msg have (if present):
 *  - msDS-LockoutThreshold
 *  - msDS-LockoutObservationWindow
 */
NTSTATUS dsdb_update_bad_pwd_count(TALLOC_CTX *mem_ctx,
				   struct ldb_context *sam_ctx,
				   struct ldb_message *user_msg,
				   struct ldb_message *domain_msg,
				   struct ldb_message *pso_msg,
				   struct ldb_message **_mod_msg)
{
	int ret, badPwdCount;
	unsigned int i;
	int64_t lockoutThreshold, lockOutObservationWindow;
	struct dom_sid *sid;
	struct timeval tv_now = timeval_current();
	NTTIME now = timeval_to_nttime(&tv_now);
	NTSTATUS status;
	uint32_t pwdProperties, rid = 0;
	struct ldb_message *mod_msg;

	sid = samdb_result_dom_sid(mem_ctx, user_msg, "objectSid");

	pwdProperties = ldb_msg_find_attr_as_uint(domain_msg,
						  "pwdProperties", -1);
	if (sid && !(pwdProperties & DOMAIN_PASSWORD_LOCKOUT_ADMINS)) {
		status = dom_sid_split_rid(NULL, sid, NULL, &rid);
		if (!NT_STATUS_IS_OK(status)) {
			/*
			 * This can't happen anyway, but always try
			 * and update the badPwdCount on failure
			 */
			rid = 0;
		}
	}
	TALLOC_FREE(sid);

	/*
	 * Work out if we are doing password lockout on the domain.
	 * Also, the built in administrator account is exempt:
	 * http://msdn.microsoft.com/en-us/library/windows/desktop/aa375371%28v=vs.85%29.aspx
	 */
	lockoutThreshold = get_lockout_threshold(domain_msg, pso_msg);
	if (lockoutThreshold == 0 || (rid == DOMAIN_RID_ADMINISTRATOR)) {
		DEBUG(5, ("Not updating badPwdCount on %s after wrong password\n",
			  ldb_dn_get_linearized(user_msg->dn)));
		return NT_STATUS_OK;
	}

	mod_msg = ldb_msg_new(mem_ctx);
	if (mod_msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	mod_msg->dn = ldb_dn_copy(mod_msg, user_msg->dn);
	if (mod_msg->dn == NULL) {
		TALLOC_FREE(mod_msg);
		return NT_STATUS_NO_MEMORY;
	}

	lockOutObservationWindow = get_lockout_observation_window(domain_msg,
								  pso_msg);

	badPwdCount = dsdb_effective_badPwdCount(user_msg, lockOutObservationWindow, now);

	badPwdCount++;

	ret = samdb_msg_add_int(sam_ctx, mod_msg, mod_msg, "badPwdCount", badPwdCount);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(mod_msg);
		return NT_STATUS_NO_MEMORY;
	}
	ret = samdb_msg_add_int64(sam_ctx, mod_msg, mod_msg, "badPasswordTime", now);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(mod_msg);
		return NT_STATUS_NO_MEMORY;
	}

	if (badPwdCount >= lockoutThreshold) {
		ret = samdb_msg_add_int64(sam_ctx, mod_msg, mod_msg, "lockoutTime", now);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(mod_msg);
			return NT_STATUS_NO_MEMORY;
		}
		DEBUGC( DBGC_AUTH, 1, ("Locked out user %s after %d wrong passwords\n",
			  ldb_dn_get_linearized(user_msg->dn), badPwdCount));
	} else {
		DEBUGC( DBGC_AUTH, 5, ("Updated badPwdCount on %s after %d wrong passwords\n",
			  ldb_dn_get_linearized(user_msg->dn), badPwdCount));
	}

	/* mark all the message elements as LDB_FLAG_MOD_REPLACE */
	for (i=0; i< mod_msg->num_elements; i++) {
		mod_msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
	}

	*_mod_msg = mod_msg;
	return NT_STATUS_OK;
}

/**
 * Sets defaults for a User object
 * List of default attributes set:
 * 	accountExpires, badPasswordTime, badPwdCount,
 * 	codePage, countryCode, lastLogoff, lastLogon
 * 	logonCount, pwdLastSet
 */
int dsdb_user_obj_set_defaults(struct ldb_context *ldb,
			       struct ldb_message *usr_obj,
			       struct ldb_request *req)
{
	size_t i;
	int ret;
	const struct attribute_values {
		const char *name;
		const char *value;
		const char *add_value;
		const char *mod_value;
		const char *control;
		unsigned add_flags;
		unsigned mod_flags;
	} map[] = {
		{
			.name = "accountExpires",
			.add_value = "9223372036854775807",
			.mod_value = "0",
		},
		{
			.name = "badPasswordTime",
			.value = "0"
		},
		{
			.name = "badPwdCount",
			.value = "0"
		},
		{
			.name = "codePage",
			.value = "0"
		},
		{
			.name = "countryCode",
			.value = "0"
		},
		{
			.name = "lastLogoff",
			.value = "0"
		},
		{
			.name = "lastLogon",
			.value = "0"
		},
		{
			.name = "logonCount",
			.value = "0"
		},
		{
			.name = "logonHours",
			.add_flags = DSDB_FLAG_INTERNAL_FORCE_META_DATA,
		},
		{
			.name = "pwdLastSet",
			.value = "0",
			.control = DSDB_CONTROL_PASSWORD_DEFAULT_LAST_SET_OID,
		},
		{
			.name = "adminCount",
			.mod_value = "0",
		},
		{
			.name = "operatorCount",
			.mod_value = "0",
		},
	};

	for (i = 0; i < ARRAY_SIZE(map); i++) {
		bool added = false;
		const char *value = NULL;
		unsigned flags = 0;

		if (req != NULL && req->operation == LDB_ADD) {
			value = map[i].add_value;
			flags = map[i].add_flags;
		} else {
			value = map[i].mod_value;
			flags = map[i].mod_flags;
		}

		if (value == NULL) {
			value = map[i].value;
		}

		if (value != NULL) {
			flags |= LDB_FLAG_MOD_ADD;
		}

		if (flags == 0) {
			continue;
		}

		ret = samdb_find_or_add_attribute_ex(ldb, usr_obj,
						     map[i].name,
						     value, flags,
						     &added);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		if (req != NULL && added && map[i].control != NULL) {
			ret = ldb_request_add_control(req,
						      map[i].control,
						      false, NULL);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
	}

	return LDB_SUCCESS;
}

/**
 * Sets 'sAMAccountType on user object based on userAccountControl
 * @param ldb Current ldb_context
 * @param usr_obj ldb_message representing User object
 * @param user_account_control Value for userAccountControl flags
 * @param account_type_p Optional pointer to account_type to return
 * @return LDB_SUCCESS or LDB_ERR* code on failure
 */
int dsdb_user_obj_set_account_type(struct ldb_context *ldb, struct ldb_message *usr_obj,
				   uint32_t user_account_control, uint32_t *account_type_p)
{
	int ret;
	uint32_t account_type;
	struct ldb_message_element *el;

	account_type = ds_uf2atype(user_account_control);
	if (account_type == 0) {
		ldb_set_errstring(ldb, "dsdb: Unrecognized account type!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	ret = samdb_msg_add_uint(ldb, usr_obj, usr_obj,
				 "sAMAccountType",
				 account_type);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	el = ldb_msg_find_element(usr_obj, "sAMAccountType");
	el->flags = LDB_FLAG_MOD_REPLACE;

	if (account_type_p) {
		*account_type_p = account_type;
	}

	return LDB_SUCCESS;
}

/**
 * Determine and set primaryGroupID based on userAccountControl value
 * @param ldb Current ldb_context
 * @param usr_obj ldb_message representing User object
 * @param user_account_control Value for userAccountControl flags
 * @param group_rid_p Optional pointer to group RID to return
 * @return LDB_SUCCESS or LDB_ERR* code on failure
 */
int dsdb_user_obj_set_primary_group_id(struct ldb_context *ldb, struct ldb_message *usr_obj,
				       uint32_t user_account_control, uint32_t *group_rid_p)
{
	int ret;
	uint32_t rid;
	struct ldb_message_element *el;

	rid = ds_uf2prim_group_rid(user_account_control);

	ret = samdb_msg_add_uint(ldb, usr_obj, usr_obj,
				 "primaryGroupID", rid);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	el = ldb_msg_find_element(usr_obj, "primaryGroupID");
	el->flags = LDB_FLAG_MOD_REPLACE;

	if (group_rid_p) {
		*group_rid_p = rid;
	}

	return LDB_SUCCESS;
}

/**
 * Returns True if the source and target DNs both have the same naming context,
 * i.e. they're both in the same partition.
 */
bool dsdb_objects_have_same_nc(struct ldb_context *ldb,
			       TALLOC_CTX *mem_ctx,
			       struct ldb_dn *source_dn,
			       struct ldb_dn *target_dn)
{
	TALLOC_CTX *tmp_ctx;
	struct ldb_dn *source_nc = NULL;
	struct ldb_dn *target_nc = NULL;
	int ret;
	bool same_nc = true;

	tmp_ctx = talloc_new(mem_ctx);

	ret = dsdb_find_nc_root(ldb, tmp_ctx, source_dn, &source_nc);
	/* fix clang warning */
	if (source_nc == NULL) {
		ret = LDB_ERR_OTHER;
	}
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to find base DN for source %s\n",
			ldb_dn_get_linearized(source_dn));
		talloc_free(tmp_ctx);
		return true;
	}

	ret = dsdb_find_nc_root(ldb, tmp_ctx, target_dn, &target_nc);
	/* fix clang warning */
	if (target_nc == NULL) {
		ret = LDB_ERR_OTHER;
	}
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to find base DN for target %s\n",
			ldb_dn_get_linearized(target_dn));
		talloc_free(tmp_ctx);
		return true;
	}

	same_nc = (ldb_dn_compare(source_nc, target_nc) == 0);

	talloc_free(tmp_ctx);

	return same_nc;
}
/*
 * Context for dsdb_count_domain_callback
 */
struct dsdb_count_domain_context {
	/*
	 * Number of matching records
	 */
	size_t count;
	/*
	 * sid of the domain that the records must belong to.
	 * if NULL records can belong to any domain.
	 */
	struct dom_sid *dom_sid;
};

/*
 * @brief ldb aysnc callback for dsdb_domain_count.
 *
 * count the number of records in the database matching an LDAP query,
 * optionally filtering for domain membership.
 *
 * @param [in,out] req the ldb request being processed
 *                    req->context contains:
 *                        count   The number of matching records
 *                        dom_sid The domain sid, if present records must belong
 *                                to the domain to be counted.
 *@param [in,out] ares The query result.
 *
 * @return an LDB error code
 *
 */
static int dsdb_count_domain_callback(
	struct ldb_request *req,
	struct ldb_reply *ares)
{

	if (ares == NULL) {
		return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		int error = ares->error;
		TALLOC_FREE(ares);
		return ldb_request_done(req, error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
	{
		struct dsdb_count_domain_context *context = NULL;
		ssize_t ret;
		bool in_domain;
		struct dom_sid sid;
		const struct ldb_val *v;

		context = req->context;
		if (context->dom_sid == NULL) {
			context->count++;
			break;
		}

		v = ldb_msg_find_ldb_val(ares->message, "objectSid");
		if (v == NULL) {
			break;
		}

		ret = sid_parse(v->data, v->length, &sid);
		if (ret == -1) {
			break;
		}

		in_domain = dom_sid_in_domain(context->dom_sid, &sid);
		if (!in_domain) {
			break;
		}

		context->count++;
		break;
	}
	case LDB_REPLY_REFERRAL:
		break;

	case LDB_REPLY_DONE:
		TALLOC_FREE(ares);
		return ldb_request_done(req, LDB_SUCCESS);
	}

	TALLOC_FREE(ares);

	return LDB_SUCCESS;
}

/*
 * @brief Count the number of records matching a query.
 *
 * Count the number of entries in the database matching the supplied query,
 * optionally filtering only those entries belonging to the supplied domain.
 *
 * @param ldb [in] Current ldb context
 * @param count [out] Pointer to the count
 * @param base [in] The base dn for the quey
 * @param dom_sid [in] The domain sid, if non NULL records that are not a member
 *                     of the domain are ignored.
 * @param scope [in] Search scope.
 * @param exp_fmt [in] format string for the query.
 *
 * @return LDB_STATUS code.
 */
int PRINTF_ATTRIBUTE(6, 7) dsdb_domain_count(
	struct ldb_context *ldb,
	size_t *count,
	struct ldb_dn *base,
	struct dom_sid *dom_sid,
	enum ldb_scope scope,
	const char *exp_fmt, ...)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct ldb_request *req = NULL;
	struct dsdb_count_domain_context *context = NULL;
	char *expression = NULL;
	const char *object_sid[] = {"objectSid", NULL};
	const char *none[] = {NULL};
	va_list ap;
	int ret;

	*count = 0;
	tmp_ctx = talloc_new(ldb);

	context = talloc_zero(tmp_ctx, struct dsdb_count_domain_context);
	if (context == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	context->dom_sid = dom_sid;

	if (exp_fmt) {
		va_start(ap, exp_fmt);
		expression = talloc_vasprintf(tmp_ctx, exp_fmt, ap);
		va_end(ap);

		if (expression == NULL) {
			TALLOC_FREE(context);
			TALLOC_FREE(tmp_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	ret = ldb_build_search_req(
		&req,
		ldb,
		tmp_ctx,
		base,
		scope,
		expression,
		(dom_sid == NULL) ? none : object_sid,
		NULL,
		context,
		dsdb_count_domain_callback,
		NULL);
	ldb_req_set_location(req, "dsdb_domain_count");

	if (ret != LDB_SUCCESS) goto done;

	ret = ldb_request(ldb, req);

	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
		if (ret == LDB_SUCCESS) {
			*count = context->count;
		}
	}


done:
	TALLOC_FREE(expression);
	TALLOC_FREE(req);
	TALLOC_FREE(context);
	TALLOC_FREE(tmp_ctx);

	return ret;
}
