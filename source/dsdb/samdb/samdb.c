/* 
   Unix SMB/CIFS implementation.

   interface functions for the sam database

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Volker Lendecke 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006

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

#include "includes.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "libcli/security/security.h"
#include "libcli/auth/libcli_auth.h"
#include "libcli/ldap/ldap.h"
#include "system/time.h"
#include "system/filesys.h"
#include "db_wrap.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/flags.h"

/*
  connect to the SAM database
  return an opaque context pointer on success, or NULL on failure
 */
struct ldb_context *samdb_connect(TALLOC_CTX *mem_ctx, 
				  struct auth_session_info *session_info)
{
	struct ldb_context *ldb;
	ldb = ldb_wrap_connect(mem_ctx, lp_sam_url(), session_info,
			       NULL, 0, NULL);
	if (!ldb) {
		return NULL;
	}
	return ldb;
}

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

	return samdb_result_string(res[0], attr_name, NULL);
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
  return the count of the number of records in the sam matching the query
*/
int samdb_search_count(struct ldb_context *sam_ldb,
		       TALLOC_CTX *mem_ctx,
		       struct ldb_dn *basedn,
		       const char *format, ...) _PRINTF_ATTRIBUTE(4,5)
{
	va_list ap;
	struct ldb_message **res;
	const char * const attrs[] = { NULL };
	int ret;

	va_start(ap, format);
	ret = gendb_search_v(sam_ldb, mem_ctx, basedn, &res, attrs, format, ap);
	va_end(ap);

	return ret;
}


/*
  search the sam for a single integer attribute in exactly 1 record
*/
uint_t samdb_search_uint(struct ldb_context *sam_ldb,
			 TALLOC_CTX *mem_ctx,
			 uint_t default_value,
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

	return samdb_result_uint(res[0], attr_name, default_value);
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

	return samdb_result_int64(res[0], attr_name, default_value);
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
		(*strs)[i] = samdb_result_string(res[i], attr_name, NULL);
	}
	(*strs)[count] = NULL;

	return count;
}

/*
  pull a uint from a result set. 
*/
uint_t samdb_result_uint(const struct ldb_message *msg, const char *attr, uint_t default_value)
{
	return ldb_msg_find_attr_as_uint(msg, attr, default_value);
}

/*
  pull a (signed) int64 from a result set. 
*/
int64_t samdb_result_int64(const struct ldb_message *msg, const char *attr, int64_t default_value)
{
	return ldb_msg_find_attr_as_int64(msg, attr, default_value);
}

/*
  pull a string from a result set. 
*/
const char *samdb_result_string(const struct ldb_message *msg, const char *attr, 
				const char *default_value)
{
	return ldb_msg_find_attr_as_string(msg, attr, default_value);
}

struct ldb_dn *samdb_result_dn(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, const struct ldb_message *msg,
			       const char *attr, struct ldb_dn *default_value)
{
	struct ldb_dn *res_dn;
	const char *string = samdb_result_string(msg, attr, NULL);
	if (string == NULL) return default_value;
	res_dn = ldb_dn_new(mem_ctx, ldb, string);
	if ( ! ldb_dn_validate(res_dn)) {
		talloc_free(res_dn);
		return NULL;
	}
	return res_dn;
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
	const struct ldb_val *v;
	struct dom_sid *sid;
	NTSTATUS status;
	v = ldb_msg_find_ldb_val(msg, attr);
	if (v == NULL) {
		return NULL;
	}
	sid = talloc(mem_ctx, struct dom_sid);
	if (sid == NULL) {
		return NULL;
	}
	status = ndr_pull_struct_blob(v, sid, sid, 
				      (ndr_pull_flags_fn_t)ndr_pull_dom_sid);
	if (!NT_STATUS_IS_OK(status)) {
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
	NTSTATUS status;
	struct GUID guid;
	TALLOC_CTX *mem_ctx;

	ZERO_STRUCT(guid);

	v = ldb_msg_find_ldb_val(msg, attr);
	if (!v) return guid;

	mem_ctx = talloc_named_const(NULL, 0, "samdb_result_guid");
	if (!mem_ctx) return guid;
	status = ndr_pull_struct_blob(v, mem_ctx, &guid, 
				      (ndr_pull_flags_fn_t)ndr_pull_GUID);
	talloc_free(mem_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return guid;
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
NTTIME samdb_result_nttime(struct ldb_message *msg, const char *attr, NTTIME default_value)
{
	const char *str = ldb_msg_find_attr_as_string(msg, attr, NULL);
	if (!str) return default_value;
	return nttime_from_string(str);
}

/*
  pull a uint64_t from a result set. 
*/
uint64_t samdb_result_uint64(struct ldb_message *msg, const char *attr, uint64_t default_value)
{
	return ldb_msg_find_attr_as_uint64(msg, attr, default_value);
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
	uint64_t attr_time = samdb_result_uint64(msg, attr, 0);
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
  construct the force_password_change field from the PwdLastSet attribute and the 
  domain password settings
*/
NTTIME samdb_result_force_password_change(struct ldb_context *sam_ldb, 
					  TALLOC_CTX *mem_ctx, 
					  struct ldb_dn *domain_dn, 
					  struct ldb_message *msg)
{
	uint64_t attr_time = samdb_result_uint64(msg, "pwdLastSet", 0);
	uint32_t user_flags = samdb_result_uint64(msg, "userAccountControl", 0);
	int64_t maxPwdAge;

	if (user_flags & UF_DONT_EXPIRE_PASSWD) {
		return 0x7FFFFFFFFFFFFFFFULL;
	}

	if (attr_time == 0) {
		return 0;
	}

	maxPwdAge = samdb_search_int64(sam_ldb, mem_ctx, 0, domain_dn, "maxPwdAge", NULL);
	if (maxPwdAge == 0) {
		return 0;
	} else {
		attr_time -= maxPwdAge;
	}

	return attr_time;
}

/*
  pull a samr_Password structutre from a result set. 
*/
struct samr_Password *samdb_result_hash(TALLOC_CTX *mem_ctx, struct ldb_message *msg, const char *attr)
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
  pull an array of samr_Password structutres from a result set. 
*/
uint_t samdb_result_hashes(TALLOC_CTX *mem_ctx, struct ldb_message *msg, 
			   const char *attr, struct samr_Password **hashes)
{
	uint_t count = 0;
	const struct ldb_val *val = ldb_msg_find_ldb_val(msg, attr);
	int i;

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

NTSTATUS samdb_result_passwords(TALLOC_CTX *mem_ctx, struct ldb_message *msg, 
				struct samr_Password **lm_pwd, struct samr_Password **nt_pwd) 
{
	struct samr_Password *lmPwdHash, *ntPwdHash;
	if (nt_pwd) {
		int num_nt;
		num_nt = samdb_result_hashes(mem_ctx, msg, "ntPwdHash", &ntPwdHash);
		if (num_nt == 0) {
			*nt_pwd = NULL;
		} else if (num_nt > 1) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		} else {
			*nt_pwd = &ntPwdHash[0];
		}
	}
	if (lm_pwd) {
		int num_lm;
		num_lm = samdb_result_hashes(mem_ctx, msg, "lmPwdHash", &lmPwdHash);
		if (num_lm == 0) {
			*lm_pwd = NULL;
		} else if (num_lm > 1) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		} else {
			*lm_pwd = &lmPwdHash[0];
		}
	}
	return NT_STATUS_OK;
}

/*
  pull a samr_LogonHours structutre from a result set. 
*/
struct samr_LogonHours samdb_result_logon_hours(TALLOC_CTX *mem_ctx, struct ldb_message *msg, const char *attr)
{
	struct samr_LogonHours hours;
	const int units_per_week = 168;
	const struct ldb_val *val = ldb_msg_find_ldb_val(msg, attr);
	ZERO_STRUCT(hours);
	hours.bits = talloc_array(mem_ctx, uint8_t, units_per_week);
	if (!hours.bits) {
		return hours;
	}
	hours.units_per_week = units_per_week;
	memset(hours.bits, 0xFF, units_per_week);
	if (val) {
		memcpy(hours.bits, val->data, MIN(val->length, units_per_week));
	}
	return hours;
}

/*
  pull a set of account_flags from a result set. 
*/
uint16_t samdb_result_acct_flags(struct ldb_message *msg, const char *attr)
{
	uint_t userAccountControl = ldb_msg_find_attr_as_uint(msg, attr, 0);
	return samdb_uf2acb(userAccountControl);
}


/* Find an attribute, with a particular value */
struct ldb_message_element *samdb_find_attribute(struct ldb_context *ldb, 
						 const struct ldb_message *msg, 
						 const char *name, const char *value)
{
	int i;
	struct ldb_message_element *el = ldb_msg_find_element(msg, name);
	struct ldb_val v;

	v.data = discard_const_p(uint8_t, value);
	v.length = strlen(value);

	if (!el) {
		return NULL;
	}

	for (i=0;i<el->num_values;i++) {
		if (strcasecmp(value, (char *)el->values[i].data) == 0) {
			return el;
		}
	}

	return NULL;
}

int samdb_find_or_add_value(struct ldb_context *ldb, struct ldb_message *msg, const char *name, const char *set_value)
{
	if (samdb_find_attribute(ldb, msg, name, set_value) == NULL) {
		return samdb_msg_add_string(ldb, msg, msg, name, set_value);
	}
	return LDB_SUCCESS;
}

int samdb_find_or_add_attribute(struct ldb_context *ldb, struct ldb_message *msg, const char *name, const char *set_value)
{
	struct ldb_message_element *el;

       	el = ldb_msg_find_element(msg, name);
	if (el) {
		return LDB_SUCCESS;
	}
		
	return samdb_msg_add_string(ldb, msg, msg, name, set_value);
}


/*
  copy from a template record to a message
*/
int samdb_copy_template(struct ldb_context *ldb, 
			struct ldb_message *msg, const char *filter,
			const char **errstring)
{
	struct ldb_result *res;
	struct ldb_message *t;
	int ret, i, j;
	struct ldb_dn *basedn = ldb_dn_new(ldb, ldb, "cn=Templates");

	*errstring = NULL;	

	/* pull the template record */
	ret = ldb_search(ldb, basedn, LDB_SCOPE_SUBTREE, filter, NULL, &res);
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		*errstring = talloc_steal(msg, ldb_errstring(ldb));
		return ret;
	}
	if (res->count != 1) {
		*errstring = talloc_asprintf(msg, "samdb_copy_template: ERROR: template '%s' matched %d records, expected 1\n", filter, 
					     res->count);
		talloc_free(res);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	t = res->msgs[0];

	for (i = 0; i < t->num_elements; i++) {
		struct ldb_message_element *el = &t->elements[i];
		/* some elements should not be copied from the template */
		if (strcasecmp(el->name, "cn") == 0 ||
		    strcasecmp(el->name, "name") == 0 ||
		    strcasecmp(el->name, "sAMAccountName") == 0 ||
		    strcasecmp(el->name, "sAMAccountName") == 0 ||
		    strcasecmp(el->name, "distinguishedName") == 0 ||
		    strcasecmp(el->name, "objectGUID") == 0) {
			continue;
		}
		for (j = 0; j < el->num_values; j++) {
			if (strcasecmp(el->name, "objectClass") == 0) {
				if (strcasecmp((char *)el->values[j].data, "Template") == 0 ||
				    strcasecmp((char *)el->values[j].data, "userTemplate") == 0 ||
				    strcasecmp((char *)el->values[j].data, "groupTemplate") == 0 ||
				    strcasecmp((char *)el->values[j].data, "foreignSecurityPrincipalTemplate") == 0 ||
				    strcasecmp((char *)el->values[j].data, "aliasTemplate") == 0 || 
				    strcasecmp((char *)el->values[j].data, "trustedDomainTemplate") == 0 || 
				    strcasecmp((char *)el->values[j].data, "secretTemplate") == 0) {
					continue;
				}
				ret = samdb_find_or_add_value(ldb, msg, el->name, 
							      (char *)el->values[j].data);
				if (ret) {
					*errstring = talloc_asprintf(msg, "Adding objectClass %s failed.\n", el->values[j].data);
					talloc_free(res);
					return ret;
				}
			} else {
				ret = samdb_find_or_add_attribute(ldb, msg, el->name, 
								  (char *)el->values[j].data);
				if (ret) {
					*errstring = talloc_asprintf(msg, "Adding attribute %s failed.\n", el->name);
					talloc_free(res);
					return ret;
				}
			}
		}
	}

	talloc_free(res);

	return LDB_SUCCESS;
}


/*
  add a string element to a message
*/
int samdb_msg_add_string(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			 const char *attr_name, const char *str)
{
	char *s = talloc_strdup(mem_ctx, str);
	char *a = talloc_strdup(mem_ctx, attr_name);
	if (s == NULL || a == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	return ldb_msg_add_string(msg, a, s);
}

/*
  add a dom_sid element to a message
*/
int samdb_msg_add_dom_sid(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			 const char *attr_name, struct dom_sid *sid)
{
	struct ldb_val v;
	NTSTATUS status;
	status = ndr_push_struct_blob(&v, mem_ctx, sid, 
				      (ndr_push_flags_fn_t)ndr_push_dom_sid);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
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
	   samdb_replace() to be used everywhere */
	return ldb_msg_add_empty(msg, attr_name, LDB_FLAG_MOD_REPLACE, NULL);
}

/*
  add a add attribute value to a message
*/
int samdb_msg_add_addval(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			 const char *attr_name, const char *value)
{
	struct ldb_message_element *el;
	char *a, *v;
	int ret;
	a = talloc_strdup(mem_ctx, attr_name);
	if (a == NULL)
		return -1;
	v = talloc_strdup(mem_ctx, value);
	if (v == NULL)
		return -1;
	ret = ldb_msg_add_string(msg, a, v);
	if (ret != 0)
		return ret;
	el = ldb_msg_find_element(msg, a);
	if (el == NULL)
		return -1;
	el->flags = LDB_FLAG_MOD_ADD;
	return 0;
}

/*
  add a delete attribute value to a message
*/
int samdb_msg_add_delval(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			 const char *attr_name, const char *value)
{
	struct ldb_message_element *el;
	char *a, *v;
	int ret;
	a = talloc_strdup(mem_ctx, attr_name);
	if (a == NULL)
		return -1;
	v = talloc_strdup(mem_ctx, value);
	if (v == NULL)
		return -1;
	ret = ldb_msg_add_string(msg, a, v);
	if (ret != 0)
		return ret;
	el = ldb_msg_find_element(msg, a);
	if (el == NULL)
		return -1;
	el->flags = LDB_FLAG_MOD_DELETE;
	return 0;
}

/*
  add a int element to a message
*/
int samdb_msg_add_int(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
		       const char *attr_name, int v)
{
	const char *s = talloc_asprintf(mem_ctx, "%d", v);
	return samdb_msg_add_string(sam_ldb, mem_ctx, msg, attr_name, s);
}

/*
  add a uint_t element to a message
*/
int samdb_msg_add_uint(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
		       const char *attr_name, uint_t v)
{
	const char *s = talloc_asprintf(mem_ctx, "%u", v);
	return samdb_msg_add_string(sam_ldb, mem_ctx, msg, attr_name, s);
}

/*
  add a (signed) int64_t element to a message
*/
int samdb_msg_add_int64(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			const char *attr_name, int64_t v)
{
	const char *s = talloc_asprintf(mem_ctx, "%lld", (long long)v);
	return samdb_msg_add_string(sam_ldb, mem_ctx, msg, attr_name, s);
}

/*
  add a uint64_t element to a message
*/
int samdb_msg_add_uint64(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			const char *attr_name, uint64_t v)
{
	const char *s = talloc_asprintf(mem_ctx, "%llu", (unsigned long long)v);
	return samdb_msg_add_string(sam_ldb, mem_ctx, msg, attr_name, s);
}

/*
  add a samr_Password element to a message
*/
int samdb_msg_add_hash(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
		       const char *attr_name, struct samr_Password *hash)
{
	struct ldb_val val;
	val.data = talloc_memdup(mem_ctx, hash->hash, 16);
	if (!val.data) {
		return -1;
	}
	val.length = 16;
	return ldb_msg_add_value(msg, attr_name, &val, NULL);
}

/*
  add a samr_Password array to a message
*/
int samdb_msg_add_hashes(TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			 const char *attr_name, struct samr_Password *hashes, uint_t count)
{
	struct ldb_val val;
	int i;
	val.data = talloc_array_size(mem_ctx, 16, count);
	val.length = count*16;
	if (!val.data) {
		return -1;
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
	return samdb_msg_add_uint(sam_ldb, mem_ctx, msg, attr_name, samdb_acb2uf(v));
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
  add a general value element to a message
*/
int samdb_msg_add_value(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			      const char *attr_name, const struct ldb_val *val)
{
	return ldb_msg_add_value(msg, attr_name, val, NULL);
}

/*
  sets a general value element to a message
*/
int samdb_msg_set_value(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			const char *attr_name, const struct ldb_val *val)
{
	struct ldb_message_element *el;

	el = ldb_msg_find_element(msg, attr_name);
	if (el) {
		el->num_values = 0;
	}
	return ldb_msg_add_value(msg, attr_name, val, NULL);
}

/*
  set a string element in a message
*/
int samdb_msg_set_string(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			 const char *attr_name, const char *str)
{
	struct ldb_message_element *el;

	el = ldb_msg_find_element(msg, attr_name);
	if (el) {
		el->num_values = 0;
	}
	return samdb_msg_add_string(sam_ldb, mem_ctx, msg, attr_name, str);
}

/*
  add a record
*/
int samdb_add(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg)
{
	return ldb_add(sam_ldb, msg);
}

/*
  delete a record
*/
int samdb_delete(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_dn *dn)
{
	return ldb_delete(sam_ldb, dn);
}

/*
  modify a record
*/
int samdb_modify(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg)
{
	return ldb_modify(sam_ldb, msg);
}

/*
  replace elements in a record
*/
int samdb_replace(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg)
{
	int i;

	/* mark all the message elements as LDB_FLAG_MOD_REPLACE */
	for (i=0;i<msg->num_elements;i++) {
		msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
	}

	/* modify the samdb record */
	return samdb_modify(sam_ldb, mem_ctx, msg);
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

struct ldb_dn *samdb_base_dn(struct ldb_context *sam_ctx) 
{
	return ldb_get_default_basedn(sam_ctx);
}


struct ldb_dn *samdb_partitions_dn(struct ldb_context *sam_ctx, TALLOC_CTX *mem_ctx)
{
	struct ldb_dn *new_dn;

	new_dn = ldb_dn_copy(mem_ctx, samdb_base_dn(sam_ctx));
	if ( ! ldb_dn_add_child_fmt(new_dn, "CN=Partitions,CN=Configuration")) {
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
	const char *attrs[] = { "rootDomainNamingContext", NULL };
	int ret;
	struct ldb_result *res = NULL;
	TALLOC_CTX *tmp_ctx;
	struct dom_sid *domain_sid;
	const char *basedn_s;
	struct ldb_dn *basedn;

	/* see if we have a cached copy */
	domain_sid = ldb_get_opaque(ldb, "cache.domain_sid");
	if (domain_sid) {
		return domain_sid;
	}

	tmp_ctx = talloc_new(ldb);
	if (tmp_ctx == NULL) {
		goto failed;
	}

	basedn = ldb_dn_new(tmp_ctx, ldb, NULL);
	if (basedn == NULL) {
		goto failed;
	}
	
	/* find the basedn of the domain from the rootdse */
	ret = ldb_search(ldb, basedn, LDB_SCOPE_BASE, NULL, attrs, &res);
	talloc_steal(tmp_ctx, res);
	if (ret != LDB_SUCCESS || res->count != 1) {
		goto failed;
	}

	basedn_s = ldb_msg_find_attr_as_string(res->msgs[0], "rootDomainNamingContext", NULL);
	if (basedn_s == NULL) {
		goto failed;
	}

	basedn = ldb_dn_new(tmp_ctx, ldb, basedn_s);
	if ( ! ldb_dn_validate(basedn)) {
		goto failed;
	}

	/* find the domain_sid */
	domain_sid = samdb_search_dom_sid(ldb, tmp_ctx, basedn, 
					  "objectSid", "objectClass=domainDNS");
	if (domain_sid == NULL) {
		goto failed;
	}

	/* cache the domain_sid in the ldb */
	if (ldb_set_opaque(ldb, "cache.domain_sid", domain_sid) != LDB_SUCCESS) {
		goto failed;
	}

	talloc_steal(ldb, domain_sid);
	talloc_free(tmp_ctx);

	return domain_sid;

failed:
	DEBUG(1,("Failed to find domain_sid for open ldb\n"));
	talloc_free(tmp_ctx);
	return NULL;
}

/*
  check that a password is sufficiently complex
*/
static BOOL samdb_password_complexity_ok(const char *pass)
{
	return check_password_quality(pass);
}



/*
  set the user password using plaintext, obeying any user or domain
  password restrictions

  note that this function doesn't actually store the result in the
  database, it just fills in the "mod" structure with ldb modify
  elements to setup the correct change when samdb_replace() is
  called. This allows the caller to combine the change with other
  changes (as is needed by some of the set user info levels)

  The caller should probably have a transaction wrapping this
*/
_PUBLIC_ NTSTATUS samdb_set_password(struct ldb_context *ctx, TALLOC_CTX *mem_ctx,
			    struct ldb_dn *user_dn,
			    struct ldb_dn *domain_dn,
			    struct ldb_message *mod,
			    const char *new_pass,
			    struct samr_Password *lmNewHash, 
			    struct samr_Password *ntNewHash,
			    BOOL user_change,
			    BOOL restrictions,
			    enum samr_RejectReason *reject_reason,
			    struct samr_DomInfo1 **_dominfo)
{
	const char * const user_attrs[] = { "userAccountControl", "sambaLMPwdHistory", 
					    "sambaNTPwdHistory", 
					    "lmPwdHash", "ntPwdHash", 
					    "objectSid", 
					    "pwdLastSet", NULL };
	const char * const domain_attrs[] = { "pwdProperties", "pwdHistoryLength", 
					      "maxPwdAge", "minPwdAge", 
					      "minPwdLength", NULL };
	NTTIME pwdLastSet;
	int64_t minPwdAge;
	uint_t minPwdLength, pwdProperties, pwdHistoryLength;
	uint_t userAccountControl;
	struct samr_Password *sambaLMPwdHistory, *sambaNTPwdHistory, *lmPwdHash, *ntPwdHash;
	struct samr_Password local_lmNewHash, local_ntNewHash;
	int sambaLMPwdHistory_len, sambaNTPwdHistory_len;
	struct dom_sid *domain_sid;
	struct ldb_message **res;
	int count;
	time_t now = time(NULL);
	NTTIME now_nt;
	int i;

	/* we need to know the time to compute password age */
	unix_to_nt_time(&now_nt, now);

	/* pull all the user parameters */
	count = gendb_search_dn(ctx, mem_ctx, user_dn, &res, user_attrs);
	if (count != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	userAccountControl = samdb_result_uint(res[0],   "userAccountControl", 0);
	sambaLMPwdHistory_len =   samdb_result_hashes(mem_ctx, res[0], 
						 "sambaLMPwdHistory", &sambaLMPwdHistory);
	sambaNTPwdHistory_len =   samdb_result_hashes(mem_ctx, res[0], 
						 "sambaNTPwdHistory", &sambaNTPwdHistory);
	lmPwdHash =          samdb_result_hash(mem_ctx, res[0],   "lmPwdHash");
	ntPwdHash =          samdb_result_hash(mem_ctx, res[0],   "ntPwdHash");
	pwdLastSet =         samdb_result_uint64(res[0], "pwdLastSet", 0);

	if (domain_dn) {
		/* pull the domain parameters */
		count = gendb_search_dn(ctx, mem_ctx, domain_dn, &res, domain_attrs);
		if (count != 1) {
			DEBUG(2, ("samdb_set_password: Domain DN %s is invalid, for user %s\n", 
				  ldb_dn_get_linearized(domain_dn),
				  ldb_dn_get_linearized(user_dn)));
			return NT_STATUS_NO_SUCH_DOMAIN;
		}
	} else {
		/* work out the domain sid, and pull the domain from there */
		domain_sid =         samdb_result_sid_prefix(mem_ctx, res[0], "objectSid");
		if (domain_sid == NULL) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		count = gendb_search(ctx, mem_ctx, NULL, &res, domain_attrs, 
				     "(objectSid=%s)", 
				     ldap_encode_ndr_dom_sid(mem_ctx, domain_sid));
		if (count != 1) {
			DEBUG(2, ("samdb_set_password: Could not find domain to match SID: %s, for user %s\n", 
				  dom_sid_string(mem_ctx, domain_sid),
				  ldb_dn_get_linearized(user_dn)));
			return NT_STATUS_NO_SUCH_DOMAIN;
		}
	}

	pwdProperties =    samdb_result_uint(res[0],   "pwdProperties", 0);
	pwdHistoryLength = samdb_result_uint(res[0],   "pwdHistoryLength", 0);
	minPwdLength =     samdb_result_uint(res[0],   "minPwdLength", 0);
	minPwdAge =        samdb_result_int64(res[0],  "minPwdAge", 0);

	if (_dominfo) {
		struct samr_DomInfo1 *dominfo;
		/* on failure we need to fill in the reject reasons */
		dominfo = talloc(mem_ctx, struct samr_DomInfo1);
		if (dominfo == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		dominfo->min_password_length     = minPwdLength;
		dominfo->password_properties     = pwdProperties;
		dominfo->password_history_length = pwdHistoryLength;
		dominfo->max_password_age        = minPwdAge;
		dominfo->min_password_age        = minPwdAge;
		*_dominfo = dominfo;
	}

	if (new_pass) {
		/* check the various password restrictions */
		if (restrictions && minPwdLength > strlen_m(new_pass)) {
			if (reject_reason) {
				*reject_reason = SAMR_REJECT_TOO_SHORT;
			}
			return NT_STATUS_PASSWORD_RESTRICTION;
		}
		
		/* possibly check password complexity */
		if (restrictions && pwdProperties & DOMAIN_PASSWORD_COMPLEX &&
		    !samdb_password_complexity_ok(new_pass)) {
			if (reject_reason) {
				*reject_reason = SAMR_REJECT_COMPLEXITY;
			}
			return NT_STATUS_PASSWORD_RESTRICTION;
		}
		
		/* compute the new nt and lm hashes */
		if (E_deshash(new_pass, local_lmNewHash.hash)) {
			lmNewHash = &local_lmNewHash;
		}
		if (!E_md4hash(new_pass, local_ntNewHash.hash)) {
			/* If we can't convert this password to UCS2, then we should not accept it */
			if (reject_reason) {
				*reject_reason = SAMR_REJECT_OTHER;
			}
			return NT_STATUS_PASSWORD_RESTRICTION;
		}
		ntNewHash = &local_ntNewHash;
	}

	if (restrictions && user_change) {
		/* are all password changes disallowed? */
		if (pwdProperties & DOMAIN_REFUSE_PASSWORD_CHANGE) {
			if (reject_reason) {
				*reject_reason = SAMR_REJECT_OTHER;
			}
			return NT_STATUS_PASSWORD_RESTRICTION;
		}
		
		/* can this user change password? */
		if (userAccountControl & UF_PASSWD_CANT_CHANGE) {
			if (reject_reason) {
				*reject_reason = SAMR_REJECT_OTHER;
			}
			return NT_STATUS_PASSWORD_RESTRICTION;
		}
		
		/* yes, this is a minus. The ages are in negative 100nsec units! */
		if (pwdLastSet - minPwdAge > now_nt) {
			if (reject_reason) {
				*reject_reason = SAMR_REJECT_OTHER;
			}
			return NT_STATUS_PASSWORD_RESTRICTION;
		}

		/* check the immediately past password */
		if (pwdHistoryLength > 0) {
			if (lmNewHash && lmPwdHash && memcmp(lmNewHash->hash, lmPwdHash->hash, 16) == 0) {
				if (reject_reason) {
					*reject_reason = SAMR_REJECT_IN_HISTORY;
				}
				return NT_STATUS_PASSWORD_RESTRICTION;
			}
			if (ntNewHash && ntPwdHash && memcmp(ntNewHash->hash, ntPwdHash->hash, 16) == 0) {
				if (reject_reason) {
					*reject_reason = SAMR_REJECT_IN_HISTORY;
				}
				return NT_STATUS_PASSWORD_RESTRICTION;
			}
		}
		
		/* check the password history */
		sambaLMPwdHistory_len = MIN(sambaLMPwdHistory_len, pwdHistoryLength);
		sambaNTPwdHistory_len = MIN(sambaNTPwdHistory_len, pwdHistoryLength);
		
		for (i=0; lmNewHash && i<sambaLMPwdHistory_len;i++) {
			if (memcmp(lmNewHash->hash, sambaLMPwdHistory[i].hash, 16) == 0) {
				if (reject_reason) {
					*reject_reason = SAMR_REJECT_IN_HISTORY;
				}
				return NT_STATUS_PASSWORD_RESTRICTION;
			}
		}
		for (i=0; ntNewHash && i<sambaNTPwdHistory_len;i++) {
			if (memcmp(ntNewHash->hash, sambaNTPwdHistory[i].hash, 16) == 0) {
				if (reject_reason) {
					*reject_reason = SAMR_REJECT_IN_HISTORY;
				}
				return NT_STATUS_PASSWORD_RESTRICTION;
			}
		}
	}

#define CHECK_RET(x) do { if (x != 0) return NT_STATUS_NO_MEMORY; } while(0)

	/* the password is acceptable. Start forming the new fields */
	if (new_pass) {
		/* if we know the cleartext, then only set it.
		 * Modules in ldb will set all the appropriate
		 * hashes */
		CHECK_RET(samdb_msg_add_string(ctx, mem_ctx, mod, 
					       "sambaPassword", new_pass));
	} else {
		/* We don't have the cleartext, so delete the old one
		 * and set what we have of the hashes */
		CHECK_RET(samdb_msg_add_delete(ctx, mem_ctx, mod, "sambaPassword"));

		if (lmNewHash) {
			CHECK_RET(samdb_msg_add_hash(ctx, mem_ctx, mod, "lmPwdHash", lmNewHash));
		} else {
			CHECK_RET(samdb_msg_add_delete(ctx, mem_ctx, mod, "lmPwdHash"));
		}
		
		if (ntNewHash) {
			CHECK_RET(samdb_msg_add_hash(ctx, mem_ctx, mod, "ntPwdHash", ntNewHash));
		} else {
			CHECK_RET(samdb_msg_add_delete(ctx, mem_ctx, mod, "ntPwdHash"));
		}
	}

	return NT_STATUS_OK;
}


/*
  set the user password using plaintext, obeying any user or domain
  password restrictions

  This wrapper function takes a SID as input, rather than a user DN,
  and actually performs the password change

*/
_PUBLIC_ NTSTATUS samdb_set_password_sid(struct ldb_context *ctx, TALLOC_CTX *mem_ctx,
				const struct dom_sid *user_sid,
				const char *new_pass,
				struct samr_Password *lmNewHash, 
				struct samr_Password *ntNewHash,
				BOOL user_change,
				BOOL restrictions,
				enum samr_RejectReason *reject_reason,
				struct samr_DomInfo1 **_dominfo) 
{
	NTSTATUS nt_status;
	struct ldb_dn *user_dn;
	struct ldb_message *msg;
	int ret;

	ret = ldb_transaction_start(ctx);
	if (ret) {
		DEBUG(1, ("Failed to start transaction: %s\n", ldb_errstring(ctx)));
		return NT_STATUS_TRANSACTION_ABORTED;
	}

	user_dn = samdb_search_dn(ctx, mem_ctx, NULL, 
				  "(&(objectSid=%s)(objectClass=user))", 
				  ldap_encode_ndr_dom_sid(mem_ctx, user_sid));
	if (!user_dn) {
		ldb_transaction_cancel(ctx);
		DEBUG(3, ("samdb_set_password_sid: SID %s not found in samdb, returning NO_SUCH_USER\n",
			  dom_sid_string(mem_ctx, user_sid)));
		return NT_STATUS_NO_SUCH_USER;
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		ldb_transaction_cancel(ctx);
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = ldb_dn_copy(msg, user_dn);
	if (!msg->dn) {
		ldb_transaction_cancel(ctx);
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = samdb_set_password(ctx, mem_ctx,
				       user_dn, NULL,
				       msg, new_pass, 
				       lmNewHash, ntNewHash,
				       user_change, /* This is a password set, not change */
				       restrictions, /* run restriction tests */
				       reject_reason, _dominfo);
	if (!NT_STATUS_IS_OK(nt_status)) {
		ldb_transaction_cancel(ctx);
		return nt_status;
	}
	
	/* modify the samdb record */
	ret = samdb_replace(ctx, mem_ctx, msg);
	if (ret != 0) {
		ldb_transaction_cancel(ctx);
		return NT_STATUS_ACCESS_DENIED;
	}

	ret = ldb_transaction_commit(ctx);
	if (ret != 0) {
		DEBUG(0,("Failed to commit transaction to change password on %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(ctx)));
		return NT_STATUS_TRANSACTION_ABORTED;
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Create the SID list for this user.
****************************************************************************/
NTSTATUS security_token_create(TALLOC_CTX *mem_ctx, 
			       struct dom_sid *user_sid,
			       struct dom_sid *group_sid, 
			       int n_groupSIDs,
			       struct dom_sid **groupSIDs, 
			       BOOL is_authenticated,
			       struct security_token **token)
{
	struct security_token *ptoken;
	int i;
	NTSTATUS status;

	ptoken = security_token_initialise(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(ptoken);

	ptoken->sids = talloc_array(ptoken, struct dom_sid *, n_groupSIDs + 5);
	NT_STATUS_HAVE_NO_MEMORY(ptoken->sids);

	ptoken->user_sid = talloc_reference(ptoken, user_sid);
	ptoken->group_sid = talloc_reference(ptoken, group_sid);
	ptoken->privilege_mask = 0;

	ptoken->sids[0] = ptoken->user_sid;
	ptoken->sids[1] = ptoken->group_sid;

	/*
	 * Finally add the "standard" SIDs.
	 * The only difference between guest and "anonymous"
	 * is the addition of Authenticated_Users.
	 */
	ptoken->sids[2] = dom_sid_parse_talloc(ptoken->sids, SID_WORLD);
	NT_STATUS_HAVE_NO_MEMORY(ptoken->sids[2]);
	ptoken->sids[3] = dom_sid_parse_talloc(ptoken->sids, SID_NT_NETWORK);
	NT_STATUS_HAVE_NO_MEMORY(ptoken->sids[3]);
	ptoken->num_sids = 4;

	if (is_authenticated) {
		ptoken->sids[4] = dom_sid_parse_talloc(ptoken->sids, SID_NT_AUTHENTICATED_USERS);
		NT_STATUS_HAVE_NO_MEMORY(ptoken->sids[4]);
		ptoken->num_sids++;
	}

	for (i = 0; i < n_groupSIDs; i++) {
		size_t check_sid_idx;
		for (check_sid_idx = 1; 
		     check_sid_idx < ptoken->num_sids; 
		     check_sid_idx++) {
			if (dom_sid_equal(ptoken->sids[check_sid_idx], groupSIDs[i])) {
				break;
			}
		}

		if (check_sid_idx == ptoken->num_sids) {
			ptoken->sids[ptoken->num_sids++] = talloc_reference(ptoken->sids, groupSIDs[i]);
		}
	}

	/* setup the privilege mask for this token */
	status = samdb_privilege_setup(ptoken);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(ptoken);
		return status;
	}

	security_token_debug(10, ptoken);

	*token = ptoken;

	return NT_STATUS_OK;
}


NTSTATUS samdb_create_foreign_security_principal(struct ldb_context *sam_ctx, TALLOC_CTX *mem_ctx, 
						 struct dom_sid *sid, struct ldb_dn **ret_dn) 
{
	struct ldb_message *msg;
	struct ldb_dn *basedn;
	const char *sidstr;
	int ret;
	
	sidstr = dom_sid_string(mem_ctx, sid);
	NT_STATUS_HAVE_NO_MEMORY(sidstr);
	
	/* We might have to create a ForeignSecurityPrincipal, even if this user
	 * is in our own domain */
	
	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	
	/* TODO: Hmmm. This feels wrong. How do I find the base dn to
	 * put the ForeignSecurityPrincipals? d_state->domain_dn does
	 * not work, this is wrong for the Builtin domain, there's no
	 * cn=For...,cn=Builtin,dc={BASEDN}.  -- vl
	 */
	
	basedn = samdb_search_dn(sam_ctx, mem_ctx, NULL,
				 "(&(objectClass=container)(cn=ForeignSecurityPrincipals))");
	
	if (basedn == NULL) {
		DEBUG(0, ("Failed to find DN for "
			  "ForeignSecurityPrincipal container\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	
	/* add core elements to the ldb_message for the alias */
	msg->dn = ldb_dn_copy(mem_ctx, basedn);
	if ( ! ldb_dn_add_child_fmt(msg->dn, "CN=%s", sidstr))
		return NT_STATUS_NO_MEMORY;
	
	samdb_msg_add_string(sam_ctx, mem_ctx, msg,
			     "objectClass",
			     "foreignSecurityPrincipal");
	
	/* create the alias */
	ret = samdb_add(sam_ctx, mem_ctx, msg);
	if (ret != 0) {
		DEBUG(0,("Failed to create foreignSecurityPrincipal "
			 "record %s: %s\n", 
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(sam_ctx)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	*ret_dn = msg->dn;
	return NT_STATUS_OK;
}
