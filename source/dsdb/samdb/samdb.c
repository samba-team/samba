/* 
   Unix SMB/CIFS implementation.

   interface functions for the sam database

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

#include "includes.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "system/time.h"
#include "system/filesys.h"
#include "db_wrap.h"
#include "dsdb/samdb/samdb.h"

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
			const struct ldb_dn *basedn,
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
				  const struct ldb_dn *basedn,
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
				const struct ldb_dn *basedn,
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
			       const struct ldb_dn *basedn,
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
				     const struct ldb_dn *basedn,
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
		       const struct ldb_dn *basedn,
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
			 const struct ldb_dn *basedn,
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
			   const struct ldb_dn *basedn,
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
				 const struct ldb_dn *basedn,
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
uint_t samdb_result_uint(struct ldb_message *msg, const char *attr, uint_t default_value)
{
	return ldb_msg_find_uint(msg, attr, default_value);
}

/*
  pull a (signed) int64 from a result set. 
*/
int64_t samdb_result_int64(struct ldb_message *msg, const char *attr, int64_t default_value)
{
	return ldb_msg_find_int64(msg, attr, default_value);
}

/*
  pull a string from a result set. 
*/
const char *samdb_result_string(struct ldb_message *msg, const char *attr, 
				const char *default_value)
{
	return ldb_msg_find_string(msg, attr, default_value);
}

struct ldb_dn *samdb_result_dn(TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			       const char *attr, struct ldb_dn *default_value)
{
	const char *string = samdb_result_string(msg, attr, NULL);
	if (string == NULL) return default_value;
	return ldb_dn_explode(mem_ctx, string);
}

/*
  pull a rid from a objectSid in a result set. 
*/
uint32_t samdb_result_rid_from_sid(TALLOC_CTX *mem_ctx, struct ldb_message *msg, 
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
struct dom_sid *samdb_result_dom_sid(TALLOC_CTX *mem_ctx, struct ldb_message *msg, 
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
struct GUID samdb_result_guid(struct ldb_message *msg, const char *attr)
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
struct dom_sid *samdb_result_sid_prefix(TALLOC_CTX *mem_ctx, struct ldb_message *msg, 
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
	const char *str = ldb_msg_find_string(msg, attr, NULL);
	if (!str) return default_value;
	return nttime_from_string(str);
}

/*
  pull a uint64_t from a result set. 
*/
uint64_t samdb_result_uint64(struct ldb_message *msg, const char *attr, uint64_t default_value)
{
	return ldb_msg_find_uint64(msg, attr, default_value);
}


/*
  construct the allow_password_change field from the PwdLastSet attribute and the 
  domain password settings
*/
NTTIME samdb_result_allow_password_change(struct ldb_context *sam_ldb, 
					  TALLOC_CTX *mem_ctx, 
					  const struct ldb_dn *domain_dn, 
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
					  const struct ldb_dn *domain_dn, 
					  struct ldb_message *msg, 
					  const char *attr)
{
	uint64_t attr_time = samdb_result_uint64(msg, attr, 0);
	int64_t maxPwdAge;

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
	uint_t userAccountControl = ldb_msg_find_uint(msg, attr, 0);
	return samdb_uf2acb(userAccountControl);
}

/*
  copy from a template record to a message
*/
int samdb_copy_template(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, 
			struct ldb_message *msg, const char *expression)
{
	struct ldb_message **res, *t;
	int ret, i, j;
	

	/* pull the template record */
	ret = gendb_search(sam_ldb, mem_ctx, NULL, &res, NULL, "%s", expression);
	if (ret != 1) {
		DEBUG(1,("samdb: ERROR: template '%s' matched %d records\n", 
			 expression, ret));
		return -1;
	}
	t = res[0];

	for (i=0;i<t->num_elements;i++) {
		struct ldb_message_element *el = &t->elements[i];
		/* some elements should not be copied from the template */
		if (strcasecmp(el->name, "cn") == 0 ||
		    strcasecmp(el->name, "name") == 0 ||
		    strcasecmp(el->name, "sAMAccountName") == 0) {
			continue;
		}
		for (j=0;j<el->num_values;j++) {
			if (strcasecmp(el->name, "objectClass") == 0 &&
			    (strcasecmp((char *)el->values[j].data, "Template") == 0 ||
			     strcasecmp((char *)el->values[j].data, "userTemplate") == 0 ||
			     strcasecmp((char *)el->values[j].data, "groupTemplate") == 0 ||
			     strcasecmp((char *)el->values[j].data, "foreignSecurityTemplate") == 0 ||
			     strcasecmp((char *)el->values[j].data, "aliasTemplate") == 0 || 
			     strcasecmp((char *)el->values[j].data, "trustedDomainTemplate") == 0 || 
			     strcasecmp((char *)el->values[j].data, "secretTemplate") == 0)) {
				continue;
			}
			samdb_msg_add_string(sam_ldb, mem_ctx, msg, el->name, 
					     (char *)el->values[j].data);
		}
	}

	return 0;
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
		return -1;
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
	return ldb_msg_add_value(msg, attr_name, &v);
}


/*
  add a delete element operation to a message
*/
int samdb_msg_add_delete(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			 const char *attr_name)
{
	/* we use an empty replace rather than a delete, as it allows for 
	   samdb_replace() to be used everywhere */
	return ldb_msg_add_empty(msg, attr_name, LDB_FLAG_MOD_REPLACE);
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
	return ldb_msg_add_value(msg, attr_name, &val);
}

/*
  add a samr_Password array to a message
*/
int samdb_msg_add_hashes(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
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
	return ldb_msg_add_value(msg, attr_name, &val);
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
	return ldb_msg_add_value(msg, attr_name, &val);
}

/*
  add a general value element to a message
*/
int samdb_msg_add_value(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, struct ldb_message *msg,
			      const char *attr_name, const struct ldb_val *val)
{
	return ldb_msg_add_value(msg, attr_name, val);
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
	return ldb_msg_add_value(msg, attr_name, val);
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
int samdb_delete(struct ldb_context *sam_ldb, TALLOC_CTX *mem_ctx, const struct ldb_dn *dn)
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

struct ldb_dn *samdb_base_dn(TALLOC_CTX *mem_ctx) 
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	int server_role = lp_server_role();
	const char **split_realm;
	struct ldb_dn *dn;
	
	if (!tmp_ctx) {
		return NULL;
	}

	if ((server_role == ROLE_DOMAIN_PDC)
	    || (server_role == ROLE_DOMAIN_BDC)) {
		int i;
		split_realm = str_list_make(tmp_ctx, lp_realm(), ".");
		if (!split_realm) {
			talloc_free(tmp_ctx);
			return NULL;
		}
		dn = NULL;
		i = str_list_length(split_realm);
		i--;
		for (; i >= 0; i--) {
			dn = ldb_dn_build_child(tmp_ctx, "dc", split_realm[i], dn);
			if (!dn) {
				talloc_free(tmp_ctx);
				return NULL;
			}
		}
		return dn;
	}
	return ldb_dn_string_compose(mem_ctx, NULL, "cn=%s", lp_netbios_name());
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

	basedn = ldb_dn_explode(tmp_ctx, "");
	if (basedn == NULL) {
		goto failed;
	}
	
	/* find the basedn of the domain from the rootdse */
	ret = ldb_search(ldb, basedn, LDB_SCOPE_BASE, NULL, attrs, &res);
	talloc_steal(tmp_ctx, res);
	if (ret != LDB_SUCCESS || res->count != 1) {
		goto failed;
	}

	basedn_s = ldb_msg_find_string(res->msgs[0], "rootDomainNamingContext", NULL);
	if (basedn_s == NULL) {
		goto failed;
	}

	basedn = ldb_dn_explode(tmp_ctx, basedn_s);
	if (basedn == NULL) {
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
