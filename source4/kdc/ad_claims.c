/*
   Unix SMB/CIFS implementation.
   Samba Active Directory claims utility functions

   Copyright (C) Catalyst.Net Ltd 2023

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

#include "lib/replace/replace.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "source4/kdc/ad_claims.h"
#include "source4/kdc/authn_policy_util.h"
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "librpc/gen_ndr/claims.h"
#include "librpc/gen_ndr/ndr_claims.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "lib/util/binsearch.h"
#include "auth/session.h"
#include "libcli/security/sddl.h"

#undef strcasecmp

bool ad_claims_are_issued(struct ldb_context *samdb)
{
	/*
	 * Claims aren’t issued by Samba unless the DC is at
	 * FL2012.  This is to match Windows, which will offer
	 * this feature as soon as the DC is upgraded.
	 */
	const int functional_level = dsdb_dc_functional_level(samdb);
	return functional_level >= DS_DOMAIN_FUNCTION_2012;
}

static int acl_attr_cmp_fn(const char *a, const char * const *b)
{
	return ldb_attr_cmp(a, *b);
}

/*
 * Add a single attribute to a list of attributes if it is not already
 * present. The list is maintained in case-insensitive sorted order.
 */
static int add_attr_unique(TALLOC_CTX *mem_ctx,
			   const char **attrs,
			   unsigned *ad_claim_attrs_count,
			   const char *attr)
{
	const unsigned count = *ad_claim_attrs_count;
	const char * const *exact = NULL;
	const char * const *next = NULL;

	BINARY_ARRAY_SEARCH_GTE(attrs,
				count,
				attr,
				acl_attr_cmp_fn,
				exact,
				next);
	if (exact != NULL) {
		/* The attribute is already present; there's nothing to do. */
		return LDB_SUCCESS;
	}

	/* Make sure we don't overflow the array. */
	SMB_ASSERT(count < talloc_array_length(attrs));
	*ad_claim_attrs_count = count + 1;

	if (next == NULL) {
		/* Just add the new element on the end. */
		attrs[count] = attr;
	} else {
		/* Shift all following elements over to make room. */
		size_t next_idx = next - attrs;
		size_t bytes_to_move = (count - next_idx) * sizeof (attrs[0]);
		memmove(&attrs[next_idx + 1],
			&attrs[next_idx],
			bytes_to_move);

		attrs[next_idx] = attr;
	}

	return LDB_SUCCESS;
}

/*
 * Return true if a data_blob, interpreted as a string, is equal to another
 * string. This is more efficient than strcmp(), particularly when comparing
 * against a string constant. This assumes the data_blob's length does not
 * include the zero-terminator.
 */
static inline bool data_blob_equals_str(const DATA_BLOB val, const char *str)
{
	size_t len = strlen(str);
	if (val.length != len) {
		return false;
	}

	return memcmp(val.data, str, len) == 0;
}

static int fill_claim_int64(TALLOC_CTX *mem_ctx,
			    struct ldb_context *ldb,
			    const struct ldb_message_element *principal_attribute,
			    const struct ldb_val name,
			    struct CLAIM_INT64 *claim)
{
	uint32_t i;

	claim->value_count = 0;
	claim->values = talloc_array(mem_ctx,
				     int64_t,
				     principal_attribute->num_values);
	if (claim->values == NULL) {
		return ldb_oom(ldb);
	}

	for (i = 0; i < principal_attribute->num_values; ++i) {
		const struct ldb_val *value = &principal_attribute->values[i];
		int ret = ldb_val_as_int64(value, &claim->values[i]);
		if (ret) {
			char buf[1024];
			const char *reason = NULL;
			int err = strerror_r(ret, buf, sizeof(buf));
			if (err == 0) {
				reason = buf;
			} else {
				reason = "Unknown error";
			}
			DBG_WARNING("Failed to interpret value %s as INT64 "
				    "while creating claim %s for attribute %s (%s); "
				    "skipping value\n",
				    (value->data != NULL) ? (const char *)value->data : "<unknown>",
				    name.data, principal_attribute->name,
				    reason);
			continue;
		}

		++claim->value_count;
	}

	/* Shrink the array to fit. */
	claim->values = talloc_realloc(mem_ctx,
				       claim->values,
				       int64_t,
				       claim->value_count);
	if (claim->value_count && claim->values == NULL) {
		return ldb_oom(ldb);
	}

	return LDB_SUCCESS;
}

static int fill_claim_uint64(TALLOC_CTX *mem_ctx,
			     struct ldb_context *ldb,
			     const struct ldb_message_element *principal_attribute,
			     const struct ldb_val name,
			     struct CLAIM_UINT64 *claim)
{
	uint32_t i;

	claim->value_count = 0;
	claim->values = talloc_array(mem_ctx,
				     uint64_t,
				     principal_attribute->num_values);
	if (claim->values == NULL) {
		return ldb_oom(ldb);
	}

	for (i = 0; i < principal_attribute->num_values; ++i) {
		const struct ldb_val *value = &principal_attribute->values[i];
		int ret = ldb_val_as_uint64(value, &claim->values[i]);
		if (ret) {
			char buf[1024];
			const char *reason = NULL;
			int err = strerror_r(ret, buf, sizeof(buf));
			if (err == 0) {
				reason = buf;
			} else {
				reason = "Unknown error";
			}
			DBG_WARNING("Failed to interpret value %s as UINT64 "
				    "while creating claim %s for attribute %s (%s); "
				    "skipping value\n",
				    (value->data != NULL) ? (const char *)value->data : "<unknown>",
				    name.data, principal_attribute->name,
				    reason);
			continue;
		}

		++claim->value_count;
	}

	/* Shrink the array to fit. */
	claim->values = talloc_realloc(mem_ctx,
				       claim->values,
				       uint64_t,
				       claim->value_count);
	if (claim->value_count && claim->values == NULL) {
		return ldb_oom(ldb);
	}

	return LDB_SUCCESS;
}

static int fill_claim_uint64_oid_syntax(TALLOC_CTX *mem_ctx,
					struct ldb_context *ldb,
					const struct dsdb_schema *schema,
					const struct ldb_message_element *principal_attribute,
					const struct ldb_val name,
					struct CLAIM_UINT64 *claim)
{
	uint32_t i;

	claim->value_count = 0;
	claim->values = talloc_array(mem_ctx,
				     uint64_t,
				     principal_attribute->num_values);
	if (claim->values == NULL) {
		return ldb_oom(ldb);
	}

	for (i = 0; i < principal_attribute->num_values; ++i) {
		const struct dsdb_class *class_val = NULL;

		/*
		 * OID values for objectClass
		 * are presented in reverse
		 * order.
		 */
		const struct ldb_val *display_name = &principal_attribute->values[
			principal_attribute->num_values - 1 - i];

		class_val = dsdb_class_by_lDAPDisplayName_ldb_val(schema, display_name);
		if (class_val == NULL) {
			DBG_WARNING("Failed to look up OID for value %s "
				    "while creating claim %s for attribute %s; "
				    "skipping value\n",
				    (display_name->data != NULL) ? (const char *)display_name->data : "<unknown>",
				    name.data, principal_attribute->name);
			continue;
		}

		claim->values[i] = class_val->governsID_id;
		++claim->value_count;
	}

	/* Shrink the array to fit. */
	claim->values = talloc_realloc(mem_ctx,
				       claim->values,
				       uint64_t,
				       claim->value_count);
	if (claim->value_count && claim->values == NULL) {
		return ldb_oom(ldb);
	}

	return LDB_SUCCESS;
}

static int fill_claim_boolean(TALLOC_CTX *mem_ctx,
			      struct ldb_context *ldb,
			      const struct ldb_message_element *principal_attribute,
			      const struct ldb_val name,
			      struct CLAIM_UINT64 *claim)
{
	uint32_t i;

	claim->value_count = 0;
	claim->values = talloc_array(mem_ctx,
				     uint64_t,
				     principal_attribute->num_values);
	if (claim->values == NULL) {
		return ldb_oom(ldb);
	}

	for (i = 0; i < principal_attribute->num_values; ++i) {
		const struct ldb_val *value = &principal_attribute->values[i];
		bool val = false;
		int ret = ldb_val_as_bool(value, &val);
		if (ret) {
			char buf[1024];
			const char *reason = NULL;
			int err = strerror_r(ret, buf, sizeof(buf));
			if (err == 0) {
				reason = buf;
			} else {
				reason = "Unknown error";
			}
			DBG_WARNING("Failed to interpret value %s as BOOL "
				    "while creating claim %s for attribute %s (%s); "
				    "skipping value\n",
				    (value->data != NULL) ? (const char *)value->data : "<unknown>",
				    name.data, principal_attribute->name,
				    reason);
			continue;
		}

		claim->values[i] = val;
		++claim->value_count;
	}

	/* Shrink the array to fit. */
	claim->values = talloc_realloc(mem_ctx,
				       claim->values,
				       uint64_t,
				       claim->value_count);
	if (claim->value_count && claim->values == NULL) {
		return ldb_oom(ldb);
	}

	return LDB_SUCCESS;
}

static int fill_claim_string(TALLOC_CTX *mem_ctx,
			     struct ldb_context *ldb,
			     const struct ldb_message_element *principal_attribute,
			     struct CLAIM_STRING *claim)
{
	uint32_t i;

	claim->value_count = 0;
	claim->values = talloc_array(mem_ctx,
				     const char *,
				     principal_attribute->num_values);
	if (claim->values == NULL) {
		return ldb_oom(ldb);
	}

	for (i = 0; i < principal_attribute->num_values; ++i) {
		const char *val = NULL;
		const struct ldb_val *v = &principal_attribute->values[i];

		if (v == NULL || v->data == NULL) {
			continue;
		}

		val = talloc_strndup(claim->values,
				     (const char *)v->data,
				     v->length);
		if (val == NULL) {
			return ldb_oom(ldb);
		}

		claim->values[i] = val;
		++claim->value_count;
	}

	/* Shrink the array to fit. */
	claim->values = talloc_realloc(mem_ctx,
				       claim->values,
				       const char *,
				       claim->value_count);
	if (claim->value_count && claim->values == NULL) {
		return ldb_oom(ldb);
	}

	return LDB_SUCCESS;
}

static int fill_claim_string_sec_desc_syntax(TALLOC_CTX *mem_ctx,
					     struct ldb_context *ldb,
					     const struct ldb_message_element *principal_attribute,
					     struct CLAIM_STRING *claim)
{
	TALLOC_CTX *tmp_ctx = NULL;
	const struct dom_sid *domain_sid = NULL;
	uint32_t i;

	claim->value_count = 0;
	claim->values = talloc_array(mem_ctx,
				     const char *,
				     principal_attribute->num_values);
	if (claim->values == NULL) {
		return ldb_oom(ldb);
	}

	domain_sid = samdb_domain_sid(ldb);
	if (domain_sid == NULL) {
		return ldb_oom(ldb);
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	for (i = 0; i < principal_attribute->num_values; ++i) {
		const struct ldb_val *v = &principal_attribute->values[i];

		enum ndr_err_code ndr_err;
		struct security_descriptor desc = {};
		const char *sddl = NULL;

		if (v == NULL || v->data == NULL) {
			continue;
		}

		ndr_err = ndr_pull_struct_blob(v,
					       tmp_ctx,
					       &desc,
					       (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
			DBG_ERR("security_descriptor pull failed: %s\n",
				nt_errstr(nt_status));
			talloc_free(tmp_ctx);
			return ldb_operr(ldb);
		}

		sddl = sddl_encode(mem_ctx,
				   &desc,
				   domain_sid);
		if (sddl == NULL) {
			talloc_free(tmp_ctx);
			return ldb_oom(ldb);
		}

		claim->values[i] = sddl;
		++claim->value_count;
	}

	talloc_free(tmp_ctx);

	/* Shrink the array to fit. */
	claim->values = talloc_realloc(mem_ctx,
				       claim->values,
				       const char *,
				       claim->value_count);
	if (claim->value_count && claim->values == NULL) {
		return ldb_oom(ldb);
	}

	return LDB_SUCCESS;
}

static int fill_claim_entry(TALLOC_CTX *mem_ctx,
			    struct ldb_context *ldb,
			    const struct dsdb_schema *schema,
			    const struct ldb_message_element *principal_attribute,
			    const struct ldb_val name,
			    const DATA_BLOB syntax,
			    enum CLAIM_TYPE claim_type,
			    struct CLAIM_ENTRY *claim_entry)
{

	claim_entry->id = talloc_strndup(mem_ctx,
				     (const char *)name.data,
				     name.length);
	if (claim_entry->id == NULL) {
		return ldb_oom(ldb);
	}

	claim_entry->type = claim_type;

	switch (claim_type) {
	case CLAIM_TYPE_INT64:
		return fill_claim_int64(mem_ctx,
					ldb,
					principal_attribute,
					name,
					&claim_entry->values.claim_int64);
	case CLAIM_TYPE_UINT64:
		if (syntax.data != NULL && data_blob_equals_str(syntax, "2.5.5.2")) {
			return fill_claim_uint64_oid_syntax(mem_ctx,
						 ldb,
						 schema,
						 principal_attribute,
						 name,
						 &claim_entry->values.claim_uint64);
		} else {
			return fill_claim_uint64(mem_ctx,
						 ldb,
						 principal_attribute,
						 name,
						 &claim_entry->values.claim_uint64);
		}
	case CLAIM_TYPE_BOOLEAN:
		return fill_claim_boolean(mem_ctx,
					  ldb,
					  principal_attribute,
					  name,
					  &claim_entry->values.claim_boolean);
	case CLAIM_TYPE_STRING:
	default:
		if (syntax.data != NULL && data_blob_equals_str(syntax, "2.5.5.15")) {
			return fill_claim_string_sec_desc_syntax(mem_ctx,
								 ldb,
								 principal_attribute,
								 &claim_entry->values.claim_string);
		} else {
			return fill_claim_string(mem_ctx,
						 ldb,
						 principal_attribute,
						 &claim_entry->values.claim_string);
		}
	}
}

/*
 * Determine whether a claim applies to the most specific objectClass of the
 * principal.
 */
static int claim_applies_to_class(TALLOC_CTX *mem_ctx,
				  struct ldb_context *ldb,
				  const struct dsdb_schema *schema,
				  const struct ldb_message *claim_msg,
				  const uint32_t principal_class_id,
				  bool *applies)
{
	struct ldb_message_element *applies_to_class = NULL;
	unsigned i;

	applies_to_class = ldb_msg_find_element(claim_msg,
						"msDS-ClaimTypeAppliesToClass");
	if (applies_to_class == NULL) {
		*applies = false;
		return LDB_SUCCESS;
	}

	for (i = 0; i < applies_to_class->num_values; ++i) {
		struct ldb_dn *class_dn = NULL;
		const struct dsdb_class *class_val = NULL;
		const struct ldb_val *class_rdn = NULL;

		class_dn = ldb_dn_from_ldb_val(mem_ctx,
					       ldb,
					       &applies_to_class->values[i]);
		if (class_dn == NULL) {
			return ldb_oom(ldb);
		}

		class_rdn = ldb_dn_get_rdn_val(class_dn);
		if (class_rdn == NULL) {
			TALLOC_FREE(class_dn);
			continue;
		}

		class_val = dsdb_class_by_cn_ldb_val(schema, class_rdn);
		TALLOC_FREE(class_dn);
		if (class_val == NULL) {
			continue;
		}

		if (class_val->governsID_id == principal_class_id) {
			*applies = true;
			return LDB_SUCCESS;
		}
	}

	*applies = false;
	return LDB_SUCCESS;
}

struct assigned_silo {
	const char *name;
	bool is_initialised;
	bool is_assigned;
};

static struct assigned_silo new_assigned_silo(void)
{
	return (struct assigned_silo) {
		.name = NULL,
		.is_initialised = false,
		.is_assigned = false,
	};
}

static bool silo_is_maybe_assigned(struct assigned_silo silo)
{
	return !silo.is_initialised || silo.is_assigned;
}

static int get_assigned_silo(struct ldb_context *ldb,
			     TALLOC_CTX *mem_ctx,
			     const struct ldb_message *principal,
			     struct assigned_silo *assigned_silo)
{
	TALLOC_CTX *tmp_ctx = NULL;
	int ret;

	const struct ldb_message *silo_msg = NULL;
	static const char * const silo_attrs[] = {
		"msDS-AuthNPolicySiloEnforced",
		"msDS-AuthNPolicySiloMembers",
		"name",
		NULL
	};

	bool is_silo_enforced = false;
	const char *silo_name = NULL;

	if (assigned_silo->is_initialised) {
		return LDB_SUCCESS;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	if (!authn_policy_silos_and_policies_in_effect(ldb)) {
		/* No assigned silo. */
		assigned_silo->is_assigned = false;
		assigned_silo->is_initialised = true;

		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	/* Check whether the user is assigned to an enforced silo. */
	ret = authn_policy_get_assigned_silo(ldb,
					     tmp_ctx,
					     principal,
					     silo_attrs,
					     &silo_msg,
					     &is_silo_enforced);
	if (ret) {
		talloc_free(tmp_ctx);
		return ret;
	}

	if (silo_msg == NULL || !is_silo_enforced) {
		/* No assigned silo. */
		assigned_silo->is_assigned = false;
		assigned_silo->is_initialised = true;

		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	/* The user does belong to a silo, so return the name of the silo. */
	silo_name = ldb_msg_find_attr_as_string(silo_msg,
						"name",
						NULL);
	assigned_silo->name = talloc_steal(mem_ctx, silo_name);
	assigned_silo->is_assigned = true;
	assigned_silo->is_initialised = true;

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}

static uint32_t claim_get_value_count(const struct CLAIM_ENTRY *claim)
{
	switch (claim->type) {
	case CLAIM_TYPE_INT64:
		return claim->values.claim_int64.value_count;
	case CLAIM_TYPE_UINT64:
		return claim->values.claim_uint64.value_count;
	case CLAIM_TYPE_STRING:
		return claim->values.claim_string.value_count;
	case CLAIM_TYPE_BOOLEAN:
		return claim->values.claim_boolean.value_count;
	}

	smb_panic(__location__ ": unknown claim type");
	return 0;
}

static bool is_schema_dn(struct ldb_dn *dn,
			 struct ldb_dn *schema_dn)
{
	if (ldb_dn_get_comp_num(dn) != (ldb_dn_get_comp_num(schema_dn) + 1)) {
		return false;
	}

	return ldb_dn_compare_base(schema_dn, dn) == 0;
}

static bool is_valid_claim_attribute_syntax(const DATA_BLOB source_syntax,
					    uint64_t claim_value_type)
{
	switch (claim_value_type) {
	case CLAIM_TYPE_STRING:
		if (data_blob_equals_str(source_syntax, "2.5.5.1")) {
			return true;
		}
		if (data_blob_equals_str(source_syntax, "2.5.5.12")) {
			return true;
		}
		if (data_blob_equals_str(source_syntax, "2.5.5.15")) {
			return true;
		}
		break;
	case CLAIM_TYPE_UINT64:
		if (data_blob_equals_str(source_syntax, "2.5.5.2")) {
			return true;
		}
		break;
	case CLAIM_TYPE_INT64:
		if (data_blob_equals_str(source_syntax, "2.5.5.9")) {
			return true;
		}
		if (data_blob_equals_str(source_syntax, "2.5.5.16")) {
			return true;
		}
		break;
	case CLAIM_TYPE_BOOLEAN:
		/* Note: MS-ADTS has a typo (2.2.5.8 instead of 2.5.5.8) */
		if (data_blob_equals_str(source_syntax, "2.5.5.8")) {
			return true;
		}
		break;
	default:
		break;
	}

	return false;
}

static int get_all_claims(struct ldb_context *ldb,
			  TALLOC_CTX *mem_ctx,
			  const struct ldb_message *principal,
			  uint32_t principal_class_id,
			  struct CLAIMS_SET **claims_set_out)
{
	TALLOC_CTX *tmp_ctx = NULL;

	const struct dsdb_schema *schema = NULL;

	struct ldb_dn *claim_config_container = NULL;
	struct ldb_dn *claim_types_child = NULL;
	struct ldb_dn *config_dn = ldb_get_config_basedn(ldb);
	struct ldb_dn *schema_dn = ldb_get_schema_basedn(ldb);
	bool ok;
	int ret;
	struct ldb_result *res = NULL;
	static const char * const attrs[] = {
		"Enabled",
		"msDS-ClaimAttributeSource",
		"msDS-ClaimSource",
		"msDS-ClaimSourceType",
		"msDS-ClaimTypeAppliesToClass",
		"msDS-ClaimValueType",
		"name",
		NULL
	};

	const char **ad_claim_attrs = NULL;
	unsigned int ad_claim_attrs_count;
	struct ad_claim_info {
		struct ldb_val name;
		DATA_BLOB syntax;
		const char *attribute;
		enum CLAIM_TYPE claim_type;
	} *ad_claims = NULL;
	unsigned ad_claims_count;

	unsigned i;

	/* The structure which we'll use to build up the claims. */
	struct CLAIMS_SET *claims_set = NULL;

	struct CLAIMS_ARRAY *ad_sourced_constructed = NULL;

	struct assigned_silo assigned_silo = new_assigned_silo();

	*claims_set_out = NULL;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	claims_set = talloc_zero(tmp_ctx, struct CLAIMS_SET);
	if (claims_set == NULL) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	schema = dsdb_get_schema(ldb, tmp_ctx);
	if (schema == NULL) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	/* Get the DN of the claims container. */
	claim_config_container = ldb_dn_copy(tmp_ctx, config_dn);
	if (claim_config_container == NULL) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	claim_types_child = ldb_dn_new(tmp_ctx, ldb,
				       "CN=Claim Types,CN=Claims Configuration,CN=Services");
	if (claim_types_child == NULL) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	ok = ldb_dn_add_child(claim_config_container, claim_types_child);
	TALLOC_FREE(claim_types_child);
	if (!ok) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	/* Search for the claims container's children. */
	ret = ldb_search(ldb, tmp_ctx, &res,
			 claim_config_container,
			 LDB_SCOPE_ONELEVEL,
			 attrs, NULL);
	if (ret) {
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			ret = LDB_SUCCESS;
		}

		talloc_free(tmp_ctx);
		return ret;
	}

	/*
	 * Allocate enough space for all AD claim attributes, followed by space
	 * for a NULL marker (so it can be passed as the attributes filter to an
	 * LDB search).
	 */
	ad_claim_attrs = talloc_array(tmp_ctx,
				      const char *,
				      res->count + 1);
	if (ad_claim_attrs == NULL) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}
	ad_claims = talloc_array(tmp_ctx,
				 struct ad_claim_info,
				 res->count);
	if (ad_claims == NULL) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}
	ad_claims_count = ad_claim_attrs_count = 0;

	/* Loop through each child of the claims container. */
	for (i = 0; i < res->count; ++i) {
		bool claim_applies = false;

		int enabled;
		uint64_t claim_value_type;

		const char *claim_source_type = NULL;
		const struct ldb_val *claim_attribute_source = NULL;
		const char *claim_source = NULL;

		/*
		 * Does this claim apply to the most specific objectClass of the
		 * principal?
		 */
		ret = claim_applies_to_class(tmp_ctx,
					     ldb,
					     schema,
					     res->msgs[i],
					     principal_class_id,
					     &claim_applies);
		if (ret) {
			talloc_free(tmp_ctx);
			return ret;
		}
		if (!claim_applies) {
			/* If the claim doesn't apply, skip it. */
			continue;
		}

		enabled = ldb_msg_find_attr_as_bool(res->msgs[i], "Enabled", 0);
		if (!enabled) {
			/* If the claim isn't enabled, skip it. */
			continue;
		}

		claim_value_type = ldb_msg_find_attr_as_uint64(res->msgs[i],
							       "msDS-ClaimValueType",
							       0);
		if (!claim_value_type) {
			continue;
		}

		claim_source_type = ldb_msg_find_attr_as_string(res->msgs[i],
								"msDS-ClaimSourceType",
								"");

		/* Get the attribute used by the claim. */
		claim_attribute_source = ldb_msg_find_ldb_val(res->msgs[i],
							      "msDS-ClaimAttributeSource");

		claim_source = ldb_msg_find_attr_as_string(res->msgs[i],
							   "msDS-ClaimSource",
							   NULL);

		if (strcasecmp(claim_source_type, "AD") == 0) {
			struct ldb_dn *claim_attribute_source_dn = NULL;
			const struct ldb_val *claim_attribute_source_rdn = NULL;
			const struct dsdb_attribute *claim_attribute_source_class = NULL;

			DATA_BLOB source_syntax;
			const char *attribute = NULL;
			const struct ldb_val *name = NULL;
			const struct ldb_val null_name = {};

			if (claim_attribute_source == NULL) {
				continue;
			}

			claim_attribute_source_dn = ldb_val_as_dn(ldb,
								  tmp_ctx,
								  claim_attribute_source);
			if (claim_attribute_source_dn == NULL) {
				talloc_free(tmp_ctx);
				return ldb_operr(ldb);
			}

			if (!is_schema_dn(claim_attribute_source_dn, schema_dn)) {
				/* This DN doesn't belong to the schema. */
				continue;
			}

			claim_attribute_source_rdn = ldb_dn_get_rdn_val(claim_attribute_source_dn);
			if (claim_attribute_source_rdn == NULL) {
				/* No RDN, skip it. */
				continue;
			}

			claim_attribute_source_class = dsdb_attribute_by_cn_ldb_val(schema,
										    claim_attribute_source_rdn);
			claim_attribute_source_rdn = NULL;
			TALLOC_FREE(claim_attribute_source_dn);
			if (claim_attribute_source_class == NULL) {
				continue;
			}

			source_syntax = data_blob_string_const(claim_attribute_source_class->attributeSyntax_oid);
			if (source_syntax.data == NULL) {
				continue;
			}

			if (!is_valid_claim_attribute_syntax(source_syntax, claim_value_type)) {
				continue;
			}

			attribute = claim_attribute_source_class->lDAPDisplayName;
			if (attribute == NULL) {
				continue;
			}

			ret = add_attr_unique(tmp_ctx,
					      ad_claim_attrs,
					      &ad_claim_attrs_count,
					      attribute);
			if (ret) {
				talloc_free(tmp_ctx);
				return ret;
			}

			name = ldb_msg_find_ldb_val(res->msgs[i], "name");
			if (name == NULL) {
				name = &null_name;
			}

			ad_claims[ad_claims_count++] = (struct ad_claim_info) {
				.name = *name,
				.syntax = source_syntax,
				.attribute = attribute,
				.claim_type = claim_value_type,
			};
		} else if (silo_is_maybe_assigned(assigned_silo)
			   && strcasecmp(claim_source_type, "Constructed") == 0)
		{
			const struct ldb_val *name = NULL;
			struct CLAIM_STRING *claim = NULL;
			struct CLAIM_ENTRY *claim_entry = NULL;
			const char *claim_value = NULL;

			if (claim_attribute_source != NULL) {
				continue;
			}

			if (claim_source != NULL) {
				continue;
			}

			name = ldb_msg_find_ldb_val(res->msgs[i], "name");
			if (name == NULL || name->data == NULL) {
				continue;
			}
			/* Does the claim ID match exactly in case? */
			if (strcmp((const char *)name->data, "ad://ext/AuthenticationSilo") != 0) {
				continue;
			}

			ret = get_assigned_silo(ldb, tmp_ctx, principal, &assigned_silo);
			if (ret) {
				talloc_free(tmp_ctx);
				return ret;
			}
			if (!assigned_silo.is_assigned) {
				continue;
			}

			if (ad_sourced_constructed == NULL) {
				claims_set->claims_arrays = talloc_realloc(claims_set,
									       claims_set->claims_arrays,
									       struct CLAIMS_ARRAY,
									       claims_set->claims_array_count + 1);
				if (claims_set->claims_arrays == NULL) {
					talloc_free(tmp_ctx);
					return ldb_oom(ldb);
				}

				ad_sourced_constructed = &claims_set->claims_arrays[claims_set->claims_array_count++];
				*ad_sourced_constructed = (struct CLAIMS_ARRAY) {
					.claims_source_type = CLAIMS_SOURCE_TYPE_AD,
				};
			}

			/* Add the claim to the array. */
			ad_sourced_constructed->claim_entries = talloc_realloc(
				claims_set->claims_arrays,
				ad_sourced_constructed->claim_entries,
				struct CLAIM_ENTRY,
				ad_sourced_constructed->claims_count + 1);
			if (ad_sourced_constructed->claim_entries == NULL) {
				talloc_free(tmp_ctx);
				return ldb_oom(ldb);
			}

			claim_entry = &ad_sourced_constructed->claim_entries[ad_sourced_constructed->claims_count++];

			/* Fill in the claim details and return the claim. */
			claim_entry->id = "ad://ext/AuthenticationSilo";
			claim_entry->type = CLAIM_TYPE_STRING;

			claim = &claim_entry->values.claim_string;

			claim->value_count = 1;
			claim->values = talloc_array(ad_sourced_constructed->claim_entries,
						     const char *,
						     claim->value_count);
			if (claim->values == NULL) {
				talloc_free(tmp_ctx);
				return ldb_oom(ldb);
			}

			claim_value = talloc_strdup(claim->values, assigned_silo.name);
			if (claim_value == NULL) {
				talloc_free(tmp_ctx);
				return ldb_oom(ldb);
			}

			claim->values[0] = claim_value;
		}
	}

	if (ad_claims_count) {
		struct ldb_message *principal_msg = NULL;

		/* Shrink the arrays to remove any unused space. */
		ad_claim_attrs = talloc_realloc(tmp_ctx,
						ad_claim_attrs,
						const char *,
						ad_claim_attrs_count + 1);
		if (ad_claim_attrs == NULL) {
			talloc_free(tmp_ctx);
			return ldb_oom(ldb);
		}
		ad_claim_attrs[ad_claim_attrs_count] = NULL;

		ad_claims = talloc_realloc(tmp_ctx,
					   ad_claims,
					   struct ad_claim_info,
					   ad_claims_count);
		if (ad_claims == NULL) {
			talloc_free(tmp_ctx);
			return ldb_oom(ldb);
		}

		ret = dsdb_search_one(ldb,
				      tmp_ctx,
				      &principal_msg,
				      principal->dn,
				      LDB_SCOPE_BASE,
				      ad_claim_attrs,
				      0,
				      NULL);
		if (ret != LDB_SUCCESS) {
			const char *dn = ldb_dn_get_linearized(principal->dn);
			DBG_ERR("Failed to find principal %s to construct claims\n",
				dn != NULL ? dn : "<NULL>");
			talloc_free(tmp_ctx);
			return ret;
		}

		/*
		 * Ensure that only the attrs we asked for end up in the results
		 * (it's fine if some are missing)
		 */
		SMB_ASSERT(principal_msg->num_elements <= ad_claim_attrs_count);

		for (i = 0; i < ad_claims_count; ++i) {
			const struct ldb_message_element *principal_attribute = NULL;
			struct CLAIM_ENTRY *claim_entry = NULL;
			uint32_t new_claims_array_count = claims_set->claims_array_count;

			/* Get the value of the claim attribute for the principal. */
			principal_attribute = ldb_msg_find_element(principal_msg,
								   ad_claims[i].attribute);
			if (principal_attribute == NULL) {
				continue;
			}

			/* Add the claim to the array. */

			if (ad_sourced_constructed == NULL) {
				claims_set->claims_arrays = talloc_realloc(claims_set,
									       claims_set->claims_arrays,
									       struct CLAIMS_ARRAY,
									       new_claims_array_count + 1);
				if (claims_set->claims_arrays == NULL) {
					talloc_free(tmp_ctx);
					return ldb_oom(ldb);
				}

				ad_sourced_constructed = &claims_set->claims_arrays[new_claims_array_count++];
				*ad_sourced_constructed = (struct CLAIMS_ARRAY) {
					.claims_source_type = CLAIMS_SOURCE_TYPE_AD,
				};
			}

			ad_sourced_constructed->claim_entries = talloc_realloc(
				claims_set->claims_arrays,
				ad_sourced_constructed->claim_entries,
				struct CLAIM_ENTRY,
				ad_sourced_constructed->claims_count + 1);
			if (ad_sourced_constructed->claim_entries == NULL) {
				talloc_free(tmp_ctx);
				return ldb_oom(ldb);
			}

			claim_entry = &ad_sourced_constructed->claim_entries[
				ad_sourced_constructed->claims_count];

			ret = fill_claim_entry(ad_sourced_constructed->claim_entries,
					       ldb,
					       schema,
					       principal_attribute,
					       ad_claims[i].name,
					       ad_claims[i].syntax,
					       ad_claims[i].claim_type,
					       claim_entry);
			if (ret != LDB_SUCCESS) {
				talloc_free(tmp_ctx);
				return ret;
			}

			if (claim_get_value_count(claim_entry) > 0) {
				/*
				 * If the claim contains values, add it to the
				 * array(s).
				 */
				++ad_sourced_constructed->claims_count;
				claims_set->claims_array_count = new_claims_array_count;
			}
		}
	}

	if (claims_set->claims_array_count) {
		*claims_set_out = talloc_steal(mem_ctx, claims_set);
	}

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}

int get_claims_set_for_principal(struct ldb_context *ldb,
				 TALLOC_CTX *mem_ctx,
				 const struct ldb_message *principal,
				 struct CLAIMS_SET **claims_set_out)
{
	struct ldb_message_element *principal_class_el = NULL;
	struct dsdb_schema *schema = NULL;
	const struct dsdb_class *principal_class = NULL;

	*claims_set_out = NULL;

	if (!ad_claims_are_issued(ldb)) {
		return LDB_SUCCESS;
	}

	principal_class_el = ldb_msg_find_element(principal,
						  "objectClass");
	if (principal_class_el == NULL) {
		return ldb_operr(ldb);
	}

	schema = dsdb_get_schema(ldb, mem_ctx);
	if (schema == NULL) {
		return ldb_operr(ldb);
	}

	principal_class = dsdb_get_last_structural_class(schema, principal_class_el);
	if (principal_class == NULL) {
		return ldb_operr(ldb);
	}

	return get_all_claims(ldb,
			      mem_ctx,
			      principal,
			      principal_class->governsID_id,
			      claims_set_out);
}
