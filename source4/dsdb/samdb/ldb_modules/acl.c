/*
  ldb database library

  Copyright (C) Simo Sorce 2006-2008
  Copyright (C) Nadezhda Ivanova 2009
  Copyright (C) Anatoliy Atanasov  2009

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

/*
 *  Name: ldb
 *
 *  Component: ldb ACL module
 *
 *  Description: Module that performs authorisation access checks based on the
 *               account's security context and the DACL of the object being polled.
 *               Only DACL checks implemented at this point
 *
 *  Authors: Nadezhda Ivanova, Anatoliy Atanasov
 */

#include "includes.h"
#include "ldb_module.h"
#include "auth/auth.h"
#include "libcli/security/security.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "param/param.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "lib/util/tsort.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"

#undef strcasecmp
#undef strncasecmp

struct acl_private {
	bool acl_search;
	const char **password_attrs;
	void *cached_schema_ptr;
	uint64_t cached_schema_metadata_usn;
	uint64_t cached_schema_loaded_usn;
	const char **confidential_attrs;
};

struct acl_context {
	struct ldb_module *module;
	struct ldb_request *req;
	bool am_system;
	bool am_administrator;
	bool constructed_attrs;
	bool allowedAttributes;
	bool allowedAttributesEffective;
	bool allowedChildClasses;
	bool allowedChildClassesEffective;
	bool sDRightsEffective;
	struct dsdb_schema *schema;
};

static int acl_module_init(struct ldb_module *module)
{
	struct ldb_context *ldb;
	struct acl_private *data;
	int ret;

	ldb = ldb_module_get_ctx(module);

	data = talloc_zero(module, struct acl_private);
	if (data == NULL) {
		return ldb_oom(ldb);
	}

	data->acl_search = lpcfg_parm_bool(ldb_get_opaque(ldb, "loadparm"),
					NULL, "acl", "search", true);
	ldb_module_set_private(module, data);

	ret = ldb_mod_register_control(module, LDB_CONTROL_SD_FLAGS_OID);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "acl_module_init: Unable to register control with rootdse!\n");
		return ldb_operr(ldb);
	}

	return ldb_next_init(module);
}

static int acl_allowedAttributes(struct ldb_module *module,
				 const struct dsdb_schema *schema,
				 struct ldb_message *sd_msg,
				 struct ldb_message *msg,
				 struct acl_context *ac)
{
	struct ldb_message_element *oc_el;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	TALLOC_CTX *mem_ctx;
	const char **attr_list;
	int i, ret;
	const struct dsdb_class *objectclass;

	/* If we don't have a schema yet, we can't do anything... */
	if (schema == NULL) {
		ldb_asprintf_errstring(ldb, "cannot add allowedAttributes to %s because no schema is loaded", ldb_dn_get_linearized(msg->dn));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Must remove any existing attribute */
	if (ac->allowedAttributes) {
		ldb_msg_remove_attr(msg, "allowedAttributes");
	}

	mem_ctx = talloc_new(msg);
	if (!mem_ctx) {
		return ldb_oom(ldb);
	}

	oc_el = ldb_msg_find_element(sd_msg, "objectClass");
	attr_list = dsdb_full_attribute_list(mem_ctx, schema, oc_el, DSDB_SCHEMA_ALL);
	if (!attr_list) {
		ldb_asprintf_errstring(ldb, "acl: Failed to get list of attributes");
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * Get the top-most structural object class for the ACL check
	 */
	objectclass = dsdb_get_last_structural_class(ac->schema,
						     oc_el);
	if (objectclass == NULL) {
		ldb_asprintf_errstring(ldb, "acl_read: Failed to find a structural class for %s",
				       ldb_dn_get_linearized(sd_msg->dn));
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ac->allowedAttributes) {
		for (i=0; attr_list && attr_list[i]; i++) {
			ldb_msg_add_string(msg, "allowedAttributes", attr_list[i]);
		}
	}
	if (ac->allowedAttributesEffective) {
		struct security_descriptor *sd;
		struct dom_sid *sid = NULL;
		struct ldb_control *as_system = ldb_request_get_control(ac->req,
									LDB_CONTROL_AS_SYSTEM_OID);

		if (as_system != NULL) {
			as_system->critical = 0;
		}

		ldb_msg_remove_attr(msg, "allowedAttributesEffective");
		if (ac->am_system || as_system) {
			for (i=0; attr_list && attr_list[i]; i++) {
				ldb_msg_add_string(msg, "allowedAttributesEffective", attr_list[i]);
			}
			return LDB_SUCCESS;
		}

		ret = dsdb_get_sd_from_ldb_message(ldb_module_get_ctx(module), mem_ctx, sd_msg, &sd);

		if (ret != LDB_SUCCESS) {
			return ret;
		}

		sid = samdb_result_dom_sid(mem_ctx, sd_msg, "objectSid");
		for (i=0; attr_list && attr_list[i]; i++) {
			const struct dsdb_attribute *attr = dsdb_attribute_by_lDAPDisplayName(schema,
											attr_list[i]);
			if (!attr) {
				return ldb_operr(ldb);
			}
			/* remove constructed attributes */
			if (attr->systemFlags & DS_FLAG_ATTR_IS_CONSTRUCTED
			    || attr->systemOnly
			    || (attr->linkID != 0 && attr->linkID % 2 != 0 )) {
				continue;
			}
			ret = acl_check_access_on_attribute(module,
							    msg,
							    sd,
							    sid,
							    SEC_ADS_WRITE_PROP,
							    attr,
							    objectclass);
			if (ret == LDB_SUCCESS) {
				ldb_msg_add_string(msg, "allowedAttributesEffective", attr_list[i]);
			}
		}
	}
	return LDB_SUCCESS;
}

static int acl_childClasses(struct ldb_module *module,
			    const struct dsdb_schema *schema,
			    struct ldb_message *sd_msg,
			    struct ldb_message *msg,
			    const char *attrName)
{
	struct ldb_message_element *oc_el;
	struct ldb_message_element *allowedClasses;
	const struct dsdb_class *sclass;
	unsigned int i, j;
	int ret;

	/* If we don't have a schema yet, we can't do anything... */
	if (schema == NULL) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module), "cannot add childClassesEffective to %s because no schema is loaded", ldb_dn_get_linearized(msg->dn));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Must remove any existing attribute, or else confusion reigns */
	ldb_msg_remove_attr(msg, attrName);
	ret = ldb_msg_add_empty(msg, attrName, 0, &allowedClasses);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	oc_el = ldb_msg_find_element(sd_msg, "objectClass");

	for (i=0; oc_el && i < oc_el->num_values; i++) {
		sclass = dsdb_class_by_lDAPDisplayName_ldb_val(schema, &oc_el->values[i]);
		if (!sclass) {
			/* We don't know this class?  what is going on? */
			continue;
		}

		for (j=0; sclass->possibleInferiors && sclass->possibleInferiors[j]; j++) {
			ldb_msg_add_string(msg, attrName, sclass->possibleInferiors[j]);
		}
	}
	if (allowedClasses->num_values > 1) {
		TYPESAFE_QSORT(allowedClasses->values, allowedClasses->num_values, data_blob_cmp);
		for (i=1 ; i < allowedClasses->num_values; i++) {
			struct ldb_val *val1 = &allowedClasses->values[i-1];
			struct ldb_val *val2 = &allowedClasses->values[i];
			if (data_blob_cmp(val1, val2) == 0) {
				memmove(val1, val2, (allowedClasses->num_values - i) * sizeof(struct ldb_val));
				allowedClasses->num_values--;
				i--;
			}
		}
	}

	return LDB_SUCCESS;
}

static int acl_childClassesEffective(struct ldb_module *module,
				     const struct dsdb_schema *schema,
				     struct ldb_message *sd_msg,
				     struct ldb_message *msg,
				     struct acl_context *ac)
{
	struct ldb_message_element *oc_el;
	struct ldb_message_element *allowedClasses = NULL;
	const struct dsdb_class *sclass;
	struct security_descriptor *sd;
	struct ldb_control *as_system = ldb_request_get_control(ac->req,
								LDB_CONTROL_AS_SYSTEM_OID);
	struct dom_sid *sid = NULL;
	unsigned int i, j;
	int ret;

	if (as_system != NULL) {
		as_system->critical = 0;
	}

	if (ac->am_system || as_system) {
		return acl_childClasses(module, schema, sd_msg, msg, "allowedChildClassesEffective");
	}

	/* If we don't have a schema yet, we can't do anything... */
	if (schema == NULL) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module), "cannot add allowedChildClassesEffective to %s because no schema is loaded", ldb_dn_get_linearized(msg->dn));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Must remove any existing attribute, or else confusion reigns */
	ldb_msg_remove_attr(msg, "allowedChildClassesEffective");

	oc_el = ldb_msg_find_element(sd_msg, "objectClass");
	ret = dsdb_get_sd_from_ldb_message(ldb_module_get_ctx(module), msg, sd_msg, &sd);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	sid = samdb_result_dom_sid(msg, sd_msg, "objectSid");
	for (i=0; oc_el && i < oc_el->num_values; i++) {
		sclass = dsdb_class_by_lDAPDisplayName_ldb_val(schema, &oc_el->values[i]);
		if (!sclass) {
			/* We don't know this class?  what is going on? */
			continue;
		}

		for (j=0; sclass->possibleInferiors && sclass->possibleInferiors[j]; j++) {
			const struct dsdb_class *sc;

			sc = dsdb_class_by_lDAPDisplayName(schema,
							   sclass->possibleInferiors[j]);
			if (!sc) {
				/* We don't know this class?  what is going on? */
				continue;
			}

			ret = acl_check_access_on_objectclass(module, ac,
							      sd, sid,
							      SEC_ADS_CREATE_CHILD,
							      sc);
			if (ret == LDB_SUCCESS) {
				ldb_msg_add_string(msg, "allowedChildClassesEffective",
						   sclass->possibleInferiors[j]);
			}
		}
	}
	allowedClasses = ldb_msg_find_element(msg, "allowedChildClassesEffective");
	if (!allowedClasses) {
		return LDB_SUCCESS;
	}

	if (allowedClasses->num_values > 1) {
		TYPESAFE_QSORT(allowedClasses->values, allowedClasses->num_values, data_blob_cmp);
		for (i=1 ; i < allowedClasses->num_values; i++) {
			struct ldb_val *val1 = &allowedClasses->values[i-1];
			struct ldb_val *val2 = &allowedClasses->values[i];
			if (data_blob_cmp(val1, val2) == 0) {
				memmove(val1, val2, (allowedClasses->num_values - i) * sizeof( struct ldb_val));
				allowedClasses->num_values--;
				i--;
			}
		}
	}
	return LDB_SUCCESS;
}

static int acl_sDRightsEffective(struct ldb_module *module,
				 struct ldb_message *sd_msg,
				 struct ldb_message *msg,
				 struct acl_context *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_message_element *rightsEffective;
	int ret;
	struct security_descriptor *sd;
	struct ldb_control *as_system = ldb_request_get_control(ac->req,
								LDB_CONTROL_AS_SYSTEM_OID);
	struct dom_sid *sid = NULL;
	uint32_t flags = 0;

	if (as_system != NULL) {
		as_system->critical = 0;
	}

	/* Must remove any existing attribute, or else confusion reigns */
	ldb_msg_remove_attr(msg, "sDRightsEffective");
	ret = ldb_msg_add_empty(msg, "sDRightsEffective", 0, &rightsEffective);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (ac->am_system || as_system) {
		flags = SECINFO_OWNER | SECINFO_GROUP |  SECINFO_SACL |  SECINFO_DACL;
	} else {
		const struct dsdb_class *objectclass;
		const struct dsdb_attribute *attr;

		objectclass = dsdb_get_structural_oc_from_msg(ac->schema, sd_msg);
		if (objectclass == NULL) {
			return ldb_operr(ldb);
		}

		attr = dsdb_attribute_by_lDAPDisplayName(ac->schema,
							 "nTSecurityDescriptor");
		if (attr == NULL) {
			return ldb_operr(ldb);
		}

		/* Get the security descriptor from the message */
		ret = dsdb_get_sd_from_ldb_message(ldb, msg, sd_msg, &sd);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		sid = samdb_result_dom_sid(msg, sd_msg, "objectSid");
		ret = acl_check_access_on_attribute(module,
						    msg,
						    sd,
						    sid,
						    SEC_STD_WRITE_OWNER,
						    attr,
						    objectclass);
		if (ret == LDB_SUCCESS) {
			flags |= SECINFO_OWNER | SECINFO_GROUP;
		}

		/*
		 * This call is made with
		 * IMPLICIT_OWNER_READ_CONTROL_AND_WRITE_DAC_RIGHTS
		 * and without reference to the dSHeuristics via
		 * dsdb_block_owner_implicit_rights().  This is
		 * probably a Windows bug but for now we match
		 * exactly.
		 */
		ret = acl_check_access_on_attribute_implicit_owner(
			module,
			msg,
			sd,
			sid,
			SEC_STD_WRITE_DAC,
			attr,
			objectclass,
			IMPLICIT_OWNER_READ_CONTROL_AND_WRITE_DAC_RIGHTS);
		if (ret == LDB_SUCCESS) {
			flags |= SECINFO_DACL;
		}
		ret = acl_check_access_on_attribute(module,
						    msg,
						    sd,
						    sid,
						    SEC_FLAG_SYSTEM_SECURITY,
						    attr,
						    objectclass);
		if (ret == LDB_SUCCESS) {
			flags |= SECINFO_SACL;
		}
	}

	if (flags != (SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL | SECINFO_SACL)) {
		const struct ldb_message_element *el = samdb_find_attribute(ldb,
									    sd_msg,
									    "objectclass",
									    "computer");
		if (el != NULL) {
			return LDB_SUCCESS;
		}
	}

	return samdb_msg_add_uint(ldb_module_get_ctx(module), msg, msg,
				  "sDRightsEffective", flags);
}

static int acl_validate_spn_value(TALLOC_CTX *mem_ctx,
				  struct ldb_context *ldb,
				  const struct ldb_val *spn_value,
				  uint32_t userAccountControl,
				  const struct ldb_val *samAccountName,
				  const struct ldb_val *original_dnsHostName,
				  const struct ldb_val *dnsHostName,
				  const char *netbios_name,
				  const char *ntds_guid)
{
	krb5_error_code ret, princ_size;
	krb5_context krb_ctx;
	krb5_error_code kerr;
	krb5_principal principal;
	char *instanceName = NULL;
	char *serviceType = NULL;
	char *serviceName = NULL;
	const char *spn_value_str = NULL;
	size_t account_name_len;
	const char *forest_name = samdb_forest_name(ldb, mem_ctx);
	const char *base_domain = samdb_default_domain_name(ldb, mem_ctx);
	struct loadparm_context *lp_ctx = talloc_get_type(ldb_get_opaque(ldb, "loadparm"),
							  struct loadparm_context);
	bool is_dc = (userAccountControl & UF_SERVER_TRUST_ACCOUNT) ||
		(userAccountControl & UF_PARTIAL_SECRETS_ACCOUNT);

	spn_value_str = talloc_strndup(mem_ctx,
				       (const char *)spn_value->data,
				       spn_value->length);
	if (spn_value_str == NULL) {
		return ldb_oom(ldb);
	}

	if (spn_value->length == samAccountName->length &&
	    strncasecmp((const char *)spn_value->data,
			(const char *)samAccountName->data,
			spn_value->length) == 0)
	{
		/* MacOS X sets this value, and setting an SPN of your
		 * own samAccountName is both pointless and safe */
		return LDB_SUCCESS;
	}

	kerr = smb_krb5_init_context_basic(mem_ctx,
					   lp_ctx,
					   &krb_ctx);
	if (kerr != 0) {
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "Could not initialize kerberos context.");
	}

	ret = krb5_parse_name(krb_ctx, spn_value_str, &principal);
	if (ret) {
		krb5_free_context(krb_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	princ_size = krb5_princ_size(krb_ctx, principal);
	if (princ_size < 2) {
		DBG_WARNING("princ_size=%d\n", princ_size);
		goto fail;
	}

	ret = smb_krb5_principal_get_comp_string(mem_ctx, krb_ctx,
							  principal, 1, &instanceName);
	if (ret) {
		goto fail;
	}
	ret = smb_krb5_principal_get_comp_string(mem_ctx, krb_ctx,
						 principal, 0, &serviceType);
	if (ret) {
		goto fail;
	}
	if (krb5_princ_size(krb_ctx, principal) == 3) {
		ret = smb_krb5_principal_get_comp_string(mem_ctx, krb_ctx,
							 principal, 2, &serviceName);
		if (ret) {
			goto fail;
		}
	}

	if (serviceName) {
		if (!is_dc) {
			DBG_WARNING("is_dc=false, serviceName=%s,"
				    "serviceType=%s\n", serviceName,
				  serviceType);
			goto fail;
		}
		if (strcasecmp(serviceType, "ldap") == 0) {
			if (strcasecmp(serviceName, netbios_name) != 0 &&
			    strcasecmp(serviceName, forest_name) != 0) {
				DBG_WARNING("serviceName=%s\n", serviceName);
				goto fail;
			}

		} else if (strcasecmp(serviceType, "gc") == 0) {
			if (strcasecmp(serviceName, forest_name) != 0) {
				DBG_WARNING("serviceName=%s\n", serviceName);
				goto fail;
			}
		} else {
			if (strcasecmp(serviceName, base_domain) != 0 &&
			    strcasecmp(serviceName, netbios_name) != 0) {
				DBG_WARNING("serviceType=%s, "
					    "serviceName=%s\n",
					    serviceType, serviceName);
				goto fail;
			}
		}
	}

	account_name_len = samAccountName->length;
	if (account_name_len &&
	    samAccountName->data[account_name_len - 1] == '$')
	{
		/* Account for the '$' character. */
		--account_name_len;
	}

	/* instanceName can be samAccountName without $ or dnsHostName
	 * or "ntds_guid._msdcs.forest_domain for DC objects */
	if (strlen(instanceName) == account_name_len
	    && strncasecmp(instanceName,
			   (const char *)samAccountName->data,
			   account_name_len) == 0)
	{
		goto success;
	}
	if ((dnsHostName != NULL) &&
	    strlen(instanceName) == dnsHostName->length &&
	    (strncasecmp(instanceName,
			 (const char *)dnsHostName->data,
			 dnsHostName->length) == 0))
	{
		goto success;
	}
	if ((original_dnsHostName != NULL) &&
	    strlen(instanceName) == original_dnsHostName->length &&
	    (strncasecmp(instanceName,
			 (const char *)original_dnsHostName->data,
			 original_dnsHostName->length) == 0))
	{
		goto success;
	}
	if (is_dc) {
		const char *guid_str = NULL;
		guid_str = talloc_asprintf(mem_ctx,"%s._msdcs.%s",
					   ntds_guid,
					   forest_name);
		if (strcasecmp(instanceName, guid_str) == 0) {
			goto success;
		}
	}

fail:
	krb5_free_principal(krb_ctx, principal);
	krb5_free_context(krb_ctx);
	ldb_debug_set(ldb, LDB_DEBUG_WARNING,
		      "acl: spn validation failed for "
		      "spn[%.*s] uac[0x%x] account[%.*s] hostname[%.*s] "
		      "nbname[%s] ntds[%s] forest[%s] domain[%s]\n",
		      (int)spn_value->length, spn_value->data,
		      (unsigned)userAccountControl,
		      (int)samAccountName->length, samAccountName->data,
		      dnsHostName != NULL ? (int)dnsHostName->length : 0,
		      dnsHostName != NULL ? (const char *)dnsHostName->data : "",
		      netbios_name, ntds_guid,
		      forest_name, base_domain);
	return LDB_ERR_CONSTRAINT_VIOLATION;

success:
	krb5_free_principal(krb_ctx, principal);
	krb5_free_context(krb_ctx);
	return LDB_SUCCESS;
}

/*
 * Passing in 'el' is critical, we want to check all the values.
 *
 */
static int acl_check_spn(TALLOC_CTX *mem_ctx,
			 struct ldb_module *module,
			 struct ldb_request *req,
			 const struct ldb_message_element *el,
			 struct security_descriptor *sd,
			 struct dom_sid *sid,
			 const struct dsdb_attribute *attr,
			 const struct dsdb_class *objectclass,
			 const struct ldb_control *implicit_validated_write_control)
{
	int ret;
	unsigned int i;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_result *acl_res;
	struct ldb_result *netbios_res;
	struct ldb_dn *partitions_dn = samdb_partitions_dn(ldb, tmp_ctx);
	uint32_t userAccountControl;
	const char *netbios_name;
	const struct ldb_val *original_dns_host_name_val = NULL;
	const struct ldb_val *dns_host_name_val = NULL;
	const struct ldb_val *sam_account_name_val = NULL;
	struct GUID ntds;
	char *ntds_guid = NULL;
	const struct ldb_message *msg = NULL;
	const struct ldb_message *search_res = NULL;

	static const char *acl_attrs[] = {
		"sAMAccountName",
		"dnsHostName",
		"userAccountControl",
		NULL
	};
	static const char *netbios_attrs[] = {
		"nETBIOSName",
		NULL
	};

	if (req->operation == LDB_MODIFY) {
		msg = req->op.mod.message;
	} else if (req->operation == LDB_ADD) {
		msg = req->op.add.message;
	}

	if (implicit_validated_write_control != NULL) {
		/*
		 * The validated write control dispenses with ACL
		 * checks. We act as if we have an implicit Self Write
		 * privilege, but, assuming we don't have Write
		 * Property, still proceed with further validation
		 * checks.
		 */
	} else {
		/* if we have wp, we can do whatever we like */
		if (acl_check_access_on_attribute(module,
						  tmp_ctx,
						  sd,
						  sid,
						  SEC_ADS_WRITE_PROP,
						  attr, objectclass) == LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return LDB_SUCCESS;
		}

		ret = acl_check_extended_right(tmp_ctx,
					       module,
					       req,
					       objectclass,
					       sd,
					       acl_user_token(module),
					       GUID_DRS_VALIDATE_SPN,
					       SEC_ADS_SELF_WRITE,
					       sid);

		if (ret != LDB_SUCCESS) {
			dsdb_acl_debug(sd, acl_user_token(module),
				       msg->dn,
				       true,
				       10);
			talloc_free(tmp_ctx);
			return ret;
		}
	}

	/*
	 * If we have "validated write spn", allow delete of any
	 * existing value (this keeps constrained delete to the same
	 * rules as unconstrained)
	 */
	if (req->operation == LDB_MODIFY) {
		/*
		 * If not add or replace (eg delete),
		 * return success
		 */
		if (LDB_FLAG_MOD_TYPE(el->flags) != LDB_FLAG_MOD_ADD &&
		    LDB_FLAG_MOD_TYPE(el->flags) != LDB_FLAG_MOD_REPLACE)
		{
			talloc_free(tmp_ctx);
			return LDB_SUCCESS;
		}

		ret = dsdb_module_search_dn(module, tmp_ctx,
					    &acl_res, msg->dn,
					    acl_attrs,
					    DSDB_FLAG_NEXT_MODULE |
					    DSDB_FLAG_AS_SYSTEM |
					    DSDB_SEARCH_SHOW_RECYCLED,
					    req);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}

		search_res = acl_res->msgs[0];
	} else if (req->operation == LDB_ADD) {
		search_res = msg;
	} else {
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (req->operation == LDB_MODIFY) {
		original_dns_host_name_val = ldb_msg_find_ldb_val(
			search_res, "dNSHostName");
	}

	ret = dsdb_msg_get_single_value(msg,
					"dNSHostName",
					original_dns_host_name_val,
					&dns_host_name_val,
					req->operation);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	userAccountControl = ldb_msg_find_attr_as_uint(search_res, "userAccountControl", 0);

	if (req->operation == LDB_MODIFY) {
		sam_account_name_val = ldb_msg_find_ldb_val(search_res, "sAMAccountName");
	}

	ret = dsdb_msg_get_single_value(msg,
					"sAMAccountName",
					sam_account_name_val,
					&sam_account_name_val,
					req->operation);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_module_search(module, tmp_ctx,
				 &netbios_res, partitions_dn,
				 LDB_SCOPE_ONELEVEL,
				 netbios_attrs,
				 DSDB_FLAG_NEXT_MODULE |
				 DSDB_FLAG_AS_SYSTEM,
				 req,
				 "(ncName=%s)",
				 ldb_dn_get_linearized(ldb_get_default_basedn(ldb)));
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	netbios_name = ldb_msg_find_attr_as_string(netbios_res->msgs[0], "nETBIOSName", NULL);

	/*
	 * NTDSDSA objectGuid of object we are checking SPN for
	 *
	 * Note - do we have the necessary attributes for this during an add operation?
	 * How should we test this?
	 */
	if (userAccountControl & (UF_SERVER_TRUST_ACCOUNT | UF_PARTIAL_SECRETS_ACCOUNT)) {
		ret = dsdb_module_find_ntdsguid_for_computer(module, tmp_ctx,
							     msg->dn, &ntds, req);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb, "Failed to find NTDSDSA objectGuid for %s: %s",
					       ldb_dn_get_linearized(msg->dn),
					       ldb_strerror(ret));
			talloc_free(tmp_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ntds_guid = GUID_string(tmp_ctx, &ntds);
	}

	for (i=0; i < el->num_values; i++) {
		ret = acl_validate_spn_value(tmp_ctx,
					     ldb,
					     &el->values[i],
					     userAccountControl,
					     sam_account_name_val,
					     original_dns_host_name_val,
					     dns_host_name_val,
					     netbios_name,
					     ntds_guid);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}
	}
	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}

static int acl_check_dns_host_name(TALLOC_CTX *mem_ctx,
				   struct ldb_module *module,
				   struct ldb_request *req,
				   const struct ldb_message_element *el,
				   struct security_descriptor *sd,
				   struct dom_sid *sid,
				   const struct dsdb_attribute *attr,
				   const struct dsdb_class *objectclass,
				   const struct ldb_control *implicit_validated_write_control)
{
	int ret;
	unsigned i;
	TALLOC_CTX *tmp_ctx = NULL;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const struct dsdb_schema *schema = NULL;
	const struct ldb_message_element *allowed_suffixes = NULL;
	struct ldb_result *nc_res = NULL;
	struct ldb_dn *nc_root = NULL;
	const char *nc_dns_name = NULL;
	const char *dnsHostName_str = NULL;
	size_t dns_host_name_len;
	size_t account_name_len;
	const struct ldb_message *msg = NULL;
	const struct ldb_message *search_res = NULL;
	const struct ldb_val *samAccountName = NULL;
	const struct ldb_val *dnsHostName = NULL;
	const struct dsdb_class *computer_objectclass = NULL;
	bool is_subclass;

	static const char *nc_attrs[] = {
		"msDS-AllowedDNSSuffixes",
		NULL
	};

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	if (req->operation == LDB_MODIFY) {
		msg = req->op.mod.message;
	} else if (req->operation == LDB_ADD) {
		msg = req->op.add.message;
	}

	if (implicit_validated_write_control != NULL) {
		/*
		 * The validated write control dispenses with ACL
		 * checks. We act as if we have an implicit Self Write
		 * privilege, but, assuming we don't have Write
		 * Property, still proceed with further validation
		 * checks.
		 */
	} else {
		/* if we have wp, we can do whatever we like */
		ret = acl_check_access_on_attribute(module,
						    tmp_ctx,
						    sd,
						    sid,
						    SEC_ADS_WRITE_PROP,
						    attr, objectclass);
		if (ret == LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return LDB_SUCCESS;
		}

		ret = acl_check_extended_right(tmp_ctx,
					       module,
					       req,
					       objectclass,
					       sd,
					       acl_user_token(module),
					       GUID_DRS_DNS_HOST_NAME,
					       SEC_ADS_SELF_WRITE,
					       sid);

		if (ret != LDB_SUCCESS) {
			dsdb_acl_debug(sd, acl_user_token(module),
				       msg->dn,
				       true,
				       10);
			talloc_free(tmp_ctx);
			return ret;
		}
	}

	/*
	 * If we have "validated write dnshostname", allow delete of
	 * any existing value (this keeps constrained delete to the
	 * same rules as unconstrained)
	 */
	if (req->operation == LDB_MODIFY) {
		struct ldb_result *acl_res = NULL;

		static const char *acl_attrs[] = {
			"sAMAccountName",
			NULL
		};

		/*
		 * If not add or replace (eg delete),
		 * return success
		 */
		if (LDB_FLAG_MOD_TYPE(el->flags) != LDB_FLAG_MOD_ADD &&
		    LDB_FLAG_MOD_TYPE(el->flags) != LDB_FLAG_MOD_REPLACE)
		{
			talloc_free(tmp_ctx);
			return LDB_SUCCESS;
		}

		ret = dsdb_module_search_dn(module, tmp_ctx,
					    &acl_res, msg->dn,
					    acl_attrs,
					    DSDB_FLAG_NEXT_MODULE |
					    DSDB_FLAG_AS_SYSTEM |
					    DSDB_SEARCH_SHOW_RECYCLED,
					    req);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}

		search_res = acl_res->msgs[0];
	} else if (req->operation == LDB_ADD) {
		search_res = msg;
	} else {
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Check if the account has objectclass 'computer' or 'server'. */

	schema = dsdb_get_schema(ldb, req);
	if (schema == NULL) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	computer_objectclass = dsdb_class_by_lDAPDisplayName(schema, "computer");
	if (computer_objectclass == NULL) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	is_subclass = dsdb_is_subclass_of(schema, objectclass, computer_objectclass);
	if (!is_subclass) {
		/* The account is not a computer -- check if it's a server. */

		const struct dsdb_class *server_objectclass = NULL;

		server_objectclass = dsdb_class_by_lDAPDisplayName(schema, "server");
		if (server_objectclass == NULL) {
			talloc_free(tmp_ctx);
			return ldb_operr(ldb);
		}

		is_subclass = dsdb_is_subclass_of(schema, objectclass, server_objectclass);
		if (!is_subclass) {
			/* Not a computer or server, so no need to validate. */
			talloc_free(tmp_ctx);
			return LDB_SUCCESS;
		}
	}

	if (req->operation == LDB_MODIFY) {
		samAccountName = ldb_msg_find_ldb_val(search_res, "sAMAccountName");
	}

	ret = dsdb_msg_get_single_value(msg,
					"sAMAccountName",
					samAccountName,
					&samAccountName,
					req->operation);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	account_name_len = samAccountName->length;
	if (account_name_len && samAccountName->data[account_name_len - 1] == '$') {
		/* Account for the '$' character. */
		--account_name_len;
	}

	/* Check for add or replace requests with no value. */
	if (el->num_values == 0) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}
	dnsHostName = &el->values[0];

	dnsHostName_str = (const char *)dnsHostName->data;
	dns_host_name_len = dnsHostName->length;

	/* Check that sAMAccountName matches the new dNSHostName. */

	if (dns_host_name_len < account_name_len) {
		goto fail;
	}
	if (strncasecmp(dnsHostName_str,
			(const char *)samAccountName->data,
			account_name_len) != 0)
	{
		goto fail;
	}

	dnsHostName_str += account_name_len;
	dns_host_name_len -= account_name_len;

	/* Check the '.' character */

	if (dns_host_name_len == 0 || *dnsHostName_str != '.') {
		goto fail;
	}

	++dnsHostName_str;
	--dns_host_name_len;

	/* Now we check the suffix. */

	ret = dsdb_find_nc_root(ldb,
				tmp_ctx,
				search_res->dn,
				&nc_root);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	nc_dns_name = samdb_dn_to_dns_domain(tmp_ctx, nc_root);
	if (nc_dns_name == NULL) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	if (strlen(nc_dns_name) == dns_host_name_len &&
	    strncasecmp(dnsHostName_str,
			nc_dns_name,
			dns_host_name_len) == 0)
	{
		/* It matches -- success. */
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	/* We didn't get a match, so now try msDS-AllowedDNSSuffixes. */

	ret = dsdb_module_search_dn(module, tmp_ctx,
				    &nc_res, nc_root,
				    nc_attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_FLAG_AS_SYSTEM |
				    DSDB_SEARCH_SHOW_RECYCLED,
				    req);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	allowed_suffixes = ldb_msg_find_element(nc_res->msgs[0],
						"msDS-AllowedDNSSuffixes");
	if (allowed_suffixes == NULL) {
		goto fail;
	}

	for (i = 0; i < allowed_suffixes->num_values; ++i) {
		const struct ldb_val *suffix = &allowed_suffixes->values[i];

		if (suffix->length == dns_host_name_len &&
		    strncasecmp(dnsHostName_str,
				(const char *)suffix->data,
				dns_host_name_len) == 0)
		{
			/* It matches -- success. */
			talloc_free(tmp_ctx);
			return LDB_SUCCESS;
		}
	}

fail:
	ldb_debug_set(ldb, LDB_DEBUG_WARNING,
		      "acl: hostname validation failed for "
		      "hostname[%.*s] account[%.*s]\n",
		      (int)dnsHostName->length, dnsHostName->data,
		      (int)samAccountName->length, samAccountName->data);
	talloc_free(tmp_ctx);
	return LDB_ERR_CONSTRAINT_VIOLATION;
}

/* checks if modifications are allowed on "Member" attribute */
static int acl_check_self_membership(TALLOC_CTX *mem_ctx,
				     struct ldb_module *module,
				     struct ldb_request *req,
				     struct security_descriptor *sd,
				     struct dom_sid *sid,
				     const struct dsdb_attribute *attr,
				     const struct dsdb_class *objectclass)
{
	int ret;
	unsigned int i;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_dn *user_dn;
	struct ldb_message_element *member_el;
	const struct ldb_message *msg = NULL;

	if (req->operation == LDB_MODIFY) {
		msg = req->op.mod.message;
	} else if (req->operation == LDB_ADD) {
		msg = req->op.add.message;
	} else {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* if we have wp, we can do whatever we like */
	if (acl_check_access_on_attribute(module,
					  mem_ctx,
					  sd,
					  sid,
					  SEC_ADS_WRITE_PROP,
					  attr, objectclass) == LDB_SUCCESS) {
		return LDB_SUCCESS;
	}
	/* if we are adding/deleting ourselves, check for self membership */
	ret = dsdb_find_dn_by_sid(ldb, mem_ctx,
				  &acl_user_token(module)->sids[PRIMARY_USER_SID_INDEX],
				  &user_dn);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	member_el = ldb_msg_find_element(msg, "member");
	if (!member_el) {
		return ldb_operr(ldb);
	}
	/* user can only remove oneself */
	if (member_el->num_values == 0) {
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}
	for (i = 0; i < member_el->num_values; i++) {
		if (strcasecmp((const char *)member_el->values[i].data,
			       ldb_dn_get_extended_linearized(mem_ctx, user_dn, 1)) != 0) {
			return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
		}
	}
	ret = acl_check_extended_right(mem_ctx,
				       module,
				       req,
				       objectclass,
				       sd,
				       acl_user_token(module),
				       GUID_DRS_SELF_MEMBERSHIP,
				       SEC_ADS_SELF_WRITE,
				       sid);
	if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
		dsdb_acl_debug(sd, acl_user_token(module),
			       msg->dn,
			       true,
			       10);
	}
	return ret;
}

static int acl_add(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_dn *parent;
	struct ldb_context *ldb;
	const struct dsdb_schema *schema;
	const struct dsdb_class *objectclass;
	const struct dsdb_class *computer_objectclass = NULL;
	const struct ldb_message_element *oc_el = NULL;
	struct ldb_message_element sorted_oc_el;
	struct ldb_control *sd_ctrl = NULL;
	struct ldb_message_element *el;
	unsigned int instanceType = 0;
	struct dsdb_control_calculated_default_sd *control_sd = NULL;
	const struct dsdb_attribute *attr = NULL;
	const char **must_contain = NULL;
	const struct ldb_message *msg = req->op.add.message;
	const struct dom_sid *domain_sid = NULL;
	int i = 0;
	bool attribute_authorization;
	bool is_subclass;

	if (ldb_dn_is_special(msg->dn)) {
		return ldb_next_request(module, req);
	}

	if (dsdb_have_system_access(module, req, SYSTEM_CONTROL_STRIP_CRITICAL))
	{
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);
	domain_sid = samdb_domain_sid(ldb);

	parent = ldb_dn_get_parent(req, msg->dn);
	if (parent == NULL) {
		return ldb_oom(ldb);
	}

	schema = dsdb_get_schema(ldb, req);
	if (!schema) {
		return ldb_operr(ldb);
	}

	/* Find the objectclass of the new account. */

	oc_el = ldb_msg_find_element(msg, "objectclass");
	if (oc_el == NULL) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "acl: unable to find or validate structural objectClass on %s\n",
				       ldb_dn_get_linearized(msg->dn));
		return ldb_module_done(req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
	}

	schema = dsdb_get_schema(ldb, req);
	if (schema == NULL) {
		return ldb_operr(ldb);
	}

	ret = dsdb_sort_objectClass_attr(ldb, schema, oc_el, req, &sorted_oc_el);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	objectclass = dsdb_get_last_structural_class(schema, &sorted_oc_el);
	if (objectclass == NULL) {
		return ldb_operr(ldb);
	}

	el = ldb_msg_find_element(msg, "instanceType");
	if ((el != NULL) && (el->num_values != 1)) {
		ldb_set_errstring(ldb, "acl: the 'instanceType' attribute is single-valued!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	instanceType = ldb_msg_find_attr_as_uint(msg,
						 "instanceType", 0);
	if (instanceType & INSTANCE_TYPE_IS_NC_HEAD) {
		static const char *no_attrs[] = { NULL };
		struct ldb_result *partition_res;
		struct ldb_dn *partitions_dn;

		partitions_dn = samdb_partitions_dn(ldb, req);
		if (!partitions_dn) {
			ldb_set_errstring(ldb, "acl: CN=partitions dn could not be generated!");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		ret = dsdb_module_search(module, req, &partition_res,
					 partitions_dn, LDB_SCOPE_ONELEVEL,
					 no_attrs,
					 DSDB_FLAG_NEXT_MODULE |
					 DSDB_FLAG_AS_SYSTEM |
					 DSDB_SEARCH_ONE_ONLY |
					 DSDB_SEARCH_SHOW_RECYCLED,
					 req,
					 "(&(nCName=%s)(objectClass=crossRef))",
					 ldb_dn_get_linearized(msg->dn));

		if (ret == LDB_SUCCESS) {
			/* Check that we can write to the crossRef object MS-ADTS 3.1.1.5.2.8.2 */
			ret = dsdb_module_check_access_on_dn(module, req, partition_res->msgs[0]->dn,
							     SEC_ADS_WRITE_PROP,
							     &objectclass->schemaIDGUID, req);
			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(ldb_module_get_ctx(module),
						       "acl: ACL check failed on crossRef object %s: %s\n",
						       ldb_dn_get_linearized(partition_res->msgs[0]->dn),
						       ldb_errstring(ldb));
				return ret;
			}

			/*
			 * TODO: Remaining checks, like if we are
			 * the naming master etc need to be handled
			 * in the instanceType module
			 */
			/* Note - do we need per-attribute checks? */
			return ldb_next_request(module, req);
		}

		/* Check that we can create a crossRef object MS-ADTS 3.1.1.5.2.8.2 */
		ret = dsdb_module_check_access_on_dn(module, req, partitions_dn,
						     SEC_ADS_CREATE_CHILD,
						     &objectclass->schemaIDGUID, req);
		if (ret == LDB_ERR_NO_SUCH_OBJECT &&
		    ldb_request_get_control(req, LDB_CONTROL_RELAX_OID))
		{
			/* Allow provision bootstrap */
			ret = LDB_SUCCESS;
		}
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb_module_get_ctx(module),
					       "acl: ACL check failed on CN=Partitions crossRef container %s: %s\n",
					       ldb_dn_get_linearized(partitions_dn), ldb_errstring(ldb));
			return ret;
		}

		/*
		 * TODO: Remaining checks, like if we are the naming
		 * master and adding the crossRef object need to be
		 * handled in the instanceType module
		 */
	} else {
		ret = dsdb_module_check_access_on_dn(module, req, parent,
						     SEC_ADS_CREATE_CHILD,
						     &objectclass->schemaIDGUID, req);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb_module_get_ctx(module),
					       "acl: unable to get access to %s\n",
					       ldb_dn_get_linearized(msg->dn));
			return ret;
		}
	}

	attribute_authorization = dsdb_attribute_authz_on_ldap_add(module,
								   req,
								   req);
	if (!attribute_authorization) {
		/* Skip the remaining checks */
		goto success;
	}

	/* Check if we have computer objectclass. */
	computer_objectclass = dsdb_class_by_lDAPDisplayName(schema, "computer");
	if (computer_objectclass == NULL) {
		return ldb_operr(ldb);
	}

	is_subclass = dsdb_is_subclass_of(schema, objectclass, computer_objectclass);
	if (!is_subclass) {
		/*
		 * This object is not a computer (or derived from computer), so
		 * skip the remaining checks.
		 */
		goto success;
	}

	/*
	 * we have established we have CC right, now check per-attribute
	 * access based on the default SD
	 */

	sd_ctrl = ldb_request_get_control(req,
					  DSDB_CONTROL_CALCULATED_DEFAULT_SD_OID);
	if (sd_ctrl == NULL) {
		goto success;
	}

	{
		TALLOC_CTX *tmp_ctx = talloc_new(req);
		control_sd = (struct dsdb_control_calculated_default_sd *) sd_ctrl->data;
		DBG_DEBUG("Received cookie descriptor %s\n\n",
			  sddl_encode(tmp_ctx, control_sd->default_sd, domain_sid));
		TALLOC_FREE(tmp_ctx);
		/* Mark the "change" control as uncritical (done) */
		sd_ctrl->critical = false;
	}

	/*
	 * At this point we do not yet have the object's SID, so we
	 * leave it empty. It is irrelevant, as it is used to expand
	 * Principal-Self, and rights granted to PS will have no effect
	 * in this case
	 */
	/* check if we have WD, no need to perform other attribute checks if we do */
	attr = dsdb_attribute_by_lDAPDisplayName(schema, "nTSecurityDescriptor");
	if (attr == NULL) {
		return ldb_operr(ldb);
	}

	if (control_sd->specified_sacl) {
		const struct security_token *token = acl_user_token(module);
		bool has_priv = security_token_has_privilege(token, SEC_PRIV_SECURITY);
		if (!has_priv) {
			return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
		}
	}

	ret = acl_check_access_on_attribute(module,
					    req,
					    control_sd->default_sd,
					    NULL,
					    SEC_STD_WRITE_DAC,
					    attr,
					    objectclass);
	if (ret == LDB_SUCCESS) {
		goto success;
	}

	if (control_sd->specified_sd) {
		bool block_owner_rights = dsdb_block_owner_implicit_rights(module,
									   req,
									   req);
		if (block_owner_rights) {
			ldb_asprintf_errstring(ldb_module_get_ctx(module),
					       "Object %s has no SD modification rights",
					       ldb_dn_get_linearized(msg->dn));
			dsdb_acl_debug(control_sd->default_sd,
				       acl_user_token(module),
				       msg->dn,
				       true,
				       10);
			ret = LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
			return ret;
		}
	}

	must_contain = dsdb_full_attribute_list(req, schema, &sorted_oc_el,
						DSDB_SCHEMA_ALL_MUST);
	for (i=0; i < msg->num_elements; i++) {
		el = &msg->elements[i];

		attr = dsdb_attribute_by_lDAPDisplayName(schema, el->name);
		if (attr == NULL && ldb_attr_cmp("clearTextPassword", el->name) != 0) {
			ldb_asprintf_errstring(ldb, "acl_add: attribute '%s' "
					       "on entry '%s' was not found in the schema!",
					       el->name,
				       ldb_dn_get_linearized(msg->dn));
			ret = LDB_ERR_NO_SUCH_ATTRIBUTE;
			return ret;
		}

		if (attr != NULL) {
			bool found = str_list_check(must_contain, attr->lDAPDisplayName);
			/* do not check the mandatory attributes */
			if (found) {
				continue;
			}
		}

		if (ldb_attr_cmp("dBCSPwd", el->name) == 0 ||
			   ldb_attr_cmp("unicodePwd", el->name) == 0 ||
			   ldb_attr_cmp("userPassword", el->name) == 0 ||
			   ldb_attr_cmp("clearTextPassword", el->name) == 0) {
			continue;
		} else if (ldb_attr_cmp("member", el->name) == 0) {
			ret = acl_check_self_membership(req,
							module,
							req,
							control_sd->default_sd,
							NULL,
							attr,
							objectclass);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		} else if (ldb_attr_cmp("servicePrincipalName", el->name) == 0) {
			ret = acl_check_spn(req,
					    module,
					    req,
					    el,
					    control_sd->default_sd,
					    NULL,
					    attr,
					    objectclass,
					    NULL);
			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(ldb_module_get_ctx(module),
						       "Object %s cannot be created with spn",
						       ldb_dn_get_linearized(msg->dn));
				dsdb_acl_debug(control_sd->default_sd,
					       acl_user_token(module),
					       msg->dn,
					       true,
					       10);
				return ret;
			}
		} else if (ldb_attr_cmp("dnsHostName", el->name) == 0) {
			ret = acl_check_dns_host_name(req,
						      module,
						      req,
						      el,
						      control_sd->default_sd,
						      NULL,
						      attr,
						      objectclass,
						      NULL);
			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(ldb_module_get_ctx(module),
						       "Object %s cannot be created with dnsHostName",
						       ldb_dn_get_linearized(msg->dn));
				dsdb_acl_debug(control_sd->default_sd,
					       acl_user_token(module),
					       msg->dn,
					       true,
					       10);
				return ret;
			}
		} else {
			ret = acl_check_access_on_attribute(module,
							    req,
							    control_sd->default_sd,
							    NULL,
							    SEC_ADS_WRITE_PROP,
							    attr,
							    objectclass);
			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(ldb_module_get_ctx(module),
						       "Object %s has no write property access",
						       ldb_dn_get_linearized(msg->dn));
				dsdb_acl_debug(control_sd->default_sd,
					       acl_user_token(module),
					       msg->dn,
					       true,
					       10);
				ret = LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
				return ret;
			}
		}
	}
success:
	return ldb_next_request(module, req);
}

static int acl_check_password_rights(
	TALLOC_CTX *mem_ctx,
	struct ldb_module *module,
	struct ldb_request *req,
	struct security_descriptor *sd,
	struct dom_sid *sid,
	const struct dsdb_class *objectclass,
	bool userPassword,
	struct  dsdb_control_password_acl_validation **control_for_response)
{
	int ret = LDB_SUCCESS;
	unsigned int del_attr_cnt = 0, add_attr_cnt = 0, rep_attr_cnt = 0;
	unsigned int del_val_cnt = 0, add_val_cnt = 0;
	struct ldb_message_element *el;
	struct ldb_message *msg;
	struct ldb_control *c = NULL;
	const char *passwordAttrs[] = { "userPassword", "clearTextPassword",
					"unicodePwd", NULL }, **l;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct dsdb_control_password_acl_validation *pav = NULL;

	if (tmp_ctx == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	pav = talloc_zero(req, struct dsdb_control_password_acl_validation);
	if (pav == NULL) {
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	/*
	 * Set control_for_response to pav so it can be added to the response
	 * and be passed up to the audit_log module which uses it to identify
	 * password reset attempts.
	 */
	*control_for_response = pav;

	c = ldb_request_get_control(req, DSDB_CONTROL_PASSWORD_CHANGE_OLD_PW_CHECKED_OID);
	if (c != NULL) {
		pav->pwd_reset = false;

		/*
		 * The "DSDB_CONTROL_PASSWORD_CHANGE_OLD_PW_CHECKED_OID" control means that we
		 * have a user password change and not a set as the message
		 * looks like. In it's value blob it contains the NT and/or LM
		 * hash of the old password specified by the user.  This control
		 * is used by the SAMR and "kpasswd" password change mechanisms.
		 *
		 * This control can't be used by real LDAP clients,
		 * the only caller is samdb_set_password_internal(),
		 * so we don't have to strict verification of the input.
		 */
		ret = acl_check_extended_right(tmp_ctx,
					       module,
					       req,
					       objectclass,
					       sd,
					       acl_user_token(module),
					       GUID_DRS_USER_CHANGE_PASSWORD,
					       SEC_ADS_CONTROL_ACCESS,
					       sid);
		goto checked;
	}

	c = ldb_request_get_control(req, DSDB_CONTROL_PASSWORD_HASH_VALUES_OID);
	if (c != NULL) {
		pav->pwd_reset = true;

		/*
		 * The "DSDB_CONTROL_PASSWORD_HASH_VALUES_OID" control, without
		 * "DSDB_CONTROL_PASSWORD_CHANGE_OLD_PW_CHECKED_OID" control means that we
		 * have a force password set.
		 * This control is used by the SAMR/NETLOGON/LSA password
		 * reset mechanisms.
		 *
		 * This control can't be used by real LDAP clients,
		 * the only caller is samdb_set_password_internal(),
		 * so we don't have to strict verification of the input.
		 */
		ret = acl_check_extended_right(tmp_ctx,
					       module,
					       req,
					       objectclass,
					       sd,
					       acl_user_token(module),
					       GUID_DRS_FORCE_CHANGE_PASSWORD,
					       SEC_ADS_CONTROL_ACCESS,
					       sid);
		goto checked;
	}

	el = ldb_msg_find_element(req->op.mod.message, "dBCSPwd");
	if (el != NULL) {
		/*
		 * dBCSPwd is only allowed with a control.
		 */
		talloc_free(tmp_ctx);
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	msg = ldb_msg_copy_shallow(tmp_ctx, req->op.mod.message);
	if (msg == NULL) {
		return ldb_module_oom(module);
	}
	for (l = passwordAttrs; *l != NULL; l++) {
		if ((!userPassword) && (ldb_attr_cmp(*l, "userPassword") == 0)) {
			continue;
		}

		while ((el = ldb_msg_find_element(msg, *l)) != NULL) {
			if (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_DELETE) {
				++del_attr_cnt;
				del_val_cnt += el->num_values;
			}
			if (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_ADD) {
				++add_attr_cnt;
				add_val_cnt += el->num_values;
			}
			if (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_REPLACE) {
				++rep_attr_cnt;
			}
			ldb_msg_remove_element(msg, el);
		}
	}

	/* single deletes will be handled by the "password_hash" LDB module
	 * later in the stack, so we let it though here */
	if ((del_attr_cnt > 0) && (add_attr_cnt == 0) && (rep_attr_cnt == 0)) {
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}


	if (rep_attr_cnt > 0) {
		pav->pwd_reset = true;

		ret = acl_check_extended_right(tmp_ctx,
					       module,
					       req,
					       objectclass,
					       sd,
					       acl_user_token(module),
					       GUID_DRS_FORCE_CHANGE_PASSWORD,
					       SEC_ADS_CONTROL_ACCESS,
					       sid);
		goto checked;
	}

	if (add_attr_cnt != del_attr_cnt) {
		pav->pwd_reset = true;

		ret = acl_check_extended_right(tmp_ctx,
					       module,
					       req,
					       objectclass,
					       sd,
					       acl_user_token(module),
					       GUID_DRS_FORCE_CHANGE_PASSWORD,
					       SEC_ADS_CONTROL_ACCESS,
					       sid);
		goto checked;
	}

	if (add_val_cnt == 1 && del_val_cnt == 1) {
		pav->pwd_reset = false;

		ret = acl_check_extended_right(tmp_ctx,
					       module,
					       req,
					       objectclass,
					       sd,
					       acl_user_token(module),
					       GUID_DRS_USER_CHANGE_PASSWORD,
					       SEC_ADS_CONTROL_ACCESS,
					       sid);
		/* Very strange, but we get constraint violation in this case */
		if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
			ret = LDB_ERR_CONSTRAINT_VIOLATION;
		}
		goto checked;
	}

	if (add_val_cnt == 1 && del_val_cnt == 0) {
		pav->pwd_reset = true;

		ret = acl_check_extended_right(tmp_ctx,
					       module,
					       req,
					       objectclass,
					       sd,
					       acl_user_token(module),
					       GUID_DRS_FORCE_CHANGE_PASSWORD,
					       SEC_ADS_CONTROL_ACCESS,
					       sid);
		/* Very strange, but we get constraint violation in this case */
		if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
			ret = LDB_ERR_CONSTRAINT_VIOLATION;
		}
		goto checked;
	}

	/*
	 * Everything else is handled by the password_hash module where it will
	 * fail, but with the correct error code when the module is again
	 * checking the attributes. As the change request will lack the
	 * DSDB_CONTROL_PASSWORD_ACL_VALIDATION_OID control, we can be sure that
	 * any modification attempt that went this way will be rejected.
	 */

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;

checked:
	if (ret != LDB_SUCCESS) {
		dsdb_acl_debug(sd, acl_user_token(module),
			       req->op.mod.message->dn,
			       true,
			       10);
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = ldb_request_add_control(req,
		DSDB_CONTROL_PASSWORD_ACL_VALIDATION_OID, false, pav);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb_module_get_ctx(module), LDB_DEBUG_ERROR,
			  "Unable to register ACL validation control!\n");
		return ret;
	}
	return LDB_SUCCESS;
}

/*
 * Context needed by acl_callback
 */
struct acl_callback_context {
	struct ldb_request *request;
	struct ldb_module *module;
};

/*
 * @brief Copy the password validation control to the reply.
 *
 * Copy the dsdb_control_password_acl_validation control from the request,
 * to the reply.  The control is used by the audit_log module to identify
 * password rests.
 *
 * @param req the ldb request.
 * @param ares the result, updated with the control.
 */
static void copy_password_acl_validation_control(
	struct ldb_request *req,
	struct ldb_reply *ares)
{
	struct ldb_control *pav_ctrl = NULL;
	struct dsdb_control_password_acl_validation *pav = NULL;

	pav_ctrl = ldb_request_get_control(
		discard_const(req),
		DSDB_CONTROL_PASSWORD_ACL_VALIDATION_OID);
	if (pav_ctrl == NULL) {
		return;
	}

	pav = talloc_get_type_abort(
		pav_ctrl->data,
		struct dsdb_control_password_acl_validation);
	if (pav == NULL) {
		return;
	}
	ldb_reply_add_control(
		ares,
		DSDB_CONTROL_PASSWORD_ACL_VALIDATION_OID,
		false,
		pav);
}
/*
 * @brief call back function for acl_modify.
 *
 * Calls acl_copy to copy the dsdb_control_password_acl_validation from
 * the request to the reply.
 *
 * @param req the ldb_request.
 * @param ares the operation result.
 *
 * @return the LDB_STATUS
 */
static int acl_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct acl_callback_context *ac = NULL;

	ac = talloc_get_type(req->context, struct acl_callback_context);

	if (!ares) {
		return ldb_module_done(
			ac->request,
			NULL,
			NULL,
			LDB_ERR_OPERATIONS_ERROR);
	}

	/* pass on to the callback */
	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		return ldb_module_send_entry(
			ac->request,
			ares->message,
			ares->controls);

	case LDB_REPLY_REFERRAL:
		return ldb_module_send_referral(
			ac->request,
			ares->referral);

	case LDB_REPLY_DONE:
		/*
		 * Copy the ACL control from the request to the response
		 */
		copy_password_acl_validation_control(req, ares);
		return ldb_module_done(
			ac->request,
			ares->controls,
			ares->response,
			ares->error);

	default:
		/* Can't happen */
		return LDB_ERR_OPERATIONS_ERROR;
	}
}

static int acl_modify(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const struct dsdb_schema *schema;
	unsigned int i;
	const struct dsdb_class *objectclass;
	struct ldb_result *acl_res;
	struct security_descriptor *sd;
	struct dom_sid *sid = NULL;
	struct ldb_control *is_undelete;
	struct ldb_control *implicit_validated_write_control = NULL;
	bool userPassword;
	bool password_rights_checked = false;
	TALLOC_CTX *tmp_ctx;
	const struct ldb_message *msg = req->op.mod.message;
	static const char *acl_attrs[] = {
		"nTSecurityDescriptor",
		"objectClass",
		"objectSid",
		NULL
	};
	struct acl_callback_context *context = NULL;
	struct ldb_request *new_req = NULL;
	struct  dsdb_control_password_acl_validation *pav = NULL;
	struct ldb_control **controls = NULL;

	if (ldb_dn_is_special(msg->dn)) {
		return ldb_next_request(module, req);
	}

	is_undelete = ldb_request_get_control(req, DSDB_CONTROL_RESTORE_TOMBSTONE_OID);

	implicit_validated_write_control = ldb_request_get_control(
		req, DSDB_CONTROL_FORCE_ALLOW_VALIDATED_DNS_HOSTNAME_SPN_WRITE_OID);
	if (implicit_validated_write_control != NULL) {
		implicit_validated_write_control->critical = 0;
	}

	/* Don't print this debug statement if elements[0].name is going to be NULL */
	if (msg->num_elements > 0) {
		DEBUG(10, ("ldb:acl_modify: %s\n", msg->elements[0].name));
	}
	if (dsdb_have_system_access(module, req, SYSTEM_CONTROL_STRIP_CRITICAL))
	{
		return ldb_next_request(module, req);
	}

	tmp_ctx = talloc_new(req);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	ret = dsdb_module_search_dn(module, tmp_ctx, &acl_res, msg->dn,
				    acl_attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_FLAG_AS_SYSTEM |
				    DSDB_SEARCH_SHOW_RECYCLED,
				    req);

	if (ret != LDB_SUCCESS) {
		goto fail;
	}

	userPassword = dsdb_user_password_support(module, req, req);

	schema = dsdb_get_schema(ldb, tmp_ctx);
	if (!schema) {
		talloc_free(tmp_ctx);
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "acl_modify: Error obtaining schema.");
	}

	ret = dsdb_get_sd_from_ldb_message(ldb, tmp_ctx, acl_res->msgs[0], &sd);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "acl_modify: Error retrieving security descriptor.");
	}
	/* Theoretically we pass the check if the object has no sd */
	if (!sd) {
		goto success;
	}

	objectclass = dsdb_get_structural_oc_from_msg(schema, acl_res->msgs[0]);
	if (!objectclass) {
		talloc_free(tmp_ctx);
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "acl_modify: Error retrieving object class for GUID.");
	}
	sid = samdb_result_dom_sid(req, acl_res->msgs[0], "objectSid");
	for (i=0; i < msg->num_elements; i++) {
		const struct ldb_message_element *el = &msg->elements[i];
		const struct dsdb_attribute *attr;

		/*
		 * This basic attribute existence check with the right errorcode
		 * is needed since this module is the first one which requests
		 * schema attribute information.
		 * The complete attribute checking is done in the
		 * "objectclass_attrs" module behind this one.
		 *
		 * NOTE: "clearTextPassword" is not defined in the schema.
		 */
		attr = dsdb_attribute_by_lDAPDisplayName(schema, el->name);
		if (!attr && ldb_attr_cmp("clearTextPassword", el->name) != 0) {
			ldb_asprintf_errstring(ldb, "acl_modify: attribute '%s' "
					       "on entry '%s' was not found in the schema!",
					       req->op.mod.message->elements[i].name,
				       ldb_dn_get_linearized(req->op.mod.message->dn));
			ret =  LDB_ERR_NO_SUCH_ATTRIBUTE;
			goto fail;
		}

		if (ldb_attr_cmp("nTSecurityDescriptor", el->name) == 0) {
			uint32_t sd_flags = dsdb_request_sd_flags(req, NULL);
			uint32_t access_mask = 0;

			bool block_owner_rights;
			enum implicit_owner_rights implicit_owner_rights;

			if (sd_flags & (SECINFO_OWNER|SECINFO_GROUP)) {
				access_mask |= SEC_STD_WRITE_OWNER;
			}
			if (sd_flags & SECINFO_DACL) {
				access_mask |= SEC_STD_WRITE_DAC;
			}
			if (sd_flags & SECINFO_SACL) {
				access_mask |= SEC_FLAG_SYSTEM_SECURITY;
			}

			block_owner_rights = !dsdb_module_am_administrator(module);

			if (block_owner_rights) {
				block_owner_rights = dsdb_block_owner_implicit_rights(module,
										      req,
										      req);
			}
			if (block_owner_rights) {
				block_owner_rights = samdb_find_attribute(ldb,
									  acl_res->msgs[0],
									  "objectclass",
									  "computer");
			}

			implicit_owner_rights = block_owner_rights ?
				IMPLICIT_OWNER_READ_CONTROL_RIGHTS :
				IMPLICIT_OWNER_READ_CONTROL_AND_WRITE_DAC_RIGHTS;

			ret = acl_check_access_on_attribute_implicit_owner(module,
									   tmp_ctx,
									   sd,
									   sid,
									   access_mask,
									   attr,
									   objectclass,
									   implicit_owner_rights);
			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(ldb_module_get_ctx(module),
						       "Object %s has no write dacl access\n",
						       ldb_dn_get_linearized(msg->dn));
				dsdb_acl_debug(sd,
					       acl_user_token(module),
					       msg->dn,
					       true,
					       10);
				ret = LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
				goto fail;
			}
		} else if (ldb_attr_cmp("member", el->name) == 0) {
			ret = acl_check_self_membership(tmp_ctx,
							module,
							req,
							sd,
							sid,
							attr,
							objectclass);
			if (ret != LDB_SUCCESS) {
				goto fail;
			}
		} else if (ldb_attr_cmp("dBCSPwd", el->name) == 0) {
			/* this one is not affected by any rights, we should let it through
			   so that passwords_hash returns the correct error */
			continue;
		} else if (ldb_attr_cmp("unicodePwd", el->name) == 0 ||
			   (userPassword && ldb_attr_cmp("userPassword", el->name) == 0) ||
			   ldb_attr_cmp("clearTextPassword", el->name) == 0) {
			/*
			 * Ideally we would do the acl_check_password_rights
			 * before we checked the other attributes, i.e. in a
			 * loop before the current one.
			 * Have not done this as yet in order to limit the size
			 * of the change. To limit the possibility of breaking
			 * the ACL logic.
			 */
			if (password_rights_checked) {
				continue;
			}
			ret = acl_check_password_rights(tmp_ctx,
							module,
							req,
							sd,
							sid,
							objectclass,
							userPassword,
							&pav);
			if (ret != LDB_SUCCESS) {
				goto fail;
			}
			password_rights_checked = true;
		} else if (ldb_attr_cmp("servicePrincipalName", el->name) == 0) {
			ret = acl_check_spn(tmp_ctx,
					    module,
					    req,
					    el,
					    sd,
					    sid,
					    attr,
					    objectclass,
					    implicit_validated_write_control);
			if (ret != LDB_SUCCESS) {
				goto fail;
			}
		} else if (ldb_attr_cmp("dnsHostName", el->name) == 0) {
			ret = acl_check_dns_host_name(tmp_ctx,
						      module,
						      req,
						      el,
						      sd,
						      sid,
						      attr,
						      objectclass,
						      implicit_validated_write_control);
			if (ret != LDB_SUCCESS) {
				goto fail;
			}
		} else if (is_undelete != NULL && (ldb_attr_cmp("isDeleted", el->name) == 0)) {
			/*
			 * in case of undelete op permissions on
			 * isDeleted are irrelevant and
			 * distinguishedName is removed by the
			 * tombstone_reanimate module
			 */
			continue;
		} else if (implicit_validated_write_control != NULL) {
			/* Allow the update. */
			continue;
		} else {
			ret = acl_check_access_on_attribute(module,
							    tmp_ctx,
							    sd,
							    sid,
							    SEC_ADS_WRITE_PROP,
							    attr,
							    objectclass);
			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(ldb_module_get_ctx(module),
						       "Object %s has no write property access\n",
						       ldb_dn_get_linearized(msg->dn));
				dsdb_acl_debug(sd,
					       acl_user_token(module),
					       msg->dn,
					       true,
					       10);
				ret = LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
				goto fail;
			}
		}
	}

success:
	talloc_free(tmp_ctx);
	context = talloc_zero(req, struct acl_callback_context);

	if (context == NULL) {
		return ldb_oom(ldb);
	}
	context->request = req;
	context->module  = module;
	ret = ldb_build_mod_req(
		&new_req,
		ldb,
		req,
		req->op.mod.message,
		req->controls,
		context,
		acl_callback,
		req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return ldb_next_request(module, new_req);
fail:
	talloc_free(tmp_ctx);
	/*
	 * We copy the pav into the result, so that the password reset
	 * logging code in audit_log can log failed password reset attempts.
	 */
	if (pav) {
		struct ldb_control *control = NULL;

		controls = talloc_zero_array(req, struct ldb_control *, 2);
		if (controls == NULL) {
			return ldb_oom(ldb);
		}

		control = talloc(controls, struct ldb_control);

		if (control == NULL) {
			return ldb_oom(ldb);
		}

		control->oid= talloc_strdup(
			control,
			DSDB_CONTROL_PASSWORD_ACL_VALIDATION_OID);
		if (control->oid == NULL) {
			return ldb_oom(ldb);
		}
		control->critical	= false;
		control->data	= pav;
		*controls = control;
	}
	return ldb_module_done(req, controls, NULL, ret);
}

/* similar to the modify for the time being.
 * We need to consider the special delete tree case, though - TODO */
static int acl_delete(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_dn *parent;
	struct ldb_context *ldb;
	struct ldb_dn *nc_root;
	const struct dsdb_schema *schema;
	const struct dsdb_class *objectclass;
	struct security_descriptor *sd = NULL;
	struct dom_sid *sid = NULL;
	struct ldb_result *acl_res;
	static const char *acl_attrs[] = {
		"nTSecurityDescriptor",
		"objectClass",
		"objectSid",
		NULL
	};

	if (ldb_dn_is_special(req->op.del.dn)) {
		return ldb_next_request(module, req);
	}

	if (dsdb_have_system_access(module, req, SYSTEM_CONTROL_STRIP_CRITICAL))
	{
		return ldb_next_request(module, req);
	}

	DEBUG(10, ("ldb:acl_delete: %s\n", ldb_dn_get_linearized(req->op.del.dn)));

	ldb = ldb_module_get_ctx(module);

	parent = ldb_dn_get_parent(req, req->op.del.dn);
	if (parent == NULL) {
		return ldb_oom(ldb);
	}

	/* Make sure we aren't deleting a NC */

	ret = dsdb_find_nc_root(ldb, req, req->op.del.dn, &nc_root);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (ldb_dn_compare(nc_root, req->op.del.dn) == 0) {
		talloc_free(nc_root);
		DEBUG(10,("acl:deleting a NC\n"));
		/* Windows returns "ERR_UNWILLING_TO_PERFORM */
		return ldb_module_done(req, NULL, NULL,
				       LDB_ERR_UNWILLING_TO_PERFORM);
	}
	talloc_free(nc_root);

	ret = dsdb_module_search_dn(module, req, &acl_res,
				    req->op.del.dn, acl_attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_FLAG_AS_SYSTEM |
				    DSDB_SEARCH_SHOW_RECYCLED, req);
	/* we should be able to find the parent */
	if (ret != LDB_SUCCESS) {
		DEBUG(10,("acl: failed to find object %s\n",
			  ldb_dn_get_linearized(req->op.rename.olddn)));
		return ret;
	}

	ret = dsdb_get_sd_from_ldb_message(ldb, req, acl_res->msgs[0], &sd);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
	}
	if (!sd) {
		return ldb_operr(ldb);
	}

	schema = dsdb_get_schema(ldb, req);
	if (!schema) {
		return ldb_operr(ldb);
	}

	sid = samdb_result_dom_sid(req, acl_res->msgs[0], "objectSid");

	objectclass = dsdb_get_structural_oc_from_msg(schema, acl_res->msgs[0]);
	if (!objectclass) {
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "acl_modify: Error retrieving object class for GUID.");
	}

	if (ldb_request_get_control(req, LDB_CONTROL_TREE_DELETE_OID)) {
		ret = acl_check_access_on_objectclass(module, req, sd, sid,
						      SEC_ADS_DELETE_TREE,
						      objectclass);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		return ldb_next_request(module, req);
	}

	/* First check if we have delete object right */
	ret = acl_check_access_on_objectclass(module, req, sd, sid,
					      SEC_STD_DELETE,
					      objectclass);
	if (ret == LDB_SUCCESS) {
		return ldb_next_request(module, req);
	}

	/* Nope, we don't have delete object. Lets check if we have delete
	 * child on the parent */
	ret = dsdb_module_check_access_on_dn(module, req, parent,
					     SEC_ADS_DELETE_CHILD,
					     &objectclass->schemaIDGUID,
					     req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(module, req);
}
static int acl_check_reanimate_tombstone(TALLOC_CTX *mem_ctx,
					 struct ldb_module *module,
					 struct ldb_request *req,
					 struct ldb_dn *nc_root)
{
	int ret;
	struct ldb_result *acl_res;
	struct security_descriptor *sd = NULL;
	struct dom_sid *sid = NULL;
	const struct dsdb_schema *schema = NULL;
	const struct dsdb_class *objectclass = NULL;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	static const char *acl_attrs[] = {
		"nTSecurityDescriptor",
		"objectClass",
		"objectSid",
		NULL
	};

	ret = dsdb_module_search_dn(module, mem_ctx, &acl_res,
				    nc_root, acl_attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_FLAG_AS_SYSTEM |
				    DSDB_SEARCH_SHOW_RECYCLED, req);
	if (ret != LDB_SUCCESS) {
		DEBUG(10,("acl: failed to find object %s\n",
			  ldb_dn_get_linearized(nc_root)));
		return ret;
	}

	ret = dsdb_get_sd_from_ldb_message(mem_ctx, req, acl_res->msgs[0], &sd);
	sid = samdb_result_dom_sid(mem_ctx, acl_res->msgs[0], "objectSid");
	schema = dsdb_get_schema(ldb, req);
	if (!schema) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	objectclass = dsdb_get_structural_oc_from_msg(schema, acl_res->msgs[0]);
	if (ret != LDB_SUCCESS || !sd) {
		return ldb_operr(ldb_module_get_ctx(module));
	}
	return acl_check_extended_right(mem_ctx,
					module,
					req,
					objectclass,
					sd,
					acl_user_token(module),
					GUID_DRS_REANIMATE_TOMBSTONE,
					SEC_ADS_CONTROL_ACCESS, sid);
}

static int acl_rename(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_dn *oldparent;
	struct ldb_dn *newparent;
	const struct dsdb_schema *schema;
	const struct dsdb_class *objectclass;
	const struct dsdb_attribute *attr = NULL;
	struct ldb_context *ldb;
	struct security_descriptor *sd = NULL;
	struct dom_sid *sid = NULL;
	struct ldb_result *acl_res;
	struct ldb_dn *nc_root;
	struct ldb_control *is_undelete;
	TALLOC_CTX *tmp_ctx;
	const char *rdn_name;
	static const char *acl_attrs[] = {
		"nTSecurityDescriptor",
		"objectClass",
		"objectSid",
		NULL
	};

	if (ldb_dn_is_special(req->op.rename.olddn)) {
		return ldb_next_request(module, req);
	}

	DEBUG(10, ("ldb:acl_rename: %s\n", ldb_dn_get_linearized(req->op.rename.olddn)));
	if (dsdb_have_system_access(module, req, SYSTEM_CONTROL_STRIP_CRITICAL))
	{
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	tmp_ctx = talloc_new(req);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	oldparent = ldb_dn_get_parent(tmp_ctx, req->op.rename.olddn);
	if (oldparent == NULL) {
		return ldb_oom(ldb);
	}
	newparent = ldb_dn_get_parent(tmp_ctx, req->op.rename.newdn);
	if (newparent == NULL) {
		return ldb_oom(ldb);
	}

	/* Make sure we aren't renaming/moving a NC */

	ret = dsdb_find_nc_root(ldb, req, req->op.rename.olddn, &nc_root);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (ldb_dn_compare(nc_root, req->op.rename.olddn) == 0) {
		talloc_free(nc_root);
		DEBUG(10,("acl:renaming/moving a NC\n"));
		/* Windows returns "ERR_UNWILLING_TO_PERFORM */
		return ldb_module_done(req, NULL, NULL,
				       LDB_ERR_UNWILLING_TO_PERFORM);
	}

	/* special check for undelete operation */
	is_undelete = ldb_request_get_control(req, DSDB_CONTROL_RESTORE_TOMBSTONE_OID);
	if (is_undelete != NULL) {
		is_undelete->critical = 0;
		ret = acl_check_reanimate_tombstone(tmp_ctx, module, req, nc_root);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}
	}
	talloc_free(nc_root);

	/* Look for the parent */

	ret = dsdb_module_search_dn(module, tmp_ctx, &acl_res,
				    req->op.rename.olddn, acl_attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_FLAG_AS_SYSTEM |
				    DSDB_SEARCH_SHOW_RECYCLED, req);
	/* we should be able to find the parent */
	if (ret != LDB_SUCCESS) {
		DEBUG(10,("acl: failed to find object %s\n",
			  ldb_dn_get_linearized(req->op.rename.olddn)));
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_get_sd_from_ldb_message(ldb, req, acl_res->msgs[0], &sd);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}
	if (!sd) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	schema = dsdb_get_schema(ldb, acl_res);
	if (!schema) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	sid = samdb_result_dom_sid(req, acl_res->msgs[0], "objectSid");

	objectclass = dsdb_get_structural_oc_from_msg(schema, acl_res->msgs[0]);
	if (!objectclass) {
		talloc_free(tmp_ctx);
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "acl_modify: Error retrieving object class for GUID.");
	}

	attr = dsdb_attribute_by_lDAPDisplayName(schema, "name");
	if (attr == NULL) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	ret = acl_check_access_on_attribute(module, tmp_ctx, sd, sid,
					    SEC_ADS_WRITE_PROP,
					    attr, objectclass);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Object %s has no wp on %s\n",
				       ldb_dn_get_linearized(req->op.rename.olddn),
				       attr->lDAPDisplayName);
		dsdb_acl_debug(sd,
			  acl_user_token(module),
			  req->op.rename.olddn,
			  true,
			  10);
		talloc_free(tmp_ctx);
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}

	rdn_name = ldb_dn_get_rdn_name(req->op.rename.olddn);
	if (rdn_name == NULL) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	attr = dsdb_attribute_by_lDAPDisplayName(schema, rdn_name);
	if (attr == NULL) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	ret = acl_check_access_on_attribute(module, tmp_ctx, sd, sid,
					    SEC_ADS_WRITE_PROP,
					    attr, objectclass);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Object %s has no wp on %s\n",
				       ldb_dn_get_linearized(req->op.rename.olddn),
				       attr->lDAPDisplayName);
		dsdb_acl_debug(sd,
			  acl_user_token(module),
			  req->op.rename.olddn,
			  true,
			  10);
		talloc_free(tmp_ctx);
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}

	if (ldb_dn_compare(oldparent, newparent) == 0) {
		/* regular rename, not move, nothing more to do */
		talloc_free(tmp_ctx);
		return ldb_next_request(module, req);
	}

	/* new parent should have create child */
	ret = dsdb_module_check_access_on_dn(module, req, newparent,
					     SEC_ADS_CREATE_CHILD,
					     &objectclass->schemaIDGUID, req);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "acl:access_denied renaming %s",
				       ldb_dn_get_linearized(req->op.rename.olddn));
		talloc_free(tmp_ctx);
		return ret;
	}

	/* do we have delete object on the object? */
	/* this access is not necessary for undelete ops */
	if (is_undelete == NULL) {
		ret = acl_check_access_on_objectclass(module, tmp_ctx, sd, sid,
						      SEC_STD_DELETE,
						      objectclass);
		if (ret == LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ldb_next_request(module, req);
		}
		/* what about delete child on the current parent */
		ret = dsdb_module_check_access_on_dn(module, req, oldparent,
						     SEC_ADS_DELETE_CHILD,
						     &objectclass->schemaIDGUID,
						     req);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb_module_get_ctx(module),
					       "acl:access_denied renaming %s", ldb_dn_get_linearized(req->op.rename.olddn));
			talloc_free(tmp_ctx);
			return ldb_module_done(req, NULL, NULL, ret);
		}
	}
	talloc_free(tmp_ctx);

	return ldb_next_request(module, req);
}

static int acl_search_update_confidential_attrs(struct acl_context *ac,
						struct acl_private *data)
{
	struct dsdb_attribute *a;
	uint32_t n = 0;

	if (data->acl_search) {
		/*
		 * If acl:search is activated, the acl_read module
		 * protects confidential attributes.
		 */
		return LDB_SUCCESS;
	}

	if ((ac->schema == data->cached_schema_ptr) &&
	    (ac->schema->metadata_usn == data->cached_schema_metadata_usn))
	{
		return LDB_SUCCESS;
	}

	data->cached_schema_ptr = NULL;
	data->cached_schema_loaded_usn = 0;
	data->cached_schema_metadata_usn = 0;
	TALLOC_FREE(data->confidential_attrs);

	if (ac->schema == NULL) {
		return LDB_SUCCESS;
	}

	for (a = ac->schema->attributes; a; a = a->next) {
		const char **attrs = data->confidential_attrs;

		if (!(a->searchFlags & SEARCH_FLAG_CONFIDENTIAL)) {
			continue;
		}

		attrs = talloc_realloc(data, attrs, const char *, n + 2);
		if (attrs == NULL) {
			TALLOC_FREE(data->confidential_attrs);
			return ldb_module_oom(ac->module);
		}

		attrs[n] = a->lDAPDisplayName;
		attrs[n+1] = NULL;
		n++;

		data->confidential_attrs = attrs;
	}

	data->cached_schema_ptr = ac->schema;
	data->cached_schema_metadata_usn = ac->schema->metadata_usn;

	return LDB_SUCCESS;
}

static int acl_search_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct acl_context *ac;
	struct acl_private *data;
	struct ldb_result *acl_res;
	static const char *acl_attrs[] = {
		"objectClass",
		"nTSecurityDescriptor",
		"objectSid",
		NULL
	};
	int ret;
	unsigned int i;

	ac = talloc_get_type(req->context, struct acl_context);
	data = talloc_get_type(ldb_module_get_private(ac->module), struct acl_private);
	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
				       LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
				       ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		if (ac->constructed_attrs) {
			ret = dsdb_module_search_dn(ac->module, ac, &acl_res, ares->message->dn,
						    acl_attrs,
						    DSDB_FLAG_NEXT_MODULE |
						    DSDB_FLAG_AS_SYSTEM |
						    DSDB_SEARCH_SHOW_RECYCLED,
						    req);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req, NULL, NULL, ret);
			}
		}

		if (ac->allowedAttributes || ac->allowedAttributesEffective) {
			ret = acl_allowedAttributes(ac->module, ac->schema,
						    acl_res->msgs[0],
						    ares->message, ac);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req, NULL, NULL, ret);
			}
		}

		if (ac->allowedChildClasses) {
			ret = acl_childClasses(ac->module, ac->schema,
					       acl_res->msgs[0],
					       ares->message,
					       "allowedChildClasses");
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req, NULL, NULL, ret);
			}
		}

		if (ac->allowedChildClassesEffective) {
			ret = acl_childClassesEffective(ac->module, ac->schema,
							acl_res->msgs[0],
							ares->message, ac);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req, NULL, NULL, ret);
			}
		}

		if (ac->sDRightsEffective) {
			ret = acl_sDRightsEffective(ac->module,
						    acl_res->msgs[0],
						    ares->message, ac);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req, NULL, NULL, ret);
			}
		}

		if (data == NULL) {
			return ldb_module_send_entry(ac->req, ares->message,
						     ares->controls);
		}

		if (ac->am_system) {
			return ldb_module_send_entry(ac->req, ares->message,
						     ares->controls);
		}

		if (ac->am_administrator) {
			return ldb_module_send_entry(ac->req, ares->message,
						     ares->controls);
		}

		if (data->confidential_attrs != NULL) {
			for (i = 0; data->confidential_attrs[i]; i++) {
				ldb_msg_remove_attr(ares->message,
						    data->confidential_attrs[i]);
			}
		}

		return ldb_module_send_entry(ac->req, ares->message, ares->controls);

	case LDB_REPLY_REFERRAL:
		return ldb_module_send_referral(ac->req, ares->referral);

	case LDB_REPLY_DONE:
		return ldb_module_done(ac->req, ares->controls,
				       ares->response, LDB_SUCCESS);

	}
	return LDB_SUCCESS;
}

static int acl_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct acl_context *ac;
	struct ldb_parse_tree *down_tree = req->op.search.tree;
	struct ldb_request *down_req;
	struct acl_private *data;
	int ret;
	unsigned int i;
	bool modify_search = true;

	if (ldb_dn_is_special(req->op.search.base)) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	ac = talloc_zero(req, struct acl_context);
	if (ac == NULL) {
		return ldb_oom(ldb);
	}
	data = talloc_get_type(ldb_module_get_private(module), struct acl_private);

	ac->module = module;
	ac->req = req;
	ac->am_system = dsdb_module_am_system(module);
	ac->am_administrator = dsdb_module_am_administrator(module);
	ac->constructed_attrs = false;
	ac->allowedAttributes = ldb_attr_in_list(req->op.search.attrs, "allowedAttributes");
	ac->allowedAttributesEffective = ldb_attr_in_list(req->op.search.attrs, "allowedAttributesEffective");
	ac->allowedChildClasses = ldb_attr_in_list(req->op.search.attrs, "allowedChildClasses");
	ac->allowedChildClassesEffective = ldb_attr_in_list(req->op.search.attrs, "allowedChildClassesEffective");
	ac->sDRightsEffective = ldb_attr_in_list(req->op.search.attrs, "sDRightsEffective");
	ac->schema = dsdb_get_schema(ldb, ac);

	ac->constructed_attrs |= ac->allowedAttributes;
	ac->constructed_attrs |= ac->allowedChildClasses;
	ac->constructed_attrs |= ac->allowedChildClassesEffective;
	ac->constructed_attrs |= ac->allowedAttributesEffective;
	ac->constructed_attrs |= ac->sDRightsEffective;

	if (data == NULL) {
		modify_search = false;
	}
	if (ac->am_system) {
		modify_search = false;
	}

	if (!ac->constructed_attrs && !modify_search) {
		talloc_free(ac);
		return ldb_next_request(module, req);
	}

	data = talloc_get_type(ldb_module_get_private(ac->module), struct acl_private);
	if (data == NULL) {
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "acl_private data is missing");
	}

	if (!ac->am_system && !ac->am_administrator) {
		ret = acl_search_update_confidential_attrs(ac, data);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		if (data->confidential_attrs != NULL) {
			down_tree = ldb_parse_tree_copy_shallow(ac, req->op.search.tree);
			if (down_tree == NULL) {
				return ldb_oom(ldb);
			}

			for (i = 0; data->confidential_attrs[i]; i++) {
				ldb_parse_tree_attr_replace(down_tree,
							    data->confidential_attrs[i],
							    "kludgeACLredactedattribute");
			}
		}
	}

	ret = ldb_build_search_req_ex(&down_req,
				      ldb, ac,
				      req->op.search.base,
				      req->op.search.scope,
				      down_tree,
				      req->op.search.attrs,
				      req->controls,
				      ac, acl_search_callback,
				      req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	/* perform the search */
	return ldb_next_request(module, down_req);
}

static int acl_extended(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	/* allow everybody to read the sequence number */
	if (strcmp(req->op.extended.oid,
		   LDB_EXTENDED_SEQUENCE_NUMBER) == 0) {
		return ldb_next_request(module, req);
	}

	if (dsdb_have_system_access(module,
				    req,
				    SYSTEM_CONTROL_KEEP_CRITICAL) ||
	    dsdb_module_am_administrator(module))
	{
		return ldb_next_request(module, req);
	} else {
		ldb_asprintf_errstring(ldb,
				       "acl_extended: "
				       "attempted database modify not permitted. "
				       "User %s is not SYSTEM or an administrator",
				       acl_user_name(req, module));
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}
}

static const struct ldb_module_ops ldb_acl_module_ops = {
	.name		   = "acl",
	.search            = acl_search,
	.add               = acl_add,
	.modify            = acl_modify,
	.del               = acl_delete,
	.rename            = acl_rename,
	.extended          = acl_extended,
	.init_context	   = acl_module_init
};

int ldb_acl_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_acl_module_ops);
}
