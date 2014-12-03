/*
   ldb database library

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2001-2010
   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Simo Sorce 2006-2008
   Copyright (C) Matthias Dieter Wallnöfer 2009

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
  handle operational attributes
 */

/*
  createTimeStamp: HIDDEN, searchable, ldaptime, alias for whenCreated
  modifyTimeStamp: HIDDEN, searchable, ldaptime, alias for whenChanged

     for the above two, we do the search as normal, and if
     createTimeStamp or modifyTimeStamp is asked for, then do
     additional searches for whenCreated and whenChanged and fill in
     the resulting values

     we also need to replace these with the whenCreated/whenChanged
     equivalent in the search expression trees

  whenCreated: not-HIDDEN, CONSTRUCTED, SEARCHABLE
  whenChanged: not-HIDDEN, CONSTRUCTED, SEARCHABLE

     on init we need to setup attribute handlers for these so
     comparisons are done correctly. The resolution is 1 second.

     on add we need to add both the above, for current time

     on modify we need to change whenChanged

  structuralObjectClass: HIDDEN, CONSTRUCTED, not-searchable. always same as objectclass?

     for this one we do the search as normal, then if requested ask
     for objectclass, change the attribute name, and add it

  primaryGroupToken: HIDDEN, CONSTRUCTED, SEARCHABLE

     contains the RID of a certain group object
    

  attributeTypes: in schema only
  objectClasses: in schema only
  matchingRules: in schema only
  matchingRuleUse: in schema only
  creatorsName: not supported by w2k3?
  modifiersName: not supported by w2k3?
*/

#include "includes.h"
#include <ldb.h>
#include <ldb_module.h>

#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"

#include "libcli/security/security.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#endif

struct operational_data {
	struct ldb_dn *aggregate_dn;
};

enum search_type {
	TOKEN_GROUPS,
	TOKEN_GROUPS_GLOBAL_AND_UNIVERSAL,
	TOKEN_GROUPS_NO_GC_ACCEPTABLE
};

/*
  construct a canonical name from a message
*/
static int construct_canonical_name(struct ldb_module *module,
				    struct ldb_message *msg, enum ldb_scope scope,
				    struct ldb_request *parent)
{
	char *canonicalName;
	canonicalName = ldb_dn_canonical_string(msg, msg->dn);
	if (canonicalName == NULL) {
		return ldb_operr(ldb_module_get_ctx(module));
	}
	return ldb_msg_add_steal_string(msg, "canonicalName", canonicalName);
}

/*
  construct a primary group token for groups from a message
*/
static int construct_primary_group_token(struct ldb_module *module,
					 struct ldb_message *msg, enum ldb_scope scope,
					 struct ldb_request *parent)
{
	struct ldb_context *ldb;
	uint32_t primary_group_token;
	
	ldb = ldb_module_get_ctx(module);
	if (ldb_match_msg_objectclass(msg, "group") == 1) {
		primary_group_token
			= samdb_result_rid_from_sid(msg, msg, "objectSid", 0);
		if (primary_group_token == 0) {
			return LDB_SUCCESS;
		}

		return samdb_msg_add_uint(ldb, msg, msg, "primaryGroupToken",
			primary_group_token);
	} else {
		return LDB_SUCCESS;
	}
}

/*
  construct the token groups for SAM objects from a message
*/
static int construct_generic_token_groups(struct ldb_module *module,
					  struct ldb_message *msg, enum ldb_scope scope,
					  struct ldb_request *parent,
					  const char *attribute_string,
					  enum search_type type)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	TALLOC_CTX *tmp_ctx = talloc_new(msg);
	unsigned int i;
	int ret;
	const char *filter;

	NTSTATUS status;

	struct dom_sid *primary_group_sid;
	const char *primary_group_string;
	const char *primary_group_dn;
	DATA_BLOB primary_group_blob;

	struct dom_sid *account_sid;
	const char *account_sid_string;
	const char *account_sid_dn;
	DATA_BLOB account_sid_blob;
	struct dom_sid *groupSIDs = NULL;
	unsigned int num_groupSIDs = 0;

	struct dom_sid *domain_sid;

	if (scope != LDB_SCOPE_BASE) {
		ldb_set_errstring(ldb, "Cannot provide tokenGroups attribute, this is not a BASE search");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* If it's not a user, it won't have a primaryGroupID */
	if (ldb_msg_find_element(msg, "primaryGroupID") == NULL) {
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	/* Ensure it has an objectSID too */
	account_sid = samdb_result_dom_sid(tmp_ctx, msg, "objectSid");
	if (account_sid == NULL) {
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	status = dom_sid_split_rid(tmp_ctx, account_sid, &domain_sid, NULL);
	if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		talloc_free(tmp_ctx);
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	} else if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	primary_group_sid = dom_sid_add_rid(tmp_ctx,
					    domain_sid,
					    ldb_msg_find_attr_as_uint(msg, "primaryGroupID", ~0));
	if (!primary_group_sid) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	/* only return security groups */
	switch(type) {
	case TOKEN_GROUPS_GLOBAL_AND_UNIVERSAL:
		filter = talloc_asprintf(tmp_ctx, "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=%u)(|(groupType:1.2.840.113556.1.4.803:=%u)(groupType:1.2.840.113556.1.4.803:=%u)))",
					 GROUP_TYPE_SECURITY_ENABLED, GROUP_TYPE_ACCOUNT_GROUP, GROUP_TYPE_UNIVERSAL_GROUP);
		break;
	case TOKEN_GROUPS_NO_GC_ACCEPTABLE:
	case TOKEN_GROUPS:
		filter = talloc_asprintf(tmp_ctx, "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=%u))",
					 GROUP_TYPE_SECURITY_ENABLED);
		break;
	}

	if (!filter) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	primary_group_string = dom_sid_string(tmp_ctx, primary_group_sid);
	if (!primary_group_string) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	primary_group_dn = talloc_asprintf(tmp_ctx, "<SID=%s>", primary_group_string);
	if (!primary_group_dn) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	primary_group_blob = data_blob_string_const(primary_group_dn);

	account_sid_string = dom_sid_string(tmp_ctx, account_sid);
	if (!account_sid_string) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	account_sid_dn = talloc_asprintf(tmp_ctx, "<SID=%s>", account_sid_string);
	if (!account_sid_dn) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	account_sid_blob = data_blob_string_const(account_sid_dn);

	status = dsdb_expand_nested_groups(ldb, &account_sid_blob,
					   true, /* We don't want to add the object's SID itself,
						    it's not returend in this attribute */
					   filter,
					   tmp_ctx, &groupSIDs, &num_groupSIDs);

	if (!NT_STATUS_IS_OK(status)) {
		ldb_asprintf_errstring(ldb, "Failed to construct tokenGroups: expanding groups of SID %s failed: %s",
				       account_sid_string, nt_errstr(status));
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Expands the primary group - this function takes in
	 * memberOf-like values, so we fake one up with the
	 * <SID=S-...> format of DN and then let it expand
	 * them, as long as they meet the filter - so only
	 * domain groups, not builtin groups
	 */
	status = dsdb_expand_nested_groups(ldb, &primary_group_blob, false, filter,
					   tmp_ctx, &groupSIDs, &num_groupSIDs);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_asprintf_errstring(ldb, "Failed to construct tokenGroups: expanding groups of SID %s failed: %s",
				       account_sid_string, nt_errstr(status));
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	for (i=0; i < num_groupSIDs; i++) {
		ret = samdb_msg_add_dom_sid(ldb, msg, msg, attribute_string, &groupSIDs[i]);
		if (ret) {
			talloc_free(tmp_ctx);
			return ret;
		}
	}

	return LDB_SUCCESS;
}

static int construct_token_groups(struct ldb_module *module,
				  struct ldb_message *msg, enum ldb_scope scope,
				  struct ldb_request *parent)
{
	/**
	 * TODO: Add in a limiting domain when we start to support
	 * trusted domains.
	 */
	return construct_generic_token_groups(module, msg, scope, parent,
					      "tokenGroups",
					      TOKEN_GROUPS);
}

static int construct_token_groups_no_gc(struct ldb_module *module,
					struct ldb_message *msg, enum ldb_scope scope,
					struct ldb_request *parent)
{
	/**
	 * TODO: Add in a limiting domain when we start to support
	 * trusted domains.
	 */
	return construct_generic_token_groups(module, msg, scope, parent,
					      "tokenGroupsNoGCAcceptable",
					      TOKEN_GROUPS);
}

static int construct_global_universal_token_groups(struct ldb_module *module,
						   struct ldb_message *msg, enum ldb_scope scope,
						   struct ldb_request *parent)
{
	return construct_generic_token_groups(module, msg, scope, parent,
					      "tokenGroupsGlobalAndUniversal",
					      TOKEN_GROUPS_GLOBAL_AND_UNIVERSAL);
}
/*
  construct the parent GUID for an entry from a message
*/
static int construct_parent_guid(struct ldb_module *module,
				 struct ldb_message *msg, enum ldb_scope scope,
				 struct ldb_request *parent)
{
	struct ldb_result *res, *parent_res;
	const struct ldb_val *parent_guid;
	const char *attrs[] = { "instanceType", NULL };
	const char *attrs2[] = { "objectGUID", NULL };
	uint32_t instanceType;
	int ret;
	struct ldb_dn *parent_dn;
	struct ldb_val v;

	/* determine if the object is NC by instance type */
	ret = dsdb_module_search_dn(module, msg, &res, msg->dn, attrs,
	                            DSDB_FLAG_NEXT_MODULE |
	                            DSDB_SEARCH_SHOW_RECYCLED, parent);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	instanceType = ldb_msg_find_attr_as_uint(res->msgs[0],
						 "instanceType", 0);
	talloc_free(res);
	if (instanceType & INSTANCE_TYPE_IS_NC_HEAD) {
		DEBUG(4,(__location__ ": Object %s is NC\n",
			 ldb_dn_get_linearized(msg->dn)));
		return LDB_SUCCESS;
	}
	parent_dn = ldb_dn_get_parent(msg, msg->dn);

	if (parent_dn == NULL) {
		DEBUG(4,(__location__ ": Failed to find parent for dn %s\n",
					 ldb_dn_get_linearized(msg->dn)));
		return LDB_SUCCESS;
	}
	ret = dsdb_module_search_dn(module, msg, &parent_res, parent_dn, attrs2,
	                            DSDB_FLAG_NEXT_MODULE |
	                            DSDB_SEARCH_SHOW_RECYCLED, parent);
	talloc_free(parent_dn);

	/* not NC, so the object should have a parent*/
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		return ldb_error(ldb_module_get_ctx(module), LDB_ERR_OPERATIONS_ERROR, 
				 talloc_asprintf(msg, "Parent dn for %s does not exist", 
						 ldb_dn_get_linearized(msg->dn)));
	} else if (ret != LDB_SUCCESS) {
		return ret;
	}

	parent_guid = ldb_msg_find_ldb_val(parent_res->msgs[0], "objectGUID");
	if (!parent_guid) {
		talloc_free(parent_res);
		return LDB_SUCCESS;
	}

	v = data_blob_dup_talloc(parent_res, *parent_guid);
	if (!v.data) {
		talloc_free(parent_res);
		return ldb_oom(ldb_module_get_ctx(module));
	}
	ret = ldb_msg_add_steal_value(msg, "parentGUID", &v);
	talloc_free(parent_res);
	return ret;
}

static int construct_modifyTimeStamp(struct ldb_module *module,
					struct ldb_message *msg, enum ldb_scope scope,
					struct ldb_request *parent)
{
	struct operational_data *data = talloc_get_type(ldb_module_get_private(module), struct operational_data);
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	/* We may be being called before the init function has finished */
	if (!data) {
		return LDB_SUCCESS;
	}

	/* Try and set this value up, if possible.  Don't worry if it
	 * fails, we may not have the DB set up yet.
	 */
	if (!data->aggregate_dn) {
		data->aggregate_dn = samdb_aggregate_schema_dn(ldb, data);
	}

	if (data->aggregate_dn && ldb_dn_compare(data->aggregate_dn, msg->dn) == 0) {
		/*
		 * If we have the DN for the object with common name = Aggregate and
		 * the request is for this DN then let's do the following:
		 * 1) search the object which changedUSN correspond to the one of the loaded
		 * schema.
		 * 2) Get the whenChanged attribute
		 * 3) Generate the modifyTimestamp out of the whenChanged attribute
		 */
		const struct dsdb_schema *schema = dsdb_get_schema(ldb, NULL);
		char *value = ldb_timestring(msg, schema->ts_last_change);

		return ldb_msg_add_string(msg, "modifyTimeStamp", value);
	}
	return ldb_msg_copy_attr(msg, "whenChanged", "modifyTimeStamp");
}

/*
  construct a subSchemaSubEntry
*/
static int construct_subschema_subentry(struct ldb_module *module,
					struct ldb_message *msg, enum ldb_scope scope,
					struct ldb_request *parent)
{
	struct operational_data *data = talloc_get_type(ldb_module_get_private(module), struct operational_data);
	char *subSchemaSubEntry;

	/* We may be being called before the init function has finished */
	if (!data) {
		return LDB_SUCCESS;
	}

	/* Try and set this value up, if possible.  Don't worry if it
	 * fails, we may not have the DB set up yet, and it's not
	 * really vital anyway */
	if (!data->aggregate_dn) {
		struct ldb_context *ldb = ldb_module_get_ctx(module);
		data->aggregate_dn = samdb_aggregate_schema_dn(ldb, data);
	}

	if (data->aggregate_dn) {
		subSchemaSubEntry = ldb_dn_alloc_linearized(msg, data->aggregate_dn);
		return ldb_msg_add_steal_string(msg, "subSchemaSubEntry", subSchemaSubEntry);
	}
	return LDB_SUCCESS;
}


static int construct_msds_isrodc_with_dn(struct ldb_module *module,
					 struct ldb_message *msg,
					 struct ldb_message_element *object_category)
{
	struct ldb_context *ldb;
	struct ldb_dn *dn;
	const struct ldb_val *val;

	ldb = ldb_module_get_ctx(module);
	if (!ldb) {
		DEBUG(4, (__location__ ": Failed to get ldb \n"));
		return ldb_operr(ldb);
	}

	dn = ldb_dn_new(msg, ldb, (const char *)object_category->values[0].data);
	if (!dn) {
		DEBUG(4, (__location__ ": Failed to create dn from %s \n",
			  (const char *)object_category->values[0].data));
		return ldb_operr(ldb);
	}

	val = ldb_dn_get_rdn_val(dn);
	if (!val) {
		DEBUG(4, (__location__ ": Failed to get rdn val from %s \n",
			  ldb_dn_get_linearized(dn)));
		return ldb_operr(ldb);
	}

	if (strequal((const char *)val->data, "NTDS-DSA")) {
		ldb_msg_add_string(msg, "msDS-isRODC", "FALSE");
	} else {
		ldb_msg_add_string(msg, "msDS-isRODC", "TRUE");
	}
	return LDB_SUCCESS;
}

static int construct_msds_isrodc_with_server_dn(struct ldb_module *module,
						struct ldb_message *msg,
						struct ldb_dn *dn,
						struct ldb_request *parent)
{
	struct ldb_dn *server_dn;
	const char *attr_obj_cat[] = { "objectCategory", NULL };
	struct ldb_result *res;
	struct ldb_message_element *object_category;
	int ret;

	server_dn = ldb_dn_copy(msg, dn);
	if (!ldb_dn_add_child_fmt(server_dn, "CN=NTDS Settings")) {
		DEBUG(4, (__location__ ": Failed to add child to %s \n",
			  ldb_dn_get_linearized(server_dn)));
		return ldb_operr(ldb_module_get_ctx(module));
	}

	ret = dsdb_module_search_dn(module, msg, &res, server_dn, attr_obj_cat,
	                            DSDB_FLAG_NEXT_MODULE, parent);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		DEBUG(4,(__location__ ": Can't get objectCategory for %s \n",
					 ldb_dn_get_linearized(server_dn)));
		return LDB_SUCCESS;
	} else if (ret != LDB_SUCCESS) {
		return ret;
	}

	object_category = ldb_msg_find_element(res->msgs[0], "objectCategory");
	if (!object_category) {
		DEBUG(4,(__location__ ": Can't find objectCategory for %s \n",
			 ldb_dn_get_linearized(res->msgs[0]->dn)));
		return LDB_SUCCESS;
	}
	return construct_msds_isrodc_with_dn(module, msg, object_category);
}

static int construct_msds_isrodc_with_computer_dn(struct ldb_module *module,
						  struct ldb_message *msg,
						  struct ldb_request *parent)
{
	int ret;
	struct ldb_dn *server_dn;

	ret = dsdb_module_reference_dn(module, msg, msg->dn, "serverReferenceBL",
				       &server_dn, parent);
	if (ret == LDB_ERR_NO_SUCH_OBJECT || ret == LDB_ERR_NO_SUCH_ATTRIBUTE) {
		/* it's OK if we can't find serverReferenceBL attribute */
		DEBUG(4,(__location__ ": Can't get serverReferenceBL for %s \n",
			 ldb_dn_get_linearized(msg->dn)));
		return LDB_SUCCESS;
	} else if (ret != LDB_SUCCESS) {
		return ret;
	}

	return construct_msds_isrodc_with_server_dn(module, msg, server_dn, parent);
}

/*
  construct msDS-isRODC attr
*/
static int construct_msds_isrodc(struct ldb_module *module,
				 struct ldb_message *msg, enum ldb_scope scope,
				 struct ldb_request *parent)
{
	struct ldb_message_element * object_class;
	struct ldb_message_element * object_category;
	unsigned int i;

	object_class = ldb_msg_find_element(msg, "objectClass");
	if (!object_class) {
		DEBUG(4,(__location__ ": Can't get objectClass for %s \n",
			 ldb_dn_get_linearized(msg->dn)));
		return ldb_operr(ldb_module_get_ctx(module));
	}

	for (i=0; i<object_class->num_values; i++) {
		if (strequal((const char*)object_class->values[i].data, "nTDSDSA")) {
			/* If TO!objectCategory  equals the DN of the classSchema  object for the nTDSDSA
			 * object class, then TO!msDS-isRODC  is false. Otherwise, TO!msDS-isRODC  is true.
			 */
			object_category = ldb_msg_find_element(msg, "objectCategory");
			if (!object_category) {
				DEBUG(4,(__location__ ": Can't get objectCategory for %s \n",
					 ldb_dn_get_linearized(msg->dn)));
				return LDB_SUCCESS;
			}
			return construct_msds_isrodc_with_dn(module, msg, object_category);
		}
		if (strequal((const char*)object_class->values[i].data, "server")) {
			/* Let TN be the nTDSDSA  object whose DN is "CN=NTDS Settings," prepended to
			 * the DN of TO. Apply the previous rule for the "TO is an nTDSDSA  object" case,
			 * substituting TN for TO.
			 */
			return construct_msds_isrodc_with_server_dn(module, msg, msg->dn, parent);
		}
		if (strequal((const char*)object_class->values[i].data, "computer")) {
			/* Let TS be the server  object named by TO!serverReferenceBL. Apply the previous
			 * rule for the "TO is a server  object" case, substituting TS for TO.
			 */
			return construct_msds_isrodc_with_computer_dn(module, msg, parent);
		}
	}

	return LDB_SUCCESS;
}


/*
  construct msDS-keyVersionNumber attr

  TODO:  Make this based on the 'win2k' DS huristics bit...

*/
static int construct_msds_keyversionnumber(struct ldb_module *module,
					   struct ldb_message *msg,
					   enum ldb_scope scope,
					   struct ldb_request *parent)
{
	uint32_t i;
	enum ndr_err_code ndr_err;
	const struct ldb_val *omd_value;
	struct replPropertyMetaDataBlob *omd;
	int ret;

	omd_value = ldb_msg_find_ldb_val(msg, "replPropertyMetaData");
	if (!omd_value) {
		/* We can't make up a key version number without meta data */
		return LDB_SUCCESS;
	}
	if (!omd_value) {
		return LDB_SUCCESS;
	}

	omd = talloc(msg, struct replPropertyMetaDataBlob);
	if (!omd) {
		ldb_module_oom(module);
		return LDB_SUCCESS;
	}

	ndr_err = ndr_pull_struct_blob(omd_value, omd, omd,
				       (ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaDataBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0,(__location__ ": Failed to parse replPropertyMetaData for %s when trying to add msDS-KeyVersionNumber\n",
			 ldb_dn_get_linearized(msg->dn)));
		return ldb_operr(ldb_module_get_ctx(module));
	}

	if (omd->version != 1) {
		DEBUG(0,(__location__ ": bad version %u in replPropertyMetaData for %s when trying to add msDS-KeyVersionNumber\n",
			 omd->version, ldb_dn_get_linearized(msg->dn)));
		talloc_free(omd);
		return LDB_SUCCESS;
	}
	for (i=0; i<omd->ctr.ctr1.count; i++) {
		if (omd->ctr.ctr1.array[i].attid == DRSUAPI_ATTID_unicodePwd) {
			ret = samdb_msg_add_uint(ldb_module_get_ctx(module),
						 msg, msg,
						 "msDS-KeyVersionNumber",
						 omd->ctr.ctr1.array[i].version);
			if (ret != LDB_SUCCESS) {
				talloc_free(omd);
				return ret;
			}
			break;
		}
	}
	return LDB_SUCCESS;

}

#define _UF_TRUST_ACCOUNTS ( \
	UF_WORKSTATION_TRUST_ACCOUNT | \
	UF_SERVER_TRUST_ACCOUNT | \
	UF_INTERDOMAIN_TRUST_ACCOUNT \
)
#define _UF_NO_EXPIRY_ACCOUNTS ( \
	UF_SMARTCARD_REQUIRED | \
	UF_DONT_EXPIRE_PASSWD | \
	_UF_TRUST_ACCOUNTS \
)

/*
  calculate msDS-UserPasswordExpiryTimeComputed
*/
static NTTIME get_msds_user_password_expiry_time_computed(struct ldb_module *module,
						struct ldb_message *msg,
						struct ldb_dn *domain_dn)
{
	int64_t pwdLastSet, maxPwdAge;
	uint32_t userAccountControl;
	NTTIME ret;

	userAccountControl = ldb_msg_find_attr_as_uint(msg,
					"userAccountControl",
					0);
	if (userAccountControl & _UF_NO_EXPIRY_ACCOUNTS) {
		return 0x7FFFFFFFFFFFFFFFULL;
	}

	pwdLastSet = ldb_msg_find_attr_as_int64(msg, "pwdLastSet", 0);
	if (pwdLastSet == 0) {
		return 0;
	}

	if (pwdLastSet <= -1) {
		/*
		 * This can't really happen...
		 */
		return 0x7FFFFFFFFFFFFFFFULL;
	}

	if (pwdLastSet >= 0x7FFFFFFFFFFFFFFFULL) {
		/*
		 * Somethings wrong with the clock...
		 */
		return 0x7FFFFFFFFFFFFFFFULL;
	}

	/*
	 * Note that maxPwdAge is a stored as negative value.
	 *
	 * Possible values are in the range of:
	 *
	 * maxPwdAge: -864000000001
	 * to
	 * maxPwdAge: -9223372036854775808 (-0x8000000000000000ULL)
	 *
	 */
	maxPwdAge = samdb_search_int64(ldb_module_get_ctx(module), msg, 0,
				       domain_dn, "maxPwdAge", NULL);
	if (maxPwdAge >= -864000000000) {
		/*
		 * This is not really possible...
		 */
		return 0x7FFFFFFFFFFFFFFFULL;
	}

	if (maxPwdAge == -0x8000000000000000ULL) {
		return 0x7FFFFFFFFFFFFFFFULL;
	}

	/*
	 * Note we already catched maxPwdAge == -0x8000000000000000ULL
	 * and pwdLastSet >= 0x7FFFFFFFFFFFFFFFULL above.
	 *
	 * Remember maxPwdAge is a negative number,
	 * so it results in the following.
	 *
	 * 0x7FFFFFFFFFFFFFFEULL + 0x7FFFFFFFFFFFFFFFULL
	 * =
	 * 0xFFFFFFFFFFFFFFFFULL
	 */
	ret = pwdLastSet - maxPwdAge;
	if (ret >= 0x7FFFFFFFFFFFFFFFULL) {
		return 0x7FFFFFFFFFFFFFFFULL;
	}

	return ret;
}


/*
  construct msDS-User-Account-Control-Computed attr
*/
static int construct_msds_user_account_control_computed(struct ldb_module *module,
							struct ldb_message *msg, enum ldb_scope scope,
							struct ldb_request *parent)
{
	uint32_t userAccountControl;
	uint32_t msDS_User_Account_Control_Computed = 0;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	NTTIME now;
	struct ldb_dn *nc_root;
	int ret;

	ret = dsdb_find_nc_root(ldb, msg, msg->dn, &nc_root);
	if (ret != 0) {
		ldb_asprintf_errstring(ldb,
				       "Failed to find NC root of DN: %s: %s",
				       ldb_dn_get_linearized(msg->dn),
				       ldb_errstring(ldb_module_get_ctx(module)));
		return ret;
	}
	if (ldb_dn_compare(nc_root, ldb_get_default_basedn(ldb)) != 0) {
		/* Only calculate this on our default NC */
		return 0;
	}
	/* Test account expire time */
	unix_to_nt_time(&now, time(NULL));

	userAccountControl = ldb_msg_find_attr_as_uint(msg,
						       "userAccountControl",
						       0);
	if (!(userAccountControl & _UF_TRUST_ACCOUNTS)) {

		int64_t lockoutTime = ldb_msg_find_attr_as_int64(msg, "lockoutTime", 0);
		if (lockoutTime != 0) {
			int64_t lockoutDuration = samdb_search_int64(ldb,
								     msg, 0, nc_root,
								     "lockoutDuration", NULL);
			if (lockoutDuration >= 0) {
				msDS_User_Account_Control_Computed |= UF_LOCKOUT;
			} else if (lockoutTime - lockoutDuration >= now) {
				msDS_User_Account_Control_Computed |= UF_LOCKOUT;
			}
		}
	}

	if (!(userAccountControl & _UF_NO_EXPIRY_ACCOUNTS)) {
		NTTIME must_change_time
			= get_msds_user_password_expiry_time_computed(module,
								      msg, nc_root);
		/* check for expired password */
		if (must_change_time < now) {
			msDS_User_Account_Control_Computed |= UF_PASSWORD_EXPIRED;
		}
	}

	return samdb_msg_add_int64(ldb,
				   msg->elements, msg,
				   "msDS-User-Account-Control-Computed",
				   msDS_User_Account_Control_Computed);
}

/*
  construct msDS-UserPasswordExpiryTimeComputed
*/
static int construct_msds_user_password_expiry_time_computed(struct ldb_module *module,
							     struct ldb_message *msg, enum ldb_scope scope,
							     struct ldb_request *parent)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_dn *nc_root;
	int64_t password_expiry_time;
	int ret;

	ret = dsdb_find_nc_root(ldb, msg, msg->dn, &nc_root);
	if (ret != 0) {
		ldb_asprintf_errstring(ldb,
				       "Failed to find NC root of DN: %s: %s",
				       ldb_dn_get_linearized(msg->dn),
				       ldb_errstring(ldb));
		return ret;
	}

	if (ldb_dn_compare(nc_root, ldb_get_default_basedn(ldb)) != 0) {
		/* Only calculate this on our default NC */
		return 0;
	}

	password_expiry_time
		= get_msds_user_password_expiry_time_computed(module, msg,
							      nc_root);

	return samdb_msg_add_int64(ldb,
				   msg->elements, msg,
				   "msDS-UserPasswordExpiryTimeComputed",
				   password_expiry_time);
}


struct op_controls_flags {
	bool sd;
	bool bypassoperational;
};

static bool check_keep_control_for_attribute(struct op_controls_flags* controls_flags, const char* attr) {
	if (controls_flags->bypassoperational && ldb_attr_cmp(attr, "msDS-KeyVersionNumber") == 0 ) {
		return true;
	}
	return false;
}

/*
  a list of attribute names that should be substituted in the parse
  tree before the search is done
*/
static const struct {
	const char *attr;
	const char *replace;
} parse_tree_sub[] = {
	{ "createTimeStamp", "whenCreated" },
	{ "modifyTimeStamp", "whenChanged" }
};


struct op_attributes_replace {
	const char *attr;
	const char *replace;
	const char * const *extra_attrs;
	int (*constructor)(struct ldb_module *, struct ldb_message *, enum ldb_scope, struct ldb_request *);
};


static const char *objectSid_attr[] =
{
	"objectSid",
	NULL
};


static const char *objectCategory_attr[] =
{
	"objectCategory",
	NULL
};


static const char *user_account_control_computed_attrs[] =
{
	"lockoutTime",
	"pwdLastSet",
	NULL
};


static const char *user_password_expiry_time_computed_attrs[] =
{
	"pwdLastSet",
	NULL
};


/*
  a list of attribute names that are hidden, but can be searched for
  using another (non-hidden) name to produce the correct result
*/
static const struct op_attributes_replace search_sub[] = {
	{ "createTimeStamp", "whenCreated", NULL , NULL },
	{ "modifyTimeStamp", "whenChanged", NULL , construct_modifyTimeStamp},
	{ "structuralObjectClass", "objectClass", NULL , NULL },
	{ "canonicalName", NULL, NULL , construct_canonical_name },
	{ "primaryGroupToken", "objectClass", objectSid_attr, construct_primary_group_token },
	{ "tokenGroups", "primaryGroupID", objectSid_attr, construct_token_groups },
	{ "tokenGroupsNoGCAcceptable", "primaryGroupID", objectSid_attr, construct_token_groups_no_gc},
	{ "tokenGroupsGlobalAndUniversal", "primaryGroupID", objectSid_attr, construct_global_universal_token_groups },
	{ "parentGUID", NULL, NULL, construct_parent_guid },
	{ "subSchemaSubEntry", NULL, NULL, construct_subschema_subentry },
	{ "msDS-isRODC", "objectClass", objectCategory_attr, construct_msds_isrodc },
	{ "msDS-KeyVersionNumber", "replPropertyMetaData", NULL, construct_msds_keyversionnumber },
	{ "msDS-User-Account-Control-Computed", "userAccountControl", user_account_control_computed_attrs,
	  construct_msds_user_account_control_computed },
	{ "msDS-UserPasswordExpiryTimeComputed", "userAccountControl", user_password_expiry_time_computed_attrs,
	  construct_msds_user_password_expiry_time_computed }
};


enum op_remove {
	OPERATIONAL_REMOVE_ALWAYS, /* remove always */
	OPERATIONAL_REMOVE_UNASKED,/* remove if not requested */
	OPERATIONAL_SD_FLAGS,	   /* show if SD_FLAGS_OID set, or asked for */
	OPERATIONAL_REMOVE_UNLESS_CONTROL	 /* remove always unless an adhoc control has been specified */
};

/*
  a list of attributes that may need to be removed from the
  underlying db return

  Some of these are attributes that were once stored, but are now calculated
*/
struct op_attributes_operations {
	const char *attr;
	enum op_remove op;
};

static const struct op_attributes_operations operational_remove[] = {
	{ "nTSecurityDescriptor",    OPERATIONAL_SD_FLAGS },
	{ "msDS-KeyVersionNumber",   OPERATIONAL_REMOVE_UNLESS_CONTROL  },
	{ "parentGUID",              OPERATIONAL_REMOVE_ALWAYS  },
	{ "replPropertyMetaData",    OPERATIONAL_REMOVE_UNASKED },
#define _SEP ,OPERATIONAL_REMOVE_UNASKED},{
	{ DSDB_SECRET_ATTRIBUTES_EX(_SEP), OPERATIONAL_REMOVE_UNASKED }
};


/*
  post process a search result record. For any search_sub[] attributes that were
  asked for, we need to call the appropriate copy routine to copy the result
  into the message, then remove any attributes that we added to the search but
  were not asked for by the user
*/
static int operational_search_post_process(struct ldb_module *module,
					   struct ldb_message *msg,
					   enum ldb_scope scope,
					   const char * const *attrs_from_user,
					   const char * const *attrs_searched_for,
					   struct op_controls_flags* controls_flags,
					   struct op_attributes_operations *list,
					   unsigned int list_size,
					   struct op_attributes_replace *list_replace,
					   unsigned int list_replace_size,
					   struct ldb_request *parent)
{
	struct ldb_context *ldb;
	unsigned int i, a = 0;
	bool constructed_attributes = false;

	ldb = ldb_module_get_ctx(module);

	/* removed any attrs that should not be shown to the user */
	for (i=0; i < list_size; i++) {
		ldb_msg_remove_attr(msg, list[i].attr);
	}

	for (a=0; a < list_replace_size; a++) {
		if (check_keep_control_for_attribute(controls_flags,
						     list_replace[a].attr)) {
			continue;
		}

		/* construct the new attribute, using either a supplied
			constructor or a simple copy */
		constructed_attributes = true;
		if (list_replace[a].constructor != NULL) {
			if (list_replace[a].constructor(module, msg, scope, parent) != LDB_SUCCESS) {
				goto failed;
			}
		} else if (ldb_msg_copy_attr(msg,
					     list_replace[a].replace,
					     list_replace[a].attr) != LDB_SUCCESS) {
			goto failed;
		}
	}

	/* Deletion of the search helper attributes are needed if:
	 * - we generated constructed attributes and
	 * - we aren't requesting all attributes
	 */
	if ((constructed_attributes) && (!ldb_attr_in_list(attrs_from_user, "*"))) {
		for (i=0; i < list_replace_size; i++) {
			/* remove the added search helper attributes, unless
			 * they were asked for by the user */
			if (list_replace[i].replace != NULL &&
			    !ldb_attr_in_list(attrs_from_user, list_replace[i].replace)) {
				ldb_msg_remove_attr(msg, list_replace[i].replace);
			}
			if (list_replace[i].extra_attrs != NULL) {
				unsigned int j;
				for (j=0; list_replace[i].extra_attrs[j]; j++) {
					if (!ldb_attr_in_list(attrs_from_user, list_replace[i].extra_attrs[j])) {
						ldb_msg_remove_attr(msg, list_replace[i].extra_attrs[j]);
					}
				}
			}
		}
	}

	return 0;

failed:
	ldb_debug_set(ldb, LDB_DEBUG_WARNING,
		      "operational_search_post_process failed for attribute '%s' - %s",
		      attrs_from_user[a], ldb_errstring(ldb));
	return -1;
}

/*
  hook search operations
*/

struct operational_context {
	struct ldb_module *module;
	struct ldb_request *req;
	enum ldb_scope scope;
	const char * const *attrs;
	struct op_controls_flags* controls_flags;
	struct op_attributes_operations *list_operations;
	unsigned int list_operations_size;
	struct op_attributes_replace *attrs_to_replace;
	unsigned int attrs_to_replace_size;
};

static int operational_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct operational_context *ac;
	int ret;

	ac = talloc_get_type(req->context, struct operational_context);

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
		/* for each record returned post-process to add any derived
		   attributes that have been asked for */
		ret = operational_search_post_process(ac->module,
						      ares->message,
						      ac->scope,
						      ac->attrs,
						      req->op.search.attrs,
						      ac->controls_flags,
						      ac->list_operations,
						      ac->list_operations_size,
						      ac->attrs_to_replace,
						      ac->attrs_to_replace_size,
						      req);
		if (ret != 0) {
			return ldb_module_done(ac->req, NULL, NULL,
						LDB_ERR_OPERATIONS_ERROR);
		}
		return ldb_module_send_entry(ac->req, ares->message, ares->controls);

	case LDB_REPLY_REFERRAL:
		return ldb_module_send_referral(ac->req, ares->referral);

	case LDB_REPLY_DONE:

		return ldb_module_done(ac->req, ares->controls,
					ares->response, LDB_SUCCESS);
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}

static struct op_attributes_operations* operation_get_op_list(TALLOC_CTX *ctx,
							      const char* const* attrs,
							      const char* const* searched_attrs,
							      struct op_controls_flags* controls_flags)
{
	int idx = 0;
	int i;
	struct op_attributes_operations *list = talloc_zero_array(ctx,
								  struct op_attributes_operations,
								  ARRAY_SIZE(operational_remove) + 1);

	if (list == NULL) {
		return NULL;
	}

	for (i=0; i<ARRAY_SIZE(operational_remove); i++) {
		switch (operational_remove[i].op) {
		case OPERATIONAL_REMOVE_UNASKED:
			if (ldb_attr_in_list(attrs, operational_remove[i].attr)) {
				continue;
			}
			if (ldb_attr_in_list(searched_attrs, operational_remove[i].attr)) {
				continue;
			}
			list[idx].attr = operational_remove[i].attr;
			list[idx].op = OPERATIONAL_REMOVE_UNASKED;
			idx++;
			break;

		case OPERATIONAL_REMOVE_ALWAYS:
			list[idx].attr = operational_remove[i].attr;
			list[idx].op = OPERATIONAL_REMOVE_ALWAYS;
			idx++;
			break;

		case OPERATIONAL_REMOVE_UNLESS_CONTROL:
			if (!check_keep_control_for_attribute(controls_flags, operational_remove[i].attr)) {
				list[idx].attr = operational_remove[i].attr;
				list[idx].op = OPERATIONAL_REMOVE_UNLESS_CONTROL;
				idx++;
			}
			break;

		case OPERATIONAL_SD_FLAGS:
			if (ldb_attr_in_list(attrs, operational_remove[i].attr)) {
				continue;
			}
			if (controls_flags->sd) {
				if (attrs == NULL) {
					continue;
				}
				if (attrs[0] == NULL) {
					continue;
				}
				if (ldb_attr_in_list(attrs, "*")) {
					continue;
				}
			}
			list[idx].attr = operational_remove[i].attr;
			list[idx].op = OPERATIONAL_SD_FLAGS;
			idx++;
			break;
		}
	}

	return list;
}

static int operational_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct operational_context *ac;
	struct ldb_request *down_req;
	const char **search_attrs = NULL;
	unsigned int i, a;
	int ret;

	/* There are no operational attributes on special DNs */
	if (ldb_dn_is_special(req->op.search.base)) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	ac = talloc(req, struct operational_context);
	if (ac == NULL) {
		return ldb_oom(ldb);
	}

	ac->module = module;
	ac->req = req;
	ac->scope = req->op.search.scope;
	ac->attrs = req->op.search.attrs;

	/*  FIXME: We must copy the tree and keep the original
	 *  unmodified. SSS */
	/* replace any attributes in the parse tree that are
	   searchable, but are stored using a different name in the
	   backend */
	for (i=0;i<ARRAY_SIZE(parse_tree_sub);i++) {
		ldb_parse_tree_attr_replace(req->op.search.tree,
					    parse_tree_sub[i].attr,
					    parse_tree_sub[i].replace);
	}

	ac->controls_flags = talloc(ac, struct op_controls_flags);
	/* remember if the SD_FLAGS_OID was set */
	ac->controls_flags->sd = (ldb_request_get_control(req, LDB_CONTROL_SD_FLAGS_OID) != NULL);
	/* remember if the LDB_CONTROL_BYPASS_OPERATIONAL_OID */
	ac->controls_flags->bypassoperational =
		(ldb_request_get_control(req, LDB_CONTROL_BYPASS_OPERATIONAL_OID) != NULL);

	ac->attrs_to_replace = NULL;
	ac->attrs_to_replace_size = 0;
	/* in the list of attributes we are looking for, rename any
	   attributes to the alias for any hidden attributes that can
	   be fetched directly using non-hidden names */
	for (a=0;ac->attrs && ac->attrs[a];a++) {
		if (check_keep_control_for_attribute(ac->controls_flags, ac->attrs[a])) {
			continue;
		}
		for (i=0;i<ARRAY_SIZE(search_sub);i++) {

			if (ldb_attr_cmp(ac->attrs[a], search_sub[i].attr) != 0 ) {
				continue;
			}

			ac->attrs_to_replace = talloc_realloc(ac,
							      ac->attrs_to_replace,
							      struct op_attributes_replace,
							      ac->attrs_to_replace_size + 1);

			ac->attrs_to_replace[ac->attrs_to_replace_size] = search_sub[i];
			ac->attrs_to_replace_size++;
			if (!search_sub[i].replace) {
				continue;
			}

			if (search_sub[i].extra_attrs && search_sub[i].extra_attrs[0]) {
				unsigned int j;
				const char **search_attrs2;
				/* Only adds to the end of the list */
				for (j = 0; search_sub[i].extra_attrs[j]; j++) {
					search_attrs2 = ldb_attr_list_copy_add(req, search_attrs
									       ? search_attrs
									       : ac->attrs, 
									       search_sub[i].extra_attrs[j]);
					if (search_attrs2 == NULL) {
						return ldb_operr(ldb);
					}
					/* may be NULL, talloc_free() doesn't mind */
					talloc_free(search_attrs);
					search_attrs = search_attrs2;
				}
			}

			if (!search_attrs) {
				search_attrs = ldb_attr_list_copy(req, ac->attrs);
				if (search_attrs == NULL) {
					return ldb_operr(ldb);
				}
			}
			/* Despite the ldb_attr_list_copy_add, this is safe as that fn only adds to the end */
			search_attrs[a] = search_sub[i].replace;
		}
	}
	ac->list_operations = operation_get_op_list(ac, ac->attrs,
						    search_attrs == NULL?req->op.search.attrs:search_attrs,
						    ac->controls_flags);
	ac->list_operations_size = 0;
	i = 0;

	while (ac->list_operations && ac->list_operations[i].attr != NULL) {
		i++;
	}
	ac->list_operations_size = i;
	ret = ldb_build_search_req_ex(&down_req, ldb, ac,
					req->op.search.base,
					req->op.search.scope,
					req->op.search.tree,
					/* use new set of attrs if any */
					search_attrs == NULL?req->op.search.attrs:search_attrs,
					req->controls,
					ac, operational_callback,
					req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
	}

	/* perform the search */
	return ldb_next_request(module, down_req);
}

static int operational_init(struct ldb_module *ctx)
{
	struct operational_data *data;
	int ret;

	ret = ldb_next_init(ctx);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	data = talloc_zero(ctx, struct operational_data);
	if (!data) {
		return ldb_module_oom(ctx);
	}

	ldb_module_set_private(ctx, data);

	return LDB_SUCCESS;
}

static const struct ldb_module_ops ldb_operational_module_ops = {
	.name              = "operational",
	.search            = operational_search,
	.init_context	   = operational_init
};

int ldb_operational_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_operational_module_ops);
}
