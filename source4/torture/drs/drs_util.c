/*
   Unix SMB/CIFS implementation.

   DRSUAPI utility functions to be used in torture tests

   Copyright (C) Kamen Mazdrashki <kamen.mazdrashki@postpath.com> 2009

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
#include "torture/torture.h"
#include "dsdb/samdb/samdb.h"
#include "torture/rpc/drsuapi.h"
#include "../lib/util/asn1.h"

/**
 * Decode Attribute OID based on MS documentation
 * See MS-DRSR.pdf - 5.16.4
 *
 * On success returns decoded OID and
 * corresponding prefix_map index (if requested)
 */
bool drs_util_oid_from_attid(struct torture_context *tctx,
			     const struct drsuapi_DsReplicaOIDMapping_Ctr *prefix_map,
			     uint32_t attid,
			     const char **_oid,
			     int *map_idx)
{
	int i;
	uint32_t hi_word, lo_word;
	DATA_BLOB bin_oid = {NULL, 0};
	struct drsuapi_DsReplicaOIDMapping *map_entry = NULL;
	TALLOC_CTX *mem_ctx = talloc_named(tctx, 0, "util_drsuapi_oid_from_attid");

	/* crack attid value */
	hi_word = attid >> 16;
	lo_word = attid & 0xFFFF;

	/* check last entry in the prefix map is the special one */
	map_entry = &prefix_map->mappings[prefix_map->num_mappings-1];
	torture_assert(tctx,
			(map_entry->id_prefix == 0)
			&& (*map_entry->oid.binary_oid == 0xFF),
			"Last entry in Prefix Map is not the special one!");

	/* locate corresponding prefixMap entry */
	map_entry = NULL;
	for (i = 0; i < prefix_map->num_mappings - 1; i++) {

		if (hi_word == prefix_map->mappings[i].id_prefix) {
			map_entry = &prefix_map->mappings[i];
			if (map_idx)	*map_idx = i;
			break;
		}
	}

	torture_assert(tctx, map_entry, "Unable to locate corresponding Prefix Map entry");

	/* copy partial oid making enough room */
	bin_oid.length = map_entry->oid.length + 2;
	bin_oid.data = talloc_array(mem_ctx, uint8_t, bin_oid.length);
	torture_assert(tctx, bin_oid.data, "Not enough memory");
	memcpy(bin_oid.data, map_entry->oid.binary_oid, map_entry->oid.length);

	if (lo_word < 128) {
		bin_oid.length = bin_oid.length - 1;
		bin_oid.data[bin_oid.length-1] = lo_word;
	}
	else {
		if (lo_word >= 32768) {
			lo_word -= 32768;
		}
		bin_oid.data[bin_oid.length-2] = ((lo_word / 128) % 128) + 128; // (0x80 | ((lo_word>>7) & 0x7f))
		bin_oid.data[bin_oid.length-1] = lo_word % 128; // lo_word & 0x7f
	}

	torture_assert(tctx,
			ber_read_OID_String(tctx, bin_oid, _oid),
			"Failed to decode binary OID");
	talloc_free(mem_ctx);

	return true;
}

/**
 * Utility function to convert drsuapi_DsAttributeId to String
 */
const char * drs_util_DsAttributeId_to_string(enum drsuapi_DsAttributeId r)
{
	const char *val = NULL;

	switch (r) {
	case DRSUAPI_ATTRIBUTE_objectClass: val = "DRSUAPI_ATTRIBUTE_objectClass"; break;
	case DRSUAPI_ATTRIBUTE_description: val = "DRSUAPI_ATTRIBUTE_description"; break;
	case DRSUAPI_ATTRIBUTE_member: val = "DRSUAPI_ATTRIBUTE_member"; break;
	case DRSUAPI_ATTRIBUTE_instanceType: val = "DRSUAPI_ATTRIBUTE_instanceType"; break;
	case DRSUAPI_ATTRIBUTE_whenCreated: val = "DRSUAPI_ATTRIBUTE_whenCreated"; break;
	case DRSUAPI_ATTRIBUTE_hasMasterNCs: val = "DRSUAPI_ATTRIBUTE_hasMasterNCs"; break;
	case DRSUAPI_ATTRIBUTE_governsID: val = "DRSUAPI_ATTRIBUTE_governsID"; break;
	case DRSUAPI_ATTRIBUTE_attributeID: val = "DRSUAPI_ATTRIBUTE_attributeID"; break;
	case DRSUAPI_ATTRIBUTE_attributeSyntax: val = "DRSUAPI_ATTRIBUTE_attributeSyntax"; break;
	case DRSUAPI_ATTRIBUTE_isSingleValued: val = "DRSUAPI_ATTRIBUTE_isSingleValued"; break;
	case DRSUAPI_ATTRIBUTE_rangeLower: val = "DRSUAPI_ATTRIBUTE_rangeLower"; break;
	case DRSUAPI_ATTRIBUTE_rangeUpper: val = "DRSUAPI_ATTRIBUTE_rangeUpper"; break;
	case DRSUAPI_ATTRIBUTE_dMDLocation: val = "DRSUAPI_ATTRIBUTE_dMDLocation"; break;
	case DRSUAPI_ATTRIBUTE_objectVersion: val = "DRSUAPI_ATTRIBUTE_objectVersion"; break;
	case DRSUAPI_ATTRIBUTE_invocationId: val = "DRSUAPI_ATTRIBUTE_invocationId"; break;
	case DRSUAPI_ATTRIBUTE_showInAdvancedViewOnly: val = "DRSUAPI_ATTRIBUTE_showInAdvancedViewOnly"; break;
	case DRSUAPI_ATTRIBUTE_adminDisplayName: val = "DRSUAPI_ATTRIBUTE_adminDisplayName"; break;
	case DRSUAPI_ATTRIBUTE_adminDescription: val = "DRSUAPI_ATTRIBUTE_adminDescription"; break;
	case DRSUAPI_ATTRIBUTE_oMSyntax: val = "DRSUAPI_ATTRIBUTE_oMSyntax"; break;
	case DRSUAPI_ATTRIBUTE_ntSecurityDescriptor: val = "DRSUAPI_ATTRIBUTE_ntSecurityDescriptor"; break;
	case DRSUAPI_ATTRIBUTE_searchFlags: val = "DRSUAPI_ATTRIBUTE_searchFlags"; break;
	case DRSUAPI_ATTRIBUTE_lDAPDisplayName: val = "DRSUAPI_ATTRIBUTE_lDAPDisplayName"; break;
	case DRSUAPI_ATTRIBUTE_name: val = "DRSUAPI_ATTRIBUTE_name"; break;
	case DRSUAPI_ATTRIBUTE_userAccountControl: val = "DRSUAPI_ATTRIBUTE_userAccountControl"; break;
	case DRSUAPI_ATTRIBUTE_currentValue: val = "DRSUAPI_ATTRIBUTE_currentValue"; break;
	case DRSUAPI_ATTRIBUTE_homeDirectory: val = "DRSUAPI_ATTRIBUTE_homeDirectory"; break;
	case DRSUAPI_ATTRIBUTE_homeDrive: val = "DRSUAPI_ATTRIBUTE_homeDrive"; break;
	case DRSUAPI_ATTRIBUTE_scriptPath: val = "DRSUAPI_ATTRIBUTE_scriptPath"; break;
	case DRSUAPI_ATTRIBUTE_profilePath: val = "DRSUAPI_ATTRIBUTE_profilePath"; break;
	case DRSUAPI_ATTRIBUTE_objectSid: val = "DRSUAPI_ATTRIBUTE_objectSid"; break;
	case DRSUAPI_ATTRIBUTE_schemaIDGUID: val = "DRSUAPI_ATTRIBUTE_schemaIDGUID"; break;
	case DRSUAPI_ATTRIBUTE_dBCSPwd: val = "DRSUAPI_ATTRIBUTE_dBCSPwd"; break;
	case DRSUAPI_ATTRIBUTE_logonHours: val = "DRSUAPI_ATTRIBUTE_logonHours"; break;
	case DRSUAPI_ATTRIBUTE_userWorkstations: val = "DRSUAPI_ATTRIBUTE_userWorkstations"; break;
	case DRSUAPI_ATTRIBUTE_unicodePwd: val = "DRSUAPI_ATTRIBUTE_unicodePwd"; break;
	case DRSUAPI_ATTRIBUTE_ntPwdHistory: val = "DRSUAPI_ATTRIBUTE_ntPwdHistory"; break;
	case DRSUAPI_ATTRIBUTE_priorValue: val = "DRSUAPI_ATTRIBUTE_priorValue"; break;
	case DRSUAPI_ATTRIBUTE_supplementalCredentials: val = "DRSUAPI_ATTRIBUTE_supplementalCredentials"; break;
	case DRSUAPI_ATTRIBUTE_trustAuthIncoming: val = "DRSUAPI_ATTRIBUTE_trustAuthIncoming"; break;
	case DRSUAPI_ATTRIBUTE_trustAuthOutgoing: val = "DRSUAPI_ATTRIBUTE_trustAuthOutgoing"; break;
	case DRSUAPI_ATTRIBUTE_lmPwdHistory: val = "DRSUAPI_ATTRIBUTE_lmPwdHistory"; break;
	case DRSUAPI_ATTRIBUTE_sAMAccountName: val = "DRSUAPI_ATTRIBUTE_sAMAccountName"; break;
	case DRSUAPI_ATTRIBUTE_sAMAccountType: val = "DRSUAPI_ATTRIBUTE_sAMAccountType"; break;
	case DRSUAPI_ATTRIBUTE_fSMORoleOwner: val = "DRSUAPI_ATTRIBUTE_fSMORoleOwner"; break;
	case DRSUAPI_ATTRIBUTE_systemFlags: val = "DRSUAPI_ATTRIBUTE_systemFlags"; break;
	case DRSUAPI_ATTRIBUTE_serverReference: val = "DRSUAPI_ATTRIBUTE_serverReference"; break;
	case DRSUAPI_ATTRIBUTE_serverReferenceBL: val = "DRSUAPI_ATTRIBUTE_serverReferenceBL"; break;
	case DRSUAPI_ATTRIBUTE_initialAuthIncoming: val = "DRSUAPI_ATTRIBUTE_initialAuthIncoming"; break;
	case DRSUAPI_ATTRIBUTE_initialAuthOutgoing: val = "DRSUAPI_ATTRIBUTE_initialAuthOutgoing"; break;
	case DRSUAPI_ATTRIBUTE_wellKnownObjects: val = "DRSUAPI_ATTRIBUTE_wellKnownObjects"; break;
	case DRSUAPI_ATTRIBUTE_dNSHostName: val = "DRSUAPI_ATTRIBUTE_dNSHostName"; break;
	case DRSUAPI_ATTRIBUTE_isMemberOfPartialAttributeSet: val = "DRSUAPI_ATTRIBUTE_isMemberOfPartialAttributeSet"; break;
	case DRSUAPI_ATTRIBUTE_userPrincipalName: val = "DRSUAPI_ATTRIBUTE_userPrincipalName"; break;
	case DRSUAPI_ATTRIBUTE_groupType: val = "DRSUAPI_ATTRIBUTE_groupType"; break;
	case DRSUAPI_ATTRIBUTE_servicePrincipalName: val = "DRSUAPI_ATTRIBUTE_servicePrincipalName"; break;
	case DRSUAPI_ATTRIBUTE_objectCategory: val = "DRSUAPI_ATTRIBUTE_objectCategory"; break;
	case DRSUAPI_ATTRIBUTE_gPLink: val = "DRSUAPI_ATTRIBUTE_gPLink"; break;
	case DRSUAPI_ATTRIBUTE_msDS_Behavior_Version: val = "DRSUAPI_ATTRIBUTE_msDS_Behavior_Version"; break;
	case DRSUAPI_ATTRIBUTE_msDS_KeyVersionNumber: val = "DRSUAPI_ATTRIBUTE_msDS_KeyVersionNumber"; break;
	case DRSUAPI_ATTRIBUTE_msDS_HasDomainNCs: val = "DRSUAPI_ATTRIBUTE_msDS_HasDomainNCs"; break;
	case DRSUAPI_ATTRIBUTE_msDS_hasMasterNCs: val = "DRSUAPI_ATTRIBUTE_msDS_hasMasterNCs"; break;
	default: val = "UNKNOWN_ENUM_VALUE"; break;
	}
	return val;
}


/**
 * Loads dsdb_schema from ldb connection using remote prefixMap.
 * Schema will be loaded only if:
 *  - ldb has no attached schema
 *  - reload_schema is true
 *
 * This function is to be used in tests that use GetNCChanges() function
 */
bool drs_util_dsdb_schema_load_ldb(struct torture_context *tctx,
				   struct ldb_context *ldb,
				   const struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr,
				   bool reload_schema)
{
	int i, ret;
	WERROR werr;
	const char *err_msg;
	struct ldb_result *a_res;
	struct ldb_result *c_res;
	struct ldb_dn *schema_dn;
	struct dsdb_schema *ldap_schema;

	ldap_schema = dsdb_get_schema(ldb, NULL);
	if (ldap_schema && !reload_schema) {
		return true;
	}

	schema_dn = ldb_get_schema_basedn(ldb);
	torture_assert(tctx, schema_dn != NULL,
		       talloc_asprintf(tctx, "ldb_get_schema_basedn() failed: %s", ldb_errstring(ldb)));

	ldap_schema = dsdb_new_schema(ldb);
	torture_assert(tctx, ldap_schema != NULL, "dsdb_new_schema() failed!");

	werr = dsdb_load_prefixmap_from_drsuapi(ldap_schema, mapping_ctr);

	/*
	 * load the attribute definitions
	 */
	ret = ldb_search(ldb, ldap_schema, &a_res,
			 schema_dn, LDB_SCOPE_ONELEVEL, NULL,
			 "(objectClass=attributeSchema)");
	if (ret != LDB_SUCCESS) {
		err_msg = talloc_asprintf(tctx,
					  "failed to search attributeSchema objects: %s",
					  ldb_errstring(ldb));
		torture_fail(tctx, err_msg);
	}

	/*
	 * load the objectClass definitions
	 */
	ret = ldb_search(ldb, ldap_schema, &c_res,
			 schema_dn, LDB_SCOPE_ONELEVEL, NULL,
			 "(objectClass=classSchema)");
	if (ret != LDB_SUCCESS) {
		err_msg = talloc_asprintf(tctx,
					  "failed to search classSchema objects: %s",
					  ldb_errstring(ldb));
		torture_fail(tctx, err_msg);
	}

	/* Build schema */
	for (i=0; i < a_res->count; i++) {
		werr = dsdb_attribute_from_ldb(ldb, ldap_schema, a_res->msgs[i]);
		torture_assert_werr_ok(tctx, werr,
				       talloc_asprintf(tctx,
						       "dsdb_attribute_from_ldb() failed for: %s",
						       ldb_dn_get_linearized(a_res->msgs[i]->dn)));
	}

	for (i=0; i < c_res->count; i++) {
		werr = dsdb_class_from_ldb(ldap_schema, c_res->msgs[i]);
		torture_assert_werr_ok(tctx, werr,
				       talloc_asprintf(tctx,
						       "dsdb_class_from_ldb() failed for: %s",
						       ldb_dn_get_linearized(c_res->msgs[i]->dn)));
	}

	talloc_free(a_res);
	talloc_free(c_res);

	ret = dsdb_set_schema(ldb, ldap_schema);
	if (ret != LDB_SUCCESS) {
		torture_fail(tctx,
			     talloc_asprintf(tctx, "dsdb_set_schema() failed: %s", ldb_strerror(ret)));
	}

	return true;
}
