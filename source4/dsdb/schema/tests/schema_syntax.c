/* 
   Unix SMB/CIFS implementation.

   Test DSDB syntax functions

   Copyright (C) Andrew Bartlet <abartlet@samba.org> 2008
   
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
#include "lib/events/events.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/ldb-samba/ldif_handlers.h"
#include "ldb_wrap.h"
#include "dsdb/samdb/samdb.h"
#include "param/param.h"
#include "torture/smbtorture.h"
#include "torture/local/proto.h"
#include "param/provision.h"


DATA_BLOB hexstr_to_data_blob(TALLOC_CTX *mem_ctx, const char *string) 
{
	DATA_BLOB binary = data_blob_talloc(mem_ctx, NULL, strlen(string)/2);
	binary.length = strhex_to_str((char *)binary.data, binary.length, string, strlen(string));
	return binary;
}

static bool torture_test_syntax(struct torture_context *torture, 
				const char *oid,
				const char *attr_string, 
				const char *ldb_str,
				const char *drs_str)
{
	TALLOC_CTX *tmp_ctx = talloc_new(torture);
	DATA_BLOB drs_binary = hexstr_to_data_blob(tmp_ctx, drs_str);
	DATA_BLOB ldb_blob = data_blob_string_const(ldb_str);
	struct drsuapi_DsReplicaAttribute drs, drs2;
	struct drsuapi_DsAttributeValue val;
	const struct dsdb_syntax *syntax;
	const struct dsdb_schema *schema;
	const struct dsdb_attribute *attr;
	struct ldb_context *ldb;
	struct ldb_message_element el;

	drs.value_ctr.num_values = 1;
	drs.value_ctr.values = &val;
	val.blob = &drs_binary;

	torture_assert(torture, ldb = provision_get_schema(tmp_ctx, torture->lp_ctx), "Failed to load schema from disk");
	torture_assert(torture, schema = dsdb_get_schema(ldb), "Failed to fetch schema");
	torture_assert(torture, syntax = find_syntax_map_by_standard_oid(oid), "Failed to find syntax handler");
	torture_assert(torture, attr = dsdb_attribute_by_lDAPDisplayName(schema, attr_string), "Failed to find attribute handler");
	torture_assert_str_equal(torture, syntax->name, attr->syntax->name, "Syntax from schema not as expected");
	

	torture_assert_werr_ok(torture, syntax->drsuapi_to_ldb(ldb, schema, attr, &drs, tmp_ctx, &el), "Failed to convert from DRS to ldb format");
	
	torture_assert_data_blob_equal(torture, el.values[0], ldb_blob, "Incorrect conversion from DRS to ldb format");

	torture_assert_werr_ok(torture, syntax->ldb_to_drsuapi(ldb, schema, attr, &el, tmp_ctx, &drs2), "Failed to convert from ldb to DRS format");
	
	torture_assert(torture, drs2.value_ctr.values[0].blob, "No blob returned from conversion");
	torture_assert_data_blob_equal(torture, *drs2.value_ctr.values[0].blob, drs_binary, "Incorrect conversion from ldb to DRS format");
	return true;
}

static bool torture_dsdb_drs_DN_BINARY(struct torture_context *torture) 
{
	const char *ldb_str = "B:32:A9D1CA15768811D1ADED00C04FD8D5CD:<GUID=23e75535-240b-447b-bdf0-ee0ab80a9116>;CN=Users,DC=ad,DC=naomi,DC=abartlet,DC=net";
	const char *drs_str = "8E000000000000003555E7230B247B44BDF0EE0AB80A9116000000000000000000000000000000000000000000000000000000002A00000043004E003D00550073006500720073002C00440043003D00610064002C00440043003D006E0061006F006D0069002C00440043003D00610062006100720074006C00650074002C00440043003D006E00650074000000000014000000A9D1CA15768811D1ADED00C04FD8D5CD";
	return torture_test_syntax(torture, DSDB_SYNTAX_BINARY_DN, "wellKnownObjects", ldb_str, drs_str);
}

static bool torture_dsdb_drs_DN(struct torture_context *torture) 
{
	const char *ldb_str = "<GUID=fbee08fd-6f75-4bd4-af3f-e4f063a6379e>;OU=Domain Controllers,DC=ad,DC=naomi,DC=abartlet,DC=net";
	const char *drs_str = "A800000000000000FD08EEFB756FD44BAF3FE4F063A6379E00000000000000000000000000000000000000000000000000000000370000004F0055003D0044006F006D00610069006E00200043006F006E00740072006F006C006C006500720073002C00440043003D00610064002C00440043003D006E0061006F006D0069002C00440043003D00610062006100720074006C00650074002C00440043003D006E00650074000000";
	return torture_test_syntax(torture, LDB_SYNTAX_DN, "lastKnownParent", ldb_str, drs_str);
}

static bool torture_dsdb_drs_INT32(struct torture_context *torture) 
{
	const char *ldb_str = "532480";
	const char *drs_str = "00200800";
	return torture_test_syntax(torture, LDB_SYNTAX_INTEGER, "userAccountControl", ldb_str, drs_str);
}

static bool torture_dsdb_drs_INT64(struct torture_context *torture) 
{
	const char *ldb_str = "129022979538281250";
	const char *drs_str = "22E33D5FB761CA01";
	return torture_test_syntax(torture, "1.2.840.113556.1.4.906", "pwdLastSet", ldb_str, drs_str);
}

static bool torture_dsdb_drs_NTTIME(struct torture_context *torture) 
{
	const char *ldb_str = "20091109003446.0Z";
	const char *drs_str = "A6F4070103000000";
	return torture_test_syntax(torture, "1.3.6.1.4.1.1466.115.121.1.24", "whenCreated", ldb_str, drs_str);
}

static bool torture_dsdb_drs_BOOL(struct torture_context *torture) 
{
	const char *ldb_str = "TRUE";
	const char *drs_str = "01000000";
	return torture_test_syntax(torture, LDB_SYNTAX_BOOLEAN, "isDeleted", ldb_str, drs_str);
}

static bool torture_dsdb_drs_UNICODE(struct torture_context *torture) 
{
	const char *ldb_str = "primaryTelexNumber,Numéro de télex";
	const char *drs_str = "7000720069006D00610072007900540065006C00650078004E0075006D006200650072002C004E0075006D00E90072006F0020006400650020007400E9006C0065007800";
	return torture_test_syntax(torture, LDB_SYNTAX_DIRECTORY_STRING, "attributeDisplayNames", ldb_str, drs_str);
}

struct torture_suite *torture_dsdb_syntax(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "DSDB-SYNTAX");

	if (suite == NULL) {
		return NULL;
	}

	torture_suite_add_simple_test(suite, "DN-BINARY", torture_dsdb_drs_DN_BINARY);
	torture_suite_add_simple_test(suite, "DN", torture_dsdb_drs_DN);
	torture_suite_add_simple_test(suite, "INT32", torture_dsdb_drs_INT32);
	torture_suite_add_simple_test(suite, "INT64", torture_dsdb_drs_INT64);
	torture_suite_add_simple_test(suite, "NTTIME", torture_dsdb_drs_NTTIME);
	torture_suite_add_simple_test(suite, "BOOL", torture_dsdb_drs_BOOL);
	torture_suite_add_simple_test(suite, "UNICODE", torture_dsdb_drs_UNICODE);

	suite->description = talloc_strdup(suite, "DSDB syntax tests");

	return suite;
}
