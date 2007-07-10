/* 
   Unix SMB/CIFS mplementation.
   LDAP replUpToDateVector tests
   
   Copyright (C) Stefan Metzmacher 2007
   
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
#include "libcli/ldap/ldap_client.h"
#include "lib/cmdline/popt_common.h"
#include "db_wrap.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "dsdb/samdb/samdb.h"
#include "lib/util/dlinklist.h"

#include "torture/torture.h"
#include "torture/ldap/proto.h"

#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"

static bool test_check_uptodatevector(struct torture_context *torture,
				      struct ldb_context *ldb,
				      struct ldb_dn *partition_dn)
{
	bool ok = true;
	uint32_t i;
	int ret;
	NTSTATUS status;
	struct ldb_result *r;
	const struct ldb_val *utdv_val1;
	struct replUpToDateVectorBlob utdv1;
	static const char *attrs[] = {
		"uSNChanged",
		"replUpToDateVector",
		"description",
		NULL
	};

	torture_comment(torture, "Check replUpToDateVector on partition[%s]\n",
				 ldb_dn_get_linearized(partition_dn));

	ret = ldb_search(ldb, partition_dn, LDB_SCOPE_BASE, 
			 "(objectClass=*)", attrs, &r);
	if (ret != LDB_SUCCESS) {
		return false;
	} else if (r->count != 1) {
		talloc_free(r);
		return false;
	}
	talloc_steal(torture, r);

	ZERO_STRUCT(utdv1);
	utdv_val1 = ldb_msg_find_ldb_val(r->msgs[0], "replUpToDateVector");
	if (utdv_val1) {
		status = ndr_pull_struct_blob_all(utdv_val1, torture, &utdv1,
						 (ndr_pull_flags_fn_t)ndr_pull_replUpToDateVectorBlob);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	for (i=0; i < 2; i++) {
		const struct ldb_val *utdv_val;
		struct replUpToDateVectorBlob utdv;
		struct ldb_message *msg;
		char *description;
		uint32_t j;
		bool no_match = false;

		/* make a 'modify' msg, and only for serverReference */
		msg = ldb_msg_new(torture);
		if (!msg) return false;
		msg->dn = partition_dn;

		description = talloc_asprintf(msg, "torture replUpToDateVector[%u]", i);
		if (!description) return false;

		ret = ldb_msg_add_string(msg, "description", description);
		if (ret != 0) return false;

		for (j=0;j<msg->num_elements;j++) {
			msg->elements[j].flags = LDB_FLAG_MOD_REPLACE;
		}

		ret = ldb_modify(ldb, msg);
		if (ret != LDB_SUCCESS) return false;

		ret = ldb_search(ldb, partition_dn, LDB_SCOPE_BASE, 
				 "(objectClass=*)", attrs, &r);
		if (ret != LDB_SUCCESS) {
			return false;
		} else if (r->count != 1) {
			talloc_free(r);
			return false;
		}
		talloc_steal(msg, r);

		ZERO_STRUCT(utdv);
		utdv_val = ldb_msg_find_ldb_val(r->msgs[0], "replUpToDateVector");
		if (utdv_val) {
			status = ndr_pull_struct_blob_all(utdv_val, torture, &utdv,
							 (ndr_pull_flags_fn_t)ndr_pull_replUpToDateVectorBlob);
			if (!NT_STATUS_IS_OK(status)) {
				return false;
			}
		}

		if (!utdv_val1 && utdv_val) {
			no_match = true;
		} else if (utdv_val1 && !utdv_val) {
			no_match = true;
		} else if (utdv_val1->length != utdv_val->length) {
			no_match = true;
		} else if (utdv_val1->length && memcmp(utdv_val1->data, utdv_val->data, utdv_val->length) != 0) {
			no_match = true;
		}

		torture_comment(torture, "[%u]: uSNChanged[%llu] description[%s] replUpToDateVector[%s]\n", i,
					samdb_result_uint64(r->msgs[0], "uSNChanged", 0),
					samdb_result_string(r->msgs[0], "description", NULL),
					(no_match ? "changed!: not ok" : "not changed: ok"));

		if (no_match) {
			NDR_PRINT_DEBUG(replUpToDateVectorBlob, &utdv1);
			NDR_PRINT_DEBUG(replUpToDateVectorBlob, &utdv);
			ok = false;
		}

		talloc_free(msg);
	}

	return ok;
}

BOOL torture_ldap_uptodatevector(struct torture_context *torture)
{
	struct ldb_context *ldb;
	BOOL ret = True;
	const char *host = torture_setting_string(torture, "host", NULL);
	char *url;

	url = talloc_asprintf(torture, "ldap://%s/", host);
	if (!url) goto failed;

	ldb = ldb_wrap_connect(torture, url,
			       NULL,
			       cmdline_credentials,
			       0, NULL);
	if (!ldb) goto failed;

	ret &= test_check_uptodatevector(torture, ldb, samdb_base_dn(ldb));
	ret &= test_check_uptodatevector(torture, ldb, samdb_config_dn(ldb));
	ret &= test_check_uptodatevector(torture, ldb, samdb_schema_dn(ldb));

	return ret;
failed:
	return False;
}
