/*
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Bartlett 2012

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
#include "torture/smbtorture.h"
#include "dlz_minimal.h"
#include <talloc.h>
#include <ldb.h>
#include "lib/param/param.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "auth/session.h"
#include "auth/gensec/gensec.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/popt_common.h"

struct torture_context *tctx_static;

static void dlz_bind9_log_wrapper(int level, const char *fmt, ...)
{
	va_list ap;
	char *msg;
	va_start(ap, fmt);
	msg = talloc_vasprintf(NULL, fmt, ap);
	torture_comment(tctx_static, "%s\n", msg);
	TALLOC_FREE(msg);
	va_end(ap);
}

static bool test_dlz_bind9_version(struct torture_context *tctx)
{
	unsigned int flags = 0;
	torture_assert_int_equal(tctx, dlz_version(&flags),
				 DLZ_DLOPEN_VERSION, "got wrong DLZ version");
	return true;
}

static bool test_dlz_bind9_create(struct torture_context *tctx)
{
	void *dbdata;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		lpcfg_private_path(tctx, tctx->lp_ctx, "dns/sam.ldb"),
		NULL
	};
	tctx_static = tctx;
	torture_assert_int_equal(tctx, dlz_create("samba_dlz", 3, argv, &dbdata,
						  "log", dlz_bind9_log_wrapper, NULL), ISC_R_SUCCESS,
		"Failed to create samba_dlz");

	dlz_destroy(dbdata);

	return true;
}

static isc_result_t dlz_bind9_writeable_zone_hook(dns_view_t *view,
					   const char *zone_name)
{
	struct torture_context *tctx = talloc_get_type((void *)view, struct torture_context);
	struct ldb_context *samdb = samdb_connect_url(tctx, NULL, tctx->lp_ctx,
						      system_session(tctx->lp_ctx),
						      0, lpcfg_private_path(tctx, tctx->lp_ctx, "dns/sam.ldb"));
	struct ldb_message *msg;
	int ret;
	const char *attrs[] = {
		NULL
	};
	if (!samdb) {
		torture_fail(tctx, "Failed to connect to samdb");
		return ISC_R_FAILURE;
	}

	ret = dsdb_search_one(samdb, tctx, &msg, NULL,
			      LDB_SCOPE_SUBTREE, attrs, DSDB_SEARCH_SEARCH_ALL_PARTITIONS,
			      "(&(objectClass=dnsZone)(name=%s))", zone_name);
	if (ret != LDB_SUCCESS) {
		torture_fail(tctx, talloc_asprintf(tctx, "Failed to search for %s: %s", zone_name, ldb_errstring(samdb)));
		return ISC_R_FAILURE;
	}
	talloc_free(msg);

	return ISC_R_SUCCESS;
}

static bool test_dlz_bind9_configure(struct torture_context *tctx)
{
	void *dbdata;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		lpcfg_private_path(tctx, tctx->lp_ctx, "dns/sam.ldb"),
		NULL
	};
	tctx_static = tctx;
	torture_assert_int_equal(tctx, dlz_create("samba_dlz", 3, argv, &dbdata,
						  "log", dlz_bind9_log_wrapper,
						  "writeable_zone", dlz_bind9_writeable_zone_hook, NULL),
				 ISC_R_SUCCESS,
				 "Failed to create samba_dlz");

	torture_assert_int_equal(tctx, dlz_configure((void*)tctx, dbdata),
						     ISC_R_SUCCESS,
				 "Failed to configure samba_dlz");

	dlz_destroy(dbdata);

	return true;
}

/*
 * Test that a ticket obtained for the DNS service will be accepted on the Samba DLZ side
 *
 */
static bool test_dlz_bind9_gensec(struct torture_context *tctx, const char *mech)
{
	NTSTATUS status;

	struct gensec_security *gensec_client_context;

	DATA_BLOB client_to_server, server_to_client;

	void *dbdata;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		lpcfg_private_path(tctx, tctx->lp_ctx, "dns/sam.ldb"),
		NULL
	};
	tctx_static = tctx;
	torture_assert_int_equal(tctx, dlz_create("samba_dlz", 3, argv, &dbdata,
						  "log", dlz_bind9_log_wrapper,
						  "writeable_zone", dlz_bind9_writeable_zone_hook, NULL),
				 ISC_R_SUCCESS,
				 "Failed to create samba_dlz");

	torture_assert_int_equal(tctx, dlz_configure((void*)tctx, dbdata),
						     ISC_R_SUCCESS,
				 "Failed to configure samba_dlz");

	status = gensec_client_start(tctx, &gensec_client_context,
				     lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status, "gensec_client_start (client) failed");

	/*
	 * dlz_bind9 use the special dns/host.domain account
	 */
	status = gensec_set_target_hostname(gensec_client_context,
					    talloc_asprintf(tctx,
				"%s.%s",
				torture_setting_string(tctx, "host", NULL),
				lpcfg_dnsdomain(tctx->lp_ctx)));
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_target_hostname (client) failed");

	status = gensec_set_target_service(gensec_client_context, "dns");
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_target_service failed");

	status = gensec_set_credentials(gensec_client_context, cmdline_credentials);
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_credentials (client) failed");

	status = gensec_start_mech_by_sasl_name(gensec_client_context, mech);
	torture_assert_ntstatus_ok(tctx, status, "gensec_start_mech_by_sasl_name (client) failed");

	server_to_client = data_blob(NULL, 0);

	/* Do one step of the client-server update dance */
	status = gensec_update(gensec_client_context, tctx, server_to_client, &client_to_server);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {;
		torture_assert_ntstatus_ok(tctx, status, "gensec_update (client) failed");
	}

	torture_assert_int_equal(tctx, dlz_ssumatch(cli_credentials_get_username(cmdline_credentials),
						    lpcfg_dnsdomain(tctx->lp_ctx),
						    "127.0.0.1", "type", "key",
						    client_to_server.length,
						    client_to_server.data,
						    dbdata),
				 ISC_TRUE,
				 "Failed to check key for update rights samba_dlz");

	dlz_destroy(dbdata);

	return true;
}

static bool test_dlz_bind9_gssapi(struct torture_context *tctx)
{
	return test_dlz_bind9_gensec(tctx, "GSSAPI");
}

static bool test_dlz_bind9_spnego(struct torture_context *tctx)
{
	return test_dlz_bind9_gensec(tctx, "GSS-SPNEGO");
}

struct test_expected_record {
	const char *name;
	const char *type;
	const char *data;
	int ttl;
	bool printed;
};

struct test_expected_rr {
	struct torture_context *tctx;
	const char *query_name;
	size_t num_records;
	struct test_expected_record *records;
	size_t num_rr;
};

static bool dlz_bind9_putnamedrr_torture_hook(struct test_expected_rr *expected,
					      const char *name,
					      const char *type,
					      dns_ttl_t ttl,
					      const char *data)
{
	size_t i;

	torture_assert(expected->tctx, name != NULL,
		       talloc_asprintf(expected->tctx,
		       "Got unnamed record type[%s] data[%s]\n",
		       type, data));

	expected->num_rr++;
	torture_comment(expected->tctx, "%u: name[%s] type[%s] ttl[%u] data[%s]\n",
			(unsigned)expected->num_rr, name, type, (unsigned)ttl, data);

	for (i = 0; i < expected->num_records; i++) {
		if (expected->records[i].name != NULL) {
			if (strcmp(name, expected->records[i].name) != 0) {
				continue;
			}
		}

		if (strcmp(type, expected->records[i].type) != 0) {
			continue;
		}

		if (expected->records[i].data != NULL) {
			if (strcmp(data, expected->records[i].data) != 0) {
				continue;
			}
		}

		torture_assert_int_equal(expected->tctx, ttl,
					 expected->records[i].ttl,
					 talloc_asprintf(expected->tctx,
					 "TTL did not match expectations for type %s",
					 type));

		expected->records[i].printed = true;
	}

	return true;
}

static isc_result_t dlz_bind9_putrr_hook(dns_sdlzlookup_t *lookup,
					 const char *type,
					 dns_ttl_t ttl,
					 const char *data)
{
	struct test_expected_rr *expected =
		talloc_get_type_abort(lookup, struct test_expected_rr);
	bool ok;

	ok = dlz_bind9_putnamedrr_torture_hook(expected, expected->query_name,
					       type, ttl, data);
	if (!ok) {
		return ISC_R_FAILURE;
	}

	return ISC_R_SUCCESS;
}

static isc_result_t dlz_bind9_putnamedrr_hook(dns_sdlzallnodes_t *allnodes,
					      const char *name,
					      const char *type,
					      dns_ttl_t ttl,
					      const char *data)
{
	struct test_expected_rr *expected =
		talloc_get_type_abort(allnodes, struct test_expected_rr);
	bool ok;

	ok = dlz_bind9_putnamedrr_torture_hook(expected, name, type, ttl, data);
	if (!ok) {
		return ISC_R_FAILURE;
	}

	return ISC_R_SUCCESS;
}

/*
 * Tests some lookups
 */
static bool test_dlz_bind9_lookup(struct torture_context *tctx)
{
	size_t i;
	void *dbdata;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		lpcfg_private_path(tctx, tctx->lp_ctx, "dns/sam.ldb"),
		NULL
	};
	struct test_expected_rr *expected1 = NULL;
	struct test_expected_rr *expected2 = NULL;

	tctx_static = tctx;
	torture_assert_int_equal(tctx, dlz_create("samba_dlz", 3, argv, &dbdata,
						  "log", dlz_bind9_log_wrapper,
						  "writeable_zone", dlz_bind9_writeable_zone_hook,
						  "putrr", dlz_bind9_putrr_hook,
						  "putnamedrr", dlz_bind9_putnamedrr_hook,
						  NULL),
				 ISC_R_SUCCESS,
				 "Failed to create samba_dlz");

	torture_assert_int_equal(tctx, dlz_configure((void*)tctx, dbdata),
						     ISC_R_SUCCESS,
				 "Failed to configure samba_dlz");

	expected1 = talloc_zero(tctx, struct test_expected_rr);
	torture_assert(tctx, expected1 != NULL, "talloc failed");
	expected1->tctx = tctx;

	expected1->query_name = "@";

	expected1->num_records = 4;
	expected1->records = talloc_zero_array(expected1,
					       struct test_expected_record,
					       expected1->num_records);
	torture_assert(tctx, expected1->records != NULL, "talloc failed");

	expected1->records[0].name = expected1->query_name;
	expected1->records[0].type = "soa";
	expected1->records[0].ttl = 3600;
	expected1->records[0].data = talloc_asprintf(expected1->records,
				"%s.%s. hostmaster.%s. 1 900 600 86400 3600",
				torture_setting_string(tctx, "host", NULL),
				lpcfg_dnsdomain(tctx->lp_ctx),
				lpcfg_dnsdomain(tctx->lp_ctx));
	torture_assert(tctx, expected1->records[0].data != NULL, "talloc failed");

	expected1->records[1].name = expected1->query_name;
	expected1->records[1].type = "ns";
	expected1->records[1].ttl = 900;
	expected1->records[1].data = talloc_asprintf(expected1->records, "%s.%s.",
				torture_setting_string(tctx, "host", NULL),
				lpcfg_dnsdomain(tctx->lp_ctx));
	torture_assert(tctx, expected1->records[1].data != NULL, "talloc failed");

	expected1->records[2].name = expected1->query_name;
	expected1->records[2].type = "aaaa";
	expected1->records[2].ttl = 900;

	expected1->records[3].name = expected1->query_name;
	expected1->records[3].type = "a";
	expected1->records[3].ttl = 900;

	torture_assert_int_equal(tctx, dlz_lookup(lpcfg_dnsdomain(tctx->lp_ctx),
						  expected1->query_name, dbdata,
						  (dns_sdlzlookup_t *)expected1),
				 ISC_R_SUCCESS,
				 "Failed to lookup @");
	for (i = 0; i < expected1->num_records; i++) {
		torture_assert(tctx, expected1->records[i].printed,
			       talloc_asprintf(tctx,
			       "Failed to have putrr callback run for type %s",
			       expected1->records[i].type));
	}
	torture_assert_int_equal(tctx, expected1->num_rr,
				 expected1->num_records,
				 "Got too much data");

	expected2 = talloc_zero(tctx, struct test_expected_rr);
	torture_assert(tctx, expected2 != NULL, "talloc failed");
	expected2->tctx = tctx;

	expected2->query_name = torture_setting_string(tctx, "host", NULL);
	torture_assert(tctx, expected2->query_name != NULL, "unknown host");

	expected2->num_records = 2;
	expected2->records = talloc_zero_array(expected2,
					       struct test_expected_record,
					       expected2->num_records);
	torture_assert(tctx, expected2->records != NULL, "talloc failed");

	expected2->records[0].name = expected2->query_name;
	expected2->records[0].type = "aaaa";
	expected2->records[0].ttl = 900;

	expected2->records[1].name = expected2->query_name;
	expected2->records[1].type = "a";
	expected2->records[1].ttl = 900;

	torture_assert_int_equal(tctx, dlz_lookup(lpcfg_dnsdomain(tctx->lp_ctx),
						  expected2->query_name, dbdata,
						  (dns_sdlzlookup_t *)expected2),
				 ISC_R_SUCCESS,
				 "Failed to lookup hostname");
	for (i = 0; i < expected2->num_records; i++) {
		torture_assert(tctx, expected2->records[i].printed,
			       talloc_asprintf(tctx,
			       "Failed to have putrr callback run name[%s] for type %s",
			       expected2->records[i].name,
			       expected2->records[i].type));
	}
	torture_assert_int_equal(tctx, expected2->num_rr,
				 expected2->num_records,
				 "Got too much data");

	dlz_destroy(dbdata);

	return true;
}

/*
 * Test some zone dumps
 */
static bool test_dlz_bind9_zonedump(struct torture_context *tctx)
{
	size_t i;
	void *dbdata;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		lpcfg_private_path(tctx, tctx->lp_ctx, "dns/sam.ldb"),
		NULL
	};
	struct test_expected_rr *expected1 = NULL;

	tctx_static = tctx;
	torture_assert_int_equal(tctx, dlz_create("samba_dlz", 3, argv, &dbdata,
						  "log", dlz_bind9_log_wrapper,
						  "writeable_zone", dlz_bind9_writeable_zone_hook,
						  "putrr", dlz_bind9_putrr_hook,
						  "putnamedrr", dlz_bind9_putnamedrr_hook,
						  NULL),
				 ISC_R_SUCCESS,
				 "Failed to create samba_dlz");

	torture_assert_int_equal(tctx, dlz_configure((void*)tctx, dbdata),
						     ISC_R_SUCCESS,
				 "Failed to configure samba_dlz");

	expected1 = talloc_zero(tctx, struct test_expected_rr);
	torture_assert(tctx, expected1 != NULL, "talloc failed");
	expected1->tctx = tctx;

	expected1->num_records = 7;
	expected1->records = talloc_zero_array(expected1,
					       struct test_expected_record,
					       expected1->num_records);
	torture_assert(tctx, expected1->records != NULL, "talloc failed");

	expected1->records[0].name = talloc_asprintf(expected1->records,
				"%s.", lpcfg_dnsdomain(tctx->lp_ctx));
	expected1->records[0].type = "soa";
	expected1->records[0].ttl = 3600;
	expected1->records[0].data = talloc_asprintf(expected1->records,
				"%s.%s. hostmaster.%s. 1 900 600 86400 3600",
				torture_setting_string(tctx, "host", NULL),
				lpcfg_dnsdomain(tctx->lp_ctx),
				lpcfg_dnsdomain(tctx->lp_ctx));
	torture_assert(tctx, expected1->records[0].data != NULL, "talloc failed");

	expected1->records[1].name = talloc_asprintf(expected1->records,
				"%s.", lpcfg_dnsdomain(tctx->lp_ctx));
	expected1->records[1].type = "ns";
	expected1->records[1].ttl = 900;
	expected1->records[1].data = talloc_asprintf(expected1->records, "%s.%s.",
				torture_setting_string(tctx, "host", NULL),
				lpcfg_dnsdomain(tctx->lp_ctx));
	torture_assert(tctx, expected1->records[1].data != NULL, "talloc failed");

	expected1->records[2].name = talloc_asprintf(expected1->records,
				"%s.", lpcfg_dnsdomain(tctx->lp_ctx));
	expected1->records[2].type = "aaaa";
	expected1->records[2].ttl = 900;

	expected1->records[3].name = talloc_asprintf(expected1->records,
				"%s.", lpcfg_dnsdomain(tctx->lp_ctx));
	expected1->records[3].type = "a";
	expected1->records[3].ttl = 900;

	expected1->records[4].name = talloc_asprintf(expected1->records, "%s.%s.",
				torture_setting_string(tctx, "host", NULL),
				lpcfg_dnsdomain(tctx->lp_ctx));
	torture_assert(tctx, expected1->records[4].name != NULL, "unknown host");
	expected1->records[4].type = "aaaa";
	expected1->records[4].ttl = 900;

	expected1->records[5].name = talloc_asprintf(expected1->records, "%s.%s.",
				torture_setting_string(tctx, "host", NULL),
				lpcfg_dnsdomain(tctx->lp_ctx));
	torture_assert(tctx, expected1->records[5].name != NULL, "unknown host");
	expected1->records[5].type = "a";
	expected1->records[5].ttl = 900;

	/*
	 * We expect multiple srv records
	 */
	expected1->records[6].name = NULL;
	expected1->records[6].type = "srv";
	expected1->records[6].ttl = 900;

	torture_assert_int_equal(tctx, dlz_allnodes(lpcfg_dnsdomain(tctx->lp_ctx),
						    dbdata, (dns_sdlzallnodes_t *)expected1),
				 ISC_R_SUCCESS,
				 "Failed to configure samba_dlz");
	for (i = 0; i < expected1->num_records; i++) {
		torture_assert(tctx, expected1->records[i].printed,
			       talloc_asprintf(tctx,
			       "Failed to have putrr callback run name[%s] for type %s",
			       expected1->records[i].name,
			       expected1->records[i].type));
	}
	torture_assert_int_equal(tctx, expected1->num_rr, 24,
				 "Got wrong record count");

	dlz_destroy(dbdata);

	return true;
}

/*
 * Test some updates
 */
static bool test_dlz_bind9_update01(struct torture_context *tctx)
{
	NTSTATUS status;
	struct gensec_security *gensec_client_context;
	DATA_BLOB client_to_server, server_to_client;
	void *dbdata;
	void *version = NULL;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		lpcfg_private_path(tctx, tctx->lp_ctx, "dns/sam.ldb"),
		NULL
	};
	struct test_expected_rr *expected1 = NULL;
	char *name = NULL;
	char *data0 = NULL;
	char *data1 = NULL;
	char *data2 = NULL;
	bool ret = false;

	tctx_static = tctx;
	torture_assert_int_equal(tctx, dlz_create("samba_dlz", 3, argv, &dbdata,
						  "log", dlz_bind9_log_wrapper,
						  "writeable_zone", dlz_bind9_writeable_zone_hook,
						  "putrr", dlz_bind9_putrr_hook,
						  "putnamedrr", dlz_bind9_putnamedrr_hook,
						  NULL),
				 ISC_R_SUCCESS,
				 "Failed to create samba_dlz");

	torture_assert_int_equal(tctx, dlz_configure((void*)tctx, dbdata),
						     ISC_R_SUCCESS,
				 "Failed to configure samba_dlz");

	expected1 = talloc_zero(tctx, struct test_expected_rr);
	torture_assert(tctx, expected1 != NULL, "talloc failed");
	expected1->tctx = tctx;

	expected1->query_name = __func__;

	name = talloc_asprintf(expected1, "%s.%s",
				expected1->query_name,
				lpcfg_dnsdomain(tctx->lp_ctx));
	torture_assert(tctx, name != NULL, "talloc failed");

	expected1->num_records = 2;
	expected1->records = talloc_zero_array(expected1,
					       struct test_expected_record,
					       expected1->num_records);
	torture_assert(tctx, expected1->records != NULL, "talloc failed");

	expected1->records[0].name = expected1->query_name;
	expected1->records[0].type = "a";
	expected1->records[0].ttl = 3600;
	expected1->records[0].data = "127.1.2.3";
	expected1->records[0].printed = false;

	data0 = talloc_asprintf(expected1,
				"%s.\t" "%u\t" "%s\t" "%s\t" "%s",
				name,
				(unsigned)expected1->records[0].ttl,
				"in",
				expected1->records[0].type,
				expected1->records[0].data);
	torture_assert(tctx, data0 != NULL, "talloc failed");

	expected1->records[1].name = expected1->query_name;
	expected1->records[1].type = "a";
	expected1->records[1].ttl = 3600;
	expected1->records[1].data = "127.3.2.1";
	expected1->records[1].printed = false;

	data1 = talloc_asprintf(expected1,
				"%s.\t" "%u\t" "%s\t" "%s\t" "%s",
				name,
				(unsigned)expected1->records[1].ttl,
				"in",
				expected1->records[1].type,
				expected1->records[1].data);
	torture_assert(tctx, data1 != NULL, "talloc failed");

	data2 = talloc_asprintf(expected1,
				"%s.\t" "0\t" "in\t" "a\t" "127.3.3.3",
				name);
	torture_assert(tctx, data2 != NULL, "talloc failed");

	/*
	 * Prepare session info
	 */
	status = gensec_client_start(tctx, &gensec_client_context,
				     lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status, "gensec_client_start (client) failed");

	/*
	 * dlz_bind9 use the special dns/host.domain account
	 */
	status = gensec_set_target_hostname(gensec_client_context,
					    talloc_asprintf(tctx,
				"%s.%s",
				torture_setting_string(tctx, "host", NULL),
				lpcfg_dnsdomain(tctx->lp_ctx)));
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_target_hostname (client) failed");

	status = gensec_set_target_service(gensec_client_context, "dns");
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_target_service failed");

	status = gensec_set_credentials(gensec_client_context, cmdline_credentials);
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_credentials (client) failed");

	status = gensec_start_mech_by_sasl_name(gensec_client_context, "GSS-SPNEGO");
	torture_assert_ntstatus_ok(tctx, status, "gensec_start_mech_by_sasl_name (client) failed");

	server_to_client = data_blob(NULL, 0);

	/* Do one step of the client-server update dance */
	status = gensec_update(gensec_client_context, tctx, server_to_client, &client_to_server);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {;
		torture_assert_ntstatus_ok(tctx, status, "gensec_update (client) failed");
	}

	torture_assert_int_equal(tctx, dlz_ssumatch(cli_credentials_get_username(cmdline_credentials),
						    name,
						    "127.0.0.1",
						    expected1->records[0].type,
						    "key",
						    client_to_server.length,
						    client_to_server.data,
						    dbdata),
				 ISC_TRUE,
				 "Failed to check key for update rights samba_dlz");

	/*
	 * We test the following:
	 *
	 *  1. lookup the records => NOT_FOUND
	 *  2. delete all records => NOT_FOUND
	 *  3. delete 1st record => NOT_FOUND
	 *  4. create 1st record => SUCCESS
	 *  5. lookup the records => found 1st
	 *  6. create 2nd record => SUCCESS
	 *  7. lookup the records => found 1st and 2nd
	 *  8. delete unknown record => NOT_FOUND
	 *  9. lookup the records => found 1st and 2nd
	 * 10. delete 1st record => SUCCESS
	 * 11. lookup the records => found 2nd
	 * 12. delete 2nd record => SUCCESS
	 * 13. lookup the records => NOT_FOUND
	 * 14. create 1st record => SUCCESS
	 * 15. lookup the records => found 1st
	 * 16. create 2nd record => SUCCESS
	 * 17. lookup the records => found 1st and 2nd
	 * 18. update 1st record => SUCCESS
	 * 19. lookup the records => found 1st and 2nd
	 * 20. delete all unknown type records => NOT_FOUND
	 * 21. lookup the records => found 1st and 2nd
	 * 22. delete all records => SUCCESS
	 * 23. lookup the records => NOT_FOUND
	 */

	/* Step 1. */
	expected1->num_rr = 0;
	expected1->records[0].printed = false;
	expected1->records[1].printed = false;
	torture_assert_int_equal(tctx, dlz_lookup(lpcfg_dnsdomain(tctx->lp_ctx),
						  expected1->query_name, dbdata,
						  (dns_sdlzlookup_t *)expected1),
				 ISC_R_NOTFOUND,
				 "Found hostname");
	torture_assert_int_equal(tctx, expected1->num_rr, 0,
				 "Got wrong record count");

	/* Step 2. */
	torture_assert_int_equal(tctx, dlz_newversion(lpcfg_dnsdomain(tctx->lp_ctx),
						      dbdata, &version),
				 ISC_R_SUCCESS,
				 "Failed to start transaction");
	torture_assert_int_equal_goto(tctx,
			dlz_delrdataset(name,
					expected1->records[0].type,
					dbdata, version),
			ISC_R_NOTFOUND, ret, cancel_version,
			talloc_asprintf(tctx, "Deleted name[%s] type[%s]\n",
			name, expected1->records[0].type));
	dlz_closeversion(lpcfg_dnsdomain(tctx->lp_ctx), false, dbdata, &version);

	/* Step 3. */
	torture_assert_int_equal(tctx, dlz_newversion(lpcfg_dnsdomain(tctx->lp_ctx),
						      dbdata, &version),
				 ISC_R_SUCCESS,
				 "Failed to start transaction");
	torture_assert_int_equal_goto(tctx,
			dlz_subrdataset(name, data0, dbdata, version),
			ISC_R_NOTFOUND, ret, cancel_version,
			talloc_asprintf(tctx, "Deleted name[%s] data[%s]\n",
			name, data0));
	dlz_closeversion(lpcfg_dnsdomain(tctx->lp_ctx), false, dbdata, &version);

	/* Step 4. */
	torture_assert_int_equal(tctx, dlz_newversion(lpcfg_dnsdomain(tctx->lp_ctx),
						      dbdata, &version),
				 ISC_R_SUCCESS,
				 "Failed to start transaction");
	torture_assert_int_equal_goto(tctx,
			dlz_addrdataset(name, data0, dbdata, version),
			ISC_R_SUCCESS, ret, cancel_version,
			talloc_asprintf(tctx, "Failed to add name[%s] data[%s]\n",
			name, data0));
	dlz_closeversion(lpcfg_dnsdomain(tctx->lp_ctx), true, dbdata, &version);

	/* Step 5. */
	expected1->num_rr = 0;
	expected1->records[0].printed = false;
	expected1->records[1].printed = false;
	torture_assert_int_equal(tctx, dlz_lookup(lpcfg_dnsdomain(tctx->lp_ctx),
						  expected1->query_name, dbdata,
						  (dns_sdlzlookup_t *)expected1),
				 ISC_R_SUCCESS,
				 "Not found hostname");
	torture_assert(tctx, expected1->records[0].printed,
		       talloc_asprintf(tctx,
		       "Failed to have putrr callback run name[%s] for type %s",
		       expected1->records[0].name,
		       expected1->records[0].type));
	torture_assert_int_equal(tctx, expected1->num_rr, 1,
				 "Got wrong record count");

	/* Step 6. */
	torture_assert_int_equal(tctx, dlz_newversion(lpcfg_dnsdomain(tctx->lp_ctx),
						      dbdata, &version),
				 ISC_R_SUCCESS,
				 "Failed to start transaction");
	torture_assert_int_equal_goto(tctx,
			dlz_addrdataset(name, data1, dbdata, version),
			ISC_R_SUCCESS, ret, cancel_version,
			talloc_asprintf(tctx, "Failed to add name[%s] data[%s]\n",
			name, data1));
	dlz_closeversion(lpcfg_dnsdomain(tctx->lp_ctx), true, dbdata, &version);

	/* Step 7. */
	expected1->num_rr = 0;
	expected1->records[0].printed = false;
	expected1->records[1].printed = false;
	torture_assert_int_equal(tctx, dlz_lookup(lpcfg_dnsdomain(tctx->lp_ctx),
						  expected1->query_name, dbdata,
						  (dns_sdlzlookup_t *)expected1),
				 ISC_R_SUCCESS,
				 "Not found hostname");
	torture_assert(tctx, expected1->records[0].printed,
		       talloc_asprintf(tctx,
		       "Failed to have putrr callback run name[%s] for type %s",
		       expected1->records[0].name,
		       expected1->records[0].type));
	torture_assert(tctx, expected1->records[1].printed,
		       talloc_asprintf(tctx,
		       "Failed to have putrr callback run name[%s] for type %s",
		       expected1->records[1].name,
		       expected1->records[1].type));
	torture_assert_int_equal(tctx, expected1->num_rr, 2,
				 "Got wrong record count");

	/* Step 8. */
	torture_assert_int_equal(tctx, dlz_newversion(lpcfg_dnsdomain(tctx->lp_ctx),
						      dbdata, &version),
				 ISC_R_SUCCESS,
				 "Failed to start transaction");
	torture_assert_int_equal_goto(tctx,
			dlz_subrdataset(name, data2, dbdata, version),
			ISC_R_NOTFOUND, ret, cancel_version,
			talloc_asprintf(tctx, "Deleted name[%s] data[%s]\n",
			name, data2));
	dlz_closeversion(lpcfg_dnsdomain(tctx->lp_ctx), true, dbdata, &version);

	/* Step 9. */
	expected1->num_rr = 0;
	expected1->records[0].printed = false;
	expected1->records[1].printed = false;
	torture_assert_int_equal(tctx, dlz_lookup(lpcfg_dnsdomain(tctx->lp_ctx),
						  expected1->query_name, dbdata,
						  (dns_sdlzlookup_t *)expected1),
				 ISC_R_SUCCESS,
				 "Not found hostname");
	torture_assert(tctx, expected1->records[0].printed,
		       talloc_asprintf(tctx,
		       "Failed to have putrr callback run name[%s] for type %s",
		       expected1->records[0].name,
		       expected1->records[0].type));
	torture_assert(tctx, expected1->records[1].printed,
		       talloc_asprintf(tctx,
		       "Failed to have putrr callback run name[%s] for type %s",
		       expected1->records[1].name,
		       expected1->records[1].type));
	torture_assert_int_equal(tctx, expected1->num_rr, 2,
				 "Got wrong record count");

	/* Step 10. */
	torture_assert_int_equal(tctx, dlz_newversion(lpcfg_dnsdomain(tctx->lp_ctx),
						      dbdata, &version),
				 ISC_R_SUCCESS,
				 "Failed to start transaction");
	torture_assert_int_equal_goto(tctx,
			dlz_subrdataset(name, data0, dbdata, version),
			ISC_R_SUCCESS, ret, cancel_version,
			talloc_asprintf(tctx, "Failed to delete name[%s] data[%s]\n",
			name, data0));
	dlz_closeversion(lpcfg_dnsdomain(tctx->lp_ctx), true, dbdata, &version);

	/* Step 11. */
	expected1->num_rr = 0;
	expected1->records[0].printed = false;
	expected1->records[1].printed = false;
	torture_assert_int_equal(tctx, dlz_lookup(lpcfg_dnsdomain(tctx->lp_ctx),
						  expected1->query_name, dbdata,
						  (dns_sdlzlookup_t *)expected1),
				 ISC_R_SUCCESS,
				 "Not found hostname");
	torture_assert(tctx, expected1->records[1].printed,
		       talloc_asprintf(tctx,
		       "Failed to have putrr callback run name[%s] for type %s",
		       expected1->records[1].name,
		       expected1->records[1].type));
	torture_assert_int_equal(tctx, expected1->num_rr, 1,
				 "Got wrong record count");

	/* Step 12. */
	torture_assert_int_equal(tctx, dlz_newversion(lpcfg_dnsdomain(tctx->lp_ctx),
						      dbdata, &version),
				 ISC_R_SUCCESS,
				 "Failed to start transaction");
	torture_assert_int_equal_goto(tctx,
			dlz_subrdataset(name, data1, dbdata, version),
			ISC_R_SUCCESS, ret, cancel_version,
			talloc_asprintf(tctx, "Failed to delete name[%s] data[%s]\n",
			name, data1));
	dlz_closeversion(lpcfg_dnsdomain(tctx->lp_ctx), true, dbdata, &version);

	/* Step 13. */
	expected1->num_rr = 0;
	expected1->records[0].printed = false;
	expected1->records[1].printed = false;
	torture_assert_int_equal(tctx, dlz_lookup(lpcfg_dnsdomain(tctx->lp_ctx),
						  expected1->query_name, dbdata,
						  (dns_sdlzlookup_t *)expected1),
				 ISC_R_NOTFOUND,
				 "Found hostname");
	torture_assert_int_equal(tctx, expected1->num_rr, 0,
				 "Got wrong record count");

	/* Step 14. */
	torture_assert_int_equal(tctx, dlz_newversion(lpcfg_dnsdomain(tctx->lp_ctx),
						      dbdata, &version),
				 ISC_R_SUCCESS,
				 "Failed to start transaction");
	torture_assert_int_equal_goto(tctx,
			dlz_addrdataset(name, data0, dbdata, version),
			ISC_R_SUCCESS, ret, cancel_version,
			talloc_asprintf(tctx, "Failed to add name[%s] data[%s]\n",
			name, data0));
	dlz_closeversion(lpcfg_dnsdomain(tctx->lp_ctx), true, dbdata, &version);

	/* Step 15. */
	expected1->num_rr = 0;
	expected1->records[0].printed = false;
	expected1->records[1].printed = false;
	torture_assert_int_equal(tctx, dlz_lookup(lpcfg_dnsdomain(tctx->lp_ctx),
						  expected1->query_name, dbdata,
						  (dns_sdlzlookup_t *)expected1),
				 ISC_R_SUCCESS,
				 "Not found hostname");
	torture_assert(tctx, expected1->records[0].printed,
		       talloc_asprintf(tctx,
		       "Failed to have putrr callback run name[%s] for type %s",
		       expected1->records[0].name,
		       expected1->records[0].type));
	torture_assert_int_equal(tctx, expected1->num_rr, 1,
				 "Got wrong record count");

	/* Step 16. */
	torture_assert_int_equal(tctx, dlz_newversion(lpcfg_dnsdomain(tctx->lp_ctx),
						      dbdata, &version),
				 ISC_R_SUCCESS,
				 "Failed to start transaction");
	torture_assert_int_equal_goto(tctx,
			dlz_addrdataset(name, data1, dbdata, version),
			ISC_R_SUCCESS, ret, cancel_version,
			talloc_asprintf(tctx, "Failed to add name[%s] data[%s]\n",
			name, data1));
	dlz_closeversion(lpcfg_dnsdomain(tctx->lp_ctx), true, dbdata, &version);

	/* Step 17. */
	expected1->num_rr = 0;
	expected1->records[0].printed = false;
	expected1->records[1].printed = false;
	torture_assert_int_equal(tctx, dlz_lookup(lpcfg_dnsdomain(tctx->lp_ctx),
						  expected1->query_name, dbdata,
						  (dns_sdlzlookup_t *)expected1),
				 ISC_R_SUCCESS,
				 "Not found hostname");
	torture_assert(tctx, expected1->records[0].printed,
		       talloc_asprintf(tctx,
		       "Failed to have putrr callback run name[%s] for type %s",
		       expected1->records[0].name,
		       expected1->records[0].type));
	torture_assert(tctx, expected1->records[1].printed,
		       talloc_asprintf(tctx,
		       "Failed to have putrr callback run name[%s] for type %s",
		       expected1->records[1].name,
		       expected1->records[1].type));
	torture_assert_int_equal(tctx, expected1->num_rr, 2,
				 "Got wrong record count");

	/* Step 18. */
	torture_assert_int_equal(tctx, dlz_newversion(lpcfg_dnsdomain(tctx->lp_ctx),
						      dbdata, &version),
				 ISC_R_SUCCESS,
				 "Failed to start transaction");
	torture_assert_int_equal_goto(tctx,
			dlz_addrdataset(name, data0, dbdata, version),
			ISC_R_SUCCESS, ret, cancel_version,
			talloc_asprintf(tctx, "Failed to update name[%s] data[%s]\n",
			name, data0));
	dlz_closeversion(lpcfg_dnsdomain(tctx->lp_ctx), true, dbdata, &version);

	/* Step 19. */
	expected1->num_rr = 0;
	expected1->records[0].printed = false;
	expected1->records[1].printed = false;
	torture_assert_int_equal(tctx, dlz_lookup(lpcfg_dnsdomain(tctx->lp_ctx),
						  expected1->query_name, dbdata,
						  (dns_sdlzlookup_t *)expected1),
				 ISC_R_SUCCESS,
				 "Not found hostname");
	torture_assert(tctx, expected1->records[0].printed,
		       talloc_asprintf(tctx,
		       "Failed to have putrr callback run name[%s] for type %s",
		       expected1->records[0].name,
		       expected1->records[0].type));
	torture_assert(tctx, expected1->records[1].printed,
		       talloc_asprintf(tctx,
		       "Failed to have putrr callback run name[%s] for type %s",
		       expected1->records[1].name,
		       expected1->records[1].type));
	torture_assert_int_equal(tctx, expected1->num_rr, 2,
				 "Got wrong record count");

	/* Step 20. */
	torture_assert_int_equal(tctx, dlz_newversion(lpcfg_dnsdomain(tctx->lp_ctx),
						      dbdata, &version),
				 ISC_R_SUCCESS,
				 "Failed to start transaction");
	torture_assert_int_equal_goto(tctx,
			dlz_delrdataset(name, "txt", dbdata, version),
			ISC_R_FAILURE, ret, cancel_version,
			talloc_asprintf(tctx, "Deleted name[%s] type[%s]\n",
			name, "txt"));
	dlz_closeversion(lpcfg_dnsdomain(tctx->lp_ctx), false, dbdata, &version);

	/* Step 21. */
	expected1->num_rr = 0;
	expected1->records[0].printed = false;
	expected1->records[1].printed = false;
	torture_assert_int_equal(tctx, dlz_lookup(lpcfg_dnsdomain(tctx->lp_ctx),
						  expected1->query_name, dbdata,
						  (dns_sdlzlookup_t *)expected1),
				 ISC_R_SUCCESS,
				 "Not found hostname");
	torture_assert(tctx, expected1->records[0].printed,
		       talloc_asprintf(tctx,
		       "Failed to have putrr callback run name[%s] for type %s",
		       expected1->records[0].name,
		       expected1->records[0].type));
	torture_assert(tctx, expected1->records[1].printed,
		       talloc_asprintf(tctx,
		       "Failed to have putrr callback run name[%s] for type %s",
		       expected1->records[1].name,
		       expected1->records[1].type));
	torture_assert_int_equal(tctx, expected1->num_rr, 2,
				 "Got wrong record count");

	/* Step 22. */
	torture_assert_int_equal(tctx, dlz_newversion(lpcfg_dnsdomain(tctx->lp_ctx),
						      dbdata, &version),
				 ISC_R_SUCCESS,
				 "Failed to start transaction");
	torture_assert_int_equal_goto(tctx,
			dlz_delrdataset(name,
					expected1->records[0].type,
					dbdata, version),
			ISC_R_SUCCESS, ret, cancel_version,
			talloc_asprintf(tctx, "Failed to delete name[%s] type[%s]\n",
			name, expected1->records[0].type));
	dlz_closeversion(lpcfg_dnsdomain(tctx->lp_ctx), true, dbdata, &version);

	/* Step 23. */
	expected1->num_rr = 0;
	expected1->records[0].printed = false;
	expected1->records[1].printed = false;
	torture_assert_int_equal(tctx, dlz_lookup(lpcfg_dnsdomain(tctx->lp_ctx),
						  expected1->query_name, dbdata,
						  (dns_sdlzlookup_t *)expected1),
				 ISC_R_NOTFOUND,
				 "Found hostname");
	torture_assert_int_equal(tctx, expected1->num_rr, 0,
				 "Got wrong record count");

	dlz_destroy(dbdata);

	return true;

cancel_version:
	dlz_closeversion(lpcfg_dnsdomain(tctx->lp_ctx), false, dbdata, &version);
	return ret;
}

static struct torture_suite *dlz_bind9_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "dlz_bind9");

	suite->description = talloc_strdup(suite,
	                                   "Tests for the BIND 9 DLZ module");
	torture_suite_add_simple_test(suite, "version", test_dlz_bind9_version);
	torture_suite_add_simple_test(suite, "create", test_dlz_bind9_create);
	torture_suite_add_simple_test(suite, "configure", test_dlz_bind9_configure);
	torture_suite_add_simple_test(suite, "gssapi", test_dlz_bind9_gssapi);
	torture_suite_add_simple_test(suite, "spnego", test_dlz_bind9_spnego);
	torture_suite_add_simple_test(suite, "lookup", test_dlz_bind9_lookup);
	torture_suite_add_simple_test(suite, "zonedump", test_dlz_bind9_zonedump);
	torture_suite_add_simple_test(suite, "update01", test_dlz_bind9_update01);
	return suite;
}

/**
 * DNS torture module initialization
 */
NTSTATUS torture_bind_dns_init(void);
NTSTATUS torture_bind_dns_init(void)
{
	struct torture_suite *suite;
	TALLOC_CTX *mem_ctx = talloc_autofree_context();

	/* register DNS related test cases */
	suite = dlz_bind9_suite(mem_ctx);
	if (!suite) return NT_STATUS_NO_MEMORY;
	torture_register_suite(suite);

	return NT_STATUS_OK;
}
