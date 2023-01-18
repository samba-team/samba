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
#include "system/network.h"
#include "dns_server/dlz_minimal.h"
#include <talloc.h>
#include <ldb.h>
#include "lib/param/param.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "auth/session.h"
#include "auth/gensec/gensec.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/cmdline.h"
#include "system/network.h"
#include "dns_server/dnsserver_common.h"
#include "librpc/gen_ndr/ndr_dnsserver.h"
#include "librpc/gen_ndr/ndr_dnsserver_c.h"
#include "torture/rpc/torture_rpc.h"
#include "librpc/gen_ndr/ndr_dnsp.h"

#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_proto.h"

/* Tests that configure multiple DLZs will use this. Increase to add stress. */
#define NUM_DLZS_TO_CONFIGURE 4

struct torture_context *tctx_static;

static void dlz_bind9_log_wrapper(int level, const char *fmt, ...)
				  PRINTF_ATTRIBUTE(2,3);

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

static char *dlz_bind9_binddns_dir(struct torture_context *tctx,
				   const char *file)
{
	return talloc_asprintf(tctx,
			       "ldb://%s/%s",
			       lpcfg_binddns_dir(tctx->lp_ctx),
			       file);
}

static bool test_dlz_bind9_create(struct torture_context *tctx)
{
	void *dbdata;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		dlz_bind9_binddns_dir(tctx, "dns/sam.ldb"),
		NULL
	};
	tctx_static = tctx;
	torture_assert_int_equal(tctx, dlz_create("samba_dlz", 3, argv, &dbdata,
						  "log", dlz_bind9_log_wrapper, NULL), ISC_R_SUCCESS,
		"Failed to create samba_dlz");

	dlz_destroy(dbdata);

	return true;
}

static bool calls_zone_hook = false;

static isc_result_t dlz_bind9_writeable_zone_hook(dns_view_t *view,
						  dns_dlzdb_t *dlzdb,
						  const char *zone_name)
{
	struct torture_context *tctx = talloc_get_type((void *)view, struct torture_context);
	struct ldb_context *samdb = NULL;
	char *errstring = NULL;
	int ret = samdb_connect_url(
			tctx,
			NULL,
			tctx->lp_ctx,
			system_session(tctx->lp_ctx),
			0,
			dlz_bind9_binddns_dir(tctx, "dns/sam.ldb"),
			NULL,
			&samdb,
			&errstring);
	struct ldb_message *msg;
	const char *attrs[] = {
		NULL
	};
	if (ret != LDB_SUCCESS) {
		torture_comment(tctx, "Failed to connect to samdb");
		return ISC_R_FAILURE;
	}

	ret = dsdb_search_one(samdb, tctx, &msg, NULL,
			      LDB_SCOPE_SUBTREE, attrs, DSDB_SEARCH_SEARCH_ALL_PARTITIONS,
			      "(&(objectClass=dnsZone)(name=%s))", zone_name);
	if (ret != LDB_SUCCESS) {
		torture_comment(tctx,
				"Failed to search for %s: %s",
				zone_name,
				ldb_errstring(samdb));
		return ISC_R_FAILURE;
	}
	talloc_free(msg);

	calls_zone_hook = true;

	return ISC_R_SUCCESS;
}

static bool test_dlz_bind9_configure(struct torture_context *tctx)
{
	void *dbdata = NULL;
	dns_dlzdb_t *dlzdb = NULL;
	int ret;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		dlz_bind9_binddns_dir(tctx, "dns/sam.ldb"),
		NULL
	};
	tctx_static = tctx;
	ret = dlz_create("samba_dlz", 3, argv, &dbdata,
			 "log", dlz_bind9_log_wrapper,
			 "writeable_zone", dlz_bind9_writeable_zone_hook,
			 NULL);
	torture_assert_int_equal(tctx,
				 ret,
				 ISC_R_SUCCESS,
				 "Failed to create samba_dlz");

	calls_zone_hook = false;
	torture_assert_int_equal(tctx, dlz_configure((void*)tctx,
						     dlzdb,
						     dbdata),
						     ISC_R_SUCCESS,
				 "Failed to configure samba_dlz");

	dlz_destroy(dbdata);

	torture_assert_int_equal(tctx, calls_zone_hook, 1, "Hasn't called zone hook");

	return true;
}

static bool test_dlz_bind9_multiple_configure(struct torture_context *tctx)
{
	int i;
	for(i = 0; i < NUM_DLZS_TO_CONFIGURE; i++){
		test_dlz_bind9_configure(tctx);
	}
	return true;
}

static bool configure_multiple_dlzs(struct torture_context *tctx,
				    void **dbdata, int count)
{
	int i, res;
	dns_dlzdb_t *dlzdb = NULL;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		dlz_bind9_binddns_dir(tctx, "dns/sam.ldb"),
		NULL
	};

	tctx_static = tctx;
	for(i = 0; i < count; i++){
		res = dlz_create("samba_dlz", 3, argv, &(dbdata[i]),
				 "log", dlz_bind9_log_wrapper,
				 "writeable_zone",
				 dlz_bind9_writeable_zone_hook, NULL);
		torture_assert_int_equal(tctx, res, ISC_R_SUCCESS,
					 "Failed to create samba_dlz");

		res = dlz_configure((void*)tctx, dlzdb, dbdata[i]);
		torture_assert_int_equal(tctx, res, ISC_R_SUCCESS,
					 "Failed to configure samba_dlz");
	}

	return true;
}

static bool test_dlz_bind9_destroy_oldest_first(struct torture_context *tctx)
{
	void *dbdata[NUM_DLZS_TO_CONFIGURE];
	int i;
	bool ret = configure_multiple_dlzs(tctx,
					   dbdata,
					   NUM_DLZS_TO_CONFIGURE);
	if (ret == false) {
		/* failure: has already been printed */
		return false;
	}

	/* Reload faults are reported to happen on the first destroy */
	dlz_destroy(dbdata[0]);

	for(i = 1; i < NUM_DLZS_TO_CONFIGURE; i++){
		dlz_destroy(dbdata[i]);
	}

	return true;
}

static bool test_dlz_bind9_destroy_newest_first(struct torture_context *tctx)
{
	void *dbdata[NUM_DLZS_TO_CONFIGURE];
	int i;
	bool ret = configure_multiple_dlzs(tctx,
					   dbdata,
					   NUM_DLZS_TO_CONFIGURE);
	if (ret == false) {
		/* failure: has already been printed */
		return false;
	}

	for(i = NUM_DLZS_TO_CONFIGURE - 1; i >= 0; i--) {
		dlz_destroy(dbdata[i]);
	}

	return true;
}

/*
 * Test that a ticket obtained for the DNS service will be accepted on the Samba DLZ side
 *
 */
static bool test_dlz_bind9_gensec(struct torture_context *tctx, const char *mech)
{
	NTSTATUS status;
	dns_dlzdb_t *dlzdb = NULL;

	struct gensec_security *gensec_client_context;

	DATA_BLOB client_to_server, server_to_client;

	void *dbdata;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		dlz_bind9_binddns_dir(tctx, "dns/sam.ldb"),
		NULL
	};
	tctx_static = tctx;
	torture_assert_int_equal(tctx, dlz_create("samba_dlz", 3, argv, &dbdata,
						  "log", dlz_bind9_log_wrapper,
						  "writeable_zone", dlz_bind9_writeable_zone_hook, NULL),
				 ISC_R_SUCCESS,
				 "Failed to create samba_dlz");

	torture_assert_int_equal(tctx, dlz_configure((void*)tctx,
						     dlzdb, dbdata),
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

	status = gensec_set_credentials(gensec_client_context,
			samba_cmdline_get_creds());
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_credentials (client) failed");

	status = gensec_start_mech_by_sasl_name(gensec_client_context, mech);
	torture_assert_ntstatus_ok(tctx, status, "gensec_start_mech_by_sasl_name (client) failed");

	server_to_client = data_blob(NULL, 0);

	/* Do one step of the client-server update dance */
	status = gensec_update(gensec_client_context, tctx, server_to_client, &client_to_server);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {;
		torture_assert_ntstatus_ok(tctx, status, "gensec_update (client) failed");
	}

	torture_assert_int_equal(tctx, dlz_ssumatch(
					cli_credentials_get_username(
						samba_cmdline_get_creds()),
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
	const char *rdata;
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
			/*
			 * For most types the data will have been reformatted
			 * or normalised, so we need to do approximately the
			 * same to compare.
			 */
			const char *data2 = expected->records[i].data;
			if (strcmp(type, "aaaa") == 0) {
				struct in6_addr adr1;
				struct in6_addr adr2;
				int ret;
				ret = inet_pton(AF_INET6, data, &adr1);
				if (ret != 1) {
					continue;
				}
				ret = inet_pton(AF_INET6, data2, &adr2);
				if (ret != 1) {
					continue;
				}
				if (memcmp(&adr1, &adr2, sizeof(adr1)) != 0) {
					continue;
				}
			} else if (strcmp(type, "cname") == 0 ||
				 strcmp(type, "ptr") == 0   ||
				 strcmp(type, "ns") == 0) {
				if (!samba_dns_name_equal(data, data2)) {
					continue;
				}
			} else if (strcmp(type, "mx") == 0) {
				/*
				 * samba_dns_name_equal works for MX records
				 * because the space in "10 example.com." is
				 * theoretically OK as a DNS character. And we
				 * need it because dlz will add the trailing
				 * dot.
				 */
				if (!samba_dns_name_equal(data, data2)) {
					continue;
				}
			} else if (strcmp(data, data2) != 0) {
				/* default, works for A records */
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

/*
 * Lookups in these tests end up coming round to run this function.
 */
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
	void *dbdata = NULL;
	dns_clientinfomethods_t *methods = NULL;
	dns_clientinfo_t *clientinfo = NULL;
	dns_dlzdb_t *dlzdb = NULL;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		dlz_bind9_binddns_dir(tctx, "dns/sam.ldb"),
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

	torture_assert_int_equal(tctx,
				 dlz_configure((void*)tctx, dlzdb, dbdata),
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
						  (dns_sdlzlookup_t *)expected1,
						  methods, clientinfo),
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
						  (dns_sdlzlookup_t *)expected2,
						  methods, clientinfo),
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
	void *dbdata = NULL;
	dns_dlzdb_t *dlzdb = NULL;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		dlz_bind9_binddns_dir(tctx, "dns/sam.ldb"),
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

	torture_assert_int_equal(tctx, dlz_configure((void*)tctx, dlzdb, dbdata),
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
	void *dbdata = NULL;
	dns_dlzdb_t *dlzdb = NULL;
	void *version = NULL;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		dlz_bind9_binddns_dir(tctx, "dns/sam.ldb"),
		NULL
	};
	struct test_expected_rr *expected1 = NULL;
	char *name = NULL;
	char *data0 = NULL;
	char *data1 = NULL;
	char *data2 = NULL;
	bool ret = false;
	dns_clientinfomethods_t *methods = NULL;
	dns_clientinfo_t *clientinfo = NULL;

	tctx_static = tctx;
	torture_assert_int_equal(tctx, dlz_create("samba_dlz", 3, argv, &dbdata,
						  "log", dlz_bind9_log_wrapper,
						  "writeable_zone", dlz_bind9_writeable_zone_hook,
						  "putrr", dlz_bind9_putrr_hook,
						  "putnamedrr", dlz_bind9_putnamedrr_hook,
						  NULL),
				 ISC_R_SUCCESS,
				 "Failed to create samba_dlz");

	torture_assert_int_equal(tctx, dlz_configure((void*)tctx, dlzdb, dbdata),
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

	status = gensec_set_credentials(gensec_client_context,
			samba_cmdline_get_creds());
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_credentials (client) failed");

	status = gensec_start_mech_by_sasl_name(gensec_client_context, "GSS-SPNEGO");
	torture_assert_ntstatus_ok(tctx, status, "gensec_start_mech_by_sasl_name (client) failed");

	server_to_client = data_blob(NULL, 0);

	/* Do one step of the client-server update dance */
	status = gensec_update(gensec_client_context, tctx, server_to_client, &client_to_server);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {;
		torture_assert_ntstatus_ok(tctx, status, "gensec_update (client) failed");
	}

	torture_assert_int_equal(tctx, dlz_ssumatch(
				cli_credentials_get_username(
					samba_cmdline_get_creds()),
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
						  (dns_sdlzlookup_t *)expected1,
						  methods, clientinfo),
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
						  (dns_sdlzlookup_t *)expected1,
						  methods, clientinfo),
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
						  (dns_sdlzlookup_t *)expected1,
						  methods, clientinfo),
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
						  (dns_sdlzlookup_t *)expected1,
						  methods, clientinfo),
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
						  (dns_sdlzlookup_t *)expected1,
						  methods, clientinfo),
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
						  (dns_sdlzlookup_t *)expected1,
						  methods, clientinfo),
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
						  (dns_sdlzlookup_t *)expected1,
						  methods, clientinfo),
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
						  (dns_sdlzlookup_t *)expected1,
						  methods, clientinfo),
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
						  (dns_sdlzlookup_t *)expected1,
						  methods, clientinfo),
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
						  (dns_sdlzlookup_t *)expected1,
						  methods, clientinfo),
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
						  (dns_sdlzlookup_t *)expected1,
						  methods, clientinfo),
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

/*
 * Test zone transfer requests restrictions
 *
 * 1: test that zone transfer is denied by default
 * 2: with an authorized list of IPs set in smb.conf, test that zone transfer
 *    is accepted only for selected IPs.
 */
static bool test_dlz_bind9_allowzonexfr(struct torture_context *tctx)
{
	void *dbdata;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		dlz_bind9_binddns_dir(tctx, "dns/sam.ldb"),
		NULL
	};
	isc_result_t ret;
	dns_dlzdb_t *dlzdb = NULL;
	bool ok;

	tctx_static = tctx;
	torture_assert_int_equal(tctx, dlz_create("samba_dlz", 3, argv, &dbdata,
						  "log", dlz_bind9_log_wrapper,
						  "writeable_zone", dlz_bind9_writeable_zone_hook,
						  "putrr", dlz_bind9_putrr_hook,
						  "putnamedrr", dlz_bind9_putnamedrr_hook,
						  NULL),
				 ISC_R_SUCCESS,
				 "Failed to create samba_dlz");

	torture_assert_int_equal(tctx, dlz_configure((void*)tctx, dlzdb, dbdata),
						     ISC_R_SUCCESS,
				             "Failed to configure samba_dlz");

    /* Ask for zone transfer with no specific config => expect denied */
    ret = dlz_allowzonexfr(dbdata, lpcfg_dnsdomain(tctx->lp_ctx), "127.0.0.1");
    torture_assert_int_equal(tctx, ret, ISC_R_NOPERM,
                            "Zone transfer accepted with default settings");

    /* Ask for zone transfer with authorizations set */
    ok = lpcfg_set_option(tctx->lp_ctx, "dns zone transfer clients allow=127.0.0.1,1234:5678::1,192.168.0.");
    torture_assert(tctx, ok, "Failed to set dns zone transfer clients allow option.");

    ok = lpcfg_set_option(tctx->lp_ctx, "dns zone transfer clients deny=192.168.0.2");
    torture_assert(tctx, ok, "Failed to set dns zone transfer clients deny option.");

    ret = dlz_allowzonexfr(dbdata, lpcfg_dnsdomain(tctx->lp_ctx), "127.0.0.1");
    torture_assert_int_equal(tctx, ret, ISC_R_SUCCESS,
                            "Zone transfer refused for authorized IPv4 address");

    ret = dlz_allowzonexfr(dbdata, lpcfg_dnsdomain(tctx->lp_ctx), "1234:5678::1");
    torture_assert_int_equal(tctx, ret, ISC_R_SUCCESS,
                             "Zone transfer refused for authorized IPv6 address.");

    ret = dlz_allowzonexfr(dbdata, lpcfg_dnsdomain(tctx->lp_ctx), "10.0.0.1");
    torture_assert_int_equal(tctx, ret, ISC_R_NOPERM,
                            "Zone transfer accepted for unauthorized IP");

    ret = dlz_allowzonexfr(dbdata, lpcfg_dnsdomain(tctx->lp_ctx), "192.168.0.1");
    torture_assert_int_equal(tctx, ret, ISC_R_SUCCESS,
                             "Zone transfer refused for address in authorized IPv4 subnet.");

    ret = dlz_allowzonexfr(dbdata, lpcfg_dnsdomain(tctx->lp_ctx), "192.168.0.2");
    torture_assert_int_equal(tctx, ret, ISC_R_NOPERM,
                            "Zone transfer allowed for denied client.");

    dlz_destroy(dbdata);
    return true;
}


static int init_dlz(struct torture_context *tctx,
		    void **dbdata)
{
	isc_result_t ret;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		dlz_bind9_binddns_dir(tctx, "dns/sam.ldb"),
		NULL
	};

	ret = dlz_create("samba_dlz", 3, argv, dbdata,
			 "log", dlz_bind9_log_wrapper,
			 "writeable_zone", dlz_bind9_writeable_zone_hook,
			 "putrr", dlz_bind9_putrr_hook,
			 "putnamedrr", dlz_bind9_putnamedrr_hook,
			 NULL);

	torture_assert_int_equal(tctx,
				 ret,
				 ISC_R_SUCCESS,
				 "Failed to create samba_dlz");

	ret = dlz_configure((void*)tctx, NULL, *dbdata);
	torture_assert_int_equal(tctx,
				 ret,
				 ISC_R_SUCCESS,
				 "Failed to configure samba_dlz");

	return true;
}


static int init_gensec(struct torture_context *tctx,
		       struct gensec_security **gensec_client_context)
{
	NTSTATUS status;
	/*
	 * Prepare session info
	 */
	status = gensec_client_start(tctx, gensec_client_context,
				     lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status,
				   "gensec_client_start (client) failed");

	/*
	 * dlz_bind9 use the special dns/host.domain account
	 */
	status = gensec_set_target_hostname(*gensec_client_context,
					    talloc_asprintf(tctx,
				"%s.%s",
				torture_setting_string(tctx, "host", NULL),
				lpcfg_dnsdomain(tctx->lp_ctx)));
	torture_assert_ntstatus_ok(tctx, status,
				   "gensec_set_target_hostname (client) failed");

	status = gensec_set_target_service(*gensec_client_context, "dns");
	torture_assert_ntstatus_ok(tctx, status,
				   "gensec_set_target_service failed");

	status = gensec_set_credentials(*gensec_client_context,
					samba_cmdline_get_creds());
	torture_assert_ntstatus_ok(tctx, status,
				   "gensec_set_credentials (client) failed");

	status = gensec_start_mech_by_sasl_name(*gensec_client_context,
						"GSS-SPNEGO");
	torture_assert_ntstatus_ok(tctx, status,
				   "gensec_start_mech_by_sasl_name (client) failed");


	return true;
}



static bool expected_record(TALLOC_CTX *mem_ctx,
			    struct test_expected_record *r,
			    const char *name,
			    const char *type,
			    const char *data)
{
	unsigned int ttl = 3600;
	const char *rdata = talloc_asprintf(
		mem_ctx,
		"%s.\t" "%u\t" "in\t" "%s\t" "%s",
		name, ttl, type, data);
	if (rdata == NULL) {
		return false;
	}

	*r = (struct test_expected_record){
		.name = name,
		.type = type,
		.data = data,
		.ttl = ttl,
		.printed = false,
		.rdata = rdata
	};
	return true;
}


struct dlz_test_handle {
	struct dcerpc_pipe *p;
};


static bool set_zone_aging(struct torture_context *tctx,
			   const char *zone,
			   int value)
{
	int ret;
	char *cmd = talloc_asprintf(tctx,
				    "bin/samba-tool dns zoneoptions "
				    "$SERVER %s -U$USERNAME%%$PASSWORD "
				    "--aging %d", zone, value);

	if (cmd == NULL) {
		return false;
	}

	ret = system(cmd);
	if (ret != 0) {
		TALLOC_FREE(cmd);
		return false;
	}
	TALLOC_FREE(cmd);
	return true;
}


static struct ldb_context* get_samdb(struct torture_context *tctx)
{
	struct ldb_context *samdb = NULL;
	char *errstring;
	int ret = samdb_connect_url(
		tctx,
		NULL,
		tctx->lp_ctx,
		system_session(tctx->lp_ctx),
		0,
		dlz_bind9_binddns_dir(tctx, "dns/sam.ldb"),
		NULL,
		&samdb,
		&errstring);
	if (ret != LDB_SUCCESS) {
		return NULL;
	}
	return samdb;
}


static void print_node_records(struct torture_context *tctx,
			       struct ldb_context *samdb,
			       struct ldb_dn *node_dn,
			       const char *msg)
{
	int ret;
	struct ldb_result *result = NULL;
	struct dnsp_DnssrvRpcRecord rec;
	struct ldb_message_element *el = NULL;
	size_t i;

	if (msg != NULL) {
		torture_comment(tctx,
				"\033[1;32m%s\033[0m\n",
				msg);
	}

	ret = dsdb_search(samdb, tctx, &result, node_dn,
			  LDB_SCOPE_SUBTREE, NULL,
			  0, NULL);
	if (ret != LDB_SUCCESS) {
		torture_comment(tctx,
				"Failed to find node: %s",
				ldb_errstring(samdb));
	}

	el = ldb_msg_find_element(result->msgs[0], "dnsRecord");

	for (i = 0; i < el->num_values; i++) {
		ret = ndr_pull_struct_blob(
			&(el->values[i]),
			result,
			&rec,
			(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ret)) {
			DBG_ERR("Failed to pull dns rec blob [%zu].\n",
				i);
			TALLOC_FREE(result);
		}
		torture_comment(tctx, "record[%zu]:\n", i);
		torture_comment(tctx, "type: %d\n", rec.wType);
		torture_comment(tctx, "timestamp: %u\n", rec.dwTimeStamp);
		torture_comment(tctx, "%s\n",
				NDR_PRINT_STRUCT_STRING(result,
							dnsp_DnssrvRpcRecord,
							&rec));
	}
}



/*
 * Test some MORE updates, this time focussing on more record types and aging.
 */
static bool test_dlz_bind9_aging(struct torture_context *tctx)
{
	struct gensec_security *gensec_client_context = NULL;
	DATA_BLOB client_to_server, server_to_client;
	NTSTATUS status;
	void *dbdata = NULL;
	void *version = NULL;
	struct test_expected_rr *testdata = NULL;
	bool ok = false;
	struct ldb_context *samdb = NULL;
	isc_result_t ret;
	size_t i, j;
	const char *domain = lpcfg_dnsdomain(tctx->lp_ctx);
	struct ldb_dn *domain_dn = NULL;
	struct ldb_dn *node_dn = NULL;
	struct ldb_result *result = NULL;
	uint32_t dns_timestamp_before;
	uint32_t dns_timestamp_after;
	const char *name = NULL;
	const char *attrs[] = {"dnsrecord", NULL};
	const char *node_dn_str = NULL;
	struct ldb_message_element *el = NULL;
	struct ldb_message *msg = NULL;

	tctx_static = tctx;

	/* Step 0. set things up */

	ok = init_dlz(tctx, &dbdata);
	if (! ok) {
		torture_fail(tctx, "Failed to init_dlz");
	}
	ok = init_gensec(tctx, &gensec_client_context);
	if (! ok) {
		torture_fail(tctx, "Failed to init_gensec");
	}

	samdb = get_samdb(tctx);
	if (samdb == NULL) {
		torture_fail(tctx, "Failed to connect to samdb");
	}

	domain_dn = ldb_get_default_basedn(samdb);
	testdata = talloc_zero(tctx, struct test_expected_rr);
	torture_assert(tctx, testdata != NULL, "talloc failed");
	testdata->tctx = tctx;

	testdata->query_name = __func__;

	name = talloc_asprintf(testdata, "%s.%s",
			       testdata->query_name,
			       domain);
	torture_assert(tctx, name != NULL, "talloc failed");

	testdata->num_records = 6;
	testdata->records = talloc_zero_array(testdata,
					      struct test_expected_record,
					      testdata->num_records);
	torture_assert(tctx, testdata->records != NULL, "talloc failed");

	torture_assert(tctx,
		       expected_record(testdata->records,
				       &testdata->records[0],
				       testdata->query_name,
				       "aaaa",
				       "::1"),
		       "failed to add record");

	torture_assert(tctx,
		       expected_record(testdata->records,
				       &testdata->records[1],
				       testdata->query_name,
				       "a",
				       "127.11.12.13"),
		       "failed to add record");
	torture_assert(tctx,
		       expected_record(testdata->records,
				       &testdata->records[2],
				       testdata->query_name,
				       "a",
				       "127.11.12.14"),
		       "failed to add record");

	torture_assert(tctx,
		       expected_record(testdata->records,
				       &testdata->records[3],
				       testdata->query_name,
				       "ptr",
				       "samba.example.com"),
		       "failed to add record");

	/*
	 * NOTE: Here we add the MX record with the priority before the name,
	 * rather than the other way around which you are more likely to see
	 * ("samba.example.com 11" e.g. in samba-tool dns), because this is
	 * how it goes in BIND9 configuration.
	 */
	torture_assert(tctx,
		       expected_record(testdata->records,
				       &testdata->records[4],
				       testdata->query_name,
				       "mx",
				       "11 samba.example.com."),
		       "failed to add record");

	torture_assert(tctx,
		       expected_record(testdata->records,
				       &testdata->records[5],
				       testdata->query_name,
				       "cname",
				       "samba.example.com"),
		       "failed to add record");


	server_to_client = data_blob(NULL, 0);

	/* Do one step of the client-server update dance */
	status = gensec_update(gensec_client_context, tctx, server_to_client,
			       &client_to_server);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {;
		torture_assert_ntstatus_ok(tctx, status,
					   "gensec_update (client) failed");
	}

	torture_assert_int_equal(tctx, dlz_ssumatch(
				cli_credentials_get_username(
					samba_cmdline_get_creds()),
				domain,
				"127.0.0.1",
				testdata->records[0].type,
				"key",
				client_to_server.length,
				client_to_server.data,
				dbdata),
				ISC_TRUE,
			 "Failed to check key for update rights samba_dlz");

	/* remember the DN for use below */
	node_dn = ldb_dn_copy(testdata, domain_dn);
	if (node_dn == NULL) {
		torture_fail(tctx, "Failed to make node dn");
	}

	ok = ldb_dn_add_child_fmt(
		node_dn,
		"DC=%s,DC=%s,CN=MicrosoftDNS,DC=DomainDnsZones",
		testdata->query_name,
		domain);
	if (! ok) {
		torture_fail(tctx, "Failed to make node dn");
	}
	node_dn_str = ldb_dn_get_linearized(node_dn);
	if (node_dn_str == NULL) {
		torture_fail(tctx, "Failed to linearise node dn");
	}

	/* LOOK: we are chopping off the last one (the CNAME) for now */
	testdata->num_records = 5;

	/*
	 * We test the following:
	 *
	 * Step 1.  Ensure we are starting with an empty node.
	 * Step 2.  Add all the records (with aging off).
	 * Step 3.  Check the timestamps are now-ish.
	 * Step 4.  Add all the records AGAIN.
	 * Step 5:  Turn aging on.
	 * Step 6.  Add all the records again.
	 * Step 7.  Check the timestamps are still now-ish.
	 * Step 8.  Wind back the timestamps in the database.
	 * Step 9.  Do another update, changing some timestamps
	 * Step 10. Check that the timestamps are right.
	 * Step 11. Set one record to be static.
	 * Step 12. Do updates on some records, zeroing their timestamps
	 * Step 13. Check that the record timeouts are *mostly* zero.
	 * Step 14. Turn aging off
	 * Step 15. Update, setting timestamps to zero
	 * Step 16. Check that the timestmaps are all zero.
	 * Step 17. Reset to non-zero via ldb, with aging still off.
	 * Step 18. Update with aging off. Nothing should change.
	 * Step 19. Check that the timestamps didn't change.
	 * Step 20. Delete all the records, 1 by 1.
	 */


	/*
	 * Step 1. Ensure we are starting with an empty node.
	 */
	torture_comment(tctx, "step 1: %s records are not there\n",
			testdata->query_name);
	testdata->num_rr = 0;
	torture_assert_int_equal(tctx, dlz_lookup(domain,
						  testdata->query_name,
						  dbdata,
						  (dns_sdlzlookup_t *)testdata,
						  NULL, NULL),
				 ISC_R_NOTFOUND,
				 "Found hostname");
	torture_assert_int_equal(tctx, testdata->num_rr, 0,
				 "Got records when there should be none");


	dns_timestamp_before = unix_to_dns_timestamp(time(NULL));

	/*
	 * Step 2. Add all the records (with aging off).
	 * After adding each one, expect to find it and earlier ones.
	 */
	torture_comment(tctx,
			"step 2: add %zu records\n",
			testdata->num_records);

	for (i = 0; i < testdata->num_records; i++) {
		struct test_expected_record r = testdata->records[i];
		ret = dlz_newversion(domain, dbdata, &version);
		torture_assert_int_equal(tctx, ret, ISC_R_SUCCESS,
					 "Failed to start transaction");

		ret = dlz_addrdataset(name, r.rdata, dbdata, version);
		torture_assert_int_equal_goto(
			tctx, ret, ISC_R_SUCCESS, ok,
			cancel_version,
			talloc_asprintf(tctx,
					"Failed to add record %zu «%s»\n",
					i, r.rdata));

		dlz_closeversion(domain, true, dbdata, &version);

		testdata->num_rr = 0;

		ret = dlz_lookup(domain, testdata->query_name, dbdata,
				 (dns_sdlzlookup_t *)testdata, NULL, NULL);

		torture_assert_int_equal(tctx, ret,
					 ISC_R_SUCCESS,
					 "Not found hostname");
		torture_assert_int_equal(tctx, testdata->num_rr, i + 1,
					 "Got wrong record count");

		for (j = 0; j < testdata->num_records; j++) {
			struct test_expected_record *r2 = &testdata->records[j];
			if (j <= i) {
				torture_assertf(
					tctx,
					r2->printed,
					"putrr callback not run on %s «%s»",
					r2->type, r2->name);
			} else {
				torture_assertf(
					tctx,
					! r2->printed,
					"putrr callback should not see %s «%s»",
					r2->type, r2->name);
			}
			r2->printed = false;
		}
	}

	dns_timestamp_after = unix_to_dns_timestamp(time(NULL));
	/*
	 * Step 3. Check the timestamps are now-ish.
	 *
	 * Those records should have DNS timestamps between
	 * dns_timestamp_before and dns_timestamp_after (the resolution is
	 * hourly, so probably both are equal).
	 */
	ret = dsdb_search(samdb, tctx, &result, node_dn,
			  LDB_SCOPE_SUBTREE, NULL,
			  0, NULL);
	if (ret != LDB_SUCCESS) {
		torture_fail(tctx,
			     talloc_asprintf(
				     tctx,
				     "Failed to find %s node: %s",
				     name, ldb_errstring(samdb)));
	}
	torture_assert_int_equal(tctx, result->count, 1,
				 "Should be one node");

	el = ldb_msg_find_element(result->msgs[0], "dnsRecord");
	torture_assert_not_null(tctx, el, "el");
	torture_assert(tctx, dns_timestamp_before <= dns_timestamp_after, "<");
	torture_assert_int_equal(tctx, el->num_values, testdata->num_records,
				 "num_values != num_records");

	for (i = 0; i < el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec;
		ret = ndr_pull_struct_blob(
			&(el->values[i]),
			result,
			&rec,
			(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ret)) {
			DBG_ERR("Failed to pull dns rec blob [%zu].\n",
				i);
			TALLOC_FREE(result);
			torture_fail(tctx, "Failed to pull dns rec blob");
		}
		torture_comment(tctx, "record[%zu]:\n", i);
		torture_comment(tctx, "type: %d\n", rec.wType);
		torture_comment(tctx, "timestamp: %u\n", rec.dwTimeStamp);
		torture_comment(tctx, "%s\n",
				NDR_PRINT_STRUCT_STRING(result,
							dnsp_DnssrvRpcRecord,
							&rec));

		torture_assert(tctx, rec.dwTimeStamp >= dns_timestamp_before,
			       "timestamp < dns_timestamp_before");
		torture_assert(tctx, rec.dwTimeStamp <= dns_timestamp_after,
			       "timestamp > dns_timestamp_after");
	}

	talloc_free(result);

	/*
	 * Step 4. Add all the records AGAIN.
	 *
	 * After adding each one, we expect no change in the number or nature
	 * of records.
	 */
	torture_comment(tctx, "step 4: add the records again\n");
	for (i = 0; i < testdata->num_records; i++) {
		struct test_expected_record r = testdata->records[i];

		ret = dlz_newversion(domain, dbdata, &version);
		torture_assert_int_equal(tctx, ret, ISC_R_SUCCESS,
					 "Failed to start transaction");

		ret = dlz_addrdataset(name, r.rdata, dbdata, version);
		torture_assert_int_equal_goto(
			tctx, ret, ISC_R_SUCCESS, ok,
			cancel_version,
			talloc_asprintf(tctx,
					"Failed to add record %zu «%s»\n",
					i, r.rdata));

		dlz_closeversion(domain, true, dbdata, &version);

		testdata->num_rr = 0;

		ret = dlz_lookup(domain, testdata->query_name, dbdata,
				 (dns_sdlzlookup_t *)testdata, NULL, NULL);

		torture_assert_int_equal(tctx, ret,
					 ISC_R_SUCCESS,
					 "Not found hostname");
		torture_assert_int_equal(tctx,
					 testdata->num_rr,
					 testdata->num_records,
					 "Got wrong record count");

		for (j = 0; j <= i; j++) {
			/* these ones are printed again. */
			struct test_expected_record *r2 = &testdata->records[j];
			torture_assert(
				tctx,
				r2->printed,
				talloc_asprintf(
					tctx,
					"putrr callback not run on %s «%s»",
					r2->type, r2->name));
			r2->printed = false;
		}
	}

	print_node_records(tctx, samdb, node_dn, "after adding again");


	/*
	 * Step 5: Turn aging on.
	 */
	torture_comment(tctx, "step 5: turn aging on\n");
	ok = set_zone_aging(tctx, domain, 1);
	torture_assert(tctx, ok, "failed to enable aging");

	print_node_records(tctx, samdb, node_dn, "aging on");

	/*
	 * Step 6. Add all the records again.
	 *
	 * We expect no change in the number or nature of records, even with
	 * aging on, because the default noRefreshInterval is 7 days (also,
	 * there should be no change because almost no time has passed).
	 */
	torture_comment(tctx, "step 6: add records again\n");

	for (i = 0; i < testdata->num_records; i++) {
		struct test_expected_record r = testdata->records[i];

		ret = dlz_newversion(domain, dbdata, &version);
		torture_assert_int_equal(tctx, ret, ISC_R_SUCCESS,
					 "Failed to start transaction");

		ret = dlz_addrdataset(domain, r.rdata, dbdata, version);
		torture_assert_int_equal_goto(
			tctx, ret, ISC_R_SUCCESS, ok,
			cancel_version,
			talloc_asprintf(tctx,
					"Failed to add record %zu «%s»\n",
					i, r.rdata));

		dlz_closeversion(domain, true, dbdata, &version);
	}

	print_node_records(tctx, samdb, node_dn, "add again");


	/*
	 * Step 7. Check the timestamps are still now-ish.
	 *
	 */
	ret = dsdb_search(samdb, tctx, &result, node_dn,
			  LDB_SCOPE_SUBTREE, NULL,
			  0, NULL);
	if (ret != LDB_SUCCESS) {
		torture_fail(tctx,
			     talloc_asprintf(
				     tctx,
				     "Failed to find %s node: %s",
				     name, ldb_errstring(samdb)));
	}
	torture_assert_int_equal(tctx, result->count, 1,
				 "Should be one node");

	el = ldb_msg_find_element(result->msgs[0], "dnsRecord");
	torture_assert_not_null(tctx, el, "el");
	torture_assert(tctx, dns_timestamp_before <= dns_timestamp_after, "<");
	torture_assert_int_equal(tctx, el->num_values, testdata->num_records,
				 "num_values != num_records");

	for (i = 0; i < el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec;
		ret = ndr_pull_struct_blob(
			&(el->values[i]),
			result,
			&rec,
			(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ret)) {
			DBG_ERR("Failed to pull dns rec blob [%zu].\n",
				i);
			TALLOC_FREE(result);
			torture_fail(tctx, "Failed to pull dns rec blob");
		}
		torture_comment(tctx, "record[%zu]:\n", i);
		torture_comment(tctx, "type: %d\n", rec.wType);
		torture_comment(tctx, "timestamp: %u\n", rec.dwTimeStamp);
		torture_comment(tctx, "%s\n",
				NDR_PRINT_STRUCT_STRING(result,
							dnsp_DnssrvRpcRecord,
							&rec));

		torture_assert(tctx, rec.dwTimeStamp >= dns_timestamp_before,
			       "timestamp < dns_timestamp_before");
		torture_assert(tctx, rec.dwTimeStamp <= dns_timestamp_after,
			       "timestamp > dns_timestamp_after");
	}

	talloc_free(result);

	/*
	 * Step 8. Wind back the timestamps in the database.
	 *
	 * We use a different number of days for each record, so that some
	 * should be refreshed, and some shouldn't.
	 */
	torture_comment(tctx, "step 8: alter timestamps\n");
	ret = dsdb_search_one(samdb, tctx, &msg, node_dn,
			      LDB_SCOPE_BASE, attrs,
			      0, NULL);
	if (ret != LDB_SUCCESS) {
		torture_fail(tctx,
			     talloc_asprintf(
				     tctx,
				     "Failed to find %s node: %s",
				     name, ldb_errstring(samdb)));
	}

	el = ldb_msg_find_element(msg, "dnsRecord");
	torture_assert_not_null(tctx, el, "el");
	torture_assert_int_equal(tctx, el->num_values,
				 testdata->num_records,
				 "num_values != num_records");

	for (i = 0; i < el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec;
		ret = ndr_pull_struct_blob(
			&(el->values[i]),
			msg,
			&rec,
			(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		torture_assert_ndr_success(tctx, ret, "failed to pull record");

		rec.dwTimeStamp = dns_timestamp_after + 3 - 24 * (i + 5);

		ret = ndr_push_struct_blob(
			&el->values[i],
			msg,
			&rec,
			(ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
		torture_assert_ndr_success(tctx, ret, "failed to PUSH record");
	}
	el->flags = LDB_FLAG_MOD_REPLACE;

	ret = ldb_modify(samdb, msg);
	torture_assert_int_equal(tctx, ret, 0, "failed to ldb_modify");
	print_node_records(tctx, samdb, node_dn, "after ldb_modify");


	/*
	 * Step 9. Do another update, changing some timestamps
	 */

	for (i = 0; i < testdata->num_records; i++) {
		struct test_expected_record r = testdata->records[i];

		ret = dlz_newversion(domain, dbdata, &version);
		torture_assert_int_equal(tctx, ret, ISC_R_SUCCESS,
					 "Failed to start transaction");

		ret = dlz_addrdataset(name, r.rdata, dbdata, version);
		dlz_closeversion(domain, ret == ISC_R_SUCCESS, dbdata,
				 &version);
		torture_assert_int_equal(tctx, ret, ISC_R_SUCCESS,
					 "Failed to update record\n");
	}
	print_node_records(tctx, samdb, node_dn, "after update");

	/*
	 * Step 10. Check that the timestamps are right.
	 *
	 * The formula was
	 *    (i + 5) days + 3 hours
	 * so 1 is 6 days + 3 hours, and should not be renewed.
	 *    2 is 7 days + 3 hours, and should be renewed
	 *
	 * NOTE: the ldb record order is different from the insertion order,
	 * but it should stay the same betweeen searches.
	 */
	ret = dsdb_search_one(samdb, tctx, &msg, node_dn,
			      LDB_SCOPE_BASE, attrs,
			      0, NULL);
	if (ret != LDB_SUCCESS) {
		torture_fail(tctx,
			     talloc_asprintf(
				     tctx,
				     "Failed to find %s node: %s",
				     name, ldb_errstring(samdb)));
	}

	el = ldb_msg_find_element(msg, "dnsRecord");
	torture_assert_not_null(tctx, el, "el");
	torture_assert_int_equal(tctx, el->num_values,
				 testdata->num_records,
				 "num_values != num_records");

	for (i = 0; i < el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec;
		ret = ndr_pull_struct_blob(
			&(el->values[i]),
			msg,
			&rec,
			(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		torture_assert_ndr_success(tctx, ret, "failed to pull record");
		if (i < 3) {
			/* records 0 and 1 should not have been renewed */
			int old_ts = dns_timestamp_after + 3 - 24 * (i + 5);
			torture_assertf(
				tctx,
				rec.dwTimeStamp == old_ts,
				"record[%zu] timestamp should not be altered."
				" diff is %d\n",
				i, rec.dwTimeStamp - old_ts);
		} else {
			/* records 3+ should have a now-ish timestamp */
			int old_ts = dns_timestamp_after + 3 - 24 * (i + 5);
			torture_assertf(
				tctx,
				rec.dwTimeStamp >= dns_timestamp_before,
				"record[%zu] should have altered timestamp "
				"now ~= %d, then ~= %d, has %d, diff %d\n", i,
				dns_timestamp_before, old_ts, rec.dwTimeStamp,
				dns_timestamp_before - rec.dwTimeStamp
				);
		}
	}

	/*
	 * Step 11. Set one record to be static.
	 *
	 * This should make the node static, but it won't "know" that until we
	 * force it with an update.
	 */
	torture_comment(tctx, "step 11: alter one timestamp to be 0\n");
	ret = dsdb_search_one(samdb, tctx, &msg, node_dn,
			      LDB_SCOPE_BASE, attrs,
			      0, NULL);
	if (ret != LDB_SUCCESS) {
		torture_fail(tctx,
			     talloc_asprintf(
				     tctx,
				     "Failed to find %s node: %s",
				     name, ldb_errstring(samdb)));
	}

	el = ldb_msg_find_element(msg, "dnsRecord");
	torture_assert_not_null(tctx, el, "el");
	torture_assert_int_equal(tctx, el->num_values,
				 testdata->num_records,
				 "num_values != num_records");

	{
		/* we're arbitrarily picking on record 3 */
		struct dnsp_DnssrvRpcRecord rec;
		ret = ndr_pull_struct_blob(
			&(el->values[3]),
			msg,
			&rec,
			(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		torture_assert_ndr_success(tctx, ret, "failed to pull record");

		rec.dwTimeStamp = 0;

		ret = ndr_push_struct_blob(
			&el->values[3],
			msg,
			&rec,
			(ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
		torture_assert_ndr_success(tctx, ret, "failed to PUSH record");
	}
	el->flags = LDB_FLAG_MOD_REPLACE;

	ret = ldb_modify(samdb, msg);
	torture_assert_int_equal(tctx, ret, 0, "failed to ldb_modify");
	print_node_records(tctx, samdb, node_dn, "after ldb_modify");


	/*
	 * Step 12. Do updates on some records, zeroing their timestamps
	 *
	 * Zero means static. A single zero timestmap is infectious, so other
	 * records get it when they are updated.
	 */

	for (i = 0; i < testdata->num_records - 2; i++) {
		struct test_expected_record r = testdata->records[i];

		ret = dlz_newversion(domain, dbdata, &version);
		torture_assert_int_equal(tctx, ret, ISC_R_SUCCESS,
					 "Failed to start transaction");

		ret = dlz_addrdataset(name, r.rdata, dbdata, version);
		dlz_closeversion(domain, ret == ISC_R_SUCCESS, dbdata,
				 &version);
		torture_assert_int_equal(tctx, ret, ISC_R_SUCCESS,
					 "Failed to update record\n");
	}
	print_node_records(tctx, samdb, node_dn, "after update to static");


	/*
	 * Step 13. Check that the record timeouts are *mostly* zero.
	 *
	 * one or two will be non-zero: we updated all but two, but one of
	 * excluded ones might be the el->records[3] that we explicitly set to
	 * zero.
	 */
	ret = dsdb_search_one(samdb, tctx, &msg, node_dn,
			      LDB_SCOPE_BASE, attrs,
			      0, NULL);
	if (ret != LDB_SUCCESS) {
		torture_fail(tctx,
			     talloc_asprintf(
				     tctx,
				     "Failed to find %s node: %s",
				     name, ldb_errstring(samdb)));
	}

	el = ldb_msg_find_element(msg, "dnsRecord");
	{
		unsigned n_zero = 0;
		for (i = 0; i < el->num_values; i++) {
			struct dnsp_DnssrvRpcRecord rec;
			ret = ndr_pull_struct_blob(
				&(el->values[i]),
				msg,
				&rec,
				(ndr_pull_flags_fn_t)\
				ndr_pull_dnsp_DnssrvRpcRecord);
			torture_assert_ndr_success(tctx, ret,
						   "failed to pull record");
			if (rec.dwTimeStamp == 0) {
				n_zero++;
			}
		}
		if (n_zero != el->num_values - 1 &&
		    n_zero != el->num_values - 2) {
			torture_comment(tctx, "got %u zeros, expected %u or %u",
					n_zero,
					el->num_values - 2,
					el->num_values - 1);
			torture_fail(tctx,
				     "static node not setting zero timestamps\n");

		}
	}


	/*
	 * Step 14. Turn aging off.
	 */
	torture_comment(tctx, "step 14: turn aging off\n");
	ok = set_zone_aging(tctx, domain, 0);
	torture_assert(tctx, ok, "failed to disable aging");
	print_node_records(tctx, samdb, node_dn, "aging off");

	/*
	 * Step 15. Update, setting timestamps to zero.
	 *
	 * Even with aging off, timestamps are still changed to static.
	 */
	for (i = 0; i < testdata->num_records; i++) {
		struct test_expected_record r = testdata->records[i];

		ret = dlz_newversion(domain, dbdata, &version);
		torture_assert_int_equal(tctx, ret, ISC_R_SUCCESS,
					 "Failed to start transaction");

		ret = dlz_addrdataset(name, r.rdata, dbdata, version);
		dlz_closeversion(domain, ret == ISC_R_SUCCESS, dbdata,
				 &version);
		torture_assert_int_equal(tctx, ret, ISC_R_SUCCESS,
					 "Failed to update record\n");
	}
	print_node_records(tctx, samdb, node_dn, "after update with aging off");


	/*
	 * Step 16. Check that the timestmaps are all zero.
	 */
	ret = dsdb_search_one(samdb, tctx, &msg, node_dn,
			      LDB_SCOPE_BASE, attrs,
			      0, NULL);
	if (ret != LDB_SUCCESS) {
		torture_fail(tctx,
			     talloc_asprintf(
				     tctx,
				     "Failed to find %s node: %s",
				     name, ldb_errstring(samdb)));
	}

	el = ldb_msg_find_element(msg, "dnsRecord");
	for (i = 0; i < el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec;
		ret = ndr_pull_struct_blob(
			&(el->values[i]),
			msg,
			&rec,
			(ndr_pull_flags_fn_t) ndr_pull_dnsp_DnssrvRpcRecord);
		torture_assert_ndr_success(tctx, ret,
					   "failed to pull record");
		torture_assertf(tctx, rec.dwTimeStamp == 0,
				"record[%zu].dwTimeStamp is %u, expected 0\n",
				i, rec.dwTimeStamp);

	}


	/*
	 * Step 17. Reset to non-zero via ldb, with aging still off.
	 *
	 * We chose timestamps in the distant past that would all be updated
	 * if aging was on.
	 */
	torture_comment(tctx, "step 17: reset to non-zero timestamps\n");
	ret = dsdb_search_one(samdb, tctx, &msg, node_dn,
			      LDB_SCOPE_BASE, attrs,
			      0, NULL);
	if (ret != LDB_SUCCESS) {
		torture_fail(tctx,
			     talloc_asprintf(
				     tctx,
				     "Failed to find %s node: %s",
				     name, ldb_errstring(samdb)));
	}

	el = ldb_msg_find_element(msg, "dnsRecord");

	for (i = 0; i < el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec;
		ret = ndr_pull_struct_blob(
			&(el->values[i]),
			msg,
			&rec,
			(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		torture_assert_ndr_success(tctx, ret, "failed to pull record");

		rec.dwTimeStamp = 10000 + i; /* a long time ago */

		ret = ndr_push_struct_blob(
			&el->values[i],
			msg,
			&rec,
			(ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
		torture_assert_ndr_success(tctx, ret, "failed to PUSH record");
	}
	el->flags = LDB_FLAG_MOD_REPLACE;

	ret = ldb_modify(samdb, msg);
	torture_assert_int_equal(tctx, ret, 0, "failed to ldb_modify");
	print_node_records(tctx, samdb, node_dn, "timestamps no-zero, aging off");


	/*
	 * Step 18. Update with aging off. Nothing should change.
	 *
	 */

	/* now, with another update, some will be updated and some won't */
	for (i = 0; i < testdata->num_records; i++) {
		struct test_expected_record r = testdata->records[i];

		ret = dlz_newversion(domain, dbdata, &version);
		torture_assert_int_equal(tctx, ret, ISC_R_SUCCESS,
					 "Failed to start transaction");

		ret = dlz_addrdataset(name, r.rdata, dbdata, version);
		dlz_closeversion(domain, ret == ISC_R_SUCCESS, dbdata,
				 &version);
		torture_assert_int_equal(tctx, ret, ISC_R_SUCCESS,
					 "Failed to update record\n");
	}
	print_node_records(tctx, samdb, node_dn, "after update");


	/*
	 * Step 19. Check that the timestamps didn't change.
	 */
	el = ldb_msg_find_element(msg, "dnsRecord");
	torture_assert_not_null(tctx, el, "el");
	torture_assert_int_equal(tctx, el->num_values,
				 testdata->num_records,
				 "num_values != num_records");

	for (i = 0; i < el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec;
		ret = ndr_pull_struct_blob(
			&(el->values[i]),
			msg,
			&rec,
			(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		torture_assert_ndr_success(tctx, ret, "failed to pull record");
		torture_assertf(
			tctx,
			rec.dwTimeStamp == 10000 + i,
			"record[%zu] timestamp should not be altered.\n",
			i);
	}


	/*
	 * Step 20. Delete all the records, 1 by 1.
	 *
	 */
	torture_comment(tctx, "step 20: delete the records\n");

	for (i = 0; i < testdata->num_records; i++) {
		struct test_expected_record r = testdata->records[i];

		ret = dlz_newversion(domain, dbdata, &version);
		torture_assert_int_equal(tctx, ret, ISC_R_SUCCESS,
					 "Failed to start transaction");

		ret = dlz_subrdataset(name, r.rdata, dbdata, version);
		torture_assert_int_equal_goto(
			tctx, ret, ISC_R_SUCCESS, ok,
			cancel_version,
			talloc_asprintf(tctx,
					"Failed to delete record %zu «%s»\n",
					i, r.rdata));

		dlz_closeversion(domain, true, dbdata, &version);

		testdata->num_rr = 0;

		ret = dlz_lookup(domain, testdata->query_name, dbdata,
				 (dns_sdlzlookup_t *)testdata, NULL, NULL);

		if (i ==  testdata->num_records - 1) {
			torture_assert_int_equal(tctx, ret,
						 ISC_R_NOTFOUND,
						 "no records should exist");
		} else {
			torture_assert_int_equal(tctx, ret,
						 ISC_R_SUCCESS,
						 "records not found");
		}

		torture_assert_int_equal(tctx,
					 testdata->num_rr,
					 testdata->num_records - 1 - i,
					 "Got wrong record count");

		for (j = 0; j < testdata->num_records; j++) {
			struct test_expected_record *r2 = &testdata->records[j];
			if (j > i) {
				torture_assert(
					tctx,
					r2->printed,
					talloc_asprintf(tctx,
					    "putrr callback not run on %s «%s»",
							r2->type, r2->name));
			} else {
				torture_assert(
					tctx,
					! r2->printed,
					talloc_asprintf(tctx,
					    "putrr callback should not see  %s «%s»",
							r2->type, r2->name));
			}
			r2->printed = false;
		}
	}

	dlz_destroy(dbdata);

	return true;

cancel_version:
	DBG_ERR("exiting with %d\n", ret);
	dlz_closeversion(domain, false, dbdata, &version);
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
	torture_suite_add_simple_test(suite, "destroyoldestfirst",
				      test_dlz_bind9_destroy_oldest_first);
	torture_suite_add_simple_test(suite, "destroynewestfirst",
				      test_dlz_bind9_destroy_newest_first);
	torture_suite_add_simple_test(suite, "multipleconfigure",
				      test_dlz_bind9_multiple_configure);

	torture_suite_add_simple_test(suite, "gssapi", test_dlz_bind9_gssapi);
	torture_suite_add_simple_test(suite, "spnego", test_dlz_bind9_spnego);
	torture_suite_add_simple_test(suite, "lookup", test_dlz_bind9_lookup);
	torture_suite_add_simple_test(suite, "zonedump", test_dlz_bind9_zonedump);
	torture_suite_add_simple_test(suite, "update01", test_dlz_bind9_update01);
	torture_suite_add_simple_test(suite, "aging", test_dlz_bind9_aging);
	torture_suite_add_simple_test(suite, "allowzonexfr", test_dlz_bind9_allowzonexfr);
	return suite;
}

/**
 * DNS torture module initialization
 */
NTSTATUS torture_bind_dns_init(TALLOC_CTX *);
NTSTATUS torture_bind_dns_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite;

	/* register DNS related test cases */
	suite = dlz_bind9_suite(ctx);
	if (!suite) return NT_STATUS_NO_MEMORY;
	torture_register_suite(ctx, suite);

	return NT_STATUS_OK;
}
