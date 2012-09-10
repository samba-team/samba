/*
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Kai Blin 2012

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
#include <talloc.h>
#include "lib/addns/dns.h"

static struct dns_connection *setup_connection(struct torture_context *tctx)
{
	DNS_ERROR err;
	struct dns_connection *conn;

	err = dns_open_connection(getenv("DC_SERVER_IP"), DNS_TCP, tctx, &conn);
	if (!ERR_DNS_IS_OK(err)) {
		printf("Failed to open connection to DNS server\n");
		return NULL;
	}

	return conn;
}

static char *get_dns_domain(struct torture_context *tctx)
{
	return strlower_talloc(tctx, getenv("REALM"));
}

static struct sockaddr_storage *str_to_sockaddr(TALLOC_CTX *mem_ctx, const char *ip_string)
{
	struct sockaddr_storage *ss = talloc_zero(mem_ctx, struct sockaddr_storage);
	int ret;

	if (ss == NULL) {
		return NULL;
	}

	ss->ss_family = AF_INET;

	ret = inet_pton(AF_INET, ip_string, &(((struct sockaddr_in *)ss)->sin_addr));
	if (ret != 1) {
		return NULL;
	}

	return ss;
}

static bool test_internal_dns_query_self(struct torture_context *tctx)
{
	struct dns_connection *conn;
	struct dns_request *req, *resp;
	char *host;
	DNS_ERROR err;

	conn = setup_connection(tctx);
	if (conn == NULL) {
		return false;
	}

	host = talloc_asprintf(tctx, "%s.%s", getenv("DC_SERVER"), get_dns_domain(tctx));
	if (host == NULL) {
		return false;
	}

	err = dns_create_query(conn, host, QTYPE_A, DNS_CLASS_IN, &req);
	if (!ERR_DNS_IS_OK(err)) {
		printf("Failed to create A record query\n");
		return false;
	}

	err = dns_transaction(conn, conn, req, &resp);
	if (!ERR_DNS_IS_OK(err)) {
		printf("Failed to query DNS server\n");
		return false;
	}

	if (dns_response_code(resp->flags) != DNS_NO_ERROR) {
		printf("Query returned %u\n", dns_response_code(resp->flags));
		return false;
	}

	/* FIXME: is there _any_ way to unmarshal the response to check this? */

	return true;
}

static bool test_internal_dns_update_self(struct torture_context *tctx)
{
	struct dns_connection *conn;
	struct dns_update_request *req, *resp;
	struct dns_rrec *rec = NULL;
	char *host;
	DNS_ERROR err;
	struct sockaddr_storage *ss;

	conn = setup_connection(tctx);
	if (conn == NULL) {
		return false;
	}

	host = talloc_asprintf(tctx, "%s.%s", getenv("DC_SERVER"), get_dns_domain(tctx));
	if (host == NULL) {
		return false;
	}

	err = dns_create_update(conn, get_dns_domain(tctx), &req);
	if (!ERR_DNS_IS_OK(err)) {
		printf("Failed to update packet\n");
		return false;
	}

	ss = str_to_sockaddr(conn, getenv("DC_SERVER_IP"));
	if (ss == NULL) {
		printf("Converting '%s' to sockaddr_storage failed\n", getenv("DC_SERVER_IP"));
		return false;
	}

	err = dns_create_a_record(req, host, 300, ss, &rec);
	if (!ERR_DNS_IS_OK(err)) {
		printf("Failed to create A update record\n");
		return false;
	}

	err = dns_add_rrec(req, rec, &req->num_updates, &req->updates);
	if (!ERR_DNS_IS_OK(err)) {
		printf("Failed to add A update record to update packet\n");
		return false;
	}

	err = dns_update_transaction(conn, conn, req, &resp);
	if (!ERR_DNS_IS_OK(err)) {
		printf("Failed to send update\n");
		return false;
	}

	if (dns_response_code(resp->flags) != DNS_REFUSED) {
		printf("Update returned %u\n", dns_response_code(resp->flags));
		return false;
	}

	/* FIXME: is there _any_ way to unmarshal the response to check this? */

	return true;
}

static struct torture_suite *internal_dns_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "dns_internal");

	suite->description = talloc_strdup(suite,
	                                   "Tests for the internal DNS server");
	torture_suite_add_simple_test(suite, "queryself", test_internal_dns_query_self);
	torture_suite_add_simple_test(suite, "updateself", test_internal_dns_update_self);
	return suite;
}


/* Silence silly compiler warning */
NTSTATUS torture_internal_dns_init(void);

/**
 * DNS torture module initialization
 */
NTSTATUS torture_internal_dns_init(void)
{
	struct torture_suite *suite;
	TALLOC_CTX *mem_ctx = talloc_autofree_context();

	/* register internal DNS torture test cases */
	suite = internal_dns_suite(mem_ctx);
	if (!suite) return NT_STATUS_NO_MEMORY;
	torture_register_suite(suite);

	return NT_STATUS_OK;
}
