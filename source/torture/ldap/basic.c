/* 
   Unix SMB/CIFS mplementation.
   LDAP protocol helper functions for SAMBA
   
   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Simo Sorce 2004
    
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

#include "torture/torture.h"
#include "torture/ldap/proto.h"

#include "param/param.h"

static bool test_bind_simple(struct ldap_connection *conn, const char *userdn, const char *password)
{
	NTSTATUS status;
	bool ret = true;

	status = torture_ldap_bind(conn, userdn, password);
	if (!NT_STATUS_IS_OK(status)) {
		ret = false;
	}

	return ret;
}

static bool test_bind_sasl(struct torture_context *tctx,
			   struct ldap_connection *conn, struct cli_credentials *creds)
{
	NTSTATUS status;
	bool ret = true;

	printf("Testing sasl bind as user\n");

	status = torture_ldap_bind_sasl(conn, creds, tctx->lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		ret = false;
	}

	return ret;
}

static bool test_multibind(struct ldap_connection *conn, const char *userdn, const char *password)
{
	bool ret = true;

	printf("Testing multiple binds on a single connnection as anonymous and user\n");

	ret = test_bind_simple(conn, NULL, NULL);
	if (!ret) {
		printf("1st bind as anonymous failed\n");
		return ret;
	}

	ret = test_bind_simple(conn, userdn, password);
	if (!ret) {
		printf("2nd bind as authenticated user failed\n");
	}

	return ret;
}

static bool test_search_rootDSE(struct ldap_connection *conn, char **basedn)
{
	bool ret = true;
	struct ldap_message *msg, *result;
	struct ldap_request *req;
	int i;
	struct ldap_SearchResEntry *r;
	NTSTATUS status;

	printf("Testing RootDSE Search\n");

	*basedn = NULL;

	msg = new_ldap_message(conn);
	if (!msg) {
		return false;
	}

	msg->type = LDAP_TAG_SearchRequest;
	msg->r.SearchRequest.basedn = "";
	msg->r.SearchRequest.scope = LDAP_SEARCH_SCOPE_BASE;
	msg->r.SearchRequest.deref = LDAP_DEREFERENCE_NEVER;
	msg->r.SearchRequest.timelimit = 0;
	msg->r.SearchRequest.sizelimit = 0;
	msg->r.SearchRequest.attributesonly = false;
	msg->r.SearchRequest.tree = ldb_parse_tree(msg, "(objectclass=*)");
	msg->r.SearchRequest.num_attributes = 0;
	msg->r.SearchRequest.attributes = NULL;

	req = ldap_request_send(conn, msg);
	if (req == NULL) {
		printf("Could not setup ldap search\n");
		return false;
	}

	status = ldap_result_one(req, &result, LDAP_TAG_SearchResultEntry);
	if (!NT_STATUS_IS_OK(status)) {
		printf("search failed - %s\n", nt_errstr(status));
		return false;
	}

	printf("received %d replies\n", req->num_replies);

	r = &result->r.SearchResultEntry;
		
	DEBUG(1,("\tdn: %s\n", r->dn));
	for (i=0; i<r->num_attributes; i++) {
		int j;
		for (j=0; j<r->attributes[i].num_values; j++) {
			DEBUG(1,("\t%s: %d %.*s\n", r->attributes[i].name,
				 (int)r->attributes[i].values[j].length,
				 (int)r->attributes[i].values[j].length,
				 (char *)r->attributes[i].values[j].data));
			if (!(*basedn) && 
			    strcasecmp("defaultNamingContext",r->attributes[i].name)==0) {
				*basedn = talloc_asprintf(conn, "%.*s",
							  (int)r->attributes[i].values[j].length,
							  (char *)r->attributes[i].values[j].data);
			}
		}
	}

	talloc_free(req);

	return ret;
}

static bool test_compare_sasl(struct ldap_connection *conn, const char *basedn)
{
	struct ldap_message *msg, *rep;
	struct ldap_request *req;
	const char *val;
	NTSTATUS status;

	printf("Testing SASL Compare: %s\n", basedn);

	if (!basedn) {
		return false;
	}

	msg = new_ldap_message(conn);
	if (!msg) {
		return false;
	}

	msg->type = LDAP_TAG_CompareRequest;
	msg->r.CompareRequest.dn = basedn;
	msg->r.CompareRequest.attribute = talloc_strdup(msg, "objectClass");
	val = "domain";
	msg->r.CompareRequest.value = data_blob_talloc(msg, val, strlen(val));

	req = ldap_request_send(conn, msg);
	if (!req) {
		return false;
	}

	status = ldap_result_one(req, &rep, LDAP_TAG_CompareResponse);
	if (!NT_STATUS_IS_OK(status)) {
		printf("error in ldap compare request - %s\n", nt_errstr(status));
		return false;
	}

	DEBUG(5,("Code: %d DN: [%s] ERROR:[%s] REFERRAL:[%s]\n",
		rep->r.CompareResponse.resultcode,
		rep->r.CompareResponse.dn,
		rep->r.CompareResponse.errormessage,
		rep->r.CompareResponse.referral));

	return true;
}


bool torture_ldap_basic(struct torture_context *torture)
{
        NTSTATUS status;
        struct ldap_connection *conn;
	TALLOC_CTX *mem_ctx;
	bool ret = true;
	const char *host = torture_setting_string(torture, "host", NULL);
	const char *userdn = torture_setting_string(torture, "ldap_userdn", NULL);
	const char *secret = torture_setting_string(torture, "ldap_secret", NULL);
	char *url;
	char *basedn;

	mem_ctx = talloc_init("torture_ldap_basic");

	url = talloc_asprintf(mem_ctx, "ldap://%s/", host);

	status = torture_ldap_connection(torture, &conn, url);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (!test_search_rootDSE(conn, &basedn)) {
		ret = false;
	}

	/* other basic tests here */

	if (!test_multibind(conn, userdn, secret)) {
		ret = false;
	}

	if (!test_bind_sasl(torture, conn, cmdline_credentials)) {
		ret = false;
	}

	if (!test_compare_sasl(conn, basedn)) {
		ret = false;
	}

	/* no more test we are closing */
        torture_ldap_close(conn);
	talloc_free(mem_ctx);


	return ret;
}

