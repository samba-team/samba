/* 
   Unix SMB/CIFS mplementation.
   LDAP protocol helper functions for SAMBA
   
   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Simo Sorce 2004
    
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
   
*/

#include "includes.h"

BOOL test_bind_simple(struct ldap_connection *conn, const char *userdn, const char *password)
{
	NTSTATUS status;
	BOOL ret = True;

	status = torture_ldap_bind(conn, userdn, password);
	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
	}

	return ret;
}

BOOL test_bind_sasl(struct ldap_connection *conn, const char *username, const char *domain, const char *password)
{
	NTSTATUS status;
	BOOL ret = True;

	printf("Testing sasl bind as user\n");

	status = torture_ldap_bind_sasl(conn, username, domain, password);
	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
	}

	return ret;
}

BOOL test_multibind(struct ldap_connection *conn, const char *userdn, const char *password)
{
	BOOL ret = True;

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

static BOOL test_search_rootDSE(struct ldap_connection *conn, char **basedn)
{
	BOOL ret = True;
	struct ldap_message *msg, *result;

	printf("Testing RootDSE Search\n");

	*basedn = NULL;
	conn->searchid = 0;
	conn->next_msgid = 30;

	msg = new_ldap_message();
	if (!msg) {
		return False;
	}

	msg->type = LDAP_TAG_SearchRequest;
	msg->r.SearchRequest.basedn = "";
	msg->r.SearchRequest.scope = LDAP_SEARCH_SCOPE_BASE;
	msg->r.SearchRequest.deref = LDAP_DEREFERENCE_NEVER;
	msg->r.SearchRequest.timelimit = 0;
	msg->r.SearchRequest.sizelimit = 0;
	msg->r.SearchRequest.attributesonly = False;
	msg->r.SearchRequest.filter = talloc_strdup(msg->mem_ctx, "(objectclass=*)");
	msg->r.SearchRequest.num_attributes = 0;
	msg->r.SearchRequest.attributes = NULL;

	if (!ldap_setsearchent(conn, msg, NULL)) {
		printf("Could not setsearchent\n");
		return False;
	}

	result = ldap_getsearchent(conn, NULL);
	if (result) {
		int i;
		struct ldap_SearchResEntry *r = &result->r.SearchResultEntry;
		
		DEBUG(1,("\tdn: %s\n", r->dn));
		for (i=0; i<r->num_attributes; i++) {
			int j;
			for (j=0; j<r->attributes[i].num_values; j++) {
				DEBUG(1,("\t%s: %d %.*s\n", r->attributes[i].name,
					 r->attributes[i].values[j].length,
					 r->attributes[i].values[j].length,
					 (char *)r->attributes[i].values[j].data));
				if (!(*basedn) && 
				    strcasecmp("defaultNamingContext",r->attributes[i].name)==0) {
					 *basedn = talloc_asprintf(conn->mem_ctx, "%.*s",
					 r->attributes[i].values[j].length,
					 (char *)r->attributes[i].values[j].data);
				}
			}
		}
	} else {
		ret = False;
	}

	ldap_endsearchent(conn, NULL);

	return ret;
}

static BOOL test_compare_sasl(struct ldap_connection *conn, const char *basedn)
{
	BOOL ret = True;
	struct ldap_message *msg, *result;
	const char *val;

	printf("Testing SASL Compare: %s\n", basedn);

	if (!basedn) {
		return False;
	}

	conn->next_msgid = 55;

	msg = new_ldap_message();
	if (!msg) {
		return False;
	}

	msg->type = LDAP_TAG_CompareRequest;
	msg->r.CompareRequest.dn = basedn;
	msg->r.CompareRequest.attribute = talloc_strdup(msg->mem_ctx, "objectClass");
	val = "domain";
	msg->r.CompareRequest.value = data_blob_talloc(msg->mem_ctx, val, strlen(val));

	if (!ldap_sasl_send_msg(conn, msg, NULL)) {
		return False;
	}

	DEBUG(5,("Code: %d DN: [%s] ERROR:[%s] REFERRAL:[%s]\n",
		msg->r.CompareResponse.resultcode,
		msg->r.CompareResponse.dn,
		msg->r.CompareResponse.errormessage,
		msg->r.CompareResponse.referral));

	return True;
	if (!result) {
		return False;
	}

	if (result->type != LDAP_TAG_CompareResponse) {
		return False;
	}

	return ret;
}

BOOL torture_ldap_basic(void)
{
        NTSTATUS status;
        struct ldap_connection *conn;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	const char *host = lp_parm_string(-1, "torture", "host");
	const char *username = lp_parm_string(-1, "torture", "username");
	const char *domain = lp_parm_string(-1, "torture", "userdomain");
	const char *password = lp_parm_string(-1, "torture", "password");
	const char *userdn = lp_parm_string(-1, "torture", "ldap_userdn");
	/*const char *basedn = lp_parm_string(-1, "torture", "ldap_basedn");*/
	const char *secret = lp_parm_string(-1, "torture", "ldap_secret");
	char *url;
	char *basedn;

	mem_ctx = talloc_init("torture_ldap_basic");

	url = talloc_asprintf(mem_ctx, "ldap://%s/", host);

	status = torture_ldap_connection(&conn, url, userdn, secret);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	/* other basic tests here */

	if (!test_multibind(conn, userdn, secret)) {
		ret = False;
	}

	if (!test_search_rootDSE(conn, &basedn)) {
		ret = False;
	}

	if (!test_bind_sasl(conn, username, domain, password)) {
		ret = False;
	}

	if (!test_compare_sasl(conn, basedn)) {
		ret = False;
	}

	/* no more test we are closing */

	talloc_destroy(mem_ctx);

        torture_ldap_close(conn);

	return ret;
}

