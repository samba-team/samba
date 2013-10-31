/* 
   Unix SMB/CIFS mplementation.

   test CLDAP/LDAP netlogon operations
   
   Copyright (C) Andrew Tridgell 2005
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

#include "includes.h"
#include "libcli/cldap/cldap.h"
#include "libcli/ldap/ldap_client.h"
#include "libcli/ldap/ldap_ndr.h"
#include "librpc/gen_ndr/netlogon.h"
#include "param/param.h"
#include "../lib/tsocket/tsocket.h"

#include "torture/torture.h"
#include "torture/ldap/proto.h"

#define CHECK_STATUS(status, correct) torture_assert_ntstatus_equal(tctx, status, correct, "incorrect status")

#define CHECK_VAL(v, correct) torture_assert_int_equal(tctx, (v), (correct), "incorrect value");

#define CHECK_STRING(v, correct) torture_assert_str_equal(tctx, v, correct, "incorrect value");

typedef NTSTATUS (*request_netlogon_t)(void *con,
				       TALLOC_CTX *mem_ctx,
				       struct cldap_netlogon *io);

typedef NTSTATUS (*request_rootdse_t)(void *con,
				     TALLOC_CTX *mem_ctx,
				     struct cldap_search *io);

/*
  test netlogon operations
*/
static bool test_ldap_netlogon(struct torture_context *tctx,
			       request_netlogon_t request_netlogon,
			       void *cldap,
			       const char *dest)
{
	NTSTATUS status;
	struct cldap_netlogon search, empty_search;
	struct netlogon_samlogon_response n1;
	struct GUID guid;
	int i;

	ZERO_STRUCT(search);
	search.in.dest_address = NULL;
	search.in.dest_port = 0;
	search.in.acct_control = -1;
	search.in.version = NETLOGON_NT_VERSION_5 | NETLOGON_NT_VERSION_5EX;
	search.in.map_response = true;

	empty_search = search;

	printf("Trying without any attributes\n");
	search = empty_search;
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	n1 = search.out.netlogon;

	search.in.user         = "Administrator";
	search.in.realm        = n1.data.nt5_ex.dns_domain;
	search.in.host         = "__cldap_torture__";

	printf("Scanning for netlogon levels\n");
	for (i=0;i<256;i++) {
		search.in.version = i;
		printf("Trying netlogon level %d\n", i);
		status = request_netlogon(cldap, tctx, &search);
		CHECK_STATUS(status, NT_STATUS_OK);
	}

	printf("Scanning for netlogon level bits\n");
	for (i=0;i<31;i++) {
		search.in.version = (1<<i);
		printf("Trying netlogon level 0x%x\n", i);
		status = request_netlogon(cldap, tctx, &search);
		CHECK_STATUS(status, NT_STATUS_OK);
	}

	search.in.version = NETLOGON_NT_VERSION_5|NETLOGON_NT_VERSION_5EX|NETLOGON_NT_VERSION_IP;
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with User=NULL\n");
	search.in.user = NULL;
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(search.out.netlogon.data.nt5_ex.command, LOGON_SAM_LOGON_RESPONSE_EX);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.user_name, "");
	torture_assert(tctx,
		       strstr(search.out.netlogon.data.nt5_ex.pdc_name, "\\\\") == NULL,
		       "PDC name should not be in UNC form");

	printf("Trying with User=Administrator\n");
	search.in.user = "Administrator";
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(search.out.netlogon.data.nt5_ex.command, LOGON_SAM_LOGON_USER_UNKNOWN_EX);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.user_name, search.in.user);
	torture_assert(tctx,
		       strstr(search.out.netlogon.data.nt5_ex.pdc_name, "\\\\") == NULL,
		       "PDC name should not be in UNC form");

	search.in.version = NETLOGON_NT_VERSION_5;
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with User=NULL\n");
	search.in.user = NULL;
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(search.out.netlogon.data.nt5_ex.command, LOGON_SAM_LOGON_RESPONSE);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.user_name, "");
	torture_assert(tctx,
		       strstr(search.out.netlogon.data.nt5_ex.pdc_name, "\\\\") != NULL,
		       "PDC name should be in UNC form");

	printf("Trying with User=Administrator\n");
	search.in.user = "Administrator";
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(search.out.netlogon.data.nt5_ex.command, LOGON_SAM_LOGON_USER_UNKNOWN);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.user_name, search.in.user);
	torture_assert(tctx,
		       strstr(search.out.netlogon.data.nt5_ex.pdc_name, "\\\\") != NULL,
		       "PDC name should be in UNC form");

	search.in.version = NETLOGON_NT_VERSION_5 | NETLOGON_NT_VERSION_5EX;

	printf("Trying with a GUID\n");
	search.in.realm       = NULL;
	search.in.domain_guid = GUID_string(tctx, &n1.data.nt5_ex.domain_uuid);
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(search.out.netlogon.data.nt5_ex.command, LOGON_SAM_LOGON_USER_UNKNOWN_EX);
	CHECK_STRING(GUID_string(tctx, &search.out.netlogon.data.nt5_ex.domain_uuid), search.in.domain_guid);
	torture_assert(tctx,
		       strstr(search.out.netlogon.data.nt5_ex.pdc_name, "\\\\") == NULL,
		       "PDC name should not be in UNC form");

	printf("Trying with a incorrect GUID\n");
	guid = GUID_random();
	search.in.user        = NULL;
	search.in.domain_guid = GUID_string(tctx, &guid);
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_NOT_FOUND);

	printf("Trying with a AAC\n");
	search.in.acct_control = ACB_WSTRUST|ACB_SVRTRUST;
	search.in.realm = n1.data.nt5_ex.dns_domain;
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(search.out.netlogon.data.nt5_ex.command, LOGON_SAM_LOGON_RESPONSE_EX);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.user_name, "");

	printf("Trying with a zero AAC\n");
	search.in.acct_control = 0x0;
	search.in.realm = n1.data.nt5_ex.dns_domain;
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(search.out.netlogon.data.nt5_ex.command, LOGON_SAM_LOGON_RESPONSE_EX);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.user_name, "");

	printf("Trying with a zero AAC and user=Administrator\n");
	search.in.acct_control = 0x0;
	search.in.user = "Administrator";
	search.in.realm = n1.data.nt5_ex.dns_domain;
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(search.out.netlogon.data.nt5_ex.command, LOGON_SAM_LOGON_USER_UNKNOWN_EX);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.user_name, "Administrator");

	printf("Trying with a bad AAC\n");
	search.in.user = NULL;
	search.in.acct_control = 0xFF00FF00;
	search.in.realm = n1.data.nt5_ex.dns_domain;
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(search.out.netlogon.data.nt5_ex.command, LOGON_SAM_LOGON_RESPONSE_EX);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.user_name, "");

	printf("Trying with a user only\n");
	search = empty_search;
	search.in.user = "Administrator";
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.forest, n1.data.nt5_ex.dns_domain);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.dns_domain, n1.data.nt5_ex.dns_domain);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.domain_name, n1.data.nt5_ex.domain_name);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.pdc_name, n1.data.nt5_ex.pdc_name);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.user_name, search.in.user);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.server_site, n1.data.nt5_ex.server_site);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.client_site, n1.data.nt5_ex.client_site);

	printf("Trying with just a bad username\n");
	search.in.user = "___no_such_user___";
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(search.out.netlogon.data.nt5_ex.command, LOGON_SAM_LOGON_USER_UNKNOWN_EX);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.forest, n1.data.nt5_ex.dns_domain);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.dns_domain, n1.data.nt5_ex.dns_domain);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.domain_name, n1.data.nt5_ex.domain_name);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.pdc_name, n1.data.nt5_ex.pdc_name);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.user_name, search.in.user);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.server_site, n1.data.nt5_ex.server_site);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.client_site, n1.data.nt5_ex.client_site);

	printf("Trying with just a bad domain\n");
	search = empty_search;
	search.in.realm = "___no_such_domain___";
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_NOT_FOUND);

	printf("Trying with a incorrect domain and correct guid\n");
	search.in.domain_guid = GUID_string(tctx, &n1.data.nt5_ex.domain_uuid);
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(search.out.netlogon.data.nt5_ex.command, LOGON_SAM_LOGON_RESPONSE_EX);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.forest, n1.data.nt5_ex.dns_domain);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.dns_domain, n1.data.nt5_ex.dns_domain);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.domain_name, n1.data.nt5_ex.domain_name);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.pdc_name, n1.data.nt5_ex.pdc_name);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.user_name, "");
	CHECK_STRING(search.out.netlogon.data.nt5_ex.server_site, n1.data.nt5_ex.server_site);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.client_site, n1.data.nt5_ex.client_site);

	printf("Trying with a incorrect domain and incorrect guid\n");
	search.in.domain_guid = GUID_string(tctx, &guid);
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_NOT_FOUND);
	CHECK_VAL(search.out.netlogon.data.nt5_ex.command, LOGON_SAM_LOGON_RESPONSE_EX);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.forest, n1.data.nt5_ex.dns_domain);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.dns_domain, n1.data.nt5_ex.dns_domain);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.domain_name, n1.data.nt5_ex.domain_name);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.pdc_name, n1.data.nt5_ex.pdc_name);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.user_name, "");
	CHECK_STRING(search.out.netlogon.data.nt5_ex.server_site, n1.data.nt5_ex.server_site);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.client_site, n1.data.nt5_ex.client_site);

	printf("Trying with a incorrect GUID and correct domain\n");
	search.in.domain_guid = GUID_string(tctx, &guid);
	search.in.realm = n1.data.nt5_ex.dns_domain;
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(search.out.netlogon.data.nt5_ex.command, LOGON_SAM_LOGON_RESPONSE_EX);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.forest, n1.data.nt5_ex.dns_domain);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.dns_domain, n1.data.nt5_ex.dns_domain);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.domain_name, n1.data.nt5_ex.domain_name);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.pdc_name, n1.data.nt5_ex.pdc_name);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.user_name, "");
	CHECK_STRING(search.out.netlogon.data.nt5_ex.server_site, n1.data.nt5_ex.server_site);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.client_site, n1.data.nt5_ex.client_site);

	printf("Proof other results\n");
	search.in.user = "Administrator";
	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.forest, n1.data.nt5_ex.dns_domain);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.dns_domain, n1.data.nt5_ex.dns_domain);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.domain_name, n1.data.nt5_ex.domain_name);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.pdc_name, n1.data.nt5_ex.pdc_name);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.user_name, search.in.user);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.server_site, n1.data.nt5_ex.server_site);
	CHECK_STRING(search.out.netlogon.data.nt5_ex.client_site, n1.data.nt5_ex.client_site);

	return true;
}

/*
  test cldap netlogon server type flags
*/
static bool test_ldap_netlogon_flags(struct torture_context *tctx,
				     request_netlogon_t request_netlogon,
				     void *cldap,
				     const char *dest)
{
	NTSTATUS status;
	struct cldap_netlogon search;
	struct netlogon_samlogon_response n1;
	uint32_t server_type;

	printf("Printing out netlogon server type flags: %s\n", dest);

	ZERO_STRUCT(search);
	search.in.dest_address = NULL;
	search.in.dest_port = 0;
	search.in.acct_control = -1;
	search.in.version = NETLOGON_NT_VERSION_5 | NETLOGON_NT_VERSION_5EX;
	search.in.map_response = true;

	status = request_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	n1 = search.out.netlogon;
	if (n1.ntver == NETLOGON_NT_VERSION_5)
		server_type = n1.data.nt5.server_type;
	else if (n1.ntver == NETLOGON_NT_VERSION_5EX)
		server_type = n1.data.nt5_ex.server_type;	

	printf("The word is: %i\n", server_type);
	if (server_type & NBT_SERVER_PDC)
		printf("NBT_SERVER_PDC ");
	if (server_type & NBT_SERVER_GC)
		printf("NBT_SERVER_GC ");
	if (server_type & NBT_SERVER_LDAP)
		printf("NBT_SERVER_LDAP ");
	if (server_type & NBT_SERVER_DS)
		printf("NBT_SERVER_DS ");
	if (server_type & NBT_SERVER_KDC)
		printf("NBT_SERVER_KDC ");
	if (server_type & NBT_SERVER_TIMESERV)
		printf("NBT_SERVER_TIMESERV ");
	if (server_type & NBT_SERVER_CLOSEST)
		printf("NBT_SERVER_CLOSEST ");
	if (server_type & NBT_SERVER_WRITABLE)
		printf("NBT_SERVER_WRITABLE ");
	if (server_type & NBT_SERVER_GOOD_TIMESERV)
		printf("NBT_SERVER_GOOD_TIMESERV ");
	if (server_type & NBT_SERVER_NDNC)
		printf("NBT_SERVER_NDNC ");
	if (server_type & NBT_SERVER_SELECT_SECRET_DOMAIN_6)
		printf("NBT_SERVER_SELECT_SECRET_DOMAIN_6");
	if (server_type & NBT_SERVER_FULL_SECRET_DOMAIN_6)
		printf("NBT_SERVER_FULL_SECRET_DOMAIN_6");
	if (server_type & DS_DNS_CONTROLLER)
		printf("DS_DNS_CONTROLLER ");
	if (server_type & DS_DNS_DOMAIN)
		printf("DS_DNS_DOMAIN ");
	if (server_type & DS_DNS_FOREST_ROOT)
		printf("DS_DNS_FOREST_ROOT ");

	printf("\n");

	return true;
}

static NTSTATUS tcp_ldap_rootdse(void *data,
				 TALLOC_CTX *mem_ctx,
				 struct cldap_search *io)
{
	struct ldap_connection *conn = talloc_get_type(data,
						       struct ldap_connection);
	struct ldap_message *msg, *result;
	struct ldap_request *req;
	int i;
	NTSTATUS status;

	msg = new_ldap_message(mem_ctx);
	if (!msg) {
		return NT_STATUS_NO_MEMORY;
	}

	msg->type = LDAP_TAG_SearchRequest;
	msg->r.SearchRequest.basedn = "";
	msg->r.SearchRequest.scope = LDAP_SEARCH_SCOPE_BASE;
	msg->r.SearchRequest.deref = LDAP_DEREFERENCE_NEVER;
	msg->r.SearchRequest.timelimit = 0;
	msg->r.SearchRequest.sizelimit = 0;
	msg->r.SearchRequest.attributesonly = false;
	msg->r.SearchRequest.tree = ldb_parse_tree(msg, io->in.filter);
	msg->r.SearchRequest.num_attributes = str_list_length(io->in.attributes);
	msg->r.SearchRequest.attributes = io->in.attributes;

	req = ldap_request_send(conn, msg);
	if (req == NULL) {
		printf("Could not setup ldap search\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	ZERO_STRUCT(io->out);
	for (i = 0; i < 2; ++i) {
		status = ldap_result_n(req, i, &result);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		switch (result->type) {
		case LDAP_TAG_SearchResultEntry:
			if (i != 0) {
				return NT_STATUS_LDAP(LDAP_PROTOCOL_ERROR);
			}
			io->out.response = &result->r.SearchResultEntry;
			break;
		case LDAP_TAG_SearchResultDone:
			io->out.result = &result->r.SearchResultDone;
			if (io->out.result->resultcode != LDAP_SUCCESS) {
				return NT_STATUS_LDAP(io->out.result->resultcode);
			}

			return NT_STATUS_OK;
		default:
			return NT_STATUS_LDAP(LDAP_PROTOCOL_ERROR);
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS tcp_ldap_netlogon(void *conn,
				  TALLOC_CTX *mem_ctx,
				  struct cldap_netlogon *io)
{
	struct cldap_search search;
	struct ldap_SearchResEntry *res;
	NTSTATUS status;
	DATA_BLOB *blob;

	ZERO_STRUCT(search);
	search.in.attributes = (const char *[]) { "netlogon", NULL };
	search.in.filter =  cldap_netlogon_create_filter(mem_ctx, io);
	if (search.in.filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = tcp_ldap_rootdse(conn, mem_ctx, &search);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	res = search.out.response;
	if (res == NULL) {
		return NT_STATUS_NOT_FOUND;
	}

	if (res->num_attributes != 1 ||
	    strcasecmp(res->attributes[0].name, "netlogon") != 0 ||
	    res->attributes[0].num_values != 1 ||
	    res->attributes[0].values->length < 2) {
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	blob = res->attributes[0].values;
	status = pull_netlogon_samlogon_response(blob, mem_ctx,
						 &io->out.netlogon);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (io->in.map_response) {
		map_netlogon_samlogon_response(&io->out.netlogon);
	}

	return NT_STATUS_OK;
}

static NTSTATUS udp_ldap_rootdse(void *data, TALLOC_CTX *mem_ctx,
				 struct cldap_search *io)
{
	struct cldap_socket *cldap = talloc_get_type(data,
						     struct cldap_socket);

	return cldap_search(cldap, mem_ctx, io);
}

static bool test_netlogon_extra_attrs(struct torture_context *tctx,
				      request_rootdse_t request_rootdse,
				      void *conn)
{
	struct cldap_search io;
	NTSTATUS status;
	const char *attrs[] = {
		"netlogon",
		"supportedCapabilities",
		NULL
	};
	const char *attrs2[] = { "netlogon", "*", NULL };
	struct ldb_message ldbmsg = { NULL, 0, NULL };

	ZERO_STRUCT(io);
	io.in.dest_address = NULL;
	io.in.dest_port = 0;
	io.in.timeout   = 2;
	io.in.retries   = 2;
	/* Additional attributes may be requested next to netlogon */
	torture_comment(tctx, "Requesting netlogon with additional attribute\n");
	io.in.filter =
		talloc_asprintf(tctx, "(&"
				"(NtVer=%s)(AAC=%s)"
				/* Query for LDAP_CAP_ACTIVE_DIRECTORY_OID */
				"(supportedCapabilities=1.2.840.113556.1.4.800)"
				")",
				ldap_encode_ndr_uint32(tctx,
						       NETLOGON_NT_VERSION_5EX),
				ldap_encode_ndr_uint32(tctx, 0));
	torture_assert(tctx, io.in.filter != NULL, "OOM");
	io.in.attributes = attrs;
	status = request_rootdse(conn, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	torture_assert(tctx, io.out.response != NULL, "No Entries found.");
	CHECK_VAL(io.out.response->num_attributes, 2);

	/* netlogon + '*' attr return zero results */
	torture_comment(tctx, "Requesting netlogon and '*' attributes\n");
	io.in.attributes = attrs2;
	status = request_rootdse(conn, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	torture_assert(tctx, io.out.response != NULL, "No Entries found.");
	ldbmsg.num_elements = io.out.response->num_attributes;
	ldbmsg.elements = io.out.response->attributes;
	torture_assert(tctx, ldb_msg_find_element(&ldbmsg, "netlogon") != NULL,
		       "Attribute netlogon not found in Result Entry\n");

	/* Wildcards are not allowed in filters when netlogon is requested. */
	torture_comment(tctx, "Requesting netlogon with invalid attr filter\n");
	io.in.filter =
		talloc_asprintf(tctx,
				"(&(NtVer=%s)(AAC=%s)(supportedCapabilities=*))",
				ldap_encode_ndr_uint32(tctx,
						       NETLOGON_NT_VERSION_5EX),
				ldap_encode_ndr_uint32(tctx, 0));
	torture_assert(tctx, io.in.filter != NULL, "OOM");
	io.in.attributes = attrs;
	status = request_rootdse(conn, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	torture_assert(tctx, io.out.response == NULL,
		       "A wildcard filter should return no entries.");

	return true;
}


bool torture_netlogon_tcp(struct torture_context *tctx)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	bool ret = true;
	NTSTATUS status;
	struct ldap_connection *conn;
	TALLOC_CTX *mem_ctx;
	const char *url;

	mem_ctx = talloc_init("torture_ldap_netlogon");

	url = talloc_asprintf(mem_ctx, "ldap://%s/", host);

	status = torture_ldap_connection(tctx, &conn, url);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	ret &= test_ldap_netlogon(tctx, tcp_ldap_netlogon, conn, host);
	ret &= test_ldap_netlogon_flags(tctx, tcp_ldap_netlogon, conn, host);
	ret &= test_netlogon_extra_attrs(tctx, tcp_ldap_rootdse, conn);

	return ret;
}

static NTSTATUS udp_ldap_netlogon(void *data,
				  TALLOC_CTX *mem_ctx,
				  struct cldap_netlogon *io)
{
	struct cldap_socket *cldap = talloc_get_type(data,
						     struct cldap_socket);

	return cldap_netlogon(cldap, mem_ctx, io);
}

bool torture_netlogon_udp(struct torture_context *tctx)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	bool ret = true;
	int r;
	struct cldap_socket *cldap;
	NTSTATUS status;
	struct tsocket_address *dest_addr;

	r = tsocket_address_inet_from_strings(tctx, "ip",
					      host,
					      lpcfg_cldap_port(tctx->lp_ctx),
					      &dest_addr);
	CHECK_VAL(r, 0);

	/* cldap_socket_init should now know about the dest. address */
	status = cldap_socket_init(tctx, NULL, dest_addr, &cldap);
	CHECK_STATUS(status, NT_STATUS_OK);

	ret &= test_ldap_netlogon(tctx, udp_ldap_netlogon, cldap, host);
	ret &= test_ldap_netlogon_flags(tctx, udp_ldap_netlogon, cldap, host);
	ret &= test_netlogon_extra_attrs(tctx, udp_ldap_rootdse, cldap);

	return ret;
}
