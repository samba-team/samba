/* 
   Unix SMB/CIFS implementation.

   local testing of RPC binding string parsing 

   Copyright (C) Jelmer Vernooij 2004
   
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
#include "librpc/gen_ndr/epmapper.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "torture/torture.h"
#include "torture/local/proto.h"
#include "lib/util/util_net.h"

static bool test_BindingString(struct torture_context *tctx,
							   const void *test_data)
{
	const char *binding = test_data;
	struct dcerpc_binding *b, *b2;
	char *s, *s2, *p;
	struct epm_tower tower;
	TALLOC_CTX *mem_ctx = tctx;
	const char *host;
	struct GUID object;

	/* Parse */
	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(mem_ctx, binding, &b),
		"Error parsing binding string");

	object = dcerpc_binding_get_object(b);

	s = dcerpc_binding_string(mem_ctx, b);
	torture_assert(tctx, s != NULL, "Error converting binding back to string");

	torture_assert_casestr_equal(tctx, binding, s, 
		"Mismatch while comparing original and regenerated binding strings");

	/* Generate protocol towers */
	torture_assert_ntstatus_ok(tctx, dcerpc_binding_build_tower(mem_ctx, b, &tower),
		"Error generating protocol tower");

	/* Convert back to binding and then back to string and compare */

	torture_assert_ntstatus_ok(tctx, dcerpc_binding_from_tower(mem_ctx, &tower, &b2),
			    "Error generating binding from tower for original binding");

	/* The tower doesn't contain the object */
	torture_assert_ntstatus_ok(tctx, dcerpc_binding_set_object(b2, object),
			    "set object on tower binding");

	s = dcerpc_binding_string(mem_ctx, b);
	torture_assert(tctx, s != NULL, "Error converting binding back to string for (stripped down)"); 

	/*
	 * Compare to a stripped down version of the binding string because
	 * the protocol tower doesn't contain the extra option data
	 *
	 * We remove all options except of the endpoint.
	 */
	p = strchr(s, '[');
	if (p != NULL) {
		char *p2;

		p2 = strchr(p + 1, ',');
		if (p2 != NULL) {
			/*
			 * We only look at the first option,
			 * which might be the endpoint.
			 */
			p2[0] = ']';
			p2[1] = '\0';
		}

		p2 = strchr(p + 1, '=');
		if (p2 != NULL) {
			/*
			 * It's not the endpoint, so remove the
			 * whole option section.
			 */
			*p = '\0';
		}
	}

	s2 = dcerpc_binding_string(mem_ctx, b2);
	torture_assert(tctx, s != NULL, "Error converting binding back to string"); 

	host = dcerpc_binding_get_string_option(b, "host");
	if (host && is_ipaddress_v4(host)) {
		torture_assert_casestr_equal(tctx, s, s2, "Mismatch while comparing original and from protocol tower generated binding strings");
	}

	return true;
}

static const char *test_strings[] = {
	"ncacn_np:", 
	"ncalrpc:", 
	"ncalrpc:[,Security=Sane]", 
	"ncacn_np:[rpcecho]",
	"ncacn_np:127.0.0.1[rpcecho]",
	"ncacn_ip_tcp:127.0.0.1",
	"ncacn_ip_tcp:127.0.0.1[20]",
	"ncacn_ip_tcp:127.0.0.1[20,sign]",
	"ncacn_ip_tcp:127.0.0.1[20,sign,Security=Foobar]",
	"ncacn_http:127.0.0.1",
	"ncacn_http:127.0.0.1[78]",
	"ncacn_http:127.0.0.1[78,ProxyServer=myproxy:3128]",
	"ncacn_np:localhost[rpcecho]",
	"ncacn_np:[/pipe/rpcecho]",
	"ncacn_np:localhost[/pipe/rpcecho,sign,seal]",
	"ncacn_np:[,sign]",
	"ncadg_ip_udp:",
	"308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_np:localhost",
	"308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_ip_tcp:127.0.0.1",
	"ncacn_unix_stream:[/tmp/epmapper]",
	"ncalrpc:[IDENTIFIER]",
	"ncacn_unix_stream:[/tmp/epmapper,sign]",
	"ncacn_ip_tcp:127.0.0.1[75,target_hostname=port75.example.com,target_principal=host/port75.example.com]",
	"ncacn_ip_tcp:127.0.0.1[75,connect,target_hostname=port75.example.com,target_principal=host/port75.example.com,assoc_group_id=0x01234567]",
	"ncacn_ip_tcp:127.0.0.1[75,packet,target_hostname=port75.example.com,target_principal=host/port75.example.com,assoc_group_id=0x01234567]",
	"ncacn_ip_tcp:::",
	"ncacn_ip_tcp:::[75]",
	"ncacn_ip_tcp:FD00::5357:5F00",
	"ncacn_ip_tcp:FD00::5357:5F00[75]",
	"ncacn_ip_tcp:FD00::5357:5F00[,target_hostname=port75.example.com]",
	"ncacn_ip_tcp:FD00::5357:5F00[75,target_hostname=port75.example.com]",
	"ncacn_ip_tcp:fe80::5357:5F00%75",
	"ncacn_ip_tcp:fe80::5357:5F00%75[75]",
	"ncacn_ip_tcp:fe80::5357:5F00%75[,target_hostname=port75.example.com]",
	"ncacn_ip_tcp:fe80::5357:5F00%75[75,target_hostname=port75.example.com]",
};

static bool test_parse_check_results(struct torture_context *tctx)
{
	struct dcerpc_binding *b;
	struct GUID uuid;
	struct GUID object;
	struct ndr_syntax_id abstract;
	enum dcerpc_transport_t transport;
	const char *endpoint;
	uint32_t flags;

	torture_assert_ntstatus_ok(tctx, 
				   GUID_from_string("308FB580-1EB2-11CA-923B-08002B1075A7", &uuid),
				   "parsing uuid");

	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(tctx, "ncacn_np:$SERVER", &b), "parse");
	transport = dcerpc_binding_get_transport(b);
	torture_assert(tctx, transport == NCACN_NP, "ncacn_np expected");
	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(tctx, "ncacn_ip_tcp:$SERVER", &b), "parse");
	transport = dcerpc_binding_get_transport(b);
	torture_assert(tctx, transport == NCACN_IP_TCP, "ncacn_ip_tcp expected");
	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(tctx, "ncacn_np:$SERVER[rpcecho]", &b), "parse");
	endpoint = dcerpc_binding_get_string_option(b, "endpoint");
	torture_assert_str_equal(tctx, endpoint, "rpcecho", "endpoint");
	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(tctx, "ncacn_np:$SERVER[/pipe/rpcecho]", &b), "parse");
	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(tctx, "ncacn_np:$SERVER[/pipe/rpcecho,sign,seal]", &b), "parse");
	flags = dcerpc_binding_get_flags(b);
	torture_assert(tctx, flags == DCERPC_SIGN+DCERPC_SEAL, "sign+seal flags");
	endpoint = dcerpc_binding_get_string_option(b, "endpoint");
	torture_assert_str_equal(tctx, endpoint, "/pipe/rpcecho", "endpoint");
	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(tctx, "ncacn_np:$SERVER[,sign]", &b), "parse");
	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(tctx, "ncacn_ip_tcp:$SERVER[,sign]", &b), "parse");
	endpoint = dcerpc_binding_get_string_option(b, "endpoint");
	torture_assert(tctx, endpoint == NULL, "endpoint");
	flags = dcerpc_binding_get_flags(b);
	torture_assert(tctx, flags == DCERPC_SIGN, "sign flag");
	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(tctx, "ncalrpc:", &b), "parse");
	transport = dcerpc_binding_get_transport(b);
	torture_assert(tctx, transport == NCALRPC, "ncalrpc expected");
	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(tctx, 
		"308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_np:$SERVER", &b), "parse");
	object = dcerpc_binding_get_object(b);
	abstract = dcerpc_binding_get_abstract_syntax(b);
	torture_assert(tctx, GUID_equal(&object, &uuid), "object uuid");
	torture_assert(tctx, ndr_syntax_id_equal(&abstract, &ndr_syntax_id_null),
		       "null abstract syntax");
	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(tctx, 
		"308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_ip_tcp:$SERVER", &b), "parse");
	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(tctx, "ncacn_ip_tcp:$SERVER[,sign,localaddress=192.168.1.1]", &b), "parse");
	transport = dcerpc_binding_get_transport(b);
	torture_assert(tctx, transport == NCACN_IP_TCP, "ncacn_ip_tcp expected");
	flags = dcerpc_binding_get_flags(b);
	torture_assert(tctx, flags == DCERPC_SIGN, "sign flag");
	torture_assert_str_equal(tctx, dcerpc_binding_get_string_option(b, "localaddress"),
				 "192.168.1.1", "localaddress");
	torture_assert_str_equal(tctx, "ncacn_ip_tcp:$SERVER[,sign,localaddress=192.168.1.1]",
				 dcerpc_binding_string(tctx, b), "back to string");
	torture_assert_str_equal(tctx, dcerpc_binding_get_string_option(b, "host"),
				 "$SERVER", "host");
	torture_assert_str_equal(tctx, dcerpc_binding_get_string_option(b, "target_hostname"),
				 "$SERVER", "target_hostname");

	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(tctx,
		"ncacn_ip_tcp:$HOST[,target_hostname=$HOSTNAME,target_principal=$PRINCIPAL]",
		&b), "parse");
	torture_assert_str_equal(tctx, dcerpc_binding_get_string_option(b, "host"),
				 "$HOST", "host");
	torture_assert_str_equal(tctx, dcerpc_binding_get_string_option(b, "target_hostname"),
				 "$HOSTNAME", "target_hostname");
	torture_assert_str_equal(tctx, dcerpc_binding_get_string_option(b, "target_principal"),
				 "$PRINCIPAL", "target_principal");
	torture_assert_str_equal(tctx,
				 dcerpc_binding_string(tctx, b),
		"ncacn_ip_tcp:$HOST[,target_hostname=$HOSTNAME,target_principal=$PRINCIPAL]",
				 "back to string");

	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(tctx,
		"ncacn_ip_tcp:$HOST[,connect,target_hostname=$HOSTNAME,target_principal=$PRINCIPAL,assoc_group_id=0x01234567]",
		&b), "parse");
	flags = dcerpc_binding_get_flags(b);
	torture_assert(tctx, flags == DCERPC_CONNECT, "connect flag");
	torture_assert_str_equal(tctx, dcerpc_binding_get_string_option(b, "host"),
				 "$HOST", "host");
	torture_assert_str_equal(tctx, dcerpc_binding_get_string_option(b, "target_hostname"),
				 "$HOSTNAME", "target_hostname");
	torture_assert_str_equal(tctx, dcerpc_binding_get_string_option(b, "target_principal"),
				 "$PRINCIPAL", "target_principal");
	torture_assert_int_equal(tctx, dcerpc_binding_get_assoc_group_id(b), 0x01234567,
				 "assoc_group_id");
	torture_assert_str_equal(tctx,
				 dcerpc_binding_string(tctx, b),
		"ncacn_ip_tcp:$HOST[,connect,target_hostname=$HOSTNAME,target_principal=$PRINCIPAL,assoc_group_id=0x01234567]",
				 "back to string");

	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(tctx,
		"ncacn_ip_tcp:$HOST[,packet,target_hostname=$HOSTNAME,target_principal=$PRINCIPAL,assoc_group_id=0x01234567]",
		&b), "parse");
	flags = dcerpc_binding_get_flags(b);
	torture_assert(tctx, flags == DCERPC_PACKET, "packet flag");
	torture_assert_str_equal(tctx, dcerpc_binding_get_string_option(b, "host"),
				 "$HOST", "host");
	torture_assert_str_equal(tctx, dcerpc_binding_get_string_option(b, "target_hostname"),
				 "$HOSTNAME", "target_hostname");
	torture_assert_str_equal(tctx, dcerpc_binding_get_string_option(b, "target_principal"),
				 "$PRINCIPAL", "target_principal");
	torture_assert_int_equal(tctx, dcerpc_binding_get_assoc_group_id(b), 0x01234567,
				 "assoc_group_id");
	torture_assert_str_equal(tctx,
				 dcerpc_binding_string(tctx, b),
		"ncacn_ip_tcp:$HOST[,packet,target_hostname=$HOSTNAME,target_principal=$PRINCIPAL,assoc_group_id=0x01234567]",
				 "back to string");

	return true;
}

static bool test_no_transport(struct torture_context *tctx, const void *test_data)
{
	const char *binding = test_data;
	struct dcerpc_binding *b;
	enum dcerpc_transport_t transport;
	const char *s;

	/* Parse */
	torture_assert_ntstatus_ok(tctx, dcerpc_parse_binding(tctx, binding, &b),
		"Error parsing binding string");

	transport = dcerpc_binding_get_transport(b);
	torture_assert(tctx, transport == NCA_UNKNOWN, "invalid transport");

	s = dcerpc_binding_string(tctx, b);
	torture_assert(tctx, s != NULL, "Error converting binding back to string");

	torture_assert_casestr_equal(tctx, binding, s, 
		"Mismatch while comparing original and regenerated binding strings");

	return true;
}

static const char *test_no_strings[] = {
	"port75.example.com",
	"port75.example.com[75]",
	"127.0.0.1",
	"127.0.0.1[75]",
	"127.0.0.1[,target_hostname=port75.example.com]",
	"127.0.0.1[75,target_hostname=port75.example.com]",
	"::",
	"::[75]",
	"::[,target_hostname=port75.example.com]",
	"::[75,target_hostname=port75.example.com]",
	"FD00::5357:5F00",
	"FD00::5357:5F00[75]",
	"FD00::5357:5F00[,target_hostname=port75.example.com]",
	"FD00::5357:5F00[75,target_hostname=port75.example.com]",
	"fe80::5357:5F00%75",
	"fe80::5357:5F00%75[75]",
	"fe80::5357:5F00%75[,target_hostname=port75.example.com]",
	"fe80::5357:5F00%75[75,target_hostname=port75.example.com]",
};

struct torture_suite *torture_local_binding_string(TALLOC_CTX *mem_ctx)
{
	int i;
	struct torture_suite *suite = torture_suite_create(mem_ctx, "binding");

	for (i = 0; i < ARRAY_SIZE(test_strings); i++) {
		torture_suite_add_simple_tcase_const(suite, test_strings[i],
						test_BindingString,
						test_strings[i]);
	}

	for (i = 0; i < ARRAY_SIZE(test_no_strings); i++) {
		torture_suite_add_simple_tcase_const(suite, test_no_strings[i],
						     test_no_transport,
						     test_no_strings[i]);
	}

	torture_suite_add_simple_test(suite, "parsing results",
			test_parse_check_results);

	return suite;
}
