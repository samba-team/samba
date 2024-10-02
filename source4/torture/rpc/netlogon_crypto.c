/*
   Unix SMB/CIFS implementation.

   test suite for netlogon rpc operations

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003-2004
   Copyright (C) Tim Potter      2003
   Copyright (C) Matthias Dieter Wallnöfer            2009-2010

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
#include "lib/replace/system/network.h"
#include "lib/cmdline/cmdline.h"
#include "torture/rpc/torture_rpc.h"
#include "libcli/auth/libcli_auth.h"
#include "librpc/gen_ndr/ndr_netlogon_c.h"
#include "param/param.h"
#include "lib/param/loadparm.h"
#include "libcli/security/security.h"

#undef strcasecmp

#define TEST_MACHINE_NAME "torturetest"

static bool test_ServerAuth3Crypto(struct dcerpc_pipe *p,
				   struct torture_context *tctx,
				   uint32_t negotiate_flags,
				   struct cli_credentials *machine_credentials,
				   bool force_client_rc4)
{
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate3 a;
	struct netr_Credential netr_creds1 = {
		.data = {0},
	};
	struct netr_Credential netr_creds2 = {
		.data = {0},
	};
	struct netr_Credential netr_creds3 = {
		.data = {0},
	};
	struct netlogon_creds_CredentialState *creds_state = NULL;
	struct samr_Password machine_password = {
		.hash = {0},
	};
	const char *machine_name = NULL;
	const char *plain_pass = NULL;
	struct dcerpc_binding_handle *b = NULL;
	uint32_t rid = 0;
	NTSTATUS status;
	bool weak_crypto_allowed =
		(lpcfg_weak_crypto(tctx->lp_ctx) ==
		 SAMBA_WEAK_CRYPTO_ALLOWED);

	if (p == NULL) {
		return false;
	}
	b = p->binding_handle;

	ZERO_STRUCT(r);
	ZERO_STRUCT(a);

	torture_comment(tctx, "client negotiate_flags=0x%08x\n", negotiate_flags);

	machine_name = cli_credentials_get_workstation(machine_credentials);
	torture_assert_not_null(tctx, machine_name, "machine name is not set");

	plain_pass = cli_credentials_get_password(machine_credentials);
	torture_assert_not_null(tctx, plain_pass, "plain_pass is not set");


	torture_comment(tctx, "Testing ServerReqChallenge\n");

	r.in.server_name = NULL;
	r.in.computer_name = machine_name;
	r.in.credentials = &netr_creds1;
	r.out.return_credentials = &netr_creds2;

	netlogon_creds_random_challenge(&netr_creds1);

	status = dcerpc_netr_ServerReqChallenge_r(b, tctx, &r);
	torture_assert_ntstatus_ok(tctx,
				   status,
				   "ServerReqChallenge failed");
	torture_assert_ntstatus_ok(tctx,
				   r.out.result,
				   "ServerReqChallenge failed");

	E_md4hash(plain_pass, machine_password.hash);

	a.in.server_name = NULL;
	a.in.account_name = talloc_asprintf(tctx, "%s$", machine_name);
	a.in.secure_channel_type =
		cli_credentials_get_secure_channel_type(machine_credentials);
	a.in.computer_name = machine_name;
	a.in.negotiate_flags = &negotiate_flags;
	a.in.credentials = &netr_creds3;
	a.out.return_credentials = &netr_creds3;
	a.out.negotiate_flags = &negotiate_flags;
	a.out.rid = &rid;

	if (force_client_rc4) {
		GNUTLS_FIPS140_SET_LAX_MODE();
	}
	creds_state = netlogon_creds_client_init(tctx,
						 a.in.account_name,
						 a.in.computer_name,
						 a.in.secure_channel_type,
						 &netr_creds1,
						 &netr_creds2,
						 &machine_password,
						 &netr_creds3,
						 negotiate_flags,
						 negotiate_flags);
	GNUTLS_FIPS140_SET_STRICT_MODE();
	/* Test that we fail to encrypt with RC4 */
	if (creds_state == NULL &&
	    !weak_crypto_allowed && !force_client_rc4 &&
	    (negotiate_flags & NETLOGON_NEG_ARCFOUR)) {
		return false;
	}
	torture_assert_not_null(tctx,
				creds_state,
				"Failed init netlogon client creds");


	torture_comment(tctx, "Testing ServerAuthenticate3\n");

	status = dcerpc_netr_ServerAuthenticate3_r(b, tctx, &a);
	torture_assert_ntstatus_ok(tctx,
				   status,
				   "ServerAuthenticate3 failed");

	/* Check that the server denies RC4 */
	if (!NT_STATUS_IS_OK(a.out.result) &&
	    !weak_crypto_allowed &&
	    force_client_rc4) {
		torture_assert_ntstatus_equal(tctx,
					      a.out.result,
					      NT_STATUS_DOWNGRADE_DETECTED,
					      "Unexpected status code");
		torture_assert_int_equal(tctx, negotiate_flags, 0,
					 "NT_STATUS_DOWNGRADE_DETECTED...");
		return false;
	}
	torture_assert_ntstatus_ok(tctx,
				   a.out.result,
				   "ServerAuthenticate3 failed");
	torture_assert(tctx,
		       netlogon_creds_client_check(creds_state, &netr_creds3),
		       "Credential chaining failed");

	torture_comment(tctx,
			"server negotiate_flags=0x%08x\n",
			negotiate_flags);

	if (!weak_crypto_allowed) {
		torture_assert(tctx,
			       (negotiate_flags & NETLOGON_NEG_SUPPORTS_AES),
			       "Server negotiate AES support");
	}

	/* Prove that requesting a challenge again won't break it */
	torture_assert_ntstatus_ok(tctx, dcerpc_netr_ServerReqChallenge_r(b, tctx, &r),
		"ServerReqChallenge failed");
	torture_assert_ntstatus_ok(tctx, r.out.result, "ServerReqChallenge failed");

	return true;
}


/* Test that we can successfully authenticate using AES. */
static bool test_AES_Crypto(struct torture_context *tctx,
			    struct dcerpc_pipe *p,
			    struct cli_credentials *machine_credentials)
{
	uint32_t negotiate_flags =
		NETLOGON_NEG_AUTH2_ADS_FLAGS|
		NETLOGON_NEG_SUPPORTS_AES;
	bool ok;

	ok = test_ServerAuth3Crypto(p,
				    tctx,
				    negotiate_flags,
				    machine_credentials,
				    false);
	if (!ok) {
		return false;
	}

	return true;
}

/* If we try to use RC4, the client code should fail to encrypt. */
static bool test_RC4_Crypto_Fail(struct torture_context *tctx,
				 struct dcerpc_pipe *p,
				 struct cli_credentials *machine_credentials)
{
	uint32_t negotiate_flags =
		NETLOGON_NEG_AUTH2_ADS_FLAGS|
		NETLOGON_NEG_ARCFOUR;
	bool ok;

	ok = test_ServerAuth3Crypto(p,
				    tctx,
				    negotiate_flags,
				    machine_credentials,
				    false);
	if (!ok) {
		return true;
	}

	return false;
}

/*
 * Enforce the use of RC4 and try to authenticate. The server should fail
 * in this case as it doesn't allow RC4
 */
static bool test_RC4_Crypto_Force(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  struct cli_credentials *machine_credentials)
{
	uint32_t negotiate_flags =
		NETLOGON_NEG_AUTH2_ADS_FLAGS|
		NETLOGON_NEG_ARCFOUR;
	bool ok;

	ok = test_ServerAuth3Crypto(p,
				    tctx,
				    negotiate_flags,
				    machine_credentials,
				    true);
	if (!ok) {
		return true;
	}

	return false;
}

struct torture_suite *torture_rpc_netlogon_crypto_fips(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx,
							   "fips.netlogon.crypto");
	struct torture_rpc_tcase *tcase = NULL;

	tcase = torture_suite_add_machine_bdc_rpc_iface_tcase(suite,
							      "netlogon",
							      &ndr_table_netlogon,
							      TEST_MACHINE_NAME);

	torture_rpc_tcase_add_test_creds(tcase,
					 "test_AES_Crytpo",
					 test_AES_Crypto);
	torture_rpc_tcase_add_test_creds(tcase,
					 "test_RC4_Crytpo_Fail",
					 test_RC4_Crypto_Fail);
	torture_rpc_tcase_add_test_creds(tcase,
					 "test_RC4_Crytpo_Force",
					 test_RC4_Crypto_Force);

	return suite;
}
