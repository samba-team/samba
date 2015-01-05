/* 
   Unix SMB/CIFS implementation.

   Validate the krb5 pac generation routines
   
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2015

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
#include "system/kerberos.h"
#include "torture/smbtorture.h"
#include "torture/winbind/proto.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/popt_common.h"
#include "source4/auth/kerberos/kerberos.h"
#include "source4/auth/kerberos/kerberos_util.h"
#include "lib/util/util_net.h"

static bool torture_krb5_init_context(struct torture_context *tctx,
				      struct smb_krb5_context **smb_krb5_context)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	krb5_error_code k5ret;
	bool ok;
	struct addrinfo *server;
	
	k5ret = smb_krb5_init_context(tctx, tctx->lp_ctx, smb_krb5_context);
	torture_assert_int_equal(tctx, k5ret, 0, "smb_krb5_init_context failed");

	ok = interpret_string_addr_internal(&server, host, AI_NUMERICHOST);
	torture_assert(tctx, ok, "Failed to parse target server");

	set_sockaddr_port(server->ai_addr, 88);

	k5ret = krb5_set_send_to_kdc_func((*smb_krb5_context)->krb5_context,
					  smb_krb5_send_and_recv_func_forced,
					  server);
	torture_assert_int_equal(tctx, k5ret, 0, "krb5_set_send_to_kdc_func failed");
	return true;
}

static bool torture_krb5_as_req_1(struct torture_context *tctx)
{
	krb5_error_code k5ret;
	bool ok;
	krb5_creds my_creds;
	krb5_principal principal;
	struct smb_krb5_context *smb_krb5_context;
	enum credentials_obtained obtained;
	const char *error_string;
	const char *password = cli_credentials_get_password(cmdline_credentials);
	
	ok = torture_krb5_init_context(tctx, &smb_krb5_context);
	torture_assert(tctx, ok, "torture_krb5_init_context failed");
	
	k5ret = principal_from_credentials(tctx, cmdline_credentials, smb_krb5_context, &principal, &obtained,  &error_string);
	torture_assert_int_equal(tctx, k5ret, 0, error_string);

	k5ret = krb5_get_init_creds_password(smb_krb5_context->krb5_context, &my_creds, principal,
					     password, NULL, NULL, 0,
					     NULL, NULL);
	torture_assert_int_equal(tctx, k5ret, 0, "krb5_get_init_creds_password failed");

	torture_assert_int_equal(tctx,
				 krb5_principal_get_type(smb_krb5_context->krb5_context,
							 my_creds.client), KRB5_NT_PRINCIPAL,
				 "smb_krb5_init_context gave incorrect client->name.name_type");

	torture_assert(tctx, krb5_principal_compare(smb_krb5_context->krb5_context,
						    principal, my_creds.client),
		       "krb5_get_init_creds_password returned a different principal");
	
	torture_assert_int_equal(tctx,
				 krb5_principal_get_type(smb_krb5_context->krb5_context,
							 my_creds.server), KRB5_NT_SRV_INST,
				 "smb_krb5_init_context gave incorrect client->name.name_type");

	torture_assert_str_equal(tctx, krb5_principal_get_comp_string(smb_krb5_context->krb5_context,
								      my_creds.server, 0),
				 "krbtgt",
				 "smb_krb5_init_context gave incorrect my_creds.server->name.name_string[0]");

	k5ret = krb5_free_cred_contents(smb_krb5_context->krb5_context, &my_creds);
	torture_assert_int_equal(tctx, k5ret, 0, "krb5_free_creds failed");

	return true;
}

NTSTATUS torture_krb5_init(void);
NTSTATUS torture_krb5_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "krb5");
	struct torture_suite *kdc_suite = torture_suite_create(suite, "kdc");
	suite->description = talloc_strdup(suite, "Kerberos tests");
	kdc_suite->description = talloc_strdup(kdc_suite, "Kerberos KDC tests");

	torture_suite_add_simple_test(kdc_suite, "as-req-1", 
				      torture_krb5_as_req_1);

	torture_suite_add_suite(suite, kdc_suite);

	torture_register_suite(suite);
	return NT_STATUS_OK;
}
