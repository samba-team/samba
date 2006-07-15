/* 
   Unix SMB/CIFS implementation.

   dcerpc torture tests, designed to walk Samba3 code paths

   Copyright (C) Volker Lendecke 2006

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
#include "libcli/raw/libcliraw.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_netlogon_c.h"
#include "librpc/gen_ndr/ndr_srvsvc.h"
#include "librpc/gen_ndr/ndr_srvsvc_c.h"
#include "lib/cmdline/popt_common.h"
#include "librpc/rpc/dcerpc.h"
#include "torture/rpc/rpc.h"
#include "libcli/libcli.h"
#include "libcli/composite/composite.h"
#include "libcli/smb_composite/smb_composite.h"
#include "libcli/auth/libcli_auth.h"
#include "libcli/auth/credentials.h"
#include "lib/crypto/crypto.h"
#include "libcli/security/proto.h"

static struct cli_credentials *create_anon_creds(TALLOC_CTX *mem_ctx)
{
	struct cli_credentials *result;

	if (!(result = cli_credentials_init(mem_ctx))) {
		return NULL;
	}

	cli_credentials_set_conf(result);
	cli_credentials_set_anonymous(result);

	return result;
}

/*
 * This tests a RPC call using an invalid vuid
 */

BOOL torture_bind_authcontext(struct torture_context *torture) 
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	BOOL ret = False;
	struct lsa_ObjectAttribute objectattr;
	struct lsa_OpenPolicy2 openpolicy;
	struct policy_handle handle;
	struct lsa_Close close;
	struct smbcli_session *tmp;
	struct smbcli_session *session2;
	struct smbcli_state *cli;
	struct dcerpc_pipe *lsa_pipe;
	struct cli_credentials *anon_creds;
	struct smb_composite_sesssetup setup;

	mem_ctx = talloc_init("torture_bind_authcontext");

	if (mem_ctx == NULL) {
		d_printf("talloc_init failed\n");
		return False;
	}

	status = smbcli_full_connection(mem_ctx, &cli,
					lp_parm_string(-1, "torture", "host"),
					"IPC$", NULL, cmdline_credentials,
					NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("smbcli_full_connection failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	lsa_pipe = dcerpc_pipe_init(mem_ctx, cli->transport->socket->event.ctx);
	if (lsa_pipe == NULL) {
		d_printf("dcerpc_pipe_init failed\n");
		goto done;
	}

	status = dcerpc_pipe_open_smb(lsa_pipe->conn, cli->tree, "\\lsarpc");
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_pipe_open_smb failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	status = dcerpc_bind_auth_none(lsa_pipe, &dcerpc_table_lsarpc);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_bind_auth_none failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	openpolicy.in.system_name =talloc_asprintf(
		mem_ctx, "\\\\%s", dcerpc_server_name(lsa_pipe));
	ZERO_STRUCT(objectattr);
	openpolicy.in.attr = &objectattr;
	openpolicy.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	openpolicy.out.handle = &handle;

	status = dcerpc_lsa_OpenPolicy2(lsa_pipe, mem_ctx, &openpolicy);

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_lsa_OpenPolicy2 failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	close.in.handle = &handle;
	close.out.handle = &handle;

	status = dcerpc_lsa_Close(lsa_pipe, mem_ctx, &close);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_lsa_Close failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	session2 = smbcli_session_init(cli->transport, mem_ctx, False);
	if (session2 == NULL) {
		d_printf("smbcli_session_init failed\n");
		goto done;
	}

	if (!(anon_creds = create_anon_creds(mem_ctx))) {
		d_printf("create_anon_creds failed\n");
		goto done;
	}

	setup.in.sesskey = cli->transport->negotiate.sesskey;
	setup.in.capabilities = cli->transport->negotiate.capabilities;
	setup.in.workgroup = "";
	setup.in.credentials = anon_creds;

	status = smb_composite_sesssetup(session2, &setup);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("anon session setup failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	tmp = cli->tree->session;
	cli->tree->session = session2;

	status = dcerpc_lsa_OpenPolicy2(lsa_pipe, mem_ctx, &openpolicy);

	cli->tree->session = tmp;
	talloc_free(lsa_pipe);
	lsa_pipe = NULL;

	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		d_printf("dcerpc_lsa_OpenPolicy2 with wrong vuid gave %s, "
			 "expected NT_STATUS_INVALID_HANDLE\n",
			 nt_errstr(status));
		goto done;
	}

	ret = True;
 done:
	talloc_free(mem_ctx);
	return ret;
}

/*
 * Bind to lsa using a specific auth method
 */

static BOOL bindtest(struct smbcli_state *cli,
		     struct cli_credentials *credentials,
		     uint8_t auth_type, uint8_t auth_level)
{
	TALLOC_CTX *mem_ctx;
	BOOL ret = False;
	NTSTATUS status;

	struct dcerpc_pipe *lsa_pipe;
	struct lsa_ObjectAttribute objectattr;
	struct lsa_OpenPolicy2 openpolicy;
	struct lsa_QueryInfoPolicy query;
	struct policy_handle handle;
	struct lsa_Close close;

	if ((mem_ctx = talloc_init("bindtest")) == NULL) {
		d_printf("talloc_init failed\n");
		return False;
	}

	lsa_pipe = dcerpc_pipe_init(mem_ctx,
				    cli->transport->socket->event.ctx);
	if (lsa_pipe == NULL) {
		d_printf("dcerpc_pipe_init failed\n");
		goto done;
	}

	status = dcerpc_pipe_open_smb(lsa_pipe->conn, cli->tree, "\\lsarpc");
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_pipe_open_smb failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	status = dcerpc_bind_auth(lsa_pipe, &dcerpc_table_lsarpc,
				  credentials, auth_type, auth_level,
				  NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_bind_auth failed: %s\n", nt_errstr(status));
		goto done;
	}

	openpolicy.in.system_name =talloc_asprintf(
		mem_ctx, "\\\\%s", dcerpc_server_name(lsa_pipe));
	ZERO_STRUCT(objectattr);
	openpolicy.in.attr = &objectattr;
	openpolicy.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	openpolicy.out.handle = &handle;

	status = dcerpc_lsa_OpenPolicy2(lsa_pipe, mem_ctx, &openpolicy);

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_lsa_OpenPolicy2 failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	query.in.handle = &handle;
	query.in.level = LSA_POLICY_INFO_DOMAIN;

	status = dcerpc_lsa_QueryInfoPolicy(lsa_pipe, mem_ctx, &query);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_lsa_QueryInfoPolicy failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	close.in.handle = &handle;
	close.out.handle = &handle;

	status = dcerpc_lsa_Close(lsa_pipe, mem_ctx, &close);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_lsa_Close failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	ret = True;
 done:
	talloc_free(mem_ctx);
	return ret;
}

/*
 * test authenticated RPC binds with the variants Samba3 does support
 */

BOOL torture_bind_samba3(struct torture_context *torture) 
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	BOOL ret = False;
	struct smbcli_state *cli;

	mem_ctx = talloc_init("torture_bind_authcontext");

	if (mem_ctx == NULL) {
		d_printf("talloc_init failed\n");
		return False;
	}

	status = smbcli_full_connection(mem_ctx, &cli,
					lp_parm_string(-1, "torture", "host"),
					"IPC$", NULL, cmdline_credentials,
					NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("smbcli_full_connection failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	ret = True;

	ret &= bindtest(cli, cmdline_credentials, DCERPC_AUTH_TYPE_NTLMSSP,
			DCERPC_AUTH_LEVEL_INTEGRITY);
	ret &= bindtest(cli, cmdline_credentials, DCERPC_AUTH_TYPE_NTLMSSP,
			DCERPC_AUTH_LEVEL_PRIVACY);
	ret &= bindtest(cli, cmdline_credentials, DCERPC_AUTH_TYPE_SPNEGO,
			DCERPC_AUTH_LEVEL_INTEGRITY);
	ret &= bindtest(cli, cmdline_credentials, DCERPC_AUTH_TYPE_SPNEGO,
			DCERPC_AUTH_LEVEL_PRIVACY);

 done:
	talloc_free(mem_ctx);
	return ret;
}

/*
 * Lookup or create a user and return all necessary info
 */

static NTSTATUS get_usr_handle(struct smbcli_state *cli,
			       TALLOC_CTX *mem_ctx,
			       struct cli_credentials *admin_creds,
			       uint8_t auth_type,
			       uint8_t auth_level,
			       const char *wks_name,
			       char **domain,
			       struct dcerpc_pipe **result_pipe,
			       struct policy_handle **result_handle)
{
	struct dcerpc_pipe *samr_pipe;
	NTSTATUS status;
	struct policy_handle conn_handle;
	struct policy_handle domain_handle;
	struct policy_handle *user_handle;
	struct samr_Connect2 conn;
	struct samr_EnumDomains enumdom;
	uint32_t resume_handle = 0;
	struct samr_LookupDomain l;
	int dom_idx;
	struct lsa_String domain_name;
	struct lsa_String user_name;
	struct samr_OpenDomain o;
	struct samr_CreateUser2 c;
	uint32_t user_rid,access_granted;

	samr_pipe = dcerpc_pipe_init(mem_ctx,
				     cli->transport->socket->event.ctx);
	if (samr_pipe == NULL) {
		d_printf("dcerpc_pipe_init failed\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	status = dcerpc_pipe_open_smb(samr_pipe->conn, cli->tree, "\\samr");
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_pipe_open_smb failed: %s\n",
			 nt_errstr(status));
		goto fail;
	}

	if (admin_creds != NULL) {
		status = dcerpc_bind_auth(samr_pipe, &dcerpc_table_samr,
					  admin_creds, auth_type, auth_level,
					  NULL);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("dcerpc_bind_auth failed: %s\n",
				 nt_errstr(status));
			goto fail;
		}
	} else {
		/* We must have an authenticated SMB connection */
		status = dcerpc_bind_auth_none(samr_pipe, &dcerpc_table_samr);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("dcerpc_bind_auth_none failed: %s\n",
				 nt_errstr(status));
			goto fail;
		}
	}

	conn.in.system_name = talloc_asprintf(
		mem_ctx, "\\\\%s", dcerpc_server_name(samr_pipe));
	conn.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	conn.out.connect_handle = &conn_handle;

	status = dcerpc_samr_Connect2(samr_pipe, mem_ctx, &conn);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("samr_Connect2 failed: %s\n", nt_errstr(status));
		goto fail;
	}

	enumdom.in.connect_handle = &conn_handle;
	enumdom.in.resume_handle = &resume_handle;
	enumdom.in.buf_size = (uint32_t)-1;
	enumdom.out.resume_handle = &resume_handle;

	status = dcerpc_samr_EnumDomains(samr_pipe, mem_ctx, &enumdom);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("samr_EnumDomains failed: %s\n", nt_errstr(status));
		goto fail;
	}

	if (enumdom.out.num_entries != 2) {
		d_printf("samr_EnumDomains returned %d entries, expected 2\n",
			 enumdom.out.num_entries);
		status = NT_STATUS_UNSUCCESSFUL;
		goto fail;
	}

	dom_idx = strequal(enumdom.out.sam->entries[0].name.string,
			   "builtin") ? 1:0;

	l.in.connect_handle = &conn_handle;
	domain_name.string = enumdom.out.sam->entries[0].name.string;
	*domain = talloc_strdup(mem_ctx, domain_name.string);
	l.in.domain_name = &domain_name;

	status = dcerpc_samr_LookupDomain(samr_pipe, mem_ctx, &l);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("samr_LookupDomain failed: %s\n", nt_errstr(status));
		goto fail;
	}

	o.in.connect_handle = &conn_handle;
	o.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	o.in.sid = l.out.sid;
	o.out.domain_handle = &domain_handle;

	status = dcerpc_samr_OpenDomain(samr_pipe, mem_ctx, &o);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("samr_OpenDomain failed: %s\n", nt_errstr(status));
		goto fail;
	}

	c.in.domain_handle = &domain_handle;
	user_name.string = talloc_asprintf(mem_ctx, "%s$", wks_name);
	c.in.account_name = &user_name;
	c.in.acct_flags = ACB_WSTRUST;
	c.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	user_handle = talloc(mem_ctx, struct policy_handle);
	c.out.user_handle = user_handle;
	c.out.access_granted = &access_granted;
	c.out.rid = &user_rid;

	status = dcerpc_samr_CreateUser2(samr_pipe, mem_ctx, &c);

	if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
		struct samr_LookupNames ln;
		struct samr_OpenUser ou;

		ln.in.domain_handle = &domain_handle;
		ln.in.num_names = 1;
		ln.in.names = &user_name;

		status = dcerpc_samr_LookupNames(samr_pipe, mem_ctx, &ln);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("samr_LookupNames failed: %s\n",
				 nt_errstr(status));
			goto fail;
		}

		ou.in.domain_handle = &domain_handle;
		ou.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		ou.in.rid = ln.out.rids.ids[0];
		ou.out.user_handle = user_handle;

		status = dcerpc_samr_OpenUser(samr_pipe, mem_ctx, &ou);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("samr_OpenUser failed: %s\n",
				 nt_errstr(status));
			goto fail;
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("samr_CreateUser failed: %s\n", nt_errstr(status));
		goto fail;
	}

	*result_pipe = samr_pipe;
	*result_handle = user_handle;
	return NT_STATUS_OK;

 fail:
	return status;
}

/*
 * Do a Samba3-style join
 */

static BOOL join3(struct smbcli_state *cli,
		  BOOL use_level25,
		  struct cli_credentials *admin_creds,
		  struct cli_credentials *wks_creds)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	char *dom_name;
	struct dcerpc_pipe *samr_pipe;
	struct policy_handle *wks_handle;
	BOOL ret = False;

	if ((mem_ctx = talloc_init("join3")) == NULL) {
		d_printf("talloc_init failed\n");
		return False;
	}

	status = get_usr_handle(cli, mem_ctx, admin_creds,
				DCERPC_AUTH_TYPE_NTLMSSP,
				DCERPC_AUTH_LEVEL_PRIVACY,
				cli_credentials_get_workstation(wks_creds),
				&dom_name, &samr_pipe, &wks_handle);

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("get_wks_handle failed: %s\n", nt_errstr(status));
		goto done;
	}

	cli_credentials_set_domain(wks_creds, dom_name, CRED_SPECIFIED);

	if (use_level25) {
		struct samr_SetUserInfo2 sui2;
		union samr_UserInfo u_info;
		struct samr_UserInfo21 *i21 = &u_info.info25.info;
		DATA_BLOB session_key;
		DATA_BLOB confounded_session_key = data_blob_talloc(
			mem_ctx, NULL, 16);
		struct MD5Context ctx;
		uint8_t confounder[16];

		ZERO_STRUCT(u_info);

		i21->full_name.string = talloc_asprintf(
			mem_ctx, "%s$",
			cli_credentials_get_workstation(wks_creds));
		i21->acct_flags = ACB_WSTRUST;
		i21->fields_present = SAMR_FIELD_FULL_NAME |
			SAMR_FIELD_ACCT_FLAGS | SAMR_FIELD_PASSWORD;

		encode_pw_buffer(u_info.info25.password.data,
				 cli_credentials_get_password(wks_creds),
				 STR_UNICODE);
		status = dcerpc_fetch_session_key(samr_pipe, &session_key);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("dcerpc_fetch_session_key failed: %s\n",
				 nt_errstr(status));
			goto done;
		}
		generate_random_buffer((uint8_t *)confounder, 16);

		MD5Init(&ctx);
		MD5Update(&ctx, confounder, 16);
		MD5Update(&ctx, session_key.data, session_key.length);
		MD5Final(confounded_session_key.data, &ctx);

		arcfour_crypt_blob(u_info.info25.password.data, 516,
				   &confounded_session_key);
		memcpy(&u_info.info25.password.data[516], confounder, 16);

		sui2.in.user_handle = wks_handle;
		sui2.in.level = 25;
		sui2.in.info = &u_info;

		status = dcerpc_samr_SetUserInfo2(samr_pipe, mem_ctx, &sui2);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("samr_SetUserInfo2(25) failed: %s\n",
				 nt_errstr(status));
			goto done;
		}
	} else {
		struct samr_SetUserInfo2 sui2;
		struct samr_SetUserInfo sui;
		union samr_UserInfo u_info;
		DATA_BLOB session_key;

		encode_pw_buffer(u_info.info24.password.data,
				 cli_credentials_get_password(wks_creds),
				 STR_UNICODE);
		u_info.info24.pw_len =
			strlen_m(cli_credentials_get_password(wks_creds))*2;

		status = dcerpc_fetch_session_key(samr_pipe, &session_key);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("dcerpc_fetch_session_key failed\n");
			goto done;
		}
		arcfour_crypt_blob(u_info.info24.password.data, 516,
				   &session_key);
		sui2.in.user_handle = wks_handle;
		sui2.in.info = &u_info;
		sui2.in.level = 24;

		status = dcerpc_samr_SetUserInfo2(samr_pipe, mem_ctx, &sui2);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("samr_SetUserInfo(24) failed\n");
			goto done;
		}

		u_info.info16.acct_flags = ACB_WSTRUST;
		sui.in.user_handle = wks_handle;
		sui.in.info = &u_info;
		sui.in.level = 16;

		status = dcerpc_samr_SetUserInfo(samr_pipe, mem_ctx, &sui);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("samr_SetUserInfo(16) failed\n");
			goto done;
		}
	}

	ret = True;

 done:
	talloc_free(mem_ctx);
	return ret;
}

/*
 * Do a ReqChallenge/Auth2 and get the wks creds
 */

static BOOL auth2(struct smbcli_state *cli,
		  struct cli_credentials *wks_cred)
{
	TALLOC_CTX *mem_ctx;
	struct dcerpc_pipe *net_pipe;
	BOOL result = False;
	NTSTATUS status;
	struct netr_ServerReqChallenge r;
	struct netr_Credential netr_cli_creds;
	struct netr_Credential netr_srv_creds;
	uint32_t negotiate_flags;
	struct netr_ServerAuthenticate2 a;
	struct creds_CredentialState *creds_state;
	struct netr_Credential netr_cred;
	struct samr_Password mach_pw;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		d_printf("talloc_new failed\n");
		return False;
	}

	net_pipe = dcerpc_pipe_init(mem_ctx,
				    cli->transport->socket->event.ctx);
	if (net_pipe == NULL) {
		d_printf("dcerpc_pipe_init failed\n");
		goto done;
	}

	status = dcerpc_pipe_open_smb(net_pipe->conn, cli->tree, "\\netlogon");
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_pipe_open_smb failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	status = dcerpc_bind_auth_none(net_pipe, &dcerpc_table_netlogon);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_bind_auth_none failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	r.in.computer_name = cli_credentials_get_workstation(wks_cred);
	r.in.server_name = talloc_asprintf(
		mem_ctx, "\\\\%s", dcerpc_server_name(net_pipe));
	if (r.in.server_name == NULL) {
		d_printf("talloc_asprintf failed\n");
		goto done;
	}
	generate_random_buffer(netr_cli_creds.data,
			       sizeof(netr_cli_creds.data));
	r.in.credentials = &netr_cli_creds;
	r.out.credentials = &netr_srv_creds;

	status = dcerpc_netr_ServerReqChallenge(net_pipe, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("netr_ServerReqChallenge failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	negotiate_flags = NETLOGON_NEG_AUTH2_FLAGS;
	E_md4hash(cli_credentials_get_password(wks_cred), mach_pw.hash);

	creds_state = talloc(mem_ctx, struct creds_CredentialState);
	creds_client_init(creds_state, r.in.credentials,
			  r.out.credentials, &mach_pw,
			  &netr_cred, negotiate_flags);

	a.in.server_name = talloc_asprintf(
		mem_ctx, "\\\\%s", dcerpc_server_name(net_pipe));
	a.in.account_name = talloc_asprintf(
		mem_ctx, "%s$", cli_credentials_get_workstation(wks_cred));
	a.in.computer_name = cli_credentials_get_workstation(wks_cred);
	a.in.secure_channel_type = SEC_CHAN_WKSTA;
	a.in.negotiate_flags = &negotiate_flags;
	a.out.negotiate_flags = &negotiate_flags;
	a.in.credentials = &netr_cred;
	a.out.credentials = &netr_cred;

	status = dcerpc_netr_ServerAuthenticate2(net_pipe, mem_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("netr_ServerServerAuthenticate2 failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	if (!creds_client_check(creds_state, a.out.credentials)) {
		d_printf("creds_client_check failed\n");
		goto done;
	}

	cli_credentials_set_netlogon_creds(wks_cred, creds_state);

	result = True;

 done:
	talloc_free(mem_ctx);
	return result;
}

/*
 * Do a couple of channel protected Netlogon ops: Interactive and Network
 * login, and change the wks password
 */

static BOOL schan(struct smbcli_state *cli,
		  struct cli_credentials *wks_creds,
		  struct cli_credentials *user_creds)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	BOOL ret = False;
	struct dcerpc_pipe *net_pipe;
	int i;
	
	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		d_printf("talloc_new failed\n");
		return False;
	}

	net_pipe = dcerpc_pipe_init(mem_ctx,
				    cli->transport->socket->event.ctx);
	if (net_pipe == NULL) {
		d_printf("dcerpc_pipe_init failed\n");
		goto done;
	}

	status = dcerpc_pipe_open_smb(net_pipe->conn, cli->tree, "\\netlogon");
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_pipe_open_smb failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

#if 0
	net_pipe->conn->flags |= DCERPC_DEBUG_PRINT_IN |
		DCERPC_DEBUG_PRINT_OUT;
#endif
#if 1
	net_pipe->conn->flags |= (DCERPC_SIGN | DCERPC_SEAL);
	status = dcerpc_bind_auth(net_pipe, &dcerpc_table_netlogon,
				  wks_creds, DCERPC_AUTH_TYPE_SCHANNEL,
				  DCERPC_AUTH_LEVEL_PRIVACY,
				  NULL);
#else
	status = dcerpc_bind_auth_none(net_pipe, &dcerpc_table_netlogon);
#endif
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("schannel bind failed: %s\n", nt_errstr(status));
		goto done;
	}


	for (i=2; i<4; i++) {
		int flags;
		DATA_BLOB chal, nt_resp, lm_resp, names_blob, session_key;
		struct creds_CredentialState *creds_state;
		struct netr_Authenticator netr_auth, netr_auth2;
		struct netr_NetworkInfo ninfo;
		struct netr_PasswordInfo pinfo;
		struct netr_LogonSamLogon r;

		flags = CLI_CRED_LANMAN_AUTH | CLI_CRED_NTLM_AUTH |
			CLI_CRED_NTLMv2_AUTH;

		chal = data_blob_talloc(mem_ctx, NULL, 8);
		if (chal.data == NULL) {
			d_printf("data_blob_talloc failed\n");
			goto done;
		}

		generate_random_buffer(chal.data, chal.length);
		names_blob = NTLMv2_generate_names_blob(
			mem_ctx, cli_credentials_get_workstation(user_creds),
			cli_credentials_get_domain(user_creds));
		status = cli_credentials_get_ntlm_response(
			user_creds, mem_ctx, &flags, chal, names_blob,
			&lm_resp, &nt_resp, NULL, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("cli_credentials_get_ntlm_response failed:"
				 " %s\n", nt_errstr(status));
			goto done;
		}

		creds_state = cli_credentials_get_netlogon_creds(wks_creds);
		creds_client_authenticator(creds_state, &netr_auth);

		ninfo.identity_info.account_name.string =
			cli_credentials_get_username(user_creds);
		ninfo.identity_info.domain_name.string =
			cli_credentials_get_domain(user_creds);
		ninfo.identity_info.parameter_control = 0;
		ninfo.identity_info.logon_id_low = 0;
		ninfo.identity_info.logon_id_high = 0;
		ninfo.identity_info.workstation.string =
			cli_credentials_get_workstation(user_creds);
		memcpy(ninfo.challenge, chal.data, sizeof(ninfo.challenge));
		ninfo.nt.length = nt_resp.length;
		ninfo.nt.data = nt_resp.data;
		ninfo.lm.length = lm_resp.length;
		ninfo.lm.data = lm_resp.data;

		r.in.server_name = talloc_asprintf(
			mem_ctx, "\\\\%s", dcerpc_server_name(net_pipe));
		ZERO_STRUCT(netr_auth2);
		r.in.computer_name =
			cli_credentials_get_workstation(wks_creds);
		r.in.credential = &netr_auth;
		r.in.return_authenticator = &netr_auth2;
		r.in.logon_level = 2;
		r.in.validation_level = i;
		r.in.logon.network = &ninfo;
		r.out.return_authenticator = NULL;

		status = dcerpc_netr_LogonSamLogon(net_pipe, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("netr_LogonSamLogon failed: %s\n",
				 nt_errstr(status));
			goto done;
		}

		if ((r.out.return_authenticator == NULL) ||
		    (!creds_client_check(creds_state,
					 &r.out.return_authenticator->cred))) {
			d_printf("Credentials check failed!\n");
			goto done;
		}

		creds_client_authenticator(creds_state, &netr_auth);

		pinfo.identity_info = ninfo.identity_info;
		ZERO_STRUCT(pinfo.lmpassword.hash);
		E_md4hash(cli_credentials_get_password(user_creds),
			  pinfo.ntpassword.hash);
		session_key = data_blob_talloc(mem_ctx,
					       creds_state->session_key, 16);
		arcfour_crypt_blob(pinfo.ntpassword.hash,
				   sizeof(pinfo.ntpassword.hash),
				   &session_key);

		r.in.logon_level = 1;
		r.in.logon.password = &pinfo;
		r.out.return_authenticator = NULL;

		status = dcerpc_netr_LogonSamLogon(net_pipe, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("netr_LogonSamLogon failed: %s\n",
				 nt_errstr(status));
			goto done;
		}

		if ((r.out.return_authenticator == NULL) ||
		    (!creds_client_check(creds_state,
					 &r.out.return_authenticator->cred))) {
			d_printf("Credentials check failed!\n");
			goto done;
		}
	}

	{
		struct netr_ServerPasswordSet s;
		char *password = generate_random_str(wks_creds, 8);
		struct creds_CredentialState *creds_state;

		s.in.server_name = talloc_asprintf(
			mem_ctx, "\\\\%s", dcerpc_server_name(net_pipe));
		s.in.computer_name = cli_credentials_get_workstation(wks_creds);
		s.in.account_name = talloc_asprintf(
			mem_ctx, "%s$", s.in.computer_name);
		s.in.secure_channel_type = SEC_CHAN_WKSTA;
		E_md4hash(password, s.in.new_password.hash);

		creds_state = cli_credentials_get_netlogon_creds(wks_creds);
		creds_des_encrypt(creds_state, &s.in.new_password);
		creds_client_authenticator(creds_state, &s.in.credential);

		status = dcerpc_netr_ServerPasswordSet(net_pipe, mem_ctx, &s);
		if (!NT_STATUS_IS_OK(status)) {
			printf("ServerPasswordSet - %s\n", nt_errstr(status));
			goto done;
		}

		if (!creds_client_check(creds_state,
					&s.out.return_authenticator.cred)) {
			printf("Credential chaining failed\n");
		}

		cli_credentials_set_password(wks_creds, password,
					     CRED_SPECIFIED);
	}

	ret = True;
 done:
	talloc_free(mem_ctx);
	return ret;
}

/*
 * Delete the wks account again
 */

static BOOL leave(struct smbcli_state *cli,
		  struct cli_credentials *admin_creds,
		  struct cli_credentials *wks_creds)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	char *dom_name;
	struct dcerpc_pipe *samr_pipe;
	struct policy_handle *wks_handle;
	BOOL ret = False;

	if ((mem_ctx = talloc_init("leave")) == NULL) {
		d_printf("talloc_init failed\n");
		return False;
	}

	status = get_usr_handle(cli, mem_ctx, admin_creds,
				DCERPC_AUTH_TYPE_NTLMSSP,
				DCERPC_AUTH_LEVEL_PRIVACY,
				cli_credentials_get_workstation(wks_creds),
				&dom_name, &samr_pipe, &wks_handle);

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("get_wks_handle failed: %s\n", nt_errstr(status));
		goto done;
	}

	{
		struct samr_DeleteUser d;

		d.in.user_handle = wks_handle;
		d.out.user_handle = wks_handle;

		status = dcerpc_samr_DeleteUser(samr_pipe, mem_ctx, &d);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("samr_DeleteUser failed\n");
			goto done;
		}
	}

	ret = True;

 done:
	talloc_free(mem_ctx);
	return ret;
}

/*
 * Test the Samba3 DC code a bit. Join, do some schan netlogon ops, leave
 */

BOOL torture_netlogon_samba3(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	BOOL ret = False;
	struct smbcli_state *cli;
	struct cli_credentials *anon_creds;
	struct cli_credentials *wks_creds;
	const char *wks_name;
	int i;

	wks_name = lp_parm_string(-1, "torture", "wksname");
	if (wks_name == NULL) {
		wks_name = get_myname();
	}

	mem_ctx = talloc_init("torture_bind_authcontext");

	if (mem_ctx == NULL) {
		d_printf("talloc_init failed\n");
		return False;
	}

	if (!(anon_creds = create_anon_creds(mem_ctx))) {
		d_printf("create_anon_creds failed\n");
		goto done;
	}

	status = smbcli_full_connection(mem_ctx, &cli,
					lp_parm_string(-1, "torture", "host"),
					"IPC$", NULL, anon_creds, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("smbcli_full_connection failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	wks_creds = cli_credentials_init(mem_ctx);
	if (wks_creds == NULL) {
		d_printf("cli_credentials_init failed\n");
		goto done;
	}

	cli_credentials_set_conf(wks_creds);
	cli_credentials_set_secure_channel_type(wks_creds, SEC_CHAN_WKSTA);
	cli_credentials_set_username(wks_creds, wks_name, CRED_SPECIFIED);
	cli_credentials_set_workstation(wks_creds, wks_name, CRED_SPECIFIED);
	cli_credentials_set_password(wks_creds, "", CRED_SPECIFIED);

	if (!join3(cli, False, cmdline_credentials, wks_creds)) {
		d_printf("join failed\n");
		goto done;
	}

	cli_credentials_set_domain(
		cmdline_credentials, cli_credentials_get_domain(wks_creds),
		CRED_SPECIFIED);

	for (i=0; i<2; i++) {

		/* Do this more than once, the routine "schan" changes
		 * the workstation password using the netlogon
		 * password change routine */

		int j;

		if (!auth2(cli, wks_creds)) {
			d_printf("auth2 failed\n");
			goto done;
		}

		for (j=0; j<2; j++) {
			if (!schan(cli, wks_creds, cmdline_credentials)) {
				d_printf("schan failed\n");
				goto done;
			}
		}
	}

	if (!leave(cli, cmdline_credentials, wks_creds)) {
		d_printf("leave failed\n");
		goto done;
	}

	ret = True;

 done:
	talloc_free(mem_ctx);
	return ret;
}

/*
 * Do a simple join, testjoin and leave using specified smb and samr
 * credentials
 */

static BOOL test_join3(TALLOC_CTX *mem_ctx,
		       BOOL use_level25,
		       struct cli_credentials *smb_creds,
		       struct cli_credentials *samr_creds,
		       const char *wks_name)
{
	NTSTATUS status;
	BOOL ret = False;
	struct smbcli_state *cli;
	struct cli_credentials *wks_creds;

	status = smbcli_full_connection(mem_ctx, &cli,
					lp_parm_string(-1, "torture", "host"),
					"IPC$", NULL, smb_creds, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("smbcli_full_connection failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	wks_creds = cli_credentials_init(cli);
	if (wks_creds == NULL) {
		d_printf("cli_credentials_init failed\n");
		goto done;
	}

	cli_credentials_set_conf(wks_creds);
	cli_credentials_set_secure_channel_type(wks_creds, SEC_CHAN_WKSTA);
	cli_credentials_set_username(wks_creds, wks_name, CRED_SPECIFIED);
	cli_credentials_set_workstation(wks_creds, wks_name, CRED_SPECIFIED);
	cli_credentials_set_password(wks_creds,
				     generate_random_str(wks_creds, 8),
				     CRED_SPECIFIED);

	if (!join3(cli, use_level25, samr_creds, wks_creds)) {
		d_printf("join failed\n");
		goto done;
	}

	cli_credentials_set_domain(
		cmdline_credentials, cli_credentials_get_domain(wks_creds),
		CRED_SPECIFIED);

	if (!auth2(cli, wks_creds)) {
		d_printf("auth2 failed\n");
		goto done;
	}

	if (!leave(cli, samr_creds, wks_creds)) {
		d_printf("leave failed\n");
		goto done;
	}

	talloc_free(cli);

	ret = True;

 done:
	return ret;
}

/*
 * Test the different session key variants. Do it by joining, this uses the
 * session key in the setpassword routine. Test the join by doing the auth2.
 */

BOOL torture_samba3_sessionkey(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx;
	BOOL ret = False;
	struct cli_credentials *anon_creds;
	const char *wks_name;

	wks_name = lp_parm_string(-1, "torture", "wksname");
	if (wks_name == NULL) {
		wks_name = get_myname();
	}

	mem_ctx = talloc_init("torture_samba3_sessionkey");

	if (mem_ctx == NULL) {
		d_printf("talloc_init failed\n");
		return False;
	}

	if (!(anon_creds = create_anon_creds(mem_ctx))) {
		d_printf("create_anon_creds failed\n");
		goto done;
	}

	ret = True;

	if (!lp_parm_bool(-1, "target", "samba3", False)) {

		/* Samba3 in the build farm right now does this happily. Need
		 * to fix :-) */

		if (test_join3(mem_ctx, False, anon_creds, NULL, wks_name)) {
			d_printf("join using anonymous bind on an anonymous smb "
				 "connection succeeded -- HUH??\n");
			ret = False;
		}
	}

	if (!test_join3(mem_ctx, False, anon_creds, cmdline_credentials,
			wks_name)) {
		d_printf("join using ntlmssp bind on an anonymous smb "
			 "connection failed\n");
		ret = False;
	}

	if (!test_join3(mem_ctx, False, cmdline_credentials, NULL, wks_name)) {
		d_printf("join using anonymous bind on an authenticated smb "
			 "connection failed\n");
		ret = False;
	}

	if (!test_join3(mem_ctx, False, cmdline_credentials,
			cmdline_credentials,
			wks_name)) {
		d_printf("join using ntlmssp bind on an authenticated smb "
			 "connection failed\n");
		ret = False;
	}

	/*
	 * The following two are tests for setuserinfolevel 25
	 */

	if (!test_join3(mem_ctx, True, anon_creds, cmdline_credentials,
			wks_name)) {
		d_printf("join using ntlmssp bind on an anonymous smb "
			 "connection failed\n");
		ret = False;
	}

	if (!test_join3(mem_ctx, True, cmdline_credentials, NULL, wks_name)) {
		d_printf("join using anonymous bind on an authenticated smb "
			 "connection failed\n");
		ret = False;
	}

 done:

	return ret;
}

/*
 * open pipe and bind, given an IPC$ context
 */

static struct dcerpc_pipe *pipe_bind_smb(TALLOC_CTX *mem_ctx,
					 struct smbcli_tree *tree,
					 const char *pipe_name,
					 const struct dcerpc_interface_table *iface)
{
	struct dcerpc_pipe *result;
	NTSTATUS status;

	if (!(result = dcerpc_pipe_init(
		      mem_ctx, tree->session->transport->socket->event.ctx))) {
		return NULL;
	}

	status = dcerpc_pipe_open_smb(result->conn, tree, pipe_name);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_pipe_open_smb failed: %s\n",
			 nt_errstr(status));
		talloc_free(result);
		return NULL;
	}

	status = dcerpc_bind_auth_none(result, iface);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("schannel bind failed: %s\n", nt_errstr(status));
		talloc_free(result);
		return NULL;
	}

	return result;
}

/*
 * Sane wrapper around lsa_LookupNames
 */

static struct dom_sid *name2sid(TALLOC_CTX *mem_ctx,
				struct dcerpc_pipe *p,
				const char *name,
				const char *domain)
{
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 r;
	struct lsa_Close c;
	NTSTATUS status;
	struct policy_handle handle;
	struct lsa_LookupNames l;
	struct lsa_TransSidArray sids;
	struct lsa_String lsa_name;
	uint32_t count = 0;
	struct dom_sid *result;
	TALLOC_CTX *tmp_ctx;

	if (!(tmp_ctx = talloc_new(mem_ctx))) {
		return NULL;
	}

	qos.len = 0;
	qos.impersonation_level = 2;
	qos.context_mode = 1;
	qos.effective_only = 0;

	attr.len = 0;
	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = &qos;

	r.in.system_name = "\\";
	r.in.attr = &attr;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = &handle;

	status = dcerpc_lsa_OpenPolicy2(p, tmp_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenPolicy2 failed - %s\n", nt_errstr(status));
		talloc_free(tmp_ctx);
		return NULL;
	}

	sids.count = 0;
	sids.sids = NULL;

	lsa_name.string = talloc_asprintf(tmp_ctx, "%s\\%s", domain, name);

	l.in.handle = &handle;
	l.in.num_names = 1;
	l.in.names = &lsa_name;
	l.in.sids = &sids;
	l.in.level = 1;
	l.in.count = &count;
	l.out.count = &count;
	l.out.sids = &sids;

	status = dcerpc_lsa_LookupNames(p, tmp_ctx, &l);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupNames failed - %s\n", nt_errstr(status));
		talloc_free(tmp_ctx);
		return False;
	}

	result = dom_sid_add_rid(mem_ctx, l.out.domains->domains[0].sid,
				 l.out.sids->sids[0].rid);

	c.in.handle = &handle;
	c.out.handle = &handle;

	status = dcerpc_lsa_Close(p, tmp_ctx, &c);
	if (!NT_STATUS_IS_OK(status)) {
		printf("dcerpc_lsa_Close failed - %s\n", nt_errstr(status));
		talloc_free(tmp_ctx);
		return NULL;
	}
	
	talloc_free(tmp_ctx);
	return result;
}

/*
 * Find out the user SID on this connection
 */

static struct dom_sid *whoami(TALLOC_CTX *mem_ctx, struct smbcli_tree *tree)
{
	struct dcerpc_pipe *lsa;
	struct lsa_GetUserName r;
	NTSTATUS status;
	struct lsa_StringPointer authority_name_p;
	struct dom_sid *result;

	if (!(lsa = pipe_bind_smb(mem_ctx, tree, "\\pipe\\lsarpc",
				  &dcerpc_table_lsarpc))) {
		d_printf("Could not bind to LSA\n");
		return NULL;
	}

	r.in.system_name = "\\";
	r.in.account_name = NULL;
	authority_name_p.string = NULL;
	r.in.authority_name = &authority_name_p;

	status = dcerpc_lsa_GetUserName(lsa, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("GetUserName failed - %s\n", nt_errstr(status));
		talloc_free(lsa);
		return NULL;
	}

	result = name2sid(mem_ctx, lsa, r.out.account_name->string,
			  r.out.authority_name->string->string);

	talloc_free(lsa);
	return result;
}

/*
 * Test the getusername behaviour
 */

BOOL torture_samba3_rpc_getusername(struct torture_context *torture)
{
	NTSTATUS status;
	struct smbcli_state *cli;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct dom_sid *user_sid;
	struct cli_credentials *anon_creds;

	if (!(mem_ctx = talloc_new(torture))) {
		return False;
	}

	status = smbcli_full_connection(
		mem_ctx, &cli, lp_parm_string(-1, "torture", "host"),
		"IPC$", NULL, cmdline_credentials, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("smbcli_full_connection failed: %s\n",
			 nt_errstr(status));
		ret = False;
		goto done;
	}

	if (!(user_sid = whoami(mem_ctx, cli->tree))) {
		d_printf("whoami on auth'ed connection failed\n");
		ret = False;
	}

	talloc_free(cli);

	if (!(anon_creds = create_anon_creds(mem_ctx))) {
		d_printf("create_anon_creds failed\n");
		ret = False;
		goto done;
	}

	status = smbcli_full_connection(
		mem_ctx, &cli, lp_parm_string(-1, "torture", "host"),
		"IPC$", NULL, anon_creds, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("anon smbcli_full_connection failed: %s\n",
			 nt_errstr(status));
		ret = False;
		goto done;
	}

	if (!(user_sid = whoami(mem_ctx, cli->tree))) {
		d_printf("whoami on anon connection failed\n");
		ret = False;
		goto done;
	}

	if (!dom_sid_equal(user_sid,
			   dom_sid_parse_talloc(mem_ctx, "s-1-5-7"))) {
		d_printf("Anon lsa_GetUserName returned %s, expected S-1-5-7",
			 dom_sid_string(mem_ctx, user_sid));
		ret = False;
	}

 done:
	talloc_free(mem_ctx);
	return ret;
}

static BOOL test_NetShareGetInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				 const char *sharename)
{
	NTSTATUS status;
	struct srvsvc_NetShareGetInfo r;
	uint32_t levels[] = { 0, 1, 2, 501, 502, 1004, 1005, 1006, 1007, 1501 };
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx, "\\\\%s",
					  dcerpc_server_name(p));
	r.in.share_name = sharename;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		r.in.level = levels[i];

		ZERO_STRUCT(r.out);

		printf("testing NetShareGetInfo level %u on share '%s'\n", 
		       r.in.level, r.in.share_name);

		status = dcerpc_srvsvc_NetShareGetInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetShareGetInfo level %u on share '%s' failed"
			       " - %s\n", r.in.level, r.in.share_name,
			       nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetShareGetInfo level %u on share '%s' failed "
			       "- %s\n", r.in.level, r.in.share_name,
			       win_errstr(r.out.result));
			ret = False;
			continue;
		}
	}

	return ret;
}

static BOOL test_NetShareEnum(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			      const char **one_sharename)
{
	NTSTATUS status;
	struct srvsvc_NetShareEnum r;
	struct srvsvc_NetShareCtr0 c0;
	uint32_t levels[] = { 0, 1, 2, 501, 502, 1004, 1005, 1006, 1007 };
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.ctr.ctr0 = &c0;
	r.in.ctr.ctr0->count = 0;
	r.in.ctr.ctr0->array = NULL;
	r.in.max_buffer = (uint32_t)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		r.in.level = levels[i];

		ZERO_STRUCT(r.out);

		printf("testing NetShareEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetShareEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetShareEnum level %u failed - %s\n",
			       r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetShareEnum level %u failed - %s\n",
			       r.in.level, win_errstr(r.out.result));
			continue;
		}
		if (r.in.level == 0) {
			struct srvsvc_NetShareCtr0 *ctr = r.out.ctr.ctr0;
			if (ctr->count > 0) {
				*one_sharename = ctr->array[0].name;
			}
		}
	}

	return ret;
}

BOOL torture_samba3_rpc_srvsvc(struct torture_context *torture)
{
	struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	const char *sharename = NULL;
	struct smbcli_state *cli;

	if (!(mem_ctx = talloc_new(torture))) {
		return False;
	}

	if (!(torture_open_connection_share(
		      mem_ctx, &cli, lp_parm_string(-1, "torture", "host"),
		      "IPC$", NULL))) {
		talloc_free(mem_ctx);
		return False;
	}

	if (!(p = pipe_bind_smb(mem_ctx, cli->tree, "\\pipe\\srvsvc",
				&dcerpc_table_srvsvc))) {
		d_printf("could not bind to srvsvc pipe\n");
		ret = False;
		goto done;
	}

	ret &= test_NetShareEnum(p, mem_ctx, &sharename);
	if (sharename == NULL) {
		printf("did not get sharename\n");
	} else {
		ret &= test_NetShareGetInfo(p, mem_ctx, sharename);
	}
 done:
	talloc_free(mem_ctx);
	return ret;
}
