/* 
   Unix SMB/CIFS implementation.

   Test code to simulate an XP logon.

   Copyright (C) Volker Lendecke 2004
   
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
#include "libcli/auth/credentials.h"
#include "libcli/raw/libcliraw.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_srvsvc.h"

static int destroy_transport(void *ptr)
{
	struct smbcli_transport *trans = ptr;
	talloc_free(trans->socket);
	return 0;
}

static NTSTATUS after_negprot(struct smbcli_transport **dst_transport,
			      const char *dest_host, uint16_t port,
			      const char *my_name)
{
	struct smbcli_socket *sock;
	struct smbcli_transport *transport;
	NTSTATUS status;

	sock = smbcli_sock_init(NULL);
	if (sock == NULL)
		return NT_STATUS_NO_MEMORY;

	if (!smbcli_sock_connect_byname(sock, dest_host, port)) {
		talloc_free(sock);
		DEBUG(2,("Failed to establish socket connection - %s\n",
			 strerror(errno)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	transport = smbcli_transport_init(sock);
	talloc_free(sock);
	if (transport == NULL)
		return NT_STATUS_NO_MEMORY;

	talloc_set_destructor(transport, destroy_transport);

	{
		struct nmb_name calling;
		struct nmb_name called;

		/* send a NBT session request, if applicable */
		make_nmb_name(&calling, my_name, 0x0);
		choose_called_name(&called, dest_host, 0x20);

		if (!smbcli_transport_connect(transport, &calling, &called)) {
			talloc_free(transport);
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* negotiate protocol options with the server */
	status = smb_raw_negotiate(transport);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(transport);
		return NT_STATUS_UNSUCCESSFUL;
	}

	*dst_transport = transport;

	return NT_STATUS_OK;
}

static int destroy_session(void *ptr)
{
	struct smbcli_session *session = ptr;
	smb_raw_ulogoff(session);
	return 0;
}

static int destroy_tree_and_session(void *ptr)
{
	struct smbcli_tree *tree = ptr;
	smb_tree_disconnect(tree);
	talloc_free(tree->session);
	return 0;
}

static NTSTATUS anon_ipc(struct smbcli_transport *transport,
			 struct smbcli_tree **dst_tree)
{
	struct smbcli_tree *tree;
	struct smbcli_session *session;
	union smb_sesssetup setup;
	union smb_tcon tcon;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;

	session = smbcli_session_init(transport);
	if (session == NULL)
		return NT_STATUS_NO_MEMORY;

	mem_ctx = talloc_init("session_init");
	if (mem_ctx == NULL) {
		talloc_free(session);
		return NT_STATUS_NO_MEMORY;
	}

	/* prepare a session setup to establish a security context */
	setup.generic.level = RAW_SESSSETUP_GENERIC;
	setup.generic.in.sesskey = transport->negotiate.sesskey;
	setup.generic.in.capabilities = transport->negotiate.capabilities;
	setup.generic.in.password = NULL;
	setup.generic.in.user = "";
	setup.generic.in.domain = "";
	setup.generic.in.capabilities &= ~CAP_EXTENDED_SECURITY;

	status = smb_raw_session_setup(session, mem_ctx, &setup);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(session);
		talloc_free(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	session->vuid = setup.generic.out.vuid;

	talloc_set_destructor(session, destroy_session);

	tree = smbcli_tree_init(session);
	talloc_free(session);
	if (tree == NULL) {
		talloc_free(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	tcon.generic.level = RAW_TCON_TCONX;
	tcon.tconx.in.flags = 0;
	tcon.tconx.in.password = data_blob(NULL, 0);
	tcon.tconx.in.path = talloc_asprintf(mem_ctx, "\\\\%s\\IPC$",
					    transport->called.name);
	tcon.tconx.in.device = "IPC";

	status = smb_tree_connect(tree, mem_ctx, &tcon);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tree);
		talloc_free(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	tree->tid = tcon.tconx.out.cnum;

	if (tcon.tconx.out.dev_type != NULL)
		tree->device = talloc_strdup(tree, tcon.tconx.out.dev_type);

	if (tcon.tconx.out.fs_type != NULL)
		tree->fs_type = talloc_strdup(tree, tcon.tconx.out.fs_type);

	talloc_set_destructor(tree, destroy_tree_and_session);

	talloc_free(mem_ctx);

	*dst_tree = tree;

	return NT_STATUS_OK;
}

static int close_pipe(void *ptr)
{
	struct dcerpc_pipe *p = ptr;
	dcerpc_pipe_close(p);
	return 0;
}

static NTSTATUS connect_to_pipe(struct dcerpc_pipe **p,
				struct smbcli_transport *transport,
				const char *pipe_name,
				const char *pipe_uuid,
				uint32_t pipe_version)
{
	const char *binding = lp_parm_string(-1, "torture", "binding");
	struct dcerpc_binding b;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	struct smbcli_tree *tree;

	if (!NT_STATUS_IS_OK(status = anon_ipc(transport, &tree)))
		return status;

	if (binding == NULL)
		return NT_STATUS_INVALID_PARAMETER;

	mem_ctx = talloc_init("dcerpc_pipe_connect");
	if (!mem_ctx) return NT_STATUS_NO_MEMORY;

	status = dcerpc_parse_binding(mem_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to parse dcerpc binding '%s'\n", binding));
		talloc_destroy(mem_ctx);
		return status;
	}

	DEBUG(3,("Using binding %s\n", dcerpc_binding_string(mem_ctx, &b)));

	if (b.endpoint == NULL) {
		const struct dcerpc_interface_table *table =
			idl_iface_by_uuid(pipe_uuid);
		struct dcerpc_binding default_binding;
		int i;

		if (!table) {
			DEBUG(0,("Unknown interface endpoint '%s'\n",
				 pipe_uuid));
			talloc_destroy(mem_ctx);
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* Find one of the default pipes for this interface */
		for (i = 0; i < table->endpoints->count; i++) {
			const char * const *names = table->endpoints->names;
			status = dcerpc_parse_binding(mem_ctx, names[i],
						      &default_binding);

			if (NT_STATUS_IS_OK(status) &&
			    default_binding.transport == NCACN_NP) {
				pipe_name = default_binding.endpoint;	
				break;
			}
		}
	} else {
		pipe_name = b.endpoint;
	}

	if (!strncasecmp(pipe_name, "/pipe/", 6) || 
		!strncasecmp(pipe_name, "\\pipe\\", 6)) {
		pipe_name+=6;
	}

	if (pipe_name[0] != '\\') {
		pipe_name = talloc_asprintf(mem_ctx, "\\%s", pipe_name);
	}
	
	status = dcerpc_pipe_open_smb(p, tree, pipe_name);

	if (!NT_STATUS_IS_OK(status))
		return status;

	talloc_destroy(mem_ctx);
	
	talloc_set_destructor(*p, close_pipe);
	talloc_steal(*p, tree);

	return NT_STATUS_OK;
}

static NTSTATUS test_enumtrusts(struct smbcli_transport *transport)
{
	struct policy_handle handle;
	struct lsa_EnumTrustDom r2;
	uint32_t resume_handle = 0;
	struct lsa_ObjectAttribute attr;
	struct lsa_OpenPolicy2 r1;
	struct lsa_DomainList domains;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
        struct dcerpc_pipe *p;

	mem_ctx = talloc_init("test_enumtrusts");
	if (mem_ctx == NULL)
		return NT_STATUS_NO_MEMORY;

	status = connect_to_pipe(&p, transport, DCERPC_LSARPC_NAME,
				 DCERPC_LSARPC_UUID, 
				 DCERPC_LSARPC_VERSION);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return status;
	}

	status = dcerpc_bind_auth_none(p, DCERPC_LSARPC_UUID,
				       DCERPC_LSARPC_VERSION);

	if (!NT_STATUS_IS_OK(status))
		return status;

	printf("\ntesting OpenPolicy2\n");

	attr.len = 0;
	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = NULL;

	r1.in.system_name = talloc_asprintf(mem_ctx,
					    "\\\\%s", dcerpc_server_name(p));
	r1.in.attr = &attr;
	r1.in.access_mask = 1;
	r1.out.handle = &handle;

	status = dcerpc_lsa_OpenPolicy2(p, mem_ctx, &r1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenPolicy2 failed - %s\n", nt_errstr(status));
		return status;
	}

	printf("\nTesting EnumTrustDom\n");

	r2.in.handle = &handle;
	r2.in.resume_handle = &resume_handle;
	r2.in.num_entries = 1000;
	r2.out.domains = &domains;
	r2.out.resume_handle = &resume_handle;

	status = dcerpc_lsa_EnumTrustDom(p, mem_ctx, &r2);

	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES))
		return status;

	talloc_free(p);

	talloc_destroy(mem_ctx);

	return NT_STATUS_OK;
}

static NTSTATUS test_lookupnames(struct smbcli_transport *transport,
				 const char *name)
{
	struct policy_handle handle;
	struct lsa_ObjectAttribute attr;
	struct lsa_OpenPolicy2 r1;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
        struct dcerpc_pipe *p;

	mem_ctx = talloc_init("test_lookupnames");
	if (mem_ctx == NULL)
		return NT_STATUS_NO_MEMORY;

	status = connect_to_pipe(&p, transport, DCERPC_LSARPC_NAME,
				 DCERPC_LSARPC_UUID, 
				 DCERPC_LSARPC_VERSION);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return status;
	}

	status = dcerpc_bind_auth_none(p, DCERPC_LSARPC_UUID,
				       DCERPC_LSARPC_VERSION);

	if (!NT_STATUS_IS_OK(status))
		return status;

	attr.len = 0;
	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = NULL;

	r1.in.system_name = talloc_asprintf(mem_ctx,
					    "\\\\%s", dcerpc_server_name(p));
	r1.in.attr = &attr;
	r1.in.access_mask = 0x801;
	r1.out.handle = &handle;

	status = dcerpc_lsa_OpenPolicy2(p, mem_ctx, &r1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenPolicy2 failed - %s\n", nt_errstr(status));
		return status;
	}

	{
		struct lsa_LookupNames l;
		struct lsa_TransSidArray sids;
		struct lsa_String lsaname;
		uint32_t count = 0;

		sids.count = 0;
		sids.sids = NULL;

		lsaname.string = name;

		l.in.handle = &handle;
		l.in.num_names = 1;
		l.in.names = &lsaname;
		l.in.sids = &sids;
		l.in.level = 2;
		l.in.count = &count;
		l.out.count = &count;
		l.out.sids = &sids;

		status = dcerpc_lsa_LookupNames(p, mem_ctx, &l);
		if (!NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
			printf("LookupNames failed - %s\n", nt_errstr(status));
			talloc_free(p);
			talloc_destroy(mem_ctx);
			return NT_STATUS_OK;
		}
	}

	{
		struct lsa_Close c;
		struct policy_handle handle2;

		c.in.handle = &handle;
		c.out.handle = &handle2;

		status = dcerpc_lsa_Close(p, mem_ctx, &c);
		if (!NT_STATUS_IS_OK(status)) {
			printf("Close failed - %s\n", nt_errstr(status));
			return status;
		}
	}

	talloc_free(p);

	talloc_destroy(mem_ctx);

	return NT_STATUS_OK;
}

static NTSTATUS setup_netlogon_creds(struct smbcli_transport *transport,
				     struct dcerpc_pipe **p,
				     const char *machine_name,
				     const char *domain,
				     const char *machine_pwd,
				     struct creds_CredentialState *creds)
{
        NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate2 a;
	struct netr_Credential credentials1, credentials2, credentials3;
	const char *plain_pass;
	struct samr_Password mach_password;
	uint32_t negotiate_flags = NETLOGON_NEG_AUTH2_FLAGS;

	
	mem_ctx = talloc_init("torture_rpc_login");

	if (mem_ctx == NULL)
		return NT_STATUS_NO_MEMORY;

	status = connect_to_pipe(p, transport, DCERPC_NETLOGON_NAME,
				 DCERPC_NETLOGON_UUID,
				 DCERPC_NETLOGON_VERSION);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return status;
	}

	status = dcerpc_bind_auth_none(*p, DCERPC_NETLOGON_UUID,
				       DCERPC_NETLOGON_VERSION);

	if (!NT_STATUS_IS_OK(status))
		return status;

	printf("Testing ServerReqChallenge\n");

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s",
					   dcerpc_server_name(*p));
	r.in.computer_name = machine_name;
	r.in.credentials = &credentials1;
	r.out.credentials = &credentials2;

	generate_random_buffer(credentials1.data, sizeof(credentials1.data));

	status = dcerpc_netr_ServerReqChallenge(*p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerReqChallenge - %s\n", nt_errstr(status));
		return status;
	}

	plain_pass = machine_pwd;
	if (!plain_pass) {
		printf("Unable to fetch machine password!\n");
		return status;
	}

	E_md4hash(plain_pass, mach_password.hash);

	a.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s",
					   dcerpc_server_name(*p));
	a.in.account_name = talloc_asprintf(mem_ctx, "%s$", machine_name);
	a.in.secure_channel_type = SEC_CHAN_WKSTA;
	a.in.computer_name = machine_name;
	a.in.negotiate_flags = &negotiate_flags;
	a.out.negotiate_flags = &negotiate_flags;
	a.in.credentials = &credentials3;
	a.out.credentials = &credentials3;

	creds_client_init(creds, &credentials1, &credentials2,
			  &mach_password, &credentials3, 
			  negotiate_flags);

	printf("Testing ServerAuthenticate2\n");

	status = dcerpc_netr_ServerAuthenticate2(*p, mem_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerAuthenticate2 - %s\n", nt_errstr(status));
		return status;
	}

	if (!creds_client_check(creds, &credentials3)) {
		printf("Credential chaining failed\n");
		return status;
	}

	printf("negotiate_flags=0x%08x\n", negotiate_flags);

	talloc_free(mem_ctx);
	return NT_STATUS_OK;
}

static NTSTATUS torture_samlogon(struct dcerpc_pipe *p,
				 struct creds_CredentialState *netlogon_creds,
				 const char *workstation,
				 const char *domain,
				 const char *username,
				 const char *password)
{
	TALLOC_CTX *mem_ctx;
	struct netr_LogonSamLogon log;
	struct netr_NetworkInfo ninfo;
	struct netr_Authenticator auth, auth2;
	uint8_t user_session_key[16];
	DATA_BLOB ntlmv2_response = data_blob(NULL, 0);
	DATA_BLOB lmv2_response = data_blob(NULL, 0);
	DATA_BLOB names_blob;
	DATA_BLOB chall;
	NTSTATUS status;

	mem_ctx = talloc_init("torture_samlogon");

	ZERO_STRUCT(user_session_key);

	printf("testing netr_LogonSamLogon\n");

	log.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s",
					     dcerpc_server_name(p));
	log.in.workstation = workstation;
	log.in.credential = &auth;
	log.in.return_authenticator = &auth2;
	log.in.validation_level = 3;
	log.in.logon_level = 2;
	log.in.logon.network = &ninfo;

	chall = data_blob_talloc(mem_ctx, NULL, 8);
	generate_random_buffer(chall.data, 8);	

	names_blob = NTLMv2_generate_names_blob(mem_ctx, workstation,
						lp_workgroup());
	ZERO_STRUCT(user_session_key);

	if (!SMBNTLMv2encrypt(username, domain, password,
			      &chall, &names_blob,
			      &lmv2_response, &ntlmv2_response, 
			      NULL, NULL)) {
		data_blob_free(&names_blob);
		talloc_destroy(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}
	data_blob_free(&names_blob);

	ninfo.identity_info.domain_name.string = domain;
	ninfo.identity_info.parameter_control = 0;
	ninfo.identity_info.logon_id_low = 0;
	ninfo.identity_info.logon_id_high = 0;
	ninfo.identity_info.account_name.string = username;
	ninfo.identity_info.workstation.string = workstation;
	memcpy(ninfo.challenge, chall.data, 8);
	ninfo.nt.data = ntlmv2_response.data;
	ninfo.nt.length = ntlmv2_response.length;
	ninfo.lm.data = NULL;
	ninfo.lm.length = 0;

	ZERO_STRUCT(auth2);
	creds_client_authenticator(netlogon_creds, &auth);

	log.out.return_authenticator = NULL;
	status = dcerpc_netr_LogonSamLogon(p, mem_ctx, &log);
	talloc_destroy(mem_ctx);
	data_blob_free(&lmv2_response);
	data_blob_free(&ntlmv2_response);
	return status;
}

static NTSTATUS test_getgroups(struct smbcli_transport *transport,
			       const char *name)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
        struct dcerpc_pipe *p;

	struct samr_Connect4 r4;
	struct policy_handle connect_handle, domain_handle, user_handle;

	mem_ctx = talloc_init("test_lookupnames");
	if (mem_ctx == NULL)
		return NT_STATUS_NO_MEMORY;

	status = connect_to_pipe(&p, transport, DCERPC_SAMR_NAME,
				 DCERPC_SAMR_UUID, 
				 DCERPC_SAMR_VERSION);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return status;
	}

	status = dcerpc_bind_auth_none(p, DCERPC_SAMR_UUID,
				       DCERPC_SAMR_VERSION);

	if (!NT_STATUS_IS_OK(status))
		return status;

	r4.in.system_name = talloc_asprintf(mem_ctx, "\\\\%s",
					    dcerpc_server_name(p));
	r4.in.unknown = 0;
	r4.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r4.out.connect_handle = &connect_handle;

	status = dcerpc_samr_Connect4(p, mem_ctx, &r4);
	if (!NT_STATUS_IS_OK(status))
		return status;

	{
		struct samr_EnumDomains e;
		uint32_t resume_handle = 0;
		int i;

		e.in.connect_handle = &connect_handle;
		e.in.resume_handle = &resume_handle;
		e.in.buf_size = (uint32_t)-1;
		e.out.resume_handle = &resume_handle;
		status = dcerpc_samr_EnumDomains(p, mem_ctx, &e);
		if (!NT_STATUS_IS_OK(status))
			return status;

		for (i=0; i<e.out.sam->count; i++) {

			struct samr_LookupDomain l;
			struct samr_OpenDomain o;

			if (strcmp(e.out.sam->entries[i].name.string,
				   "Builtin") == 0)
				continue;

			l.in.connect_handle = &connect_handle;
			l.in.domain = &e.out.sam->entries[i].name;

			status = dcerpc_samr_LookupDomain(p, mem_ctx, &l);

			if (!NT_STATUS_IS_OK(status))
				return status;

			o.in.connect_handle = &connect_handle;
			o.in.access_mask = 0x200;
			o.in.sid = l.out.sid;
			o.out.domain_handle = &domain_handle;

			status = dcerpc_samr_OpenDomain(p, mem_ctx, &o);

			if (!NT_STATUS_IS_OK(status))
				return status;

			break;
		}
	}

	{
		struct samr_LookupNames l;
		struct samr_String samr_name;
		struct samr_OpenUser o;

		samr_name.string = name;

		l.in.domain_handle = &domain_handle;
		l.in.num_names = 1;
		l.in.names = &samr_name;

		status = dcerpc_samr_LookupNames(p, mem_ctx, &l);

		if (!NT_STATUS_IS_OK(status))
			return status;

		o.in.domain_handle = &domain_handle;
		o.in.rid = l.out.rids.ids[0];
		o.in.access_mask = 0x100;
		o.out.user_handle = &user_handle;

		status = dcerpc_samr_OpenUser(p, mem_ctx, &o);
		
		if (!NT_STATUS_IS_OK(status))
			return status;
	}

	{
		struct samr_GetGroupsForUser g;
		struct samr_LookupRids l;
		int i;

		g.in.user_handle = &user_handle;

		status = dcerpc_samr_GetGroupsForUser(p, mem_ctx, &g);
		if (!NT_STATUS_IS_OK(status))
			return status;

		l.in.domain_handle = &domain_handle;
		l.in.num_rids = g.out.rids->count;
		l.in.rids = talloc(mem_ctx,
				   g.out.rids->count * sizeof(uint32_t));

		for (i=0; i<g.out.rids->count; i++)
			l.in.rids[i] = g.out.rids->rid[i].rid;

		status = dcerpc_samr_LookupRids(p, mem_ctx, &l);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_destroy(mem_ctx);
			return status;
		}
	}

	{
		struct samr_Close c;

		c.in.handle = &user_handle;
		c.out.handle = &user_handle;
		dcerpc_samr_Close(p, mem_ctx, &c);

		c.in.handle = &domain_handle;
		c.out.handle = &domain_handle;
		dcerpc_samr_Close(p, mem_ctx, &c);

		c.in.handle = &connect_handle;
		c.out.handle = &connect_handle;
		dcerpc_samr_Close(p, mem_ctx, &c);
	}

	talloc_free(p);
	talloc_destroy(mem_ctx);

	return NT_STATUS_OK;
}

static NTSTATUS test_getallsids(struct smbcli_transport *transport,
				const char *name, BOOL includeDomain)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
        struct dcerpc_pipe *p;

	struct samr_Connect4 r4;
	struct policy_handle connect_handle, user_handle;
	struct policy_handle builtin_handle, domain_handle;
	struct dom_sid *domain_sid;

	struct dom_sid *user_sid;
	struct dom_sid *primary_group_sid;
	struct samr_GetGroupsForUser g;


	mem_ctx = talloc_init("test_getallsids");
	if (mem_ctx == NULL)
		return NT_STATUS_NO_MEMORY;

	status = connect_to_pipe(&p, transport, DCERPC_SAMR_NAME,
				 DCERPC_SAMR_UUID, 
				 DCERPC_SAMR_VERSION);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return status;
	}

	status = dcerpc_bind_auth_none(p, DCERPC_SAMR_UUID,
				       DCERPC_SAMR_VERSION);

	if (!NT_STATUS_IS_OK(status))
		return status;

	r4.in.system_name = talloc_asprintf(mem_ctx, "\\\\%s",
					    dcerpc_server_name(p));
	r4.in.unknown = 0;
	r4.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r4.out.connect_handle = &connect_handle;

	status = dcerpc_samr_Connect4(p, mem_ctx, &r4);
	if (!NT_STATUS_IS_OK(status))
		return status;

	{
		struct samr_EnumDomains e;
		struct samr_OpenDomain o;
		uint32_t resume_handle = 0;
		int i;

		e.in.connect_handle = &connect_handle;
		e.in.resume_handle = &resume_handle;
		e.in.buf_size = (uint32_t)-1;
		e.out.resume_handle = &resume_handle;
		status = dcerpc_samr_EnumDomains(p, mem_ctx, &e);
		if (!NT_STATUS_IS_OK(status))
			return status;

		for (i=0; i<e.out.sam->count; i++) {

			struct samr_LookupDomain l;

			if (strcmp(e.out.sam->entries[i].name.string,
				   "Builtin") == 0)
				continue;

			l.in.connect_handle = &connect_handle;
			l.in.domain = &e.out.sam->entries[i].name;

			status = dcerpc_samr_LookupDomain(p, mem_ctx, &l);

			if (!NT_STATUS_IS_OK(status))
				return status;

			o.in.connect_handle = &connect_handle;
			o.in.access_mask = 0x280;
			domain_sid = l.out.sid;
			o.in.sid = l.out.sid;
			o.out.domain_handle = &domain_handle;

			status = dcerpc_samr_OpenDomain(p, mem_ctx, &o);

			if (!NT_STATUS_IS_OK(status))
				return status;
			break;
		}
		o.in.connect_handle = &connect_handle;
		o.in.access_mask = 0x280;
		o.in.sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32");
		o.out.domain_handle = &builtin_handle;

		status = dcerpc_samr_OpenDomain(p, mem_ctx, &o);

		if (!NT_STATUS_IS_OK(status))
			return status;
	}

	{
		struct samr_LookupNames l;
		struct samr_String samr_name;
		struct samr_OpenUser o;

		samr_name.string = name;

		l.in.domain_handle = &domain_handle;
		l.in.num_names = 1;
		l.in.names = &samr_name;

		status = dcerpc_samr_LookupNames(p, mem_ctx, &l);

		if (!NT_STATUS_IS_OK(status))
			return status;

		o.in.domain_handle = &domain_handle;
		o.in.rid = l.out.rids.ids[0];
		o.in.access_mask = 0x100;
		o.out.user_handle = &user_handle;

		status = dcerpc_samr_OpenUser(p, mem_ctx, &o);
		
		if (!NT_STATUS_IS_OK(status))
			return status;
	}

	{
		struct samr_QueryUserInfo q;

		q.in.user_handle = &user_handle;
		q.in.level = 21;

		status = dcerpc_samr_QueryUserInfo(p, mem_ctx, &q);

		if (!NT_STATUS_IS_OK(status))
			return status;

		user_sid = dom_sid_add_rid(mem_ctx, domain_sid,
					   q.out.info->info21.rid);
		primary_group_sid = dom_sid_add_rid(mem_ctx, domain_sid,
						    q.out.info->info21.primary_gid);
	}

	g.in.user_handle = &user_handle;

	status = dcerpc_samr_GetGroupsForUser(p, mem_ctx, &g);
	if (!NT_STATUS_IS_OK(status))
		return status;

	{
		struct lsa_SidArray sids;
		struct samr_Ids rids;
		struct samr_GetAliasMembership ga;
		int i;

		ga.in.alias_handle = &builtin_handle;

		sids.num_sids = g.out.rids->count+2;
		sids.sids = talloc_array_p(mem_ctx, struct lsa_SidPtr,
					   g.out.rids->count+2);
		sids.sids[0].sid = user_sid;
		sids.sids[1].sid = primary_group_sid;
		for (i=0; i<g.out.rids->count; i++) {
			sids.sids[i+2].sid = dom_sid_add_rid(mem_ctx,
							     domain_sid,
							     g.out.rids->rid[i].rid);
		}
		ga.in.sids = &sids;
		ga.out.rids = &rids;

		status = dcerpc_samr_GetAliasMembership(p, mem_ctx, &ga);
		if (!NT_STATUS_IS_OK(status))
			return status;

		if (includeDomain) {
			ga.in.alias_handle = &domain_handle;
			status = dcerpc_samr_GetAliasMembership(p, mem_ctx,
								&ga);
			if (!NT_STATUS_IS_OK(status))
				return status;
		}
	}

	{
		struct samr_Close c;

		c.in.handle = &user_handle;
		c.out.handle = &user_handle;
		dcerpc_samr_Close(p, mem_ctx, &c);

		c.in.handle = &domain_handle;
		c.out.handle = &domain_handle;
		dcerpc_samr_Close(p, mem_ctx, &c);

		c.in.handle = &builtin_handle;
		c.out.handle = &builtin_handle;
		dcerpc_samr_Close(p, mem_ctx, &c);

		c.in.handle = &connect_handle;
		c.out.handle = &connect_handle;
		dcerpc_samr_Close(p, mem_ctx, &c);
	}

	talloc_free(p);
	talloc_destroy(mem_ctx);

	return NT_STATUS_OK;
}

static NTSTATUS test_remoteTOD(struct smbcli_transport *transport)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
        struct dcerpc_pipe *p;
	struct srvsvc_NetRemoteTOD r;

	mem_ctx = talloc_init("test_lookupnames");
	if (mem_ctx == NULL)
		return NT_STATUS_NO_MEMORY;

	status = connect_to_pipe(&p, transport, DCERPC_SRVSVC_NAME,
				 DCERPC_SRVSVC_UUID,
				 DCERPC_SRVSVC_VERSION);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return status;
	}

	status = dcerpc_bind_auth_none(p, DCERPC_SRVSVC_UUID,
				       DCERPC_SRVSVC_VERSION);

	if (!NT_STATUS_IS_OK(status))
		return status;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));

	ZERO_STRUCT(r.out);
	status = dcerpc_srvsvc_NetRemoteTOD(p, mem_ctx, &r);
	talloc_destroy(mem_ctx);
	talloc_free(p);
	return status;
}

static BOOL xp_login(const char *dcname, const char *wksname,
		     const char *domain, const char *wkspwd,
		     const char *user1name, const char *user1pw,
		     const char *user2name, const char *user2pw)
{
        NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	char *user1dom;

	struct smbcli_transport *transport;

        struct dcerpc_pipe *netlogon_pipe;
	struct creds_CredentialState *netlogon_creds;

	struct dcerpc_pipe *netlogon_schannel_pipe;

	talloc_enable_leak_report();

	mem_ctx = talloc_init("rpc_login");

	if (mem_ctx == NULL)
		return False;

	netlogon_creds = talloc_p(mem_ctx, struct creds_CredentialState);
	if (!netlogon_creds) {
		return False;
	}

	if (!NT_STATUS_IS_OK(after_negprot(&transport, dcname, 139,
					   wksname)))
		return False;

	if (!NT_STATUS_IS_OK(setup_netlogon_creds(transport, &netlogon_pipe,
						  wksname, domain, wkspwd,
						  netlogon_creds)))
		return False;

	if (!NT_STATUS_IS_OK(test_enumtrusts(transport)))
		return False;

	user1dom = talloc_asprintf(mem_ctx, "%s\\%s", domain, user1name);

	if (!NT_STATUS_IS_OK(test_lookupnames(transport, user1dom)))
		return False;

	status = connect_to_pipe(&netlogon_schannel_pipe,
				 transport, DCERPC_NETLOGON_NAME,
				 DCERPC_NETLOGON_UUID,
				 DCERPC_NETLOGON_VERSION);

	if (!NT_STATUS_IS_OK(status))
		return False;

	netlogon_schannel_pipe->flags |= DCERPC_SEAL;

	status = dcerpc_bind_auth_schannel_withkey(netlogon_schannel_pipe,
						   DCERPC_NETLOGON_UUID,
						   DCERPC_NETLOGON_VERSION,
						   "", "", "",
						   netlogon_creds);

	if (!NT_STATUS_IS_OK(status))
                return False;

	status = torture_samlogon(netlogon_schannel_pipe,
				  netlogon_creds, wksname, domain,
				  user1name, user1pw);

	if (!NT_STATUS_IS_OK(status))
                return False;

	talloc_free(netlogon_pipe);

	status = torture_samlogon(netlogon_schannel_pipe,
				  netlogon_creds, wksname, domain,
				  user2name, user2pw);

	if (!NT_STATUS_IS_OK(status))
                return False;

	status = test_getgroups(transport, user2name);
	
	if (!NT_STATUS_IS_OK(status))
                return False;

	status = test_remoteTOD(transport);
	
	if (!NT_STATUS_IS_OK(status))
                return False;

	status = test_remoteTOD(transport);
	
	if (!NT_STATUS_IS_OK(status))
                return False;

	status = test_getallsids(transport, user2name, False);
	
	if (!NT_STATUS_IS_OK(status))
                return False;

	status = test_getgroups(transport, user2name);
	
	if (!NT_STATUS_IS_OK(status))
                return False;

	status = test_getallsids(transport, user2name, True);
	
	if (!NT_STATUS_IS_OK(status))
                return False;

	talloc_free(netlogon_schannel_pipe);

	talloc_free(transport);

	talloc_destroy(mem_ctx);

	return True;
}

struct user_pw {
	const char *username;
	const char *password;
};

static const struct user_pw users[] = {
	{ "username1", "password1" },
	{ "username2", "password2" }
};

static const struct user_pw machines[] = {
	{ "machine1", "mpw1" },
	{ "machine2", "mpw2" }
};

BOOL torture_rpc_login(void)
{
	const char *pdcname = "pdcname";
	const char *domainname = "domain";

	int useridx1 = rand() % ARRAY_SIZE(users);
	int useridx2 = rand() % ARRAY_SIZE(users);
	int machidx = rand() % ARRAY_SIZE(machines);
	printf("machine: %s user1: %s user2: %s\n",
	       machines[machidx].username,
	       users[useridx1].username,
	       users[useridx2].username);

	return xp_login(pdcname, machines[machidx].username,
			domainname, machines[machidx].password,
			users[useridx1].username,
			users[useridx1].password,
			users[useridx2].username,
			users[useridx2].password);
}
