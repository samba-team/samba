/* 
   Unix SMB/CIFS implementation.
   dump the remote SAM using rpc samsync operations

   Copyright (C) Andrew Tridgell 2002
   Copyright (C) Tim Potter 2001,2002

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
#include "../utils/net.h"

static void display_group_mem_info(uint32 rid, SAM_GROUP_MEM_INFO *g)
{
	int i;
	d_printf("Group mem %u: ", rid);
	for (i=0;i<g->num_members;i++) {
		d_printf("%u ", g->rids[i]);
	}
	d_printf("\n");
}

static void display_alias_info(uint32 rid, SAM_ALIAS_INFO *a)
{
	d_printf("Alias '%s' ", unistr2_static(&a->uni_als_name));
	d_printf("desc='%s' rid=%u\n", unistr2_static(&a->uni_als_desc), a->als_rid);
}

static void display_alias_mem(uint32 rid, SAM_ALIAS_MEM_INFO *a)
{
	int i;
	d_printf("Alias rid %u: ", rid);
	for (i=0;i<a->num_members;i++) {
		d_printf("%s ", sid_string_static(&a->sids[i].sid));
	}
	d_printf("\n");
}

static void display_account_info(uint32 rid, SAM_ACCOUNT_INFO *a)
{
	fstring hex_nt_passwd, hex_lm_passwd;
	uchar lm_passwd[16], nt_passwd[16];

	/* Decode hashes from password hash */
	sam_pwd_hash(a->user_rid, a->pass.buf_lm_pwd, lm_passwd, 0);
	sam_pwd_hash(a->user_rid, a->pass.buf_nt_pwd, nt_passwd, 0);
	
	/* Encode as strings */
	smbpasswd_sethexpwd(hex_lm_passwd, lm_passwd, a->acb_info);
	smbpasswd_sethexpwd(hex_nt_passwd, nt_passwd, a->acb_info);
	
	printf("%s:%d:%s:%s:%s:LCT-0\n", unistr2_static(&a->uni_acct_name),
	       a->user_rid, hex_lm_passwd, hex_nt_passwd,
	       smbpasswd_encode_acb_info(a->acb_info));
}

static void display_sam_entry(SAM_DELTA_HDR *hdr_delta, SAM_DELTA_CTR *delta)
{
	switch (hdr_delta->type) {
	case SAM_DELTA_ACCOUNT_INFO:
		display_account_info(hdr_delta->target_rid, &delta->account_info);
		break;
	case SAM_DELTA_GROUP_MEM:
		display_group_mem_info(hdr_delta->target_rid, &delta->grp_mem_info);
		break;
	case SAM_DELTA_ALIAS_INFO:
		display_alias_info(hdr_delta->target_rid, &delta->alias_info);
		break;
	case SAM_DELTA_ALIAS_MEM:
		display_alias_mem(hdr_delta->target_rid, &delta->als_mem_info);
		break;
	default:
		d_printf("Unknown delta record type %d\n", hdr_delta->type);
		break;
	}
}


static void dump_database(struct cli_state *cli, unsigned db_type, DOM_CRED *ret_creds)
{
	unsigned last_rid = 0;
        NTSTATUS result;
	int i;
        TALLOC_CTX *mem_ctx;
        SAM_DELTA_HDR *hdr_deltas;
        SAM_DELTA_CTR *deltas;
        uint32 num_deltas;

	if (!(mem_ctx = talloc_init())) {
		return;
	}

	d_printf("Dumping database %u\n", db_type);

	do {
		result = cli_netlogon_sam_sync(cli, mem_ctx, ret_creds, db_type, last_rid+1,
					       &num_deltas, &hdr_deltas, &deltas);
		clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), ret_creds);
		last_rid = 0;
                for (i = 0; i < num_deltas; i++) {
			display_sam_entry(&hdr_deltas[i], &deltas[i]);
			last_rid = hdr_deltas[i].target_rid;
			if (last_rid == 0) {
				break;
			}
                }
	} while (last_rid && NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

	talloc_destroy(mem_ctx);
}

/* dump sam database via samsync rpc calls */
int rpc_samdump(int argc, const char **argv)
{
        NTSTATUS result;
	struct cli_state *cli = NULL;
	uchar trust_password[16];
	DOM_CRED ret_creds;

	ZERO_STRUCT(ret_creds);

	/* Connect to remote machine */
	if (!(cli = net_make_ipc_connection(NET_FLAGS_ANONYMOUS | NET_FLAGS_PDC))) {
		return 1;
	}

	if (!cli_nt_session_open(cli, PIPE_NETLOGON)) {
		DEBUG(0,("Error connecting to NETLOGON pipe\n"));
		goto fail;
	}

	if (!secrets_fetch_trust_account_password(lp_workgroup(), trust_password, NULL)) {
		d_printf("Could not retrieve domain trust secret");
		goto fail;
	}
	
	result = cli_nt_setup_creds(cli, SEC_CHAN_BDC,  trust_password);
	if (!NT_STATUS_IS_OK(result)) {
		d_printf("Failed to setup BDC creds\n");
		goto fail;
	}

	dump_database(cli, SAM_DATABASE_DOMAIN, &ret_creds);
	dump_database(cli, SAM_DATABASE_BUILTIN, &ret_creds);
	dump_database(cli, SAM_DATABASE_PRIVS, &ret_creds);

	cli_nt_session_close(cli);
        
        return 0;

fail:
	if (cli) {
		cli_nt_session_close(cli);
	}
	return -1;
}
