/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Tim Potter 2000

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
#include "rpcclient.h"

static NTSTATUS cmd_netlogon_logon_ctrl2(struct cli_state *cli, 
                                         TALLOC_CTX *mem_ctx, int argc, 
                                         const char **argv)
{
	uint32 query_level = 1;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (argc > 1) {
		fprintf(stderr, "Usage: %s\n", argv[0]);
		return NT_STATUS_OK;
	}

	result = cli_netlogon_logon_ctrl2(cli, mem_ctx, query_level);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* Display results */

 done:
	return result;
}

static NTSTATUS cmd_netlogon_getdcname(struct cli_state *cli, 
				       TALLOC_CTX *mem_ctx, int argc, 
				       const char **argv)
{
	fstring dcname;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s domainname\n", argv[0]);
		return NT_STATUS_OK;
	}

	result = cli_netlogon_getdcname(cli, mem_ctx, argv[1], dcname);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* Display results */

	printf("%s\n", dcname);

 done:
	return result;
}

static NTSTATUS cmd_netlogon_logon_ctrl(struct cli_state *cli, 
                                        TALLOC_CTX *mem_ctx, int argc, 
                                        const char **argv)
{
#if 0
	uint32 query_level = 1;
#endif
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (argc > 1) {
		fprintf(stderr, "Usage: %s\n", argv[0]);
		return NT_STATUS_OK;
	}

#if 0
	result = cli_netlogon_logon_ctrl(cli, mem_ctx, query_level);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}
#endif

	/* Display results */

	return result;
}

/* Display sam synchronisation information */

static void display_sam_sync(uint32 num_deltas, SAM_DELTA_HDR *hdr_deltas,
                             SAM_DELTA_CTR *deltas)
{
        fstring name;
        uint32 i, j;

        for (i = 0; i < num_deltas; i++) {
                switch (hdr_deltas[i].type) {
                case SAM_DELTA_DOMAIN_INFO:
                        unistr2_to_ascii(name,
                                         &deltas[i].domain_info.uni_dom_name,
                                         sizeof(name) - 1);
                        printf("Domain: %s\n", name);
                        break;
                case SAM_DELTA_GROUP_INFO:
                        unistr2_to_ascii(name,
                                         &deltas[i].group_info.uni_grp_name,
                                         sizeof(name) - 1);
                        printf("Group: %s\n", name);
                        break;
                case SAM_DELTA_ACCOUNT_INFO:
                        unistr2_to_ascii(name, 
                                         &deltas[i].account_info.uni_acct_name,
                                         sizeof(name) - 1);
                        printf("Account: %s\n", name);
                        break;
                case SAM_DELTA_ALIAS_INFO:
                        unistr2_to_ascii(name, 
                                         &deltas[i].alias_info.uni_als_name,
                                         sizeof(name) - 1);
                        printf("Alias: %s\n", name);
                        break;
                case SAM_DELTA_ALIAS_MEM: {
                        SAM_ALIAS_MEM_INFO *alias = &deltas[i].als_mem_info;

                        for (j = 0; j < alias->num_members; j++) {
                                fstring sid_str;

                                sid_to_string(sid_str, &alias->sids[j].sid);

                                printf("%s\n", sid_str);
                        }
                        break;
                }
                case SAM_DELTA_GROUP_MEM: {
                        SAM_GROUP_MEM_INFO *group = &deltas[i].grp_mem_info;

                        for (j = 0; j < group->num_members; j++)
                                printf("rid 0x%x, attrib 0x%08x\n", 
                                          group->rids[j], group->attribs[j]);
                        break;
                }
                case SAM_DELTA_MODIFIED_COUNT: {
                        SAM_DELTA_MOD_COUNT *mc = &deltas[i].mod_count;

                        printf("sam sequence update: 0x%04x\n", mc->seqnum);
                        break;
                }                                  
                default:
                        printf("unknown delta type 0x%02x\n", 
                                  hdr_deltas[i].type);
                        break;
                }
        }
}

/* Perform sam synchronisation */

static NTSTATUS cmd_netlogon_sam_sync(struct cli_state *cli, 
                                      TALLOC_CTX *mem_ctx, int argc,
                                      const char **argv)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        uint32 database_id = 0, num_deltas;
        SAM_DELTA_HDR *hdr_deltas;
        SAM_DELTA_CTR *deltas;
	DOM_CRED ret_creds;

        if (argc > 2) {
                fprintf(stderr, "Usage: %s [database_id]\n", argv[0]);
                return NT_STATUS_OK;
        }

        if (argc == 2)
                database_id = atoi(argv[1]);

	/* on first call the returnAuthenticator is empty */
	memset(&ret_creds, 0, sizeof(ret_creds));
 
        /* Synchronise sam database */

	result = cli_netlogon_sam_sync(cli, mem_ctx, &ret_creds, database_id,
				       0, &num_deltas, &hdr_deltas, &deltas);

	if (!NT_STATUS_IS_OK(result))
		goto done;

        /* Display results */

        display_sam_sync(num_deltas, hdr_deltas, deltas);

 done:
        return result;
}

/* Perform sam delta synchronisation */

static NTSTATUS cmd_netlogon_sam_deltas(struct cli_state *cli, 
                                        TALLOC_CTX *mem_ctx, int argc,
                                        const char **argv)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        uint32 database_id, num_deltas, tmp;
        SAM_DELTA_HDR *hdr_deltas;
        SAM_DELTA_CTR *deltas;
        UINT64_S seqnum;

        if (argc != 3) {
                fprintf(stderr, "Usage: %s database_id seqnum\n", argv[0]);
                return NT_STATUS_OK;
        }

        database_id = atoi(argv[1]);
        tmp = atoi(argv[2]);

        seqnum.low = tmp & 0xffff;
        seqnum.high = 0;

	result = cli_netlogon_sam_deltas(cli, mem_ctx, database_id,
					 seqnum, &num_deltas, 
					 &hdr_deltas, &deltas);

	if (!NT_STATUS_IS_OK(result))
		goto done;

        /* Display results */

        display_sam_sync(num_deltas, hdr_deltas, deltas);
        
 done:
        return result;
}

/* Log on a domain user */

static NTSTATUS cmd_netlogon_sam_logon(struct cli_state *cli, 
                                       TALLOC_CTX *mem_ctx, int argc,
                                       const char **argv)
{
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        int logon_type = NET_LOGON_TYPE;
        const char *username, *password;
	uint32 neg_flags = 0x000001ff;
	int auth_level = 2;
	DOM_CRED ret_creds;

        /* Check arguments */

        if (argc < 3 || argc > 6) {
                fprintf(stderr, "Usage: samlogon <username> <password> "
                        "[logon_type] [neg flags] [auth level (2 or 3)]\n"
			"neg flags being 0x000001ff or 0x6007ffff\n");
                return NT_STATUS_OK;
        }

        username = argv[1];
        password = argv[2];

        if (argc == 4)
                sscanf(argv[3], "%i", &logon_type);

	if (argc == 5)
                sscanf(argv[4], "%i", &neg_flags);

	if (argc == 6)
                sscanf(argv[5], "%i", &auth_level);

        /* Perform the sam logon */

	ZERO_STRUCT(ret_creds);

        result = cli_netlogon_sam_logon(cli, mem_ctx, &ret_creds, username, password, logon_type);

	clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), &ret_creds);
	
        result = cli_netlogon_sam_logon(cli, mem_ctx, &ret_creds, username, password, logon_type);

	clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), &ret_creds);

	if (!NT_STATUS_IS_OK(result))
		goto done;

 done:
        return result;
}

/* Change the trust account password */

static NTSTATUS cmd_netlogon_change_trust_pw(struct cli_state *cli, 
					     TALLOC_CTX *mem_ctx, int argc,
					     const char **argv)
{
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	DOM_CRED ret_creds;

        /* Check arguments */

        if (argc > 1) {
                fprintf(stderr, "Usage: change_trust_pw");
                return NT_STATUS_OK;
        }

        /* Perform the sam logon */

	ZERO_STRUCT(ret_creds);

	result = trust_pw_find_change_and_store_it(cli, mem_ctx,
						   lp_workgroup());

	clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), &ret_creds);

	if (!NT_STATUS_IS_OK(result))
		goto done;

 done:
        return result;
}


/* List of commands exported by this module */

struct cmd_set netlogon_commands[] = {

	{ "NETLOGON" },

	{ "logonctrl2", RPC_RTYPE_NTSTATUS, cmd_netlogon_logon_ctrl2, NULL, PI_NETLOGON, "Logon Control 2",     "" },
	{ "getdcname", RPC_RTYPE_NTSTATUS, cmd_netlogon_getdcname, NULL, PI_NETLOGON, "Get trusted DC name",     "" },
	{ "logonctrl",  RPC_RTYPE_NTSTATUS, cmd_netlogon_logon_ctrl,  NULL, PI_NETLOGON, "Logon Control",       "" },
	{ "samsync",    RPC_RTYPE_NTSTATUS, cmd_netlogon_sam_sync,    NULL, PI_NETLOGON, "Sam Synchronisation", "" },
	{ "samdeltas",  RPC_RTYPE_NTSTATUS, cmd_netlogon_sam_deltas,  NULL, PI_NETLOGON, "Query Sam Deltas",    "" },
	{ "samlogon",   RPC_RTYPE_NTSTATUS, cmd_netlogon_sam_logon,   NULL, PI_NETLOGON, "Sam Logon",           "" },
	{ "samlogon",   RPC_RTYPE_NTSTATUS, cmd_netlogon_change_trust_pw,   NULL, PI_NETLOGON, "Change Trust Account Password",           "" },

	{ NULL }
};
