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
                                         char **argv)
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

static NTSTATUS cmd_netlogon_logon_ctrl(struct cli_state *cli, 
                                        TALLOC_CTX *mem_ctx, int argc, 
                                        char **argv)
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
                        unistr2_to_unix(name,
                                         &deltas[i].domain_info.uni_dom_name,
                                         sizeof(name) - 1);
                        printf("Domain: %s\n", name);
                        break;
                case SAM_DELTA_GROUP_INFO:
                        unistr2_to_unix(name,
                                         &deltas[i].group_info.uni_grp_name,
                                         sizeof(name) - 1);
                        printf("Group: %s\n", name);
                        break;
                case SAM_DELTA_ACCOUNT_INFO:
                        unistr2_to_unix(name, 
                                         &deltas[i].account_info.uni_acct_name,
                                         sizeof(name) - 1);
                        printf("Account: %s\n", name);
                        break;
                case SAM_DELTA_ALIAS_INFO:
                        unistr2_to_unix(name, 
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
                case SAM_DELTA_SAM_STAMP: {
                        SAM_DELTA_STAMP *stamp = &deltas[i].stamp;

                        printf("sam sequence update: 0x%04x\n",
                                  stamp->seqnum);
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
                                      char **argv)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        unsigned char trust_passwd[16];
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

        if (!secrets_init()) {
                fprintf(stderr, "Unable to initialise secrets database\n");
                return result;
        }

        /* Initialise session credentials */

	if (!secrets_fetch_trust_account_password(lp_workgroup(), trust_passwd,
                                                  NULL)) {
		fprintf(stderr, "could not fetch trust account password\n");
		goto done;
	}        

        result = cli_nt_setup_creds(cli, trust_passwd);

        if (!NT_STATUS_IS_OK(result)) {
                fprintf(stderr, "Error initialising session creds\n");
                goto done;
        }

	/* on first call the returnAuthenticator is empty */
	memset(&ret_creds, 0, sizeof(ret_creds));
 
        /* Synchronise sam database */

	result = cli_netlogon_sam_sync(cli, mem_ctx, &ret_creds, database_id,
				       &num_deltas, &hdr_deltas, &deltas);

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
                                        char **argv)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        unsigned char trust_passwd[16];
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

        if (!secrets_init()) {
                fprintf(stderr, "Unable to initialise secrets database\n");
                goto done;
        }

        /* Initialise session credentials */

	if (!secrets_fetch_trust_account_password(lp_workgroup(), trust_passwd,
                                                  NULL)) {
		fprintf(stderr, "could not fetch trust account password\n");
		goto done;
	}        

        result = cli_nt_setup_creds(cli, trust_passwd);

        if (!NT_STATUS_IS_OK(result)) {
                fprintf(stderr, "Error initialising session creds\n");
                goto done;
        }

        /* Synchronise sam database */

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
                                       char **argv)
{
        unsigned char trust_passwd[16];
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        int logon_type = NET_LOGON_TYPE;
        char *username, *password;

        /* Check arguments */

        if (argc < 3 || argc > 4) {
                fprintf(stderr, "Usage: samlogon <username> <password> "
                        "[logon_type]\n");
                return NT_STATUS_OK;
        }

        username = argv[1];
        password = argv[2];

        if (argc == 4)
                sscanf(argv[3], "%i", &logon_type);

        /* Authenticate ourselves with the domain controller */

        if (!secrets_init()) {
                fprintf(stderr, "Unable to initialise secrets database\n");
                return result;
        }

	if (!secrets_fetch_trust_account_password(lp_workgroup(), trust_passwd,
                                                  NULL)) {
		fprintf(stderr, "could not fetch trust account password\n");
		goto done;
	}        

        result = cli_nt_setup_creds(cli, trust_passwd);

        if (!NT_STATUS_IS_OK(result)) {
                fprintf(stderr, "Error initialising session creds\n");
                goto done;
        }

        /* Perform the sam logon */

        result = cli_netlogon_sam_logon(cli, mem_ctx, username, password,
                                        logon_type);

	if (!NT_STATUS_IS_OK(result))
		goto done;

 done:
        return result;
}

/* List of commands exported by this module */

struct cmd_set netlogon_commands[] = {

	{ "NETLOGON" },

	{ "logonctrl2", cmd_netlogon_logon_ctrl2, PIPE_NETLOGON, "Logon Control 2",     "" },
	{ "logonctrl",  cmd_netlogon_logon_ctrl,  PIPE_NETLOGON, "Logon Control",       "" },
	{ "samsync",    cmd_netlogon_sam_sync,    PIPE_NETLOGON, "Sam Synchronisation", "" },
	{ "samdeltas",  cmd_netlogon_sam_deltas,  PIPE_NETLOGON, "Query Sam Deltas",    "" },
        { "samlogon",   cmd_netlogon_sam_logon,   PIPE_NETLOGON, "Sam Logon",           "" },

	{ NULL }
};
