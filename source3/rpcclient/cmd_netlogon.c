/* 
   Unix SMB/Netbios implementation.
   Version 2.2
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

extern int DEBUGLEVEL;

static NTSTATUS cmd_netlogon_logon_ctrl2(struct cli_state *cli, int argc,
				       char **argv)
{
	uint32 query_level = 1;
	TALLOC_CTX *mem_ctx;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (argc > 1) {
		printf("Usage: %s\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0,("cmd_srvsvc_srv_query_info: talloc_init failed\n"));
		goto done;
	}

	/* Initialise RPC connection */

	if (!cli_nt_session_open (cli, PIPE_NETLOGON)) {
		DEBUG(0, ("Could not initialize srvsvc pipe!\n"));
		goto done;
	}

	result = cli_netlogon_logon_ctrl2(cli, mem_ctx, query_level);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Display results */

 done:
	return result;
}

static NTSTATUS cmd_netlogon_logon_ctrl(struct cli_state *cli, int argc,
				      char **argv)
{
#if 0
	uint32 query_level = 1;
#endif
	TALLOC_CTX *mem_ctx;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (argc > 1) {
		printf("Usage: %s\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0,("cmd_srvsvc_srv_query_info: talloc_init failed\n"));
		goto done;
	}

	/* Initialise RPC connection */

	if (!cli_nt_session_open (cli, PIPE_NETLOGON)) {
		DEBUG(0, ("Could not initialize netlogon pipe!\n"));
		goto done;
	}

#if 0
	result = cli_netlogon_logon_ctrl(cli, mem_ctx, query_level);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}
#endif

	/* Display results */

 done:
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
                        DEBUG(0, ("Domain: %s\n", name));
                        break;
                case SAM_DELTA_GROUP_INFO:
                        unistr2_to_ascii(name,
                                         &deltas[i].group_info.uni_grp_name,
                                         sizeof(name) - 1);
                        DEBUG(0, ("Group: %s\n", name));
                        break;
                case SAM_DELTA_ACCOUNT_INFO:
                        unistr2_to_ascii(name, 
                                         &deltas[i].account_info.uni_acct_name,
                                         sizeof(name) - 1);
                        DEBUG(0, ("Account: %s\n", name));
                        break;
                case SAM_DELTA_ALIAS_INFO:
                        unistr2_to_ascii(name, 
                                         &deltas[i].alias_info.uni_als_name,
                                         sizeof(name) - 1);
                        DEBUG(0, ("Alias: %s\n", name));
                        break;
                case SAM_DELTA_ALIAS_MEM: {
                        SAM_ALIAS_MEM_INFO *alias = &deltas[i].als_mem_info;

                        for (j = 0; j < alias->num_members; j++) {
                                fstring sid_str;

                                sid_to_string(sid_str, &alias->sids[j].sid);

                                DEBUG(0, ("%s\n", sid_str));
                        }
                        break;
                }
                case SAM_DELTA_GROUP_MEM: {
                        SAM_GROUP_MEM_INFO *group = &deltas[i].grp_mem_info;

                        for (j = 0; j < group->num_members; j++)
                                DEBUG(0, ("rid 0x%x, attrib 0x%08x\n", 
                                          group->rids[j], group->attribs[j]));
                        break;
                }
                case SAM_DELTA_SAM_STAMP: {
                        SAM_DELTA_STAMP *stamp = &deltas[i].stamp;

                        DEBUG(0, ("sam sequence update: 0x%04x\n",
                                  stamp->seqnum));
                        break;
                }                                  
                default:
                        DEBUG(0, ("unknown delta type 0x%02x\n", 
                                  hdr_deltas[i].type));
                        break;
                }
        }
}

/* Perform sam synchronisation */

static NTSTATUS cmd_netlogon_sam_sync(struct cli_state *cli, int argc,
                                    char **argv)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        unsigned char trust_passwd[16];
        TALLOC_CTX *mem_ctx;
        uint32 database_id = 0, num_deltas;
        SAM_DELTA_HDR *hdr_deltas;
        SAM_DELTA_CTR *deltas;

        if (argc > 2) {
                printf("Usage: %s [database_id]\n", argv[0]);
                return NT_STATUS_OK;
        }

        if (argc == 2)
                database_id = atoi(argv[1]);

        if (!secrets_init()) {
                DEBUG(0, ("Unable to initialise secrets database\n"));
                return result;
        }

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0,("talloc_init failed\n"));
		return result;
	}

	/* Initialise RPC connection */

	if (!cli_nt_session_open (cli, PIPE_NETLOGON)) {
		DEBUG(0, ("Could not initialize netlogon pipe!\n"));
		goto done;
	}

        /* Initialise session credentials */

	if (!secrets_fetch_trust_account_password(lp_workgroup(), trust_passwd,
                                                  NULL)) {
		DEBUG(0, ("could not fetch trust account password\n"));
		goto done;
	}        

        result = cli_nt_setup_creds(cli, trust_passwd);

        if (!NT_STATUS_IS_OK(result)) {
                DEBUG(0, ("Error initialising session creds\n"));
                goto done;
        }

        /* Synchronise sam database */

	result = cli_netlogon_sam_sync(cli, mem_ctx, database_id,
				       &num_deltas, &hdr_deltas, &deltas);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

        /* Display results */

        display_sam_sync(num_deltas, hdr_deltas, deltas);

 done:
	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);
        
        return result;
}

/* Perform sam delta synchronisation */

static NTSTATUS cmd_netlogon_sam_deltas(struct cli_state *cli, int argc,
                                      char **argv)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        unsigned char trust_passwd[16];
        TALLOC_CTX *mem_ctx = NULL;
        uint32 database_id, num_deltas, tmp;
        SAM_DELTA_HDR *hdr_deltas;
        SAM_DELTA_CTR *deltas;
        UINT64_S seqnum;

        if (argc != 3) {
                printf("Usage: %s database_id seqnum\n", argv[0]);
                return NT_STATUS_OK;
        }

        database_id = atoi(argv[1]);
        tmp = atoi(argv[2]);

        seqnum.low = tmp & 0xffff;
        seqnum.high = 0;

        if (!secrets_init()) {
                DEBUG(0, ("Unable to initialise secrets database\n"));
                goto done;
        }

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0,("talloc_init failed\n"));
		goto done;
	}

	/* Initialise RPC connection */

	if (!cli_nt_session_open (cli, PIPE_NETLOGON)) {
		DEBUG(0, ("Could not initialize netlogon pipe!\n"));
		goto done;
	}

        /* Initialise session credentials */

	if (!secrets_fetch_trust_account_password(lp_workgroup(), trust_passwd,
                                                  NULL)) {
		DEBUG(0, ("could not fetch trust account password\n"));
		goto done;
	}        

        result = cli_nt_setup_creds(cli, trust_passwd);

        if (!NT_STATUS_IS_OK(result)) {
                DEBUG(0, ("Error initialising session creds\n"));
                goto done;
        }

        /* Synchronise sam database */

	result = cli_netlogon_sam_deltas(cli, mem_ctx, database_id,
					 seqnum, &num_deltas, 
					 &hdr_deltas, &deltas);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

        /* Display results */

        display_sam_sync(num_deltas, hdr_deltas, deltas);
        
 done:
	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

        return result;
}

/* List of commands exported by this module */

struct cmd_set netlogon_commands[] = {

	{ "NETLOGON" },

	{ "logonctrl2", cmd_netlogon_logon_ctrl2, "Logon Control 2",     "" },
	{ "logonctrl",  cmd_netlogon_logon_ctrl,  "Logon Control",       "" },
	{ "samsync",    cmd_netlogon_sam_sync,    "Sam Synchronisation", "" },
	{ "samdeltas",  cmd_netlogon_sam_deltas,  "Query Sam Deltas", "" },

	{ NULL }
};
