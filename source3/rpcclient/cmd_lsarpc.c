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
extern pstring server;

/* Look up domain related information on a remote host */
static NTSTATUS cmd_lsa_query_info_policy(struct cli_state *cli, int argc, char **argv) 
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	BOOL got_policy_hnd = False;
	DOM_SID dom_sid;
	fstring sid_str, domain_name;
	uint32 info_class = 3;
	TALLOC_CTX *mem_ctx;

	if (argc > 2) {
		printf("Usage: %s [info_class]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0,("cmd_lsa_query_info_poicy: talloc_init failed\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (argc == 2) {
		info_class = atoi(argv[1]);
	}
	
	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_LSARPC)) {
		DEBUG(0, ("Could not initialize samr pipe!\n"));
		talloc_destroy(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	result = cli_lsa_open_policy(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	got_policy_hnd = True;

	/* Lookup info policy */

	result = cli_lsa_query_info_policy(cli, mem_ctx, &pol, info_class, 
					   domain_name, &dom_sid);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	sid_to_string(sid_str, &dom_sid);

	if (domain_name[0]) {
		printf("domain %s has sid %s\n", domain_name, sid_str);
	} else {
		printf("could not query info for level %d\n", info_class);
	}

done:

	if (got_policy_hnd) {
		cli_lsa_close(cli, mem_ctx, &pol);
	}

	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return result;
}

/* Resolve a list of names to a list of sids */

static NTSTATUS cmd_lsa_lookup_names(struct cli_state *cli, int argc, char **argv)
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	BOOL got_policy_hnd = False;
	DOM_SID *sids;
	uint32 *types;
	int num_names, i;
	TALLOC_CTX *mem_ctx;

	if (argc == 1) {
		printf("Usage: %s [name1 [name2 [...]]]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0,("cmd_lsa_lookup_names: talloc_init failed\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_LSARPC)) {
		DEBUG(0, ("Could not initialize samr pipe!\n"));
		talloc_destroy(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}


	result = cli_lsa_open_policy(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	got_policy_hnd = True;

	/* Lookup the names */

	result = cli_lsa_lookup_names(cli, mem_ctx, &pol, argc - 1, 
				      &argv[1], &sids, &types, &num_names);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Print results */

	for (i = 0; i < num_names; i++) {
		fstring sid_str;

		sid_to_string(sid_str, &sids[i]);
		printf("%s %s (%d)\n", argv[i + 1], sid_str,
		       types[i]);
	}

 done:

	if (got_policy_hnd) {
		cli_lsa_close(cli, mem_ctx, &pol);
	}

	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return result;
}

/* Resolve a list of SIDs to a list of names */

static NTSTATUS cmd_lsa_lookup_sids(struct cli_state *cli, int argc, char **argv)
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	BOOL got_policy_hnd = False;
	DOM_SID *sids;
	char **names;
	uint32 *types;
	int num_names, i;
	TALLOC_CTX *mem_ctx;

	if (argc == 1) {
		printf("Usage: %s [sid1 [sid2 [...]]]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0,("cmd_lsa_lookup_sids: talloc_init failed\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_LSARPC)) {
		DEBUG(0, ("Could not initialize samr pipe!\n"));
		talloc_destroy(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	result = cli_lsa_open_policy(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	got_policy_hnd = True;

	/* Convert arguments to sids */

	sids = (DOM_SID *)talloc(mem_ctx, sizeof(DOM_SID) * (argc - 1));

	if (!sids) {
		printf("out of memory\n");
		goto done;
	}

	for (i = 0; i < argc - 1; i++) {
		string_to_sid(&sids[i], argv[i + 1]);
	}

	/* Lookup the SIDs */

	result = cli_lsa_lookup_sids(cli, mem_ctx, &pol, argc - 1, sids, 
				     &names, &types, &num_names);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Print results */

	for (i = 0; i < num_names; i++) {
		fstring sid_str;

		sid_to_string(sid_str, &sids[i]);
		printf("%s %s (%d)\n", sid_str, names[i] ? names[i] :
		       "*unknown*", types[i]);
	}

#if 0	/* JERRY */
	SAFE_FREE(sids);
	SAFE_FREE(types);      

	for (i = 0; i < num_names; i++) {
		SAFE_FREE(names[i]);
	}

	SAFE_FREE(names);
#endif

 done:

	if (got_policy_hnd) {
		cli_lsa_close(cli, mem_ctx, &pol);
	}

	cli_nt_session_close(cli);
	talloc_destroy (mem_ctx);

	return result;
}

/* Enumerate list of trusted domains */

static NTSTATUS cmd_lsa_enum_trust_dom(struct cli_state *cli, int argc, char **argv)
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	BOOL got_policy_hnd = False;
	DOM_SID *domain_sids;
	char **domain_names;
	uint32 enum_ctx = 0;
	uint32 num_domains;
	int i;
	TALLOC_CTX *mem_ctx;

	if (argc != 1) {
		printf("Usage: %s\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0,("cmd_lsa_enum_trust_dom: talloc_init failed\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_LSARPC)) {
		DEBUG(0, ("Could not initialize samr pipe!\n"));
		talloc_destroy(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	result = cli_lsa_open_policy(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	got_policy_hnd = True;

	/* Lookup list of trusted domains */

	result = cli_lsa_enum_trust_dom(cli, mem_ctx, &pol, &enum_ctx,
					&num_domains, &domain_names,
					&domain_sids);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Print results */

	for (i = 0; i < num_domains; i++) {
		fstring sid_str;

		sid_to_string(sid_str, &domain_sids[i]);
		printf("%s %s\n", domain_names[i] ? domain_names[i] : 
		       "*unknown*", sid_str);
	}

 done:

	if (got_policy_hnd) {
		cli_lsa_close(cli, mem_ctx, &pol);
	}

	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return result;
}

/* List of commands exported by this module */

struct cmd_set lsarpc_commands[] = {

	{ "LSARPC" },

	{ "lsaquery", 	 cmd_lsa_query_info_policy, 	"Query info policy",         "" },
	{ "lookupsids",  cmd_lsa_lookup_sids, 		"Convert SIDs to names",     "" },
	{ "lookupnames", cmd_lsa_lookup_names, 		"Convert names to SIDs",     "" },
	{ "enumtrust", 	 cmd_lsa_enum_trust_dom, 	"Enumerate trusted domains", "" },

	{ NULL }
};
