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

static uint32 cmd_lsa_query_info_policy(int argc, char **argv) 
{
	struct cli_state cli;
	POLICY_HND pol;
	uint32 result = NT_STATUS_UNSUCCESSFUL;
	struct ntuser_creds creds;
	BOOL got_policy_hnd = False;
	DOM_SID dom_sid;
	fstring sid_str, domain_name;
	uint32 info_class = 3;

	if (argc > 2) {
		printf("Usage: %s [info_class]\n", argv[0]);
		return 0;
	}

	if (argc == 2) {
		info_class = atoi(argv[1]);
	}
	
	/* Open a lsa handle */

	ZERO_STRUCT(cli);
	init_rpcclient_creds(&creds);

	if (cli_lsa_initialise(&cli, server, &creds) == NULL) {
		goto done;
	}

	if ((result = cli_lsa_open_policy(&cli, True, 
					  SEC_RIGHTS_MAXIMUM_ALLOWED,
					  &pol)) != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_policy_hnd = True;

	/* Lookup the names */

	if ((result = cli_lsa_query_info_policy(&cli, &pol, info_class, 
						domain_name, &dom_sid)) 
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	sid_to_string(sid_str, &dom_sid);

	printf("domain %s has sid %s\n", domain_name, sid_str);

 done:

	if (got_policy_hnd) {
		cli_lsa_close(&cli, &pol);
	}

	return result;
}

/* Resolve a list of names to a list of sids */

static uint32 cmd_lsa_lookup_names(int argc, char **argv)
{
	struct cli_state cli;
	struct ntuser_creds creds;
	POLICY_HND pol;
	uint32 result = NT_STATUS_UNSUCCESSFUL;
	BOOL got_policy_hnd = False;
	DOM_SID *sids;
	uint32 *types;
	int num_names, i;

	if (argc == 1) {
		printf("Usage: %s [name1 [name2 [...]]]\n", argv[0]);
		return 0;
	}

	/* Open a lsa handle */

	ZERO_STRUCT(cli);
	init_rpcclient_creds(&creds);

	if (cli_lsa_initialise(&cli, server, &creds) == NULL) {
		goto done;
	}

	if ((result = cli_lsa_open_policy(&cli, True, 
					  SEC_RIGHTS_MAXIMUM_ALLOWED,
					  &pol)) != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_policy_hnd = True;

	/* Lookup the names */

	if ((result = cli_lsa_lookup_names(
		&cli, &pol, argc - 1, &argv[1], &sids, &types, &num_names) !=
	     NT_STATUS_NOPROBLEMO)) {
		goto done;
	}

	/* Print results */

	for (i = 0; i < num_names; i++) {
		fstring sid_str;

		sid_to_string(sid_str, &sids[i]);
		printf("%s\t\t%s (%d)\n", argv[i + 1], sid_str,
		       types[i]);
	}

	safe_free(sids);
	safe_free(types);      

 done:

	if (got_policy_hnd) {
		cli_lsa_close(&cli, &pol);
	}

	return result;
}

/* Resolve a list of SIDs to a list of names */

static uint32 cmd_lsa_lookup_sids(int argc, char **argv)
{
	struct cli_state cli;
	POLICY_HND pol;
	uint32 result = NT_STATUS_UNSUCCESSFUL;
	struct ntuser_creds creds;
	BOOL got_policy_hnd = False;
	DOM_SID *sids;
	char **names;
	uint32 *types;
	int num_names, i;

	if (argc == 1) {
		printf("Usage: %s [sid1 [sid2 [...]]]\n", argv[0]);
		return 0;
	}

	/* Open a lsa handle */

	ZERO_STRUCT(cli);
	init_rpcclient_creds(&creds);

	if (cli_lsa_initialise(&cli, server, &creds) == NULL) {
		goto done;
	}

	if ((result = cli_lsa_open_policy(&cli, True, 
					  SEC_RIGHTS_MAXIMUM_ALLOWED,
					  &pol)) != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_policy_hnd = True;

	/* Convert arguments to sids */

	sids = (DOM_SID *)malloc(sizeof(DOM_SID) * (argc - 1));

	if (!sids) {
		printf("out of memory\n");
		goto done;
	}

	for (i = 0; i < argc - 1; i++) {
		string_to_sid(&sids[i], argv[i + 1]);
	}

	/* Lookup the SIDs */

	if ((result = cli_lsa_lookup_sids(&cli, &pol, argc - 1, sids, 
					  &names, &types, &num_names) !=
	     NT_STATUS_NOPROBLEMO)) {
		goto done;
	}

	/* Print results */

	for (i = 0; i < num_names; i++) {
		fstring sid_str;

		sid_to_string(sid_str, &sids[i]);
		printf("%s\t\t%s (%d)\n", sid_str, names[i] ? names[i] :
		       "*unknown*", types[i]);
	}

	safe_free(sids);
	safe_free(types);      

	for (i = 0; i < num_names; i++) {
		safe_free(names[i]);
	}

	safe_free(names);

 done:

	if (got_policy_hnd) {
		cli_lsa_close(&cli, &pol);
	}

	return result;
}

/* Enumerate list of trusted domains */

static uint32 cmd_lsa_enum_trust_dom(int argc, char **argv)
{
	struct cli_state cli;
	POLICY_HND pol;
	uint32 result = NT_STATUS_UNSUCCESSFUL;
	struct ntuser_creds creds;
	BOOL got_policy_hnd = False;
	DOM_SID *domain_sids;
	char **domain_names;
	int num_domains, enum_ctx = 0, i;

	if (argc != 1) {
		printf("Usage: %s\n", argv[0]);
		return 0;
	}

	/* Open a lsa handle */

	ZERO_STRUCT(cli);
	init_rpcclient_creds(&creds);

	if (cli_lsa_initialise(&cli, server, &creds) == NULL) {
		goto done;
	}

	if ((result = cli_lsa_open_policy(&cli, True, 
					  SEC_RIGHTS_MAXIMUM_ALLOWED,
					  &pol)) != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_policy_hnd = True;

	/* Lookup list of trusted domains */

	if ((result = cli_lsa_enum_trust_dom(&cli, &pol, &enum_ctx,
					     &num_domains, &domain_names,
					     &domain_sids) 
	     != NT_STATUS_NOPROBLEMO)) {
		goto done;
	}

	/* Print results */

	for (i = 0; i < num_domains; i++) {
		fstring sid_str;

		sid_to_string(sid_str, &domain_sids[i]);
		printf("%s\t\t%s\n", domain_names[i] ? domain_names[i] : 
		       "*unknown*", sid_str);
	}

	safe_free(domain_sids);

	for (i = 0; i < num_domains; i++) {
		safe_free(domain_names[i]);
	}

	safe_free(domain_names);

 done:

	if (got_policy_hnd) {
		cli_lsa_close(&cli, &pol);
	}

	return result;
}

/* List of commands exported by this module */

struct cmd_set lsarpc_commands[] = {
	{ "lsaquery", cmd_lsa_query_info_policy, "Query info policy" },
	{ "lookupsids", cmd_lsa_lookup_sids, "Convert SIDs to names" },
	{ "lookupnames", cmd_lsa_lookup_names, "Convert names to SIDs" },
	{ "enumtrust", cmd_lsa_enum_trust_dom, "Enumerate trusted domains" },
	{ NULL, NULL, NULL }
};
