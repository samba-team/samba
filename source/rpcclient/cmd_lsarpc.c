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

/* Look up domain related information on a remote host */

static NTSTATUS cmd_lsa_query_info_policy(struct cli_state *cli, 
                                          TALLOC_CTX *mem_ctx, int argc, 
                                          char **argv) 
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	DOM_SID dom_sid;
	fstring sid_str, domain_name;
	uint32 info_class = 3;

	if (argc > 2) {
		printf("Usage: %s [info_class]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc == 2)
		info_class = atoi(argv[1]);
	
	result = cli_lsa_open_policy(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* Lookup info policy */

	result = cli_lsa_query_info_policy(cli, mem_ctx, &pol, info_class, 
					   domain_name, &dom_sid);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	sid_to_string(sid_str, &dom_sid);

	if (domain_name[0])
		printf("domain %s has sid %s\n", domain_name, sid_str);
	else
		printf("could not query info for level %d\n", info_class);

 done:
	return result;
}

/* Resolve a list of names to a list of sids */

static NTSTATUS cmd_lsa_lookup_names(struct cli_state *cli, 
                                     TALLOC_CTX *mem_ctx, int argc, 
                                     char **argv)
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	DOM_SID *sids;
	uint32 *types;
	int i;

	if (argc == 1) {
		printf("Usage: %s [name1 [name2 [...]]]\n", argv[0]);
		return NT_STATUS_OK;
	}

	result = cli_lsa_open_policy(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_lsa_lookup_names(cli, mem_ctx, &pol, argc - 1,
					(const char**)(argv + 1), &sids, &types);

	if (!NT_STATUS_IS_OK(result) && NT_STATUS_V(result) !=
			NT_STATUS_V(STATUS_SOME_UNMAPPED))
		goto done;

	result = NT_STATUS_OK;

	/* Print results */

	for (i = 0; i < (argc - 1); i++) {
		fstring sid_str;

		sid_to_string(sid_str, &sids[i]);
		printf("%s %s (%d)\n", argv[i + 1], sid_str,
		       types[i]);
	}

 done:
	return result;
}

/* Resolve a list of SIDs to a list of names */

static NTSTATUS cmd_lsa_lookup_sids(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                                    int argc, char **argv)
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	DOM_SID *sids;
	char **domains;
	char **names;
	uint32 *types;
	int i;

	if (argc == 1) {
		printf("Usage: %s [sid1 [sid2 [...]]]\n", argv[0]);
		return NT_STATUS_OK;
	}

	result = cli_lsa_open_policy(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* Convert arguments to sids */

	sids = (DOM_SID *)talloc(mem_ctx, sizeof(DOM_SID) * (argc - 1));

	if (!sids) {
		printf("could not allocate memory for %d sids\n", argc - 1);
		goto done;
	}

	for (i = 0; i < argc - 1; i++)
		string_to_sid(&sids[i], argv[i + 1]);

	/* Lookup the SIDs */

	result = cli_lsa_lookup_sids(cli, mem_ctx, &pol, argc - 1, sids,
					&domains, &names, &types);

	if (!NT_STATUS_IS_OK(result) && NT_STATUS_V(result) !=
				NT_STATUS_V(STATUS_SOME_UNMAPPED))
		goto done;

	result = NT_STATUS_OK;

	/* Print results */

	for (i = 0; i < (argc - 1); i++) {
		fstring sid_str;

		sid_to_string(sid_str, &sids[i]);
		printf("%s %s\\%s (%d)\n", sid_str,
			domains[i] ? domains[i] : "*unknown*",
			names[i] ? names[i] : "*unknown*", types[i]);
	}

 done:
	return result;
}

/* Enumerate list of trusted domains */

static NTSTATUS cmd_lsa_enum_trust_dom(struct cli_state *cli, 
                                       TALLOC_CTX *mem_ctx, int argc, 
                                       char **argv)
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	DOM_SID *domain_sids;
	char **domain_names;
	uint32 enum_ctx = 0;
	uint32 num_domains;
	int i;

	if (argc != 1) {
		printf("Usage: %s\n", argv[0]);
		return NT_STATUS_OK;
	}

	result = cli_lsa_open_policy(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* Lookup list of trusted domains */

	result = cli_lsa_enum_trust_dom(cli, mem_ctx, &pol, &enum_ctx,
					&num_domains, &domain_names,
					&domain_sids);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* Print results */

	for (i = 0; i < num_domains; i++) {
		fstring sid_str;

		sid_to_string(sid_str, &domain_sids[i]);
		printf("%s %s\n", domain_names[i] ? domain_names[i] : 
		       "*unknown*", sid_str);
	}

 done:
	return result;
}

/* Enumerates privileges */

static NTSTATUS cmd_lsa_enum_privilege(struct cli_state *cli, 
                                          TALLOC_CTX *mem_ctx, int argc, 
                                          char **argv) 
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	uint32 enum_context=0;
	uint32 pref_max_length=0x1000;
	uint32 count=0;
	char   **privs_name;
	uint32 *privs_high;
	uint32 *privs_low;
	int i;

	if (argc > 3) {
		printf("Usage: %s [enum context] [max length]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc>=2)
		enum_context=atoi(argv[1]);

	if (argc==3)
		pref_max_length=atoi(argv[2]);

	result = cli_lsa_open_policy(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_lsa_enum_privilege(cli, mem_ctx, &pol, &enum_context, pref_max_length,
					&count, &privs_name, &privs_high, &privs_low);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* Print results */
	printf("found %d privileges\n\n", count);

	for (i = 0; i < count; i++) {
		printf("%s \t\t%d:%d (0x%x:0x%x)\n", privs_name[i] ? privs_name[i] : "*unknown*",
		       privs_high[i], privs_low[i], privs_high[i], privs_low[i]);
	}

 done:
	return result;
}

/* Get privilege name */

static NTSTATUS cmd_lsa_get_dispname(struct cli_state *cli, 
                                     TALLOC_CTX *mem_ctx, int argc, 
                                     char **argv) 
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	uint16 lang_id=0;
	uint16 lang_id_sys=0;
	uint16 lang_id_desc;
	fstring description;

	if (argc != 2) {
		printf("Usage: %s privilege name\n", argv[0]);
		return NT_STATUS_OK;
	}

	result = cli_lsa_open_policy(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_lsa_get_dispname(cli, mem_ctx, &pol, argv[1], lang_id, lang_id_sys, description, &lang_id_desc);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* Print results */
	printf("%s -> %s (language: 0x%x)\n", argv[1], description, lang_id_desc);

 done:
	return result;
}

/* Enumerate the LSA SIDS */

static NTSTATUS cmd_lsa_enum_sids(struct cli_state *cli, 
                                     TALLOC_CTX *mem_ctx, int argc, 
                                     char **argv) 
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	uint32 enum_context=0;
	uint32 pref_max_length=0x1000;
	DOM_SID *sids;
	uint32 count=0;
	int i;

	if (argc > 3) {
		printf("Usage: %s [enum context] [max length]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc>=2)
		enum_context=atoi(argv[1]);

	if (argc==3)
		pref_max_length=atoi(argv[2]);

	result = cli_lsa_open_policy(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_lsa_enum_sids(cli, mem_ctx, &pol, &enum_context, pref_max_length,
					&count, &sids);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* Print results */
	printf("found %d SIDs\n\n", count);

	for (i = 0; i < count; i++) {
		fstring sid_str;

		sid_to_string(sid_str, &sids[i]);
		printf("%s\n", sid_str);
	}

 done:
	return result;
}

/* Enumerate the privileges of an SID */

static NTSTATUS cmd_lsa_enum_privsaccounts(struct cli_state *cli, 
                                           TALLOC_CTX *mem_ctx, int argc, 
                                           char **argv) 
{
	POLICY_HND dom_pol;
	POLICY_HND user_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 access_desired = 0x000f000f;
	
	DOM_SID sid;
	uint32 count=0;
	LUID_ATTR *set;
	int i;

	if (argc != 2 ) {
		printf("Usage: %s SID\n", argv[0]);
		return NT_STATUS_OK;
	}

	string_to_sid(&sid, argv[1]);

	result = cli_lsa_open_policy2(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &dom_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_lsa_open_account(cli, mem_ctx, &dom_pol, &sid, access_desired, &user_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_lsa_enum_privsaccount(cli, mem_ctx, &user_pol, &count, &set);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* Print results */
	printf("found %d privileges for SID %s\n\n", count, argv[1]);
	printf("high\tlow\tattribute\n");

	for (i = 0; i < count; i++) {
		printf("%u\t%u\t%u\n", set[i].luid.high, set[i].luid.low, set[i].attr);
	}

 done:
	return result;
}

/* Get a privilege value given its name */

static NTSTATUS cmd_lsa_lookupprivvalue(struct cli_state *cli, 
                                           TALLOC_CTX *mem_ctx, int argc, 
                                           char **argv) 
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	LUID luid;

	if (argc != 2 ) {
		printf("Usage: %s name\n", argv[0]);
		return NT_STATUS_OK;
	}

	result = cli_lsa_open_policy2(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_lsa_lookupprivvalue(cli, mem_ctx, &pol, argv[1], &luid);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* Print results */

	printf("%u:%u (0x%x:0x%x)\n", luid.high, luid.low, luid.high, luid.low);

 done:
	return result;
}

/* Query LSA security object */

static NTSTATUS cmd_lsa_query_secobj(struct cli_state *cli, 
				     TALLOC_CTX *mem_ctx, int argc, 
				     char **argv) 
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	SEC_DESC_BUF *sdb;
	uint32 sec_info = 0x00000004; /* ??? */

	if (argc != 1 ) {
		printf("Usage: %s\n", argv[0]);
		return NT_STATUS_OK;
	}

	result = cli_lsa_open_policy2(cli, mem_ctx, True, 
				      SEC_RIGHTS_MAXIMUM_ALLOWED,
				      &pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_lsa_query_secobj(cli, mem_ctx, &pol, sec_info, &sdb);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* Print results */

	display_sec_desc(sdb->sec);

 done:
	return result;
}

/* List of commands exported by this module */

struct cmd_set lsarpc_commands[] = {

	{ "LSARPC" },

	{ "lsaquery", 	 cmd_lsa_query_info_policy, 	PIPE_LSARPC, "Query info policy",         "" },
	{ "lookupsids",  cmd_lsa_lookup_sids, 		PIPE_LSARPC, "Convert SIDs to names",     "" },
	{ "lookupnames", cmd_lsa_lookup_names, 		PIPE_LSARPC, "Convert names to SIDs",     "" },
	{ "enumtrust", 	 cmd_lsa_enum_trust_dom, 	PIPE_LSARPC, "Enumerate trusted domains", "" },
	{ "enumprivs", 	         cmd_lsa_enum_privilege,     PIPE_LSARPC, "Enumerate privileges",                 "" },
	{ "getdispname",         cmd_lsa_get_dispname,       PIPE_LSARPC, "Get the privilege name",               "" },
	{ "lsaenumsid",          cmd_lsa_enum_sids,          PIPE_LSARPC, "Enumerate the LSA SIDS",               "" },
	{ "lsaenumprivsaccount", cmd_lsa_enum_privsaccounts, PIPE_LSARPC, "Enumerate the privileges of an SID",   "" },
	{ "lsalookupprivvalue",  cmd_lsa_lookupprivvalue,    PIPE_LSARPC, "Get a privilege value given its name", "" },
	{ "lsaquerysecobj",      cmd_lsa_query_secobj,       PIPE_LSARPC, "Query LSA security object", "" },

	{ NULL }
};
