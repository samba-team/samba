/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   
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

extern FILE *out_hnd;

/* Convert SID_NAME_USE values to strings */

struct sid_name {
	enum SID_NAME_USE name_type;
	char *name;
} sid_name_type_str[] = {
	{ SID_NAME_UNKNOWN, "UNKNOWN" },       
	{ SID_NAME_USER,    "User" },
	{ SID_NAME_DOM_GRP, "Domain Group" },
	{ SID_NAME_DOMAIN,  "Domain" },
	{ SID_NAME_ALIAS,   "Local Group"} ,
	{ SID_NAME_WKN_GRP, "Well-known Group" },
	{ SID_NAME_DELETED, "Deleted" },
	{ SID_NAME_INVALID, "Invalid" },
	{ 0, NULL }
};

static char *get_sid_name_type_str(enum SID_NAME_USE name_type)
{
	int i = 0;

	while(sid_name_type_str[i].name) {
		if (name_type == sid_name_type_str[i].name_type) {
			return sid_name_type_str[i].name;
		}
		i++;
	}

	return NULL;
}

/* Look up a list of sids */

uint32 cmd_lsa_lookup_sids(struct client_info *info, int argc, char *argv[])
{
	POLICY_HND lsa_pol;
	fstring srv_name;
	char **names;
	DOM_SID *sids;
	int num_sids = 0, num_names, i;
	uint32 *types, result;

	/* Check command arguments */

	if (argc == 1) {
		fprintf(out_hnd, "lsa_lookupsids sid1 [sid2...]\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	sids = (DOM_SID *)malloc((argc - 1) * sizeof(DOM_SID));

	for (i = 1; i < argc; i++) {
		if (string_to_sid(&sids[num_sids], argv[i])) {
			num_sids++;
		} else {
			fprintf(out_hnd, "could not parse sid %s\n", argv[i]);
		}
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	/* Lookup domain controller; receive a policy handle */

	result = lsa_open_policy(srv_name, &lsa_pol, True,
				 SEC_RIGHTS_MAXIMUM_ALLOWED);

	if (result != 0) {
		report(out_hnd, "open policy failed: %s\n",
		       get_nt_error_msg(result));
		return result;
	}

	/* Send lsa lookup sids call */

	result = lsa_lookup_sids(&lsa_pol, num_sids, sids, &names,
				 &types, &num_names);

	if (result != 0) {
		report(out_hnd, "lookup names failed: %s\n",
		       get_nt_error_msg(result));
		return result;
	}

	result = lsa_close(&lsa_pol);

	if (result != 0) {
		report(out_hnd, "lsa close failed: %s\n",
		       get_nt_error_msg(result));
		return result;
	}

	/* Print output */

	if (names != NULL) {
		report(out_hnd, "Lookup SIDS:\n");

		for (i = 0; i < num_names; i++) {
			fstring temp;

			sid_to_string(temp, &sids[i]);

			report(out_hnd, "SID: %s -> %s (%d: %s)\n",
			       temp, names[i] ? names[i] : "(null)", 
			       types[i], get_sid_name_type_str(types[i]));

			if (names[i] != NULL) {
				free(names[i]);
			}
		}

		free(names);
	}

	if (types) {
		free(types);
	}

	return result;
}

/* Look up a list of names */

uint32 cmd_lsa_lookup_names(struct client_info *info, int argc, char *argv[])
{
	POLICY_HND lsa_pol;
	fstring srv_name;
	int num_names, i, num_sids;
	DOM_SID *sids;
	char **names;
	uint32 *types, result;

	/* Check command arguments */

	if (argc == 1) {
		fprintf(out_hnd, "lsa_lookupnames name1 [name2...]\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	names = (char **)malloc((argc - 1) * sizeof(char *));
	num_names = argc - 1;

	for (i = 1; i < argc; i++) {
		names[i - 1] = argv[i];
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	/* Lookup domain controller; receive a policy handle */

	result = lsa_open_policy(srv_name, &lsa_pol, True,
				 SEC_RIGHTS_MAXIMUM_ALLOWED);

	if (result != 0) {
		report(out_hnd, "open policy failed: %s\n",
		       get_nt_error_msg(result));
		return result;
	}

	/* Send lsa lookup names call */

	result = lsa_lookup_names(&lsa_pol, num_names, names, &sids,
				  &types, &num_sids);

	if (result != 0) {
		report(out_hnd, "lookup sids failed: %s\n",
		       get_nt_error_msg(result));
		return result;
	}

	result = lsa_close(&lsa_pol);

	if (result != 0) {
		report(out_hnd, "lsa close failed: %s\n",
		       get_nt_error_msg(result));
		return result;
	}

	/* Print output */

	if (sids != NULL) {
		fstring temp;

		report(out_hnd, "Lookup Names:\n");
		for (i = 0; i < num_sids; i++) {
			sid_to_string(temp, &sids[i]);
			report(out_hnd, "Name: %s -> %s (%d: %s)\n",
			       names[i], temp, types[i],
			       get_sid_name_type_str(types[i]));
#if 0
			if (sids[i] != NULL) {
				free(sids[i]);
			}
#endif
		}

		free(sids);
	}

	return result;
}

/* rpcclient interface */

static const struct command_set lsa_commands[] = {

	{ "LSARPC", NULL, NULL, {NULL, NULL} },

	{ "lsa_lookup_sids", cmd_lsa_lookup_sids },
	{ "lsa_lookup_names", cmd_lsa_lookup_names },

	{"", NULL, NULL, {NULL, NULL}}
};


void add_lsa_commands(void)
{
	add_command_set(lsa_commands);
}
