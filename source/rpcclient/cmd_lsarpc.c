/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Elrond 2000
   
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
#include "rpc_parse.h"
#include "rpc_client.h"
#include "rpcclient.h"
#include "nterr.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

extern FILE *out_hnd;

/****************************************************************************
nt enumerate trusted domains
****************************************************************************/
void cmd_lsa_enum_trust_dom(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	uint32 num_doms = 0;
	char **domains = NULL;
	DOM_SID **sids = NULL;
	uint32 enum_ctx = 0;
	POLICY_HND lsa_pol;

	BOOL res = True;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	DEBUG(4, ("cmd_lsa_enum_trust_dom: server:%s\n", srv_name));

	/* lookup domain controller; receive a policy handle */
	res = res ? lsa_open_policy(srv_name,
				    &lsa_pol, False,
				    SEC_RIGHTS_MAXIMUM_ALLOWED) : False;

	do
	{
		/* send enum trusted domains query */
		res = res ? lsa_enum_trust_dom(&lsa_pol,
					       &enum_ctx,
					       &num_doms, &domains,
					       &sids) : False;

	}
	while (res && enum_ctx != 0);

	res = res ? lsa_close(&lsa_pol) : False;

	if (res)
	{
		uint32 i;
		DEBUG(5, ("cmd_lsa_enum_trust_dom: query succeeded\n"));

		report(out_hnd, "LSA Enumerate Trusted Domains\n");
		for (i = 0; i < num_doms; i++)
		{
			fstring sid;
			sid_to_string(sid, sids[i]);
			report(out_hnd, "Domain:\t%s\tSID:\t%s\n",
			       domains[i], sid);
		}
	}
	else
	{
		DEBUG(5, ("cmd_lsa_enum_trust_dom: query failed\n"));
	}

	free_char_array(num_doms, domains);
	free_sid_array(num_doms, sids);
}

/****************************************************************************
nt lsa query
****************************************************************************/
void cmd_lsa_query_info(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	POLICY_HND lsa_pol;

	BOOL res = True;

	fstrcpy(info->dom.level3_dom, "");
	fstrcpy(info->dom.level5_dom, "");
	ZERO_STRUCT(info->dom.level3_sid);
	ZERO_STRUCT(info->dom.level5_sid);

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	DEBUG(4, ("cmd_lsa_query_info: server:%s\n", srv_name));

	/* lookup domain controller; receive a policy handle */
	res = res ? lsa_open_policy(srv_name, &lsa_pol, False,
				    SEC_RIGHTS_MAXIMUM_ALLOWED) : False;

	/* send client info query, level 3.  receive domain name and sid */
	res = res ? lsa_query_info_pol(&lsa_pol, 0x03,
				       info->dom.level3_dom,
				       &info->dom.level3_sid) : False;

	/* send client info query, level 5.  receive domain name and sid */
	res = res ? lsa_query_info_pol(&lsa_pol, 0x05,
				       info->dom.level5_dom,
				       &info->dom.level5_sid) : False;

	res = res ? lsa_close(&lsa_pol) : False;

	if (res)
	{
		BOOL domain_something = False;
		fstring sid;
		DEBUG(5, ("cmd_lsa_query_info: query succeeded\n"));

		report(out_hnd, "LSA Query Info Policy\n");

		sid_to_string(sid, &info->dom.level3_sid);
		report(out_hnd, "Domain Member     - Domain: %s SID: %s\n",
		       info->dom.level3_dom, sid);
		if (info->dom.level3_dom[0] != 0)
		{
			domain_something = True;
		}
		sid_to_string(sid, &info->dom.level5_sid);
		report(out_hnd, "Domain Controller - Domain: %s SID: %s\n",
		       info->dom.level5_dom, sid);
		if (info->dom.level3_dom[0] != 0)
		{
			domain_something = True;
		}
		if (!domain_something)
		{
			report(out_hnd,
			       "%s is not a Domain Member or Controller\n",
			       info->dest_host);
		}
	}
	else
	{
		DEBUG(5, ("cmd_lsa_query_info: query failed\n"));
	}
}

/****************************************************************************
lookup names
****************************************************************************/
void cmd_lsa_lookup_names(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	int num_names = 0;
	char **names;
	uint32 *types = NULL;
	DOM_SID *sids = NULL;
	uint32 num_sids = 0;
	uint32 ret;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	DEBUG(4, ("cmd_lsa_lookup_names: server: %s\n", srv_name));

	argc--;
	argv++;

	num_names = argc;
	names = argv;

	if (num_names <= 0)
	{
		report(out_hnd, "lookupnames <name> [<name> ...]\n");
		return;
	}

	ret = lookup_lsa_names(srv_name,
			       num_names, names, &num_sids, &sids, &types);

	if (ret != 0x0)
	{
		report(out_hnd, "cmd_lsa_lookup_names: FAILED: %s\n",
		       get_nt_error_msg(ret));
	}

	if (sids != NULL)
	{
		int i;
		fstring temp;

		report(out_hnd, "Lookup Names:\n");
		for (i = 0; i < num_sids; i++)
		{
			sid_to_string(temp, &sids[i]);
			report(out_hnd, "SID: %s -> %s (%d: %s)\n",
			       names[i], temp, types[i],
			       get_sid_name_use_str(types[i]));
#if 0
			if (sids[i] != NULL)
			{
				free(sids[i]);
			}
#endif
		}
		free(sids);
	}
	safe_free(types);
}

/****************************************************************************
lookup sids
****************************************************************************/
void cmd_lsa_lookup_sids(struct client_info *info, int argc, char *argv[])
{
	POLICY_HND lsa_pol;
	int i;
	pstring sid_name;
	fstring srv_name;
	DOM_SID **sids = NULL;
	uint32 num_sids = 0;
	char **names = NULL;
	uint32 *types = NULL;
	int num_names = 0;

	BOOL res = True;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	DEBUG(4, ("cmd_lsa_lookup_sids: server: %s\n", srv_name));

	argv++;
	argc--;

	while (argc > 0)
	{
		DOM_SID sid;
		if (strnequal("S-", argv[0], 2))
		{
			fstrcpy(sid_name, argv[0]);
		}
		else
		{
			sid_to_string(sid_name, &info->dom.level5_sid);

			if (sid_name[0] == 0)
			{
				report(out_hnd,
				       "please use lsaquery first or specify a complete SID\n");
				return;
			}

			fstrcat(sid_name, "-");
			fstrcat(sid_name, argv[0]);
		}
		string_to_sid(&sid, sid_name);

		add_sid_to_array(&num_sids, &sids, &sid);

		argc--;
		argv++;
	}

	if (num_sids == 0)
	{
		report(out_hnd, "lookupsid RID or SID\n");
		return;
	}

	/* lookup domain controller; receive a policy handle */
	res = res ? lsa_open_policy(srv_name, &lsa_pol, True,
				    SEC_RIGHTS_MAXIMUM_ALLOWED) : False;

	/* send lsa lookup sids call */
	res = res ? lsa_lookup_sids(&lsa_pol,
				    num_sids, sids,
				    &names, &types, &num_names) : False;

	res = res ? lsa_close(&lsa_pol) : False;

	if (res)
	{
		DEBUG(5, ("cmd_lsa_lookup_sids: query succeeded\n"));
	}
	else
	{
		DEBUG(5, ("cmd_lsa_lookup_sids: query failed\n"));
	}
	if (names != NULL)
	{
		report(out_hnd, "Lookup SIDS:\n");
		for (i = 0; i < num_names; i++)
		{
			fstring temp;
			sid_to_string(temp, sids[i]);
			report(out_hnd, "SID: %s -> %s (%d: %s)\n",
			       temp, names[i], types[i],
			       get_sid_name_use_str(types[i]));
			if (names[i] != NULL)
			{
				free(names[i]);
			}
		}
		free(names);
	}

	if (types)
	{
		free(types);
	}

	free_sid_array(num_sids, sids);
}

/****************************************************************************
nt lsa query
****************************************************************************/
void cmd_lsa_set_secret(struct client_info *info, int argc, char *argv[])
{
	char *secret_name;
	fstring srv_name;
	char *data;
	int len;
	UNISTR2 uni_data;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc != 3)
	{
		report(out_hnd, "setsecret <secret name> <secret value>\n");
		return;
	}

	secret_name = argv[1];
	data = argv[2];
	len = strlen(argv[2]);

	make_unistr2(&uni_data, data, len);

	if (msrpc_lsa_set_secret(srv_name, secret_name,
				 (const char *)uni_data.buffer,
				 uni_data.uni_str_len * 2))
	{
		report(out_hnd, "LSA Set Secret: OK\n");
	}
	else
	{
		report(out_hnd, "LSA Set Secret: failed\n");
	}
}

/****************************************************************************
nt lsa query
****************************************************************************/
void cmd_lsa_create_secret(struct client_info *info, int argc, char *argv[])
{
	char *secret_name;
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc > 2)
	{
		report(out_hnd, "createsecret <secret name>\n");
		return;
	}

	secret_name = argv[1];

	if (msrpc_lsa_create_secret(srv_name, secret_name, 0x020003))
	{
		report(out_hnd, "LSA Create Secret: OK\n");
	}
	else
	{
		report(out_hnd, "LSA Query Secret: failed\n");
	}
}

/****************************************************************************
nt lsa query
****************************************************************************/
void cmd_lsa_query_secret_secobj(struct client_info *info, int argc,
				 char *argv[])
{
	char *secret_name;
	fstring srv_name;

	BOOL res = True;
	BOOL res1;
	BOOL res2;

	POLICY_HND pol_sec;
	POLICY_HND lsa_pol;
	SEC_DESC_BUF buf;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	ZERO_STRUCT(buf);

	if (argc > 2)
	{
		report(out_hnd, "querysecretsecdes <secret name>\n");
		return;
	}

	secret_name = argv[1];

	/* lookup domain controller; receive a policy handle */
	res = res ? lsa_open_policy(srv_name, &lsa_pol, False,
				    SEC_RIGHTS_MAXIMUM_ALLOWED) : False;

	/* lookup domain controller; receive a policy handle */
	res1 = res ? lsa_open_secret(&lsa_pol, secret_name,
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol_sec) : False;

	res2 = res1 ? lsa_query_sec_obj(&pol_sec, 0x07, &buf) : False;

	if (buf.sec != NULL)
	{
		display_sec_desc(out_hnd, ACTION_HEADER, buf.sec);
		display_sec_desc(out_hnd, ACTION_ENUMERATE, buf.sec);
		display_sec_desc(out_hnd, ACTION_FOOTER, buf.sec);
	}
	else
	{
		report(out_hnd, "LSA Query Secret: failed\n");
	}

	free_sec_desc_buf(&buf);

	res1 = res1 ? lsa_close(&pol_sec) : False;
	res = res ? lsa_close(&lsa_pol) : False;


}

/****************************************************************************
nt lsa query
****************************************************************************/
void cmd_lsa_query_secret(struct client_info *info, int argc, char *argv[])
{
	char *secret_name;
	STRING2 secret;
	NTTIME last_update;
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	ZERO_STRUCT(secret);

	if (argc > 2)
	{
		report(out_hnd, "querysecret <secret name>\n");
		return;
	}

	secret_name = argv[1];

	if (msrpc_lsa_query_secret(srv_name, secret_name, &secret,
				   &last_update))
	{
		int i;
		report(out_hnd, "\tValue       : ");
		for (i = 0; i < secret.str_str_len; i++)
		{
			report(out_hnd, "%02X", secret.buffer[i]);
		}

		report(out_hnd, "\n\tLast Updated: %s\n\n",
		       http_timestring(nt_time_to_unix(&last_update)));
	}
	else
	{
		report(out_hnd, "LSA Query Secret: failed\n");
	}
}

/****************************************************************************
****************************************************************************/
uint32 cmd_lsa_enum_privs(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	uint32 unk0 = 0, unk1 = 0x1000;
	BOOL do_info = False;
	POLICY_HND lsa_pol;
	uint32 count;
	LSA_PRIV_ENTRY *privs;

	BOOL res = True;
	BOOL res1 = True;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	DEBUG(4, ("cmd_lsa_enum_privileges: server:%s\n", srv_name));

	if (argc >= 2 && strequal(argv[1], "-i"))
		do_info = True;

	/* lookup domain controller; receive a policy handle */
	res = res ? lsa_open_policy(srv_name,
				    &lsa_pol, False,
				    SEC_RIGHTS_MAXIMUM_ALLOWED) : False;


	res1 = res ? lsa_enum_privs(&lsa_pol, unk0, unk1,
				    &count, &privs) : False;

	if (res1)
	{
		uint32 i;
		for (i = 0; i < count; i++)
		{
			char *name;
			name = unistr2_to_ascii(NULL, &privs[i].name, 0);
			report(out_hnd, "\t%3d  %s\n", privs[i].num, name);
			if (do_info)
			{
				UNISTR2 *uni_desc = NULL;
				uint16 unknown = 0;
				char *desc;
				lsa_priv_info(&lsa_pol, name, 0x407,
					      &uni_desc, &unknown);
				desc = unistr2_to_ascii(NULL, uni_desc, 0);
				report(out_hnd, "\t\t%s (0x%x)\n",
				       desc, unknown);
				safe_free(desc);
				unistr2_free(uni_desc);
			}
			safe_free(name);
		}
	}

	res = res ? lsa_close(&lsa_pol) : False;

	return 0;
}

/****************************************************************************
****************************************************************************/
uint32 cmd_lsa_priv_info(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	uint16 unk = 0x407;
	POLICY_HND lsa_pol;
	const char *name;

	BOOL res = True;
	BOOL res1 = True;

	if (argc < 2)
	{
		report(out_hnd, "privinfo <priv-name>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	name = argv[1];

	if (argc >= 3)
	{
		unk = atoi(argv[2]);
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	DEBUG(4, ("cmd_lsa_enum_privileges: server:%s\n", srv_name));

	/* lookup domain controller; receive a policy handle */
	res = res ? lsa_open_policy(srv_name,
				    &lsa_pol, False,
				    SEC_RIGHTS_MAXIMUM_ALLOWED) : False;


	res1 = res ? lsa_priv_info(&lsa_pol, name, unk, NULL, NULL) == 0x0 : False;

	res = res ? lsa_close(&lsa_pol) : False;

	if (res1)
	{
	}

	return 0;
}
