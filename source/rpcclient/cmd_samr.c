/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell              1994-2000,
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
   Copyright (C) Elrond                            2000
   
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
#include "nterr.h"
#include "rpcclient.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

extern struct user_creds *usr_creds;

extern FILE *out_hnd;

static void sam_display_domain(const char *domain)
{
	report(out_hnd, "Domain Name: %s\n", domain);
}

static void sam_display_dom_info(const char *domain, const DOM_SID *sid,
				 uint32 switch_value, SAM_UNK_CTR * ctr)
{
	fstring sidstr;
	sid_to_string(sidstr, sid);
	report(out_hnd, "Domain Name:\t%s\tSID:\t%s\n", domain, sidstr);
	display_sam_unk_ctr(out_hnd, ACTION_HEADER, switch_value, ctr);
	display_sam_unk_ctr(out_hnd, ACTION_ENUMERATE, switch_value, ctr);
	display_sam_unk_ctr(out_hnd, ACTION_FOOTER, switch_value, ctr);
}

static void sam_display_alias_info(const char *domain, const DOM_SID *sid,
				   uint32 alias_rid,
				   ALIAS_INFO_CTR * const ctr)
{
	display_alias_info_ctr(out_hnd, ACTION_HEADER, ctr);
	display_alias_info_ctr(out_hnd, ACTION_ENUMERATE, ctr);
	display_alias_info_ctr(out_hnd, ACTION_FOOTER, ctr);
}

static void sam_display_alias(const char *domain, const DOM_SID *sid,
			      uint32 alias_rid, const char *alias_name)
{
	report(out_hnd, "Alias RID: %8x  Alias Name: %s\n",
	       alias_rid, alias_name);
}

static void sam_display_alias_members(const char *domain, const DOM_SID *sid,
				      uint32 alias_rid,
				      const char *alias_name,
				      uint32 num_names,
				      DOM_SID *const *const sids,
				      char *const *const name,
				      uint32 *const type)
{
	display_alias_members(out_hnd, ACTION_HEADER, num_names, name, type);
	display_alias_members(out_hnd, ACTION_ENUMERATE, num_names, name,
			      type);
	display_alias_members(out_hnd, ACTION_FOOTER, num_names, name, type);
}

static void sam_display_group_info(const char *domain, const DOM_SID *sid,
				   uint32 group_rid,
				   GROUP_INFO_CTR * const ctr)
{
	display_group_info_ctr(out_hnd, ACTION_HEADER, ctr);
	display_group_info_ctr(out_hnd, ACTION_ENUMERATE, ctr);
	display_group_info_ctr(out_hnd, ACTION_FOOTER, ctr);
}

static void sam_display_group(const char *domain, const DOM_SID *sid,
			      uint32 group_rid, const char *group_name)
{
	report(out_hnd, "Group RID: %8x  Group Name: %s\n",
	       group_rid, group_name);
}

static void sam_display_group_members(const char *domain, const DOM_SID *sid,
				      uint32 group_rid,
				      const char *group_name,
				      uint32 num_names,
				      const uint32 *rid_mem,
				      char *const *const name,
				      uint32 *const type)
{
	display_group_members(out_hnd, ACTION_HEADER, num_names, name, type);
	display_group_members(out_hnd, ACTION_ENUMERATE, num_names, name,
			      type);
	display_group_members(out_hnd, ACTION_FOOTER, num_names, name, type);
}

static void sam_display_user_info(const char *domain, const DOM_SID *sid,
				  uint32 user_rid,
				  SAM_USERINFO_CTR * const ctr)
{
	if (ctr->switch_value == 21)
	{
		SAM_USER_INFO_21 *const usr = ctr->info.id21;
		display_sam_user_info_21(out_hnd, ACTION_HEADER, usr);
		display_sam_user_info_21(out_hnd, ACTION_ENUMERATE, usr);
		display_sam_user_info_21(out_hnd, ACTION_FOOTER, usr);
	}
}

static void sam_display_user(const char *domain, const DOM_SID *sid,
			     uint32 user_rid, const char *user_name)
{
	report(out_hnd, "User RID: %8x  User Name: %s\n",
	       user_rid, user_name);
}


/****************************************************************************
SAM password change
****************************************************************************/
uint32 cmd_sam_ntchange_pwd(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	char *pwd;
	fstring new_passwd;
	fstring new_passwd2;
	uchar nt_oldhash[16];
	uchar lm_oldhash[16];
	fstring acct_name;
	fstring domain;
	DOM_SID sid;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	report(out_hnd, "SAM NT Password Change\n");

	if (msrpc_sam_get_first_domain(srv_name, domain, &sid) != 0x0)
	{
		report(out_hnd,
		       "please use 'lsaquery' first, to ascertain the SID\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (argc >= 2)
	{
		struct pwd_info old_pwd;
		safe_strcpy(acct_name, argv[1], sizeof(acct_name) - 1);
		pwd_read(&old_pwd, "Old Password:", True);
		pwd_get_lm_nt_16(&old_pwd, lm_oldhash, nt_oldhash);
	}
	else
	{
		safe_strcpy(domain, usr_creds->ntc.domain,
			    sizeof(domain) - 1);
		safe_strcpy(acct_name, usr_creds->ntc.user_name,
			    sizeof(acct_name) - 1);
		pwd_get_lm_nt_16(&(usr_creds->ntc.pwd), lm_oldhash,
				 nt_oldhash);
	}

	report(out_hnd, "User: %s Domain: %s\n", acct_name, domain);

	pwd = (char *)getpass("New Password: ");
	ZERO_STRUCT(new_passwd);
	if (pwd != NULL)
	{
		fstrcpy(new_passwd, pwd);
	}

	pwd = (char *)getpass("retype: ");
	ZERO_STRUCT(new_passwd2);
	if (pwd != NULL)
	{
		fstrcpy(new_passwd2, pwd);
	}

	if (!strequal(new_passwd, new_passwd2))
	{
		report(out_hnd, "New passwords differ!\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* establish a connection. */
	if (msrpc_sam_ntchange_pwd(srv_name, domain, acct_name,
				   lm_oldhash, nt_oldhash, new_passwd))
	{
		report(out_hnd, "NT Password changed OK\n");
		return NT_STATUS_NOPROBLEMO;
	}
	report(out_hnd, "NT Password change FAILED\n");
	return NT_STATUS_UNSUCCESSFUL;
}


/****************************************************************************
experimental SAM encryted rpc test connection
****************************************************************************/
uint32 cmd_sam_test(struct client_info *info, int argc, char *argv[])
{
	struct cli_connection *con = NULL;
	fstring srv_name;
	fstring domain;
	fstring sid;
	BOOL res = True;

	sid_to_string(sid, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	report(out_hnd, "SAM Encryption Test\n");

	usr_creds->ntc.ntlmssp_flags = NTLMSSP_NEGOTIATE_UNICODE |
		NTLMSSP_NEGOTIATE_OEM |
		NTLMSSP_NEGOTIATE_SIGN |
		NTLMSSP_NEGOTIATE_SEAL |
		NTLMSSP_NEGOTIATE_LM_KEY |
		NTLMSSP_NEGOTIATE_NTLM |
		NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
		NTLMSSP_NEGOTIATE_00001000 | NTLMSSP_NEGOTIATE_00002000;

	/* open SAMR session.  */
	res = res ? cli_connection_init(srv_name, PIPE_SAMR, &con) : False;

	/* close the session */
	cli_connection_unlink(con);

	if (res)
	{
		DEBUG(5, ("cmd_sam_test: succeeded\n"));
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_test: failed\n"));
	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
Lookup domain in SAM server.
****************************************************************************/
uint32 cmd_sam_lookup_domain(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	char *domain;
	fstring str_sid;
	DOM_SID dom_sid;
	BOOL res = True;
	POLICY_HND sam_pol;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "lookupdomain: <name>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	domain = argv[1];
	strupper(domain);

	report(out_hnd, "Lookup Domain %s in SAM Server\n", domain);

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_query_lookup_domain(&sam_pol, domain,
					     &dom_sid) : False;

	res = res ? samr_close(&sam_pol) : False;

	if (res)
	{
		DEBUG(5, ("cmd_sam_lookup_domain: succeeded\n"));

		sid_to_string(str_sid, &dom_sid);
		report(out_hnd, "Domain:\t%s\tSID:\t%s\n", domain, str_sid);
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_lookup_domain: failed\n"));
	report(out_hnd, "Lookup Domain: FAILED\n");
	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
Lookup names in SAM server.
****************************************************************************/
static void fill_domain_sid(const char *srv_name,
			    const char *new_domain, char *domain,
			    DOM_SID *sid)
{
	uint32 ret;
	DOM_SID new_sid;
	fstring temp;

	ret = lookup_sam_domainname(srv_name, new_domain, &new_sid);

	if (ret != 0x0)
	{
		report(out_hnd, "Domain %s: %s\n",
		       new_domain, get_nt_error_msg(ret));
	}
	else
	{
		sid_copy(sid, &new_sid);
		fstrcpy(domain, new_domain);
	}

	sid_to_string(temp, sid);
	DEBUG(3, ("Using Domain-SID: %s\n", temp));
}

/****************************************************************************
Lookup names in SAM server.
****************************************************************************/
uint32 cmd_sam_lookup_names(struct client_info *info, int argc, char *argv[])
{
	int opt;
	fstring srv_name;
	fstring domain;
	DOM_SID sid_dom;
	uint32 ace_perms = SEC_RIGHTS_MAXIMUM_ALLOWED;
	BOOL res = True, res1 = True;
	POLICY_HND pol_sam;
	POLICY_HND pol_dom;
	int num_names;
	char **names;
	uint32 num_rids, i;
	uint32 *rids = NULL;
	uint32 *types = NULL;

	sid_copy(&sid_dom, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd,
		       "samlookupnames [-d <domain>] <name> [<name> ...]\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	while ((opt = getopt_long(argc, argv, "d:", NULL, NULL)) != EOF)
	{
		switch (opt)
		{
			case 'd':
			{
				fill_domain_sid(srv_name, optarg,
						domain, &sid_dom);
				break;
			}
		}
	}

	if (sid_dom.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid_dom) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	report(out_hnd, "SAM Lookup Names\n");

	argc -= optind;
	argv += optind;

	num_names = argc;
	names = (char **)argv;

	if (num_names <= 0)
	{
		report(out_hnd,
		       "samlookupnames [-d <domain>] <name> [<name> ...]\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &pol_sam) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&pol_sam, ace_perms, &sid_dom,
				     &pol_dom) : False;

	res1 = res ? samr_query_lookup_names(&pol_dom, 0x000003e8,
					     num_names, names,
					     &num_rids, &rids,
					     &types) : False;

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&pol_sam) : False;

	if (res1)
	{
		for (i = 0; i < num_rids; i++)
		{
			report(out_hnd, "RID: %s -> %d (%d: %s)\n",
			       names[i], rids[i], types[i],
			       get_sid_name_use_str(types[i]));
		}
	}

	safe_free(rids);
	safe_free(types);
	if (res1)
	{
		DEBUG(5, ("cmd_sam_lookup_names: query succeeded\n"));
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_lookup_names: query failed\n"));
	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
Lookup rids in SAM server.
****************************************************************************/
uint32 cmd_sam_lookup_rids(struct client_info *info, int argc, char *argv[])
{
	int opt;
	fstring srv_name;
	fstring domain;
	DOM_SID sid_dom;
	uint32 ace_perms = SEC_RIGHTS_MAXIMUM_ALLOWED;
	BOOL res = True, res1 = True;
	POLICY_HND pol_sam;
	POLICY_HND pol_dom;
	uint32 num_names = 0;
	char **names = NULL;
	uint32 num_rids, i;
	uint32 *rids = NULL;
	uint32 *types = NULL;

	sid_copy(&sid_dom, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd,
		       "samlookuprids [-d <domain>] <rid> [<rid> ...]\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	while ((opt = getopt(argc, argv, "d:")) != EOF)
	{
		switch (opt)
		{
			case 'd':
			{
				fill_domain_sid(srv_name, optarg,
						domain, &sid_dom);
				break;
			}
		}
	}

	if (sid_dom.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid_dom) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	report(out_hnd, "SAM Lookup Rids\n");

	argc -= optind;
	argv += optind;

	if (argc <= 0)
	{
		report(out_hnd,
		       "samlookuprids [-d <domain>] <rid> [<rid> ...]\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	num_rids = 0;

	while (num_rids < argc)
	{
		rids = Realloc(rids, sizeof(rids[0]) * (num_rids + 1));
		if (rids == NULL)
		{
			return NT_STATUS_NO_MEMORY;
		}
		rids[num_rids] = get_number(argv[num_rids]);
		num_rids++;
	}

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &pol_sam) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&pol_sam, ace_perms, &sid_dom,
				     &pol_dom) : False;

	res1 = res ? samr_query_lookup_rids(&pol_dom, 0x000003e8,
					    num_rids, rids,
					    &num_names, &names,
					    &types) : False;

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&pol_sam) : False;

	if (res1)
	{
		for (i = 0; i < num_names; i++)
		{
			report(out_hnd, "Name: %s -> %d (%d: %s)\n",
			       names[i], rids[i], types[i],
			       get_sid_name_use_str(types[i]));
		}
	}

	safe_free(rids);
	safe_free(types);
	free_char_array(num_names, names);

	if (res1)
	{
		DEBUG(5, ("cmd_sam_lookup_rids: query succeeded\n"));
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_lookup_rids: query failed\n"));
	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
SAM delete alias member.
****************************************************************************/
uint32 cmd_sam_del_aliasmem(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND alias_pol;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = SEC_RIGHTS_MAXIMUM_ALLOWED;
	DOM_SID member_sid;
	uint32 alias_rid;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid1) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc < 2)
	{
		report(out_hnd,
		       "delaliasmem: <alias rid> [member sid1] [member sid2] ...\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	argc--;
	argv++;

	alias_rid = get_number(argv[0]);

	report(out_hnd, "SAM Domain Alias Member\n");

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, ace_perms, &sid1,
				     &pol_dom) : False;

	/* connect to the domain */
	res1 = res ? samr_open_alias(&pol_dom,
				     0x000f001f, alias_rid,
				     &alias_pol) : False;

	while (argc > 0 && res2 && res1)
	{
		argc--;
		argv++;
		/* get a sid, delete a member from the alias */
		res2 = res2 ? string_to_sid(&member_sid, argv[0]) : False;
		res2 = res2 ? samr_del_aliasmem(&alias_pol,
						&member_sid) : False;

		if (res2)
		{
			report(out_hnd, "SID deleted from Alias 0x%x: %s\n",
			       alias_rid, argv[0]);
		}
	}

	res1 = res1 ? samr_close(&alias_pol) : False;
	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res2)
	{
		DEBUG(5, ("cmd_sam_del_aliasmem: succeeded\n"));
		report(out_hnd, "Delete Domain Alias Member: OK\n");
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_del_aliasmem: failed\n"));
	report(out_hnd, "Delete Domain Alias Member: FAILED\n");
	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
SAM delete alias.
****************************************************************************/
uint32 cmd_sam_delete_dom_alias(struct client_info *info, int argc,
			      char *argv[])
{
	fstring srv_name;
	fstring domain;
	char *name;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND alias_pol;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = SEC_RIGHTS_MAXIMUM_ALLOWED;
	uint32 alias_rid = 0;
	char *names[1];
	uint32 *rids;
	uint32 *types;
	uint32 num_rids;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid1) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc < 2)
	{
		report(out_hnd, "delalias <alias name>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	name = argv[1];

	report(out_hnd, "SAM Delete Domain Alias\n");

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, ace_perms, &sid1,
				     &pol_dom) : False;

	names[0] = name;

	res1 = res ? samr_query_lookup_names(&pol_dom, 0x000003e8,
					     1, names,
					     &num_rids, &rids,
					     &types) : False;

	if (res1 && num_rids == 1 && rids)
	{
		alias_rid = rids[0];
	}
	if (rids)
	{
		free(rids);
	}
	if (types)
	{
		free(types);
	}

	/* connect to the domain */
	res1 = res1 ? samr_open_alias(&pol_dom,
				      0x00f001f, alias_rid,
				      &alias_pol) : False;

	res2 = res1 ? samr_delete_dom_alias(&alias_pol) : False;

	res1 = res1 ? samr_close(&alias_pol) : False;
	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res2)
	{
		DEBUG(5, ("cmd_sam_delete_dom_alias: succeeded\n"));
		report(out_hnd, "Delete Domain Alias: OK\n");
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_delete_dom_alias: failed\n"));
	report(out_hnd, "Delete Domain Alias: FAILED\n");
	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
SAM add alias member.
****************************************************************************/
uint32 cmd_sam_add_aliasmem(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring tmp;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND alias_pol;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	BOOL res3 = True;
	BOOL res4 = True;
	uint32 ace_perms = SEC_RIGHTS_MAXIMUM_ALLOWED;
	uint32 alias_rid;
	char **names = NULL;
	int num_names = 0;
	DOM_SID *sids = NULL;
	int num_sids = 0;
	int i;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	POLICY_HND lsa_pol;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid1) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc < 2)
	{
		report(out_hnd,
		       "addaliasmem <alias name> [member name1] [member name2] ...\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	num_names = argc - 1;
	names = argv + 1;

	report(out_hnd, "SAM Domain Alias Member\n");

	/* lookup domain controller; receive a policy handle */
	res3 = res3 ? lsa_open_policy(srv_name, &lsa_pol, True,
				      SEC_RIGHTS_MAXIMUM_ALLOWED) : False;

	/* send lsa lookup sids call */
	res4 = res3 ? lsa_lookup_names(&lsa_pol,
				       num_names, names,
				       &sids, NULL, &num_sids) : False;

	res3 = res3 ? lsa_close(&lsa_pol) : False;

	res4 = num_sids < 2 ? False : res4;

	if (res4)
	{
		/*
		 * accept domain sid or builtin sid
		 */

		DOM_SID sid_1_5_20;
		string_to_sid(&sid_1_5_20, "S-1-5-32");
		sid_split_rid(&sids[0], &alias_rid);

		if (sid_equal(&sids[0], &sid_1_5_20))
		{
			sid_copy(&sid1, &sid_1_5_20);
		}
		else if (!sid_equal(&sids[0], &sid1))
		{
			res4 = False;
		}
	}

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, ace_perms, &sid1,
				     &pol_dom) : False;

	/* connect to the domain */
	res1 = res ? samr_open_alias(&pol_dom,
				     0x000f001f, alias_rid,
				     &alias_pol) : False;

	for (i = 1; i < num_sids && res2 && res1; i++)
	{
		/* add a member to the alias */
		res2 = res2 ? samr_add_aliasmem(&alias_pol, &sids[i]) : False;

		if (res2)
		{
			sid_to_string(tmp, &sids[i]);
			report(out_hnd, "SID added to Alias 0x%x: %s\n",
			       alias_rid, tmp);
		}
	}

	res1 = res1 ? samr_close(&alias_pol) : False;
	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	safe_free(sids);

	if (res2)
	{
		DEBUG(5, ("cmd_sam_add_aliasmem: succeeded\n"));
		report(out_hnd, "Add Domain Alias Member: OK\n");
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_add_aliasmem: failed\n"));
	report(out_hnd, "Add Domain Alias Member: FAILED\n");
	return NT_STATUS_UNSUCCESSFUL;
}


#if 0
/****************************************************************************
SAM create domain user.
****************************************************************************/
uint32 cmd_sam_create_dom_trusting(struct client_info *info, int argc,
				 char *argv[])
{
	fstring local_domain;
	fstring local_pdc;

	char *trusting_domain;
	char *trusting_pdc;
	fstring password;

	fstring sid;
	DOM_SID sid1;
	uint32 user_rid;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid1) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc < 3)
	{
		report(out_hnd,
		       "createtrusting: <Domain Name> <PDC Name> [password]\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	argc--;
	argv++;

	trusting_domain = argv[0];

	argc--;
	argv++;

	trusting_pdc = argv[0];

	argc--;
	argv++;

	if (argc > 0)
	{
		safe_strcpy(password, argv[0], sizeof(password) - 1);
	}
	else
	{
		fstring pass_str;
		char *pass;
		slprintf(pass_str, sizeof(pass_str) - 1,
			 "Enter %s's Password:", user_name);
		pass = (char *)getpass(pass_str);

		if (pass != NULL)
		{
			safe_strcpy(password, pass, sizeof(password) - 1);
			set_passwd = True;
		}
	}
	report(out_hnd, "SAM Create Domain Trusting Account\n");

	if (msrpc_sam_create_dom_user(srv_name,
				      acct_name, ACB_WSTRUST, &user_rid) ==
	    NT_STATUS_NOPROBLEMO)
	{
		report(out_hnd, "Create Domain User: OK\n");
		return NT_STATUS_NOPROBLEMO;
	}
	report(out_hnd, "Create Domain User: FAILED\n");
	return NT_STATUS_UNSUCCESSFUL;
}
#endif

/* this is a hack to integrate TNG with Samba 3.0 */ 
static BOOL lsa_local_set_secret(char *domain, uchar ntpw[16])
{
	static fstring keystr;
	struct machine_acct_pass pass;

	secrets_init();
	slprintf(keystr,sizeof(keystr),"%s/%s", SECRETS_MACHINE_ACCT_PASS, domain);

	memcpy(pass.hash, ntpw, 16);
	pass.mod_time = time(NULL);
	return secrets_store(keystr, &pass, sizeof(pass));
}


/****************************************************************************
SAM create domain user.
****************************************************************************/
uint32 cmd_sam_create_dom_user(struct client_info *info, int argc, char *argv[])
{
	fstring domain;
	fstring acct_name;
	fstring sec_name;
	fstring name;
	fstring sid;
	DOM_SID sid1;
	uint32 user_rid;
	uint16 acb_info = ACB_NORMAL;
	BOOL join_domain = False;
	fstring join_dom_name;
	int opt;
	char *password = NULL;
	pstring upwb;
	int plen = 0;
	int len = 0;
	UNISTR2 upw;
	fstring ascii_pwd;
	BOOL use_ascii_pwd = False;
	uint32 status = NT_STATUS_ACCESS_DENIED;
	BOOL lsa_local = False;

	BOOL res = True;
	POLICY_HND lsa_pol;

	fstring wks_name;

	fstring srv_name;
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		status = msrpc_sam_get_first_domain(srv_name, domain, &sid1);

		if (status != NT_STATUS_NOPROBLEMO)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return status;
		}
	}

	if (argc < 2)
	{
		report(out_hnd,
		       "createuser: <acct name> [-i] [-s] [-L] [-j] domain_name [-p password]\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	argc--;
	argv++;

	safe_strcpy(acct_name, argv[0], sizeof(acct_name) - 1);
	strlower(acct_name);
	len = strlen(acct_name) - 1;
	if (acct_name[len] == '$')
	{
		safe_strcpy(name, argv[0], sizeof(name) - 1);
		name[len] = 0;
		acb_info = ACB_WSTRUST;
	}

	while ((opt = getopt_long(argc, argv, "isj:p:w:L", NULL, NULL)) != EOF)
	{
		switch (opt)
		{
			case 'i':
			{
				acb_info = ACB_DOMTRUST;
				break;
			}
			case 's':
			{
				acb_info = ACB_SVRTRUST;
				break;
			}
			case 'j':
			{
				join_domain = True;
				fstrcpy(join_dom_name, optarg);
				break;
			}
			case 'p':
			{
				safe_strcpy(ascii_pwd, optarg,
					    sizeof(ascii_pwd) - 1);
				use_ascii_pwd = True;
				break;
			}
		        case 'L':
				if (getuid() != 0) {
					report(out_hnd, "you must be root to use the -L option\n");
					return NT_STATUS_INVALID_PARAMETER;
				}
				lsa_local = True;
				break;
		}
	}

	switch (acb_info)
	{
		case ACB_DOMTRUST:
		{
			fstrcpy(sec_name, "G$$");
			fstrcat(sec_name, join_dom_name);
			break;
		}
		case ACB_SVRTRUST:
		case ACB_WSTRUST:
		{
			fstrcpy(sec_name, "$MACHINE.ACC");
			break;
		}
		default:
		{
			break;
		}
	}
	/*
	 * sort out the workstation name.  if it's ourselves, and we're
	 * on MSRPC local loopback, must _also_ connect to workstation
	 * local-loopback.
	 */

	DEBUG(10, ("create_dom_user: myhostname: %s server: %s\n",
		   info->myhostname, name));

	fstrcpy(wks_name, "\\\\");
	if (strequal(srv_name, "\\\\.") && strequal(name, info->myhostname))
	{
		fstrcat(wks_name, ".");
	}
	else
	{
		fstrcat(wks_name, name);
	}
	strupper(wks_name);

	report(out_hnd, "SAM Create Domain User\n");
	if (join_domain && acb_info == ACB_NORMAL)
	{
		report(out_hnd, "can only join trust accounts to a domain\n");
		return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
	}

	if (join_domain)
	{
		fstrcpy(domain, join_dom_name);
		if (!get_any_dc_name(domain, srv_name))
		{
			report(out_hnd,
			       "could not locate server for domain %s\n",
			       domain);
			return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
		}

		status = msrpc_sam_get_first_domain(srv_name, domain, &sid1);

		if (status != NT_STATUS_NOPROBLEMO)
		{
			report(out_hnd,
			       "could not find SID for domain %s\n", domain);
			return status;
		}
	}

	report(out_hnd, "Domain: %s Name: %s ACB: %s\n",
	       domain, acct_name,
	       pwdb_encode_acct_ctrl(acb_info,
				     NEW_PW_FORMAT_SPACE_PADDED_LEN));

	if (acb_info == ACB_WSTRUST || acb_info == ACB_SVRTRUST)
	{
		if (password != NULL)
		{
			report(out_hnd,
			       ("Workstation and Server Trust Accounts are randomly auto-generated\n"));
			memset(&upw, 0, sizeof(upw));
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (join_domain)
		{
			upw.uni_str_len = 0xc;
			upw.uni_max_len = 0xc;

			password = (char *)upw.buffer;
			plen = upw.uni_str_len * 2;
			generate_random_buffer(password, plen, True);
		}
		else
		{
			safe_strcpy(ascii_pwd, name, sizeof(ascii_pwd) - 1);
			strlower(ascii_pwd);
			use_ascii_pwd = True;

			report(out_hnd,
			       "Resetting Trust Account to insecure, initial, well-known value: \"%s\"\n",
			       ascii_pwd);
			report(out_hnd,
			       "%s can now be joined to the domain, which should\n",
			       name);
			report(out_hnd,
			       "be done on a private, secure network as soon as possible\n");
		}
	}

	if (use_ascii_pwd)
	{
		make_unistr2(&upw, ascii_pwd, strlen(ascii_pwd));
		ascii_to_unibuf(upwb, ascii_pwd, strlen(ascii_pwd) * 2);
		password = upwb;
		plen = upw.uni_str_len * 2;
	}

	ZERO_STRUCT(ascii_pwd);

	if (join_domain && !lsa_local)
	{
		/*
		 * ok.  this looks really weird, but if you don't open
		 * the connection to the workstation first, then the
		 * set trust account on the SAM database may get the
		 * local copy-of trust account out-of-sync with the
		 * remote one, and you're stuffed!
		 */
		res = lsa_open_policy(wks_name, &lsa_pol, True,
				      SEC_RIGHTS_MAXIMUM_ALLOWED);

		if (!res)
		{
			report(out_hnd, "Connection to %s FAILED\n",
			       wks_name);
			report(out_hnd,
			       "(Do a \"use \\\\%s -U localadmin\")\n",
			       wks_name);
		}
	}

	if (!res) {
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	if ((status=msrpc_sam_create_dom_user(srv_name, &sid1,
					      acct_name, acb_info, password,
					      plen, &user_rid)) !=
	    NT_STATUS_NOPROBLEMO) {
		report(out_hnd, "Create Domain User: FAILED\n");
		goto done;
	}

	report(out_hnd, "Create Domain User: OK\n");

	if (join_domain) {
		POLICY_HND pol_sec;
		BOOL res1;
		BOOL res2 = False;
		uchar ntpw[16];
		
		nt_owf_genW(&upw, ntpw);
		
		strupper(domain);
		strupper(name);
		
		report(out_hnd, "Join %s to Domain %s\n", name,
		       domain);
		
		/* attempt to create, and if already exist, open */
		if (lsa_local) {
			res2 = res1 = res = lsa_local_set_secret(domain, ntpw);
			status = res ? NT_STATUS_NOPROBLEMO : NT_STATUS_ACCESS_DENIED;
		} else {
			res1 = lsa_create_secret(&lsa_pol, "$MACHINE.ACC",
						 0x020003, &pol_sec);
			
			if (res1) {
				report(out_hnd, "Create $MACHINE.ACC: OK\n");
			} else {
				res1 = lsa_open_secret(&lsa_pol,
						       "$MACHINE.ACC",
						       0x020003, &pol_sec);
			}
			
			/* valid pol_sec on $MACHINE.ACC, set trust passwd */
			if (res1) {
				STRING2 secret;
				secret_store_data(&secret, password, plen);
				status = lsa_set_secret(&pol_sec, &secret);
				res2 = status == NT_STATUS_NOPROBLEMO;
			}
		}
		
		if (res2) {
			report(out_hnd, "Set $MACHINE.ACC: OK\n");
			status = NT_STATUS_NOPROBLEMO;
		} else {
			report(out_hnd, "Set $MACHINE.ACC: FAILED\n");
			status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		if (!lsa_local) {
			res1 = res1 ? lsa_close(&pol_sec) : False;
			res = res ? lsa_close(&lsa_pol) : False;
		}

		memset(ntpw, 0, sizeof(ntpw));
	}

 done:
	memset(&upw, 0, sizeof(upw));
	return status;
}


/****************************************************************************
SAM create domain alias.
****************************************************************************/
uint32 cmd_sam_create_dom_alias(struct client_info *info, int argc,
			      char *argv[])
{
	fstring srv_name;
	fstring domain;
	char *acct_name;
	fstring acct_desc;
	fstring sid;
	DOM_SID sid1;
	BOOL res = True;
	BOOL res1 = True;
	uint32 ace_perms = 0x200003d3;	/* permissions */
	uint32 alias_rid;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid1) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}


	if ((argc < 2) || (argc > 3))
	{
		report(out_hnd,
		       "createalias: <acct name> [acct description]\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	acct_name = argv[1];

	if (argc < 3)
	{
		acct_desc[0] = 0;
	}
	else
	{
		safe_strcpy(acct_desc, argv[2], sizeof(acct_desc) - 1);
	}

	report(out_hnd, "SAM Create Domain Alias\n");
	report(out_hnd, "Domain: %s Name: %s Description: %s\n",
	       domain, acct_name, acct_desc);

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, ace_perms, &sid1,
				     &pol_dom) : False;

	/* create a domain alias */
	res1 = res ? create_samr_domain_alias(&pol_dom,
					      acct_name, acct_desc,
					      &alias_rid) : False;

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res1)
	{
		DEBUG(5, ("cmd_sam_create_dom_alias: succeeded\n"));
		report(out_hnd, "Create Domain Alias: OK\n");
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_create_dom_alias: failed\n"));
	report(out_hnd, "Create Domain Alias: FAILED\n");
	return NT_STATUS_UNSUCCESSFUL;
}


/****************************************************************************
SAM delete group member.
****************************************************************************/
uint32 cmd_sam_del_groupmem(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND pol_grp;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = SEC_RIGHTS_MAXIMUM_ALLOWED;
	uint32 member_rid;
	uint32 group_rid;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid1) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc < 2)
	{
		report(out_hnd,
		       "delgroupmem: <group rid> [member rid1] [member rid2] ...\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	argc--;
	argv++;

	group_rid = get_number(argv[0]);

	report(out_hnd, "SAM Add Domain Group member\n");

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, ace_perms, &sid1,
				     &pol_dom) : False;

	/* connect to the domain */
	res1 = res ? samr_open_group(&pol_dom,
				     0x0000001f, group_rid, &pol_grp) : False;

	while (argc > 0 && res2 && res1)
	{
		argc--;
		argv++;

		/* get a rid, delete a member from the group */
		member_rid = get_number(argv[0]);
		res2 = res2 ? samr_del_groupmem(&pol_grp, member_rid) : False;

		if (res2)
		{
			report(out_hnd, "RID deleted from Group 0x%x: 0x%x\n",
			       group_rid, member_rid);
		}
	}

	res1 = res1 ? samr_close(&pol_grp) : False;
	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res2)
	{
		DEBUG(5, ("cmd_sam_del_groupmem: succeeded\n"));
		report(out_hnd, "Add Domain Group Member: OK\n");
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_del_groupmem: failed\n"));
	report(out_hnd, "Add Domain Group Member: FAILED\n");
	return NT_STATUS_UNSUCCESSFUL;
}


/****************************************************************************
SAM delete user.
****************************************************************************/
uint32 cmd_sam_delete_dom_user(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	char *name;
	fstring sid;
	DOM_SID sid1;
	DOM_SID sid_usr;
	POLICY_HND pol_usr;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 user_rid = 0;
	char *names[1];
	uint32 *rids;
	uint32 *types;
	uint32 num_rids;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid1) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc < 2)
	{
		report(out_hnd, "deluser <user name>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	name = argv[1];

	report(out_hnd, "SAM Delete Domain User\n");

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, 0x0200, &sid1,
				     &pol_dom) : False;

	names[0] = name;

	res1 = res ? samr_query_lookup_names(&pol_dom, 0x000003e8,
					     1, names,
					     &num_rids, &rids,
					     &types) : False;

	if (res1 && num_rids == 1 && rids)
	{
		user_rid = rids[0];
		sid_copy(&sid_usr, &sid1);
		if (!sid_append_rid(&sid_usr, user_rid))
		{
			res1 = False;
		}

	}
	else
	{
		res1 = False;
	}
	safe_free(rids);
	safe_free(types);

	/* connect to the domain */
	res1 = res1 ? samr_open_user(&pol_dom,
				     0x010000, user_rid, &pol_usr) : False;

	res2 = res1 ? samr_unknown_2d(&pol_dom, &sid_usr) : False;
	res2 = res2 ? samr_delete_dom_user(&pol_usr) : False;
	res2 = res2 ? samr_unknown_2d(&pol_dom, &sid_usr) : False;

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res2)
	{
		DEBUG(5, ("cmd_sam_delete_dom_user: succeeded\n"));
		report(out_hnd, "Delete Domain User: OK\n");
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_delete_dom_user: failed\n"));
	report(out_hnd, "Delete Domain User: FAILED\n");
	return NT_STATUS_UNSUCCESSFUL;
}


/****************************************************************************
SAM delete group.
****************************************************************************/
uint32 cmd_sam_delete_dom_group(struct client_info *info, int argc,
			      char *argv[])
{
	fstring srv_name;
	fstring domain;
	char *name;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND pol_grp;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = SEC_RIGHTS_MAXIMUM_ALLOWED;
	uint32 group_rid = 0;
	char *names[1];
	uint32 *rids;
	uint32 *types;
	uint32 num_rids;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid1) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc < 2)
	{
		report(out_hnd, "delgroup <group name>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	name = argv[1];

	report(out_hnd, "SAM Delete Domain Group\n");

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, ace_perms, &sid1,
				     &pol_dom) : False;

	names[0] = name;

	res1 = res ? samr_query_lookup_names(&pol_dom, 0x000003e8,
					     1, names,
					     &num_rids, &rids,
					     &types) : False;

	if (res1 && num_rids == 1 && rids)
	{
		group_rid = rids[0];
	}
	if (rids)
	{
		free(rids);
	}
	if (types)
	{
		free(types);
	}

	/* connect to the domain */
	res1 = res1 ? samr_open_group(&pol_dom,
				      0x0000001f, group_rid,
				      &pol_grp) : False;

	res2 = res1 ? samr_delete_dom_group(&pol_grp) : False;

	res1 = res1 ? samr_close(&pol_grp) : False;
	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res2)
	{
		DEBUG(5, ("cmd_sam_delete_dom_group: succeeded\n"));
		report(out_hnd, "Delete Domain Group: OK\n");
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_delete_dom_group: failed\n"));
	report(out_hnd, "Delete Domain Group: FAILED\n");
	return NT_STATUS_UNSUCCESSFUL;
}


/****************************************************************************
SAM add group member.
****************************************************************************/
uint32 cmd_sam_add_groupmem(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND pol_grp;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	BOOL res3 = True;
	BOOL res4 = True;
	uint32 ace_perms = SEC_RIGHTS_MAXIMUM_ALLOWED;
	uint32 *group_rids;
	uint32 *group_types;
	char **names = NULL;
	uint32 num_names = 0;
	fstring group_name;
	char *group_names[1];
	uint32 *rids;
	uint32 *types;
	uint32 num_rids;
	uint32 num_group_rids;
	uint32 i;
	DOM_SID sid_1_5_20;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	POLICY_HND pol_blt;

	string_to_sid(&sid_1_5_20, "S-1-5-32");

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid1) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc < 3)
	{
		report(out_hnd,
		       "addgroupmem <group name> [member name1] [member name2] ...\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	argc--;
	argv++;

	group_names[0] = argv[0];

	argc--;
	argv++;

	num_names = argc;
	names = (char **)argv;

	report(out_hnd, "SAM Add Domain Group member\n");

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res4 = res ? samr_open_domain(&sam_pol, ace_perms, &sid1,
				      &pol_dom) : False;

	/* connect to the domain */
	res3 = res ? samr_open_domain(&sam_pol, ace_perms, &sid_1_5_20,
				      &pol_blt) : False;

	res2 = res4 ? samr_query_lookup_names(&pol_dom, 0x000003e8,
					      1, group_names,
					      &num_group_rids, &group_rids,
					      &group_types) : False;

	/* open the group */
	res2 = res2 ? samr_open_group(&pol_dom,
				      0x0000001f, group_rids[0],
				      &pol_grp) : False;

	if (!res2
	    || (group_types != NULL && group_types[0] == SID_NAME_UNKNOWN))
	{
		if (group_rids != NULL)
		{
			free(group_rids);
		}
		if (group_types != NULL)
		{
			free(group_types);
		}

		res2 = res3 ? samr_query_lookup_names(&pol_blt, 0x000003e8,
						      1, group_names,
						      &num_group_rids,
						      &group_rids,
						      &group_types) : False;

		/* open the group */
		res2 = res2 ? samr_open_group(&pol_blt,
					      0x0000001f, group_rids[0],
					      &pol_grp) : False;
	}

	if (res2 && group_types[0] == SID_NAME_ALIAS)
	{
		report(out_hnd,
		       "%s is a local alias, not a group.  Use addaliasmem command instead\n",
		       group_name);
		safe_free(group_rids);
		safe_free(group_types);
		return NT_STATUS_UNSUCCESSFUL;
	}
	res1 = res2 ? samr_query_lookup_names(&pol_dom, 0x000003e8,
					      num_names, names,
					      &num_rids, &rids,
					      &types) : False;

	if (num_rids == 0)
	{
		report(out_hnd, "Member names not known\n");
	}
	for (i = 0; i < num_rids && res2 && res1; i++)
	{
		if (types[i] == SID_NAME_UNKNOWN)
		{
			report(out_hnd, "Name %s unknown\n", names[i]);
		}
		else
		{
			if (samr_add_groupmem(&pol_grp, rids[i]))
			{
				report(out_hnd,
				       "RID added to Group 0x%x: 0x%x\n",
				       group_rids[0], rids[i]);
			}
		}
	}

	res1 = res ? samr_close(&pol_grp) : False;
	res1 = res3 ? samr_close(&pol_blt) : False;
	res1 = res4 ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

#if 0
	free_char_array(num_names, names);
#endif

	safe_free(group_rids);
	safe_free(group_types);
	safe_free(rids);
	safe_free(types);

	if (res2)
	{
		DEBUG(5, ("cmd_sam_add_groupmem: succeeded\n"));
		report(out_hnd, "Add Domain Group Member: OK\n");
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_add_groupmem: failed\n"));
	report(out_hnd, "Add Domain Group Member: FAILED\n");
	return NT_STATUS_UNSUCCESSFUL;
}


/****************************************************************************
SAM create domain group.
****************************************************************************/
uint32 cmd_sam_create_dom_group(struct client_info *info, int argc,
			      char *argv[])
{
	fstring srv_name;
	fstring domain;
	char *acct_name;
	fstring acct_desc;
	fstring sid;
	DOM_SID sid1;
	BOOL res = True;
	BOOL res1 = True;
	uint32 ace_perms = SEC_RIGHTS_MAXIMUM_ALLOWED;
	uint32 group_rid;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid1) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if ((argc < 2) || (argc > 3))
	{
		report(out_hnd,
		       "creategroup: <acct name> [acct description]\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	acct_name = argv[1];

	if (argc < 3)
	{
		acct_desc[0] = 0;
	}
	else
	{
		safe_strcpy(acct_desc, argv[2], sizeof(acct_desc) - 1);
	}


	report(out_hnd, "SAM Create Domain Group\n");
	report(out_hnd, "Domain: %s Name: %s Description: %s\n",
	       domain, acct_name, acct_desc);

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, ace_perms, &sid1,
				     &pol_dom) : False;

	/* read some users */
	res1 = res ? create_samr_domain_group(&pol_dom,
					      acct_name, acct_desc,
					      &group_rid) : False;

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res1)
	{
		DEBUG(5, ("cmd_sam_create_dom_group: succeeded\n"));
		report(out_hnd, "Create Domain Group: OK\n");
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_create_dom_group: failed\n"));
	report(out_hnd, "Create Domain Group: FAILED\n");
	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
experimental SAM users enum.
****************************************************************************/
uint32 cmd_sam_enum_users(struct client_info *info, int argc, char *argv[])
{
	BOOL request_user_info = False;
	BOOL request_group_info = False;
	BOOL request_alias_info = False;
	struct acct_info *sam = NULL;
	uint32 num_sam_entries = 0;
	int opt;
	BOOL res1;

	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid1) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	while ((opt = getopt(argc, argv, "uga")) != EOF)
	{
		switch (opt)
		{
			case 'u':
			{
				request_user_info = True;
				break;
			}
			case 'g':
			{
				request_group_info = True;
				break;
			}
			case 'a':
			{
				request_alias_info = True;
				break;
			}
		}
	}

	report(out_hnd, "SAM Enumerate Users\n");

	res1 = msrpc_sam_enum_users(srv_name, domain, &sid1,
			     &sam, &num_sam_entries,
			     sam_display_user,
			     request_user_info ? sam_display_user_info : NULL,
			     request_group_info ? sam_display_group_members :
			     NULL,
			     request_alias_info ? sam_display_group_members :
			     NULL);

	safe_free(sam);

	if (res1)
	{
		return NT_STATUS_NOPROBLEMO;
	}
	return NT_STATUS_UNSUCCESSFUL;
}


/****************************************************************************
experimental SAM group query members.
****************************************************************************/
uint32 cmd_sam_query_groupmem(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;

	char *group_name;
	char *names[1];
	uint32 num_rids;
	uint32 *rids;
	uint32 *types;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid) != 0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc < 2)
	{
		report(out_hnd, "samgroupmem <name>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	group_name = argv[1];

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query Group: %s\n", group_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	       info->myhostname, srv_name, domain, sid_str);

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, 0x304, &sid, &pol_dom) : False;

	/* look up group rid */
	names[0] = group_name;
	res1 = res ? samr_query_lookup_names(&pol_dom, 0x3e8,
					     1, names,
					     &num_rids, &rids,
					     &types) : False;

	if (res1 && num_rids == 1)
	{
		res1 = req_groupmem_info(&pol_dom,
					 domain,
					 &sid,
					 rids[0],
					 group_name,
					 sam_display_group_members);
	}

	safe_free(rids);
	safe_free(types);

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res1)
	{
		DEBUG(5, ("cmd_sam_query_group: succeeded\n"));
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_query_group: failed\n"));
	return NT_STATUS_UNSUCCESSFUL;
}


/****************************************************************************
experimental SAM group query.
****************************************************************************/
uint32 cmd_sam_query_group(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;

	char *group_name;
	char *names[1];
	uint32 num_rids;
	uint32 *rids;
	uint32 *types;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid) != 0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc < 2)
	{
		report(out_hnd, "samgroup <name>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	group_name = argv[1];

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query Group: %s\n", group_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	       info->myhostname, srv_name, domain, sid_str);

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, 0x304, &sid, &pol_dom) : False;

	/* look up group rid */
	names[0] = group_name;
	res1 = res ? samr_query_lookup_names(&pol_dom, 0x3e8,
					     1, names,
					     &num_rids, &rids,
					     &types) : False;

	if (res1 && num_rids == 1)
	{
		res1 = query_groupinfo(&pol_dom,
				       domain,
				       &sid, rids[0], sam_display_group_info);
	}

	safe_free(rids);
	safe_free(types);

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res1)
	{
		DEBUG(5, ("cmd_sam_query_group: succeeded\n"));
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_query_group: failed\n"));
	return NT_STATUS_UNSUCCESSFUL;
}


/****************************************************************************
experimental SAM query security object.
****************************************************************************/
uint32 cmd_sam_query_sec_obj(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;

	char *user_name;
	char *names[1];
	uint32 num_rids;
	uint32 *rids;
	uint32 *types;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid) != 0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc < 2)
	{
		report(out_hnd, "samquerysec <name>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	user_name = argv[1];

	argc--;
	argv++;

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query User: %s\n", user_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	       info->myhostname, srv_name, domain, sid_str);

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, 0x304, &sid, &pol_dom) : False;

	/* look up user rid */
	names[0] = user_name;
	res1 = res ? samr_query_lookup_names(&pol_dom, 0x3e8,
					     1, names,
					     &num_rids, &rids,
					     &types) : False;

	/* send user info query */
	if (res1 && num_rids == 1)
	{
		POLICY_HND pol_usr;
		BOOL ret = True;
		SEC_DESC_BUF buf;

		/* send open domain (on user sid) */
		ret = samr_open_user(&pol_dom, 0x02011b, rids[0], &pol_usr);
		res1 = ret ? samr_query_sec_obj(&pol_usr, 0x04, &buf) : False;
		ret = ret ? samr_close(&pol_usr) : False;

		if (buf.sec != NULL)
		{
			display_sec_desc(out_hnd, ACTION_HEADER, buf.sec);
			display_sec_desc(out_hnd, ACTION_ENUMERATE, buf.sec);
			display_sec_desc(out_hnd, ACTION_FOOTER, buf.sec);
		}

		free_sec_desc_buf(&buf);
	}
	else
	{
		res1 = False;
	}

	safe_free(rids);
	safe_free(types);

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res1)
	{
		DEBUG(5, ("cmd_sam_query_sec_obj: succeeded\n"));
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_query_sec_obj: failed\n"));
	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
experimental SAM user query.
****************************************************************************/
uint32 cmd_sam_query_user(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;
	int opt;

	char *user_name;
	char *names[1];
	uint32 num_rids;
	uint32 *rids;
	uint32 *types;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	uint16 info_level = 0x15;

	BOOL request_user_info = False;
	BOOL request_group_info = False;
	BOOL request_alias_info = False;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid) != 0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc < 2)
	{
		report(out_hnd, "samuser <name> [-u] [-g] [-a]\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	user_name = argv[1];

	argc--;
	argv++;

	while ((opt = getopt(argc, argv, "ugai:")) != EOF)
	{
		switch (opt)
		{
			case 'u':
			{
				request_user_info = True;
				break;
			}
			case 'g':
			{
				request_group_info = True;
				break;
			}
			case 'a':
			{
				request_alias_info = True;
				break;
			}
			case 'i':
			{
				info_level = get_number(optarg);
				break;
			}
		}
	}

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query User: %s\n", user_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	       info->myhostname, srv_name, domain, sid_str);

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, 0x304, &sid, &pol_dom) : False;

	/* look up user rid */
	names[0] = user_name;
	res1 = res ? samr_query_lookup_names(&pol_dom, 0x3e8,
					     1, names,
					     &num_rids, &rids,
					     &types) : False;

	/* send user info query */
	if (res1 && num_rids == 1)
	{
		msrpc_sam_user(&pol_dom, NULL,
			       domain,
			       &sid, NULL,
			       rids[0], info_level, user_name,
			       sam_display_user,
			       request_user_info ? sam_display_user_info :
			       NULL,
			       request_group_info ? sam_display_group_members
			       : NULL,
			       request_alias_info ? sam_display_group_members
			       : NULL);
	}
	else
	{
		res1 = False;
	}

	safe_free(rids);
	safe_free(types);

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res1)
	{
		DEBUG(5, ("cmd_sam_query_user: succeeded\n"));
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_query_user: failed\n"));
	return NT_STATUS_UNSUCCESSFUL;
}


/****************************************************************************
experimental SAM user set.
****************************************************************************/
uint32 cmd_sam_set_userinfo2(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;
	int opt;
	BOOL set_acb_bits = False;
	BOOL clr_acb_bits = False;

	fstring user_name;

	char *names[1];
	uint32 num_rids;
	uint32 *rids;
	uint32 *types;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	SAM_USERINFO_CTR ctr;
	uint16 acb_set = 0x0;
	uint16 acb_clr = 0x0;

	BOOL set_passwd = False;

	fstring password;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid) != 0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc < 2)
	{
		report(out_hnd,
		       "samuserset2 <name> [-s <acb_bits>] [-c <acb_bits]\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	argc--;
	argv++;

	safe_strcpy(user_name, argv[0], sizeof(user_name) - 1);

	while ((opt = getopt(argc, argv, "s:c:p:")) != EOF)
	{
		switch (opt)
		{
			case 'p':
			{
				set_passwd = True;
				safe_strcpy(password, optarg,
					    sizeof(password) - 1);
				break;
			}
			case 's':
			{
				set_acb_bits = True;
				acb_set = (uint16)get_number(optarg);
				break;
			}
			case 'c':
			{
				clr_acb_bits = True;
				acb_clr = (uint16)get_number(optarg);
				break;
			}
		}
	}

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Set User Info: %s\n", user_name);

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &sid, &pol_dom) : False;

	/* look up user rid */
	names[0] = user_name;
	res1 = res ? samr_query_lookup_names(&pol_dom, 0x3e8,
					     1, names,
					     &num_rids, &rids,
					     &types) : False;


	if (set_passwd && res1 && num_rids == 1)
	{
		void *usr = NULL;
		uint32 switch_value = 0;

		SAM_USER_INFO_12 *p = g_new(SAM_USER_INFO_12, 1);
		usr = (void *)p;
		switch_value = 0x12;

		if (usr != NULL)
		{
			nt_lm_owf_gen(password, p->nt_pwd, p->lm_pwd);
			p->lm_pwd_active = 1;
			p->nt_pwd_active = 1;
			res1 = set_samr_set_userinfo2(&pol_dom,
						      switch_value, rids[0],
						      usr);
		}
	}

	/* send set user info */
	if ((!set_passwd) && res1 && num_rids == 1 &&
	    get_samr_query_userinfo(&pol_dom, 0x10, rids[0], &ctr))
	{
		void *usr = NULL;
		uint32 switch_value = 0;

		if (True)
		{
			SAM_USER_INFO_10 *p = g_new(SAM_USER_INFO_10, 1);
			p->acb_info = ctr.info.id10->acb_info;
			DEBUG(10, ("acb_info: %x set: %x clr: %x\n",
				   p->acb_info, acb_set, acb_clr));
			if (set_acb_bits)
			{
				p->acb_info |= acb_set;
			}

			if (clr_acb_bits)
			{
				p->acb_info &= (~acb_clr);
			}

			DEBUG(10, ("acb_info: %x set: %x clr: %x\n",
				   p->acb_info, acb_set, acb_clr));

			usr = (void *)p;
			switch_value = 16;
		}

		if (usr != NULL)
		{
			res1 = set_samr_set_userinfo2(&pol_dom,
						      switch_value, rids[0],
						      usr);
		}
	}

	safe_free(rids);
	safe_free(types);
	free_samr_userinfo_ctr(&ctr);

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res1)
	{
		report(out_hnd, "Set User Info: OK\n");
		DEBUG(5, ("cmd_sam_query_user: succeeded\n"));
		return NT_STATUS_NOPROBLEMO;
	}
	report(out_hnd, "Set User Info: Failed\n");
	DEBUG(5, ("cmd_sam_query_user: failed\n"));
	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
experimental SAM user set.
****************************************************************************/
uint32 cmd_sam_set_userinfo(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	int opt;
	BOOL set_info_21 = False;
	BOOL set_passwd = False;
	BOOL set_full_name = False;
	BOOL set_home_dir = False;
	BOOL set_dir_drive = False;
	BOOL set_profile_path = False;
	BOOL set_logon_script = False;

	fstring user_name;
	fstring password;
	fstring full_name;
	fstring home_dir;
	fstring dir_drive;
	fstring profile_path;
	fstring logon_script;

	int len_full_name;
	int len_home_dir;
	int len_dir_drive;
	int len_profile_path;
	int len_logon_script;

	char *names[1];
	uint32 num_rids;
	uint32 *rids;
	uint32 *types;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	SAM_USERINFO_CTR ctr;

	ZERO_STRUCT(ctr);

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid) != 0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	argc--;
	argv++;

	if (argc == 0)
	{
		report(out_hnd, "samuserset <name> [<-p password> [-F fullname] [-H homedrive]\n");
		report(out_hnd, "                  [-D homedrive] [-P profilepath] [-L logonscript]]\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	safe_strcpy(user_name, argv[0], sizeof(user_name) - 1);

	if (argc == 1)
	{
		fstring pass_str;
		char *pass;
		slprintf(pass_str, sizeof(pass_str) - 1,
			 "Enter %s's Password:", user_name);
		pass = (char *)getpass(pass_str);

		if (pass != NULL)
		{
			safe_strcpy(password, pass, sizeof(password) - 1);
			set_passwd = True;
		}
	}
	else
	{
		while ((opt = getopt(argc, argv, "p:F:H:D:P:L:")) != EOF)
		{
			switch (opt)
			{
				case 'p':
				{
					set_passwd = True;
					safe_strcpy(password, optarg,
						    sizeof(password) - 1);
					break;
				}
				case 'F':
				{
					set_info_21 = set_full_name = True;
					safe_strcpy(full_name, optarg,
						    sizeof(full_name) - 1);
					break;
				}
				case 'H':
				{
					set_info_21 = set_home_dir = True;
					safe_strcpy(home_dir, optarg,
						    sizeof(home_dir) - 1);
					break;
				}
				case 'D':
				{
					set_info_21 = set_dir_drive = True;
					safe_strcpy(dir_drive, optarg,
						    sizeof(dir_drive) - 1);
					break;
				}
				case 'P':
				{
					set_info_21 = set_profile_path = True;
					safe_strcpy(profile_path, optarg,
						    sizeof(profile_path) - 1);
					break;
				}
				case 'L':
				{
					set_info_21 = set_logon_script = True;
					safe_strcpy(logon_script, optarg,
						    sizeof(logon_script) - 1);
					break;
				}
			}
		}
	}

/* Test for set_passwd if set_info_21 is true.  I can't seem to figure out how to use
   info level 21 to set the userinfo without having a password handy... UGH. */

	if (set_info_21 && !set_passwd) 
	{
		report(out_hnd, "To Change the User Info, you MUST specify -p!\n");
		DEBUG(5, ("cmd_sam_query_user: failed\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Set User Info: %s\n", user_name);
	if (set_passwd)
		report(out_hnd, "Password: %s\n", password);
	if (set_full_name)
		report(out_hnd, "Full Name: %s\n", full_name);
	if (set_home_dir)
		report(out_hnd, "Home Drive: %s\n", home_dir);
	if (set_dir_drive)
		report(out_hnd, "Dir Drive: %s\n", dir_drive);
	if (set_profile_path)
		report(out_hnd, "Profile Path: %s\n", profile_path);
	if (set_logon_script)
		report(out_hnd, "Logon Script: %s\n", logon_script);

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &sid, &pol_dom) : False;

	/* look up user rid */
	names[0] = user_name;
	res1 = res ? samr_query_lookup_names(&pol_dom, 0x3e8,
					     1, names,
					     &num_rids, &rids,
					     &types) : False;

	/* send set user info */
	if (res1 && num_rids == 1 && get_samr_query_userinfo(&pol_dom,
							     0x15, rids[0],
							     &ctr))
	{
		void *usr = NULL;
		uint32 switch_value = 0;
		char pwbuf[516];

		if (set_passwd)
		{
			SAM_USER_INFO_24 *p = g_new(SAM_USER_INFO_24, 1);
			encode_pw_buffer(pwbuf, password,
					 strlen(password), True);
			make_sam_user_info24(p, pwbuf, strlen(password));

			usr = p;
			switch_value = 24;
			if (usr != NULL)
			{
				res1 = set_samr_set_userinfo(&pol_dom,
							     switch_value, rids[0],
							     usr);
			}
		}

		if (set_passwd && set_info_21)
		{
			SAM_USER_INFO_21 *usr21 = ctr.info.id21;
			SAM_USER_INFO_21 *p = g_new(SAM_USER_INFO_21, 1);
			/* send user info query, level 0x15 */
			report(out_hnd, "Before\n");
			display_sam_user_info_21(out_hnd, ACTION_HEADER, usr21);
			display_sam_user_info_21(out_hnd, ACTION_ENUMERATE, usr21);
			display_sam_user_info_21(out_hnd, ACTION_FOOTER, usr21);

			if (set_full_name)
			{
			        len_full_name = full_name != NULL ? strlen(full_name) : 0;
				make_unistr2(&(usr21->uni_full_name), full_name, len_full_name);
			}
			if (set_home_dir)
			{
			        len_home_dir = home_dir != NULL ? strlen(home_dir) : 0;
				make_unistr2(&(usr21->uni_home_dir), home_dir, len_home_dir);
			}
			if (set_dir_drive)
			{
			        len_dir_drive = dir_drive != NULL ? strlen(dir_drive) : 0;
				make_unistr2(&(usr21->uni_dir_drive), dir_drive, len_dir_drive);
			}
			if (set_profile_path)
			{
			        len_profile_path = profile_path != NULL ? strlen(profile_path) : 0;
				make_unistr2(&(usr21->uni_profile_path), profile_path, len_profile_path);
			}
			if (set_logon_script)
			{
			        len_logon_script = logon_script != NULL ? strlen(logon_script) : 0;
				make_unistr2(&(usr21->uni_logon_script), logon_script, len_logon_script);
			}
			report(out_hnd, "After\n");
			display_sam_user_info_21(out_hnd, ACTION_HEADER, usr21);
			display_sam_user_info_21(out_hnd, ACTION_ENUMERATE, usr21);
			display_sam_user_info_21(out_hnd, ACTION_FOOTER, usr21);
			make_sam_user_info21W(p,
					      &usr21->logon_time,
					      &usr21->logoff_time,
					      &usr21->kickoff_time,
					      &usr21->pass_last_set_time,
					      &usr21->pass_can_change_time,
					      &usr21->pass_must_change_time,
					      &usr21->uni_user_name,
					      &usr21->uni_full_name,
					      &usr21->uni_home_dir,
					      &usr21->uni_dir_drive,
					      &usr21->uni_logon_script,
					      &usr21->uni_profile_path,
					      &usr21->uni_acct_desc,
					      &usr21->uni_workstations,
					      &usr21->uni_unknown_str,
					      &usr21->uni_munged_dial,
					      usr21->lm_pwd,
					      usr21->nt_pwd,
					      usr21->user_rid,
					      usr21->group_rid,
					      usr21->acb_info,
					      usr21->unknown_3,
					      usr21->logon_divs,
					      &usr21->logon_hrs,
					      usr21->unknown_5,
					      usr21->unknown_6);

			usr = p;
			report(out_hnd, "After Make\n");
			display_sam_user_info_21(out_hnd, ACTION_HEADER, usr);
			display_sam_user_info_21(out_hnd, ACTION_ENUMERATE, usr);
			display_sam_user_info_21(out_hnd, ACTION_FOOTER, usr);
			switch_value = 21;
			if (usr != NULL)
			{
				res2 = set_samr_set_userinfo(&pol_dom,
							     switch_value, rids[0],
							     usr);
			}
		}
	}

	free_samr_userinfo_ctr(&ctr);
	safe_free(rids);
	safe_free(types);

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (set_passwd && res1 && res2)
	{
		report(out_hnd, "Set User Info: OK\n");
		DEBUG(5, ("cmd_sam_query_user: succeeded\n"));
		return NT_STATUS_NOPROBLEMO;
	}
	report(out_hnd, "Set User Info: Failed\n");
	if (!res1)
		report(out_hnd, "Password change failed\n");
	if (!res2)
		report(out_hnd, "User Info change failed\n");
	DEBUG(5, ("cmd_sam_query_user: failed\n"));
	return NT_STATUS_UNSUCCESSFUL;
}

static void sam_display_disp_info(const char *domain, const DOM_SID *sid,
				  uint16 info, uint32 num,
				  SAM_DISPINFO_CTR * ctr)
{
	report(out_hnd, "SAM Display Info for Domain %s\n", domain);

	display_sam_disp_info_ctr(out_hnd, ACTION_HEADER, info, num, ctr);
	display_sam_disp_info_ctr(out_hnd, ACTION_ENUMERATE, info, num, ctr);
	display_sam_disp_info_ctr(out_hnd, ACTION_FOOTER, info, num, ctr);
}

/****************************************************************************
experimental SAM query display info.
****************************************************************************/
uint32 cmd_sam_query_dispinfo(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	uint16 switch_value = 1;
	SAM_DISPINFO_CTR ctr;
	SAM_DISPINFO_1 inf1;
	uint32 num_entries;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

	string_to_sid(&sid1, sid);

	if (sid1.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid1) !=
		    0x0)
		{
			fprintf(out_hnd,
				"please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc > 1)
	{
		switch_value = strtoul(argv[1], (char **)NULL, 10);
	}

	ctr.sam.info1 = &inf1;

	if (msrpc_sam_query_dispinfo(srv_name, domain, &sid1,
				     switch_value,
				     &num_entries, &ctr,
				     sam_display_disp_info))
	{

		DEBUG(5, ("cmd_sam_query_dispinfo: succeeded\n"));
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_query_dispinfo: failed\n"));
	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
experimental SAM domain info query.
****************************************************************************/
uint32 cmd_sam_query_dominfo(struct client_info *info, int argc, char *argv[])
{
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	uint32 switch_value = 2;
	SAM_UNK_CTR ctr;
	fstring srv_name;
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

	string_to_sid(&sid1, sid);

	if (sid1.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid1) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc > 1)
	{
		switch_value = strtoul(argv[1], (char **)NULL, 10);
	}

	if (sam_query_dominfo(srv_name, &sid1, switch_value, &ctr))
	{
		DEBUG(5, ("cmd_sam_query_dominfo: succeeded\n"));
		sam_display_dom_info(domain, &sid1, switch_value, &ctr);
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_query_dominfo: failed\n"));
	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
experimental SAM alias query members.
****************************************************************************/
uint32 cmd_sam_query_aliasmem(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;

	fstring alias_name;
	char *names[1];
	uint32 num_rids;
	uint32 *rids;
	uint32 *types;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "samaliasmem [DOMAIN\\]<name>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid) != 0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (strchr(argv[1], '\\')
	    && split_domain_name(argv[1], domain, alias_name))
	{
		fill_domain_sid(srv_name, domain, domain, &sid);
	}
	else
	{
		safe_strcpy(alias_name, argv[1], sizeof(alias_name)-1);
	}

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query Alias: %s\n", alias_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	       info->myhostname, srv_name, domain, sid_str);

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, 0x304, &sid, &pol_dom) : False;

	/* look up alias rid */
	names[0] = alias_name;
	res1 = res ? samr_query_lookup_names(&pol_dom, 0x3e8,
					     1, names,
					     &num_rids, &rids,
					     &types) : False;

	if (res1 && num_rids == 1)
	{
		res1 = req_aliasmem_info(srv_name,
					 &pol_dom,
					 domain,
					 &sid,
					 rids[0],
					 alias_name,
					 sam_display_alias_members);
	}

	safe_free(rids);
	safe_free(types);

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res1)
	{
		DEBUG(5, ("cmd_sam_query_alias: succeeded\n"));
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_query_alias: failed\n"));
	return NT_STATUS_UNSUCCESSFUL;
}


/****************************************************************************
experimental SAM alias query.
****************************************************************************/
uint32 cmd_sam_query_alias(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;

	char *alias_name;
	char *names[1];
	uint32 num_rids;
	uint32 *rids;
	uint32 *types;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid) != 0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (argc < 2)
	{
		report(out_hnd, "samalias <name>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	alias_name = argv[1];

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query Alias: %s\n", alias_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	       info->myhostname, srv_name, domain, sid_str);

	/* establish a connection. */
	res = res ? samr_connect(srv_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
				 &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(&sam_pol, 0x304, &sid, &pol_dom) : False;

	/* look up alias rid */
	names[0] = alias_name;
	res1 = res ? samr_query_lookup_names(&pol_dom, 0x3e8,
					     1, names,
					     &num_rids, &rids,
					     &types) : False;

	if (res1 && num_rids == 1)
	{
		res1 = query_aliasinfo(&pol_dom,
				       domain,
				       &sid, rids[0], sam_display_alias_info);
	}

	safe_free(rids);
	safe_free(types);

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res1)
	{
		DEBUG(5, ("cmd_sam_query_alias: succeeded\n"));
		return NT_STATUS_NOPROBLEMO;
	}
	DEBUG(5, ("cmd_sam_query_alias: failed\n"));
	return NT_STATUS_UNSUCCESSFUL;
}


/****************************************************************************
SAM aliases query.
****************************************************************************/
uint32 cmd_sam_enum_aliases(struct client_info *info, int argc, char *argv[])
{
	BOOL request_member_info = False;
	BOOL request_alias_info = False;
	struct acct_info *sam = NULL;
	uint32 num_sam_entries = 0;
	int opt;
	BOOL res1;

	fstring domain;
	fstring srv_name;
	fstring sid;
	DOM_SID sid1;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	while ((opt = getopt(argc, argv, "mad:")) != EOF)
	{
		switch (opt)
		{
			case 'd':
			{
				fill_domain_sid(srv_name, optarg,
						domain, &sid1);
				break;
			}
			case 'm':
			{
				request_member_info = True;
				break;
			}
			case 'a':
			{
				request_alias_info = True;
				break;
			}
		}
	}

	if (sid1.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid1) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	report(out_hnd, "SAM Enumerate Aliases\n");

	res1 = msrpc_sam_enum_aliases(srv_name, domain, &sid1,
			       &sam, &num_sam_entries,
			       sam_display_alias,
			       request_alias_info ? sam_display_alias_info :
			       NULL,
			       request_member_info ? sam_display_alias_members
			       : NULL);

	safe_free(sam);
	if (res1)
	{
		return NT_STATUS_NOPROBLEMO;
	}
	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
experimental SAM groups enum.
****************************************************************************/
uint32 cmd_sam_enum_groups(struct client_info *info, int argc, char *argv[])
{
	BOOL request_member_info = False;
	BOOL request_group_info = False;
	struct acct_info *sam = NULL;
	uint32 num_sam_entries = 0;
	int opt;
	BOOL res1;

	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		if (msrpc_sam_get_first_domain(srv_name, domain, &sid1) !=
		    0x0)
		{
			report(out_hnd,
			       "please use 'lsaquery' first, to ascertain the SID\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	while ((opt = getopt(argc, argv, "mg")) != EOF)
	{
		switch (opt)
		{
			case 'm':
			{
				request_member_info = True;
				break;
			}
			case 'g':
			{
				request_group_info = True;
				break;
			}
		}
	}

	report(out_hnd, "SAM Enumerate Groups\n");

	res1 = msrpc_sam_enum_groups(srv_name, domain, &sid1,
			      &sam, &num_sam_entries,
			      sam_display_group,
			      request_group_info ? sam_display_group_info :
			      NULL,
			      request_member_info ? sam_display_group_members
			      : NULL);

	safe_free(sam);

	if (res1)
	{
		return NT_STATUS_NOPROBLEMO;
	}
	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
experimental SAM domains enum.
****************************************************************************/
uint32 cmd_sam_enum_domains(struct client_info *info, int argc, char *argv[])
{
	BOOL request_domain_info = False;
	struct acct_info *sam = NULL;
	uint32 num_sam_entries = 0;
	int opt;
	BOOL res1;

	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	while ((opt = getopt(argc, argv, "i")) != EOF)
	{
		switch (opt)
		{
			case 'i':
			{
				request_domain_info = True;
				break;
			}
		}
	}

	report(out_hnd, "SAM Enumerate Domains\n");

	res1 = msrpc_sam_enum_domains(srv_name,
			       &sam, &num_sam_entries,
			       request_domain_info ? NULL :
			       sam_display_domain,
			       request_domain_info ? sam_display_dom_info :
			       NULL);

	safe_free(sam);
	if (res1)
	{
		return NT_STATUS_NOPROBLEMO;
	}
	return NT_STATUS_UNSUCCESSFUL;
}
