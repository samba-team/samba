/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   
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



#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "nterr.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

extern struct user_creds *usr_creds;

extern FILE* out_hnd;

static void sam_display_domain(const char *domain)
{
	report(out_hnd, "Domain Name: %s\n", domain);
}

static void sam_display_dom_info(const char* domain, const DOM_SID *sid,
				uint32 switch_value,
				SAM_UNK_CTR *ctr)
{
	fstring sidstr;
	sid_to_string(sidstr, sid);
	report(out_hnd, "Domain Name:\t%s\tSID:\t%s\n", domain, sidstr);
	display_sam_unk_ctr(out_hnd, ACTION_HEADER   , switch_value, ctr);
	display_sam_unk_ctr(out_hnd, ACTION_ENUMERATE, switch_value, ctr);
	display_sam_unk_ctr(out_hnd, ACTION_FOOTER   , switch_value, ctr);
}

static void sam_display_alias_info(const char *domain, const DOM_SID *sid,
				uint32 alias_rid, 
				ALIAS_INFO_CTR *const ctr)
{
	display_alias_info_ctr(out_hnd, ACTION_HEADER   , ctr);
	display_alias_info_ctr(out_hnd, ACTION_ENUMERATE, ctr);
	display_alias_info_ctr(out_hnd, ACTION_FOOTER   , ctr);
}

static void sam_display_alias(const char *domain, const DOM_SID *sid,
				uint32 alias_rid, const char *alias_name)
{
	report(out_hnd, "Alias RID: %8x  Alias Name: %s\n",
			  alias_rid, alias_name);
}

static void sam_display_alias_members(const char *domain, const DOM_SID *sid,
				uint32 alias_rid, const char *alias_name,
				uint32 num_names,
				DOM_SID *const *const sids,
				char *const *const name,
				uint8 *const type)
{
	display_alias_members(out_hnd, ACTION_HEADER   , num_names, name, type);
	display_alias_members(out_hnd, ACTION_ENUMERATE, num_names, name, type);
	display_alias_members(out_hnd, ACTION_FOOTER   , num_names, name, type);
}

static void sam_display_group_info(const char *domain, const DOM_SID *sid,
				uint32 group_rid, 
				GROUP_INFO_CTR *const ctr)
{
	display_group_info_ctr(out_hnd, ACTION_HEADER   , ctr);
	display_group_info_ctr(out_hnd, ACTION_ENUMERATE, ctr);
	display_group_info_ctr(out_hnd, ACTION_FOOTER   , ctr);
}

static void sam_display_group(const char *domain, const DOM_SID *sid,
				uint32 group_rid, const char *group_name)
{
	report(out_hnd, "Group RID: %8x  Group Name: %s\n",
			  group_rid, group_name);
}

static void sam_display_group_members(const char *domain, const DOM_SID *sid,
				uint32 group_rid, const char *group_name,
				uint32 num_names,
				const uint32 *rid_mem,
				char *const *const name,
				uint32 *const type)
{
	display_group_members(out_hnd, ACTION_HEADER   , num_names, name, type);
	display_group_members(out_hnd, ACTION_ENUMERATE, num_names, name, type);
	display_group_members(out_hnd, ACTION_FOOTER   , num_names, name, type);
}

static void sam_display_user_info(const char *domain, const DOM_SID *sid,
				uint32 user_rid, 
				SAM_USER_INFO_21 *const usr)
{
	display_sam_user_info_21(out_hnd, ACTION_HEADER   , usr);
	display_sam_user_info_21(out_hnd, ACTION_ENUMERATE, usr);
	display_sam_user_info_21(out_hnd, ACTION_FOOTER   , usr);
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
void cmd_sam_ntchange_pwd(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	char *new_passwd;
	char *new_passwd2;
	uchar nt_oldhash[16];
	uchar lm_oldhash[16];
	fstring acct_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	report(out_hnd, "SAM NT Password Change\n");

	if (argc >= 2)
	{
		struct pwd_info old_pwd;
		safe_strcpy(acct_name, argv[1], sizeof(acct_name));
		pwd_read(&old_pwd, "Old Password:", True);
		pwd_get_lm_nt_16(&old_pwd, lm_oldhash, nt_oldhash );
	}
	else
	{
		safe_strcpy(acct_name, usr_creds->ntc.user_name, sizeof(acct_name));
		pwd_get_lm_nt_16(&(usr_creds->ntc.pwd), lm_oldhash, nt_oldhash );
	}

	new_passwd = (char*)getpass("New Password: ");
	new_passwd2 = (char*)getpass("retype: ");

	if ((new_passwd != NULL && new_passwd2 != NULL &&
	     !strequal(new_passwd, new_passwd2)) ||
	    (new_passwd != new_passwd2))
	{
		report(out_hnd, "New passwords differ!\n");
		return;
	}

	/* establish a connection. */
	if (msrpc_sam_ntchange_pwd( srv_name, NULL, acct_name, 
	                                   lm_oldhash, nt_oldhash,
	                                   new_passwd))
	{
		report(out_hnd, "NT Password changed OK\n");
	}
	else
	{
		report(out_hnd, "NT Password change FAILED\n");
	}
}


/****************************************************************************
experimental SAM encryted rpc test connection
****************************************************************************/
void cmd_sam_test(struct client_info *info, int argc, char *argv[])
{
	struct cli_connection *con = NULL;
	fstring srv_name;
	fstring domain;
	fstring sid;
	BOOL res = True;

	sid_to_string(sid, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

/*
	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}
*/
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
		                    NTLMSSP_NEGOTIATE_00001000 |
		                    NTLMSSP_NEGOTIATE_00002000;

	/* open SAMR session.  */
	res = res ? cli_connection_init(srv_name, PIPE_SAMR, &con) : False;

	/* close the session */
	cli_connection_unlink(con);

	if (res)
	{
		DEBUG(5,("cmd_sam_test: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_test: failed\n"));
	}
}

/****************************************************************************
Lookup domain in SAM server.
****************************************************************************/
void cmd_sam_lookup_domain(struct client_info *info, int argc, char *argv[])
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
		return;
	}

	domain = argv[1];

	report(out_hnd, "Lookup Domain in SAM Server\n");

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_query_lookup_domain( &sam_pol, domain, &dom_sid) : False;

	res = res ? samr_close(&sam_pol) : False;

	if (res)
	{
		DEBUG(5,("cmd_sam_lookup_domain: succeeded\n"));

		sid_to_string(str_sid, &dom_sid);
		report(out_hnd, "%s SID: %s\n", domain, str_sid);
		report(out_hnd, "Lookup Domain: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_lookup_domain: failed\n"));
		report(out_hnd, "Lookup Domain: FAILED\n");
	}
}

/****************************************************************************
SAM delete alias member.
****************************************************************************/
void cmd_sam_del_aliasmem(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND alias_pol;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	DOM_SID member_sid; 
	uint32 alias_rid;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "delaliasmem: <alias rid> [member sid1] [member sid2] ...\n");
		return;
	}

	argc--;
	argv++;

	alias_rid = get_number(argv[0]);

	report(out_hnd, "SAM Domain Alias Member\n");

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	/* connect to the domain */
	res1 = res ? samr_open_alias( &pol_dom,
	            0x000f001f, alias_rid, &alias_pol) : False;

	while (argc > 0 && res2 && res1)
	{
		argc--;
		argv++;
		/* get a sid, delete a member from the alias */
		res2 = res2 ? string_to_sid(&member_sid, argv[0]) : False;
		res2 = res2 ? samr_del_aliasmem(&alias_pol, &member_sid) : False;

		if (res2)
		{
			report(out_hnd, "SID deleted from Alias 0x%x: %s\n", alias_rid, argv[0]);
		}
	}

	res1 = res1 ? samr_close(&alias_pol) : False;
	res  = res  ? samr_close(&pol_dom) : False;
	res  = res  ? samr_close(&sam_pol) : False;

	if (res && res1 && res2)
	{
		DEBUG(5,("cmd_sam_del_aliasmem: succeeded\n"));
		report(out_hnd, "Delete Domain Alias Member: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_del_aliasmem: failed\n"));
		report(out_hnd, "Delete Domain Alias Member: FAILED\n");
	}
}

/****************************************************************************
SAM delete alias.
****************************************************************************/
void cmd_sam_delete_dom_alias(struct client_info *info, int argc, char *argv[])
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
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 alias_rid = 0;
	const char *names[1];
	uint32 *rids;
	uint32 *types;
	uint32 num_rids;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "delalias <alias name>\n");
		return;
	}

	name = argv[1];

	report(out_hnd, "SAM Delete Domain Alias\n");

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	names[0] = name;

	res1 = res ? samr_query_lookup_names( &pol_dom, 0x000003e8,
	            1, names,
	            &num_rids, &rids, &types) : False;

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
	res1 = res1 ? samr_open_alias( &pol_dom,
	            0x000f001f, alias_rid, &alias_pol) : False;

	res2 = res1 ? samr_delete_dom_alias(&alias_pol) : False;

	res1 = res1 ? samr_close(&alias_pol) : False;
	res  = res  ? samr_close(&pol_dom) : False;
	res  = res  ? samr_close(&sam_pol) : False;

	if (res && res1 && res2)
	{
		DEBUG(5,("cmd_sam_delete_dom_alias: succeeded\n"));
		report(out_hnd, "Delete Domain Alias: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_delete_dom_alias: failed\n"));
		report(out_hnd, "Delete Domain Alias: FAILED\n");
	}
}

/****************************************************************************
SAM add alias member.
****************************************************************************/
void cmd_sam_add_aliasmem(struct client_info *info, int argc, char *argv[])
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
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 alias_rid;
	char **names = NULL;
	int num_names = 0;
	DOM_SID *sids = NULL; 
	int num_sids = 0;
	int i;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	POLICY_HND lsa_pol;

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "addaliasmem <group name> [member name1] [member name2] ...\n");
		return;
	}
	
	num_names = argc+1;
	names = argv+1;

	report(out_hnd, "SAM Domain Alias Member\n");

	/* lookup domain controller; receive a policy handle */
	res3 = res3 ? lsa_open_policy(srv_name,
				&lsa_pol, True) : False;

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
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	/* connect to the domain */
	res1 = res ? samr_open_alias( &pol_dom,
	            0x000f001f, alias_rid, &alias_pol) : False;

	for (i = 1; i < num_sids && res2 && res1; i++)
	{
		/* add a member to the alias */
		res2 = res2 ? samr_add_aliasmem(&alias_pol, &sids[i]) : False;

		if (res2)
		{
			sid_to_string(tmp, &sids[i]);
			report(out_hnd, "SID added to Alias 0x%x: %s\n", alias_rid, tmp);
		}
	}

	res1 = res1 ? samr_close(&alias_pol) : False;
	res  = res  ? samr_close(&pol_dom) : False;
	res  = res  ? samr_close(&sam_pol) : False;

	if (sids != NULL)
	{
		free(sids);
	}
	
	free_char_array(num_names, names);

	if (res && res1 && res2)
	{
		DEBUG(5,("cmd_sam_add_aliasmem: succeeded\n"));
		report(out_hnd, "Add Domain Alias Member: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_add_aliasmem: failed\n"));
		report(out_hnd, "Add Domain Alias Member: FAILED\n");
	}
}


#if 0
/****************************************************************************
SAM create domain user.
****************************************************************************/
void cmd_sam_create_dom_trusting(struct client_info *info, int argc, char *argv[])
{
	fstring local_domain;
	fstring local_pdc;

	char *trusting_domain;
	char *trusting_pdc;
	fstring password;

	fstring sid;
	DOM_SID sid1;
	uint32 user_rid; 

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	if (argc < 3)
	{
		report(out_hnd, "createtrusting: <Domain Name> <PDC Name> [password]\n");
		return;
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
		safe_strcpy(password, argv[0], sizeof(password)-1);
	}
	else
	{
		fstring pass_str;
		char *pass;
		slprintf(pass_str, sizeof(pass_str)-1, "Enter %s's Password:",
		         user_name);
		pass = (char*)getpass(pass_str);

		if (pass != NULL)
		{
			safe_strcpy(password, pass, sizeof(password)-1);
			set_passwd = True;
		}
	}
	report(out_hnd, "SAM Create Domain Trusting Account\n");

	if (msrpc_sam_create_dom_user(srv_name,
	                              acct_name, ACB_WSTRUST, &user_rid))
	{
		report(out_hnd, "Create Domain User: OK\n");
	}
	else
	{
		report(out_hnd, "Create Domain User: FAILED\n");
	}
}
#endif

/****************************************************************************
SAM create domain user.
****************************************************************************/
void cmd_sam_create_dom_user(struct client_info *info, int argc, char *argv[])
{
	fstring domain;
	fstring acct_name;
	fstring name;
	fstring sid;
	DOM_SID sid1;
	uint32 user_rid; 
	uint16 acb_info = ACB_NORMAL;
	BOOL join_domain = False;
	int opt;
	char *password = NULL;
	int plen = 0;
	int len = 0;
	UNISTR2 upw;

	fstring srv_name;
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);


	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	if (argc < 2)
	{
		report(out_hnd, "createuser: <acct name> [-i] [-s] [-j]\n");
		return;
	}

	argc--;
	argv++;

	safe_strcpy(acct_name, argv[0], sizeof(acct_name));
	len = strlen(acct_name)-1;
	if (acct_name[len] == '$')
	{
		safe_strcpy(name, argv[0], sizeof(name));
		name[len] = 0;
		acb_info = ACB_WSTRUST;
	}

	while ((opt = getopt(argc, argv,"isj")) != EOF)
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
			}
		}
	}

	if (join_domain && acb_info == ACB_NORMAL)
	{
		report(out_hnd, "can only join trust accounts to a domain\n");
		return;
	}

	report(out_hnd, "SAM Create Domain User\n");
	report(out_hnd, "Domain: %s Name: %s ACB: %s\n",
	                  domain, acct_name,
	    pwdb_encode_acct_ctrl(acb_info, NEW_PW_FORMAT_SPACE_PADDED_LEN));

	if (acb_info == ACB_WSTRUST || acb_info == ACB_SVRTRUST)
	{
		upw.uni_str_len = 12;
		upw.uni_max_len = 12;
		generate_random_buffer((uchar*)upw.buffer,
		                       upw.uni_str_len*2, True);
		password = (char*)upw.buffer;
		plen = upw.uni_str_len * 2;
	}

	if (msrpc_sam_create_dom_user(srv_name, &sid1,
	                              acct_name, acb_info, password, plen,
	                              &user_rid))
	{
		report(out_hnd, "Create Domain User: OK\n");

		if (join_domain)
		{
			uchar ntpw[16];
			
			nt_owf_genW(&upw, ntpw);

			strupper(domain);
			strupper(name);

			report(out_hnd, "Join %s to Domain %s", name, domain);
			if (create_trust_account_file(domain, name, ntpw))
			{
				report(out_hnd, ": OK\n");
			}
			else
			{
				report(out_hnd, ": FAILED\n");
			}
		}
	}
	else
	{
		report(out_hnd, "Create Domain User: FAILED\n");
	}
}


/****************************************************************************
SAM create domain alias.
****************************************************************************/
void cmd_sam_create_dom_alias(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	char *acct_name;
	fstring acct_desc;
	fstring sid;
	DOM_SID sid1;
	BOOL res = True;
	BOOL res1 = True;
	uint32 ace_perms = 0x02000000; /* permissions */
	uint32 alias_rid; 
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}


	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "createalias: <acct name> [acct description]\n");
	}

	acct_name = argv[1];

	if (argc < 3)
	{
		acct_desc[0] = 0;
	}
	else
	{
		safe_strcpy(acct_desc, argv[2], sizeof(acct_desc)-1);
	}

	report(out_hnd, "SAM Create Domain Alias\n");
	report(out_hnd, "Domain: %s Name: %s Description: %s\n",
	                  domain, acct_name, acct_desc);

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	/* create a domain alias */
	res1 = res ? create_samr_domain_alias( &pol_dom,
	                        acct_name, acct_desc, &alias_rid) : False;

	res = res ? samr_close( &pol_dom) : False;
	res = res ? samr_close( &sam_pol) : False;

	if (res && res1)
	{
		DEBUG(5,("cmd_sam_create_dom_alias: succeeded\n"));
		report(out_hnd, "Create Domain Alias: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_create_dom_alias: failed\n"));
		report(out_hnd, "Create Domain Alias: FAILED\n");
	}
}


/****************************************************************************
SAM delete group member.
****************************************************************************/
void cmd_sam_del_groupmem(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND pol_grp;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 member_rid; 
	uint32 group_rid;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "delgroupmem: <group rid> [member rid1] [member rid2] ...\n");
		return;
	}

	argc--;
	argv++;

	group_rid = get_number(argv[0]);

	report(out_hnd, "SAM Add Domain Group member\n");

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	/* connect to the domain */
	res1 = res ? samr_open_group( &pol_dom,
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
			report(out_hnd, "RID deleted from Group 0x%x: 0x%x\n", group_rid, member_rid);
		}
	}

	res1 = res1 ? samr_close(&pol_grp) : False;
	res  = res  ? samr_close(&pol_dom) : False;
	res  = res  ? samr_close(&sam_pol) : False;

	if (res && res1 && res2)
	{
		DEBUG(5,("cmd_sam_del_groupmem: succeeded\n"));
		report(out_hnd, "Add Domain Group Member: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_del_groupmem: failed\n"));
		report(out_hnd, "Add Domain Group Member: FAILED\n");
	}
}


/****************************************************************************
SAM delete group.
****************************************************************************/
void cmd_sam_delete_dom_group(struct client_info *info, int argc, char *argv[])
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
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 group_rid = 0;
	const char *names[1];
	uint32 *rids;
	uint32 *types;
	uint32 num_rids;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "delgroup <group name>\n");
		return;
	}

	name = argv[1];

	report(out_hnd, "SAM Delete Domain Group\n");

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	names[0] = name;

	res1 = res ? samr_query_lookup_names( &pol_dom, 0x000003e8,
	            1, names,
	            &num_rids, &rids, &types) : False;

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
	res1 = res1 ? samr_open_group( &pol_dom,
	            0x0000001f, group_rid, &pol_grp) : False;

	res2 = res1 ? samr_delete_dom_group(&pol_grp) : False;

	res1 = res1 ? samr_close(&pol_grp) : False;
	res  = res  ? samr_close(&pol_dom) : False;
	res  = res  ? samr_close(&sam_pol) : False;

	if (res && res1 && res2)
	{
		DEBUG(5,("cmd_sam_delete_dom_group: succeeded\n"));
		report(out_hnd, "Delete Domain Group: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_delete_dom_group: failed\n"));
		report(out_hnd, "Delete Domain Group: FAILED\n");
	}
}


/****************************************************************************
SAM add group member.
****************************************************************************/
void cmd_sam_add_groupmem(struct client_info *info, int argc, char *argv[])
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
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 *group_rids;
	uint32 *group_types;
	const char **names = NULL;
	uint32 num_names = 0;
	fstring group_name;
	const char *group_names[1];
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

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 3)
	{
		report(out_hnd, "addgroupmem <group name> [member name1] [member name2] ...\n");
		return;
	}
	
	argc--;
	argv++;

	group_names[0] = argv[0];

	argc--;
	argv++;

	num_names = argc;
	names = (const char **) argv;

	report(out_hnd, "SAM Add Domain Group member\n");

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000, &sam_pol) : False;

	/* connect to the domain */
	res4 = res ? samr_open_domain( &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	/* connect to the domain */
	res3 = res ? samr_open_domain( &sam_pol, ace_perms, &sid_1_5_20,
	            &pol_blt) : False;

	res2 = res4 ? samr_query_lookup_names( &pol_dom, 0x000003e8,
	            1, group_names,
	            &num_group_rids, &group_rids, &group_types) : False;

	/* open the group */
	res2 = res2 ? samr_open_group( &pol_dom,
	            0x0000001f, group_rids[0], &pol_grp) : False;

	if (!res2 || (group_types != NULL && group_types[0] == SID_NAME_UNKNOWN))
	{
		if (group_rids != NULL)
		{
			free(group_rids);
		}
		if (group_types != NULL)
		{
			free(group_types);
		}

		res2 = res3 ? samr_query_lookup_names( &pol_blt, 0x000003e8,
			    1, group_names, 
			    &num_group_rids, &group_rids, &group_types) : False;

		/* open the group */
		res2 = res2 ? samr_open_group( &pol_blt,
			    0x0000001f, group_rids[0], &pol_grp) : False;
	}

	if (res2 && group_types[0] == SID_NAME_ALIAS)
	{
		report(out_hnd, "%s is a local alias, not a group.  Use addaliasmem command instead\n",
			group_name);
		if (group_rids != NULL)
		{
			free(group_rids);
		}
		if (group_types != NULL)
		{
			free(group_types);
		}
		return;
	}
	res1 = res2 ? samr_query_lookup_names( &pol_dom, 0x000003e8,
	            num_names, names,
	            &num_rids, &rids, &types) : False;

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
				report(out_hnd, "RID added to Group 0x%x: 0x%x\n",
						 group_rids[0], rids[i]);
			}
		}
	}

	res1 = res ? samr_close(&pol_grp) : False;
	res1 = res3 ? samr_close(&pol_blt) : False;
	res1 = res4 ? samr_close(&pol_dom) : False;
	res  = res ? samr_close(&sam_pol) : False;

#if 0
	free_char_array(num_names, names);
#endif
	
	if (res && res1 && res2)
	{
		DEBUG(5,("cmd_sam_add_groupmem: succeeded\n"));
		report(out_hnd, "Add Domain Group Member: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_add_groupmem: failed\n"));
		report(out_hnd, "Add Domain Group Member: FAILED\n");
	}
	if (group_rids != NULL)
	{
		free(group_rids);
	}
	if (group_types != NULL)
	{
		free(group_types);
	}
	if (rids != NULL)
	{
		free(rids);
	}
	if (types != NULL)
	{
		free(types);
	}
}


/****************************************************************************
SAM create domain group.
****************************************************************************/
void cmd_sam_create_dom_group(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	char *acct_name;
	fstring acct_desc;
	fstring sid;
	DOM_SID sid1;
	BOOL res = True;
	BOOL res1 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 group_rid; 
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}


	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "creategroup: <acct name> [acct description]\n");
	}

	acct_name = argv[1];

	if (argc < 3)
	{
		acct_desc[0] = 0;
	}
	else
	{
		safe_strcpy(acct_desc, argv[2], sizeof(acct_desc)-1);
	}


	report(out_hnd, "SAM Create Domain Group\n");
	report(out_hnd, "Domain: %s Name: %s Description: %s\n",
	                  domain, acct_name, acct_desc);

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	/* read some users */
	res1 = res ? create_samr_domain_group( &pol_dom,
	                        acct_name, acct_desc, &group_rid) : False;

	res = res ? samr_close( &pol_dom) : False;
	res = res ? samr_close( &sam_pol) : False;

	if (res && res1)
	{
		DEBUG(5,("cmd_sam_create_dom_group: succeeded\n"));
		report(out_hnd, "Create Domain Group: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_create_dom_group: failed\n"));
		report(out_hnd, "Create Domain Group: FAILED\n");
	}
}

/****************************************************************************
experimental SAM users enum.
****************************************************************************/
void cmd_sam_enum_users(struct client_info *info, int argc, char *argv[])
{
	BOOL request_user_info  = False;
	BOOL request_group_info = False;
	BOOL request_alias_info = False;
	struct acct_info *sam = NULL;
	uint32 num_sam_entries = 0;
	int opt;

	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	while ((opt = getopt(argc, argv, "uga")) != EOF)
	{
		switch (opt)
		{
			case 'u':
			{
				request_user_info  = True;
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

	msrpc_sam_enum_users(srv_name, domain, &sid1,
	            &sam, &num_sam_entries,
	            sam_display_user,
	            request_user_info  ? sam_display_user_info     : NULL,
	            request_group_info ? sam_display_group_members : NULL,
	            request_alias_info ? sam_display_group_members : NULL);

	if (sam != NULL)
	{
		free(sam);
	}
}


/****************************************************************************
experimental SAM group query members.
****************************************************************************/
void cmd_sam_query_groupmem(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;

	char *group_name;
	const char *names[1];
	uint32 num_rids;
	uint32 *rids;
	uint32 *types;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	if (argc < 2)
	{
		report(out_hnd, "samgroupmem <name>\n");
		return;
	}

	group_name = argv[1];

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query Group: %s\n", group_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid_str);

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, 0x304, &sid,
	            &pol_dom) : False;

	/* look up group rid */
	names[0] = group_name;
	res1 = res ? samr_query_lookup_names( &pol_dom, 0x3e8,
					1, names,
					&num_rids, &rids, &types) : False;

	if (res1 && num_rids == 1)
	{
		res1 = req_groupmem_info( &pol_dom,
				domain,
				&sid,
				rids[0],
	                        group_name,
				sam_display_group_members);
	}

	res = res ? samr_close( &pol_dom) : False;
	res = res ? samr_close( &sam_pol) : False;

	if (res1)
	{
		DEBUG(5,("cmd_sam_query_group: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_query_group: failed\n"));
	}
	if (rids != NULL)
	{
		free(rids);
	}
	if (types != NULL)
	{
		free(types);
	}
}


/****************************************************************************
experimental SAM group query.
****************************************************************************/
void cmd_sam_query_group(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;

	char *group_name;
	const char *names[1];
	uint32 num_rids;
	uint32 *rids;
	uint32 *types;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	if (argc < 2)
	{
		report(out_hnd, "samgroup <name>\n");
		return;
	}

	group_name = argv[1];

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query Group: %s\n", group_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid_str);

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000, &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, 0x304, &sid, &pol_dom) : False;

	/* look up group rid */
	names[0] = group_name;
	res1 = res ? samr_query_lookup_names( &pol_dom, 0x3e8,
					1, names,
					&num_rids, &rids, &types) : False;

	if (res1 && num_rids == 1)
	{
		res1 = query_groupinfo( &pol_dom,
				domain,
				&sid,
				rids[0],
				sam_display_group_info);
	}

	res = res ? samr_close( &pol_dom) : False;
	res = res ? samr_close( &sam_pol) : False;

	if (res1)
	{
		DEBUG(5,("cmd_sam_query_group: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_query_group: failed\n"));
	}
	if (rids != NULL)
	{
		free(rids);
	}
	if (types != NULL)
	{
		free(types);
	}
	
}


/****************************************************************************
experimental SAM user query.
****************************************************************************/
void cmd_sam_query_user(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;
	int opt;

	char *user_name;
	const char *names[1];
	uint32 num_rids;
	uint32 *rids;
	uint32 *types;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	BOOL request_user_info  = False;
	BOOL request_group_info = False;
	BOOL request_alias_info = False;

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	if (argc < 2)
	{
		report(out_hnd, "samuser <name> [-u] [-g] [-a]\n");
		return;
	}

	user_name = argv[1];

	argc--;
	argv++;

	while ((opt = getopt(argc, argv, "uga")) != EOF)
	{
		switch (opt)
		{
			case 'u':
			{
				request_user_info  = True;
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

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query User: %s\n", user_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid_str);

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, 0x304, &sid,
	            &pol_dom) : False;

	/* look up user rid */
	names[0] = user_name;
	res1 = res ? samr_query_lookup_names( &pol_dom, 0x3e8,
					1, names,
					&num_rids, &rids, &types) : False;

	/* send user info query */
	if (res1 && num_rids == 1)
	{
		msrpc_sam_user( &pol_dom, NULL,
				domain,
				&sid, NULL,
				rids[0], user_name,
	            sam_display_user,
	            request_user_info  ? sam_display_user_info     : NULL,
	            request_group_info ? sam_display_group_members : NULL,
	            request_alias_info ? sam_display_group_members : NULL);
	}
	else
	{
		res1 = False;
	}

	res = res ? samr_close( &pol_dom) : False;
	res = res ? samr_close( &sam_pol) : False;

	if (res1)
	{
		DEBUG(5,("cmd_sam_query_user: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_query_user: failed\n"));
	}
	if (rids != NULL)
	{
		free(rids);
	}
	if (types != NULL)
	{
		free(types);
	}
}


/****************************************************************************
experimental SAM user set.
****************************************************************************/
void cmd_sam_set_userinfo2(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;
	int opt;
	BOOL set_acb_bits = False;

	fstring user_name;

	const char *names[1];
	uint32 num_rids;
	uint32 *rids;
	uint32 *types;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	SAM_USER_INFO_16 usr16;
	uint16 acb_set = 0x0;

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	if (argc < 2)
	{
		report(out_hnd, "samuserset2 <name> [-s <acb_bits>]\n");
		return;
	}

	argc--;
	argv++;

	safe_strcpy(user_name, argv[0], sizeof(user_name));

	while ((opt = getopt(argc, argv,"s:")) != EOF)
	{
		switch (opt)
		{
			case 's':
			{
				set_acb_bits = True;
				acb_set = get_number(optarg);
				break;
			}
		}
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Set User Info: %s\n", user_name);

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, 0x02000000, &sid,
	            &pol_dom) : False;

	/* look up user rid */
	names[0] = user_name;
	res1 = res ? samr_query_lookup_names( &pol_dom, 0x3e8,
					1, names,
					&num_rids, &rids, &types) : False;

	/* send set user info */
	if (res1 && num_rids == 1 && get_samr_query_userinfo( &pol_dom,
						    0x10, rids[0],
	                                            (void*)&usr16))
	{
		void *usr = NULL;
		uint32 switch_value = 0;

		if (set_acb_bits)
		{
			usr16.acb_info |= acb_set;
		}

		if (True)
		{
			SAM_USER_INFO_16 *p = (SAM_USER_INFO_16 *)malloc(sizeof(SAM_USER_INFO_16));
			p->acb_info = usr16.acb_info;

			usr = (void*)p;
			switch_value = 16;
		}
		
		if (usr != NULL)
		{
			res1 = set_samr_set_userinfo2( &pol_dom,
					    switch_value, rids[0], usr);
		}
	}

	res = res ? samr_close( &pol_dom) : False;
	res = res ? samr_close( &sam_pol) : False;

	if (res1)
	{
		report(out_hnd, "Set User Info: OK\n");
		DEBUG(5,("cmd_sam_query_user: succeeded\n"));
	}
	else
	{
		report(out_hnd, "Set User Info: Failed\n");
		DEBUG(5,("cmd_sam_query_user: failed\n"));
	}
	if (rids != NULL)
	{
		free(rids);
	}
	if (types != NULL)
	{
		free(types);
	}
}

/****************************************************************************
experimental SAM user set.
****************************************************************************/
void cmd_sam_set_userinfo(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;
	int opt;
	BOOL set_passwd = False;

	fstring user_name;
	fstring password;

	const char *names[1];
	uint32 num_rids;
	uint32 *rids;
	uint32 *types;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	SAM_USER_INFO_21 usr21;

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	argc--;
	argv++;

	if (argc == 0)
	{
		report(out_hnd, "samuserset <name> [-p password]\n");
		return;
	}

	safe_strcpy(user_name, argv[0], sizeof(user_name));

	if (argc == 1)
	{
		fstring pass_str;
		char *pass;
		slprintf(pass_str, sizeof(pass_str)-1, "Enter %s's Password:",
		         user_name);
		pass = (char*)getpass(pass_str);

		if (pass != NULL)
		{
			safe_strcpy(password, pass,
				    sizeof(password)-1);
			set_passwd = True;
		}
	}
	else
	{
		while ((opt = getopt(argc, argv,"p:")) != EOF)
		{
			switch (opt)
			{
				case 'p':
				{
					set_passwd = True;
					safe_strcpy(password, optarg,
					            sizeof(password)-1);
					break;
				}
			}
		}
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Set User Info: %s\n", user_name);
	report(out_hnd, "Password: %s\n", password);

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, 0x02000000, &sid,
	            &pol_dom) : False;

	/* look up user rid */
	names[0] = user_name;
	res1 = res ? samr_query_lookup_names( &pol_dom, 0x3e8,
					1, names,
					&num_rids, &rids, &types) : False;

	/* send set user info */
	if (res1 && num_rids == 1 && get_samr_query_userinfo( &pol_dom,
						    0x15, rids[0], &usr21))
	{
		void *usr = NULL;
		uint32 switch_value = 0;
		char pwbuf[516];

		if (set_passwd)
		{
			encode_pw_buffer(pwbuf, password,
			               strlen(password), True);
		}

		if (True)
		{
			SAM_USER_INFO_24 *p = (SAM_USER_INFO_24*)malloc(sizeof(SAM_USER_INFO_24));
			make_sam_user_info24(p, pwbuf, strlen(password));

			usr = p;
			switch_value = 24;
		}
		
		if (False)
		{
			SAM_USER_INFO_23 *p = (SAM_USER_INFO_23*)malloc(sizeof(SAM_USER_INFO_23));
			/* send user info query, level 0x15 */
			make_sam_user_info23W(p,
				&usr21.logon_time, 
				&usr21.logoff_time, 
				&usr21.kickoff_time, 
				&usr21.pass_last_set_time, 
				&usr21.pass_can_change_time, 
				&usr21.pass_must_change_time, 

				&usr21.uni_user_name, 
				&usr21.uni_full_name,
				&usr21.uni_home_dir,
				&usr21.uni_dir_drive,
				&usr21.uni_logon_script,
				&usr21.uni_profile_path,
				&usr21.uni_acct_desc,
				&usr21.uni_workstations,
				&usr21.uni_unknown_str,
				&usr21.uni_munged_dial,

				0x0, 
				usr21.group_rid,
				usr21.acb_info, 

				0x09f827fa,
				usr21.logon_divs,
				&usr21.logon_hrs,
				usr21.unknown_5,
				pwbuf
#if 0
				, usr21.unknown_6
#endif
				);

			usr = p;
			switch_value = 23;
		}
		if (usr != NULL)
		{
			res1 = set_samr_set_userinfo( &pol_dom,
					    switch_value, rids[0], usr);
		}
	}

	res = res ? samr_close( &pol_dom) : False;
	res = res ? samr_close( &sam_pol) : False;

	if (res1)
	{
		report(out_hnd, "Set User Info: OK\n");
		DEBUG(5,("cmd_sam_query_user: succeeded\n"));
	}
	else
	{
		report(out_hnd, "Set User Info: Failed\n");
		DEBUG(5,("cmd_sam_query_user: failed\n"));
	}
	if (rids != NULL)
	{
		free(rids);
	}
	if (types != NULL)
	{
		free(types);
	}
}

static void sam_display_disp_info(const char* domain, const DOM_SID *sid,
				uint16 info, uint32 num,
				SAM_DISPINFO_CTR *ctr)
				
{
	report(out_hnd, "SAM Display Info for Domain %s\n", domain);

	display_sam_disp_info_ctr(out_hnd, ACTION_HEADER   , info, num, ctr);
	display_sam_disp_info_ctr(out_hnd, ACTION_ENUMERATE, info, num, ctr);
	display_sam_disp_info_ctr(out_hnd, ACTION_FOOTER   , info, num, ctr);
}

/****************************************************************************
experimental SAM query display info.
****************************************************************************/
void cmd_sam_query_dispinfo(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	uint16 switch_value = 1;
	SAM_DISPINFO_CTR ctr;
	SAM_DISPINFO_1 inf1;
	uint32 num_entries;

	sid_to_string(sid, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

	string_to_sid(&sid1, sid);

	if (sid1.num_auths == 0)
	{
		fprintf(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc > 1)
	{
		switch_value = strtoul(argv[1], (char**)NULL, 10);
	}

	ctr.sam.info1 = &inf1;

	if (msrpc_sam_query_dispinfo( srv_name, domain, &sid1,
	            switch_value, 
		    &num_entries, &ctr, sam_display_disp_info))
	{

		DEBUG(5,("cmd_sam_query_dispinfo: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_query_dispinfo: failed\n"));
	}
}

/****************************************************************************
experimental SAM domain info query.
****************************************************************************/
void cmd_sam_query_dominfo(struct client_info *info, int argc, char *argv[])
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
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	if (argc > 1)
	{
		switch_value = strtoul(argv[1], (char**)NULL, 10);
	}

	if (sam_query_dominfo(srv_name, &sid1, switch_value, &ctr))
	{
		DEBUG(5,("cmd_sam_query_dominfo: succeeded\n"));
		sam_display_dom_info(domain, &sid1, switch_value, &ctr);
	}
	else
	{
		DEBUG(5,("cmd_sam_query_dominfo: failed\n"));
	}
}

/****************************************************************************
experimental SAM alias query members.
****************************************************************************/
void cmd_sam_query_aliasmem(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;

	char *alias_name;
	const char *names[1];
	uint32 num_rids;
	uint32 *rids;
	uint32 *types;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	if (argc < 2)
	{
		report(out_hnd, "samaliasmem <name>\n");
		return;
	}

	alias_name = argv[1];

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query Alias: %s\n", alias_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid_str);

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, 0x304, &sid,
	            &pol_dom) : False;

	/* look up alias rid */
	names[0] = alias_name;
	res1 = res ? samr_query_lookup_names( &pol_dom, 0x3e8,
					1, names,
					&num_rids, &rids, &types) : False;

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

	res = res ? samr_close( &pol_dom) : False;
	res = res ? samr_close( &sam_pol) : False;

	if (res1)
	{
		DEBUG(5,("cmd_sam_query_alias: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_query_alias: failed\n"));
	}
	if (rids != NULL)
	{
		free(rids);
	}
	if (types != NULL)
	{
		free(types);
	}
}


/****************************************************************************
experimental SAM alias query.
****************************************************************************/
void cmd_sam_query_alias(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;

	char *alias_name;
	const char *names[1];
	uint32 num_rids;
	uint32 *rids;
	uint32 *types;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	if (argc < 2)
	{
		report(out_hnd, "samalias <name>\n");
		return;
	}

	alias_name = argv[1];

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query Alias: %s\n", alias_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid_str);

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, 0x304, &sid,
	            &pol_dom) : False;

	/* look up alias rid */
	names[0] = alias_name;
	res1 = res ? samr_query_lookup_names( &pol_dom, 0x3e8,
					1, names,
					&num_rids, &rids, &types) : False;

	if (res1 && num_rids == 1)
	{
		res1 = query_aliasinfo( &pol_dom,
				domain,
				&sid,
				rids[0],
				sam_display_alias_info);
	}

	res = res ? samr_close( &pol_dom) : False;
	res = res ? samr_close( &sam_pol) : False;

	if (res1)
	{
		DEBUG(5,("cmd_sam_query_alias: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_query_alias: failed\n"));
	}
	if (rids != NULL)
	{
		free(rids);
	}
	if (types != NULL)
	{
		free(types);
	}
}


/****************************************************************************
SAM aliases query.
****************************************************************************/
void cmd_sam_enum_aliases(struct client_info *info, int argc, char *argv[])
{
	BOOL request_member_info = False;
	BOOL request_alias_info = False;
	struct acct_info *sam = NULL;
	uint32 num_sam_entries = 0;
	int opt;

	fstring domain;
	fstring srv_name;
	fstring sid;
	DOM_SID sid1;
	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	while ((opt = getopt(argc, argv, "ma")) != EOF)
	{
		switch (opt)
		{
			case 'm':
			{
				request_member_info  = True;
				break;
			}
			case 'a':
			{
				request_alias_info = True;
				break;
			}
		}
	}

	report(out_hnd, "SAM Enumerate Aliases\n");

	msrpc_sam_enum_aliases(srv_name, domain, &sid1, 
	            &sam, &num_sam_entries,
	            sam_display_alias,
	            request_alias_info  ? sam_display_alias_info    : NULL,
	            request_member_info ? sam_display_alias_members : NULL);

	if (sam != NULL)
	{
		free(sam);
	}
}

/****************************************************************************
experimental SAM groups enum.
****************************************************************************/
void cmd_sam_enum_groups(struct client_info *info, int argc, char *argv[])
{
	BOOL request_member_info = False;
	BOOL request_group_info = False;
	struct acct_info *sam = NULL;
	uint32 num_sam_entries = 0;
	int opt;

	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	while ((opt = getopt(argc, argv, "mg")) != EOF)
	{
		switch (opt)
		{
			case 'm':
			{
				request_member_info  = True;
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

	msrpc_sam_enum_groups(srv_name, domain, &sid1, 
	            &sam, &num_sam_entries,
	            sam_display_group,
	            request_group_info  ? sam_display_group_info    : NULL,
	            request_member_info ? sam_display_group_members : NULL);

	if (sam != NULL)
	{
		free(sam);
	}
}

/****************************************************************************
experimental SAM domains enum.
****************************************************************************/
void cmd_sam_enum_domains(struct client_info *info, int argc, char *argv[])
{
	BOOL request_domain_info = False;
	struct acct_info *sam = NULL;
	uint32 num_sam_entries = 0;
	int opt;

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
				request_domain_info= True;
				break;
			}
		}
	}

	report(out_hnd, "SAM Enumerate Domains\n");

	msrpc_sam_enum_domains(srv_name,
	            &sam, &num_sam_entries,
	            request_domain_info ? NULL : sam_display_domain,
	            request_domain_info ? sam_display_dom_info : NULL);

	if (sam != NULL)
	{
		free(sam);
	}
}

