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



#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "nterr.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

extern struct cli_state *smb_cli;

extern FILE* out_hnd;


/****************************************************************************
SAM password change
****************************************************************************/
void cmd_sam_ntchange_pwd(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid;
	char *new_passwd;
	BOOL res = True;
	char nt_newpass[516];
	uchar nt_hshhash[16];
	uchar nt_newhash[16];
	uchar nt_oldhash[16];
	char lm_newpass[516];
	uchar lm_newhash[16];
	uchar lm_hshhash[16];
	uchar lm_oldhash[16];

	sid_to_string(sid, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	report(out_hnd, "SAM NT Password Change\n");

#if 0
	struct pwd_info new_pwd;
	pwd_read(&new_pwd, "New Password (ONCE: this is test code!):", True);
#endif
	new_passwd = (char*)getpass("New Password (ONCE ONLY - get it right :-)");

	nt_lm_owf_gen(new_passwd, lm_newhash, nt_newhash);
	pwd_get_lm_nt_16(&(smb_cli->pwd), lm_oldhash, nt_oldhash );
	make_oem_passwd_hash(nt_newpass, new_passwd, nt_oldhash, True);
	make_oem_passwd_hash(lm_newpass, new_passwd, lm_oldhash, True);
	E_old_pw_hash(lm_newhash, lm_oldhash, lm_hshhash);
	E_old_pw_hash(lm_newhash, nt_oldhash, nt_hshhash);

	cli_nt_set_ntlmssp_flgs(smb_cli,
		                    NTLMSSP_NEGOTIATE_UNICODE |
		                    NTLMSSP_NEGOTIATE_OEM |
		                    NTLMSSP_NEGOTIATE_SIGN |
		                    NTLMSSP_NEGOTIATE_SEAL |
		                    NTLMSSP_NEGOTIATE_LM_KEY |
		                    NTLMSSP_NEGOTIATE_NTLM |
		                    NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
		                    NTLMSSP_NEGOTIATE_00001000 |
		                    NTLMSSP_NEGOTIATE_00002000);

	/* open SAMR session.  */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_unknown_38(smb_cli, fnum, srv_name) : False;

	/* establish a connection. */
	res = res ? samr_chgpasswd_user(smb_cli, fnum,
	                                   srv_name, smb_cli->user_name,
	                                   nt_newpass, nt_hshhash,
	                                   lm_newpass, lm_hshhash) : False;
	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res)
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
void cmd_sam_test(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid;
	BOOL res = True;

	sid_to_string(sid, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

/*
	if (strlen(sid) == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}
*/
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	report(out_hnd, "SAM Encryption Test\n");

	cli_nt_set_ntlmssp_flgs(smb_cli,
		                    NTLMSSP_NEGOTIATE_UNICODE |
		                    NTLMSSP_NEGOTIATE_OEM |
		                    NTLMSSP_NEGOTIATE_SIGN |
		                    NTLMSSP_NEGOTIATE_SEAL |
		                    NTLMSSP_NEGOTIATE_LM_KEY |
		                    NTLMSSP_NEGOTIATE_NTLM |
		                    NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
		                    NTLMSSP_NEGOTIATE_00001000 |
		                    NTLMSSP_NEGOTIATE_00002000);

	/* open SAMR session.  */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_unknown_38(smb_cli, fnum, srv_name) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

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
void cmd_sam_lookup_domain(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring str_sid;
	DOM_SID dom_sid;
	BOOL res = True;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (!next_token(NULL, domain, NULL, sizeof(domain)))
	{
		report(out_hnd, "lookupdomain: <name>\n");
		return;
	}

	report(out_hnd, "Lookup Domain in SAM Server\n");

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? samr_query_lookup_domain(smb_cli, fnum, 
	            &info->dom.samr_pol_connect, domain, &dom_sid) : False;

	res = res ? samr_close(smb_cli, fnum, &info->dom.samr_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

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
void cmd_sam_del_aliasmem(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring tmp;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND alias_pol;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	DOM_SID member_sid; 
	uint32 alias_rid;

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

	if (!next_token(NULL, tmp, NULL, sizeof(tmp)))
	{
		report(out_hnd, "delaliasmem: <alias rid> [member sid1] [member sid2] ...\n");
		return;
	}
	alias_rid = get_number(tmp);

	report(out_hnd, "SAM Domain Alias Member\n");

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &info->dom.samr_pol_connect, ace_perms, &sid1,
	            &info->dom.samr_pol_open_domain) : False;

	/* connect to the domain */
	res1 = res ? samr_open_alias(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain,
	            0x000f001f, alias_rid, &alias_pol) : False;

	while (next_token(NULL, tmp, NULL, sizeof(tmp)) && res2 && res1)
	{
		/* get a sid, delete a member from the alias */
		res2 = res2 ? string_to_sid(&member_sid, tmp) : False;
		res2 = res2 ? samr_del_aliasmem(smb_cli, fnum, &alias_pol, &member_sid) : False;

		if (res2)
		{
			report(out_hnd, "SID deleted from Alias 0x%x: %s\n", alias_rid, tmp);
		}
	}

	res1 = res1 ? samr_close(smb_cli, fnum, &alias_pol) : False;
	res  = res  ? samr_close(smb_cli, fnum, &info->dom.samr_pol_open_domain) : False;
	res  = res  ? samr_close(smb_cli, fnum, &info->dom.samr_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

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
void cmd_sam_delete_dom_alias(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring name;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND alias_pol;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 alias_rid = 0;
	const char *names[1];
	uint32 rid [MAX_LOOKUP_SIDS];
	uint32 type[MAX_LOOKUP_SIDS];
	uint32 num_rids;

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

	if (!next_token(NULL, name, NULL, sizeof(name)))
	{
		report(out_hnd, "delalias <alias name>\n");
		return;
	}

	report(out_hnd, "SAM Delete Domain Alias\n");

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &info->dom.samr_pol_connect, ace_perms, &sid1,
	            &info->dom.samr_pol_open_domain) : False;

	names[0] = name;

	res1 = res ? samr_query_lookup_names(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain, 0x000003e8,
	            1, names,
	            &num_rids, rid, type) : False;

	if (res1 && num_rids == 1)
	{
		alias_rid = rid[0];
	}

	/* connect to the domain */
	res1 = res1 ? samr_open_alias(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain,
	            0x000f001f, alias_rid, &alias_pol) : False;

	res2 = res1 ? samr_delete_dom_alias(smb_cli, fnum, &alias_pol) : False;

	res1 = res1 ? samr_close(smb_cli, fnum, &alias_pol) : False;
	res  = res  ? samr_close(smb_cli, fnum, &info->dom.samr_pol_open_domain) : False;
	res  = res  ? samr_close(smb_cli, fnum, &info->dom.samr_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

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
void cmd_sam_add_aliasmem(struct client_info *info)
{
	uint16 fnum;
	uint16 fnum_lsa;
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
	const char **names = NULL;
	int num_names = 0;
	DOM_SID *sids = NULL; 
	int num_sids = 0;
	int i;

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

	while (next_token(NULL, tmp, NULL, sizeof(tmp)))
	{
		num_names++;
		names = Realloc(names, num_names * sizeof(char*));
		if (names == NULL)
		{
			DEBUG(0,("Realloc returned NULL\n"));
			return;
		}
		names[num_names-1] = strdup(tmp);
	}

	if (num_names < 2)
	{
		report(out_hnd, "addaliasmem <group name> [member name1] [member name2] ...\n");
		return;
	}
	
	report(out_hnd, "SAM Domain Alias Member\n");

	/* open LSARPC session. */
	res3 = res3 ? cli_nt_session_open(smb_cli, PIPE_LSARPC, &fnum_lsa) : False;

	/* lookup domain controller; receive a policy handle */
	res3 = res3 ? lsa_open_policy(smb_cli, fnum_lsa,
				srv_name,
				&info->dom.lsa_info_pol, True) : False;

	/* send lsa lookup sids call */
	res4 = res3 ? lsa_lookup_names(smb_cli, fnum_lsa, 
				       &info->dom.lsa_info_pol,
				       num_names, names, 
				       &sids, NULL, &num_sids) : False;

	res3 = res3 ? lsa_close(smb_cli, fnum_lsa, &info->dom.lsa_info_pol) : False;

	cli_nt_session_close(smb_cli, fnum_lsa);

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

	/* open SAMR session.  negotiate credentials */
	res = res4 ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &info->dom.samr_pol_connect, ace_perms, &sid1,
	            &info->dom.samr_pol_open_domain) : False;

	/* connect to the domain */
	res1 = res ? samr_open_alias(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain,
	            0x000f001f, alias_rid, &alias_pol) : False;

	for (i = 1; i < num_sids && res2 && res1; i++)
	{
		/* add a member to the alias */
		res2 = res2 ? samr_add_aliasmem(smb_cli, fnum, &alias_pol, &sids[i]) : False;

		if (res2)
		{
			sid_to_string(tmp, &sids[i]);
			report(out_hnd, "SID added to Alias 0x%x: %s\n", alias_rid, tmp);
		}
	}

	res1 = res1 ? samr_close(smb_cli, fnum, &alias_pol) : False;
	res  = res  ? samr_close(smb_cli, fnum, &info->dom.samr_pol_open_domain) : False;
	res  = res  ? samr_close(smb_cli, fnum, &info->dom.samr_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (sids != NULL)
	{
		free(sids);
	}
	
	if (names != NULL)
	{
		for (i = 0; i < num_names; i++)
		{
			if (names[i] != NULL)
			{
				free(((char**)(names))[i]);
			}
		}
		free(names);
	}
	
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


/****************************************************************************
SAM create domain user.
****************************************************************************/
void cmd_sam_create_dom_user(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring acct_name;
	fstring acct_desc;
	fstring sid;
	DOM_SID sid1;
	BOOL res = True;
	BOOL res1 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 user_rid; 

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

	if (!next_token(NULL, acct_name, NULL, sizeof(acct_name)))
	{
		report(out_hnd, "createuser: <acct name> [acct description]\n");
	}

	if (!next_token(NULL, acct_desc, NULL, sizeof(acct_desc)))
	{
		acct_desc[0] = 0;
	}


	report(out_hnd, "SAM Create Domain User\n");
	report(out_hnd, "Domain: %s Name: %s Description: %s\n",
	                  domain, acct_name, acct_desc);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &info->dom.samr_pol_connect, ace_perms, &sid1,
	            &info->dom.samr_pol_open_domain) : False;

	/* create a domain user */
	res1 = res ? create_samr_domain_user(smb_cli, fnum, 
				&info->dom.samr_pol_open_domain,
	                        acct_name, ACB_NORMAL, &user_rid) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &info->dom.samr_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res && res1)
	{
		DEBUG(5,("cmd_sam_create_dom_user: succeeded\n"));
		report(out_hnd, "Create Domain User: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_create_dom_user: failed\n"));
		report(out_hnd, "Create Domain User: FAILED\n");
	}
}


/****************************************************************************
SAM create domain alias.
****************************************************************************/
void cmd_sam_create_dom_alias(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring acct_name;
	fstring acct_desc;
	fstring sid;
	DOM_SID sid1;
	BOOL res = True;
	BOOL res1 = True;
	uint32 ace_perms = 0x02000000; /* permissions */
	uint32 alias_rid; 

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

	if (!next_token(NULL, acct_name, NULL, sizeof(acct_name)))
	{
		report(out_hnd, "createalias: <acct name> [acct description]\n");
	}

	if (!next_token(NULL, acct_desc, NULL, sizeof(acct_desc)))
	{
		acct_desc[0] = 0;
	}


	report(out_hnd, "SAM Create Domain Alias\n");
	report(out_hnd, "Domain: %s Name: %s Description: %s\n",
	                  domain, acct_name, acct_desc);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &info->dom.samr_pol_connect, ace_perms, &sid1,
	            &info->dom.samr_pol_open_domain) : False;

	/* create a domain alias */
	res1 = res ? create_samr_domain_alias(smb_cli, fnum, 
				&info->dom.samr_pol_open_domain,
	                        acct_name, acct_desc, &alias_rid) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &info->dom.samr_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

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
void cmd_sam_del_groupmem(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring tmp;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND group_pol;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 member_rid; 
	uint32 group_rid;

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

	if (!next_token(NULL, tmp, NULL, sizeof(tmp)))
	{
		report(out_hnd, "delgroupmem: <group rid> [member rid1] [member rid2] ...\n");
		return;
	}
	group_rid = get_number(tmp);

	report(out_hnd, "SAM Add Domain Group member\n");

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &info->dom.samr_pol_connect, ace_perms, &sid1,
	            &info->dom.samr_pol_open_domain) : False;

	/* connect to the domain */
	res1 = res ? samr_open_group(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain,
	            0x0000001f, group_rid, &group_pol) : False;

	while (next_token(NULL, tmp, NULL, sizeof(tmp)) && res2 && res1)
	{
		/* get a rid, delete a member from the group */
		member_rid = get_number(tmp);
		res2 = res2 ? samr_del_groupmem(smb_cli, fnum, &group_pol, member_rid) : False;

		if (res2)
		{
			report(out_hnd, "RID deleted from Group 0x%x: 0x%x\n", group_rid, member_rid);
		}
	}

	res1 = res1 ? samr_close(smb_cli, fnum, &group_pol) : False;
	res  = res  ? samr_close(smb_cli, fnum, &info->dom.samr_pol_open_domain) : False;
	res  = res  ? samr_close(smb_cli, fnum, &info->dom.samr_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

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
void cmd_sam_delete_dom_group(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring name;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND group_pol;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 group_rid = 0;
	const char *names[1];
	uint32 rid [MAX_LOOKUP_SIDS];
	uint32 type[MAX_LOOKUP_SIDS];
	uint32 num_rids;

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

	if (!next_token(NULL, name, NULL, sizeof(name)))
	{
		report(out_hnd, "delgroup <group name>\n");
		return;
	}

	report(out_hnd, "SAM Delete Domain Group\n");

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &info->dom.samr_pol_connect, ace_perms, &sid1,
	            &info->dom.samr_pol_open_domain) : False;

	names[0] = name;

	res1 = res ? samr_query_lookup_names(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain, 0x000003e8,
	            1, names,
	            &num_rids, rid, type) : False;

	if (res1 && num_rids == 1)
	{
		group_rid = rid[0];
	}

	/* connect to the domain */
	res1 = res1 ? samr_open_group(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain,
	            0x0000001f, group_rid, &group_pol) : False;

	res2 = res1 ? samr_delete_dom_group(smb_cli, fnum, &group_pol) : False;

	res1 = res1 ? samr_close(smb_cli, fnum, &group_pol) : False;
	res  = res  ? samr_close(smb_cli, fnum, &info->dom.samr_pol_open_domain) : False;
	res  = res  ? samr_close(smb_cli, fnum, &info->dom.samr_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

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
void cmd_sam_add_groupmem(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring tmp;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND group_pol;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 group_rid = 0;
	uint32 group_type = SID_NAME_UNKNOWN;
	const char **names = NULL;
	uint32 num_names = 0;
	fstring group_name;
	const char *group_names[1];
	uint32 rid [MAX_LOOKUP_SIDS];
	uint32 type[MAX_LOOKUP_SIDS];
	uint32 num_rids;
	uint32 num_group_rids;
	int i;
	DOM_SID sid_1_5_20;
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

	res = next_token(NULL, group_name, NULL, sizeof(group_name));
	group_names[0] = group_name;

	while (res && next_token(NULL, tmp, NULL, sizeof(tmp)))
	{
		num_names++;
		names = Realloc(names, num_names * sizeof(char*));
		if (names == NULL)
		{
			DEBUG(0,("Realloc returned NULL\n"));
			return;
		}
		names[num_names-1] = strdup(tmp);
	}

	if (num_names < 1)
	{
		report(out_hnd, "addgroupmem <group name> [member name1] [member name2] ...\n");
		return;
	}
	
	report(out_hnd, "SAM Add Domain Group member\n");

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res1 = res ? samr_open_domain(smb_cli, fnum, 
	            &info->dom.samr_pol_connect, ace_perms, &sid1,
	            &info->dom.samr_pol_open_domain) : False;

	/* connect to the domain */
	res1 = res1 ? samr_open_domain(smb_cli, fnum, 
	            &info->dom.samr_pol_connect, ace_perms, &sid_1_5_20,
	            &info->dom.samr_pol_open_builtindom) : False;

	res2 = res1 ? samr_query_lookup_names(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain, 0x000003e8,
	            1, group_names,
	            &num_group_rids, &group_rid, &group_type) : False;

	/* open the group */
	res2 = res2 ? samr_open_group(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain,
	            0x0000001f, group_rid, &group_pol) : False;

	if (!res2 || group_type == SID_NAME_UNKNOWN)
	{
		res2 = res1 ? samr_query_lookup_names(smb_cli, fnum,
			    &info->dom.samr_pol_open_builtindom, 0x000003e8,
			    1, group_names, 
			    &num_group_rids, &group_rid, &group_type) : False;

		/* open the group */
		res2 = res2 ? samr_open_group(smb_cli, fnum,
			    &info->dom.samr_pol_open_builtindom,
			    0x0000001f, group_rid, &group_pol) : False;
	}

	if (group_type == SID_NAME_ALIAS)
	{
		report(out_hnd, "%s is a local alias, not a group.  Use addaliasmem command instead\n",
			group_name);
		return;
	}
	res1 = res2 ? samr_query_lookup_names(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain, 0x000003e8,
	            num_names, names,
	            &num_rids, rid, type) : False;

	for (i = 0; i < num_rids && res2 && res1; i++)
	{
		res2 = res2 ? samr_add_groupmem(smb_cli, fnum, &group_pol, rid[i]) : False;

		if (res2)
		{
			report(out_hnd, "RID added to Group 0x%x: 0x%x\n", group_rid, rid[i]);
		}
	}

	res1 = res ? samr_close(smb_cli, fnum, &group_pol) : False;
	res1 = res ? samr_close(smb_cli, fnum, &info->dom.samr_pol_open_builtindom) : False;
	res1 = res ? samr_close(smb_cli, fnum, &info->dom.samr_pol_open_domain) : False;
	res  = res ? samr_close(smb_cli, fnum, &info->dom.samr_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (names != NULL)
	{
		for (i = 0; i < num_names; i++)
		{
			if (names[i] != NULL)
			{
				free(((char**)(names))[i]);
			}
		}
		free(names);
	}
	
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
}


/****************************************************************************
SAM create domain group.
****************************************************************************/
void cmd_sam_create_dom_group(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring acct_name;
	fstring acct_desc;
	fstring sid;
	DOM_SID sid1;
	BOOL res = True;
	BOOL res1 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 group_rid; 

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

	if (!next_token(NULL, acct_name, NULL, sizeof(acct_name)))
	{
		report(out_hnd, "creategroup: <acct name> [acct description]\n");
	}

	if (!next_token(NULL, acct_desc, NULL, sizeof(acct_desc)))
	{
		acct_desc[0] = 0;
	}


	report(out_hnd, "SAM Create Domain Group\n");
	report(out_hnd, "Domain: %s Name: %s Description: %s\n",
	                  domain, acct_name, acct_desc);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &info->dom.samr_pol_connect, ace_perms, &sid1,
	            &info->dom.samr_pol_open_domain) : False;

	/* read some users */
	res1 = res ? create_samr_domain_group(smb_cli, fnum, 
				&info->dom.samr_pol_open_domain,
	                        acct_name, acct_desc, &group_rid) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &info->dom.samr_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

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

static void req_user_info(struct client_info *info, uint16 fnum,
				uint32 user_rid)
{
	SAM_USER_INFO_21 usr;
	/* send user info query, level 0x15 */
	if (get_samr_query_userinfo(smb_cli, fnum,
				    &info->dom.samr_pol_open_domain,
				    0x15, user_rid, &usr))
	{
		display_sam_user_info_21(out_hnd, ACTION_HEADER   , &usr);
		display_sam_user_info_21(out_hnd, ACTION_ENUMERATE, &usr);
		display_sam_user_info_21(out_hnd, ACTION_FOOTER   , &usr);
	}
}

static void query_groupinfo(struct client_info *info, uint16 fnum,
				uint32 group_rid)
{
	GROUP_INFO_CTR ctr;

	/* send group info query */
	if (get_samr_query_groupinfo(smb_cli, fnum,
				      &info->dom.samr_pol_open_domain,
				      1, group_rid, &ctr))
	{
#if 0
		display_samr_groupinfo(out_hnd, ACTION_HEADER   , &ctr);
		display_samr_groupinfo(out_hnd, ACTION_ENUMERATE, &ctr);
		display_samr_groupinfo(out_hnd, ACTION_FOOTER   , &ctr);
#endif
	}
}

static void req_group_info(struct client_info *info, uint16 fnum,
				uint32 user_rid)
{
	uint32 num_groups;
	DOM_GID gid[LSA_MAX_GROUPS];

	/* send user group query */
	if (get_samr_query_usergroups(smb_cli, fnum,
				      &info->dom.samr_pol_open_domain,
				      user_rid, &num_groups, gid))
	{
		int i;
		uint32 num_names;
		uint32  rid_mem[MAX_LOOKUP_SIDS];
		fstring name   [MAX_LOOKUP_SIDS];
		uint32  type   [MAX_LOOKUP_SIDS];

		for (i = 0; i < num_groups; i++)
		{
			rid_mem[i] = gid[i].g_rid;
		}

		if (samr_query_lookup_rids(smb_cli, fnum, 
				&info->dom.samr_pol_open_domain, 0x3e8,
				num_groups, rid_mem, 
				&num_names, name, type))
		{
			display_group_members(out_hnd, ACTION_HEADER   , num_names, name, type);
			display_group_members(out_hnd, ACTION_ENUMERATE, num_names, name, type);
			display_group_members(out_hnd, ACTION_FOOTER   , num_names, name, type);
		}
	}
}

static void req_alias_info(struct client_info *info, uint16 fnum,
				DOM_SID *sid1, uint32 user_rid)
{
	uint32 num_aliases;
	uint32 rid[LSA_MAX_GROUPS];
	DOM_SID als_sid;

	sid_copy(&als_sid, sid1);
	sid_append_rid(&als_sid, user_rid);

	/* send user alias query */
	if (samr_query_useraliases(smb_cli, fnum,
				&info->dom.samr_pol_open_domain,
				&als_sid, &num_aliases, rid))
	{
		uint32 num_names;
		fstring name   [MAX_LOOKUP_SIDS];
		uint32  type   [MAX_LOOKUP_SIDS];

		if (samr_query_lookup_rids(smb_cli, fnum, 
				&info->dom.samr_pol_open_domain, 0x3e8,
				num_aliases, rid, 
				&num_names, name, type))
		{
			display_group_members(out_hnd, ACTION_HEADER   , num_names, name, type);
			display_group_members(out_hnd, ACTION_ENUMERATE, num_names, name, type);
			display_group_members(out_hnd, ACTION_FOOTER   , num_names, name, type);
		}
	}

	/* send user alias query */
	if (samr_query_useraliases(smb_cli, fnum,
				&info->dom.samr_pol_open_builtindom,
				&als_sid, &num_aliases, rid))
	{
		uint32 num_names;
		fstring name   [MAX_LOOKUP_SIDS];
		uint32  type   [MAX_LOOKUP_SIDS];

		if (samr_query_lookup_rids(smb_cli, fnum, 
				&info->dom.samr_pol_open_builtindom, 0x3e8,
				num_aliases, rid, 
				&num_names, name, type))
		{
			display_group_members(out_hnd, ACTION_HEADER   , num_names, name, type);
			display_group_members(out_hnd, ACTION_ENUMERATE, num_names, name, type);
			display_group_members(out_hnd, ACTION_FOOTER   , num_names, name, type);
		}
	}
}

/****************************************************************************
experimental SAM users enum.
****************************************************************************/
int msrpc_sam_enum_users(struct client_info *info,
			BOOL request_user_info,
			BOOL request_group_info,
			BOOL request_alias_info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	DOM_SID sid_1_5_20;
	int user_idx;
	BOOL res = True;
	BOOL res1 = True;
	uint16 start_idx = 0x0;
	uint16 unk_0 = 0x0;
	uint16 acb_mask = 0;
	uint16 unk_1 = 0x0;
	uint32 ace_perms = 0x304; /* access control permissions */

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	info->dom.sam = NULL;
	info->dom.num_sam_entries = 0;

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return 0;
	}


	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	string_to_sid(&sid_1_5_20, "S-1-5-32");

	report(out_hnd, "SAM Enumerate Users\n");
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid);

	DEBUG(5,("Number of entries:%d unk_0:%04x acb_mask:%04x unk_1:%04x\n",
	          start_idx, unk_0, acb_mask, unk_1));

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &info->dom.samr_pol_connect, ace_perms, &sid1,
	            &info->dom.samr_pol_open_domain) : False;

	/* connect to the S-1-5-20 domain */
	res1 = res ? samr_open_domain(smb_cli, fnum, 
	            &info->dom.samr_pol_connect, ace_perms, &sid_1_5_20,
	            &info->dom.samr_pol_open_builtindom) : False;

	/* read some users */
	res = res ? samr_enum_dom_users(smb_cli, fnum, 
	             &info->dom.samr_pol_open_domain,
	             start_idx, acb_mask, unk_1, 0x8000,
	             &info->dom.sam, &info->dom.num_sam_entries) : False;

	if (res && info->dom.num_sam_entries == 0)
	{
		report(out_hnd, "No users\n");
	}

	if (res)
	{
		/* query all the users */
		for (user_idx = 0; res && user_idx <
		              info->dom.num_sam_entries; user_idx++)
		{
			uint32 user_rid = info->dom.sam[user_idx].rid;

			report(out_hnd, "User RID: %8x  User Name: %s\n",
			        user_rid,
			        info->dom.sam[user_idx].acct_name);

			if (request_group_info)
			{
				req_group_info(info, fnum, user_rid);
			}

			if (request_user_info)
			{
				req_user_info(info, fnum, user_rid);
			}

			if (request_alias_info)
			{
				req_alias_info(info, fnum, &sid1, user_rid);
			}
		}
	}

	res1 = res1 ? samr_close(smb_cli, fnum,
	            &info->dom.samr_pol_open_builtindom) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &info->dom.samr_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res)
	{
		DEBUG(5,("msrpc_sam_enum_users: succeeded\n"));
	}
	else
	{
		DEBUG(5,("msrpc_sam_enum_users: failed\n"));
	}

	return info->dom.num_sam_entries;
}


/****************************************************************************
experimental SAM users enum.
****************************************************************************/
void cmd_sam_enum_users(struct client_info *info)
{
	BOOL request_user_info  = False;
	BOOL request_group_info = False;
	BOOL request_alias_info = False;
	fstring tmp;
	int i;

	for (i = 0; i < 3; i++)
	{
		/* a bad way to do token parsing... */
		if (next_token(NULL, tmp, NULL, sizeof(tmp)))
		{
			request_user_info  |= strequal(tmp, "-u");
			request_group_info |= strequal(tmp, "-g");
			request_alias_info |= strequal(tmp, "-a");
		}
		else
		{
			break;
		}
	}

	msrpc_sam_enum_users(info,
	                     request_user_info,
	                     request_group_info,
	                     request_alias_info);

	if (info->dom.sam != NULL)
	{
		free(info->dom.sam);
	}
}


/****************************************************************************
experimental SAM user query.
****************************************************************************/
void cmd_sam_query_user(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;

	fstring user_name;
	const char *names[1];
	uint32 num_rids;
	uint32 rid[MAX_LOOKUP_SIDS];
	uint32 type[MAX_LOOKUP_SIDS];
	uint32 info_level = 0x15;
	SAM_USER_INFO_21 usr;

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	if (!next_token(NULL, user_name, NULL, sizeof(user_name)))
	{
		report(out_hnd, "samuser <name>\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query User: %s\n", user_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid_str);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum,
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum,
	            &info->dom.samr_pol_connect, 0x304, &sid,
	            &info->dom.samr_pol_open_domain) : False;

	/* look up user rid */
	names[0] = user_name;
	res1 = res ? samr_query_lookup_names(smb_cli, fnum,
					&info->dom.samr_pol_open_domain, 0x3e8,
					1, names,
					&num_rids, rid, type) : False;

	/* send user info query */
	res1 = (res1 && num_rids == 1) ? get_samr_query_userinfo(smb_cli, fnum,
					 &info->dom.samr_pol_open_domain,
					 info_level, rid[0], &usr) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &info->dom.samr_pol_connect) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res1)
	{
		display_sam_user_info_21(out_hnd, ACTION_HEADER   , &usr);
		display_sam_user_info_21(out_hnd, ACTION_ENUMERATE, &usr);
		display_sam_user_info_21(out_hnd, ACTION_FOOTER   , &usr);

		DEBUG(5,("cmd_sam_query_user: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_query_user: failed\n"));
	}
}


/****************************************************************************
experimental SAM query display info.
****************************************************************************/
void cmd_sam_query_dispinfo(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	BOOL res = True;
	fstring info_str;
	uint16 switch_value = 1;
	uint32 ace_perms = 0x304; /* absolutely no idea. */
	SAM_DISPINFO_CTR ctr;
	SAM_DISPINFO_1 inf1;
	uint32 num_entries;

	sid_to_string(sid, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

	if (strlen(sid) == 0)
	{
		fprintf(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	string_to_sid(&sid1, sid);

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (next_token(NULL, info_str, NULL, sizeof(info_str)))
	{
		switch_value = strtoul(info_str, (char**)NULL, 10);
	}

	fprintf(out_hnd, "SAM Query Domain Info: info level %d\n", switch_value);
	fprintf(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &info->dom.samr_pol_connect, ace_perms, &sid1,
	            &info->dom.samr_pol_open_domain) : False;

	ctr.sam.info1 = &inf1;

	/* send a samr query_disp_info command */
	res = res ? samr_query_dispinfo(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain, switch_value, 
		    &num_entries, &ctr) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &info->dom.samr_pol_connect) : False;

	res = res ? samr_close(smb_cli, fnum, 
	            &info->dom.samr_pol_open_domain) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res)
	{
		DEBUG(5,("cmd_sam_query_dispinfo: succeeded\n"));
#if 0
		display_sam_disp_info_ctr(out_hnd, ACTION_HEADER   , switch_value, &ctr);
		display_sam_disp_info_ctr(out_hnd, ACTION_ENUMERATE, switch_value, &ctr);
		display_sam_disp_info_ctr(out_hnd, ACTION_FOOTER   , switch_value, &ctr);
#endif
	}
	else
	{
		DEBUG(5,("cmd_sam_query_dispinfo: failed\n"));
	}
}


/****************************************************************************
experimental SAM domain info query.
****************************************************************************/
BOOL sam_query_dominfo(struct client_info *info, DOM_SID *sid1,
				uint32 switch_value, SAM_UNK_CTR *ctr)
{
	uint16 fnum;
	fstring srv_name;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res1 = res ? samr_open_domain(smb_cli, fnum, 
	            &info->dom.samr_pol_connect, ace_perms, sid1,
	            &info->dom.samr_pol_open_domain) : False;

	/* send a samr 0x8 command */
	res2 = res ? samr_query_dom_info(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain, switch_value, ctr) : False;

	res1 = res1 ? samr_close(smb_cli, fnum,
	            &info->dom.samr_pol_connect) : False;

	res = res ? samr_close(smb_cli, fnum, 
	            &info->dom.samr_pol_open_domain) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res2)
	{
		DEBUG(5,("sam_query_dominfo: succeeded\n"));
	}
	else
	{
		DEBUG(5,("sam_query_dominfo: failed\n"));
	}

	return res2;
}


/****************************************************************************
experimental SAM domain info query.
****************************************************************************/
void cmd_sam_query_dominfo(struct client_info *info)
{
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	fstring info_str;
	uint32 switch_value = 2;
	SAM_UNK_CTR ctr;

	sid_to_string(sid, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

	if (strlen(sid) == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	string_to_sid(&sid1, sid);

	if (next_token(NULL, info_str, NULL, sizeof(info_str)))
	{
		switch_value = strtoul(info_str, (char**)NULL, 10);
	}

	report(out_hnd, "SAM Query Domain Info: info level %d\n", switch_value);
	report(out_hnd, "From: %s Domain: %s SID: %s\n",
	                  info->myhostname, domain, sid);

	if (sam_query_dominfo(info, &sid1, switch_value, &ctr))
	{
		DEBUG(5,("cmd_sam_query_dominfo: succeeded\n"));
		display_sam_unk_ctr(out_hnd, ACTION_HEADER   , switch_value, &ctr);
		display_sam_unk_ctr(out_hnd, ACTION_ENUMERATE, switch_value, &ctr);
		display_sam_unk_ctr(out_hnd, ACTION_FOOTER   , switch_value, &ctr);
	}
	else
	{
		DEBUG(5,("cmd_sam_query_dominfo: failed\n"));
	}
}


/****************************************************************************
SAM aliases query.
****************************************************************************/
void cmd_sam_enum_aliases(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	BOOL res = True;
	BOOL request_member_info = False;
	uint32 ace_perms = 0x02000000; /* access control permissions */
	fstring tmp;
	uint32 alias_idx;

	sid_to_string(sid, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);
#if 0
	fstrcpy(sid   , "S-1-5-20");
#endif
	if (strlen(sid) == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	string_to_sid(&sid1, sid);

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	/* a bad way to do token parsing... */
	if (next_token(NULL, tmp, NULL, sizeof(tmp)))
	{
		request_member_info |= strequal(tmp, "-m");
	}

	report(out_hnd, "SAM Enumerate Aliases\n");
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum,
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum,
	            &info->dom.samr_pol_connect, ace_perms, &sid1,
	            &info->dom.samr_pol_open_domain) : False;

	info->dom.sam = NULL;

	/* read some aliases */
	res = res ? samr_enum_dom_aliases(smb_cli, fnum,
	                        &info->dom.samr_pol_open_domain,
	                        0xffff,
	                        &info->dom.sam, &info->dom.num_sam_entries) : False;

	if (res && info->dom.num_sam_entries == 0)
	{
		report(out_hnd, "No aliases\n");
	}

	if (res)
	{
	for (alias_idx = 0; alias_idx < info->dom.num_sam_entries; alias_idx++)
	{
		uint32 alias_rid = info->dom.sam[alias_idx].rid;

		report(out_hnd, "Alias RID: %8x  Group Name: %s\n",
				  alias_rid,
				  info->dom.sam[alias_idx].acct_name);

		if (request_member_info)
		{
			uint32 num_aliases;
			DOM_SID2 sid_mem[MAX_LOOKUP_SIDS];

			/* send user aliases query */
			if (get_samr_query_aliasmem(smb_cli, fnum, 
				&info->dom.samr_pol_open_domain,
						alias_rid, &num_aliases, sid_mem))
			{
				uint16 fnum_lsa;
				BOOL res3 = True;
				BOOL res4 = True;
				char **names = NULL;
				int num_names = 0;
				DOM_SID **sids = NULL;
				int i;

				if (num_aliases != 0)
				{
					sids = malloc(num_aliases * sizeof(DOM_SID*));
				}

				res3 = sids != NULL;
				if (res3)
				{
					for (i = 0; i < num_aliases; i++)
					{
						sids[i] = &sid_mem[i].sid;
					}
				}

				/* open LSARPC session. */
				res3 = res3 ? cli_nt_session_open(smb_cli, PIPE_LSARPC, &fnum_lsa) : False;

				/* lookup domain controller; receive a policy handle */
				res3 = res3 ? lsa_open_policy(smb_cli, fnum_lsa,
							srv_name,
							&info->dom.lsa_info_pol, True) : False;

				/* send lsa lookup sids call */
				res4 = res3 ? lsa_lookup_sids(smb_cli, fnum_lsa, 
							       &info->dom.lsa_info_pol,
				                               num_aliases, sids, 
				                               &names, NULL, &num_names) : False;

				res3 = res3 ? lsa_close(smb_cli, fnum_lsa, &info->dom.lsa_info_pol) : False;

				cli_nt_session_close(smb_cli, fnum_lsa);

				if (res4 && names != NULL)
				{
					display_alias_members(out_hnd, ACTION_HEADER   , num_names, names);
					display_alias_members(out_hnd, ACTION_ENUMERATE, num_names, names);
					display_alias_members(out_hnd, ACTION_FOOTER   , num_names, names);
				}
				if (names != NULL)
				{
					for (i = 0; i < num_names; i++)
					{
						if (names[i] != NULL)
						{
							free(names[i]);
						}
					}
					free(names);
				}
				if (sids != NULL)
				{
					free(sids);
				}
			}
		}
	}
	}

	res = res ? samr_close(smb_cli, fnum, 
	            &info->dom.samr_pol_connect) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (info->dom.sam != NULL)
	{
		free(info->dom.sam);
	}

	if (res)
	{
		DEBUG(5,("cmd_sam_enum_aliases: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_enum_aliases: failed\n"));
	}
}

static void req_groupmem_info(struct client_info *info, uint16 fnum,
				uint32 group_rid)
{
	uint32 num_mem;
	uint32 rid_mem[MAX_LOOKUP_SIDS];
	uint32 attr_mem[MAX_LOOKUP_SIDS];

	/* get group members */
	if (get_samr_query_groupmem(smb_cli, fnum, 
		&info->dom.samr_pol_open_domain,
		group_rid, &num_mem, rid_mem, attr_mem))
	{
		BOOL res3 = True;
		int num_names = 0;
		fstring names[MAX_LOOKUP_SIDS];
		uint32 types[MAX_LOOKUP_SIDS];

		res3 = samr_query_lookup_rids(smb_cli, fnum,
		                   &info->dom.samr_pol_open_domain, 1000,
		                   num_mem, rid_mem, &num_names, names, types);

		if (res3)
		{
			display_group_members(out_hnd, ACTION_HEADER   , num_names, names, types);
			display_group_members(out_hnd, ACTION_ENUMERATE, num_names, names, types);
			display_group_members(out_hnd, ACTION_FOOTER   , num_names, names, types);
		}
	}
}

/****************************************************************************
SAM groups query.
****************************************************************************/
void cmd_sam_enum_groups(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	BOOL res = True;
	BOOL request_member_info = False;
	BOOL request_group_info = False;
	uint32 ace_perms = 0x02000000; /* access control permissions. */
	fstring tmp;
	uint32 group_idx;
	int i;

	sid_copy(&sid1, &info->dom.level5_sid);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level3_dom);

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	/* a bad way to do token parsing... */
	for (i = 0; i < 2; i++)
	{
		/* a bad way to do token parsing... */
		if (next_token(NULL, tmp, NULL, sizeof(tmp)))
		{
			request_member_info |= strequal(tmp, "-m");
			request_group_info  |= strequal(tmp, "-g");
		}
		else
		{
			break;
		}
	}

	report(out_hnd, "SAM Enumerate Groups\n");
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum,
				srv_name, 0x02000000,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum,
	            &info->dom.samr_pol_connect, ace_perms, &sid1,
	            &info->dom.samr_pol_open_domain) : False;

	info->dom.sam = NULL;

	/* read some groups */
	res = res ? samr_enum_dom_groups(smb_cli, fnum,
	                        &info->dom.samr_pol_open_domain,
	                        0xffff,
	                        &info->dom.sam, &info->dom.num_sam_entries) : False;

	if (res && info->dom.num_sam_entries == 0)
	{
		report(out_hnd, "No groups\n");
	}

	if (res)
	{
		for (group_idx = 0; group_idx < info->dom.num_sam_entries; group_idx++)
		{
			uint32 group_rid = info->dom.sam[group_idx].rid;

			report(out_hnd, "Group RID: %8x  Group Name: %s\n",
					  group_rid,
					  info->dom.sam[group_idx].acct_name);

			if (request_group_info)
			{
				query_groupinfo(info, fnum, group_rid);
			}
			if (request_member_info)
			{
				req_groupmem_info(info, fnum, group_rid);
			}
		}
	}

	res = res ? samr_close(smb_cli, fnum,
	            &info->dom.samr_pol_open_domain) : False;

	res = res ? samr_close(smb_cli, fnum, 
	            &info->dom.samr_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (info->dom.sam != NULL)
	{
		free(info->dom.sam);
	}

	if (res)
	{
		DEBUG(5,("cmd_sam_enum_groups: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_enum_groups: failed\n"));
	}
}
