#define NEW_NTDOMAIN 1
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Paul Ashton                  1997-2000,
 *  Copyright (C) Elrond                            2000
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <includes.h>

/*******************************************************************
makes a SAMR_Q_CONNECT structure.
********************************************************************/
BOOL init_samr_q_connect(SAMR_Q_CONNECT * q_u, char *srv_name, 
			 uint32 access_mask)
{
	int len_srv_name = strlen(srv_name);

	DEBUG(5, ("init_samr_q_connect\n"));

	/* make PDC server name \\server */

	q_u->ptr_srv_name = len_srv_name ? 1 : 0;
	init_unistr2(&q_u->uni_srv_name, srv_name, len_srv_name + 1);

	/* example values: 0x0000 0002 */

	q_u->access_mask = access_mask;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_connect(char *desc, SAMR_Q_CONNECT * q_u, prs_struct *ps, 
		       int depth)
{
	prs_debug(ps, depth, desc, "samr_io_q_connect");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name", ps, depth, &q_u->ptr_srv_name);
	smb_io_unistr2("", &q_u->uni_srv_name, q_u->ptr_srv_name, ps,
		       depth);

	prs_align(ps);

	prs_uint32("access_mask", ps, depth, &q_u->access_mask);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_connect(char *desc, SAMR_R_CONNECT * r_u, prs_struct *ps, 
		       int depth)
{
	prs_debug(ps, depth, desc, "samr_io_r_connect");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("connect_pol", &r_u->connect_pol, ps, depth);
	prs_uint32("status", ps, depth, &r_u->status);

	return True;
}

/*******************************************************************
makes a SAMR_Q_CLOSE_HND structure.
********************************************************************/
BOOL init_samr_q_close_hnd(SAMR_Q_CLOSE_HND * q_c, POLICY_HND *hnd)
{
	DEBUG(5, ("init_samr_q_close_hnd\n"));

	q_c->pol = *hnd;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_close_hnd(char *desc, SAMR_Q_CLOSE_HND * q_u,
			 prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_q_close_hnd");
	depth++;

	prs_align(ps);

	return smb_io_pol_hnd("pol", &q_u->pol, ps, depth);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_close_hnd(char *desc, SAMR_R_CLOSE_HND * r_u,
			 prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_r_close_hnd");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &r_u->pol, ps, depth);
	prs_uint32("status", ps, depth, &r_u->status);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL init_samr_q_open_domain(SAMR_Q_OPEN_DOMAIN * q_u, 
			     POLICY_HND *connect_pol, uint32 access_mask,
			     DOM_SID *sid)
{
	DEBUG(5, ("init_samr_q_open_domain\n"));

	q_u->connect_pol = *connect_pol;
	q_u->access_mask = access_mask;

	init_dom_sid2(&q_u->dom_sid, sid);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_open_domain(char *desc, SAMR_Q_OPEN_DOMAIN * q_u,
			   prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_q_open_domain");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("connect_pol", &q_u->connect_pol, ps, depth);

	prs_uint32("access_mask", ps, depth, &q_u->access_mask);

	smb_io_dom_sid2("sid", &q_u->dom_sid, ps, depth);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_open_domain(char *desc, SAMR_R_OPEN_DOMAIN * r_u,
			   prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_r_open_domain");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("domain_pol", &r_u->domain_pol, ps, depth);

	prs_uint32("status", ps, depth, &r_u->status);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL init_samr_q_open_user(SAMR_Q_OPEN_USER * q_u, POLICY_HND *pol,
			   uint32 access_mask, uint32 rid)
{
	DEBUG(5, ("init_samr_q_open_user\n"));

	q_u->domain_pol = *pol;
	q_u->access_mask = access_mask;
	q_u->user_rid = rid;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_open_user(char *desc, SAMR_Q_OPEN_USER * q_u,
			 prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_q_open_user");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("domain_pol", &q_u->domain_pol, ps, depth);

	prs_uint32("access_mask", ps, depth, &q_u->access_mask);
	prs_uint32("user_rid ", ps, depth, &q_u->user_rid);

	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_open_user(char *desc, SAMR_R_OPEN_USER * r_u,
			 prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_r_open_user");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("user_pol", &r_u->user_pol, ps, depth);

	prs_uint32("status", ps, depth, &r_u->status);

	return True;
}

/*******************************************************************
makes a SAMR_Q_QUERY_USERINFO structure.
********************************************************************/
BOOL init_samr_q_query_userinfo(SAMR_Q_QUERY_USERINFO * q_u,
				POLICY_HND *hnd, uint16 switch_value)
{
	DEBUG(5, ("init_samr_q_query_userinfo\n"));

	q_u->pol = *hnd;
	q_u->switch_value = switch_value;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_query_userinfo(char *desc, SAMR_Q_QUERY_USERINFO * q_u,
			      prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_q_query_userinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &q_u->pol, ps, depth);

	prs_uint16("switch_value", ps, depth, &q_u->switch_value);	/* 0x0015 or 0x0011 */

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_query_userinfo(char *desc, SAMR_R_QUERY_USERINFO * r_u,
			      prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_r_query_userinfo");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &r_u->ptr);

	if (r_u->ptr != 0) {
		samr_io_userinfo_ctr("ctr", r_u->ctr, ps, depth);
	}

	prs_uint32("status", ps, depth, &r_u->status);

	if (!ps->io) {
		/* writing */
		if (r_u->ctr != NULL) {
			free_samr_userinfo_ctr(r_u->ctr);
		}
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_userinfo_ctr(char *desc, SAM_USERINFO_CTR * ctr,
				 prs_struct *ps, int depth)
{
	BOOL ret;

	prs_debug(ps, depth, desc, "samr_io_userinfo_ctr");
	depth++;

	/* lkclXXXX DO NOT ALIGN BEFORE READING SWITCH VALUE! */

	prs_uint16("switch_value", ps, depth, &(ctr->switch_value));
	prs_align(ps);

	ret = False;

	switch (ctr->switch_value)
	{
		case 0x10:
		{
			if (UNMARSHALLING(ps))
			{
				/* reading */
				ctr->info.id10 = (SAM_USER_INFO_10 *)
					malloc(sizeof(SAM_USER_INFO_10));
			}
			if (ctr->info.id10 == NULL)
			{
				DEBUG(2,
				      ("samr_io_userinfo_ctr: info pointer not initialised\n"));
				return False;
			}
			ret = sam_io_user_info10("", ctr->info.id10, ps,
						 depth);
			break;
		}
		case 0x11:
		{
			if (UNMARSHALLING(ps))
			{
				/* reading */
				ctr->info.id11 = (SAM_USER_INFO_11 *)
					malloc(sizeof(SAM_USER_INFO_11));
			}
			if (ctr->info.id11 == NULL)
			{
				DEBUG(2,
				      ("samr_io_userinfo_ctr: info pointer not initialised\n"));
				return False;
			}
			ret = sam_io_user_info11("", ctr->info.id11, ps,
						 depth);
			break;
		}
		case 0x12:
		{
			if (UNMARSHALLING(ps))
			{
				/* reading */
				ctr->info.id12 = (SAM_USER_INFO_12 *)
					malloc(sizeof(SAM_USER_INFO_12));
			}
			if (ctr->info.id12 == NULL)
			{
				DEBUG(2,
				      ("samr_io_userinfo_ctr: info pointer not initialised\n"));
				return False;
			}
			ret = sam_io_user_info12("", ctr->info.id12, ps,
						 depth);
			break;
		}
		case 21:
		{
#if 0
			if (UNMARSHALLING(ps))
			{
				/* reading */
				ctr->info.id21 = (SAM_USER_INFO_21 *)
					malloc(sizeof(SAM_USER_INFO_21));
			}
#endif
			if (ctr->info.id21 == NULL)
			{
				DEBUG(2,
				      ("samr_io_userinfo_ctr: info pointer not initialised\n"));
				return False;
			}
			ret = sam_io_user_info21("", ctr->info.id21, ps,
						 depth);
			break;
		}
		case 23:
		{
			if (UNMARSHALLING(ps))
			{
				/* reading */
				ctr->info.id23 = (SAM_USER_INFO_23 *)
					malloc(sizeof(SAM_USER_INFO_23));
			}
			if (ctr->info.id23 == NULL)
			{
				DEBUG(2,
				      ("samr_io_userinfo_ctr: info pointer not initialised\n"));
				return False;
			}
			ret = sam_io_user_info23("", ctr->info.id23, ps,
						 depth);
			break;
		}
		case 24:
		{
			if (UNMARSHALLING(ps))
			{
				/* reading */
				ctr->info.id24 = (SAM_USER_INFO_24 *)
					malloc(sizeof(SAM_USER_INFO_24));
			}
			if (ctr->info.id24 == NULL)
			{
				DEBUG(2,
				      ("samr_io_userinfo_ctr: info pointer not initialised\n"));
				return False;
			}
			ret = sam_io_user_info24("", ctr->info.id24, ps,
						 depth);
			break;
		}
		default:
		{
			DEBUG(2, ("samr_io_userinfo_ctr: unknown switch "
				  "level 0x%x\n", ctr->switch_value));
			ret = False;
			break;
		}

	}

	prs_align(ps);

	return ret;
}

/*******************************************************************
frees a structure.
********************************************************************/
void free_samr_userinfo_ctr(SAM_USERINFO_CTR * ctr)
{
	if (!ctr) return;

	safe_free(ctr->info.id);
	ctr->info.id = NULL;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL sam_io_user_info10(char *desc, SAM_USER_INFO_10 * usr,
			prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_r_user_info10");
	depth++;

	prs_align(ps);

	prs_uint32("acb_info", ps, depth, &(usr->acb_info));

	return True;
}

/*******************************************************************
makes a SAM_USER_INFO_11 structure.
********************************************************************/
BOOL init_sam_user_info11(SAM_USER_INFO_11 * usr,
			  NTTIME * expiry,
			  char *mach_acct,
			  uint32 rid_user, uint32 rid_group, uint16 acct_ctrl)
{
	int len_mach_acct;

	DEBUG(5, ("init_sam_user_info11\n"));

	len_mach_acct = strlen(mach_acct);

	memcpy(&(usr->expiry), expiry, sizeof(usr->expiry));	/* expiry time or something? */
	ZERO_STRUCT(usr->padding_1);	/* 0 - padding 24 bytes */

	init_uni_hdr(&(usr->hdr_mach_acct), len_mach_acct);	/* unicode header for machine account */
	usr->padding_2 = 0;	/* 0 - padding 4 bytes */

	usr->ptr_1 = 1;		/* pointer */
	ZERO_STRUCT(usr->padding_3);	/* 0 - padding 32 bytes */
	usr->padding_4 = 0;	/* 0 - padding 4 bytes */

	usr->ptr_2 = 1;		/* pointer */
	usr->padding_5 = 0;	/* 0 - padding 4 bytes */

	usr->ptr_3 = 1;		/* pointer */
	ZERO_STRUCT(usr->padding_6);	/* 0 - padding 32 bytes */

	usr->rid_user = rid_user;
	usr->rid_group = rid_group;

	usr->acct_ctrl = acct_ctrl;
	usr->unknown_3 = 0x0000;

	usr->unknown_4 = 0x003f;	/* 0x003f      - 16 bit unknown */
	usr->unknown_5 = 0x003c;	/* 0x003c      - 16 bit unknown */

	ZERO_STRUCT(usr->padding_7);	/* 0 - padding 16 bytes */
	usr->padding_8 = 0;	/* 0 - padding 4 bytes */

	init_unistr2(&(usr->uni_mach_acct), mach_acct, len_mach_acct);	/* unicode string for machine account */

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL sam_io_user_info11(char *desc, SAM_USER_INFO_11 * usr,
			prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_r_unknown_11");
	depth++;

	prs_align(ps);

	prs_uint8s(False, "padding_0", ps, depth, usr->padding_0,
		   sizeof(usr->padding_0));

	smb_io_time("time", &(usr->expiry), ps, depth);

	prs_uint8s(False, "padding_1", ps, depth, usr->padding_1,
		   sizeof(usr->padding_1));

	smb_io_unihdr("unihdr", &(usr->hdr_mach_acct), ps, depth);
	prs_uint32("padding_2", ps, depth, &(usr->padding_2));

	prs_uint32("ptr_1    ", ps, depth, &(usr->ptr_1));
	prs_uint8s(False, "padding_3", ps, depth, usr->padding_3,
		   sizeof(usr->padding_3));
	prs_uint32("padding_4", ps, depth, &(usr->padding_4));

	prs_uint32("ptr_2    ", ps, depth, &(usr->ptr_2));
	prs_uint32("padding_5", ps, depth, &(usr->padding_5));

	prs_uint32("ptr_3    ", ps, depth, &(usr->ptr_3));
	prs_uint8s(False, "padding_6", ps, depth, usr->padding_6,
		   sizeof(usr->padding_6));

	prs_uint32("rid_user ", ps, depth, &(usr->rid_user));
	prs_uint32("rid_group", ps, depth, &(usr->rid_group));
	prs_uint16("acct_ctrl", ps, depth, &(usr->acct_ctrl));
	prs_uint16("unknown_3", ps, depth, &(usr->unknown_3));
	prs_uint16("unknown_4", ps, depth, &(usr->unknown_4));
	prs_uint16("unknown_5", ps, depth, &(usr->unknown_5));

	prs_uint8s(False, "padding_7", ps, depth, usr->padding_7,
		   sizeof(usr->padding_7));
	prs_uint32("padding_8", ps, depth, &(usr->padding_8));

	smb_io_unistr2("unistr2", &(usr->uni_mach_acct), True, ps, depth);
	prs_align(ps);

	prs_uint8s(False, "padding_9", ps, depth, usr->padding_9,
		   sizeof(usr->padding_9));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL sam_io_user_info12(char *desc, SAM_USER_INFO_12 * u,
			prs_struct *ps, int depth)
{
	DEBUG(0, ("possible security breach!\n"));

	prs_debug(ps, depth, desc, "samr_io_r_user_info12");
	depth++;

	prs_align(ps);

	prs_uint8s(False, "lm_pwd", ps, depth, u->lm_pwd, sizeof(u->lm_pwd));
	prs_uint8s(False, "nt_pwd", ps, depth, u->nt_pwd, sizeof(u->nt_pwd));

	prs_uint8("lm_pwd_active", ps, depth, &u->lm_pwd_active);
	prs_uint8("nt_pwd_active", ps, depth, &u->nt_pwd_active);
	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL sam_io_user_info21(char *desc, SAM_USER_INFO_21 * usr,
			prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "sam_io_user_info21");
	depth++;

	prs_align(ps);

	smb_io_time("logon_time           ", &(usr->logon_time), ps, depth);
	smb_io_time("logoff_time          ", &(usr->logoff_time), ps, depth);
	smb_io_time("pass_last_set_time   ", &(usr->pass_last_set_time), ps,
		    depth);
	smb_io_time("kickoff_time         ", &(usr->kickoff_time), ps, depth);
	smb_io_time("pass_can_change_time ", &(usr->pass_can_change_time), ps,
		    depth);
	smb_io_time("pass_must_change_time", &(usr->pass_must_change_time),
		    ps, depth);

	smb_io_unihdr("hdr_user_name   ", &(usr->hdr_user_name), ps, depth);	/* username unicode string header */
	smb_io_unihdr("hdr_full_name   ", &(usr->hdr_full_name), ps, depth);	/* user's full name unicode string header */
	smb_io_unihdr("hdr_home_dir    ", &(usr->hdr_home_dir), ps, depth);	/* home directory unicode string header */
	smb_io_unihdr("hdr_dir_drive   ", &(usr->hdr_dir_drive), ps, depth);	/* home directory drive */
	smb_io_unihdr("hdr_logon_script", &(usr->hdr_logon_script), ps, depth);	/* logon script unicode string header */
	smb_io_unihdr("hdr_profile_path", &(usr->hdr_profile_path), ps, depth);	/* profile path unicode string header */
	smb_io_unihdr("hdr_acct_desc   ", &(usr->hdr_acct_desc), ps, depth);	/* account desc */
	smb_io_unihdr("hdr_workstations", &(usr->hdr_workstations), ps, depth);	/* wkstas user can log on from */
	smb_io_unihdr("hdr_unknown_str ", &(usr->hdr_unknown_str), ps, depth);	/* unknown string */
	smb_io_unihdr("hdr_munged_dial ", &(usr->hdr_munged_dial), ps, depth);	/* wkstas user can log on from */

	prs_uint8s(False, "lm_pwd        ", ps, depth, usr->lm_pwd,
		   sizeof(usr->lm_pwd));
	prs_uint8s(False, "nt_pwd        ", ps, depth, usr->nt_pwd,
		   sizeof(usr->nt_pwd));

	prs_uint32("user_rid      ", ps, depth, &(usr->user_rid));	/* User ID */
	prs_uint32("group_rid     ", ps, depth, &(usr->group_rid));	/* Group ID */
	prs_uint32("acb_info      ", ps, depth, &(usr->acb_info));

	prs_uint32("unknown_3     ", ps, depth, &(usr->unknown_3));
	prs_uint16("logon_divs    ", ps, depth, &(usr->logon_divs));	/* logon divisions per week */
	prs_align(ps);
	prs_uint32("ptr_logon_hrs ", ps, depth, &(usr->ptr_logon_hrs));
	prs_uint32("unknown_5     ", ps, depth, &(usr->unknown_5));

	prs_uint8s(False, "padding1      ", ps, depth, usr->padding1,
		   sizeof(usr->padding1));

	/* here begins pointed-to data */

	smb_io_unistr2("uni_user_name   ", &(usr->uni_user_name),
		       usr->hdr_user_name.buffer, ps, depth);	/* username unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_full_name   ", &(usr->uni_full_name),
		       usr->hdr_full_name.buffer, ps, depth);	/* user's full name unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_home_dir    ", &(usr->uni_home_dir),
		       usr->hdr_home_dir.buffer, ps, depth);	/* home directory unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_dir_drive   ", &(usr->uni_dir_drive),
		       usr->hdr_dir_drive.buffer, ps, depth);	/* home directory drive unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_logon_script", &(usr->uni_logon_script),
		       usr->hdr_logon_script.buffer, ps, depth);	/* logon script unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_profile_path", &(usr->uni_profile_path),
		       usr->hdr_profile_path.buffer, ps, depth);	/* profile path unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_acct_desc   ", &(usr->uni_acct_desc),
		       usr->hdr_acct_desc.buffer, ps, depth);	/* user desc unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_workstations", &(usr->uni_workstations),
		       usr->hdr_workstations.buffer, ps, depth);	/* worksations user can log on from */
	prs_align(ps);
	smb_io_unistr2("uni_unknown_str ", &(usr->uni_unknown_str),
		       usr->hdr_unknown_str.buffer, ps, depth);	/* unknown string */
	prs_align(ps);
	smb_io_unistr2("uni_munged_dial ", &(usr->uni_munged_dial),
		       usr->hdr_munged_dial.buffer, ps, depth);	/* worksations user can log on from */
	prs_align(ps);

	/* ok, this is only guess-work (as usual) */
	if (usr->unknown_3 != 0x0)
	{
		prs_uint32("unknown_6     ", ps, depth, &(usr->unknown_6));
		prs_uint32("padding4      ", ps, depth, &(usr->padding4));
	}
	else if (UNMARSHALLING(ps))
	{
		usr->unknown_6 = 0;
		usr->padding4 = 0;
	}

	if (usr->ptr_logon_hrs)
	{
		sam_io_logon_hrs("logon_hrs", &(usr->logon_hrs), ps, depth);
		prs_align(ps);
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL sam_io_user_info23(char *desc, SAM_USER_INFO_23 * usr,
			prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "sam_io_user_info23");
	depth++;

	prs_align(ps);

	smb_io_time("logon_time           ", &(usr->logon_time), ps, depth);
	smb_io_time("logoff_time          ", &(usr->logoff_time), ps, depth);
	smb_io_time("kickoff_time         ", &(usr->kickoff_time), ps, depth);
	smb_io_time("pass_last_set_time   ", &(usr->pass_last_set_time), ps,
		    depth);
	smb_io_time("pass_can_change_time ", &(usr->pass_can_change_time), ps,
		    depth);
	smb_io_time("pass_must_change_time", &(usr->pass_must_change_time),
		    ps, depth);

	smb_io_unihdr("hdr_user_name   ", &(usr->hdr_user_name), ps, depth);	/* username unicode string header */
	smb_io_unihdr("hdr_full_name   ", &(usr->hdr_full_name), ps, depth);	/* user's full name unicode string header */
	smb_io_unihdr("hdr_home_dir    ", &(usr->hdr_home_dir), ps, depth);	/* home directory unicode string header */
	smb_io_unihdr("hdr_dir_drive   ", &(usr->hdr_dir_drive), ps, depth);	/* home directory drive */
	smb_io_unihdr("hdr_logon_script", &(usr->hdr_logon_script), ps, depth);	/* logon script unicode string header */
	smb_io_unihdr("hdr_profile_path", &(usr->hdr_profile_path), ps, depth);	/* profile path unicode string header */
	smb_io_unihdr("hdr_acct_desc   ", &(usr->hdr_acct_desc), ps, depth);	/* account desc */
	smb_io_unihdr("hdr_workstations", &(usr->hdr_workstations), ps, depth);	/* wkstas user can log on from */
	smb_io_unihdr("hdr_unknown_str ", &(usr->hdr_unknown_str), ps, depth);	/* unknown string */
	smb_io_unihdr("hdr_munged_dial ", &(usr->hdr_munged_dial), ps, depth);	/* wkstas user can log on from */

	prs_uint8s(False, "lm_pwd        ", ps, depth, usr->lm_pwd,
		   sizeof(usr->lm_pwd));
	prs_uint8s(False, "nt_pwd        ", ps, depth, usr->nt_pwd,
		   sizeof(usr->nt_pwd));

	prs_uint32("user_rid      ", ps, depth, &(usr->user_rid));	/* User ID */
	prs_uint32("group_rid     ", ps, depth, &(usr->group_rid));	/* Group ID */
	prs_uint32("acb_info      ", ps, depth, &(usr->acb_info));

	prs_uint32("unknown_3     ", ps, depth, &(usr->unknown_3));
	prs_uint16("logon_divs    ", ps, depth, &(usr->logon_divs));	/* logon divisions per week */
	prs_align(ps);
	prs_uint32("ptr_logon_hrs ", ps, depth, &(usr->ptr_logon_hrs));
	prs_uint8s(False, "padding1      ", ps, depth, usr->padding1,
		   sizeof(usr->padding1));
	prs_uint32("unknown_5     ", ps, depth, &(usr->unknown_5));

	prs_uint8s(False, "password      ", ps, depth, usr->pass,
		   sizeof(usr->pass));

	/* here begins pointed-to data */

	smb_io_unistr2("uni_user_name   ", &(usr->uni_user_name),
		       usr->hdr_user_name.buffer, ps, depth);	/* username unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_full_name   ", &(usr->uni_full_name),
		       usr->hdr_full_name.buffer, ps, depth);	/* user's full name unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_home_dir    ", &(usr->uni_home_dir),
		       usr->hdr_home_dir.buffer, ps, depth);	/* home directory unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_dir_drive   ", &(usr->uni_dir_drive),
		       usr->hdr_dir_drive.buffer, ps, depth);	/* home directory drive unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_logon_script", &(usr->uni_logon_script),
		       usr->hdr_logon_script.buffer, ps, depth);	/* logon script unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_profile_path", &(usr->uni_profile_path),
		       usr->hdr_profile_path.buffer, ps, depth);	/* profile path unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_acct_desc   ", &(usr->uni_acct_desc),
		       usr->hdr_acct_desc.buffer, ps, depth);	/* user desc unicode string */
	prs_align(ps);
	smb_io_unistr2("uni_workstations", &(usr->uni_workstations),
		       usr->hdr_workstations.buffer, ps, depth);	/* worksations user can log on from */
	prs_align(ps);
	smb_io_unistr2("uni_unknown_str ", &(usr->uni_unknown_str),
		       usr->hdr_unknown_str.buffer, ps, depth);	/* unknown string */
	prs_align(ps);
	smb_io_unistr2("uni_munged_dial ", &(usr->uni_munged_dial),
		       usr->hdr_munged_dial.buffer, ps, depth);	/* worksations user can log on from */
	prs_align(ps);

	/* ok, this is only guess-work (as usual) */
	if (usr->unknown_3 != 0x0)
	{
		prs_uint32("unknown_6     ", ps, depth, &(usr->unknown_6));
		prs_uint32("padding4      ", ps, depth, &(usr->padding4));
	}
	else if (UNMARSHALLING(ps))
	{
		usr->unknown_6 = 0;
		usr->padding4 = 0;
	}

	if (usr->ptr_logon_hrs)
	{
		sam_io_logon_hrs("logon_hrs", &(usr->logon_hrs), ps, depth);
		prs_align(ps);
	}

	return True;
}

/*************************************************************************
 make_sam_user_infoa

 unknown_3 = 0x09f8 27fa
 unknown_5 = 0x0001 0000
 unknown_6 = 0x0000 04ec 

 *************************************************************************/
BOOL init_sam_user_info24(SAM_USER_INFO_24 * usr,
			  const char newpass[516], uint16 passlen)
{
	DEBUG(10, ("init_sam_user_info24: passlen: %d\n", passlen));
	memcpy(usr->pass, newpass, sizeof(usr->pass));
	usr->unk_0 = passlen;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL sam_io_user_info24(char *desc, SAM_USER_INFO_24 * usr,
			prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "sam_io_user_info24");
	depth++;

	prs_align(ps);

	prs_uint8s(False, "password", ps, depth, usr->pass,
		   sizeof(usr->pass));
	prs_uint16("unk_0", ps, depth, &(usr->unk_0));	/* unknown */
	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes a LOGON_HRS structure.
********************************************************************/
BOOL sam_io_logon_hrs(char *desc, LOGON_HRS * hrs, prs_struct *ps, 
		      int depth)
{
	if (hrs == NULL)
		return False;

	prs_debug(ps, depth, desc, "sam_io_logon_hrs");
	depth++;

	prs_align(ps);

	prs_uint32("len  ", ps, depth, &hrs->len);

	if (hrs->len > sizeof(hrs->hours))
	{
		DEBUG(3, ("sam_io_logon_hrs: truncating length from %d\n",
			  hrs->len));
		hrs->len = sizeof(hrs->hours);
	}

	prs_uint8s(False, "hours", ps, depth, hrs->hours, hrs->len);

	return True;
}

/*******************************************************************
makes a SAMR_Q_QUERY_GROUPINFO structure.
********************************************************************/
BOOL init_samr_q_query_groupinfo(SAMR_Q_QUERY_GROUPINFO * q_e,
				 POLICY_HND *pol, uint16 switch_level)
{
	DEBUG(5, ("init_samr_q_query_groupinfo\n"));

	q_e->pol = *pol;
	q_e->switch_level = switch_level;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_query_groupinfo(char *desc, SAMR_Q_QUERY_GROUPINFO * q_e,
			       prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_q_query_groupinfo");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &q_e->pol, ps, depth);
	prs_uint16("switch_level", ps, depth, &q_e->switch_level);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_query_groupinfo(char *desc, SAMR_R_QUERY_GROUPINFO * r_u,
			       prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_r_query_groupinfo");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &r_u->ptr);

	if (r_u->ptr != 0) {
		samr_group_info_ctr("ctr", r_u->ctr, ps, depth);
	}

	prs_uint32("status", ps, depth, &r_u->status);

	return True;
}

/*******************************************************************
makes a SAMR_Q_QUERY_USERGROUPS structure.
********************************************************************/
BOOL samr_q_query_usergroups(SAMR_Q_QUERY_USERGROUPS * q_u, 
				  POLICY_HND *hnd)
{
	DEBUG(5, ("init_samr_q_query_usergroups\n"));

	q_u->pol = *hnd;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_query_usergroups(char *desc, SAMR_Q_QUERY_USERGROUPS * q_u,
				prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_q_query_usergroups");
	depth++;

	prs_align(ps);

	return smb_io_pol_hnd("pol", &q_u->pol, ps, depth);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_query_usergroups(char *desc, SAMR_R_QUERY_USERGROUPS * r_u,
				prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_r_query_usergroups");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_0       ", ps, depth, &r_u->ptr_0);

	if (r_u->ptr_0 != 0) {
		prs_uint32("num_entries ", ps, depth, &r_u->num_entries);
		prs_uint32("ptr_1       ", ps, depth, &r_u->ptr_1);

		if (r_u->num_entries != 0 && r_u->ptr_1 != 0)
		{
			samr_io_gids("gids", &r_u->num_entries2, &r_u->gid,
				     ps, depth);
		}
	}
	prs_uint32("status", ps, depth, &r_u->status);

	return True;
}

/*******************************************************************
makes a SAMR_Q_QUERY_GROUPMEM structure.
********************************************************************/
BOOL init_samr_q_query_groupmem(SAMR_Q_QUERY_GROUPMEM * q_c, POLICY_HND *hnd)
{
	DEBUG(5, ("init_samr_q_query_groupmem\n"));

	q_c->group_pol = *hnd;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_query_groupmem(char *desc, SAMR_Q_QUERY_GROUPMEM * q_u,
			      prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_q_query_groupmem");
	depth++;

	prs_align(ps);

	return smb_io_pol_hnd("group_pol", &q_u->group_pol, ps, depth);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_query_groupmem(char *desc, SAMR_R_QUERY_GROUPMEM * r_u,
			      prs_struct *ps, int depth)
{
	uint32 i;

	if (UNMARSHALLING(ps)) {
		ZERO_STRUCTP(r_u);
	}

	prs_debug(ps, depth, desc, "samr_io_r_query_groupmem");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &r_u->ptr);
	prs_uint32("num_entries ", ps, depth, &r_u->num_entries);

	if (r_u->ptr != 0)
	{
		prs_uint32("ptr_rids ", ps, depth, &r_u->ptr_rids);
		prs_uint32("ptr_attrs", ps, depth, &r_u->ptr_attrs);

		if (r_u->ptr_rids != 0) {
			prs_uint32("num_rids", ps, depth, &r_u->num_rids);
			if (r_u->num_rids != 0) {

				r_u->rid = (uint32 *)
					talloc(ps->mem_ctx, 
					       sizeof(r_u->rid [0]) *
					       r_u->num_rids);
			}

			for (i = 0; i < r_u->num_rids; i++) {
				prs_uint32("", ps, depth, &r_u->rid[i]);
			}
		}

		if (r_u->ptr_attrs != 0) {
			prs_uint32("num_attrs", ps, depth, &r_u->num_attrs);

			if (r_u->num_attrs != 0) {
				r_u->attr = (uint32 *)
					talloc(ps->mem_ctx, 
					       sizeof(r_u->attr[0]) *
					       r_u->num_attrs);
			}

			for (i = 0; i < r_u->num_attrs; i++) {
				prs_uint32("", ps, depth, &r_u->attr[i]);
			}
		}
	}

	prs_uint32("status", ps, depth, &(r_u->status));

	if (!ps->io) {
		/* storing.  memory no longer needed */
		samr_free_r_query_groupmem(r_u);
	}

	return True;
}

/*******************************************************************
frees a structure.
********************************************************************/
void samr_free_r_query_groupmem(SAMR_R_QUERY_GROUPMEM * r_u)
{
	safe_free(r_u->rid);
	r_u->rid = NULL;

	safe_free(r_u->attr);
	r_u->attr = NULL;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_group_info_ctr(char *desc, GROUP_INFO_CTR * ctr, prs_struct *ps, 
			 int depth)
{
	prs_debug(ps, depth, desc, "samr_group_info_ctr");
	depth++;

	prs_uint16("switch_value1", ps, depth, &(ctr->switch_value1));
	prs_uint16("switch_value2", ps, depth, &(ctr->switch_value2));

	switch (ctr->switch_value1)
	{
		case 1:
		{
			samr_io_group_info1("group_info1",
					    &(ctr->group.info1), ps, depth);
			break;
		}
		case 4:
		{
			samr_io_group_info4("group_info4",
					    &(ctr->group.info4), ps, depth);
			break;
		}
		default:
		{
			DEBUG(4,
			      ("samr_group_info_ctr: unsupported switch level\n"));
			break;
		}
	}

	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_gids(char *desc, uint32 *num_gids, DOM_GID ** gid,
		  prs_struct *ps, int depth)
{
	uint32 i;

	prs_debug(ps, depth, desc, "samr_io_gids");
	depth++;

	prs_align(ps);

	prs_uint32("num_gids", ps, depth, num_gids);

	if ((*num_gids) != 0)
	{
		if (UNMARSHALLING(ps))
		{
			(*gid) = (DOM_GID *)
				talloc(ps->mem_ctx, sizeof(DOM_GID) * 
				       (*num_gids));
		}

		if ((*gid) == NULL)
		{
			return False;
		}

		for (i = 0; i < (*num_gids); i++)
		{
			smb_io_gid("gids", &(*gid)[i], ps, depth);
		}
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_group_info1(char *desc, GROUP_INFO1 * gr1,
			 prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_group_info1");
	depth++;

	prs_align(ps);

	smb_io_unihdr("hdr_acct_name", &(gr1->hdr_acct_name), ps, depth);

	prs_uint32("unknown_1", ps, depth, &(gr1->unknown_1));
	prs_uint32("num_members", ps, depth, &(gr1->num_members));

	smb_io_unihdr("hdr_acct_desc", &(gr1->hdr_acct_desc), ps, depth);

	smb_io_unistr2("uni_acct_name", &(gr1->uni_acct_name),
		       gr1->hdr_acct_name.buffer, ps, depth);
	prs_align(ps);

	smb_io_unistr2("uni_acct_desc", &(gr1->uni_acct_desc),
		       gr1->hdr_acct_desc.buffer, ps, depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_group_info4(char *desc, GROUP_INFO4 * gr4,
			 prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_group_info4");
	depth++;

	prs_align(ps);

	smb_io_unihdr("hdr_acct_desc", &(gr4->hdr_acct_desc), ps, depth);
	smb_io_unistr2("uni_acct_desc", &(gr4->uni_acct_desc),
		       gr4->hdr_acct_desc.buffer, ps, depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
makes a SAMR_Q_QUERY_USERGROUPS structure.
********************************************************************/
BOOL init_samr_q_query_usergroups(SAMR_Q_QUERY_USERGROUPS * q_u,
				  POLICY_HND *hnd)
{
	DEBUG(5, ("init_samr_q_query_usergroups\n"));

	q_u->pol = *hnd;

	return True;
}

/*******************************************************************
makes a SAMR_Q_OPEN_GROUP structure.
********************************************************************/
BOOL init_samr_q_open_group(SAMR_Q_OPEN_GROUP * q_c, POLICY_HND *hnd,
			    uint32 access_mask, uint32 rid)
{
	DEBUG(5, ("init_samr_q_open_group\n"));

	q_c->domain_pol = *hnd;
	q_c->access_mask = access_mask;
	q_c->rid_group = rid;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_q_open_group(char *desc, SAMR_Q_OPEN_GROUP * q_u,
			  prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_q_open_group");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("domain_pol", &(q_u->domain_pol), ps, depth);

	prs_uint32("access_mask", ps, depth, &(q_u->access_mask));
	prs_uint32("rid_group", ps, depth, &(q_u->rid_group));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL samr_io_r_open_group(char *desc, SAMR_R_OPEN_GROUP * r_u,
			  prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "samr_io_r_open_group");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol", &r_u->group_pol, ps, depth);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

#undef NEW_NTDOMAIN
