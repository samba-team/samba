/* 
   Unix SMB/CIFS implementation.
   SAMR Pipe utility functions.
   Copyright (C) Jeremy Allison 		1996-2001
   Copyright (C) Luke Kenneth Casson Leighton 	1996-1998
   Copyright (C) Gerald (Jerry) Carter		2000-2001
   Copyright (C) Andrew Bartlett		2001-2002
      
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/*************************************************************
 Copies a SAM_USER_INFO_23 to a SAM_ACCOUNT
 **************************************************************/

void copy_id23_to_sam_passwd(SAM_ACCOUNT *to, SAM_USER_INFO_23 *from)
{

	if (from == NULL || to == NULL) 
		return;

	pdb_set_logon_time(to,nt_time_to_unix(&from->logon_time), True);
	pdb_set_logoff_time(to,nt_time_to_unix(&from->logoff_time), True);
	pdb_set_kickoff_time(to, nt_time_to_unix(&from->kickoff_time), True);
	pdb_set_pass_can_change_time(to, nt_time_to_unix(&from->pass_can_change_time), True);
	pdb_set_pass_must_change_time(to, nt_time_to_unix(&from->pass_must_change_time), True);

	pdb_set_pass_last_set_time(to, nt_time_to_unix(&from->pass_last_set_time));

	if (from->uni_user_name.buffer)
		pdb_set_username(to      , pdb_unistr2_convert(&from->uni_user_name   ));
	if (from->uni_full_name.buffer)
		pdb_set_fullname(to      , pdb_unistr2_convert(&from->uni_full_name   ));
	if (from->uni_home_dir.buffer)
		pdb_set_homedir(to       , pdb_unistr2_convert(&from->uni_home_dir    ), True);
	if (from->uni_dir_drive.buffer)
		pdb_set_dir_drive(to     , pdb_unistr2_convert(&from->uni_dir_drive   ), True);
	if (from->uni_logon_script.buffer)
		pdb_set_logon_script(to  , pdb_unistr2_convert(&from->uni_logon_script), True);
	if (from->uni_profile_path.buffer)
		pdb_set_profile_path(to  , pdb_unistr2_convert(&from->uni_profile_path), True);
	if (from->uni_acct_desc.buffer)
		pdb_set_acct_desc(to     , pdb_unistr2_convert(&from->uni_acct_desc   ));
	if (from->uni_workstations.buffer)
		pdb_set_workstations(to  , pdb_unistr2_convert(&from->uni_workstations));
	if (from->uni_unknown_str.buffer)
		pdb_set_unknown_str(to   , pdb_unistr2_convert(&from->uni_unknown_str ));
	if (from->uni_munged_dial.buffer)
		pdb_set_munged_dial(to   , pdb_unistr2_convert(&from->uni_munged_dial ));

	if (from->user_rid)
		pdb_set_user_sid_from_rid(to, from->user_rid);
	if (from->group_rid)
		pdb_set_group_sid_from_rid(to, from->group_rid);

	pdb_set_acct_ctrl(to, from->acb_info);
	pdb_set_unknown_3(to, from->unknown_3);

	pdb_set_logon_divs(to, from->logon_divs);
	pdb_set_hours_len(to, from->logon_hrs.len);
	pdb_set_hours(to, from->logon_hrs.hours);

	pdb_set_unknown_5(to, from->unknown_5);
	pdb_set_unknown_6(to, from->unknown_6);
}


/*************************************************************
 Copies a sam passwd.
 **************************************************************/

void copy_id21_to_sam_passwd(SAM_ACCOUNT *to, SAM_USER_INFO_21 *from)
{
	if (from == NULL || to == NULL) 
		return;

	pdb_set_logon_time(to,nt_time_to_unix(&from->logon_time), True);
	pdb_set_logoff_time(to,nt_time_to_unix(&from->logoff_time), True);
	pdb_set_kickoff_time(to, nt_time_to_unix(&from->kickoff_time), True);
	pdb_set_pass_can_change_time(to, nt_time_to_unix(&from->pass_can_change_time), True);
	pdb_set_pass_must_change_time(to, nt_time_to_unix(&from->pass_must_change_time), True);

	pdb_set_pass_last_set_time(to, nt_time_to_unix(&from->pass_last_set_time));

	if (from->uni_user_name.buffer)
		pdb_set_username(to      , pdb_unistr2_convert(&from->uni_user_name   ));
	if (from->uni_full_name.buffer)
		pdb_set_fullname(to      , pdb_unistr2_convert(&from->uni_full_name   ));
	if (from->uni_home_dir.buffer)
		pdb_set_homedir(to       , pdb_unistr2_convert(&from->uni_home_dir    ), True);
	if (from->uni_dir_drive.buffer)
		pdb_set_dir_drive(to     , pdb_unistr2_convert(&from->uni_dir_drive   ), True);
	if (from->uni_logon_script.buffer)
		pdb_set_logon_script(to  , pdb_unistr2_convert(&from->uni_logon_script), True);
	if (from->uni_profile_path.buffer)
		pdb_set_profile_path(to  , pdb_unistr2_convert(&from->uni_profile_path), True);
	if (from->uni_acct_desc.buffer)
		pdb_set_acct_desc(to     , pdb_unistr2_convert(&from->uni_acct_desc   ));
	if (from->uni_workstations.buffer)
		pdb_set_workstations(to  , pdb_unistr2_convert(&from->uni_workstations));
	if (from->uni_unknown_str.buffer)
		pdb_set_unknown_str(to   , pdb_unistr2_convert(&from->uni_unknown_str ));
	if (from->uni_munged_dial.buffer)
		pdb_set_munged_dial(to   , pdb_unistr2_convert(&from->uni_munged_dial ));

	if (from->user_rid)
		pdb_set_user_sid_from_rid(to, from->user_rid);
	if (from->group_rid)
		pdb_set_group_sid_from_rid(to, from->group_rid);

	/* FIXME!!  Do we need to copy the passwords here as well?
	   I don't know.  Need to figure this out   --jerry */

	/* Passwords dealt with in caller --abartlet */

	pdb_set_acct_ctrl(to, from->acb_info);
	pdb_set_unknown_3(to, from->unknown_3);

	pdb_set_logon_divs(to, from->logon_divs);
	pdb_set_hours_len(to, from->logon_hrs.len);
	pdb_set_hours(to, from->logon_hrs.hours);

	pdb_set_unknown_5(to, from->unknown_5);
	pdb_set_unknown_6(to, from->unknown_6);
}

