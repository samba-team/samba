/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996 - 1999
   
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

/****************************************************************************
 display alias members
 ****************************************************************************/
void display_alias_members(FILE *out_hnd, enum action_type action, 
				uint32 num_mem, char *const *const sid_mem, 
				uint32 *const type)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			if (num_mem == 0)
			{
				report(out_hnd, "\tNo Alias Members\n");
			}
			else
			{
				report(out_hnd, "\tAlias Members:\n");
				report(out_hnd, "\t-------------\n");
			}
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < num_mem; i++)
			{
				if (sid_mem[i] != NULL)
				{
					report(out_hnd, "\tMember Name:\t%s\tType:\t%s\n", 
					sid_mem[i], 
					get_sid_name_use_str(type[i]));
				}
			}

			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}
}


/****************************************************************************
 display alias rid info
 ****************************************************************************/
void display_alias_rid_info(FILE *out_hnd, enum action_type action, 
				DOM_SID *const sid, 
				uint32 num_rids, uint32 *const rid)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			fstring sid_str;
			sid_to_string(sid_str, sid);
			if (num_rids == 0)
			{
				report(out_hnd, "\tNo Aliases:\tSid %s\n", sid_str);
			}
			else
			{
				report(out_hnd, "\tAlias Info:\tSid %s\n", sid_str);
				report(out_hnd, "\t----------\n");
			}
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < num_rids; i++)
			{
				report(out_hnd, "\tAlias RID:\t%8x\n", rid[i]);
			}

			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}
}

/****************************************************************************
 display group members
 ****************************************************************************/
void display_group_members(FILE *out_hnd, enum action_type action, 
				uint32 num_mem, char *const *const name, uint32 *const type)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			if (num_mem == 0)
			{
				report(out_hnd, "\tNo Members\n");
			}
			else
			{
				report(out_hnd, "\tMembers:\n");
				report(out_hnd, "\t-------\n");
			}
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < num_mem; i++)
			{
				report(out_hnd, "\tMember Name:\t%s\tType:\t%s\n", 
				        name[i], get_sid_name_use_str(type[i]));
			}

			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}
}


/****************************************************************************
 display group info
 ****************************************************************************/
void display_group_info1(FILE *out_hnd, enum action_type action, GROUP_INFO1 *const info1)
				
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring temp;

			unistr2_to_ascii(temp, &info1->uni_acct_name, sizeof(temp)-1);
			report(out_hnd, "\tGroup Name:\t%s\n", temp);
			unistr2_to_ascii(temp, &info1->uni_acct_desc, sizeof(temp)-1);
			report(out_hnd, "\tDescription:\t%s\n", temp);
			report(out_hnd, "\tunk1:%d\n", info1->unknown_1);
			report(out_hnd, "\tNum Members:%d\n", info1->num_members);
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
 display group info
 ****************************************************************************/
void display_group_info4(FILE *out_hnd, enum action_type action, GROUP_INFO4 *const info4)
				
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring desc;

			unistr2_to_ascii(desc, &info4->uni_acct_desc, sizeof(desc)-1);
			report(out_hnd, "\tGroup Description:%s\n", 
			                  desc);
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
 display sam sync structure
 ****************************************************************************/
void display_group_info_ctr(FILE *out_hnd, enum action_type action, 
				GROUP_INFO_CTR *const ctr)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "\tSAM Group Info\n"); 
			report(out_hnd, "\t--------------\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			switch (ctr->switch_value1)
			{
				case 1:
				{
					display_group_info1(out_hnd, ACTION_HEADER   , &ctr->group.info1);
					display_group_info1(out_hnd, ACTION_ENUMERATE, &ctr->group.info1);
					display_group_info1(out_hnd, ACTION_FOOTER   , &ctr->group.info1);
					break;
				}
				case 4:
				{
					display_group_info4(out_hnd, ACTION_HEADER   , &ctr->group.info4);
					display_group_info4(out_hnd, ACTION_ENUMERATE, &ctr->group.info4);
					display_group_info4(out_hnd, ACTION_FOOTER   , &ctr->group.info4);
					break;
				}
			}
			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}
}

/****************************************************************************
 display group rid info
 ****************************************************************************/
void display_group_rid_info(FILE *out_hnd, enum action_type action, 
				uint32 num_gids, DOM_GID *const gid)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			if (num_gids == 0)
			{
				report(out_hnd, "\tNo Groups\n");
			}
			else
			{
				report(out_hnd, "\tGroup Info\n");
				report(out_hnd, "\t----------\n");
			}
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < num_gids; i++)
			{
				report(out_hnd, "\tGroup RID:\t%8x attr:\t%x\n", 
								  gid[i].g_rid, gid[i].attr);
			}

			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}
}


/****************************************************************************
 display alias name info
 ****************************************************************************/
void display_alias_name_info(FILE *out_hnd, enum action_type action, 
				uint32 num_aliases, fstring *const alias_name, const uint32 *const num_als_usrs)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			if (num_aliases == 0)
			{
				report(out_hnd, "\tNo Aliases\n");
			}
			else
			{
				report(out_hnd, "\tAlias Names\n");
				report(out_hnd, "\t----------- \n");
			}
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < num_aliases; i++)
			{
				report(out_hnd, "\tAlias Name:\t%s Attributes:\t%3d\n", 
								  alias_name[i], num_als_usrs[i]);
			}

			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}
}

/****************************************************************************
 display alias info
 ****************************************************************************/
void display_alias_info3(FILE *out_hnd, enum action_type action, ALIAS_INFO3 *const info3)
				
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring temp;

			unistr2_to_ascii(temp, &info3->uni_acct_desc, sizeof(temp)-1);
			report(out_hnd, "\tDescription:\t%s\n", temp);
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
 display sam sync structure
 ****************************************************************************/
void display_alias_info_ctr(FILE *out_hnd, enum action_type action, 
				ALIAS_INFO_CTR *const ctr)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "\tSAM Group Info\n"); 
			report(out_hnd, "\t--------------\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			switch (ctr->switch_value1)
			{
				case 3:
				{
					display_alias_info3(out_hnd, ACTION_HEADER   , &ctr->alias.info3);
					display_alias_info3(out_hnd, ACTION_ENUMERATE, &ctr->alias.info3);
					display_alias_info3(out_hnd, ACTION_FOOTER   , &ctr->alias.info3);
					break;
				}
			}
			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}
}


/****************************************************************************
 display sam_user_info_21 structure
 ****************************************************************************/
void display_sam_user_info_21(FILE *out_hnd, enum action_type action, SAM_USER_INFO_21 *const usr)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "\tUser Info, Level 0x15\n");
			report(out_hnd, "\t---------------------\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring temp;

			unistr2_to_ascii(temp, &usr->uni_user_name, sizeof(temp)-1);
			report(out_hnd, "\t\tUser Name   :\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_full_name, sizeof(temp)-1);
			report(out_hnd, "\t\tFull Name   :\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_home_dir, sizeof(temp)-1);
			report(out_hnd, "\t\tHome Drive  :\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_dir_drive, sizeof(temp)-1);
			report(out_hnd, "\t\tDir Drive   :\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_profile_path, sizeof(temp)-1);
			report(out_hnd, "\t\tProfile Path:\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_logon_script, sizeof(temp)-1);
			report(out_hnd, "\t\tLogon Script:\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_acct_desc, sizeof(temp)-1);
			report(out_hnd, "\t\tDescription :\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_workstations, sizeof(temp)-1);
			report(out_hnd, "\t\tWorkstations:\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_unknown_str, sizeof(temp)-1);
			report(out_hnd, "\t\tUnknown Str :\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_munged_dial, sizeof(temp)-1);
			report(out_hnd, "\t\tRemote Dial :\t%s\n", temp);

			report(out_hnd, "\t\tLogon Time               :\t%s\n", http_timestring(nt_time_to_unix(&(usr->logon_time           ))));
			report(out_hnd, "\t\tLogoff Time              :\t%s\n", http_timestring(nt_time_to_unix(&(usr->logoff_time          ))));
			report(out_hnd, "\t\tKickoff Time             :\t%s\n", http_timestring(nt_time_to_unix(&(usr->kickoff_time         ))));
			report(out_hnd, "\t\tPassword last set Time   :\t%s\n", http_timestring(nt_time_to_unix(&(usr->pass_last_set_time   ))));
			report(out_hnd, "\t\tPassword can change Time :\t%s\n", http_timestring(nt_time_to_unix(&(usr->pass_can_change_time ))));
			report(out_hnd, "\t\tPassword must change Time:\t%s\n", http_timestring(nt_time_to_unix(&(usr->pass_must_change_time))));
			
			report(out_hnd, "\t\tunknown_2[0..31]...\n"); /* user passwords? */

			report(out_hnd, "\t\tuser_rid :\t%x\n"  , usr->user_rid ); /* User ID */
			report(out_hnd, "\t\tgroup_rid:\t%x\n"  , usr->group_rid); /* Group ID */
			report(out_hnd, "\t\tacb_info :\t%04x\n", usr->acb_info ); /* Account Control Info */

			report(out_hnd, "\t\tunknown_3:\t%08x\n", usr->unknown_3); /* 0x00ff ffff */
			report(out_hnd, "\t\tlogon_divs:\t%d\n", usr->logon_divs); /* 0x0000 00a8 which is 168 which is num hrs in a week */
			report(out_hnd, "\t\tunknown_5:\t%08x\n", usr->unknown_5); /* 0x0002 0000 */

			report(out_hnd, "\t\tpadding1[0..7]...\n");

			if (usr->ptr_logon_hrs)
			{
				report(out_hnd, "\t\tlogon_hrs[0..%d]...\n", usr->logon_hrs.len);
			}

			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}
}


/****************************************************************************
 display sam sync structure
 ****************************************************************************/
void display_sam_unk_info_2(FILE *out_hnd, enum action_type action, 
				SAM_UNK_INFO_2 *const info2)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring name;
			unistr2_to_ascii(name, &(info2->uni_domain), sizeof(name)-1); 
			report(out_hnd, "Domain:\t%s\n", name);

			unistr2_to_ascii(name, &(info2->uni_server), sizeof(name)-1); 
			report(out_hnd, "Server:\t%s\n", name);

			report(out_hnd, "Total Users:\t%d\n", info2->num_domain_usrs);
			report(out_hnd, "Total Groups:\t%d\n", info2->num_domain_grps);
			report(out_hnd, "Total Aliases:\t%d\n", info2->num_local_grps);

			report(out_hnd, "Sequence No:\t%d\n", info2->seq_num);

			report(out_hnd, "Unknown 0:\t0x%x\n", info2->unknown_0);
			report(out_hnd, "Unknown 1:\t0x%x\n", info2->unknown_1);
			report(out_hnd, "Unknown 2:\t0x%x\n", info2->unknown_2);
			report(out_hnd, "Unknown 3:\t0x%x\n", info2->unknown_3);
			report(out_hnd, "Unknown 4:\t0x%x\n", info2->unknown_4);
			report(out_hnd, "Unknown 5:\t0x%x\n", info2->unknown_5);
			report(out_hnd, "Unknown 6:\t0x%x\n", info2->unknown_6);

			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}
}

/****************************************************************************
 display sam sync structure
 ****************************************************************************/
void display_sam_unk_ctr(FILE *out_hnd, enum action_type action, 
				uint32 switch_value, SAM_UNK_CTR *const ctr)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "\tSAM Domain Info\n"); 
			report(out_hnd, "\t---------------\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			switch (switch_value)
			{
				case 2:
				{
					display_sam_unk_info_2(out_hnd, ACTION_HEADER   , &ctr->info.inf2);
					display_sam_unk_info_2(out_hnd, ACTION_ENUMERATE, &ctr->info.inf2);
					display_sam_unk_info_2(out_hnd, ACTION_FOOTER   , &ctr->info.inf2);
					break;
				}
			}
			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}
}

/****************************************************************************
sam info level 1 display function
****************************************************************************/
void display_sam_info_1(FILE *out_hnd, enum action_type action, 
		SAM_ENTRY1 *const e1, SAM_STR1 *const s1)
{
	if (e1 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "Sam Level 1:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring tmp;

			report(out_hnd, "\tIndex:\t%d\n", e1->user_idx);
			report(out_hnd, "\tRID:\t0x%x\n", e1->rid_user);
			report(out_hnd, "\tACB:\t%s\n", 
			             pwdb_encode_acct_ctrl(e1->acb_info,
			             NEW_PW_FORMAT_SPACE_PADDED_LEN));

			unistr2_to_ascii(tmp, &s1->uni_acct_name, sizeof(tmp)-1);
			report(out_hnd, "\tAccount Name:\t%s\n", tmp);
			unistr2_to_ascii(tmp, &s1->uni_full_name, sizeof(tmp)-1);
			report(out_hnd, "\tFull Name:\t%s\n", tmp);
			unistr2_to_ascii(tmp, &s1->uni_acct_desc, sizeof(tmp)-1);
			report(out_hnd, "\tUser Description:\t%s\n", tmp);

			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}

}

/****************************************************************************
connection info level 1 container display function
****************************************************************************/
void display_sam_info_1_ctr(FILE *out_hnd, enum action_type action, 
				uint32 count, SAM_DISPINFO_1 *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_sam_info_1_ctr: unavailable due to an internal error\n");
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < count; i++)
			{
				display_sam_info_1(out_hnd, ACTION_HEADER   , &ctr->sam[i], &ctr->str[i]);
				display_sam_info_1(out_hnd, ACTION_ENUMERATE, &ctr->sam[i], &ctr->str[i]);
				display_sam_info_1(out_hnd, ACTION_FOOTER   , &ctr->sam[i], &ctr->str[i]);
			}
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
connection info container display function
****************************************************************************/
void display_sam_disp_info_ctr(FILE *out_hnd, enum action_type action, 
				uint16 level, uint32 count,
				SAM_DISPINFO_CTR *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_sam_info_ctr: unavailable due to an internal error\n");
		return;
	}

	switch (level)
	{
		case 1:
		{
			display_sam_info_1_ctr(out_hnd, action, 
			                   count, ctr->sam.info1);
			break;
		}
		default:
		{
			report(out_hnd, "display_sam_info_ctr: Unknown Info Level\n");
			break;
		}
	}
}

