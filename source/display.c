/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1997
   
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
server info level 101 display function
****************************************************************************/
void display_srv_info_101(FILE *out_hnd, SRV_INFO_101 *sv101)
{
	fstring name;
	fstring comment;

	if (sv101 == NULL)
	{
		return;
	}

	fstrcpy(name    , unistrn2(sv101->uni_name    .buffer, sv101->uni_name    .uni_str_len));
	fstrcpy(comment , unistrn2(sv101->uni_comment .buffer, sv101->uni_comment .uni_str_len));

	fprintf(out_hnd, "Server Info Level 101:\n");

	display_server(out_hnd, name, sv101->srv_type, comment);

	fprintf(out_hnd, "\tplatform_id     : %d\n"    , sv101->platform_id);
	fprintf(out_hnd, "\tos version      : %d.%d\n" , sv101->ver_major, sv101->ver_minor);
}

/****************************************************************************
server info level 102 display function
****************************************************************************/
void display_srv_info_102(FILE *out_hnd, SRV_INFO_102 *sv102)
{
	fstring name;
	fstring comment;
	fstring usr_path;

	if (sv102 == NULL)
	{
		return;
	}

	fstrcpy(name    , unistrn2(sv102->uni_name    .buffer, sv102->uni_name    .uni_str_len));
	fstrcpy(comment , unistrn2(sv102->uni_comment .buffer, sv102->uni_comment .uni_str_len));
	fstrcpy(usr_path, unistrn2(sv102->uni_usr_path.buffer, sv102->uni_usr_path.uni_str_len));

	fprintf(out_hnd, "Server Info Level 102:\n");

	display_server(out_hnd, name, sv102->srv_type, comment);

	fprintf(out_hnd, "\tplatform_id     : %d\n"    , sv102->platform_id);
	fprintf(out_hnd, "\tos version      : %d.%d\n" , sv102->ver_major, sv102->ver_minor);

	fprintf(out_hnd, "\tusers           : %x\n"    , sv102->users      );
	fprintf(out_hnd, "\tdisc, hidden    : %x,%x\n" , sv102->disc     , sv102->hidden   );
	fprintf(out_hnd, "\tannounce, delta : %d, %d\n", sv102->announce , sv102->ann_delta);
	fprintf(out_hnd, "\tlicenses        : %d\n"    , sv102->licenses   );
	fprintf(out_hnd, "\tuser path       : %s\n"    , usr_path);
}

/****************************************************************************
server info container display function
****************************************************************************/
void display_srv_info_ctr(FILE *out_hnd, SRV_INFO_CTR *ctr)
{
	if (ctr == NULL || ctr->ptr_srv_ctr == 0)
	{
		fprintf(out_hnd, "Server Information: unavailable due to an error\n");
		return;
	}

	switch (ctr->switch_value)
	{
		case 101:
		{
			display_srv_info_101(out_hnd, &(ctr->srv.sv101));
			break;
		}
		case 102:
		{
			display_srv_info_102(out_hnd, &(ctr->srv.sv102));
			break;
		}
		default:
		{
			fprintf(out_hnd, "Server Information: Unknown Info Level\n");
			break;
		}
	}
}

/****************************************************************************
 print browse connection on a host
 ****************************************************************************/
void display_server(FILE *out_hnd, char *sname, uint32 type, char *comment)
{
	fstring typestr;
	*typestr=0;

	if (type == SV_TYPE_ALL)
	{
		strcpy(typestr, "All");
	}
	else
	{
		int i;
		typestr[0] = 0;
		for (i = 0; i < 32; i++)
		{
			if (IS_BITS_SET_ALL(type, 1 << i))
			{
				switch (1 << i)
				{
					case SV_TYPE_WORKSTATION      : strcat(typestr, "Wk " ); break;
					case SV_TYPE_SERVER           : strcat(typestr, "Sv " ); break;
					case SV_TYPE_SQLSERVER        : strcat(typestr, "Sql "); break;
					case SV_TYPE_DOMAIN_CTRL      : strcat(typestr, "PDC "); break;
					case SV_TYPE_DOMAIN_BAKCTRL   : strcat(typestr, "BDC "); break;
					case SV_TYPE_TIME_SOURCE      : strcat(typestr, "Tim "); break;
					case SV_TYPE_AFP              : strcat(typestr, "AFP "); break;
					case SV_TYPE_NOVELL           : strcat(typestr, "Nov "); break;
					case SV_TYPE_DOMAIN_MEMBER    : strcat(typestr, "Dom "); break;
					case SV_TYPE_PRINTQ_SERVER    : strcat(typestr, "PrQ "); break;
					case SV_TYPE_DIALIN_SERVER    : strcat(typestr, "Din "); break;
					case SV_TYPE_SERVER_UNIX      : strcat(typestr, "Unx "); break;
					case SV_TYPE_NT               : strcat(typestr, "NT " ); break;
					case SV_TYPE_WFW              : strcat(typestr, "Wfw "); break;
					case SV_TYPE_SERVER_MFPN      : strcat(typestr, "Mfp "); break;
					case SV_TYPE_SERVER_NT        : strcat(typestr, "SNT "); break;
					case SV_TYPE_POTENTIAL_BROWSER: strcat(typestr, "PtB "); break;
					case SV_TYPE_BACKUP_BROWSER   : strcat(typestr, "BMB "); break;
					case SV_TYPE_MASTER_BROWSER   : strcat(typestr, "LMB "); break;
					case SV_TYPE_DOMAIN_MASTER    : strcat(typestr, "DMB "); break;
					case SV_TYPE_SERVER_OSF       : strcat(typestr, "OSF "); break;
					case SV_TYPE_SERVER_VMS       : strcat(typestr, "VMS "); break;
					case SV_TYPE_WIN95_PLUS       : strcat(typestr, "W95 "); break;
					case SV_TYPE_ALTERNATE_XPORT  : strcat(typestr, "Xpt "); break;
					case SV_TYPE_LOCAL_LIST_ONLY  : strcat(typestr, "Dom "); break;
					case SV_TYPE_DOMAIN_ENUM      : strcat(typestr, "Loc "); break;
				}
			}
		}
		i = strlen(typestr)-1;
		if (typestr[i] == ' ') typestr[i] = 0;

	}

	fprintf(out_hnd, "\t%-15.15s%-20s %s\n", sname, typestr, comment);
}

/****************************************************************************
print browse connection on a host
****************************************************************************/
void display_share(FILE *out_hnd, char *sname, uint32 type, char *comment)
{
	fstring typestr;
	*typestr=0;

	switch (type)
	{
		case STYPE_DISKTREE: strcpy(typestr,"Disk"); break;
		case STYPE_PRINTQ  : strcpy(typestr,"Printer"); break;	      
		case STYPE_DEVICE  : strcpy(typestr,"Device"); break;
		case STYPE_IPC     : strcpy(typestr,"IPC"); break;      
		default            : strcpy(typestr,"????"); break;      
	}

	fprintf(out_hnd, "\t%-15.15s%-10.10s%s\n", sname, typestr, comment);
}


/****************************************************************************
 display group rid info
 ****************************************************************************/
void display_group_info(FILE *out_hnd, uint32 num_gids, DOM_GID *gid)
{
	int i;

	if (num_gids == 0)
	{
		fprintf(out_hnd, "\tNo Groups\n");
	}
	else
	{
		fprintf(out_hnd, "\tGroup Info\n");
		fprintf(out_hnd, "\t----------\n");

		for (i = 0; i < num_gids; i++)
		{
			fprintf(out_hnd, "\tGroup RID: %8x attr: %x\n",
							  gid[i].g_rid, gid[i].attr);
		}

		fprintf(out_hnd, "\n");
	}
}


/****************************************************************************
 display sam_user_info_15 structure
 ****************************************************************************/
void display_sam_user_info_15(FILE *out_hnd, SAM_USER_INFO_15 *usr)
{
	fprintf(out_hnd, "\tUser Info, Level 0x15\n");
	fprintf(out_hnd, "\t---------------------\n");

	fprintf(out_hnd, "\t\tUser Name   : %s\n", unistrn2(usr->uni_user_name   .buffer, usr->uni_user_name   .uni_str_len)); /* username unicode string */
	fprintf(out_hnd, "\t\tFull Name   : %s\n", unistrn2(usr->uni_full_name   .buffer, usr->uni_full_name   .uni_str_len)); /* user's full name unicode string */
	fprintf(out_hnd, "\t\tHome Drive  : %s\n", unistrn2(usr->uni_home_dir    .buffer, usr->uni_home_dir    .uni_str_len)); /* home directory unicode string */
	fprintf(out_hnd, "\t\tDir Drive   : %s\n", unistrn2(usr->uni_dir_drive   .buffer, usr->uni_dir_drive   .uni_str_len)); /* home directory drive unicode string */
	fprintf(out_hnd, "\t\tProfile Path: %s\n", unistrn2(usr->uni_profile_path.buffer, usr->uni_profile_path.uni_str_len)); /* profile path unicode string */
	fprintf(out_hnd, "\t\tLogon Script: %s\n", unistrn2(usr->uni_logon_script.buffer, usr->uni_logon_script.uni_str_len)); /* logon script unicode string */
	fprintf(out_hnd, "\t\tDescription : %s\n", unistrn2(usr->uni_description .buffer, usr->uni_description .uni_str_len)); /* user description unicode string */

	fprintf(out_hnd, "\t\tLogon Time               : %s\n", time_to_string(interpret_nt_time(&(usr->logon_time           ))));
	fprintf(out_hnd, "\t\tLogoff Time              : %s\n", time_to_string(interpret_nt_time(&(usr->logoff_time          ))));
	fprintf(out_hnd, "\t\tKickoff Time             : %s\n", time_to_string(interpret_nt_time(&(usr->kickoff_time         ))));
	fprintf(out_hnd, "\t\tPassword last set Time   : %s\n", time_to_string(interpret_nt_time(&(usr->pass_last_set_time   ))));
	fprintf(out_hnd, "\t\tPassword can change Time : %s\n", time_to_string(interpret_nt_time(&(usr->pass_can_change_time ))));
	fprintf(out_hnd, "\t\tPassword must change Time: %s\n", time_to_string(interpret_nt_time(&(usr->pass_must_change_time))));
	
	fprintf(out_hnd, "\t\tlogon_count : %d\n", usr->logon_count); /* logon count */
	fprintf(out_hnd, "\t\tbad_pw_count: %d\n", usr->bad_pw_count); /* bad password count */
	fprintf(out_hnd, "\t\tunknown_0: %08x\n", usr->unknown_0);
	fprintf(out_hnd, "\t\tunknown_1: %08x\n", usr->unknown_1);

	fprintf(out_hnd, "\t\tunknown_2[0..31]...\n"); /* user passwords? */

	fprintf(out_hnd, "\t\tuser_rid : %x\n"  , usr->user_rid ); /* User ID */
	fprintf(out_hnd, "\t\tgroup_rid: %x\n"  , usr->group_rid); /* Group ID */
	fprintf(out_hnd, "\t\tacb_info : %04x\n", usr->acb_info ); /* Account Control Info */

	fprintf(out_hnd, "\t\tunknown_3: %08x\n", usr->unknown_3); /* 0x00ff ffff */
	fprintf(out_hnd, "\t\tlogon_divs: %d\n", usr->logon_divs); /* 0x0000 00a8 which is 168 which is num hrs in a week */
	fprintf(out_hnd, "\t\tunknown_5: %08x\n", usr->unknown_5); /* 0x0002 0000 */

	fprintf(out_hnd, "\t\tpadding1[0..7]...\n");

	if (usr->ptr_padding2)
	{
		fprintf(out_hnd, "\t\tpadding2[0..31]...\n");
	}

	if (usr->ptr_padding3)
	{
		fprintf(out_hnd, "\t\tpadding3: %x\n", usr->padding3);
	}

	if (usr->ptr_unknown6)
	{
		fprintf(out_hnd, "\t\tunknown_6,pad4: %08x %08x\n", usr->unknown_6, usr->padding4);
	}

	if (usr->ptr_logon_hrs)
	{
		fprintf(out_hnd, "\t\tlogon_hrs[0..%d]...\n", usr->logon_hrs.len);
	}

	fprintf(out_hnd, "\n");
}

