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
convert a share mode to a string
****************************************************************************/
char *get_file_mode_str(uint32 share_mode)
{
	static fstring mode;

	switch ((share_mode>>4)&0xF)
	{
		case DENY_NONE : strcpy(mode, "DENY_NONE  "); break;
		case DENY_ALL  : strcpy(mode, "DENY_ALL   "); break;
		case DENY_DOS  : strcpy(mode, "DENY_DOS   "); break;
		case DENY_READ : strcpy(mode, "DENY_READ  "); break;
		case DENY_WRITE: strcpy(mode, "DENY_WRITE "); break;
		default        : strcpy(mode, "DENY_????  "); break;
	}

	switch (share_mode & 0xF)
	{
		case 0 : strcat(mode, "RDONLY"); break;
		case 1 : strcat(mode, "WRONLY"); break;
		case 2 : strcat(mode, "RDWR  "); break;
		default: strcat(mode, "R??W??"); break;
	}

	return mode;
}

/****************************************************************************
convert an oplock mode to a string
****************************************************************************/
char *get_file_oplock_str(uint32 op_type)
{
	static fstring oplock;
	BOOL excl  = IS_BITS_SET_ALL(op_type, EXCLUSIVE_OPLOCK);
	BOOL batch = IS_BITS_SET_ALL(op_type, BATCH_OPLOCK    );

	oplock[0] = 0;

	if (excl           ) strcat(oplock, "EXCLUSIVE");
	if (excl  &&  batch) strcat(oplock, "+");
	if (          batch) strcat(oplock, "BATCH");
	if (!excl && !batch) strcat(oplock, "NONE");

	return oplock;
}

/****************************************************************************
convert a share type enum to a string
****************************************************************************/
char *get_share_type_str(uint32 type)
{
	static fstring typestr;

	switch (type)
	{
		case STYPE_DISKTREE: strcpy(typestr, "Disk"   ); break;
		case STYPE_PRINTQ  : strcpy(typestr, "Printer"); break;	      
		case STYPE_DEVICE  : strcpy(typestr, "Device" ); break;
		case STYPE_IPC     : strcpy(typestr, "IPC"    ); break;      
		default            : strcpy(typestr, "????"   ); break;      
	}
	return typestr;
}

/****************************************************************************
convert a server type enum to a string
****************************************************************************/
char *get_server_type_str(uint32 type)
{
	static fstring typestr;

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
	return typestr;
}

/****************************************************************************
server info level 101 display function
****************************************************************************/
void display_srv_info_101(FILE *out_hnd, enum display_type disp, enum action_type action,
		SRV_INFO_101 *sv101)
{
	if (sv101 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "Server Info Level 101:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring name;
			fstring comment;

			fstrcpy(name    , unistrn2(sv101->uni_name    .buffer, sv101->uni_name    .uni_str_len));
			fstrcpy(comment , unistrn2(sv101->uni_comment .buffer, sv101->uni_comment .uni_str_len));

			display_server(out_hnd, disp, action, name, sv101->srv_type, comment);

			fprintf(out_hnd, "\tplatform_id     : %d\n"    , sv101->platform_id);
			fprintf(out_hnd, "\tos version      : %d.%d\n" , sv101->ver_major, sv101->ver_minor);

			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}

}

/****************************************************************************
server info level 102 display function
****************************************************************************/
void display_srv_info_102(FILE *out_hnd, enum display_type disp, enum action_type action,SRV_INFO_102 *sv102)
{
	if (sv102 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "Server Info Level 102:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring name;
			fstring comment;
			fstring usr_path;

			fstrcpy(name    , unistrn2(sv102->uni_name    .buffer, sv102->uni_name    .uni_str_len));
			fstrcpy(comment , unistrn2(sv102->uni_comment .buffer, sv102->uni_comment .uni_str_len));
			fstrcpy(usr_path, unistrn2(sv102->uni_usr_path.buffer, sv102->uni_usr_path.uni_str_len));

			display_server(out_hnd, disp, action, name, sv102->srv_type, comment);

			fprintf(out_hnd, "\tplatform_id     : %d\n"    , sv102->platform_id);
			fprintf(out_hnd, "\tos version      : %d.%d\n" , sv102->ver_major, sv102->ver_minor);

			fprintf(out_hnd, "\tusers           : %x\n"    , sv102->users      );
			fprintf(out_hnd, "\tdisc, hidden    : %x,%x\n" , sv102->disc     , sv102->hidden   );
			fprintf(out_hnd, "\tannounce, delta : %d, %d\n", sv102->announce , sv102->ann_delta);
			fprintf(out_hnd, "\tlicenses        : %d\n"    , sv102->licenses   );
			fprintf(out_hnd, "\tuser path       : %s\n"    , usr_path);

			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
server info container display function
****************************************************************************/
void display_srv_info_ctr(FILE *out_hnd, enum display_type disp, enum action_type action,SRV_INFO_CTR *ctr)
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
			display_srv_info_101(out_hnd, disp, action, &(ctr->srv.sv101));
			break;
		}
		case 102:
		{
			display_srv_info_102(out_hnd, disp, action, &(ctr->srv.sv102));
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
connection info level 0 display function
****************************************************************************/
void display_conn_info_0(FILE *out_hnd, enum display_type disp, enum action_type action,
		CONN_INFO_0 *info0)
{
	if (info0 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "Connection Info Level 0:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fprintf(out_hnd, "\tid: %d\n", info0->id);

			break;
		}
		case ACTION_FOOTER:
		{
			fprintf(out_hnd, "\n");
			break;
		}
	}

}

/****************************************************************************
connection info level 1 display function
****************************************************************************/
void display_conn_info_1(FILE *out_hnd, enum display_type disp, enum action_type action,
		CONN_INFO_1 *info1, CONN_INFO_1_STR *str1)
{
	if (info1 == NULL || str1 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "Connection Info Level 1:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring usr_name;
			fstring net_name;

			fstrcpy(usr_name, unistrn2(str1->uni_usr_name.buffer, str1->uni_usr_name.uni_str_len));
			fstrcpy(net_name, unistrn2(str1->uni_net_name.buffer, str1->uni_net_name.uni_str_len));

			fprintf(out_hnd, "\tid       : %d\n", info1->id);
			fprintf(out_hnd, "\ttype     : %s\n", get_share_type_str(info1->type));
			fprintf(out_hnd, "\tnum_opens: %d\n", info1->num_opens);
			fprintf(out_hnd, "\tnum_users: %d\n", info1->num_users);
			fprintf(out_hnd, "\topen_time: %d\n", info1->open_time);

			fprintf(out_hnd, "\tuser name: %s\n", usr_name);
			fprintf(out_hnd, "\tnet  name: %s\n", net_name);

			break;
		}
		case ACTION_FOOTER:
		{
			fprintf(out_hnd, "\n");
			break;
		}
	}

}

/****************************************************************************
connection info level 0 container display function
****************************************************************************/
void display_srv_conn_info_0_ctr(FILE *out_hnd, enum display_type disp, enum action_type action,
				SRV_CONN_INFO_0 *ctr)
{
	if (ctr == NULL)
	{
		fprintf(out_hnd, "display_srv_conn_info_0_ctr: unavailable due to an internal error\n");
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

			for (i = 0; i < ctr->num_entries_read; i++)
			{
				display_conn_info_0(out_hnd, disp, ACTION_HEADER   , &(ctr->info_0[i]));
				display_conn_info_0(out_hnd, disp, ACTION_ENUMERATE, &(ctr->info_0[i]));
				display_conn_info_0(out_hnd, disp, ACTION_FOOTER   , &(ctr->info_0[i]));
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
connection info level 1 container display function
****************************************************************************/
void display_srv_conn_info_1_ctr(FILE *out_hnd, enum display_type disp, enum action_type action,
				SRV_CONN_INFO_1 *ctr)
{
	if (ctr == NULL)
	{
		fprintf(out_hnd, "display_srv_conn_info_1_ctr: unavailable due to an internal error\n");
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

			for (i = 0; i < ctr->num_entries_read; i++)
			{
				display_conn_info_1(out_hnd, disp, ACTION_HEADER   , &(ctr->info_1[i]), &(ctr->info_1_str[i]));
				display_conn_info_1(out_hnd, disp, ACTION_ENUMERATE, &(ctr->info_1[i]), &(ctr->info_1_str[i]));
				display_conn_info_1(out_hnd, disp, ACTION_FOOTER   , &(ctr->info_1[i]), &(ctr->info_1_str[i]));
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
void display_srv_conn_info_ctr(FILE *out_hnd, enum display_type disp, enum action_type action,
				SRV_CONN_INFO_CTR *ctr)
{
	if (ctr == NULL || ctr->ptr_conn_ctr == 0)
	{
		fprintf(out_hnd, "display_srv_conn_info_ctr: unavailable due to an internal error\n");
		return;
	}

	switch (ctr->switch_value)
	{
		case 0:
		{
			display_srv_conn_info_0_ctr(out_hnd, disp, action,
			                   &(ctr->conn.info0));
			break;
		}
		case 1:
		{
			display_srv_conn_info_1_ctr(out_hnd, disp, action,
			                   &(ctr->conn.info1));
			break;
		}
		default:
		{
			fprintf(out_hnd, "display_srv_conn_info_ctr: Unknown Info Level\n");
			break;
		}
	}
}


/****************************************************************************
share info level 1 display function
****************************************************************************/
void display_share_info_1(FILE *out_hnd, enum display_type disp, enum action_type action,
		SH_INFO_1 *info1, SH_INFO_1_STR *str1)
{
	if (info1 == NULL || str1 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "Share Info Level 1:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring remark  ;
			fstring net_name;

			fstrcpy(net_name, unistrn2(str1->uni_netname.buffer, str1->uni_netname.uni_str_len));
			fstrcpy(remark  , unistrn2(str1->uni_remark .buffer, str1->uni_remark .uni_str_len));

			display_share(out_hnd, disp, action, net_name, info1->type, remark);

			break;
		}
		case ACTION_FOOTER:
		{
			fprintf(out_hnd, "\n");
			break;
		}
	}

}

/****************************************************************************
share info level 1 container display function
****************************************************************************/
void display_srv_share_info_1_ctr(FILE *out_hnd, enum display_type disp, enum action_type action,
				SRV_SHARE_INFO_1 *ctr)
{
	if (ctr == NULL)
	{
		fprintf(out_hnd, "display_srv_share_info_1_ctr: unavailable due to an internal error\n");
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

			for (i = 0; i < ctr->num_entries_read; i++)
			{
				display_share_info_1(out_hnd, disp, ACTION_HEADER   , &(ctr->info_1[i]), &(ctr->info_1_str[i]));
				display_share_info_1(out_hnd, disp, ACTION_ENUMERATE, &(ctr->info_1[i]), &(ctr->info_1_str[i]));
				display_share_info_1(out_hnd, disp, ACTION_FOOTER   , &(ctr->info_1[i]), &(ctr->info_1_str[i]));
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
share info container display function
****************************************************************************/
void display_srv_share_info_ctr(FILE *out_hnd, enum display_type disp, enum action_type action,
				SRV_SHARE_INFO_CTR *ctr)
{
	if (ctr == NULL || ctr->ptr_share_ctr == 0)
	{
		fprintf(out_hnd, "display_srv_share_info_ctr: unavailable due to an internal error\n");
		return;
	}

	switch (ctr->switch_value)
	{
		case 1:
		{
			display_srv_share_info_1_ctr(out_hnd, disp, action,
			                   &(ctr->share.info1));
			break;
		}
		default:
		{
			fprintf(out_hnd, "display_srv_share_info_ctr: Unknown Info Level\n");
			break;
		}
	}
}


/****************************************************************************
file info level 3 display function
****************************************************************************/
void display_file_info_3(FILE *out_hnd, enum display_type disp, enum action_type action,
		FILE_INFO_3 *info3, FILE_INFO_3_STR *str3)
{
	if (info3 == NULL || str3 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "File Info Level 3:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring path_name;
			fstring user_name;

			fstrcpy(path_name, unistrn2(str3->uni_path_name.buffer, str3->uni_path_name.uni_str_len));
			fstrcpy(user_name, unistrn2(str3->uni_user_name.buffer, str3->uni_user_name.uni_str_len));

			fprintf(out_hnd, "\tid       : %d\n", info3->id);
			fprintf(out_hnd, "\tperms    : %s\n", get_file_mode_str(info3->perms));
			fprintf(out_hnd, "\tnum_locks: %d\n", info3->num_locks);

			fprintf(out_hnd, "\tpath name: %s\n", path_name);
			fprintf(out_hnd, "\tuser name: %s\n", user_name);

			break;
		}
		case ACTION_FOOTER:
		{
			fprintf(out_hnd, "\n");
			break;
		}
	}

}

/****************************************************************************
file info level 3 container display function
****************************************************************************/
void display_srv_file_info_3_ctr(FILE *out_hnd, enum display_type disp, enum action_type action,
				SRV_FILE_INFO_3 *ctr)
{
	if (ctr == NULL)
	{
		fprintf(out_hnd, "display_srv_file_info_3_ctr: unavailable due to an internal error\n");
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

			for (i = 0; i < ctr->num_entries_read; i++)
			{
				display_file_info_3(out_hnd, disp, ACTION_HEADER   , &(ctr->info_3[i]), &(ctr->info_3_str[i]));
				display_file_info_3(out_hnd, disp, ACTION_ENUMERATE, &(ctr->info_3[i]), &(ctr->info_3_str[i]));
				display_file_info_3(out_hnd, disp, ACTION_FOOTER   , &(ctr->info_3[i]), &(ctr->info_3_str[i]));
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
file info container display function
****************************************************************************/
void display_srv_file_info_ctr(FILE *out_hnd, enum display_type disp, enum action_type action,
				SRV_FILE_INFO_CTR *ctr)
{
	if (ctr == NULL || ctr->ptr_file_ctr == 0)
	{
		fprintf(out_hnd, "display_srv_file_info_ctr: unavailable due to an internal error\n");
		return;
	}

	switch (ctr->switch_value)
	{
		case 3:
		{
			display_srv_file_info_3_ctr(out_hnd, disp, action,
			                   &(ctr->file.info3));
			break;
		}
		default:
		{
			fprintf(out_hnd, "display_srv_file_info_ctr: Unknown Info Level\n");
			break;
		}
	}
}

/****************************************************************************
 print browse connection on a host
 ****************************************************************************/
void display_server(FILE *out_hnd, enum display_type disp, enum action_type action,
				char *sname, uint32 type, char *comment)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			fprintf(out_hnd, "\t%-15.15s%-20s %s\n",
			                 sname, get_server_type_str(type), comment);
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
print browse connection on a host
****************************************************************************/
void display_share(FILE *out_hnd, enum display_type disp, enum action_type action,
				char *sname, uint32 type, char *comment)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			fprintf(out_hnd, "\t%-15.15s%-10.10s%s\n",
			                 sname, get_share_type_str(type), comment);
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}


/****************************************************************************
 display group rid info
 ****************************************************************************/
void display_group_rid_info(FILE *out_hnd, enum display_type disp, enum action_type action,
				uint32 num_gids, DOM_GID *gid)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			if (num_gids == 0)
			{
				fprintf(out_hnd, "\tNo Groups\n");
			}
			else
			{
				fprintf(out_hnd, "\tGroup Info\n");
				fprintf(out_hnd, "\t----------\n");
			}
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < num_gids; i++)
			{
				fprintf(out_hnd, "\tGroup RID: %8x attr: %x\n",
								  gid[i].g_rid, gid[i].attr);
			}

			break;
		}
		case ACTION_FOOTER:
		{
			fprintf(out_hnd, "\n");
			break;
		}
	}
}


/****************************************************************************
 display alias name info
 ****************************************************************************/
void display_alias_name_info(FILE *out_hnd, enum display_type disp, enum action_type action,
				uint32 num_aliases, fstring *alias_name, uint32 *num_als_usrs)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			if (num_aliases == 0)
			{
				fprintf(out_hnd, "\tNo Aliases\n");
			}
			else
			{
				fprintf(out_hnd, "\tAlias Names\n");
				fprintf(out_hnd, "\t----------- \n");
			}
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < num_aliases; i++)
			{
				fprintf(out_hnd, "\tAlias Name: %s Attributes: %3d\n",
								  alias_name[i], num_als_usrs[i]);
			}

			break;
		}
		case ACTION_FOOTER:
		{
			fprintf(out_hnd, "\n");
			break;
		}
	}
}


/****************************************************************************
 display sam_user_info_15 structure
 ****************************************************************************/
void display_sam_user_info_15(FILE *out_hnd, enum display_type disp, enum action_type action, SAM_USER_INFO_15 *usr)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "\tUser Info, Level 0x15\n");
			fprintf(out_hnd, "\t---------------------\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
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

			break;
		}
		case ACTION_FOOTER:
		{
			fprintf(out_hnd, "\n");
			break;
		}
	}
}

