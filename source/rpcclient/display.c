/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996 - 1998
   
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


struct field_info sid_name_info[] =
{
	{ SID_NAME_UNKNOWN, "UNKNOWN"         }, /* default */
	{ SID_NAME_USER   , "User"            },
	{ SID_NAME_DOM_GRP, "Domain Group"    },
	{ SID_NAME_DOMAIN , "Domain"          },
	{ SID_NAME_ALIAS  , "Local Group"     },
	{ SID_NAME_WKN_GRP, "Well-known Group"},
	{ SID_NAME_DELETED, "Deleted"         },
	{ SID_NAME_INVALID, "Invalid"         },
	{ 0               , NULL }
};

/****************************************************************************
convert a SID_NAME_USE to a string 
****************************************************************************/
char *get_sid_name_use_str(uint8 sid_name_use)
{
	return enum_field_to_str((uint32)sid_name_use, sid_name_info, True);
}

/****************************************************************************
convert a share mode to a string
****************************************************************************/
char *get_file_mode_str(uint32 share_mode)
{
	static fstring mode;

	switch ((share_mode>>4)&0xF)
	{
		case DENY_NONE : fstrcpy(mode, "DENY_NONE  "); break;
		case DENY_ALL  : fstrcpy(mode, "DENY_ALL   "); break;
		case DENY_DOS  : fstrcpy(mode, "DENY_DOS   "); break;
		case DENY_READ : fstrcpy(mode, "DENY_READ  "); break;
		case DENY_WRITE: fstrcpy(mode, "DENY_WRITE "); break;
		default        : fstrcpy(mode, "DENY_????  "); break;
	}

	switch (share_mode & 0xF)
	{
		case 0 : fstrcat(mode, "RDONLY"); break;
		case 1 : fstrcat(mode, "WRONLY"); break;
		case 2 : fstrcat(mode, "RDWR  "); break;
		default: fstrcat(mode, "R??W??"); break;
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

	if (excl           ) fstrcat(oplock, "EXCLUSIVE");
	if (excl  &&  batch) fstrcat(oplock, "+");
	if (          batch) fstrcat(oplock, "BATCH");
	if (!excl && !batch) fstrcat(oplock, "NONE");

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
		case STYPE_DISKTREE: fstrcpy(typestr, "Disk"   ); break;
		case STYPE_PRINTQ  : fstrcpy(typestr, "Printer"); break;	      
		case STYPE_DEVICE  : fstrcpy(typestr, "Device" ); break;
		case STYPE_IPC     : fstrcpy(typestr, "IPC"    ); break;      
		default            : fstrcpy(typestr, "????"   ); break;      
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
		fstrcpy(typestr, "All");
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
					case SV_TYPE_WORKSTATION      : fstrcat(typestr, "Wk " ); break;
					case SV_TYPE_SERVER           : fstrcat(typestr, "Sv " ); break;
					case SV_TYPE_SQLSERVER        : fstrcat(typestr, "Sql "); break;
					case SV_TYPE_DOMAIN_CTRL      : fstrcat(typestr, "PDC "); break;
					case SV_TYPE_DOMAIN_BAKCTRL   : fstrcat(typestr, "BDC "); break;
					case SV_TYPE_TIME_SOURCE      : fstrcat(typestr, "Tim "); break;
					case SV_TYPE_AFP              : fstrcat(typestr, "AFP "); break;
					case SV_TYPE_NOVELL           : fstrcat(typestr, "Nov "); break;
					case SV_TYPE_DOMAIN_MEMBER    : fstrcat(typestr, "Dom "); break;
					case SV_TYPE_PRINTQ_SERVER    : fstrcat(typestr, "PrQ "); break;
					case SV_TYPE_DIALIN_SERVER    : fstrcat(typestr, "Din "); break;
					case SV_TYPE_SERVER_UNIX      : fstrcat(typestr, "Unx "); break;
					case SV_TYPE_NT               : fstrcat(typestr, "NT " ); break;
					case SV_TYPE_WFW              : fstrcat(typestr, "Wfw "); break;
					case SV_TYPE_SERVER_MFPN      : fstrcat(typestr, "Mfp "); break;
					case SV_TYPE_SERVER_NT        : fstrcat(typestr, "SNT "); break;
					case SV_TYPE_POTENTIAL_BROWSER: fstrcat(typestr, "PtB "); break;
					case SV_TYPE_BACKUP_BROWSER   : fstrcat(typestr, "BMB "); break;
					case SV_TYPE_MASTER_BROWSER   : fstrcat(typestr, "LMB "); break;
					case SV_TYPE_DOMAIN_MASTER    : fstrcat(typestr, "DMB "); break;
					case SV_TYPE_SERVER_OSF       : fstrcat(typestr, "OSF "); break;
					case SV_TYPE_SERVER_VMS       : fstrcat(typestr, "VMS "); break;
					case SV_TYPE_WIN95_PLUS       : fstrcat(typestr, "W95 "); break;
					case SV_TYPE_ALTERNATE_XPORT  : fstrcat(typestr, "Xpt "); break;
					case SV_TYPE_LOCAL_LIST_ONLY  : fstrcat(typestr, "Dom "); break;
					case SV_TYPE_DOMAIN_ENUM      : fstrcat(typestr, "Loc "); break;
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
void display_srv_info_101(FILE *out_hnd, enum action_type action,
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

			unistr2_to_ascii(name, &sv101->uni_name, sizeof(name)-1);
			unistr2_to_ascii(comment, &sv101->uni_comment, sizeof(comment)-1);

			display_server(out_hnd, action, name, sv101->srv_type, comment);

			fprintf(out_hnd, "\tplatform_id     :\t%d\n"    , sv101->platform_id);
			fprintf(out_hnd, "\tos version      :\t%d.%d\n" , sv101->ver_major, sv101->ver_minor);

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
void display_srv_info_102(FILE *out_hnd, enum action_type action,SRV_INFO_102 *sv102)
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

			unistr2_to_ascii(name, &sv102->uni_name, sizeof(name)-1);
			unistr2_to_ascii(comment, &sv102->uni_comment, sizeof(comment)-1);
			unistr2_to_ascii(usr_path, &sv102->uni_usr_path,
					 sizeof(usr_path)-1);

			display_server(out_hnd, action, name, sv102->srv_type, comment);

			fprintf(out_hnd, "\tplatform_id     :\t%d\n"    , sv102->platform_id);
			fprintf(out_hnd, "\tos version      :\t%d.%d\n" , sv102->ver_major, sv102->ver_minor);

			fprintf(out_hnd, "\tusers           :\t%x\n"    , sv102->users      );
			fprintf(out_hnd, "\tdisc, hidden    :\t%x,%x\n" , sv102->disc     , sv102->hidden   );
			fprintf(out_hnd, "\tannounce, delta :\t%d, %d\n", sv102->announce , sv102->ann_delta);
			fprintf(out_hnd, "\tlicenses        :\t%d\n"    , sv102->licenses   );
			fprintf(out_hnd, "\tuser path       :\t%s\n"    , usr_path);

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
void display_srv_info_ctr(FILE *out_hnd, enum action_type action,SRV_INFO_CTR *ctr)
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
			display_srv_info_101(out_hnd, action, &(ctr->srv.sv101));
			break;
		}
		case 102:
		{
			display_srv_info_102(out_hnd, action, &(ctr->srv.sv102));
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
void display_conn_info_0(FILE *out_hnd, enum action_type action,
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
			fprintf(out_hnd, "\tid:\t%d\n", info0->id);

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
void display_conn_info_1(FILE *out_hnd, enum action_type action,
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

			unistr2_to_ascii(usr_name, &str1->uni_usr_name, sizeof(usr_name)-1);
			unistr2_to_ascii(net_name, &str1->uni_net_name, sizeof(net_name)-1);

			fprintf(out_hnd, "\tid       :\t%d\n", info1->id);
			fprintf(out_hnd, "\ttype     :\t%s\n", get_share_type_str(info1->type));
			fprintf(out_hnd, "\tnum_opens:\t%d\n", info1->num_opens);
			fprintf(out_hnd, "\tnum_users:\t%d\n", info1->num_users);
			fprintf(out_hnd, "\topen_time:\t%d\n", info1->open_time);

			fprintf(out_hnd, "\tuser name:\t%s\n", usr_name);
			fprintf(out_hnd, "\tnet  name:\t%s\n", net_name);

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
void display_srv_conn_info_0_ctr(FILE *out_hnd, enum action_type action,
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
				display_conn_info_0(out_hnd, ACTION_HEADER   , &(ctr->info_0[i]));
				display_conn_info_0(out_hnd, ACTION_ENUMERATE, &(ctr->info_0[i]));
				display_conn_info_0(out_hnd, ACTION_FOOTER   , &(ctr->info_0[i]));
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
void display_srv_conn_info_1_ctr(FILE *out_hnd, enum action_type action,
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
				display_conn_info_1(out_hnd, ACTION_HEADER   , &(ctr->info_1[i]), &(ctr->info_1_str[i]));
				display_conn_info_1(out_hnd, ACTION_ENUMERATE, &(ctr->info_1[i]), &(ctr->info_1_str[i]));
				display_conn_info_1(out_hnd, ACTION_FOOTER   , &(ctr->info_1[i]), &(ctr->info_1_str[i]));
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
void display_srv_conn_info_ctr(FILE *out_hnd, enum action_type action,
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
			display_srv_conn_info_0_ctr(out_hnd, action,
			                   &(ctr->conn.info0));
			break;
		}
		case 1:
		{
			display_srv_conn_info_1_ctr(out_hnd, action,
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
void display_share_info_1(FILE *out_hnd, enum action_type action,
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

			unistr2_to_ascii(net_name, &str1->uni_netname, sizeof(net_name)-1);
			unistr2_to_ascii(remark, &str1->uni_remark, sizeof(remark)-1);

			display_share(out_hnd, action, net_name, info1->type, remark);

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
share info level 2 display function
****************************************************************************/
void display_share_info_2(FILE *out_hnd, enum action_type action,
		SH_INFO_2 *info2, SH_INFO_2_STR *str2)
{
	if (info2 == NULL || str2 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "Share Info Level 2:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring remark  ;
			fstring net_name;
			fstring path    ;
			fstring passwd  ;

			unistr2_to_ascii(net_name, &str2->uni_netname, sizeof(net_name)-1);
			unistr2_to_ascii(remark, &str2->uni_remark, sizeof(remark)-1);
			unistr2_to_ascii(path, &str2->uni_path, sizeof(path)-1);
			unistr2_to_ascii(passwd, &str2->uni_passwd, sizeof(passwd)-1);

			display_share2(out_hnd, action, net_name, info2->type, remark,
			                                      info2->perms, info2->max_uses, info2->num_uses,
			                                      path, passwd);

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
void display_srv_share_info_1_ctr(FILE *out_hnd, enum action_type action,
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
				display_share_info_1(out_hnd, ACTION_HEADER   , &(ctr->info_1[i]), &(ctr->info_1_str[i]));
				display_share_info_1(out_hnd, ACTION_ENUMERATE, &(ctr->info_1[i]), &(ctr->info_1_str[i]));
				display_share_info_1(out_hnd, ACTION_FOOTER   , &(ctr->info_1[i]), &(ctr->info_1_str[i]));
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
share info level 2 container display function
****************************************************************************/
void display_srv_share_info_2_ctr(FILE *out_hnd, enum action_type action,
				SRV_SHARE_INFO_2 *ctr)
{
	if (ctr == NULL)
	{
		fprintf(out_hnd, "display_srv_share_info_2_ctr: unavailable due to an internal error\n");
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
				display_share_info_2(out_hnd, ACTION_HEADER   , &(ctr->info_2[i]), &(ctr->info_2_str[i]));
				display_share_info_2(out_hnd, ACTION_ENUMERATE, &(ctr->info_2[i]), &(ctr->info_2_str[i]));
				display_share_info_2(out_hnd, ACTION_FOOTER   , &(ctr->info_2[i]), &(ctr->info_2_str[i]));
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
void display_srv_share_info_ctr(FILE *out_hnd, enum action_type action,
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
			display_srv_share_info_1_ctr(out_hnd, action,
			                   &(ctr->share.info1));
			break;
		}
		case 2:
		{
			display_srv_share_info_2_ctr(out_hnd, action,
			                   &(ctr->share.info2));
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
void display_file_info_3(FILE *out_hnd, enum action_type action,
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

			unistr2_to_ascii(path_name, &str3->uni_path_name,
					 sizeof(path_name)-1);
			unistr2_to_ascii(user_name, &str3->uni_user_name,
					 sizeof(user_name)-1);

			fprintf(out_hnd, "\tid       :\t%d\n", info3->id);
			fprintf(out_hnd, "\tperms    :\t%s\n", get_file_mode_str(info3->perms));
			fprintf(out_hnd, "\tnum_locks:\t%d\n", info3->num_locks);

			fprintf(out_hnd, "\tpath name:\t%s\n", path_name);
			fprintf(out_hnd, "\tuser name:\t%s\n", user_name);

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
void display_srv_file_info_3_ctr(FILE *out_hnd, enum action_type action,
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
				display_file_info_3(out_hnd, ACTION_HEADER   , &(ctr->info_3[i]), &(ctr->info_3_str[i]));
				display_file_info_3(out_hnd, ACTION_ENUMERATE, &(ctr->info_3[i]), &(ctr->info_3_str[i]));
				display_file_info_3(out_hnd, ACTION_FOOTER   , &(ctr->info_3[i]), &(ctr->info_3_str[i]));
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
void display_srv_file_info_ctr(FILE *out_hnd, enum action_type action,
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
			display_srv_file_info_3_ctr(out_hnd, action,
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
sess info level 0 display function
****************************************************************************/
void display_sess_info_0(FILE *out_hnd, enum action_type action,
		SESS_INFO_0 *info0, SESS_INFO_0_STR *str0)
{
	if (info0 == NULL || str0 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "Session Info Level 0:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring name;

			unistr2_to_ascii(name, &str0->uni_name,
					 sizeof(name)-1);

			fprintf(out_hnd, "\tname:\t%s\n", name);

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
sess info level 1 display function
****************************************************************************/
void display_sess_info_1(FILE *out_hnd, enum action_type action,
		SESS_INFO_1 *info1, SESS_INFO_1_STR *str1)
{
	if (info1 == NULL || str1 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "Session Info Level 1:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring name;
			fstring user_name;

			unistr2_to_ascii(user_name, &str1->uni_user,
					 sizeof(user_name)-1);
			unistr2_to_ascii(name, &str1->uni_name,
					 sizeof(name)-1);

			fprintf(out_hnd, "\tname:\t%s\n", name);

			fprintf(out_hnd, "\topen :\t%d\n", info1->num_opens);
			fprintf(out_hnd, "\ttime :\t%d\n", info1->open_time);
			fprintf(out_hnd, "\tidle :\t%d\n", info1->idle_time);
			fprintf(out_hnd, "\tflags:\t%d\n", info1->user_flags);

			fprintf(out_hnd, "\tuser :\t%s\n", user_name);

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
sess info level 0 container display function
****************************************************************************/
void display_srv_sess_info_0_ctr(FILE *out_hnd, enum action_type action,
				SRV_SESS_INFO_0 *ctr)
{
	if (ctr == NULL)
	{
		fprintf(out_hnd, "display_srv_sess_info_0_ctr: unavailable due to an internal error\n");
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
				display_sess_info_0(out_hnd, ACTION_HEADER   , &(ctr->info_0[i]), &(ctr->info_0_str[i]));
				display_sess_info_0(out_hnd, ACTION_ENUMERATE, &(ctr->info_0[i]), &(ctr->info_0_str[i]));
				display_sess_info_0(out_hnd, ACTION_FOOTER   , &(ctr->info_0[i]), &(ctr->info_0_str[i]));
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
sess info level 1 container display function
****************************************************************************/
void display_srv_sess_info_1_ctr(FILE *out_hnd, enum action_type action,
				SRV_SESS_INFO_1 *ctr)
{
	if (ctr == NULL)
	{
		fprintf(out_hnd, "display_srv_sess_info_1_ctr: unavailable due to an internal error\n");
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
				display_sess_info_1(out_hnd, ACTION_HEADER   , &(ctr->info_1[i]), &(ctr->info_1_str[i]));
				display_sess_info_1(out_hnd, ACTION_ENUMERATE, &(ctr->info_1[i]), &(ctr->info_1_str[i]));
				display_sess_info_1(out_hnd, ACTION_FOOTER   , &(ctr->info_1[i]), &(ctr->info_1_str[i]));
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
sess info container display function
****************************************************************************/
void display_srv_sess_info_ctr(FILE *out_hnd, enum action_type action,
				SRV_SESS_INFO_CTR *ctr)
{
	if (ctr == NULL || ctr->ptr_sess_ctr == 0)
	{
		fprintf(out_hnd, "display_srv_sess_info_ctr: unavailable due to an internal error\n");
		return;
	}

	switch (ctr->switch_value)
	{
		case 0:
		{
			display_srv_sess_info_0_ctr(out_hnd, action,
			                   &(ctr->sess.info0));
			break;
		}
		case 1:
		{
			display_srv_sess_info_1_ctr(out_hnd, action,
			                   &(ctr->sess.info1));
			break;
		}
		default:
		{
			fprintf(out_hnd, "display_srv_sess_info_ctr: Unknown Info Level\n");
			break;
		}
	}
}

/****************************************************************************
 print browse connection on a host
 ****************************************************************************/
void display_server(FILE *out_hnd, enum action_type action,
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
print shares on a host
****************************************************************************/
void display_share(FILE *out_hnd, enum action_type action,
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
print shares on a host, level 2
****************************************************************************/
void display_share2(FILE *out_hnd, enum action_type action,
				char *sname, uint32 type, char *comment,
				uint32 perms, uint32 max_uses, uint32 num_uses,
				char *path, char *passwd)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			fprintf(out_hnd, "\t%-15.15s%-10.10s%s %x %x %x %s %s\n",
			                 sname, get_share_type_str(type), comment,
			                 perms, max_uses, num_uses, path, passwd);
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}


/****************************************************************************
print name info
****************************************************************************/
void display_name(FILE *out_hnd, enum action_type action,
				char *sname)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			fprintf(out_hnd, "\t%-21.21s\n", sname);
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}


/****************************************************************************
 display alias members
 ****************************************************************************/
void display_alias_members(FILE *out_hnd, enum action_type action,
				uint32 num_mem, char **sid_mem)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			if (num_mem == 0)
			{
				fprintf(out_hnd, "\tNo Alias Members\n");
			}
			else
			{
				fprintf(out_hnd, "\tAlias Members:\n");
				fprintf(out_hnd, "\t-------------\n");
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
					fprintf(out_hnd, "\tMember Name:\t%s\n", sid_mem[i]);
				}
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
 display alias rid info
 ****************************************************************************/
void display_alias_rid_info(FILE *out_hnd, enum action_type action,
				DOM_SID *sid,
				uint32 num_rids, uint32 *rid)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			fstring sid_str;
			sid_to_string(sid_str, sid);
			if (num_rids == 0)
			{
				fprintf(out_hnd, "\tNo Aliases:\tSid %s\n", sid_str);
			}
			else
			{
				fprintf(out_hnd, "\tAlias Info:\tSid %s\n", sid_str);
				fprintf(out_hnd, "\t----------\n");
			}
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < num_rids; i++)
			{
				fprintf(out_hnd, "\tAlias RID:\t%8x\n", rid[i]);
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
 display group members
 ****************************************************************************/
void display_group_members(FILE *out_hnd, enum action_type action,
				uint32 num_mem, char **name, uint32 *type)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			if (num_mem == 0)
			{
				fprintf(out_hnd, "\tNo Members\n");
			}
			else
			{
				fprintf(out_hnd, "\tMembers:\n");
				fprintf(out_hnd, "\t-------\n");
			}
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < num_mem; i++)
			{
				fprintf(out_hnd, "\tMember Name:\t%s\tType:\t%s\n",
				        name[i], get_sid_name_use_str(type[i]));
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
 display group info
 ****************************************************************************/
void display_group_info1(FILE *out_hnd, enum action_type action, GROUP_INFO1 *info1)
				
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
			fprintf(out_hnd, "\tGroup Name:\t%s\n", temp);
			unistr2_to_ascii(temp, &info1->uni_acct_desc, sizeof(temp)-1);
			fprintf(out_hnd, "\tDescription:\t%s\n", temp);
			fprintf(out_hnd, "\tunk1:%d\n", info1->unknown_1);
			fprintf(out_hnd, "\tNum Members:%d\n", info1->num_members);
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
void display_group_info4(FILE *out_hnd, enum action_type action, GROUP_INFO4 *info4)
				
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
			fprintf(out_hnd, "\tGroup Description:%s\n",
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
				GROUP_INFO_CTR *ctr)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "\tSAM Group Info\n"); 
			fprintf(out_hnd, "\t--------------\n");

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
			fprintf(out_hnd, "\n");
			break;
		}
	}
}

/****************************************************************************
 display group rid info
 ****************************************************************************/
void display_group_rid_info(FILE *out_hnd, enum action_type action,
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
				fprintf(out_hnd, "\tGroup RID:\t%8x attr:\t%x\n",
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
void display_alias_name_info(FILE *out_hnd, enum action_type action,
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
				fprintf(out_hnd, "\tAlias Name:\t%s Attributes:\t%3d\n",
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
 display sam_user_info_21 structure
 ****************************************************************************/
void display_sam_user_info_21(FILE *out_hnd, enum action_type action, SAM_USER_INFO_21 *usr)
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
			fstring temp;

			unistr2_to_ascii(temp, &usr->uni_user_name, sizeof(temp)-1);
			fprintf(out_hnd, "\t\tUser Name   :\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_full_name, sizeof(temp)-1);
			fprintf(out_hnd, "\t\tFull Name   :\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_home_dir, sizeof(temp)-1);
			fprintf(out_hnd, "\t\tHome Drive  :\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_dir_drive, sizeof(temp)-1);
			fprintf(out_hnd, "\t\tDir Drive   :\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_profile_path, sizeof(temp)-1);
			fprintf(out_hnd, "\t\tProfile Path:\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_logon_script, sizeof(temp)-1);
			fprintf(out_hnd, "\t\tLogon Script:\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_acct_desc, sizeof(temp)-1);
			fprintf(out_hnd, "\t\tDescription :\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_workstations, sizeof(temp)-1);
			fprintf(out_hnd, "\t\tWorkstations:\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_unknown_str, sizeof(temp)-1);
			fprintf(out_hnd, "\t\tUnknown Str :\t%s\n", temp);

			unistr2_to_ascii(temp, &usr->uni_munged_dial, sizeof(temp)-1);
			fprintf(out_hnd, "\t\tRemote Dial :\t%s\n", temp);

			fprintf(out_hnd, "\t\tLogon Time               :\t%s\n", http_timestring(nt_time_to_unix(&(usr->logon_time           ))));
			fprintf(out_hnd, "\t\tLogoff Time              :\t%s\n", http_timestring(nt_time_to_unix(&(usr->logoff_time          ))));
			fprintf(out_hnd, "\t\tKickoff Time             :\t%s\n", http_timestring(nt_time_to_unix(&(usr->kickoff_time         ))));
			fprintf(out_hnd, "\t\tPassword last set Time   :\t%s\n", http_timestring(nt_time_to_unix(&(usr->pass_last_set_time   ))));
			fprintf(out_hnd, "\t\tPassword can change Time :\t%s\n", http_timestring(nt_time_to_unix(&(usr->pass_can_change_time ))));
			fprintf(out_hnd, "\t\tPassword must change Time:\t%s\n", http_timestring(nt_time_to_unix(&(usr->pass_must_change_time))));
			
			fprintf(out_hnd, "\t\tunknown_2[0..31]...\n"); /* user passwords? */

			fprintf(out_hnd, "\t\tuser_rid :\t%x\n"  , usr->user_rid ); /* User ID */
			fprintf(out_hnd, "\t\tgroup_rid:\t%x\n"  , usr->group_rid); /* Group ID */
			fprintf(out_hnd, "\t\tacb_info :\t%04x\n", usr->acb_info ); /* Account Control Info */

			fprintf(out_hnd, "\t\tunknown_3:\t%08x\n", usr->unknown_3); /* 0x00ff ffff */
			fprintf(out_hnd, "\t\tlogon_divs:\t%d\n", usr->logon_divs); /* 0x0000 00a8 which is 168 which is num hrs in a week */
			fprintf(out_hnd, "\t\tunknown_5:\t%08x\n", usr->unknown_5); /* 0x0002 0000 */

			fprintf(out_hnd, "\t\tpadding1[0..7]...\n");

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


/****************************************************************************
convert a security permissions into a string
****************************************************************************/
char *get_sec_mask_str(uint32 type)
{
	static fstring typestr;
	int i;

	switch (type)
	{
		case SEC_RIGHTS_FULL_CONTROL:
		{
			fstrcpy(typestr, "Full Control");
			return typestr;
		}

		case SEC_RIGHTS_READ:
		{
			fstrcpy(typestr, "Read");
			return typestr;
		}
		default:
		{
			break;
		}
	}

	typestr[0] = 0;
	for (i = 0; i < 32; i++)
	{
		if (IS_BITS_SET_ALL(type, 1 << i))
		{
			switch (1 << i)
			{
				case SEC_RIGHTS_QUERY_VALUE    : fstrcat(typestr, "Query " ); break;
				case SEC_RIGHTS_SET_VALUE      : fstrcat(typestr, "Set " ); break;
				case SEC_RIGHTS_CREATE_SUBKEY  : fstrcat(typestr, "Create "); break;
				case SEC_RIGHTS_ENUM_SUBKEYS   : fstrcat(typestr, "Enum "); break;
				case SEC_RIGHTS_NOTIFY         : fstrcat(typestr, "Notify "); break;
				case SEC_RIGHTS_CREATE_LINK    : fstrcat(typestr, "CreateLink "); break;
				case SEC_RIGHTS_DELETE         : fstrcat(typestr, "Delete "); break;
				case SEC_RIGHTS_READ_CONTROL   : fstrcat(typestr, "ReadControl "); break;
				case SEC_RIGHTS_WRITE_DAC      : fstrcat(typestr, "WriteDAC "); break;
				case SEC_RIGHTS_WRITE_OWNER    : fstrcat(typestr, "WriteOwner "); break;
			}
			type &= ~(1 << i);
		}
	}

	/* remaining bits get added on as-is */
	if (type != 0)
	{
		fstring tmp;
		slprintf(tmp, sizeof(tmp)-1, "[%08x]", type);
		fstrcat(typestr, tmp);
	}

	/* remove last space */
	i = strlen(typestr)-1;
	if (typestr[i] == ' ') typestr[i] = 0;

	return typestr;
}

/****************************************************************************
 display sec_access structure
 ****************************************************************************/
void display_sec_access(FILE *out_hnd, enum action_type action, SEC_ACCESS *info)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			fprintf(out_hnd, "\t\tPermissions:\t%s\n",
			        get_sec_mask_str(info->mask));
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
 display sec_ace structure
 ****************************************************************************/
void display_sec_ace(FILE *out_hnd, enum action_type action, SEC_ACE *ace)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "\tACE\n");
			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring sid_str;

			display_sec_access(out_hnd, ACTION_HEADER   , &ace->info);
			display_sec_access(out_hnd, ACTION_ENUMERATE, &ace->info);
			display_sec_access(out_hnd, ACTION_FOOTER   , &ace->info);

			sid_to_string(sid_str, &ace->sid);
			fprintf(out_hnd, "\t\tSID:\t%s\n", sid_str);
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
 display sec_acl structure
 ****************************************************************************/
void display_sec_acl(FILE *out_hnd, enum action_type action, SEC_ACL *sec_acl)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "\tACL\tNum ACEs:\t%d\trevision:\t%x\n",
			                 sec_acl->num_aces, sec_acl->revision); 
			fprintf(out_hnd, "\t---\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			if (sec_acl->size != 0 && sec_acl->num_aces != 0)
			{
				int i;
				for (i = 0; i < sec_acl->num_aces; i++)
				{
					display_sec_ace(out_hnd, ACTION_HEADER   , &sec_acl->ace[i]);
					display_sec_ace(out_hnd, ACTION_ENUMERATE, &sec_acl->ace[i]);
					display_sec_ace(out_hnd, ACTION_FOOTER   , &sec_acl->ace[i]);
				}
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
 display sec_desc structure
 ****************************************************************************/
void display_sec_desc(FILE *out_hnd, enum action_type action, SEC_DESC *sec)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "\tSecurity Descriptor\trevision:\t%x\ttype:\t%x\n",
			                 sec->revision, sec->type); 
			fprintf(out_hnd, "\t-------------------\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring sid_str;

			if (sec->off_sacl != 0)
			{
				display_sec_acl(out_hnd, ACTION_HEADER   , sec->sacl);
				display_sec_acl(out_hnd, ACTION_ENUMERATE, sec->sacl);
				display_sec_acl(out_hnd, ACTION_FOOTER   , sec->sacl);
			}
			if (sec->off_dacl != 0)
			{
				display_sec_acl(out_hnd, ACTION_HEADER   , sec->dacl);
				display_sec_acl(out_hnd, ACTION_ENUMERATE, sec->dacl);
				display_sec_acl(out_hnd, ACTION_FOOTER   , sec->dacl);
			}
			if (sec->off_owner_sid != 0)
			{
				sid_to_string(sid_str, sec->owner_sid);
				fprintf(out_hnd, "\tOwner SID:\t%s\n", sid_str);
			}
			if (sec->off_grp_sid != 0)
			{
				sid_to_string(sid_str, sec->grp_sid);
				fprintf(out_hnd, "\tParent SID:\t%s\n", sid_str);
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
convert a security permissions into a string
****************************************************************************/
char *get_reg_val_type_str(uint32 type)
{
	static fstring typestr;

	switch (type)
	{
		case 0x01:
		{
			fstrcpy(typestr, "string");
			return typestr;
		}

		case 0x03:
		{
			fstrcpy(typestr, "bytes");
			return typestr;
		}

		case 0x04:
		{
			fstrcpy(typestr, "uint32");
			return typestr;
		}

		case 0x07:
		{
			fstrcpy(typestr, "multi");
			return typestr;
		}
		default:
		{
			break;
		}
	}
	slprintf(typestr, sizeof(typestr)-1, "[%d]", type);
	return typestr;
}


static void print_reg_value(FILE *out_hnd, char *val_name, uint32 val_type, BUFFER2 *value)
{
	fstring type;
	fstring valstr;

	fstrcpy(type, get_reg_val_type_str(val_type));

	switch (val_type)
	{
		case 0x01: /* unistr */
		{
			unibuf_to_ascii(valstr, value->buffer,
					MIN(value->buf_len, sizeof(valstr)-1));
			fprintf(out_hnd,"\t%s:\t%s:\t%s\n", val_name, type, valstr);
			break;
		}

		default: /* unknown */
		case 0x03: /* bytes */
		{
			if (value->buf_len <= 8)
			{
				fprintf(out_hnd,"\t%s:\t%s:\t", val_name, type);
				out_data(out_hnd, (char*)value->buffer, value->buf_len, 8);
			}
			else
			{
				fprintf(out_hnd,"\t%s:\t%s:\n", val_name, type);
				out_data(out_hnd, (char*)value->buffer, value->buf_len, 16);
			}
			break;
		}

		case 0x04: /* uint32 */
		{
			fprintf(out_hnd,"\t%s:\t%s:\t0x%08x\n", val_name, type, buffer2_to_uint32(value));
			break;
		}

		case 0x07: /* multiunistr */
		{
			buffer2_to_multistr(valstr, value, sizeof(valstr)-1);
			fprintf(out_hnd,"\t%s:\t%s:\t%s\n", val_name, type, valstr);
			break;
		}
	}
}

/****************************************************************************
 display structure
 ****************************************************************************/
void display_reg_value_info(FILE *out_hnd, enum action_type action,
				char *val_name, uint32 val_type, BUFFER2 *value)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			print_reg_value(out_hnd, val_name, val_type, value);
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
 display structure
 ****************************************************************************/
void display_reg_key_info(FILE *out_hnd, enum action_type action,
				char *key_name, time_t key_mod_time)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			fprintf(out_hnd, "\t%s\t(%s)\n",
			        key_name, http_timestring(key_mod_time));
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
convert a security permissions into a string
****************************************************************************/
char *get_svc_start_type_str(uint32 type)
{
	static fstring typestr;

	switch (type)
	{
		case 0x00: fstrcpy(typestr, "Boot"    ); return typestr;
		case 0x01: fstrcpy(typestr, "System"  ); return typestr;
		case 0x02: fstrcpy(typestr, "Auto"    ); return typestr;
		case 0x03: fstrcpy(typestr, "Manual"  ); return typestr;
		case 0x04: fstrcpy(typestr, "Disabled"); return typestr;
		default  : break;
	}
	slprintf(typestr, sizeof(typestr)-1, "[%d]", type);
	return typestr;
}


/****************************************************************************
 display structure
 ****************************************************************************/
void display_query_svc_cfg(FILE *out_hnd, enum action_type action,
				QUERY_SERVICE_CONFIG *cfg)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			fstring service;

			unistr2_to_ascii(service, &cfg->uni_display_name, sizeof(service)-1);
			fprintf(out_hnd, "\tService:\t%s\n", service);
			fprintf(out_hnd, "\t-------\n");
			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring temp;

			unistr2_to_ascii(temp, &cfg->uni_bin_path_name, sizeof(temp)-1);
			fprintf(out_hnd, "\tPath:\t%s\n", temp);

			unistr2_to_ascii(temp, &cfg->uni_load_order_grp, sizeof(temp)-1);
			fprintf(out_hnd, "\tLoad Order:\t%s\n", temp);

			unistr2_to_ascii(temp, &cfg->uni_dependencies, sizeof(temp)-1);
			fprintf(out_hnd, "\tDependencies:\t%s\n", temp);

			unistr2_to_ascii(temp, &cfg->uni_service_start_name, sizeof(temp)-1);
			fprintf(out_hnd, "\tService Start:\t%s\n", temp);

			fprintf(out_hnd, "\tService Type:\t%d\n", cfg->service_type);
			fprintf(out_hnd, "\tStart Type:\t%s\n" , get_svc_start_type_str(cfg->start_type));
			fprintf(out_hnd, "\tError Control:\t%d\n" , cfg->error_control);
			fprintf(out_hnd, "\tTag Id:\t%d\n" , cfg->tag_id);
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
 display structure
 ****************************************************************************/
void display_svc_info(FILE *out_hnd, enum action_type action, ENUM_SRVC_STATUS *svc)
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

			unistr_to_ascii(name, svc->uni_srvc_name.buffer,
					sizeof(name)-1); /* service name */
			fprintf(out_hnd, "\t%s:", name);

			unistr_to_ascii(name, svc->uni_disp_name.buffer,
					sizeof(name)-1); /* display name */
			fprintf(out_hnd, "\t%s\n", name);
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

static char *get_at_time_str(uint32 t)
{
	static fstring timestr;
	unsigned int hours, minutes, seconds;

	hours = t / 1000;
	seconds = hours % 60;
	hours /= 60;
	minutes = hours % 60;
	hours /= 60;

	slprintf(timestr, sizeof(timestr)-1, "%2d:%02d:%02d",
		 hours, minutes, seconds);

	return timestr;
}

extern char *daynames_short[];

static char *get_at_days_str(uint32 monthdays, uint8 weekdays, uint8 flags)
{
	static fstring days;
	fstring numstr;
	int day, bit;
	BOOL first = True;

	if (monthdays == 0 && weekdays == 0)
		return "Once";

	if (flags & JOB_PERIODIC)
	{
		if (IS_BITS_SET_ALL(weekdays, 0x7F))
			return "Every Day";

		fstrcpy(days, "Every ");
	}
	else
	{
		fstrcpy(days, "Next ");
	}

	for (day = 1, bit = 1; day < 32; day++, bit <<= 1)
	{
		if (monthdays & bit)
		{
			if (first)
				first = False;
			else
				fstrcat(days, ",");

			slprintf(numstr, sizeof(numstr)-1, "%d", day);
			fstrcat(days, numstr);
		}
	}

	for (day = 0, bit = 1; day < 7; day++, bit <<= 1)
	{
		if (weekdays & bit)
		{
			if (first)
				first = False;
			else
				fstrcat(days, ",");

			fstrcat(days, daynames_short[day]);
		}
	}

	return days;
}

/****************************************************************************
 display scheduled jobs
 ****************************************************************************/
void display_at_enum_info(FILE *out_hnd, enum action_type action,
		     uint32 num_jobs, AT_ENUM_INFO *jobs, fstring *commands)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			if (num_jobs == 0)
			{
				fprintf(out_hnd, "\tNo Jobs.\n");
			}
			else
			{
				fprintf(out_hnd, "\tJobs:\n");
				fprintf(out_hnd, "\t-----\n");
			}
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < num_jobs; i++)
			{
				AT_JOB_INFO *job = &jobs[i].info;

				fprintf(out_hnd, "\t%d\t%s\t%s\t%s\n",
					jobs[i].jobid,
					get_at_time_str(job->time),
					get_at_days_str(job->monthdays,
							job->weekdays,
							job->flags),
					commands[i]);
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
 display information about a scheduled job
 ****************************************************************************/
void display_at_job_info(FILE *out_hnd, enum action_type action,
		     AT_JOB_INFO *job, fstring command)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "\tJob Information:\n");
			fprintf(out_hnd, "\t----------------\n");
			break;
		}
		case ACTION_ENUMERATE:
		{
			fprintf(out_hnd, "\tTime:        %s\n", 
				get_at_time_str(job->time));

			fprintf(out_hnd, "\tSchedule:    %s\n",
				get_at_days_str(job->monthdays, job->weekdays,
						job->flags));

			fprintf(out_hnd, "\tStatus:      %s",
				(job->flags & JOB_EXEC_ERR) ? "Failed" : "OK");

			if (job->flags & JOB_RUNS_TODAY)
			{
				fprintf(out_hnd, ", Runs Today");
			}

			fprintf(out_hnd, "\n\tInteractive: %s\n",
				(job->flags & JOB_NONINTERACTIVE) ? "No"
				: "Yes");

			fprintf(out_hnd, "\tCommand:     %s\n", command);
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
 display structure
 ****************************************************************************/
void display_eventlog_eventrecord(FILE *out_hnd, enum action_type action, EVENTLOGRECORD *ev)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "\tevent log records\n"); 
			fprintf(out_hnd, "\t-----------------\n");
			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring temp;
			fprintf(out_hnd, "\t\trecord n.:\t%d\n", ev->recordnumber);
			
			fprintf(out_hnd, "\t\tsource\teventnumber\teventtype\tcategory\n");
			unistr_to_ascii(temp, ev->sourcename.buffer, sizeof(temp)-1);
			
			fprintf(out_hnd, "\t\t%s", temp);
			
			fprintf(out_hnd, "\t%d\t\t", ev->eventnumber&0x0000FFFF);
			
			switch (ev->eventtype)
			{
				case EVENTLOG_OK:
					fprintf(out_hnd, "Normal");
					break;
 
				case EVENTLOG_ERROR:
					fprintf(out_hnd, "Error");
					break;
			
				case EVENTLOG_WARNING:
					fprintf(out_hnd, "Warning");
					break;
			
				case EVENTLOG_INFORMATION:
					fprintf(out_hnd, "Information");
					break;
			
				case EVENTLOG_AUDIT_OK:
					fprintf(out_hnd, "Audit Normal");
					break;
			
				case EVENTLOG_AUDIT_ERROR:
					fprintf(out_hnd, "Audit Error\n");
					break;			
			}
			
			fprintf(out_hnd, "\t%d\n", ev->category);
			fprintf(out_hnd, "\t\tcreationtime:\t%s\n", http_timestring(ev->creationtime));
			fprintf(out_hnd, "\t\twritetime:\t%s\n", http_timestring(ev->writetime));

			unistr_to_ascii(temp, ev->computername.buffer, sizeof(temp)-1);
			fprintf(out_hnd, "\t\tcomputer:\t%s\n", temp);

			if (ev->num_of_strings!=0)
			{
				unistr_to_ascii(temp, ev->strings.buffer, sizeof(temp)-1);
				fprintf(out_hnd, "\t\tdescription:\t%s\n", temp);
			}

			fprintf(out_hnd, "\n");			
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
 display sam sync structure
 ****************************************************************************/
void display_sam_sync_ctr(FILE *out_hnd, enum action_type action,
				SAM_DELTA_HDR *delta,
				SAM_DELTA_CTR *ctr)
{
	fstring name;

	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			switch (delta->type)
			{
				case 1:
				{
					unistr2_to_ascii(name, &(ctr->domain_info.uni_dom_name), sizeof(name)-1); 
					fprintf(out_hnd, "Domain: %s\n", name);
					break;
				}
				case 2:
				{
					unistr2_to_ascii(name, &(ctr->group_info.uni_grp_name), sizeof(name)-1); 
					fprintf(out_hnd, "Group: %s\n", name);
					break;
				}
				case 5:
				{
					unsigned char lm_pwd[16];
					unsigned char nt_pwd[16];

					unistr2_to_ascii(name, &(ctr->account_info.uni_acct_name), sizeof(name)-1); 
					fprintf(out_hnd, "Account: %s\n", name);

					sam_pwd_hash(ctr->account_info.user_rid, ctr->account_info.pass.buf_lm_pwd, lm_pwd, 0);
					out_struct(out_hnd, lm_pwd, 16, 8);

					sam_pwd_hash(ctr->account_info.user_rid, ctr->account_info.pass.buf_nt_pwd, nt_pwd, 0);
					out_struct(out_hnd, nt_pwd, 16, 8);
				}
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
 display sam sync structure
 ****************************************************************************/
void display_sam_sync(FILE *out_hnd, enum action_type action,
				SAM_DELTA_HDR *deltas,
				SAM_DELTA_CTR *ctr,
				uint32 num)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "\tSAM Database Sync\n"); 
			fprintf(out_hnd, "\t-----------------\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;
			for (i = 0; i < num; i++)
			{
				display_sam_sync_ctr(out_hnd, ACTION_HEADER   , &deltas[i], &ctr[i]);
				display_sam_sync_ctr(out_hnd, ACTION_ENUMERATE, &deltas[i], &ctr[i]);
				display_sam_sync_ctr(out_hnd, ACTION_FOOTER   , &deltas[i], &ctr[i]);
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
 display sam sync structure
 ****************************************************************************/
void display_sam_unk_info_2(FILE *out_hnd, enum action_type action,
				SAM_UNK_INFO_2 *info2)
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
			fprintf(out_hnd, "Domain:\t%s\n", name);

			unistr2_to_ascii(name, &(info2->uni_server), sizeof(name)-1); 
			fprintf(out_hnd, "Server:\t%s\n", name);

			fprintf(out_hnd, "Total Users:\t%d\n", info2->num_domain_usrs);
			fprintf(out_hnd, "Total Groups:\t%d\n", info2->num_domain_grps);
			fprintf(out_hnd, "Total Aliases:\t%d\n", info2->num_local_grps);

			fprintf(out_hnd, "Sequence No:\t%d\n", info2->seq_num);

			fprintf(out_hnd, "Unknown 0:\t0x%x\n", info2->unknown_0);
			fprintf(out_hnd, "Unknown 1:\t0x%x\n", info2->unknown_1);
			fprintf(out_hnd, "Unknown 2:\t0x%x\n", info2->unknown_2);
			fprintf(out_hnd, "Unknown 3:\t0x%x\n", info2->unknown_3);
			fprintf(out_hnd, "Unknown 4:\t0x%x\n", info2->unknown_4);
			fprintf(out_hnd, "Unknown 5:\t0x%x\n", info2->unknown_5);
			fprintf(out_hnd, "Unknown 6:\t0x%x\n", info2->unknown_6);

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
 display sam sync structure
 ****************************************************************************/
void display_sam_unk_ctr(FILE *out_hnd, enum action_type action,
				uint32 switch_value, SAM_UNK_CTR *ctr)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "\tSAM Domain Info\n"); 
			fprintf(out_hnd, "\t---------------\n");

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
			fprintf(out_hnd, "\n");
			break;
		}
	}
}


#if COPY_THIS_TEMPLATE
/****************************************************************************
 display structure
 ****************************************************************************/
 void display_(FILE *out_hnd, enum action_type action, *)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "\t\n"); 
			fprintf(out_hnd, "\t-------------------\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			break;
		}
		case ACTION_FOOTER:
		{
			fprintf(out_hnd, "\n");
			break;
		}
	}
}

#endif
