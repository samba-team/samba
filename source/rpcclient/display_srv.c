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
		SRV_INFO_101 *const sv101)
{
	if (sv101 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "Server Info Level 101:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring name;
			fstring comment;

			unistr2_to_ascii(name, &sv101->uni_name, sizeof(name)-1);
			unistr2_to_ascii(comment, &sv101->uni_comment, sizeof(comment)-1);

			display_server(out_hnd, action, name, sv101->srv_type, comment);

			report(out_hnd, "\tplatform_id     :\t%d\n"    , sv101->platform_id);
			report(out_hnd, "\tos version      :\t%d.%d\n" , sv101->ver_major, sv101->ver_minor);

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
void display_srv_info_102(FILE *out_hnd, enum action_type action, SRV_INFO_102 *const sv102)
{
	if (sv102 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "Server Info Level 102:\n");

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

			report(out_hnd, "\tplatform_id     :\t%d\n"    , sv102->platform_id);
			report(out_hnd, "\tos version      :\t%d.%d\n" , sv102->ver_major, sv102->ver_minor);

			report(out_hnd, "\tusers           :\t%x\n"    , sv102->users      );
			report(out_hnd, "\tdisc, hidden    :\t%x, %x\n" , sv102->disc     , sv102->hidden   );
			report(out_hnd, "\tannounce, delta :\t%d, %d\n", sv102->announce , sv102->ann_delta);
			report(out_hnd, "\tlicenses        :\t%d\n"    , sv102->licenses   );
			report(out_hnd, "\tuser path       :\t%s\n"    , usr_path);

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
void display_srv_info_ctr(FILE *out_hnd, enum action_type action, SRV_INFO_CTR *const ctr)
{
	if (ctr == NULL || ctr->ptr_srv_ctr == 0)
	{
		report(out_hnd, "Server Information: unavailable due to an error\n");
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
			report(out_hnd, "Server Information: Unknown Info Level\n");
			break;
		}
	}
}

/****************************************************************************
connection info level 0 display function
****************************************************************************/
void display_conn_info_0(FILE *out_hnd, enum action_type action, 
		CONN_INFO_0 *const info0)
{
	if (info0 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "Connection Info Level 0:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			report(out_hnd, "\tid:\t%d\n", info0->id);

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
connection info level 1 display function
****************************************************************************/
void display_conn_info_1(FILE *out_hnd, enum action_type action, 
		CONN_INFO_1 *const info1, CONN_INFO_1_STR *const str1)
{
	if (info1 == NULL || str1 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "Connection Info Level 1:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring usr_name;
			fstring net_name;

			unistr2_to_ascii(usr_name, &str1->uni_usr_name, sizeof(usr_name)-1);
			unistr2_to_ascii(net_name, &str1->uni_net_name, sizeof(net_name)-1);

			report(out_hnd, "\tid       :\t%d\n", info1->id);
			report(out_hnd, "\ttype     :\t%s\n", get_share_type_str(info1->type));
			report(out_hnd, "\tnum_opens:\t%d\n", info1->num_opens);
			report(out_hnd, "\tnum_users:\t%d\n", info1->num_users);
			report(out_hnd, "\topen_time:\t%d\n", info1->open_time);

			report(out_hnd, "\tuser name:\t%s\n", usr_name);
			report(out_hnd, "\tnet  name:\t%s\n", net_name);

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
connection info level 0 container display function
****************************************************************************/
void display_srv_conn_info_0_ctr(FILE *out_hnd, enum action_type action, 
				SRV_CONN_INFO_0 *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_srv_conn_info_0_ctr: unavailable due to an internal error\n");
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
				SRV_CONN_INFO_1 *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_srv_conn_info_1_ctr: unavailable due to an internal error\n");
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
				SRV_CONN_INFO_CTR *const ctr)
{
	if (ctr == NULL || ctr->ptr_conn_ctr == 0)
	{
		report(out_hnd, "display_srv_conn_info_ctr: unavailable due to an internal error\n");
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
			report(out_hnd, "display_srv_conn_info_ctr: Unknown Info Level\n");
			break;
		}
	}
}


/****************************************************************************
transport info level 0 display function
****************************************************************************/
void display_tprt_info_0(FILE *out_hnd, enum action_type action, 
		TPRT_INFO_0 *const info0, TPRT_INFO_0_STR *const str0)
{
	if (info0 == NULL || str0 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "Transport Info Level 0:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring trans_name;
			fstring trans_addr;
			fstring addr_name;

			unistr2_to_ascii(trans_name, &str0->uni_trans_name, sizeof(trans_name)-1);
			buffer4_to_str(trans_addr, &str0->buf_trans_addr, sizeof(trans_addr)-1);
			unistr2_to_ascii(addr_name, &str0->uni_addr_name, sizeof(addr_name)-1);

			report(out_hnd, "\tnum_vcs  :\t%d\n", info0->num_vcs);
			report(out_hnd, "\ttransport name:\t%s\n", trans_name);
			report(out_hnd, "\ttransport addr:\t%s\n", trans_addr);
			report(out_hnd, "\taddress name:\t%s\n", addr_name);

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
transport info level 0 container display function
****************************************************************************/
void display_srv_tprt_info_0_ctr(FILE *out_hnd, enum action_type action, 
				const SRV_TPRT_INFO_0 *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_srv_tprt_info_0_ctr: unavailable due to an internal error\n");
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
				display_tprt_info_0(out_hnd, ACTION_HEADER   , &(ctr->info_0[i]), &(ctr->info_0_str[i]));
				display_tprt_info_0(out_hnd, ACTION_ENUMERATE, &(ctr->info_0[i]), &(ctr->info_0_str[i]));
				display_tprt_info_0(out_hnd, ACTION_FOOTER   , &(ctr->info_0[i]), &(ctr->info_0_str[i]));
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
transport info container display function
****************************************************************************/
void display_srv_tprt_info_ctr(FILE *out_hnd, enum action_type action, 
				const SRV_TPRT_INFO_CTR *const ctr)
{
	if (ctr == NULL || ctr->ptr_tprt_ctr == 0)
	{
		report(out_hnd, "display_srv_tprt_info_ctr: unavailable due to an internal error\n");
		return;
	}

	switch (ctr->switch_value)
	{
		case 0:
		{
			display_srv_tprt_info_0_ctr(out_hnd, action, 
			                   &(ctr->tprt.info0));
			break;
		}
		default:
		{
			report(out_hnd, "display_srv_tprt_info_ctr: Unknown Info Level\n");
			break;
		}
	}
}


/****************************************************************************
share info level 1 display function
****************************************************************************/
void display_share_info_1(FILE *out_hnd, enum action_type action, 
		SH_INFO_1 *const info1, SH_INFO_1_STR *const str1)
{
	if (info1 == NULL || str1 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "Share Info Level 1:\n");

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
			report(out_hnd, "\n");
			break;
		}
	}

}

/****************************************************************************
share info level 2 display function
****************************************************************************/
void display_share_info_2(FILE *out_hnd, enum action_type action, 
		SH_INFO_2 *const info2, SH_INFO_2_STR *const str2)
{
	if (info2 == NULL || str2 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "Share Info Level 2:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring remark  ;
			fstring net_name;
			fstring path    ;
			fstring password;

			unistr2_to_ascii(net_name, &str2->uni_netname, sizeof(net_name)-1);
			unistr2_to_ascii(remark, &str2->uni_remark, sizeof(remark)-1);
			unistr2_to_ascii(path, &str2->uni_path, sizeof(path)-1);
			unistr2_to_ascii(password, &str2->uni_passwd, sizeof(password)-1);

			display_share2(out_hnd, action, net_name, info2->type, remark, 
			                                      info2->perms, info2->max_uses, info2->num_uses, 
			                                      path, password);

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
share info level 1 container display function
****************************************************************************/
void display_srv_share_info_1_ctr(FILE *out_hnd, enum action_type action, 
				SRV_SHARE_INFO_1 *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_srv_share_info_1_ctr: unavailable due to an internal error\n");
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
				SRV_SHARE_INFO_2 *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_srv_share_info_2_ctr: unavailable due to an internal error\n");
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
				SRV_SHARE_INFO_CTR *const ctr)
{
	if (ctr == NULL || ctr->ptr_share_ctr == 0)
	{
		report(out_hnd, "display_srv_share_info_ctr: unavailable due to an internal error\n");
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
			report(out_hnd, "display_srv_share_info_ctr: Unknown Info Level\n");
			break;
		}
	}
}


/****************************************************************************
file info level 3 display function
****************************************************************************/
void display_file_info_3(FILE *out_hnd, enum action_type action, 
		FILE_INFO_3 *const info3, FILE_INFO_3_STR *const str3)
{
	if (info3 == NULL || str3 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "File Info Level 3:\n");

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

			report(out_hnd, "\tid       :\t%d\n", info3->id);
			report(out_hnd, "\tperms    :\t%s\n", get_file_mode_str(info3->perms));
			report(out_hnd, "\tnum_locks:\t%d\n", info3->num_locks);

			report(out_hnd, "\tpath name:\t%s\n", path_name);
			report(out_hnd, "\tuser name:\t%s\n", user_name);

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
file info level 3 container display function
****************************************************************************/
void display_srv_file_info_3_ctr(FILE *out_hnd, enum action_type action, 
				SRV_FILE_INFO_3 *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_srv_file_info_3_ctr: unavailable due to an internal error\n");
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
				SRV_FILE_INFO_CTR *const ctr)
{
	if (ctr == NULL || ctr->ptr_file_ctr == 0)
	{
		report(out_hnd, "display_srv_file_info_ctr: unavailable due to an internal error\n");
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
			report(out_hnd, "display_srv_file_info_ctr: Unknown Info Level\n");
			break;
		}
	}
}

/****************************************************************************
sess info level 0 display function
****************************************************************************/
void display_sess_info_0(FILE *out_hnd, enum action_type action, 
		SESS_INFO_0 *const info0, SESS_INFO_0_STR *const str0)
{
	if (info0 == NULL || str0 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "Session Info Level 0:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring name;

			unistr2_to_ascii(name, &str0->uni_name, 
					 sizeof(name)-1);

			report(out_hnd, "\tname:\t%s\n", name);

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
sess info level 1 display function
****************************************************************************/
void display_sess_info_1(FILE *out_hnd, enum action_type action, 
		SESS_INFO_1 *const info1, SESS_INFO_1_STR *const str1)
{
	if (info1 == NULL || str1 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "Session Info Level 1:\n");

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

			report(out_hnd, "\tname:\t%s\n", name);

			report(out_hnd, "\topen :\t%d\n", info1->num_opens);
			report(out_hnd, "\ttime :\t%d\n", info1->open_time);
			report(out_hnd, "\tidle :\t%d\n", info1->idle_time);
			report(out_hnd, "\tflags:\t%d\n", info1->user_flags);

			report(out_hnd, "\tuser :\t%s\n", user_name);

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
sess info level 0 container display function
****************************************************************************/
void display_srv_sess_info_0_ctr(FILE *out_hnd, enum action_type action, 
				SRV_SESS_INFO_0 *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_srv_sess_info_0_ctr: unavailable due to an internal error\n");
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
				SRV_SESS_INFO_1 *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_srv_sess_info_1_ctr: unavailable due to an internal error\n");
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
				SRV_SESS_INFO_CTR *const ctr)
{
	if (ctr == NULL || ctr->ptr_sess_ctr == 0)
	{
		report(out_hnd, "display_srv_sess_info_ctr: unavailable due to an internal error\n");
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
			report(out_hnd, "display_srv_sess_info_ctr: Unknown Info Level\n");
			break;
		}
	}
}

/****************************************************************************
 print browse connection on a host
 ****************************************************************************/
void display_server(FILE *out_hnd, enum action_type action, 
				char *const sname, uint32 type, char *const comment)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			report(out_hnd, "\t%-15.15s%-20s %s\n", 
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
				char *const sname, uint32 type, char *const comment)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			report(out_hnd, "\t%-15.15s%-10.10s%s\n", 
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
				char *const sname, uint32 type, char *const comment, 
				uint32 perms, uint32 max_uses, uint32 num_uses, 
				char *const path, char *const password)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			report(out_hnd, "\t%-15.15s%-10.10s%s %x %x %x %s %s\n", 
			                 sname, get_share_type_str(type), comment, 
			                 perms, max_uses, num_uses, path, password);
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
				char *const sname)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			report(out_hnd, "\t%-21.21s\n", sname);
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

