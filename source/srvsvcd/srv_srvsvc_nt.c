/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Main SMB server routines
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Jean-Francois Micouleau      1999-2000
   Copyright (C) Sean Millichamp                   2000
   
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
#include "nterr.h"

extern pstring global_myname;
extern int DEBUGLEVEL;

/*******************************************************************
time of day
********************************************************************/
uint32 _srv_net_remote_tod( UNISTR2 *srv_name, TIME_OF_DAY_INFO *tod )
{
	struct tm *t;
	time_t unixdate = time(NULL);

	t = gmtime(&unixdate);

	/* set up the */
	make_time_of_day_info(tod,
	                      unixdate,
	                      0,
	                      t->tm_hour,
	                      t->tm_min,
	                      t->tm_sec,
	                      0,
	                      TimeDiff(unixdate)/60,
	                      10000,
	                      t->tm_mday,
	                      t->tm_mon + 1,
	                      1900+t->tm_year,
	                      t->tm_wday);
	return 0x0;
}

/*******************************************************************
 makes a SRV_INFO_101 structure.
 ********************************************************************/
static BOOL make_r_srv_info_101(SRV_INFO_101 *sv101, uint32 platform_id, 
				char *name, int32 ver_major, uint32 ver_minor,
				uint32 srv_type, char *comment)
{
	if (sv101 == NULL) return False;

	DEBUG(5,("make_srv_info_101\n"));

	sv101->platform_id  = platform_id;
	make_buf_unistr2(&(sv101->uni_name), &(sv101->ptr_name) , name    );
	sv101->ver_major    = ver_major;
	sv101->ver_minor    = ver_minor;
	sv101->srv_type     = srv_type;
	make_buf_unistr2(&(sv101->uni_comment ), &(sv101->ptr_comment) , comment );

return True;
}

/*******************************************************************
 makes a SRV_INFO_102 structure.
 ********************************************************************/
static BOOL make_r_srv_info_102(SRV_INFO_102 *sv102, uint32 platform_id,
			char *name, char *comment, uint32 ver_major,
			uint32 ver_minor, uint32 srv_type, uint32 users,
			uint32 disc, uint32 hidden, uint32 announce,
			uint32 ann_delta, uint32 licenses, char *usr_path)
{
	if (sv102 == NULL) return False;

	DEBUG(5,("make_srv_info_102\n"));

	sv102->platform_id  = platform_id;
	make_buf_unistr2(&(sv102->uni_name  ), &(sv102->ptr_name  ), name  );
	sv102->ver_major    = ver_major;
	sv102->ver_minor    = ver_minor;
	sv102->srv_type     = srv_type;
	make_buf_unistr2(&(sv102->uni_comment ), &(sv102->ptr_comment ), comment );

	/* same as 101 up to here */

	sv102->users        = users;
	sv102->disc         = disc;
	sv102->hidden       = hidden;
	sv102->announce     = announce;
	sv102->ann_delta    = ann_delta;
	sv102->licenses     = licenses;
	make_buf_unistr2(&(sv102->uni_usr_path), &(sv102->ptr_usr_path), usr_path);

	return True;
}


/*******************************************************************
net server get info
********************************************************************/
uint32 _srv_net_srv_get_info( UNISTR2 *srv_name, uint32 switch_value,
                                SRV_INFO_CTR *ctr)
{
	switch (switch_value)
	{
		case 102:
		{
			make_r_srv_info_102(&(ctr->srv.sv102),
					500, /* platform id */
					global_myname,
					lp_serverstring(),
					lp_major_announce_version(),
					lp_minor_announce_version(),
					lp_default_server_announce(),
					0xffffffff, /* users */
					0xf, /* disc */
					0, /* hidden */
					240, /* announce */
					3000, /* announce delta */
					100000, /* licenses */
					"c:\\"); /* user path */
			break;
		}
		case 101:
		{
			make_r_srv_info_101(&(ctr->srv.sv101),
					500, /* platform id */
					global_myname,
					lp_major_announce_version(),
					lp_minor_announce_version(),
					lp_default_server_announce(),
					lp_serverstring());
			break;
		}
		default:
		{
			return (0xC0000000 | NT_STATUS_INVALID_INFO_CLASS);
			break;
		}
	}
	return 0x0;
}

/*******************************************************************
 fill in a share info level 1 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 see ipc.c:fill_share_info()

 ********************************************************************/
static void make_srv_share_1_info(SH_INFO_1    *sh1,
                                  SH_INFO_1_STR *str1, int snum)
{
	int len_net_name;
	pstring net_name;
	pstring remark;
	uint32 type;

	pstrcpy(net_name, lp_servicename(snum));
	pstrcpy(remark  , lp_comment    (snum));
	len_net_name = strlen(net_name);

	/* work out the share type */
	type = STYPE_DISKTREE;

	if (lp_print_ok(snum))             type = STYPE_PRINTQ;
	if (strequal("IPC$", net_name))    type = STYPE_IPC;
	if (net_name[len_net_name] == '$') type |= STYPE_HIDDEN;

	make_srv_share_info1    (sh1 , net_name, type, remark);
	make_srv_share_info1_str(str1, net_name,       remark);
}

/*******************************************************************
 fill in a share info level 1 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void make_srv_share_info_1(SRV_SHARE_INFO_1 *sh1, uint32 *snum, 
					uint32 *svcs)
{
	uint32 num_entries = 0;
	(*svcs) = lp_numservices();

	if (sh1 == NULL)
	{
		(*snum) = 0;
		return;
	}

	DEBUG(5,("make_srv_share_1_sh1\n"));

	for (; (*snum) < (*svcs) && num_entries < MAX_SHARE_ENTRIES; (*snum)++)
	{
		if (lp_browseable((*snum)) && lp_snum_ok((*snum)))
		{
			make_srv_share_1_info(&(sh1->info_1    [num_entries]),
			  &(sh1->info_1_str[num_entries]), (*snum));

			/* move on to creating next share */
			num_entries++;
		}
	}

	sh1->num_entries_read  = num_entries;
	sh1->ptr_share_info    = num_entries > 0 ? 1 : 0;
	sh1->num_entries_read2 = num_entries;

	if ((*snum) >= (*svcs))
	{
		(*snum) = 0;
	}
}

/*******************************************************************
 fill in a share info level 2 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 see ipc.c:fill_share_info()

 ********************************************************************/
static void make_srv_share_2_info(SH_INFO_2     *sh2,
				  SH_INFO_2_STR *str2, int snum)
{
	int len_net_name;
	pstring net_name;
	pstring remark;
	pstring path;
	pstring passwd;
	uint32 type;

	pstrcpy(net_name, lp_servicename(snum));
	pstrcpy(remark  , lp_comment    (snum));
	pstrcpy(path    , lp_pathname   (snum));
	pstrcpy(passwd  , "");
	len_net_name = strlen(net_name);

	/* work out the share type */
	type = STYPE_DISKTREE;

	if (lp_print_ok(snum))             type = STYPE_PRINTQ;
	if (strequal("IPC$", net_name))    type = STYPE_IPC;
	if (net_name[len_net_name] == '$') type |= STYPE_HIDDEN;

	make_srv_share_info2    (sh2 , net_name, type, remark, 0, 
				0xffffffff, 1, path, passwd);
	make_srv_share_info2_str(str2, net_name, remark, path, passwd);
}

/*******************************************************************
 fill in a share info level 2 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void make_srv_share_info_2(SRV_SHARE_INFO_2 *sh2, uint32 *snum, 
					uint32 *svcs)
{
	uint32 num_entries = 0;
	(*svcs) = lp_numservices();

	if (sh2 == NULL)
	{
		(*snum) = 0;
		return;
	}

	DEBUG(5,("make_srv_share_2_sh1\n"));

	for (; (*snum) < (*svcs) && num_entries < MAX_SHARE_ENTRIES; (*snum)++)
	{
		if (lp_browseable((*snum)) && lp_snum_ok((*snum)))
		{
			make_srv_share_2_info(&(sh2->info_2    [num_entries]),
			  &(sh2->info_2_str[num_entries]), (*snum));

			/* move on to creating next share */
			num_entries++;
		}
	}

	sh2->num_entries_read  = num_entries;
	sh2->ptr_share_info    = num_entries > 0 ? 1 : 0;
	sh2->num_entries_read2 = num_entries;

	if ((*snum) >= (*svcs))
	{
		(*snum) = 0;
	}
}

/*******************************************************************
 makes a SRV_R_NET_SHARE_ENUM structure.
********************************************************************/
static uint32 make_srv_share_info_ctr(SRV_SHARE_INFO_CTR *ctr,
					int switch_value, uint32 *resume_hnd,
					uint32 *total_entries)
{
	uint32 status = 0x0;
	DEBUG(5,("make_srv_share_info_ctr: %d\n", __LINE__));

	ctr->switch_value = switch_value;

	switch (switch_value)
	{
		case 1:
		{
			make_srv_share_info_1(&(ctr->share.info1), 
						resume_hnd, 
						total_entries);
			ctr->ptr_share_ctr = 1;
			break;
		}
		case 2:
		{
			make_srv_share_info_2(&(ctr->share.info2), 
						resume_hnd, 
						total_entries);
			ctr->ptr_share_ctr = 2;
			break;
		}
		default:
		{
			DEBUG(5,("make_srv_share_info_ctr: unsupported switch value %d\n",
					switch_value));
			(*resume_hnd = 0);
			(*total_entries) = 0;
			ctr->ptr_share_ctr = 0;
			status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
			break;
		}
	}

	return status;
}

/*******************************************************************
 makes a SRV_R_NET_SHARE_ENUM structure.
********************************************************************/
static uint32 make_srv_r_net_share_enum( uint32 resume_hnd,
			int switch_value, SRV_SHARE_INFO_CTR *ctr,
			uint32 *total_entries, ENUM_HND *enum_hnd,
			uint32 share_level )
{
	uint32 status;

	DEBUG(5,("make_srv_r_net_share_enum: %d\n", __LINE__));

	if (share_level == 0)
	{
		status = (0xC0000000 | NT_STATUS_INVALID_INFO_CLASS);
	}
	else
	{
		status = make_srv_share_info_ctr(ctr, switch_value,
				&resume_hnd, total_entries);
	}

	if (status != 0x0)
	{
		resume_hnd = 0;
	}
	make_enum_hnd(enum_hnd, resume_hnd);

	return status;
}

/*******************************************************************
net share enum
********************************************************************/
uint32 _srv_net_srv_share_enum( const UNISTR2 *srv_name, 
				uint32 switch_value, SRV_SHARE_INFO_CTR *ctr,
				uint32 preferred_len, ENUM_HND *enum_hnd,
				uint32 *total_entries, uint32 share_level )
{
	uint32 status;	

	DEBUG(5,("_srv_net_share_enum: %d\n", __LINE__));
	
	status = make_srv_r_net_share_enum( get_enum_hnd(enum_hnd),
						ctr->switch_value,
						ctr,
						total_entries,
						enum_hnd,
						share_level );

	DEBUG(5,("srv_net_share_enum: %d\n", __LINE__));

	return status;
}
