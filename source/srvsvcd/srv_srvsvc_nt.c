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
BOOL make_r_srv_info_101(SRV_INFO_101 *sv101, uint32 platform_id, char *name,
                                uint32 ver_major, uint32 ver_minor,
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
BOOL make_r_srv_info_102(SRV_INFO_102 *sv102, uint32 platform_id, char *name,
                      char *comment, uint32 ver_major, uint32 ver_minor,
                      uint32 srv_type, uint32 users, uint32 disc, uint32 hidden,
                      uint32 announce, uint32 ann_delta, uint32 licenses,
                      char *usr_path)
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
	sv102->ann_delta    =ann_delta;
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

