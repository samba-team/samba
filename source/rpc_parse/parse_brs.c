
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1999,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1999,
 *  Copyright (C) Paul Ashton                  1997-1999.
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


#include "includes.h"
#include "rpc_parse.h"

extern int DEBUGLEVEL;


/*******************************************************************
 make_brs_q_query_info
 ********************************************************************/
BOOL make_brs_q_query_info(BRS_Q_QUERY_INFO *q_u,
				const char *server, uint16 switch_value)  
{
	DEBUG(5,("make_brs_q_query_info\n"));

	make_buf_unistr2(&(q_u->uni_srv_name), &(q_u->ptr_srv_name), server);
	q_u->switch_value1 = switch_value;
	q_u->switch_value2 = switch_value;

	q_u->ptr = 1;
	q_u->pad1 = 0x0;
	q_u->pad2 = 0x0;

	return True;
}

/*******************************************************************
reads or writes a BRS_Q_QUERY_INFO structure.
********************************************************************/
BOOL brs_io_q_query_info(char *desc, BRS_Q_QUERY_INFO *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "brs_io_q_query_info");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name", ps, depth, &(q_u->ptr_srv_name));
	smb_io_unistr2("", &(q_u->uni_srv_name), q_u->ptr_srv_name, ps, depth); 
	prs_align(ps);

	prs_uint16("switch_value1", ps, depth, &(q_u->switch_value1));
	prs_align(ps);

	prs_uint16("switch_value2", ps, depth, &(q_u->switch_value2));
	prs_align(ps);

	prs_uint32("ptr", ps, depth, &(q_u->ptr));
	if (q_u->ptr)
	{
		prs_uint32("pad1", ps, depth, &(q_u->pad1));
	}
	
	prs_uint32("pad2", ps, depth, &(q_u->pad2));

	return True;
}

/*******************************************************************
 brs_info_100
 ********************************************************************/
BOOL make_brs_info_100(BRS_INFO_100 *inf)
{
	DEBUG(5,("BRS_INFO_100: %d\n", __LINE__));

	inf->pad1 = 0x0;
	inf->ptr2 = 0x1;
	inf->pad2 = 0x0;
	inf->pad3 = 0x0;

	return True;
}

/*******************************************************************
reads or writes a BRS_INFO_100 structure.
********************************************************************/
static BOOL brs_io_brs_info_100(char *desc, BRS_INFO_100 *inf, prs_struct *ps, int depth)
{
	if (inf == NULL) return False;

	prs_debug(ps, depth, desc, "brs_io_brs_info_100");
	depth++;

	prs_align(ps);

	prs_uint32("pad1", ps, depth, &(inf->pad1)); 
	prs_uint32("ptr2", ps, depth, &(inf->ptr2)); 
	prs_uint32("pad2", ps, depth, &(inf->pad2)); 
	prs_uint32("pad3", ps, depth, &(inf->pad3)); 

	return True;
}

/*******************************************************************
 make_brs_r_query_info

 only supports info level 100 at the moment.

 ********************************************************************/
BOOL make_brs_r_query_info(BRS_R_QUERY_INFO *r_u,
				uint32 switch_value, void *inf,
				int status)  
{
	DEBUG(5,("make_brs_r_unknown_0: %d\n", __LINE__));

	r_u->switch_value1 = switch_value;  /* same as in request */
	r_u->switch_value2 = switch_value;  /* same as in request */

	r_u->ptr_1   = inf != NULL ? 1 : 0;          /* pointer 1 */
	r_u->info.id = inf;

	r_u->status  = status;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL brs_io_r_query_info(char *desc,  BRS_R_QUERY_INFO *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "brs_io_r_query_info");
	depth++;

	prs_align(ps);

	prs_uint16("switch_value1", ps, depth, &(r_u->switch_value1)); 
	prs_align(ps);

	prs_uint16("switch_value2", ps, depth, &(r_u->switch_value2)); 
	prs_align(ps);

	prs_uint32("ptr_1       ", ps, depth, &(r_u->ptr_1));
	if (r_u->ptr_1 != 0x0)
	{
		switch (r_u->switch_value1)
		{
			case 100:
			{
				brs_io_brs_info_100("inf", r_u->info.brs100, ps, depth);
				break;
			}
			default:
			{	
				break;
			}
		}
	}

	prs_uint32("status      ", ps, depth, &(r_u->status));

	return True;
}

