/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Luke Leighton 1996 - 1997  Paul Ashton 1997
   
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

extern int DEBUGLEVEL;


/*******************************************************************
reads or writes a structure.
********************************************************************/
char* srv_io_share_info1_str(BOOL io, SH_INFO_1_STR *sh1, char *q, char *base, int align, int depth)
{
	if (sh1 == NULL) return NULL;

	DEBUG(5,("%s%04x srv_io_share_info1_str\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	q = smb_io_unistr2(io, &(sh1->uni_netname), q, base, align, depth); 
	q = smb_io_unistr2(io, &(sh1->uni_remark ), q, base, align, depth); 

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* srv_io_share_info1(BOOL io, SH_INFO_1 *sh1, char *q, char *base, int align, int depth)
{
	if (sh1 == NULL) return NULL;

	DEBUG(5,("%s%04x srv_io_share_info1\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	DBG_RW_IVAL("ptr_netname", depth, base, io, q, sh1->ptr_netname); q += 4;
	DBG_RW_IVAL("type       ", depth, base, io, q, sh1->type       ); q += 4;
	DBG_RW_IVAL("ptr_remark ", depth, base, io, q, sh1->ptr_remark); q += 4;

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* srv_io_share_1_ctr(BOOL io, SHARE_INFO_1_CTR *ctr, char *q, char *base, int align, int depth)
{
	if (ctr == NULL) return NULL;

	DEBUG(5,("%s%04x srv_io_share_1_ctr\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	DBG_RW_IVAL("num_entries_read", depth, base, io, q, ctr->num_entries_read); q += 4;
	DBG_RW_IVAL("ptr_share_info", depth, base, io, q, ctr->ptr_share_info); q += 4;

	if (ctr->ptr_share_info != 0)
	{
		int i;
		int num_entries = ctr->num_entries_read;
		if (num_entries > MAX_SHARE_ENTRIES)
		{
			num_entries = MAX_SHARE_ENTRIES; /* report this! */
		}

		for (i = 0; i < num_entries; i++)
		{
			q = srv_io_share_info1(io, &(ctr->info_1[i]), q, base, align, depth); 
		}

		for (i = 0; i < num_entries; i++)
		{
			q = srv_io_share_info1_str(io, &(ctr->info_1_str[i]), q, base, align, depth); 
		}

		DBG_RW_IVAL("num_entries_read2", depth, base, io, q, ctr->num_entries_read); q += 4;
	}

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* srv_io_q_net_share_enum(BOOL io, SRV_Q_NET_SHARE_ENUM *q_n, char *q, char *base, int align, int depth)
{
	if (q_n == NULL) return NULL;

	DEBUG(5,("%s%04x srv_io_q_net_share_enum\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	DBG_RW_IVAL("ptr_srv_name", depth, base, io, q, q_n->ptr_srv_name); q += 4;
	q = smb_io_unistr2(io, &(q_n->uni_srv_name), q, base, align, depth); 

	q = align_offset(q, base, align);

	DBG_RW_IVAL("share_level   ", depth, base, io, q, q_n->share_level); q += 4;
	DBG_RW_IVAL("switch_value  ", depth, base, io, q, q_n->switch_value); q += 4;

	DBG_RW_IVAL("ptr_share_info", depth, base, io, q, q_n->ptr_share_info); q += 4;
	if (q_n->ptr_share_info != 0)
	{
		switch (q_n->switch_value)
		{
			case 1:
			{
				q = srv_io_share_1_ctr(io, &(q_n->share.info1), q, base, align, depth); 
				break;
			}
			default:
			{
				DEBUG(5,("%s% no share info at switch_value %d\n",
				         tab_depth(depth), q_n->switch_value));
				break;
			}
		}
	}
	DBG_RW_IVAL("preferred_len ", depth, base, io, q, q_n->preferred_len); q += 4;

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* srv_io_r_net_share_enum(BOOL io, SRV_R_NET_SHARE_ENUM *r_n, char *q, char *base, int align, int depth)
{
	if (r_n == NULL) return NULL;

	DEBUG(5,("%s%04x srv_io_q_net_share_enum\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	DBG_RW_IVAL("share_level   ", depth, base, io, q, r_n->share_level); q += 4;
	DBG_RW_IVAL("switch_value  ", depth, base, io, q, r_n->switch_value); q += 4;

	DBG_RW_IVAL("ptr_share_info", depth, base, io, q, r_n->ptr_share_info); q += 4;
	if (r_n->ptr_share_info != 0)
	{
		switch (r_n->switch_value)
		{
			case 1:
			{
				q = srv_io_share_1_ctr(io, &(r_n->share.info1), q, base, align, depth); 
				break;
			}
			default:
			{
				DEBUG(5,("%s% no share info at switch_value %d\n",
				         tab_depth(depth), r_n->switch_value));
				break;
			}
		}
	}
	DBG_RW_IVAL("status        ", depth, base, io, q, r_n->status); q += 4;

	return q;
}

#if 0
/*******************************************************************
reads or writes a structure.
********************************************************************/
 char* lsa_io_(BOOL io, *, char *q, char *base, int align, int depth)
{
	if (== NULL) return NULL;

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL("", depth, base, io, q, ); q += 4;

	return q;
}
#endif
