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
 display sam sync structure
 ****************************************************************************/
void display_sam_sync_ctr(FILE *out_hnd, enum action_type action, 
				SAM_DELTA_HDR *const delta, 
				SAM_DELTA_CTR *const ctr)
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
					report(out_hnd, "Domain: %s\n", name);
					break;
				}
				case 2:
				{
					unistr2_to_ascii(name, &(ctr->group_info.uni_grp_name), sizeof(name)-1); 
					report(out_hnd, "Group: %s\n", name);
					break;
				}
				case 5:
				{
					unsigned char lm_pwd[16];
					unsigned char nt_pwd[16];

					unistr2_to_ascii(name, &(ctr->account_info.uni_acct_name), sizeof(name)-1); 
					report(out_hnd, "Account: %s\n", name);

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
				SAM_DELTA_HDR *const deltas, 
				SAM_DELTA_CTR *const ctr, 
				uint32 num)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "\tSAM Database Sync\n"); 
			report(out_hnd, "\t-----------------\n");

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
			report(out_hnd, "\n");
			break;
		}
	}
}

