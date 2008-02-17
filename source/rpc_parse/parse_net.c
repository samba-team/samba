/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Jean Francois Micouleau           2002.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_PARSE

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool net_io_neg_flags(const char *desc, NEG_FLAGS *neg, prs_struct *ps, int depth)
{
	if (neg == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_neg_flags");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("neg_flags", ps, depth, &neg->neg_flags))
		return False;

	return True;
}

/*******************************************************************
 Inits a NET_Q_AUTH_3 struct.
********************************************************************/

void init_q_auth_3(NET_Q_AUTH_3 *q_a,
		const char *logon_srv, const char *acct_name, uint16 sec_chan, const char *comp_name,
		const DOM_CHAL *clnt_chal, uint32 clnt_flgs)
{
	DEBUG(5,("init_q_auth_3: %d\n", __LINE__));

	init_log_info(&q_a->clnt_id, logon_srv, acct_name, sec_chan, comp_name);
	memcpy(q_a->clnt_chal.data, clnt_chal->data, sizeof(clnt_chal->data));
	q_a->clnt_flgs.neg_flags = clnt_flgs;

	DEBUG(5,("init_q_auth_3: %d\n", __LINE__));
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool net_io_q_auth_3(const char *desc, NET_Q_AUTH_3 *q_a, prs_struct *ps, int depth)
{
	if (q_a == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_q_auth_3");
	depth++;

	if(!prs_align(ps))
		return False;
    
	if(!smb_io_log_info ("", &q_a->clnt_id, ps, depth)) /* client identification info */
		return False;
	if(!smb_io_chal("", &q_a->clnt_chal, ps, depth))
		return False;
	if(!net_io_neg_flags("", &q_a->clnt_flgs, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool net_io_r_auth_3(const char *desc, NET_R_AUTH_3 *r_a, prs_struct *ps, int depth)
{
	if (r_a == NULL)
		return False;

	prs_debug(ps, depth, desc, "net_io_r_auth_3");
	depth++;

	if(!prs_align(ps))
		return False;
    
	if(!smb_io_chal("srv_chal", &r_a->srv_chal, ps, depth)) /* server challenge */
		return False;
	if(!net_io_neg_flags("srv_flgs", &r_a->srv_flgs, ps, depth))
		return False;
	if (!prs_uint32("unknown", ps, depth, &r_a->unknown))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_a->status))
		return False;

	return True;
}
