
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
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

extern int DEBUGLEVEL;


/*******************************************************************
checks an RPC_HDR_AUTH structure.
********************************************************************/
BOOL rpc_hdr_netsec_auth_chk(RPC_HDR_AUTH *rai)
{
	return (rai->auth_type == 0x44 && rai->auth_level == 0x06);
}

/*******************************************************************
creates an RPC_AUTH_NETSEC_NEG structure.
********************************************************************/
BOOL make_rpc_auth_netsec_neg(RPC_AUTH_NETSEC_NEG *neg,
				fstring domain,
				fstring myname)
{
	if (neg == NULL) return False;

	fstrcpy(neg->domain, domain);
	fstrcpy(neg->myname, myname);

	return True;
}

/*******************************************************************
reads or writes an RPC_AUTH_NETSEC_NEG structure.

*** lkclXXXX HACK ALERT! ***

********************************************************************/
BOOL smb_io_rpc_auth_netsec_neg(char *desc, RPC_AUTH_NETSEC_NEG *neg, prs_struct *ps, int depth)
{
	if (neg == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_netsec_neg");
	depth++;

	prs_string("domain", ps, depth, neg->domain, 0, sizeof(neg->domain)); 
	prs_string("myname", ps, depth, neg->myname, 0, sizeof(neg->myname)); 

	return True;
}

/*******************************************************************
creates an RPC_AUTH_NETSEC_RESP structure.

*** lkclXXXX FUDGE!  HAVE TO MANUALLY SPECIFY OFFSET HERE (0x1c bytes) ***
*** lkclXXXX the actual offset is at the start of the auth verifier    ***

********************************************************************/
BOOL make_rpc_auth_netsec_resp(RPC_AUTH_NETSEC_RESP *rsp, uint32 flags)
{
	DEBUG(5,("make_rpc_auth_netsec_resp\n"));

	if (rsp == NULL) return False;

	rsp->flags = flags;

	return True;
}

/*******************************************************************
reads or writes an RPC_AUTH_NETSEC_RESP structure.

*** lkclXXXX FUDGE!  HAVE TO MANUALLY SPECIFY OFFSET HERE (0x1c bytes) ***
*** lkclXXXX the actual offset is at the start of the auth verifier    ***

********************************************************************/
BOOL smb_io_rpc_auth_netsec_resp(char *desc, RPC_AUTH_NETSEC_RESP *rsp, prs_struct *ps, int depth)
{
	if (rsp == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_netsec_resp");
	depth++;

	prs_uint32("flags", ps, depth, &rsp->flags); 

	return True;
}

/*******************************************************************
checks an RPC_AUTH_NETSEC_CHK structure.
********************************************************************/
BOOL rpc_auth_netsec_chk(RPC_AUTH_NETSEC_CHK *chk)
{
	if (chk == NULL)
	{
		return False;
	}

	if (memcmp(chk, NETSEC_SIGNATURE, 8) != 0)
	{
		return False;
	}
	return True;
}

/*******************************************************************
creates an RPC_AUTH_NETSEC_CHK structure.
********************************************************************/
BOOL make_rpc_auth_netsec_chk(RPC_AUTH_NETSEC_CHK *chk,
				uchar sig[8],
				uchar data1[8],
				uchar data3[8],
				uchar data8[8])
{
	if (chk == NULL) return False;

	if (sig != NULL)
	{
		memcpy(chk->sig  , sig  , sizeof(chk->sig  ));
	}
	if (data1 != NULL)
	{
		memcpy(chk->data1, data1, sizeof(chk->data1));
	}
	if (data3 != NULL)
	{
		memcpy(chk->data3, data3, sizeof(chk->data3));
	}
	if (data8 != NULL)
	{
		memcpy(chk->data8, data8, sizeof(chk->data8));
	}

	return True;
}

/*******************************************************************
reads or writes an RPC_AUTH_NETSEC_CHK structure.
********************************************************************/
BOOL smb_io_rpc_auth_netsec_chk(char *desc, RPC_AUTH_NETSEC_CHK *chk, prs_struct *ps, int depth)
{
	if (chk == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_netsec_chk");
	depth++;

	prs_uint8s(False, "sig  ", ps, depth, chk->sig  , sizeof(chk->sig  ));
	prs_uint8s(False, "data1", ps, depth, chk->data1, sizeof(chk->data1));
	prs_uint8s(False, "data3", ps, depth, chk->data3, sizeof(chk->data3));
	prs_uint8s(False, "data8", ps, depth, chk->data8, sizeof(chk->data8));

	return True;
}
