
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  Copyright (C) Paul Ashton                  1997-1998.
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

/*  this module apparently provides an implementation of DCE/RPC over a
 *  named pipe (IPC$ connection using SMBtrans).  details of DCE/RPC
 *  documentation are available (in on-line form) from the X-Open group.
 *
 *  this module should provide a level of abstraction between SMB
 *  and DCE/RPC, while minimising the amount of mallocs, unnecessary
 *  data copies, and network traffic.
 *
 *  in this version, which takes a "let's learn what's going on and
 *  get something running" approach, there is additional network
 *  traffic generated, but the code should be easier to understand...
 *
 *  ... if you read the docs.  or stare at packets for weeks on end.
 *
 */

#include "includes.h"
#include "nterr.h"

extern int DEBUGLEVEL;


/*******************************************************************
turns a DCE/RPC request into a DCE/RPC reply
********************************************************************/
static BOOL api_noauth_create_pdu(rpcsrv_struct *l, uint32 data_start,
				prs_struct *resp)
{
	BOOL ret;
	char *data;
	uint32 data_len;
	uint32 auth_len;
	uint32 data_end = l->rdata.offset;
	prs_struct rhdr;
	prs_struct rdata_i;
	RPC_HDR_RESP  hdr_resp;

	DEBUG(5,("create_noauth_reply: data_start: %d data_end: %d max_tsize: %d\n",
	          data_start, data_end, l->hdr_ba.bba.max_tsize));

	auth_len = l->hdr.auth_len;

	if (auth_len != 0)
	{
		return False;
	}

	prs_init(&rhdr , 0, 4, False);

	l->hdr.pkt_type = RPC_RESPONSE; /* mark header as an rpc response */

	/* set up rpc header (fragmentation issues) */
	if (data_start == 0)
	{
		l->hdr.flags = RPC_FLG_FIRST;
	}
	else
	{
		l->hdr.flags = 0;
	}

	hdr_resp.alloc_hint = data_end - data_start; /* calculate remaining data to be sent */

	DEBUG(10,("alloc_hint: %d\n", hdr_resp.alloc_hint));

	if (hdr_resp.alloc_hint + 0x18 <= l->hdr_ba.bba.max_tsize)
	{
		l->hdr.flags |= RPC_FLG_LAST;
		l->hdr.frag_len = hdr_resp.alloc_hint + 0x18;
	}
	else
	{
		l->hdr.frag_len = l->hdr_ba.bba.max_tsize;
	}

	data_len = l->hdr.frag_len - 0x18;

	rhdr.start = 0;
	rhdr.end   = 0x18;

	DEBUG(10,("hdr flags: %x\n", l->hdr.flags));

	/* store the header in the data stream */
	smb_io_rpc_hdr     ("rhdr", &(l->hdr     ), &(rhdr), 0);
	smb_io_rpc_hdr_resp("resp", &(hdr_resp), &(rhdr), 0);

	/* don't use rdata: use rdata_i instead, which moves... */
	/* make a pointer to the rdata data, NOT A COPY */

	data = prs_data(&l->rdata, data_start);
	prs_create(&rdata_i, data, data_len, l->rdata.align, rdata_i.io); 
	rdata_i.offset = data_len;
	l->rdata_offset += data_len;

	prs_debug_out(&rdata_i, "rdata_i", 200);
	prs_debug_out(&l->rdata, "rdata", 200);

	prs_link(NULL , &rhdr   , &rdata_i);
	prs_link(&rhdr, &rdata_i, NULL    );

	prs_init(resp, 0, 4, False);
	ret = prs_copy(resp, &rhdr);

	prs_free_data(&rhdr );

	return ret;
}

static BOOL api_noauth_auth_gen(rpcsrv_struct *l, prs_struct *resp,
				enum RPC_PKT_TYPE pkt_type)
{
	prs_struct rhdr;
	BOOL ret;

	DEBUG(10,("api_noauth_auth_gen\n"));

	prs_init(&rhdr, 0, 4, False);

	make_rpc_hdr(&l->hdr, pkt_type, RPC_FLG_FIRST | RPC_FLG_LAST,
		     l->hdr.call_id,
		     l->rdata.offset + 0x10, 0);

	smb_io_rpc_hdr("", &l->hdr, &rhdr, 0);
	prs_realloc_data(&rhdr, l->rdata.offset);

	/***/
	/*** link rpc header and bind acknowledgment ***/
	/***/

	prs_link(NULL    , &rhdr , &l->rdata);
	prs_link(&rhdr, &l->rdata, NULL     );

	prs_init(resp, 0, 4, False);
	ret = prs_copy(resp, &rhdr);

	prs_free_data(&l->rdata);
	prs_free_data(&rhdr );

	return ret;
}

static BOOL api_noauth_auth_chk(rpcsrv_struct *l,
				enum RPC_PKT_TYPE pkt_type)
{
	l->auth_validated = True;
	memset(l->user_sess_key, 0, 16);
	return True;
}

static BOOL api_noauth_decode_pdu(rpcsrv_struct *l)
{
	return True;
}

srv_auth_fns noauth_fns = 
{
	api_noauth_auth_chk,
	api_noauth_auth_gen,
	api_noauth_decode_pdu,
	api_noauth_create_pdu,
};

