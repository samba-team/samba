
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

BOOL rpc_redir_remote(struct msrpc_state *m, prs_struct *req, prs_struct *resp)
{
	BOOL last = False;
	BOOL first = False;
	BOOL pdu_received;

	DEBUG(10,("rpc_redir_remote\n"));

	pdu_received = req != NULL && req->data != NULL && req->data_size != 0;

	if (pdu_received)
	{
		RPC_HDR hdr;
		/* process incoming PDU */
		req->offset = 0x0;
		req->io = True;
		smb_io_rpc_hdr("", &hdr, req, 0);

		if (req->offset == 0) return False;

		last  = IS_BITS_SET_ALL(hdr.flags, RPC_FLG_LAST);
		first = IS_BITS_SET_ALL(hdr.flags, RPC_FLG_FIRST);

		if (hdr.pkt_type == RPC_BIND)
		{
			last = True;
			first = True;
		}

		if (!msrpc_send(m->fd, req))
		{
			DEBUG(2,("msrpc redirect send failed\n"));
			return False;
		}
	}
	if (last || !pdu_received)
	{
		/* process outgoing PDU */
		if (!msrpc_receive(m->fd, resp))
		{
			DEBUG(2,("msrpc redirect receive failed\n"));
			return False;
		}
		prs_link(NULL, resp, NULL);
		prs_debug_out(resp, "redirect", 100);
	}
	return True;
}

/*******************************************************************
 entry point from msrpc to smb.  adds data received to pdu; checks
 pdu; hands pdu off to msrpc, which gets a pdu back (except in the
 case of the RPC_BINDCONT pdu).
 ********************************************************************/
BOOL rpc_to_smb_remote(pipes_struct *p, char *data, int len)
{
	BOOL reply = False;

	DEBUG(10,("rpc_to_smb: len %d\n", len));

	if (len != 0)
	{
		reply = prs_add_data(&p->smb_pdu, data, len);

		if (reply && is_complete_pdu(&p->smb_pdu))
		{
			p->smb_pdu.offset = p->smb_pdu.data_size;
			prs_link(NULL, &p->smb_pdu, NULL);
			reply = rpc_redir_remote(p->m, &p->smb_pdu, &p->rsmb_pdu);
			prs_free_data(&p->smb_pdu);
			prs_init(&p->smb_pdu, 0, 4, True);
		}
	}
	else
	{
		prs_free_data(&p->smb_pdu);
		prs_init(&p->smb_pdu, 0, 4, True);
		reply = rpc_redir_remote(p->m, &p->smb_pdu, &p->rsmb_pdu);
	}
	return reply;
}

/****************************************************************************
 writes data to a pipe.
 ****************************************************************************/
ssize_t write_pipe(pipes_struct *p, char *data, size_t n)
{
	DEBUG(6,("write_pipe: %x", p->pnum));
	DEBUG(6,("name: %s open: %s len: %d",
		 p->name, BOOLSTR(p->open), n));

	dump_data(50, data, n);

	return rpc_to_smb_remote(p, data, n) ? ((ssize_t)n) : -1;
}


/****************************************************************************
 reads data from a pipe.

 headers are interspersed with the data at regular intervals.  by the time
 this function is called, the start of the data could possibly have been
 read by an SMBtrans (file_offset != 0).

 ****************************************************************************/
int read_pipe(pipes_struct *p, char *data, uint32 pos, int n)
{
	int num = 0;
	int pdu_len = 0;
	uint32 hdr_num = 0;
	int pdu_data_sent; /* amount of current pdu already sent */
	int data_pos; /* entire rpc data sent - no headers, no auth verifiers */
	int this_pdu_data_pos;
	RPC_HDR hdr;

	DEBUG(6,("read_pipe: %x name: %s open: %s pos: %d len: %d",
		 p->pnum, p->name, BOOLSTR(p->open),
		 pos, n));

	if (!p || !p->open)
	{
		DEBUG(6,("pipe not open\n"));
		return -1;		
	}


	if (p->rsmb_pdu.data == NULL ||  p->rsmb_pdu.data_size == 0)
	{
		return 0;
	}

	p->rsmb_pdu.offset = 0;
	p->rsmb_pdu.io = True;

	if (!smb_io_rpc_hdr("hdr", &hdr, &p->rsmb_pdu, 0) ||
             p->rsmb_pdu.offset != 0x10)
	{
		DEBUG(6,("read_pipe: rpc header invalid\n"));
		return -1;
	}

	DEBUG(6,("read_pipe: p: %p file_offset: %d file_pos: %d\n",
		 p, p->file_offset, n));

	/* the read request starts from where the SMBtrans2 left off. */
	data_pos = p->file_offset - p->hdr_offsets;
	pdu_data_sent = p->file_offset - p->prev_pdu_file_offset;
	this_pdu_data_pos = (pdu_data_sent == 0) ? 0 : (pdu_data_sent - 0x18);

	if (!IS_BITS_SET_ALL(hdr.flags, RPC_FLG_LAST))
	{
		/* intermediate fragment - possibility of another header */
		
		DEBUG(5,("read_pipe: frag_len: %d data_pos: %d pdu_data_sent: %d\n",
			 hdr.frag_len, data_pos, pdu_data_sent));
		
		if (pdu_data_sent == 0)
		{
			DEBUG(6,("read_pipe: next fragment header\n"));

			/* this is subtracted from the total data bytes, later */
			hdr_num = 0x18;
			p->hdr_offsets += 0x18;
			data_pos -= 0x18;

			rpc_redir_remote(p->m, &p->smb_pdu, &p->rsmb_pdu);
		}			
	}
	
	pdu_len = prs_buf_len(&p->rsmb_pdu);
	num = pdu_len - this_pdu_data_pos;
	
	DEBUG(6,("read_pipe: pdu_len: %d num: %d n: %d\n", pdu_len, num, n));
	
	if (num > n) num = n;
	if (num <= 0)
	{
		DEBUG(5,("read_pipe: 0 or -ve data length\n"));
		return 0;
	}

	if (num < hdr_num)
	{
		DEBUG(5,("read_pipe: warning - data read only part of a header\n"));
	}

	prs_buf_copy(data, &p->rsmb_pdu, pdu_data_sent, num);
	
	p->file_offset  += num;
	pdu_data_sent  += num;
	
	if (hdr_num == 0x18 && num == 0x18)
	{
		DEBUG(6,("read_pipe: just header read\n"));
	}

	if (pdu_data_sent == hdr.frag_len)
	{
		DEBUG(6,("read_pipe: next fragment expected\n"));
		p->prev_pdu_file_offset = p->file_offset;
	}

	return num;
}


