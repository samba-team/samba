/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client
   Copyright (C) Andrew Tridgell 1994-1997
   
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

#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

extern int DEBUGLEVEL;

#define CLIENT_TIMEOUT (30*1000)

/****************************************************************************
do a LSA Request Challenge
****************************************************************************/
static BOOL do_lsa_req_chal(uint16 fnum,
		char *desthost, char *myhostname, DOM_CHAL *srv_chal)
{
	char *rparam = NULL;
	char *rdata = NULL;
	char *p;
	int rdrcnt,rprcnt;
	pstring data; /* only 1024 bytes */
	uint16 setup[2]; /* only need 2 uint16 setup parameters */
	LSA_Q_REQ_CHAL q_c;
	DOM_CHAL clnt_chal;
	int call_id = 0x1;
    BOOL valid_chal = False;

	if (srv_chal == NULL) return False;

	/* create and send a MSRPC command with api LSA_REQCHAL */

	clnt_chal.data[0] = 0x11111111;
	clnt_chal.data[1] = 0x22222222;

	DEBUG(4,("LSA Request Challenge from %s to %s: %lx %lx\n",
	          desthost, myhostname, clnt_chal.data[0], clnt_chal.data[1]));

	/* store the parameters */
	make_q_req_chal(&q_c, desthost, myhostname, &clnt_chal);


	/* turn parameters into data stream */
	p = lsa_io_q_req_chal(False, &q_c, data + 0x18, data, 4, 0);

	/* create the request RPC_HDR _after_ the main data: length is now known */
	create_rpc_request(call_id, LSA_REQCHAL, data, PTR_DIFF(p, data));

	/* create setup parameters. */
	SIVAL(setup, 0, 0x0026); /* 0x26 indicates "transact named pipe" */
	SIVAL(setup, 2, fnum); /* file handle, from the SMBcreateX pipe, earlier */

	/* send the data on \PIPE\ */
	if (cli_call_api("\\PIPE\\", 0, PTR_DIFF(p, data), 2, 1024,
                BUFFER_SIZE,
				&rprcnt,&rdrcnt,
				NULL, data, setup,
				&rparam,&rdata))
	{
		LSA_R_REQ_CHAL r_c;
		RPC_HDR hdr;
		int hdr_len;
		int pkt_len;

		DEBUG(5, ("cli_call_api: return OK\n"));

		p = rdata;

		if (p) p = smb_io_rpc_hdr   (True, &hdr, p, rdata, 4, 0);
		if (p) p = align_offset(p, rdata, 4); /* oh, what a surprise */

		hdr_len = PTR_DIFF(p, rdata);

		if (p && hdr_len != hdr.frag_len - hdr.alloc_hint)
		{
			/* header length not same as calculated header length */
			DEBUG(2,("do_lsa_req_chal: hdr_len %x != frag_len-alloc_hint\n",
			          hdr_len, hdr.frag_len - hdr.alloc_hint));
			p = NULL;
		}

		if (p) p = lsa_io_r_req_chal(True, &r_c, p, rdata, 4, 0);
		
		pkt_len = PTR_DIFF(p, rdata);

		if (p && pkt_len != hdr.frag_len)
		{
			/* packet data size not same as reported fragment length */
			DEBUG(2,("do_lsa_req_chal: pkt_len %x != frag_len \n",
			                           pkt_len, hdr.frag_len));
			p = NULL;
		}

		if (p && r_c.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_REQ_CHAL: nt_status error %lx\n", r_c.status));
			p = NULL;
		}

		if (p)
		{
			/* ok, at last: we're happy. return the challenge */
			memcpy(srv_chal, r_c.srv_chal.data, sizeof(srv_chal->data));
			valid_chal = True;
		}
	}

	if (rparam) free(rparam);
	if (rdata) free(rdata);

	return valid_chal;
}

/****************************************************************************
  open an rpc pipe (\NETLOGON or \srvsvc for example)
  ****************************************************************************/
static uint16 open_rpc_pipe(char *inbuf, char *outbuf, char *rname, int Client, int cnum)
{
	int fnum;
	char *p;

	DEBUG(5,("open_rpc_pipe: %s\n", rname));

	bzero(outbuf,smb_size);
	set_message(outbuf,15,1 + strlen(rname),True);

	CVAL(outbuf,smb_com) = SMBopenX;
	SSVAL(outbuf,smb_tid, cnum);
	cli_setup_pkt(outbuf);

	SSVAL(outbuf,smb_vwv0,0xFF);
	SSVAL(outbuf,smb_vwv2,1);
	SSVAL(outbuf,smb_vwv3,(DENY_NONE<<4));
	SSVAL(outbuf,smb_vwv4,aSYSTEM | aHIDDEN);
	SSVAL(outbuf,smb_vwv5,aSYSTEM | aHIDDEN);
	SSVAL(outbuf,smb_vwv8,1);

	p = smb_buf(outbuf);
	strcpy(p,rname);
	p = skip_string(p,1);

	send_smb(Client,outbuf);
	receive_smb(Client,inbuf,CLIENT_TIMEOUT);

	if (CVAL(inbuf,smb_rcls) != 0)
	{
		if (CVAL(inbuf,smb_rcls) == ERRSRV &&
		    SVAL(inbuf,smb_err) == ERRnoresource &&
		    cli_reopen_connection(inbuf,outbuf))
		{
			return open_rpc_pipe(inbuf, outbuf, rname, Client, cnum);
		}
		DEBUG(0,("opening remote pipe %s - error %s\n", rname, smb_errstr(inbuf)));

		return 0xffff;
	}

	fnum = SVAL(inbuf, smb_vwv2);

	DEBUG(5,("opening pipe: fnum %d\n", fnum));

	return fnum;
}

/****************************************************************************

****************************************************************************/
BOOL cli_lsa_req_chal(DOM_CHAL *srv_chal, char *desthost, char *myhostname,
				int Client, int cnum)
{
	uint16 fnum;
	char *inbuf,*outbuf; 

	if (srv_chal == NULL) return False;

	inbuf  = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
	outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

	if (!inbuf || !outbuf)
	{
		DEBUG(0,("out of memory\n"));
		return False;
	}
	
	/* open the \PIPE\NETLOGON file */
	fnum = open_rpc_pipe(inbuf, outbuf, PIPE_NETLOGON, Client, cnum);

	if (fnum != 0xffff)
	{
		do_lsa_req_chal(fnum, desthost, myhostname, srv_chal);

		/* close \PIPE\NETLOGON */
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);

		free(inbuf); free(outbuf);
		return True;
	}

	return False;
}

