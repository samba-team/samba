/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   
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
extern pstring username;
extern pstring workgroup;

#define CLIENT_TIMEOUT (30*1000)

#ifdef NTDOMAIN

/****************************************************************************
do a LSA Open Policy
****************************************************************************/
BOOL do_lsa_open_policy(uint16 fnum, uint32 call_id,
			char *server_name, LSA_POL_HND *hnd)
{
	char *rparam = NULL;
	char *rdata = NULL;
	char *p;
	int rdrcnt,rprcnt;
	pstring data; /* only 1024 bytes */
	uint16 setup[2]; /* only need 2 uint16 setup parameters */
	LSA_Q_OPEN_POL q_o;
    BOOL valid_pol = False;

	if (hnd == NULL) return False;

	/* create and send a MSRPC command with api LSA_OPENPOLICY */

	DEBUG(4,("LSA Open Policy\n"));

	/* store the parameters */
	make_q_open_pol(&q_o, server_name, 0, 0, 0x1);

	/* turn parameters into data stream */
	p = lsa_io_q_open_pol(False, &q_o, data + 0x18, data, 4, 0);

	/* create the request RPC_HDR_RR with no data */
	create_rpc_request(call_id, LSA_OPENPOLICY, data, PTR_DIFF(p, data));

	/* create setup parameters. */
	setup[0] = 0x0026; /* 0x26 indicates "transact named pipe" */
	setup[1] = fnum; /* file handle, from the SMBcreateX pipe, earlier */

	/* send the data on \PIPE\ */
	if (cli_call_api("\\PIPE\\", 0, PTR_DIFF(p, data), 2, 1024,
                BUFFER_SIZE,
				&rprcnt, &rdrcnt,
				NULL, data, setup,
				&rparam, &rdata))
	{
		LSA_R_OPEN_POL r_o;
		RPC_HDR_RR hdr;
		int hdr_len;
		int pkt_len;

		DEBUG(5, ("cli_call_api: return OK\n"));

		p = rdata;

		if (p) p = smb_io_rpc_hdr_rr   (True, &hdr, p, rdata, 4, 0);
		if (p) p = align_offset(p, rdata, 4); /* oh, what a surprise */

		hdr_len = PTR_DIFF(p, rdata);

		if (p && hdr_len != hdr.hdr.frag_len - hdr.alloc_hint)
		{
			/* header length not same as calculated header length */
			DEBUG(2,("do_lsa_open_policy: hdr_len %x != frag_len-alloc_hint %x\n",
			          hdr_len, hdr.hdr.frag_len - hdr.alloc_hint));
			p = NULL;
		}

		if (p) p = lsa_io_r_open_pol(True, &r_o, p, rdata, 4, 0);
		
		pkt_len = PTR_DIFF(p, rdata);

		if (p && pkt_len != hdr.hdr.frag_len)
		{
			/* packet data size not same as reported fragment length */
			DEBUG(2,("do_lsa_open_policy: pkt_len %x != frag_len \n",
			                           pkt_len, hdr.hdr.frag_len));
			p = NULL;
		}

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_OPENPOLICY: nt_status error %lx\n", r_o.status));
			p = NULL;
		}

		if (p)
		{
			/* ok, at last: we're happy. return the policy handle */
			memcpy(hnd, r_o.pol.data, sizeof(hnd->data));
			valid_pol = True;
		}
	}

	if (rparam) free(rparam);
	if (rdata) free(rdata);

	return valid_pol;
}

/****************************************************************************
do a LSA Query Info Policy
****************************************************************************/
BOOL do_lsa_query_info_pol(uint16 fnum, uint32 call_id,
			LSA_POL_HND *hnd, uint16 info_class,
			fstring domain_name, pstring domain_sid)
{
	char *rparam = NULL;
	char *rdata = NULL;
	char *p;
	int rdrcnt,rprcnt;
	pstring data; /* only 1024 bytes */
	uint16 setup[2]; /* only need 2 uint16 setup parameters */
	LSA_Q_QUERY_INFO q_q;
    BOOL valid_response = False;

	if (hnd == NULL || domain_name == NULL || domain_sid == NULL) return False;

	/* create and send a MSRPC command with api LSA_QUERYINFOPOLICY */

	DEBUG(4,("LSA Query Info Policy\n"));

	/* store the parameters */
	make_q_query(&q_q, hnd, info_class);

	/* turn parameters into data stream */
	p = lsa_io_q_query(False, &q_q, data + 0x18, data, 4, 0);

	/* create the request RPC_HDR_RR with no data */
	create_rpc_request(call_id, LSA_QUERYINFOPOLICY, data, PTR_DIFF(p, data));

	/* create setup parameters. */
	setup[0] = 0x0026; /* 0x26 indicates "transact named pipe" */
	setup[1] = fnum; /* file handle, from the SMBcreateX pipe, earlier */

	/* send the data on \PIPE\ */
	if (cli_call_api("\\PIPE\\", 0, PTR_DIFF(p, data), 2, 1024,
                BUFFER_SIZE,
				&rprcnt, &rdrcnt,
				NULL, data, setup,
				&rparam, &rdata))
	{
		LSA_R_QUERY_INFO r_q;
		RPC_HDR_RR hdr;
		int hdr_len;
		int pkt_len;

		DEBUG(5, ("cli_call_api: return OK\n"));

		p = rdata;

		if (p) p = smb_io_rpc_hdr_rr   (True, &hdr, p, rdata, 4, 0);
		if (p) p = align_offset(p, rdata, 4); /* oh, what a surprise */

		hdr_len = PTR_DIFF(p, rdata);

		if (p && hdr_len != hdr.hdr.frag_len - hdr.alloc_hint)
		{
			/* header length not same as calculated header length */
			DEBUG(2,("do_lsa_query_info: hdr_len %x != frag_len-alloc_hint %x\n",
			          hdr_len, hdr.hdr.frag_len - hdr.alloc_hint));
			p = NULL;
		}

		if (p) p = lsa_io_r_query(True, &r_q, p, rdata, 4, 0);
		
		pkt_len = PTR_DIFF(p, rdata);

		if (p && pkt_len != hdr.hdr.frag_len)
		{
			/* packet data size not same as reported fragment length */
			DEBUG(2,("do_lsa_query_info: pkt_len %x != frag_len \n",
			                           pkt_len, hdr.hdr.frag_len));
			p = NULL;
		}

		if (p && r_q.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_QUERYINFOPOLICY: nt_status error %lx\n", r_q.status));
			p = NULL;
		}

		if (p && r_q.info_class != q_q.info_class)
		{
			/* report different info classes */
			DEBUG(0,("LSA_QUERYINFOPOLICY: error info_class (q,r) differ - (%x,%x)\n",
					q_q.info_class, r_q.info_class));
			p = NULL;
		}

		if (p)
		{
			/* ok, at last: we're happy. */
			switch (r_q.info_class)
			{
				case 3:
				{
					char *dom_name = unistrn2(r_q.dom.id3.uni_domain_name.buffer,
					                          r_q.dom.id3.uni_domain_name.uni_str_len);
					char *dom_sid  = dom_sid_to_string(&(r_q.dom.id3.dom_sid));
					fstrcpy(domain_name, dom_name);
					pstrcpy(domain_sid , dom_sid);

					valid_response = True;
					break;
				}
				case 5:
				{
					char *dom_name = unistrn2(r_q.dom.id5.uni_domain_name.buffer,
					                          r_q.dom.id5.uni_domain_name.uni_str_len);
					char *dom_sid  = dom_sid_to_string(&(r_q.dom.id5.dom_sid));
					fstrcpy(domain_name, dom_name);
					pstrcpy(domain_sid , dom_sid);

					valid_response = True;
					break;
				}
				default:
				{
					DEBUG(3,("LSA_QUERYINFOPOLICY: unknown info class\n"));
					domain_name[0] = 0;
					domain_sid [0] = 0;

					break;
				}
			}
			DEBUG(3,("LSA_QUERYINFOPOLICY (level %x): domain:%s  domain sid:%s\n",
			          r_q.info_class, domain_name, domain_sid));
		}
	}

	if (rparam) free(rparam);
	if (rdata) free(rdata);

	return valid_response;
}

/****************************************************************************
do a LSA Close
****************************************************************************/
BOOL do_lsa_close(uint16 fnum, uint32 call_id,
			LSA_POL_HND *hnd)
{
	char *rparam = NULL;
	char *rdata = NULL;
	char *p;
	int rdrcnt,rprcnt;
	pstring data; /* only 1024 bytes */
	uint16 setup[2]; /* only need 2 uint16 setup parameters */
	LSA_Q_CLOSE q_c;
    BOOL valid_close = False;

	if (hnd == NULL) return False;

	/* create and send a MSRPC command with api LSA_OPENPOLICY */

	DEBUG(4,("LSA Close\n"));

	/* store the parameters */
	make_q_close(&q_c, hnd);

	/* turn parameters into data stream */
	p = lsa_io_q_close(False, &q_c, data + 0x18, data, 4, 0);

	/* create the request RPC_HDR_RR with no data */
	create_rpc_request(call_id, LSA_CLOSE, data, PTR_DIFF(p, data));

	/* create setup parameters. */
	setup[0] = 0x0026; /* 0x26 indicates "transact named pipe" */
	setup[1] = fnum; /* file handle, from the SMBcreateX pipe, earlier */

	/* send the data on \PIPE\ */
	if (cli_call_api("\\PIPE\\", 0, PTR_DIFF(p, data), 2, 1024,
                BUFFER_SIZE,
				&rprcnt, &rdrcnt,
				NULL, data, setup,
				&rparam, &rdata))
	{
		LSA_R_CLOSE r_c;
		RPC_HDR_RR hdr;
		int hdr_len;
		int pkt_len;

		DEBUG(5, ("cli_call_api: return OK\n"));

		p = rdata;

		if (p) p = smb_io_rpc_hdr_rr   (True, &hdr, p, rdata, 4, 0);
		if (p) p = align_offset(p, rdata, 4); /* oh, what a surprise */

		hdr_len = PTR_DIFF(p, rdata);

		if (p && hdr_len != hdr.hdr.frag_len - hdr.alloc_hint)
		{
			/* header length not same as calculated header length */
			DEBUG(2,("do_lsa_close: hdr_len %x != frag_len-alloc_hint %x\n",
			          hdr_len, hdr.hdr.frag_len - hdr.alloc_hint));
			p = NULL;
		}

		if (p) p = lsa_io_r_close(True, &r_c, p, rdata, 4, 0);
		
		pkt_len = PTR_DIFF(p, rdata);

		if (p && pkt_len != hdr.hdr.frag_len)
		{
			/* packet data size not same as reported fragment length */
			DEBUG(2,("do_lsa_close: pkt_len %x != frag_len \n",
			                           pkt_len, hdr.hdr.frag_len));
			p = NULL;
		}

		if (p && r_c.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_OPENPOLICY: nt_status error %lx\n", r_c.status));
			p = NULL;
		}

		if (p)
		{
			/* check that the returned policy handle is all zeros */
			int i;
			valid_close = True;

			for (i = 0; i < sizeof(r_c.pol.data); i++)
			{
				if (r_c.pol.data[i] != 0)
				{
					valid_close = False;
					break;
				}
			}	
			if (!valid_close)
			{
				DEBUG(0,("LSA_CLOSE: non-zero handle returned\n"));
			}
		}
	}

	if (rparam) free(rparam);
	if (rdata) free(rdata);

	return valid_close;
}

#endif /* NTDOMAIN */
