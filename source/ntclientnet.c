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
do a LSA Request Challenge
****************************************************************************/
BOOL do_lsa_req_chal(uint16 fnum, uint32 call_id,
		char *desthost, char *myhostname,
        DOM_CHAL *clnt_chal, DOM_CHAL *srv_chal)
{
	char *rparam = NULL;
	char *rdata = NULL;
	char *p;
	int rdrcnt,rprcnt;
	pstring data; /* only 1024 bytes */
	uint16 setup[2]; /* only need 2 uint16 setup parameters */
	LSA_Q_REQ_CHAL q_c;
    BOOL valid_chal = False;

	if (srv_chal == NULL || clnt_chal == NULL) return False;

	/* create and send a MSRPC command with api LSA_REQCHAL */

	DEBUG(4,("LSA Request Challenge from %s to %s: %lx %lx\n",
	          desthost, myhostname, clnt_chal->data[0], clnt_chal->data[1]));

	/* store the parameters */
	make_q_req_chal(&q_c, desthost, myhostname, clnt_chal);


	/* turn parameters into data stream */
	p = lsa_io_q_req_chal(False, &q_c, data + 0x18, data, 4, 0);

	/* create the request RPC_HDR_RR _after_ the main data: length is now known */
	create_rpc_request(call_id, LSA_REQCHAL, data, PTR_DIFF(p, data));

	/* create setup parameters. */
	setup[0] = 0x0026; /* 0x26 indicates "transact named pipe" */
	setup[1] = fnum; /* file handle, from the SMBcreateX pipe, earlier */

	/* send the data on \PIPE\ */
	if (cli_call_api("\\PIPE\\", 0, PTR_DIFF(p, data), 2, 1024,
                BUFFER_SIZE,
				&rprcnt,&rdrcnt,
				NULL, data, setup,
				&rparam,&rdata))
	{
		LSA_R_REQ_CHAL r_c;
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
			DEBUG(2,("do_lsa_req_chal: hdr_len %x != frag_len-alloc_hint %x\n",
			          hdr_len, hdr.hdr.frag_len - hdr.alloc_hint));
			p = NULL;
		}

		if (p) p = lsa_io_r_req_chal(True, &r_c, p, rdata, 4, 0);
		
		pkt_len = PTR_DIFF(p, rdata);

		if (p && pkt_len != hdr.hdr.frag_len)
		{
			/* packet data size not same as reported fragment length */
			DEBUG(2,("do_lsa_req_chal: pkt_len %x != frag_len \n",
			                           pkt_len, hdr.hdr.frag_len));
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
do a LSA Authenticate 2
****************************************************************************/
BOOL do_lsa_auth2(uint16 fnum, uint32 call_id,
		char *logon_srv, char *acct_name, uint16 sec_chan, char *comp_name,
        DOM_CHAL *clnt_chal, uint32 neg_flags, DOM_CHAL *srv_chal)
{
	char *rparam = NULL;
	char *rdata = NULL;
	char *p;
	int rdrcnt,rprcnt;
	pstring data; /* only 1024 bytes */
	uint16 setup[2]; /* only need 2 uint16 setup parameters */
	LSA_Q_AUTH_2 q_a;
    BOOL valid_chal = False;

	if (srv_chal == NULL || clnt_chal == NULL) return False;

	/* create and send a MSRPC command with api LSA_AUTH2 */

	DEBUG(4,("LSA Authenticate 2: srv:%s acct:%s sc:%x mc: %s chal %lx %lx neg: %lx\n",
	          logon_srv, acct_name, sec_chan, comp_name,
	          clnt_chal->data[0], clnt_chal->data[1], neg_flags));

	/* store the parameters */
	make_q_auth_2(&q_a, logon_srv, acct_name, sec_chan, comp_name,
	             clnt_chal, neg_flags);

	/* turn parameters into data stream */
	p = lsa_io_q_auth_2(False, &q_a, data + 0x18, data, 4, 0);

	/* create the request RPC_HDR_RR _after_ the main data: length is now known */
	create_rpc_request(call_id, LSA_AUTH2, data, PTR_DIFF(p, data));

	/* create setup parameters. */
	setup[0] = 0x0026; /* 0x26 indicates "transact named pipe" */
	setup[1] = fnum; /* file handle, from the SMBcreateX pipe, earlier */

	/* send the data on \PIPE\ */
	if (cli_call_api("\\PIPE\\", 0, PTR_DIFF(p, data), 2, 1024,
                BUFFER_SIZE,
				&rprcnt,&rdrcnt,
				NULL, data, setup,
				&rparam,&rdata))
	{
		LSA_R_AUTH_2 r_a;
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
			DEBUG(2,("do_lsa_auth2: hdr_len %x != frag_len-alloc_hint %x\n",
			          hdr_len, hdr.hdr.frag_len - hdr.alloc_hint));
			p = NULL;
		}

		if (p) p = lsa_io_r_auth_2(True, &r_a, p, rdata, 4, 0);
		
		pkt_len = PTR_DIFF(p, rdata);

		if (p && pkt_len != hdr.hdr.frag_len)
		{
			/* packet data size not same as reported fragment length */
			DEBUG(2,("do_lsa_auth2: pkt_len %x != frag_len \n",
			                           pkt_len, hdr.hdr.frag_len));
			p = NULL;
		}

		if (p && r_a.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_AUTH2: nt_status error %lx\n", r_a.status));
			p = NULL;
		}

		if (p && r_a.srv_flgs.neg_flags != q_a.clnt_flgs.neg_flags)
		{
			/* report different neg_flags */
			DEBUG(0,("LSA_AUTH2: error neg_flags (q,r) differ - (%lx,%lx)\n",
					q_a.clnt_flgs.neg_flags, r_a.srv_flgs.neg_flags));
			p = NULL;
		}

		if (p)
		{
			/* ok, at last: we're happy. return the challenge */
			memcpy(srv_chal, r_a.srv_chal.data, sizeof(srv_chal->data));
			valid_chal = True;
		}
	}

	if (rparam) free(rparam);
	if (rdata) free(rdata);

	return valid_chal;
}

/***************************************************************************
do a LSA SAM Logon
****************************************************************************/
BOOL do_lsa_sam_logon(uint16 fnum, uint32 call_id,
		uint32 sess_key[2], DOM_CRED *sto_clnt_cred,
		char *logon_srv, char *comp_name,
        DOM_CRED *clnt_cred, DOM_CRED *rtn_cred,
		uint16 logon_level, uint16 switch_value, DOM_ID_INFO_1 *id1,
		LSA_USER_INFO *user_info,
		DOM_CRED *srv_cred)
{
	char *rparam = NULL;
	char *rdata = NULL;
	char *p;
	int rdrcnt,rprcnt;
	pstring data; /* only 1024 bytes */
	uint16 setup[2]; /* only need 2 uint16 setup parameters */
	LSA_Q_SAM_LOGON q_s;
    BOOL valid_cred = False;

	if (srv_cred == NULL || clnt_cred == NULL || rtn_cred == NULL || user_info == NULL) return False;

	/* create and send a MSRPC command with api LSA_SAMLOGON */

	DEBUG(4,("LSA SAM Logon: srv:%s mc:%s clnt %lx %lx %lx rtn: %lx %lx %lx ll: %d\n",
	          logon_srv, comp_name,
	          clnt_cred->challenge.data[0], clnt_cred->challenge.data[1], clnt_cred->timestamp.time,
	          rtn_cred ->challenge.data[0], rtn_cred ->challenge.data[1], rtn_cred ->timestamp.time,
	          logon_level));

	/* store the parameters */
	make_sam_info(&(q_s.sam_id), logon_srv, comp_name,
	             clnt_cred, rtn_cred, logon_level, switch_value, id1);

	/* turn parameters into data stream */
	p = lsa_io_q_sam_logon(False, &q_s, data + 0x18, data, 4, 0);

	/* create the request RPC_HDR_RR _after_ the main data: length is now known */
	create_rpc_request(call_id, LSA_SAMLOGON, data, PTR_DIFF(p, data));

	/* create setup parameters. */
	setup[0] = 0x0026; /* 0x26 indicates "transact named pipe" */
	setup[1] = fnum; /* file handle, from the SMBcreateX pipe, earlier */

	/* send the data on \PIPE\ */
	if (cli_call_api("\\PIPE\\", 0, PTR_DIFF(p, data), 2, 1024,
                BUFFER_SIZE,
				&rprcnt,&rdrcnt,
				NULL, data, setup,
				&rparam,&rdata))
	{
		LSA_R_SAM_LOGON r_s;
		RPC_HDR_RR hdr;
		int hdr_len;
		int pkt_len;

		r_s.user = user_info;

		DEBUG(5, ("cli_call_api: return OK\n"));

		p = rdata;

		if (p) p = smb_io_rpc_hdr_rr   (True, &hdr, p, rdata, 4, 0);
		if (p) p = align_offset(p, rdata, 4); /* oh, what a surprise */

		hdr_len = PTR_DIFF(p, rdata);

		if (p && hdr_len != hdr.hdr.frag_len - hdr.alloc_hint)
		{
			/* header length not same as calculated header length */
			DEBUG(2,("do_lsa_sam_logon: hdr_len %x != frag_len-alloc_hint %x\n",
			          hdr_len, hdr.hdr.frag_len - hdr.alloc_hint));
			p = NULL;
		}

		if (p) p = lsa_io_r_sam_logon(True, &r_s, p, rdata, 4, 0);
		
		pkt_len = PTR_DIFF(p, rdata);

		if (p && pkt_len != hdr.hdr.frag_len)
		{
			/* packet data size not same as reported fragment length */
			DEBUG(2,("do_lsa_sam_logon: pkt_len %x != frag_len \n",
			                           pkt_len, hdr.hdr.frag_len));
			p = NULL;
		}

		if (p && r_s.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_SAMLOGON: nt_status error %lx\n", r_s.status));
			p = NULL;
		}

		if (p && r_s.switch_value != 3)
		{
			/* report different switch_value */
			DEBUG(0,("LSA_SAMLOGON: switch_value of 3 expected %x\n",
					r_s.switch_value));
			p = NULL;
		}

		if (p)
		{
			if (clnt_deal_with_creds(sess_key, sto_clnt_cred, &(r_s.srv_creds)))
			{
				DEBUG(5, ("do_lsa_sam_logon: server credential check OK\n"));
				/* ok, at last: we're happy. return the challenge */
				memcpy(srv_cred, &(r_s.srv_creds), sizeof(r_s.srv_creds));
				valid_cred = True;
			}
			else
			{
				DEBUG(5, ("do_lsa_sam_logon: server credential check failed\n"));
			}
		}
	}

	if (rparam) free(rparam);
	if (rdata) free(rdata);

	return valid_cred;
}

/***************************************************************************
do a LSA SAM Logoff
****************************************************************************/
BOOL do_lsa_sam_logoff(uint16 fnum, uint32 call_id,
		uint32 sess_key[2], DOM_CRED *sto_clnt_cred,
		char *logon_srv, char *comp_name,
        DOM_CRED *clnt_cred, DOM_CRED *rtn_cred,
		uint16 logon_level, uint16 switch_value, DOM_ID_INFO_1 *id1,
		DOM_CRED *srv_cred)
{
	char *rparam = NULL;
	char *rdata = NULL;
	char *p;
	int rdrcnt,rprcnt;
	pstring data; /* only 1024 bytes */
	uint16 setup[2]; /* only need 2 uint16 setup parameters */
	LSA_Q_SAM_LOGOFF q_s;
    BOOL valid_cred = False;

	if (srv_cred == NULL || clnt_cred == NULL || rtn_cred == NULL) return False;

	/* create and send a MSRPC command with api LSA_SAMLOGON */

	DEBUG(4,("LSA SAM Logoff: srv:%s mc:%s clnt %lx %lx %lx rtn: %lx %lx %lx ll: %d\n",
	          logon_srv, comp_name,
	          clnt_cred->challenge.data[0], clnt_cred->challenge.data[1], clnt_cred->timestamp.time,
	          rtn_cred ->challenge.data[0], rtn_cred ->challenge.data[1], rtn_cred ->timestamp.time,
	          logon_level));

	/* store the parameters */
	make_sam_info(&(q_s.sam_id), logon_srv, comp_name,
	             clnt_cred, rtn_cred, logon_level, switch_value, id1);

	/* turn parameters into data stream */
	p = lsa_io_q_sam_logoff(False, &q_s, data + 0x18, data, 4, 0);

	/* create the request RPC_HDR_RR _after_ the main data: length is now known */
	create_rpc_request(call_id, LSA_SAMLOGOFF, data, PTR_DIFF(p, data));

	/* create setup parameters. */
	setup[0] = 0x0026; /* 0x26 indicates "transact named pipe" */
	setup[1] = fnum; /* file handle, from the SMBcreateX pipe, earlier */

	/* send the data on \PIPE\ */
	if (cli_call_api("\\PIPE\\", 0, PTR_DIFF(p, data), 2, 1024,
                BUFFER_SIZE,
				&rprcnt,&rdrcnt,
				NULL, data, setup,
				&rparam,&rdata))
	{
		LSA_R_SAM_LOGOFF r_s;
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
			DEBUG(2,("do_lsa_sam_logoff: hdr_len %x != frag_len-alloc_hint %x\n",
			          hdr_len, hdr.hdr.frag_len - hdr.alloc_hint));
			p = NULL;
		}

		if (p) p = lsa_io_r_sam_logoff(True, &r_s, p, rdata, 4, 0);
		
		pkt_len = PTR_DIFF(p, rdata);

		if (p && pkt_len != hdr.hdr.frag_len)
		{
			/* packet data size not same as reported fragment length */
			DEBUG(2,("do_lsa_sam_logoff: pkt_len %x != frag_len \n",
			                           pkt_len, hdr.hdr.frag_len));
			p = NULL;
		}

		if (p && r_s.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_SAMLOGOFF: nt_status error %lx\n", r_s.status));
			p = NULL;
		}

		if (p)
		{
			if (clnt_deal_with_creds(sess_key, sto_clnt_cred, &(r_s.srv_creds)))
			{
				DEBUG(5, ("do_lsa_sam_logoff: server credential check OK\n"));
				/* ok, at last: we're happy. return the challenge */
				memcpy(srv_cred, &(r_s.srv_creds), sizeof(r_s.srv_creds));
				valid_cred = True;
			}
			else
			{
				DEBUG(5, ("do_lsa_sam_logoff: server credential check failed\n"));
			}
		}
	}

	if (rparam) free(rparam);
	if (rdata) free(rdata);

	return valid_cred;
}

#endif /* NTDOMAIN */
