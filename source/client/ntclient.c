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
extern pstring username;
extern pstring workgroup;

#define CLIENT_TIMEOUT (30*1000)

#ifdef NTDOMAIN

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
do a LSA Request Challenge
****************************************************************************/
static BOOL do_lsa_req_chal(uint16 fnum,
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
	int call_id = 0x1;
    BOOL valid_chal = False;

	if (srv_chal == NULL || clnt_chal == NULL) return False;

	/* create and send a MSRPC command with api LSA_REQCHAL */

	DEBUG(4,("LSA Request Challenge from %s to %s: %lx %lx\n",
	          desthost, myhostname, clnt_chal->data[0], clnt_chal->data[1]));

	/* store the parameters */
	make_q_req_chal(&q_c, desthost, myhostname, clnt_chal);


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
do a LSA Authenticate 2
****************************************************************************/
static BOOL do_lsa_auth2(uint16 fnum,
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
	int call_id = 0x1;
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

	/* create the request RPC_HDR _after_ the main data: length is now known */
	create_rpc_request(call_id, LSA_AUTH2, data, PTR_DIFF(p, data));

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
		LSA_R_AUTH_2 r_a;
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
			DEBUG(2,("do_lsa_auth2: hdr_len %x != frag_len-alloc_hint\n",
			          hdr_len, hdr.frag_len - hdr.alloc_hint));
			p = NULL;
		}

		if (p) p = lsa_io_r_auth_2(True, &r_a, p, rdata, 4, 0);
		
		pkt_len = PTR_DIFF(p, rdata);

		if (p && pkt_len != hdr.frag_len)
		{
			/* packet data size not same as reported fragment length */
			DEBUG(2,("do_lsa_auth2: pkt_len %x != frag_len \n",
			                           pkt_len, hdr.frag_len));
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
static BOOL do_lsa_sam_logon(uint16 fnum, uint32 sess_key[2], DOM_CRED *sto_clnt_cred,
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
	int call_id = 0x1;
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

	/* create the request RPC_HDR _after_ the main data: length is now known */
	create_rpc_request(call_id, LSA_SAMLOGON, data, PTR_DIFF(p, data));

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
		LSA_R_SAM_LOGON r_s;
		RPC_HDR hdr;
		int hdr_len;
		int pkt_len;

		r_s.user = user_info;

		DEBUG(5, ("cli_call_api: return OK\n"));

		p = rdata;

		if (p) p = smb_io_rpc_hdr   (True, &hdr, p, rdata, 4, 0);
		if (p) p = align_offset(p, rdata, 4); /* oh, what a surprise */

		hdr_len = PTR_DIFF(p, rdata);

		if (p && hdr_len != hdr.frag_len - hdr.alloc_hint)
		{
			/* header length not same as calculated header length */
			DEBUG(2,("do_lsa_sam_logon: hdr_len %x != frag_len-alloc_hint\n",
			          hdr_len, hdr.frag_len - hdr.alloc_hint));
			p = NULL;
		}

		if (p) p = lsa_io_r_sam_logon(True, &r_s, p, rdata, 4, 0);
		
		pkt_len = PTR_DIFF(p, rdata);

		if (p && pkt_len != hdr.frag_len)
		{
			/* packet data size not same as reported fragment length */
			DEBUG(2,("do_lsa_sam_logon: pkt_len %x != frag_len \n",
			                           pkt_len, hdr.frag_len));
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
#endif
	}

	if (rparam) free(rparam);
	if (rdata) free(rdata);

	return valid_cred;
}

/***************************************************************************
do a LSA SAM Logoff
****************************************************************************/
static BOOL do_lsa_sam_logoff(uint16 fnum, uint32 sess_key[2], DOM_CRED *sto_clnt_cred,
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
	int call_id = 0x1;
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

	/* create the request RPC_HDR _after_ the main data: length is now known */
	create_rpc_request(call_id, LSA_SAMLOGOFF, data, PTR_DIFF(p, data));

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
		LSA_R_SAM_LOGOFF r_s;
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
			DEBUG(2,("do_lsa_sam_logoff: hdr_len %x != frag_len-alloc_hint\n",
			          hdr_len, hdr.frag_len - hdr.alloc_hint));
			p = NULL;
		}

		if (p) p = lsa_io_r_sam_logoff(True, &r_s, p, rdata, 4, 0);
		
		pkt_len = PTR_DIFF(p, rdata);

		if (p && pkt_len != hdr.frag_len)
		{
			/* packet data size not same as reported fragment length */
			DEBUG(2,("do_lsa_sam_logoff: pkt_len %x != frag_len \n",
			                           pkt_len, hdr.frag_len));
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

/****************************************************************************
experimental nt login.
****************************************************************************/
BOOL do_nt_login(char *desthost, char *myhostname,
				int Client, int cnum)
{
	DOM_CHAL clnt_chal;
	DOM_CHAL srv_chal;

	DOM_CRED clnt_cred;

	DOM_CHAL auth2_srv_chal;

	DOM_CRED sam_logon_clnt_cred;
	DOM_CRED sam_logon_rtn_cred;
	DOM_CRED sam_logon_srv_cred;

	DOM_CRED sam_logoff_clnt_cred;
	DOM_CRED sam_logoff_rtn_cred;
	DOM_CRED sam_logoff_srv_cred;

	DOM_ID_INFO_1 id1;
	LSA_USER_INFO user_info1;

	UTIME zerotime;

	uint32 sess_key[2];
	char nt_owf_mach_pwd[16];
	fstring mach_acct;
	fstring mach_pwd;

	uint16 fnum;
	char *inbuf,*outbuf; 

	zerotime.time = 0;

	inbuf  = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
	outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

	if (!inbuf || !outbuf)
	{
		DEBUG(0,("out of memory\n"));
		return False;
	}
	
	/******************* open the \PIPE\NETLOGON file *****************/

	if ((fnum = open_rpc_pipe(inbuf, outbuf, PIPE_NETLOGON, Client, cnum)) == 0xffff)
	{
		free(inbuf); free(outbuf);
		return False;
	}

	/******************* Request Challenge ********************/

	fstrcpy(mach_acct, myhostname);
	strlower(mach_pwd);

	fstrcpy(mach_pwd , myhostname);
	strcat(mach_acct, "$");

	clnt_chal.data[0] = 0x11111111;
	clnt_chal.data[1] = 0x22222222;
	
	/* send a client challenge; receive a server challenge */
	if (!do_lsa_req_chal(fnum, desthost, myhostname, &clnt_chal, &srv_chal))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	/************ Long-term Session key (default) **********/

#if 0
	/* DAMN!  can't get the machine password - need become_root() to do it! */
	/* get the machine password */
	if (!get_md4pw(mach_acct, nt_owf_mach_pwd))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	DEBUG(5,("got nt owf from smbpasswd entry: %s\n", mach_pwd));
#else

	{
		char lm_owf_mach_pwd[16];
		nt_lm_owf_gen(mach_pwd, nt_owf_mach_pwd, lm_owf_mach_pwd);
		DEBUG(5,("generating nt owf from initial machine pwd: %s\n", mach_pwd));
	}

#endif

	dump_data(6, nt_owf_mach_pwd, 16);

	/* calculate the session key */
	cred_session_key(&clnt_chal, &srv_chal, nt_owf_mach_pwd, sess_key);


	/******************* Authenticate 2 ********************/

	/* calculate auth-2 credentials */
	cred_create(sess_key, &clnt_chal, zerotime, &(clnt_cred.challenge));

	/* send client auth-2 challenge; receive an auth-2 challenge */
	if (!do_lsa_auth2(fnum, desthost, mach_acct, 2, myhostname,
	                  &(clnt_cred.challenge), 0x000001ff, &auth2_srv_chal))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}


	/*********************** SAM Info ***********************/

	/* this is used in both the SAM Logon and the SAM Logoff */
	make_id_info1(&id1, workgroup, 0,
	              getuid(), 0,
	              username, myhostname,
	              NULL, NULL);

	/*********************** SAM Logon **********************/

	clnt_cred.timestamp.time = sam_logon_clnt_cred.timestamp.time = time(NULL);

	/* calculate sam logon credentials, using the auth2 client challenge */
	cred_create(sess_key, &(clnt_cred.challenge), sam_logon_clnt_cred.timestamp,
	                                  &(sam_logon_clnt_cred.challenge));

	/* send client sam-logon challenge; receive a sam-logon challenge */
	if (!do_lsa_sam_logon(fnum, sess_key, &clnt_cred, 
	                  desthost, mach_acct, 
	                  &sam_logon_clnt_cred, &sam_logon_rtn_cred,
	                  1, 1, &id1, &user_info1,
	                  &sam_logon_srv_cred))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	/*********************** SAM Logoff *********************/

	clnt_cred.timestamp.time = sam_logoff_clnt_cred.timestamp.time = time(NULL);

	/* calculate sam logoff credentials, using the sam logon return challenge */
	cred_create(sess_key, &(clnt_cred.challenge),
	                        sam_logoff_clnt_cred.timestamp,
	                      &(sam_logoff_clnt_cred.challenge));

	/* send client sam-logoff challenge; receive a sam-logoff challenge */
	if (!do_lsa_sam_logoff(fnum, sess_key, &clnt_cred,
	                  desthost, mach_acct, 
	                  &sam_logoff_clnt_cred, &sam_logoff_rtn_cred,
	                  1, 1, &id1,
	                  &sam_logoff_srv_cred))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
	free(inbuf); free(outbuf);

	return True;
}
