/* 
   Unix SMB/CIFS implementation.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Tim Potter 2001
   Copyright (C) Paul Ashton                       1997.
   Copyright (C) Jeremy Allison                    1998.
   Copyright (C) Andrew Bartlett                   2001.
   
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

/* LSA Request Challenge. Sends our challenge to server, then gets
   server response. These are used to generate the credentials. */

NTSTATUS cli_net_req_chal(struct cli_state *cli, DOM_CHAL *clnt_chal, 
			  DOM_CHAL *srv_chal)
{
        prs_struct qbuf, rbuf;
        NET_Q_REQ_CHAL q;
        NET_R_REQ_CHAL r;
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

        prs_init(&qbuf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
        prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);
        
        /* create and send a MSRPC command with api NET_REQCHAL */

        DEBUG(4,("cli_net_req_chal: LSA Request Challenge from %s to %s: %s\n",
                 global_myname(), cli->desthost, credstr(clnt_chal->data)));
        
        /* store the parameters */
        init_q_req_chal(&q, cli->srv_name_slash, global_myname(), clnt_chal);
        
        /* Marshall data and send request */

        if (!net_io_q_req_chal("", &q,  &qbuf, 0) ||
            !rpc_api_pipe_req(cli, NET_REQCHAL, &qbuf, &rbuf)) {
                goto done;
        }

        /* Unmarhall response */

        if (!net_io_r_req_chal("", &r, &rbuf, 0)) {
                goto done;
        }

        result = r.status;

        /* Return result */

        if (NT_STATUS_IS_OK(result)) {
                memcpy(srv_chal, r.srv_chal.data, sizeof(srv_chal->data));
        }
        
 done:
        prs_mem_free(&qbuf);
        prs_mem_free(&rbuf);
        
        return result;
}

/****************************************************************************
LSA Authenticate 2

Send the client credential, receive back a server credential.
Ensure that the server credential returned matches the session key 
encrypt of the server challenge originally received. JRA.
****************************************************************************/

NTSTATUS cli_net_auth2(struct cli_state *cli, 
		       uint16 sec_chan, 
		       uint32 *neg_flags, DOM_CHAL *srv_chal)
{
        prs_struct qbuf, rbuf;
        NET_Q_AUTH_2 q;
        NET_R_AUTH_2 r;
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

        prs_init(&qbuf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
        prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

        /* create and send a MSRPC command with api NET_AUTH2 */

        DEBUG(4,("cli_net_auth2: srv:%s acct:%s sc:%x mc: %s chal %s neg: %x\n",
                 cli->srv_name_slash, cli->mach_acct, sec_chan, global_myname(),
                 credstr(cli->clnt_cred.challenge.data), *neg_flags));

        /* store the parameters */
        init_q_auth_2(&q, cli->srv_name_slash, cli->mach_acct, 
                      sec_chan, global_myname(), &cli->clnt_cred.challenge, 
                      *neg_flags);

        /* turn parameters into data stream */

        if (!net_io_q_auth_2("", &q,  &qbuf, 0) ||
            !rpc_api_pipe_req(cli, NET_AUTH2, &qbuf, &rbuf)) {
                goto done;
        }
        
        /* Unmarshall response */
        
        if (!net_io_r_auth_2("", &r, &rbuf, 0)) {
                goto done;
        }

        result = r.status;

        if (NT_STATUS_IS_OK(result)) {
                UTIME zerotime;
                
                /*
                 * Check the returned value using the initial
                 * server received challenge.
                 */

                zerotime.time = 0;
                if (cred_assert( &r.srv_chal, cli->sess_key, srv_chal, 
                                 zerotime) == 0) {

                        /*
                         * Server replied with bad credential. Fail.
                         */
                        DEBUG(0,("cli_net_auth2: server %s replied with bad credential (bad machine \
password ?).\n", cli->desthost ));
                        result = NT_STATUS_ACCESS_DENIED;
                        goto done;
                }
		*neg_flags = r.srv_flgs.neg_flags;
        }

 done:
        prs_mem_free(&qbuf);
        prs_mem_free(&rbuf);
        
        return result;
}

/****************************************************************************
LSA Authenticate 3

Send the client credential, receive back a server credential.
Ensure that the server credential returned matches the session key 
encrypt of the server challenge originally received. JRA.
****************************************************************************/

NTSTATUS cli_net_auth3(struct cli_state *cli, 
		       uint16 sec_chan, 
		       uint32 *neg_flags, DOM_CHAL *srv_chal)
{
        prs_struct qbuf, rbuf;
        NET_Q_AUTH_3 q;
        NET_R_AUTH_3 r;
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

        prs_init(&qbuf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
        prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

        /* create and send a MSRPC command with api NET_AUTH2 */

        DEBUG(4,("cli_net_auth3: srv:%s acct:%s sc:%x mc: %s chal %s neg: %x\n",
                 cli->srv_name_slash, cli->mach_acct, sec_chan, global_myname(),
                 credstr(cli->clnt_cred.challenge.data), *neg_flags));

        /* store the parameters */
        init_q_auth_3(&q, cli->srv_name_slash, cli->mach_acct, 
                      sec_chan, global_myname(), &cli->clnt_cred.challenge, 
                      *neg_flags);

        /* turn parameters into data stream */

        if (!net_io_q_auth_3("", &q,  &qbuf, 0) ||
            !rpc_api_pipe_req(cli, NET_AUTH3, &qbuf, &rbuf)) {
                goto done;
        }
        
        /* Unmarshall response */
        
        if (!net_io_r_auth_3("", &r, &rbuf, 0)) {
                goto done;
        }

        result = r.status;

        if (NT_STATUS_IS_OK(result)) {
                UTIME zerotime;
                
                /*
                 * Check the returned value using the initial
                 * server received challenge.
                 */

                zerotime.time = 0;
                if (cred_assert( &r.srv_chal, cli->sess_key, srv_chal, 
                                 zerotime) == 0) {

                        /*
                         * Server replied with bad credential. Fail.
                         */
                        DEBUG(0,("cli_net_auth3: server %s replied with bad credential (bad machine \
password ?).\n", cli->desthost ));
                        result = NT_STATUS_ACCESS_DENIED;
                        goto done;
                }
		*neg_flags = r.srv_flgs.neg_flags;
        }

 done:
        prs_mem_free(&qbuf);
        prs_mem_free(&rbuf);
        
        return result;
}

/* Initialize domain session credentials */

NTSTATUS cli_nt_setup_creds(struct cli_state *cli, 
			    uint16 sec_chan,
			    const unsigned char mach_pwd[16], uint32 *neg_flags, int level)
{
        DOM_CHAL clnt_chal;
        DOM_CHAL srv_chal;
        UTIME zerotime;
        NTSTATUS result;

        /******************* Request Challenge ********************/

        generate_random_buffer(clnt_chal.data, 8, False);
	
        /* send a client challenge; receive a server challenge */
        result = cli_net_req_chal(cli, &clnt_chal, &srv_chal);

        if (!NT_STATUS_IS_OK(result)) {
                DEBUG(0,("cli_nt_setup_creds: request challenge failed\n"));
                return result;
        }
        
        /**************** Long-term Session key **************/

        /* calculate the session key */
        cred_session_key(&clnt_chal, &srv_chal, mach_pwd, 
                         cli->sess_key);
        memset((char *)cli->sess_key+8, '\0', 8);

        /******************* Authenticate 2/3 ********************/

        /* calculate auth-2/3 credentials */
        zerotime.time = 0;
        cred_create(cli->sess_key, &clnt_chal, zerotime, &cli->clnt_cred.challenge);

        /*  
         * Send client auth-2/3 challenge.
         * Receive an auth-2/3 challenge response and check it.
         */
        switch (level) {
		case 2:
			result = cli_net_auth2(cli, sec_chan, neg_flags, &srv_chal);
			break;
		case 3:
			result = cli_net_auth3(cli, sec_chan, neg_flags, &srv_chal);
			break;
		default:
			DEBUG(1,("cli_nt_setup_creds: unsupported auth level: %d\n", level));
			break;
	}

	if (!NT_STATUS_IS_OK(result))
                DEBUG(3,("cli_nt_setup_creds: auth%d challenge failed %s\n", level, nt_errstr(result)));

        return result;
}

/* Logon Control 2 */

NTSTATUS cli_netlogon_logon_ctrl2(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                                  uint32 query_level)
{
	prs_struct qbuf, rbuf;
	NET_Q_LOGON_CTRL2 q;
	NET_R_LOGON_CTRL2 r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	init_net_q_logon_ctrl2(&q, cli->srv_name_slash, query_level);

	/* Marshall data and send request */

	if (!net_io_q_logon_ctrl2("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, NET_LOGON_CTRL2, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!net_io_r_logon_ctrl2("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* GetDCName */

NTSTATUS cli_netlogon_getdcname(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				const char *domainname, fstring dcname)
{
	prs_struct qbuf, rbuf;
	NET_Q_GETDCNAME q;
	NET_R_GETDCNAME r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	init_net_q_getdcname(&q, cli->srv_name_slash, domainname);

	/* Marshall data and send request */

	if (!net_io_q_getdcname("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, NET_GETDCNAME, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!net_io_r_getdcname("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	result = r.status;

	if (NT_STATUS_IS_OK(result))
		rpcstr_pull_unistr2_fstring(dcname, &r.uni_dcname);

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/****************************************************************************
Generate the next creds to use.
****************************************************************************/

static void gen_next_creds( struct cli_state *cli, DOM_CRED *new_clnt_cred)
{
	/*
	 * Create the new client credentials.
	 */
	
	cli->clnt_cred.timestamp.time = time(NULL);
	
	memcpy(new_clnt_cred, &cli->clnt_cred, sizeof(*new_clnt_cred));

	/* Calculate the new credentials. */
	cred_create(cli->sess_key, &(cli->clnt_cred.challenge),
		    new_clnt_cred->timestamp, &(new_clnt_cred->challenge));
}

/* Sam synchronisation */

NTSTATUS cli_netlogon_sam_sync(struct cli_state *cli, TALLOC_CTX *mem_ctx, DOM_CRED *ret_creds,
                               uint32 database_id, uint32 next_rid, uint32 *num_deltas,
                               SAM_DELTA_HDR **hdr_deltas, 
                               SAM_DELTA_CTR **deltas)
{
	prs_struct qbuf, rbuf;
	NET_Q_SAM_SYNC q;
	NET_R_SAM_SYNC r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        DOM_CRED clnt_creds;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        gen_next_creds(cli, &clnt_creds);

	init_net_q_sam_sync(&q, cli->srv_name_slash, cli->clnt_name_slash + 2,
                            &clnt_creds, ret_creds, database_id, next_rid);

	/* Marshall data and send request */

	if (!net_io_q_sam_sync("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, NET_SAM_SYNC, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!net_io_r_sam_sync("", cli->sess_key, &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

        /* Return results */

	result = r.status;
        *num_deltas = r.num_deltas2;
        *hdr_deltas = r.hdr_deltas;
        *deltas = r.deltas;

	memcpy(ret_creds, &r.srv_creds, sizeof(*ret_creds));

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Sam synchronisation */

NTSTATUS cli_netlogon_sam_deltas(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                                 uint32 database_id, UINT64_S seqnum,
                                 uint32 *num_deltas, 
                                 SAM_DELTA_HDR **hdr_deltas, 
                                 SAM_DELTA_CTR **deltas)
{
	prs_struct qbuf, rbuf;
	NET_Q_SAM_DELTAS q;
	NET_R_SAM_DELTAS r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        DOM_CRED clnt_creds;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        gen_next_creds(cli, &clnt_creds);

	init_net_q_sam_deltas(&q, cli->srv_name_slash, 
                              cli->clnt_name_slash + 2, &clnt_creds, 
                              database_id, seqnum);

	/* Marshall data and send request */

	if (!net_io_q_sam_deltas("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, NET_SAM_DELTAS, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!net_io_r_sam_deltas("", cli->sess_key, &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

        /* Return results */

	result = r.status;
        *num_deltas = r.num_deltas2;
        *hdr_deltas = r.hdr_deltas;
        *deltas = r.deltas;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Logon domain user */

NTSTATUS cli_netlogon_sam_logon(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				DOM_CRED *ret_creds,
                                const char *username, const char *password,
                                int logon_type)
{
	prs_struct qbuf, rbuf;
	NET_Q_SAM_LOGON q;
	NET_R_SAM_LOGON r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        DOM_CRED clnt_creds, dummy_rtn_creds;
        NET_ID_INFO_CTR ctr;
        NET_USER_INFO_3 user;
        int validation_level = 3;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);
	ZERO_STRUCT(dummy_rtn_creds);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

        /* Initialise input parameters */

        gen_next_creds(cli, &clnt_creds);

        q.validation_level = validation_level;

	if (ret_creds == NULL)
		ret_creds = &dummy_rtn_creds;

        ctr.switch_value = logon_type;

        switch (logon_type) {
        case INTERACTIVE_LOGON_TYPE: {
                unsigned char lm_owf_user_pwd[16], nt_owf_user_pwd[16];

                nt_lm_owf_gen(password, nt_owf_user_pwd, lm_owf_user_pwd);

                init_id_info1(&ctr.auth.id1, lp_workgroup(), 
                              0, /* param_ctrl */
                              0xdead, 0xbeef, /* LUID? */
                              username, cli->clnt_name_slash,
                              (const char *)cli->sess_key, lm_owf_user_pwd,
                              nt_owf_user_pwd);

                break;
        }
        case NET_LOGON_TYPE: {
                uint8 chal[8];
                unsigned char local_lm_response[24];
                unsigned char local_nt_response[24];

                generate_random_buffer(chal, 8, False);

                SMBencrypt(password, chal, local_lm_response);
                SMBNTencrypt(password, chal, local_nt_response);

                init_id_info2(&ctr.auth.id2, lp_workgroup(), 
                              0, /* param_ctrl */
                              0xdead, 0xbeef, /* LUID? */
                              username, cli->clnt_name_slash, chal,
                              local_lm_response, 24, local_nt_response, 24);
                break;
        }
        default:
                DEBUG(0, ("switch value %d not supported\n", 
                          ctr.switch_value));
                goto done;
        }

        init_sam_info(&q.sam_id, cli->srv_name_slash, global_myname(),
                      &clnt_creds, ret_creds, logon_type,
                      &ctr);

        /* Marshall data and send request */

	if (!net_io_q_sam_logon("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, NET_SAMLOGON, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

        r.user = &user;

	if (!net_io_r_sam_logon("", &r, &rbuf, 0)) {
		goto done;
	}

        /* Return results */

	result = r.status;
	memcpy(ret_creds, &r.srv_creds, sizeof(*ret_creds));

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

        return result;
}


/** 
 * Logon domain user with an 'network' SAM logon 
 *
 * @param info3 Pointer to a NET_USER_INFO_3 already allocated by the caller.
 **/

NTSTATUS cli_netlogon_sam_network_logon(struct cli_state *cli, TALLOC_CTX *mem_ctx,
					DOM_CRED *ret_creds,
					const char *username, const char *domain, const char *workstation, 
					const uint8 chal[8], 
					DATA_BLOB lm_response, DATA_BLOB nt_response,
					NET_USER_INFO_3 *info3)

{
	prs_struct qbuf, rbuf;
	NET_Q_SAM_LOGON q;
	NET_R_SAM_LOGON r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        DOM_CRED clnt_creds, dummy_rtn_creds;
	NET_ID_INFO_CTR ctr;
	int validation_level = 3;
	char *workstation_name_slash;
	uint8 netlogon_sess_key[16];
	static uint8 zeros[16];
	
	ZERO_STRUCT(q);
	ZERO_STRUCT(r);
	ZERO_STRUCT(dummy_rtn_creds);

	workstation_name_slash = talloc_asprintf(mem_ctx, "\\\\%s", workstation);
	
	if (!workstation_name_slash) {
		DEBUG(0, ("talloc_asprintf failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	gen_next_creds(cli, &clnt_creds);

	q.validation_level = validation_level;

	if (ret_creds == NULL)
		ret_creds = &dummy_rtn_creds;

        ctr.switch_value = NET_LOGON_TYPE;

	init_id_info2(&ctr.auth.id2, domain,
		      0, /* param_ctrl */
		      0xdead, 0xbeef, /* LUID? */
		      username, workstation_name_slash, (const uchar*)chal,
		      lm_response.data, lm_response.length, nt_response.data, nt_response.length);
 
        init_sam_info(&q.sam_id, cli->srv_name_slash, global_myname(),
                      &clnt_creds, ret_creds, NET_LOGON_TYPE,
                      &ctr);

        /* Marshall data and send request */

	if (!net_io_q_sam_logon("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, NET_SAMLOGON, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

        r.user = info3;

	if (!net_io_r_sam_logon("", &r, &rbuf, 0)) {
		goto done;
	}

	ZERO_STRUCT(netlogon_sess_key);
	memcpy(netlogon_sess_key, cli->sess_key, 8);
	
	if (memcmp(zeros, info3->user_sess_key, 16) != 0) {
		SamOEMhash(info3->user_sess_key, netlogon_sess_key, 16);
	} else {
		memset(info3->user_sess_key, '\0', 16);
	}

	if (memcmp(zeros, info3->padding, 16) != 0) {
		SamOEMhash(info3->padding, netlogon_sess_key, 16);
	} else {
		memset(info3->padding, '\0', 16);
	}

        /* Return results */

	result = r.status;
	memcpy(ret_creds, &r.srv_creds, sizeof(*ret_creds));

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

        return result;
}

/***************************************************************************
LSA Server Password Set.
****************************************************************************/

NTSTATUS cli_net_srv_pwset(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
			   const char *machine_name, uint8 hashed_mach_pwd[16])
{
	prs_struct rbuf;
	prs_struct qbuf; 
	DOM_CRED new_clnt_cred;
	NET_Q_SRV_PWSET q_s;
	uint16 sec_chan_type = 2;
	NTSTATUS nt_status;

	gen_next_creds( cli, &new_clnt_cred);
	
	prs_init(&qbuf , 1024, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0,    mem_ctx, UNMARSHALL);
	
	DEBUG(4,("cli_net_srv_pwset: srv:%s acct:%s sc: %d mc: %s clnt %s %x\n",
		 cli->srv_name_slash, cli->mach_acct, sec_chan_type, machine_name,
		 credstr(new_clnt_cred.challenge.data), new_clnt_cred.timestamp.time));
	
        /* store the parameters */
	init_q_srv_pwset(&q_s, cli->srv_name_slash, (const char *)cli->sess_key,
			 cli->mach_acct, sec_chan_type, machine_name, 
			 &new_clnt_cred, hashed_mach_pwd);
	
	/* turn parameters into data stream */
	if(!net_io_q_srv_pwset("", &q_s,  &qbuf, 0)) {
		DEBUG(0,("cli_net_srv_pwset: Error : failed to marshall NET_Q_SRV_PWSET struct.\n"));
		nt_status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	
	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, NET_SRVPWSET, &qbuf, &rbuf))
	{
		NET_R_SRV_PWSET r_s;
		
		if (!net_io_r_srv_pwset("", &r_s, &rbuf, 0)) {
			nt_status =  NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
		
		nt_status = r_s.status;

		if (!NT_STATUS_IS_OK(r_s.status))
		{
			/* report error code */
			DEBUG(0,("cli_net_srv_pwset: %s\n", nt_errstr(nt_status)));
			goto done;
		}

		/* Update the credentials. */
		if (!clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), &(r_s.srv_cred)))
		{
			/*
			 * Server replied with bad credential. Fail.
			 */
			DEBUG(0,("cli_net_srv_pwset: server %s replied with bad credential (bad machine \
password ?).\n", cli->desthost ));
			nt_status = NT_STATUS_UNSUCCESSFUL;
		}
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);
	
	return nt_status;
}

