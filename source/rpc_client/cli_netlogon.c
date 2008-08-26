/*
   Unix SMB/CIFS implementation.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1992-2000
   Copyright (C) Jeremy Allison                    1998.
   Largely re-written by Jeremy Allison (C)	   2005.
   Copyright (C) Guenther Deschner                 2008.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"

/* LSA Request Challenge. Sends our challenge to server, then gets
   server response. These are used to generate the credentials.
 The sent and received challenges are stored in the netlog pipe
 private data. Only call this via rpccli_netlogon_setup_creds(). JRA.
*/

/* instead of rpccli_net_req_chal() we use rpccli_netr_ServerReqChallenge() now - gd */

#if 0
/****************************************************************************
LSA Authenticate 2

Send the client credential, receive back a server credential.
Ensure that the server credential returned matches the session key
encrypt of the server challenge originally received. JRA.
****************************************************************************/

  NTSTATUS rpccli_net_auth2(struct rpc_pipe_client *cli,
		       uint16 sec_chan,
		       uint32 *neg_flags, DOM_CHAL *srv_chal)
{
        prs_struct qbuf, rbuf;
        NET_Q_AUTH_2 q;
        NET_R_AUTH_2 r;
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	fstring machine_acct;

	if ( sec_chan == SEC_CHAN_DOMAIN )
		fstr_sprintf( machine_acct, "%s$", lp_workgroup() );
	else
		fstrcpy( machine_acct, cli->mach_acct );

        /* create and send a MSRPC command with api NET_AUTH2 */

        DEBUG(4,("cli_net_auth2: srv:%s acct:%s sc:%x mc: %s chal %s neg: %x\n",
                 cli->srv_name_slash, machine_acct, sec_chan, global_myname(),
                 credstr(cli->clnt_cred.challenge.data), *neg_flags));

        /* store the parameters */

        init_q_auth_2(&q, cli->srv_name_slash, machine_acct,
                      sec_chan, global_myname(), &cli->clnt_cred.challenge,
                      *neg_flags);

        /* turn parameters into data stream */

	CLI_DO_RPC(cli, mem_ctx, PI_NETLOGON, NET_AUTH2,
		q, r,
		qbuf, rbuf,
		net_io_q_auth_2,
		net_io_r_auth_2,
		NT_STATUS_UNSUCCESSFUL);

        result = r.status;

        if (NT_STATUS_IS_OK(result)) {
                UTIME zerotime;

                /*
                 * Check the returned value using the initial
                 * server received challenge.
                 */

                zerotime.time = 0;
                if (cred_assert( &r.srv_chal, cli->sess_key, srv_chal, zerotime) == 0) {

                        /*
                         * Server replied with bad credential. Fail.
                         */
                        DEBUG(0,("cli_net_auth2: server %s replied with bad credential (bad machine \
password ?).\n", cli->cli->desthost ));
			return NT_STATUS_ACCESS_DENIED;
                }
		*neg_flags = r.srv_flgs.neg_flags;
        }

        return result;
}
#endif

/****************************************************************************
 LSA Authenticate 2

 Send the client credential, receive back a server credential.
 The caller *must* ensure that the server credential returned matches the session key
 encrypt of the server challenge originally received. JRA.
****************************************************************************/

/* instead of rpccli_net_auth2() we use rpccli_netr_ServerAuthenticate2() now -  gd */


/****************************************************************************
 Wrapper function that uses the auth and auth2 calls to set up a NETLOGON
 credentials chain. Stores the credentials in the struct dcinfo in the
 netlogon pipe struct.
****************************************************************************/

NTSTATUS rpccli_netlogon_setup_creds(struct rpc_pipe_client *cli,
				     const char *server_name,
				     const char *domain,
				     const char *clnt_name,
				     const char *machine_account,
				     const unsigned char machine_pwd[16],
				     enum netr_SchannelType sec_chan_type,
				     uint32_t *neg_flags_inout)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	struct netr_Credential clnt_chal_send;
	struct netr_Credential srv_chal_recv;
	struct dcinfo *dc;
	bool retried = false;

	SMB_ASSERT(cli->pipe_idx == PI_NETLOGON);

	dc = cli->dc;
	if (!dc) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Ensure we don't reuse any of this state. */
	ZERO_STRUCTP(dc);

	/* Store the machine account password we're going to use. */
	memcpy(dc->mach_pw, machine_pwd, 16);

	fstrcpy(dc->remote_machine, "\\\\");
	fstrcat(dc->remote_machine, server_name);

	fstrcpy(dc->domain, domain);

	fstr_sprintf( dc->mach_acct, "%s$", machine_account);

 again:
	/* Create the client challenge. */
	generate_random_buffer(clnt_chal_send.data, 8);

	/* Get the server challenge. */
	result = rpccli_netr_ServerReqChallenge(cli, cli->mem_ctx,
						dc->remote_machine,
						clnt_name,
						&clnt_chal_send,
						&srv_chal_recv);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	/* Calculate the session key and client credentials */
	creds_client_init(*neg_flags_inout,
			dc,
			&clnt_chal_send,
			&srv_chal_recv,
			machine_pwd,
			&clnt_chal_send);

	/*
	 * Send client auth-2 challenge and receive server repy.
	 */

	result = rpccli_netr_ServerAuthenticate2(cli, cli->mem_ctx,
						 dc->remote_machine,
						 dc->mach_acct,
						 sec_chan_type,
						 clnt_name,
						 &clnt_chal_send, /* input. */
						 &srv_chal_recv, /* output. */
						 neg_flags_inout);

	/* we might be talking to NT4, so let's downgrade in that case and retry
	 * with the returned neg_flags - gd */

	if (NT_STATUS_EQUAL(result, NT_STATUS_ACCESS_DENIED) && !retried) {
		retried = true;
		goto again;
	}

	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	/*
	 * Check the returned value using the initial
	 * server received challenge.
	 */

	if (!netlogon_creds_client_check(dc, &srv_chal_recv)) {
		/*
		 * Server replied with bad credential. Fail.
		 */
		DEBUG(0,("rpccli_netlogon_setup_creds: server %s "
			"replied with bad credential\n",
			cli->cli->desthost ));
		return NT_STATUS_ACCESS_DENIED;
	}

	DEBUG(5,("rpccli_netlogon_setup_creds: server %s credential "
		"chain established.\n",
		cli->cli->desthost ));

	return NT_STATUS_OK;
}

/* Logon domain user */

NTSTATUS rpccli_netlogon_sam_logon(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   uint32 logon_parameters,
				   const char *domain,
				   const char *username,
				   const char *password,
				   const char *workstation,
				   int logon_type)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	struct netr_Authenticator clnt_creds;
	struct netr_Authenticator ret_creds;
	union netr_LogonInfo *logon;
	union netr_Validation validation;
	uint8_t authoritative;
	int validation_level = 3;
	fstring clnt_name_slash;
	uint8 zeros[16];

	ZERO_STRUCT(ret_creds);
	ZERO_STRUCT(zeros);

	logon = TALLOC_ZERO_P(mem_ctx, union netr_LogonInfo);
	if (!logon) {
		return NT_STATUS_NO_MEMORY;
	}

	if (workstation) {
		fstr_sprintf( clnt_name_slash, "\\\\%s", workstation );
	} else {
		fstr_sprintf( clnt_name_slash, "\\\\%s", global_myname() );
	}

	/* Initialise input parameters */

	netlogon_creds_client_step(cli->dc, &clnt_creds);

	switch (logon_type) {
	case INTERACTIVE_LOGON_TYPE: {

		struct netr_PasswordInfo *password_info;

		struct samr_Password lmpassword;
		struct samr_Password ntpassword;

		unsigned char lm_owf_user_pwd[16], nt_owf_user_pwd[16];

		unsigned char lm_owf[16];
		unsigned char nt_owf[16];
		unsigned char key[16];

		password_info = TALLOC_ZERO_P(mem_ctx, struct netr_PasswordInfo);
		if (!password_info) {
			return NT_STATUS_NO_MEMORY;
		}

		nt_lm_owf_gen(password, nt_owf_user_pwd, lm_owf_user_pwd);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("lm cypher:"));
		dump_data(100, lm_owf_user_pwd, 16);

		DEBUG(100,("nt cypher:"));
		dump_data(100, nt_owf_user_pwd, 16);
#endif
		memset(key, 0, 16);
		memcpy(key, cli->dc->sess_key, 8);

		memcpy(lm_owf, lm_owf_user_pwd, 16);
		SamOEMhash(lm_owf, key, 16);
		memcpy(nt_owf, nt_owf_user_pwd, 16);
		SamOEMhash(nt_owf, key, 16);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("encrypt of lm owf password:"));
		dump_data(100, lm_owf, 16);

		DEBUG(100,("encrypt of nt owf password:"));
		dump_data(100, nt_owf, 16);
#endif
		memcpy(lmpassword.hash, lm_owf, 16);
		memcpy(ntpassword.hash, nt_owf, 16);

		init_netr_PasswordInfo(password_info,
				       domain,
				       logon_parameters,
				       0xdead,
				       0xbeef,
				       username,
				       clnt_name_slash,
				       lmpassword,
				       ntpassword);

		logon->password = password_info;

		break;
	}
	case NET_LOGON_TYPE: {
		struct netr_NetworkInfo *network_info;
		uint8 chal[8];
		unsigned char local_lm_response[24];
		unsigned char local_nt_response[24];
		struct netr_ChallengeResponse lm;
		struct netr_ChallengeResponse nt;

		ZERO_STRUCT(lm);
		ZERO_STRUCT(nt);

		network_info = TALLOC_ZERO_P(mem_ctx, struct netr_NetworkInfo);
		if (!network_info) {
			return NT_STATUS_NO_MEMORY;
		}

		generate_random_buffer(chal, 8);

		SMBencrypt(password, chal, local_lm_response);
		SMBNTencrypt(password, chal, local_nt_response);

		lm.length = 24;
		lm.data = local_lm_response;

		nt.length = 24;
		nt.data = local_nt_response;

		init_netr_NetworkInfo(network_info,
				      domain,
				      logon_parameters,
				      0xdead,
				      0xbeef,
				      username,
				      clnt_name_slash,
				      chal,
				      nt,
				      lm);

		logon->network = network_info;

		break;
	}
	default:
		DEBUG(0, ("switch value %d not supported\n",
			logon_type));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	result = rpccli_netr_LogonSamLogon(cli, mem_ctx,
					   cli->dc->remote_machine,
					   global_myname(),
					   &clnt_creds,
					   &ret_creds,
					   logon_type,
					   logon,
					   validation_level,
					   &validation,
					   &authoritative);

	if (memcmp(zeros, &ret_creds.cred.data, sizeof(ret_creds.cred.data)) != 0) {
		/* Check returned credentials if present. */
		if (!netlogon_creds_client_check(cli->dc, &ret_creds.cred)) {
			DEBUG(0,("rpccli_netlogon_sam_logon: credentials chain check failed\n"));
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	return result;
}


/**
 * Logon domain user with an 'network' SAM logon
 *
 * @param info3 Pointer to a NET_USER_INFO_3 already allocated by the caller.
 **/

NTSTATUS rpccli_netlogon_sam_network_logon(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   uint32 logon_parameters,
					   const char *server,
					   const char *username,
					   const char *domain,
					   const char *workstation,
					   const uint8 chal[8],
					   DATA_BLOB lm_response,
					   DATA_BLOB nt_response,
					   struct netr_SamInfo3 **info3)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	int validation_level = 3;
	const char *workstation_name_slash;
	const char *server_name_slash;
	uint8 zeros[16];
	struct netr_Authenticator clnt_creds;
	struct netr_Authenticator ret_creds;
	union netr_LogonInfo *logon = NULL;
	struct netr_NetworkInfo *network_info;
	uint8_t authoritative;
	union netr_Validation validation;
	struct netr_ChallengeResponse lm;
	struct netr_ChallengeResponse nt;

	*info3 = NULL;

	ZERO_STRUCT(zeros);
	ZERO_STRUCT(ret_creds);

	ZERO_STRUCT(lm);
	ZERO_STRUCT(nt);

	logon = TALLOC_ZERO_P(mem_ctx, union netr_LogonInfo);
	if (!logon) {
		return NT_STATUS_NO_MEMORY;
	}

	network_info = TALLOC_ZERO_P(mem_ctx, struct netr_NetworkInfo);
	if (!network_info) {
		return NT_STATUS_NO_MEMORY;
	}

	netlogon_creds_client_step(cli->dc, &clnt_creds);

	if (server[0] != '\\' && server[1] != '\\') {
		server_name_slash = talloc_asprintf(mem_ctx, "\\\\%s", server);
	} else {
		server_name_slash = server;
	}

	if (workstation[0] != '\\' && workstation[1] != '\\') {
		workstation_name_slash = talloc_asprintf(mem_ctx, "\\\\%s", workstation);
	} else {
		workstation_name_slash = workstation;
	}

	if (!workstation_name_slash || !server_name_slash) {
		DEBUG(0, ("talloc_asprintf failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* Initialise input parameters */

	lm.data = lm_response.data;
	lm.length = lm_response.length;
	nt.data = nt_response.data;
	nt.length = nt_response.length;

	init_netr_NetworkInfo(network_info,
			      domain,
			      logon_parameters,
			      0xdead,
			      0xbeef,
			      username,
			      workstation_name_slash,
			      (uint8_t *) chal,
			      nt,
			      lm);

	logon->network = network_info;

	/* Marshall data and send request */

	result = rpccli_netr_LogonSamLogon(cli, mem_ctx,
					   server_name_slash,
					   global_myname(),
					   &clnt_creds,
					   &ret_creds,
					   NET_LOGON_TYPE,
					   logon,
					   validation_level,
					   &validation,
					   &authoritative);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	if (memcmp(zeros, validation.sam3->base.key.key, 16) != 0) {
		SamOEMhash(validation.sam3->base.key.key,
			   cli->dc->sess_key, 16);
	}

	if (memcmp(zeros, validation.sam3->base.LMSessKey.key, 8) != 0) {
		SamOEMhash(validation.sam3->base.LMSessKey.key,
			   cli->dc->sess_key, 8);
	}

	if (memcmp(zeros, ret_creds.cred.data, sizeof(ret_creds.cred.data)) != 0) {
		/* Check returned credentials if present. */
		if (!netlogon_creds_client_check(cli->dc, &ret_creds.cred)) {
			DEBUG(0,("rpccli_netlogon_sam_network_logon: credentials chain check failed\n"));
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	*info3 = validation.sam3;

	return result;
}

NTSTATUS rpccli_netlogon_sam_network_logon_ex(struct rpc_pipe_client *cli,
					      TALLOC_CTX *mem_ctx,
					      uint32 logon_parameters,
					      const char *server,
					      const char *username,
					      const char *domain,
					      const char *workstation,
					      const uint8 chal[8],
					      DATA_BLOB lm_response,
					      DATA_BLOB nt_response,
					      struct netr_SamInfo3 **info3)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	int validation_level = 3;
	const char *workstation_name_slash;
	const char *server_name_slash;
	uint8 zeros[16];
	union netr_LogonInfo *logon = NULL;
	struct netr_NetworkInfo *network_info;
	uint8_t authoritative;
	union netr_Validation validation;
	struct netr_ChallengeResponse lm;
	struct netr_ChallengeResponse nt;
	uint32_t flags = 0;

	*info3 = NULL;

	ZERO_STRUCT(zeros);

	ZERO_STRUCT(lm);
	ZERO_STRUCT(nt);

	logon = TALLOC_ZERO_P(mem_ctx, union netr_LogonInfo);
	if (!logon) {
		return NT_STATUS_NO_MEMORY;
	}

	network_info = TALLOC_ZERO_P(mem_ctx, struct netr_NetworkInfo);
	if (!network_info) {
		return NT_STATUS_NO_MEMORY;
	}

	if (server[0] != '\\' && server[1] != '\\') {
		server_name_slash = talloc_asprintf(mem_ctx, "\\\\%s", server);
	} else {
		server_name_slash = server;
	}

	if (workstation[0] != '\\' && workstation[1] != '\\') {
		workstation_name_slash = talloc_asprintf(mem_ctx, "\\\\%s", workstation);
	} else {
		workstation_name_slash = workstation;
	}

	if (!workstation_name_slash || !server_name_slash) {
		DEBUG(0, ("talloc_asprintf failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* Initialise input parameters */

	lm.data = lm_response.data;
	lm.length = lm_response.length;
	nt.data = nt_response.data;
	nt.length = nt_response.length;

	init_netr_NetworkInfo(network_info,
			      domain,
			      logon_parameters,
			      0xdead,
			      0xbeef,
			      username,
			      workstation_name_slash,
			      (uint8_t *) chal,
			      nt,
			      lm);

	logon->network = network_info;

        /* Marshall data and send request */

	result = rpccli_netr_LogonSamLogonEx(cli, mem_ctx,
					     server_name_slash,
					     global_myname(),
					     NET_LOGON_TYPE,
					     logon,
					     validation_level,
					     &validation,
					     &authoritative,
					     &flags);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	if (memcmp(zeros, validation.sam3->base.key.key, 16) != 0) {
		SamOEMhash(validation.sam3->base.key.key,
			   cli->dc->sess_key, 16);
	}

	if (memcmp(zeros, validation.sam3->base.LMSessKey.key, 8) != 0) {
		SamOEMhash(validation.sam3->base.LMSessKey.key,
			   cli->dc->sess_key, 8);
	}

	*info3 = validation.sam3;

	return result;
}
